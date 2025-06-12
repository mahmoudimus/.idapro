"""
Unflatten solver -- Attempts to deflatten a control flow flattened function.

Run inside IDA Pro (9.0+) with latest Triton.
"""

from __future__ import annotations

import dataclasses
import enum
import functools
import logging
import re
import struct
import tempfile
import time
import traceback
from collections import namedtuple
from dataclasses import dataclass
from typing import Any, Callable, Optional

import networkx as nx
import triton
from triton import ARCH, AST_NODE, CALLBACK, MODE, OPERAND, Instruction, TritonContext

import ida_allins
import ida_auto
import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_xref
import idaapi
import idautils
import idc

logging.basicConfig(level=logging.DEBUG)


# ──────────────────────────────────────────────────────────────────────
# USER SETTINGS ─ change these if needed
# ──────────────────────────────────────────────────────────────────────
FUNC = idaapi.get_func(idaapi.get_screen_ea())
FUNC_EA = FUNC.start_ea  # start EA
FUNC_END = FUNC.end_ea
ENABLE_PATCHING = True  # True → rewrite code
MAX_STEPS = 250000  # safety
GRAPH_DOT = False

# ── map an artificial 64‑KiB stack so Triton accepts all [rsp+disp] accesses
STACK_TOP = 0x7FFF0000
STACK_SIZE = 0x10000
# Crucial for emulating TLS Callbacks that use gs:[offset]
TEB_AREA = 0x100000
TEB_SIZE = 0x2000
# A dummy memory region for the pointer passed as the first argument (RCX)
DUMMY_ARG_REGION = 0x600000
DUMMY_ARG_SIZE = 0x1000
# ──────────────────────────────────────────────────────────────────────
# 1. Gather basic info
# ──────────────────────────────────────────────────────────────────────
if FUNC_EA == idc.BADADDR:
    raise RuntimeError(f"label {FUNC_EA:X} not found")


Edge = namedtuple("Edge", "src dst ip")


class PatchManager:
    """Manages deferred patch operations."""

    class Mode(enum.Enum):
        PATCH = enum.auto()  # Use ida_bytes.patch_bytes
        PUT = enum.auto()  # Use ida_bytes.put_bytes

    def __init__(
        self,
        patch_mode: Mode = Mode.PATCH,
        dry_run: bool = False,
        auto_clear: bool = True,
    ):
        self.dry_run = dry_run
        self.patch_mode = patch_mode
        self.pending_patches: list[DeferredPatchOp] = []
        self.auto_clear = auto_clear
        logging.info(
            "PatchManager initialized (dry_run=%s, mode=%s)",
            self.dry_run,
            self.patch_mode.name,
        )

    def add_patch(self, address: int, byte_values: bytes):
        """Creates and queues a DeferredPatchOp."""
        op = DeferredPatchOp(address, byte_values, self.patch_mode)
        self.pending_patches.append(op)
        logging.debug("Queued patch operation: %s", op)

    def apply_all(self, dry_run_override: bool | None = None) -> bool:
        """Applies all queued patch operations."""
        logging.info("Applying %d queued patches...", len(self))
        success_count = 0
        fail_count = 0

        if dry_run_override is None:
            # None is a sentinel value here that represents "use the default"
            dry_run_override = self.dry_run

        for op in self.pending_patches:
            if op.apply(dry_run_override):
                success_count += 1
            else:
                fail_count += 1

        logging.info(
            "Patch application complete. Success: %d, Failed: %d",
            success_count,
            fail_count,
        )
        if self.auto_clear:
            self.pending_patches.clear()  # Clear the list after applying
        return fail_count == 0  # Return True if all patches were applied successfully

    def __len__(self) -> int:
        return len(self.pending_patches)


@dataclasses.dataclass(repr=False)
class DeferredPatchOp:
    """Class to store patch operations that will be applied later."""

    address: int
    byte_values: bytes
    mode: PatchManager.Mode
    dry_run: bool = False

    @classmethod
    def patch(cls, address: int, byte_values: bytes, dry_run: bool = False):
        return cls(address, byte_values, PatchManager.Mode.PATCH, dry_run)

    @classmethod
    def put(cls, address: int, byte_values: bytes, dry_run: bool = False):
        return cls(address, byte_values, PatchManager.Mode.PUT, dry_run)

    def apply(self, dry_run_override: bool = False) -> bool:
        """Apply the patch operation using either patch_bytes or put_bytes based on mode."""
        is_dry_run = dry_run_override or self.dry_run
        logging.debug(
            "[*] %sPatching decrypted chunk %s at 0x%X (size: %d)",
            "(Dry Run) " if is_dry_run else "",
            ("revertably" if self.mode == PatchManager.Mode.PATCH else "destructively"),
            self.address,
            len(self.byte_values),
        )
        success = True
        if is_dry_run:
            return success

        try:
            func = (
                idaapi.put_bytes
                if self.mode == PatchManager.Mode.PUT
                else idaapi.patch_bytes
            )
            func(self.address, self.byte_values)
        except Exception as e:
            logging.error(f"Failed to apply patch {self}: {e}", exc_info=True)
            success = False
        return success

    def __str__(self):
        """String representation with hex formatting."""
        dry_run_str = " (dry run)" if self.dry_run else ""
        return f"{self.__class__.__name__}({len(self.byte_values)} bytes, mode={self.mode.name}{dry_run_str} @ address=0x{self.address:X})"

    __repr__ = __str__


class UserCanceledError(Exception):
    pass


@dataclass
class CheckContinuePrompt:
    """Decorator that checks if user wants to continue after elapsed time.

    Args:
        metadata: Dictionary containing metadata to format into the prompt message
        cancel_func: Function to call if user cancels
        enable_prompt: Whether to enable the continue prompt
        start_time: Optional start time, will be initialized if None
        prompt_interval: Initial time before first prompt in seconds
        logger: Optional logger instance
    """

    metadata: dict | None = None
    cancel_func: Callable[[], None] | None = None
    enable_prompt: bool = True
    start_time: float = 0.0
    prompt_interval: int = 120
    logger: logging.Logger | None = None

    def __post_init__(self):
        current_time = time.time()
        self.start_time = current_time if self.start_time == 0.0 else self.start_time
        self.next_prompt_time = self.start_time + self.prompt_interval

    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time

    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.enable_prompt:
                return func(*args, **kwargs)

            if self.elapsed_time < self.next_prompt_time:
                return func(*args, **kwargs)

            minutes = int(self.elapsed_time / 60)
            seconds = int(self.elapsed_time % 60)
            time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

            # Format metadata into message
            message = f"{func.__name__} has been running for {time_str}.\n\n"
            if self.metadata:
                for key, value in self.metadata.items():
                    message += f"{key}: {value}\n"
            message += "\nContinue?"

            reply = ida_kernwin.ask_yn(0, message)
            if reply == 0:
                if self.cancel_func:
                    return self.cancel_func()
                raise UserCanceledError("User canceled")

            self.next_prompt_time *= 2
            if self.logger is not None:
                self.logger.info(
                    "Next prompt will be at %d seconds (%.1f minutes)",
                    self.next_prompt_time,
                    self.next_prompt_time / 60.0,
                )
            return func(*args, **kwargs)

        return wrapper


class IDAToTritonRegisterMapper:
    """
    Maps IDA Pro register representations to Triton register objects.
    Supports x86, x86-64 architectures.
    """

    def __init__(self, ctx: triton.TritonContext):
        """
        Initialize the mapper with a Triton context.

        Args:
            ctx: Triton context object
        """
        self.ctx = ctx
        self.arch = ctx.getArchitecture()

        # Build mapping tables based on architecture
        self._build_register_mappings()

    def _build_register_mappings(self) -> None:
        """Build register mapping dictionaries based on current architecture."""

        if self.arch == triton.ARCH.X86_64:
            self.register_map = {
                # 64-bit general purpose registers
                "rax": triton.REG.X86_64.RAX,
                "rbx": triton.REG.X86_64.RBX,
                "rcx": triton.REG.X86_64.RCX,
                "rdx": triton.REG.X86_64.RDX,
                "rsi": triton.REG.X86_64.RSI,
                "rdi": triton.REG.X86_64.RDI,
                "rbp": triton.REG.X86_64.RBP,
                "rsp": triton.REG.X86_64.RSP,
                "r8": triton.REG.X86_64.R8,
                "r9": triton.REG.X86_64.R9,
                "r10": triton.REG.X86_64.R10,
                "r11": triton.REG.X86_64.R11,
                "r12": triton.REG.X86_64.R12,
                "r13": triton.REG.X86_64.R13,
                "r14": triton.REG.X86_64.R14,
                "r15": triton.REG.X86_64.R15,
                # 32-bit general purpose registers
                "eax": triton.REG.X86_64.EAX,
                "ebx": triton.REG.X86_64.EBX,
                "ecx": triton.REG.X86_64.ECX,
                "edx": triton.REG.X86_64.EDX,
                "esi": triton.REG.X86_64.ESI,
                "edi": triton.REG.X86_64.EDI,
                "ebp": triton.REG.X86_64.EBP,
                "esp": triton.REG.X86_64.ESP,
                "r8d": triton.REG.X86_64.R8D,
                "r9d": triton.REG.X86_64.R9D,
                "r10d": triton.REG.X86_64.R10D,
                "r11d": triton.REG.X86_64.R11D,
                "r12d": triton.REG.X86_64.R12D,
                "r13d": triton.REG.X86_64.R13D,
                "r14d": triton.REG.X86_64.R14D,
                "r15d": triton.REG.X86_64.R15D,
                # 16-bit general purpose registers
                "ax": triton.REG.X86_64.AX,
                "bx": triton.REG.X86_64.BX,
                "cx": triton.REG.X86_64.CX,
                "dx": triton.REG.X86_64.DX,
                "si": triton.REG.X86_64.SI,
                "di": triton.REG.X86_64.DI,
                "bp": triton.REG.X86_64.BP,
                "sp": triton.REG.X86_64.SP,
                "r8w": triton.REG.X86_64.R8W,
                "r9w": triton.REG.X86_64.R9W,
                "r10w": triton.REG.X86_64.R10W,
                "r11w": triton.REG.X86_64.R11W,
                "r12w": triton.REG.X86_64.R12W,
                "r13w": triton.REG.X86_64.R13W,
                "r14w": triton.REG.X86_64.R14W,
                "r15w": triton.REG.X86_64.R15W,
                # 8-bit general purpose registers
                "al": triton.REG.X86_64.AL,
                "bl": triton.REG.X86_64.BL,
                "cl": triton.REG.X86_64.CL,
                "dl": triton.REG.X86_64.DL,
                "ah": triton.REG.X86_64.AH,
                "bh": triton.REG.X86_64.BH,
                "ch": triton.REG.X86_64.CH,
                "dh": triton.REG.X86_64.DH,
                "sil": triton.REG.X86_64.SIL,
                "dil": triton.REG.X86_64.DIL,
                "bpl": triton.REG.X86_64.BPL,
                "spl": triton.REG.X86_64.SPL,
                "r8b": triton.REG.X86_64.R8B,
                "r9b": triton.REG.X86_64.R9B,
                "r10b": triton.REG.X86_64.R10B,
                "r11b": triton.REG.X86_64.R11B,
                "r12b": triton.REG.X86_64.R12B,
                "r13b": triton.REG.X86_64.R13B,
                "r14b": triton.REG.X86_64.R14B,
                "r15b": triton.REG.X86_64.R15B,
                # Segment registers
                "cs": triton.REG.X86_64.CS,
                "ds": triton.REG.X86_64.DS,
                "es": triton.REG.X86_64.ES,
                "fs": triton.REG.X86_64.FS,
                "gs": triton.REG.X86_64.GS,
                "ss": triton.REG.X86_64.SS,
                # Flag registers
                # "rflags": triton.REG.X86_64.RFLAGS,
                "eflags": triton.REG.X86_64.EFLAGS,
                # Instruction pointer
                "rip": triton.REG.X86_64.RIP,
                "eip": triton.REG.X86_64.EIP,
                # # FPU registers
                # "st0": triton.REG.X86_64.ST0,
                # "st1": triton.REG.X86_64.ST1,
                # "st2": triton.REG.X86_64.ST2,
                # "st3": triton.REG.X86_64.ST3,
                # "st4": triton.REG.X86_64.ST4,
                # "st5": triton.REG.X86_64.ST5,
                # "st6": triton.REG.X86_64.ST6,
                # "st7": triton.REG.X86_64.ST7,
                # XMM registers
                "xmm0": triton.REG.X86_64.XMM0,
                "xmm1": triton.REG.X86_64.XMM1,
                "xmm2": triton.REG.X86_64.XMM2,
                "xmm3": triton.REG.X86_64.XMM3,
                "xmm4": triton.REG.X86_64.XMM4,
                "xmm5": triton.REG.X86_64.XMM5,
                "xmm6": triton.REG.X86_64.XMM6,
                "xmm7": triton.REG.X86_64.XMM7,
                "xmm8": triton.REG.X86_64.XMM8,
                "xmm9": triton.REG.X86_64.XMM9,
                "xmm10": triton.REG.X86_64.XMM10,
                "xmm11": triton.REG.X86_64.XMM11,
                "xmm12": triton.REG.X86_64.XMM12,
                "xmm13": triton.REG.X86_64.XMM13,
                "xmm14": triton.REG.X86_64.XMM14,
                "xmm15": triton.REG.X86_64.XMM15,
            }

        elif self.arch == triton.ARCH.X86:
            self.register_map = {
                # 32-bit general purpose registers
                "eax": triton.REG.X86.EAX,
                "ebx": triton.REG.X86.EBX,
                "ecx": triton.REG.X86.ECX,
                "edx": triton.REG.X86.EDX,
                "esi": triton.REG.X86.ESI,
                "edi": triton.REG.X86.EDI,
                "ebp": triton.REG.X86.EBP,
                "esp": triton.REG.X86.ESP,
                # 16-bit general purpose registers
                "ax": triton.REG.X86.AX,
                "bx": triton.REG.X86.BX,
                "cx": triton.REG.X86.CX,
                "dx": triton.REG.X86.DX,
                "si": triton.REG.X86.SI,
                "di": triton.REG.X86.DI,
                "bp": triton.REG.X86.BP,
                "sp": triton.REG.X86.SP,
                # 8-bit general purpose registers
                "al": triton.REG.X86.AL,
                "bl": triton.REG.X86.BL,
                "cl": triton.REG.X86.CL,
                "dl": triton.REG.X86.DL,
                "ah": triton.REG.X86.AH,
                "bh": triton.REG.X86.BH,
                "ch": triton.REG.X86.CH,
                "dh": triton.REG.X86.DH,
                # Segment registers
                "cs": triton.REG.X86.CS,
                "ds": triton.REG.X86.DS,
                "es": triton.REG.X86.ES,
                "fs": triton.REG.X86.FS,
                "gs": triton.REG.X86.GS,
                "ss": triton.REG.X86.SS,
                # Flag registers
                "eflags": triton.REG.X86.EFLAGS,
                # Instruction pointer
                "eip": triton.REG.X86.EIP,
                # # FPU registers
                # "st0": triton.REG.X86.ST0,
                # "st1": triton.REG.X86.ST1,
                # "st2": triton.REG.X86.ST2,
                # "st3": triton.REG.X86.ST3,
                # "st4": triton.REG.X86.ST4,
                # "st5": triton.REG.X86.ST5,
                # "st6": triton.REG.X86.ST6,
                # "st7": triton.REG.X86.ST7,
                # XMM registers
                "xmm0": triton.REG.X86.XMM0,
                "xmm1": triton.REG.X86.XMM1,
                "xmm2": triton.REG.X86.XMM2,
                "xmm3": triton.REG.X86.XMM3,
                "xmm4": triton.REG.X86.XMM4,
                "xmm5": triton.REG.X86.XMM5,
                "xmm6": triton.REG.X86.XMM6,
                "xmm7": triton.REG.X86.XMM7,
            }
        else:
            raise ValueError(f"Unsupported architecture: {self.arch}")

    def map_register(self, ida_reg: Any) -> Optional[triton.Register]:
        """
        Map an IDA register to a Triton register.

        Args:
            ida_reg: IDA register object or string representation

        Returns:
            Triton Register object or None if mapping not found
        """
        # Handle different input types
        if hasattr(ida_reg, "name"):
            # IDA register object with name attribute
            reg_name = ida_reg.name.lower()
        elif hasattr(ida_reg, "reg"):
            # IDA register object with reg attribute
            reg_name = str(ida_reg.reg).lower()
        elif isinstance(ida_reg, str):
            # String representation
            reg_name = ida_reg.lower()
        elif isinstance(ida_reg, int):
            # Register ID - would need IDA context to resolve
            # This is a simplified approach
            reg_name = self._resolve_register_id(ida_reg)
        else:
            # Try to convert to string
            reg_name = str(ida_reg).lower()

        # Clean up register name
        reg_name = reg_name.strip()

        # Look up in mapping table
        if reg_name in self.register_map:
            triton_reg_id = self.register_map[reg_name]
            return self.ctx.getRegister(triton_reg_id)

        return None

    def _resolve_register_id(self, reg_id: int) -> str:
        """
        Resolve IDA register ID to register name.
        This is a simplified implementation - in practice you'd use IDA's API.
        """
        # Common x86/x64 register ID mappings (simplified)
        x86_64_id_map = {
            0: "rax",
            1: "rcx",
            2: "rdx",
            3: "rbx",
            4: "rsp",
            5: "rbp",
            6: "rsi",
            7: "rdi",
            8: "r8",
            9: "r9",
            10: "r10",
            11: "r11",
            12: "r12",
            13: "r13",
            14: "r14",
            15: "r15",
        }

        x86_id_map = {
            0: "eax",
            1: "ecx",
            2: "edx",
            3: "ebx",
            4: "esp",
            5: "ebp",
            6: "esi",
            7: "edi",
        }

        if self.arch == triton.ARCH.X86_64:
            return x86_64_id_map.get(reg_id, f"unknown_{reg_id}")
        else:
            return x86_id_map.get(reg_id, f"unknown_{reg_id}")

    def get_register_value(self, ida_reg: Any) -> Optional[int]:
        """
        Get the current value of a register in Triton context.

        Args:
            ida_reg: IDA register representation

        Returns:
            Register value or None if register not found
        """
        triton_reg = self.map_register(ida_reg)
        if triton_reg:
            return self.ctx.getConcreteRegisterValue(triton_reg)
        return None

    def set_register_value(self, ida_reg: Any, value: int) -> bool:
        """
        Set the value of a register in Triton context.

        Args:
            ida_reg: IDA register representation
            value: Value to set

        Returns:
            True if successful, False otherwise
        """
        triton_reg = self.map_register(ida_reg)
        if triton_reg:
            self.ctx.setConcreteRegisterValue(triton_reg, value)
            return True
        return False


class TraversalEnum(enum.IntEnum):
    CONTINUE = 0
    STOP = 1
    SKIP = 2


class CTreeSwitchFinder(ida_hexrays.ctree_visitor_t):
    """A ctree visitor to find all switch statements in a function."""

    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.switches: list[ida_hexrays.cinsn_t] = []

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> TraversalEnum:
        if insn.op == ida_hexrays.cit_switch:
            self.switches.append(insn.cswitch)
        return TraversalEnum.CONTINUE


class CTreeContainsVisitor(ida_hexrays.ctree_visitor_t):
    """A ctree visitor to check if a ctree fragment contains a specific item."""

    def __init__(self, state_var_idx: int):
        super().__init__(ida_hexrays.CV_FAST)
        self.state_var_idx = state_var_idx
        self.found = False
        self.level = 0
        self.nodes = [
            "cot_comma",
            "cot_asg",
            "cot_asgbor",
            "cot_asgxor",
            "cot_asgband",
            "cot_asgadd",
            "cot_asgsub",
            "cot_asgmul",
            "cot_asgsshr",
            "cot_asgushr",
            "cot_asgshl",
            "cot_asgsdiv",
            "cot_asgudiv",
            "cot_asgsmod",
            "cot_asgumod",
            "cot_tern",
            "cot_lor",
            "cot_land",
            "cot_bor",
            "cot_xor",
            "cot_band",
            "cot_eq",
            "cot_ne",
            "cot_sge",
            "cot_uge",
            "cot_sle",
            "cot_ule",
            "cot_sgt",
            "cot_ugt",
            "cot_slt",
            "cot_ult",
            "cot_sshr",
            "cot_ushr",
            "cot_shl",
            "cot_add",
            "cot_sub",
            "cot_mul",
            "cot_sdiv",
            "cot_udiv",
            "cot_smod",
            "cot_umod",
            "cot_fadd",
            "cot_fsub",
            "cot_fmul",
            "cot_fdiv",
            "cot_fneg",
            "cot_neg",
            "cot_cast",
            "cot_lnot",
            "cot_bnot",
            "cot_ptr",
            "cot_ref",
            "cot_postinc",
            "cot_postdec",
            "cot_preinc",
            "cot_predec",
            "cot_call",
            "cot_idx",
            "cot_memref",
            "cot_memptr",
            "cot_num",
            "cot_fnum",
            "cot_str",
            "cot_obj",
            "cot_var",
            "cot_insn",
            "cot_sizeof",
            "cot_helper",
            "cot_type",
        ]

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> TraversalEnum:
        if self.found:
            return TraversalEnum.STOP  # Stop traversal

        print(
            "looking for",
            self.state_var_idx,
            " and im currently at",
            hex(insn.ea),
            idc.generate_disasm_line(insn.ea, 0),
        )
        print(
            "current insn is:",
            insn.opname,
            "looking for",
            f"cot_asg (assignment) ({ida_hexrays.cot_asg})",
        )
        # We are looking for an assignment instruction, e.g., `v1 = 0;`
        if insn.cexpr is not None and insn.cexpr.op == ida_hexrays.cot_asg:
            print(
                "HERE!!!",
                idc.print_operand(insn.ea, 0),
                idc.generate_disasm_line(insn.ea, 0),
            )
            dest_expr = insn.cexpr.x
            # Check if the destination of the assignment is a variable
            if dest_expr.op == ida_hexrays.cot_var:
                # Check if the variable's index matches our state variable
                if dest_expr.v.idx == self.state_var_idx:
                    self.found = True
                    return TraversalEnum.STOP  # Stop traversal
        return TraversalEnum.CONTINUE

    def visit_expr(self, e):
        for node in self.nodes:
            if e.op == idaapi.__dict__[node]:
                print((" " * self.level) + "{} at {}".format(node, hex(e.ea)))
                self.level += 1
        return TraversalEnum.CONTINUE

    def leave_expr(self, e):
        for node in self.nodes:
            if e.op == idaapi.__dict__[node]:
                self.level -= 1
        return TraversalEnum.CONTINUE


class SpecificSwitchVisitor(ida_hexrays.ctree_visitor_t):
    """
    A ctree visitor that performs a deep search to find the switch
    statement at a specific address.
    """

    def __init__(self, target_ea):
        super().__init__(ida_hexrays.CV_FAST)
        self.target_ea = target_ea
        self.found_switch = None

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> TraversalEnum:
        if self.found_switch:
            return TraversalEnum.STOP  # Stop traversal if found

        # We are looking for a switch statement whose corresponding
        # instruction address matches our target dispatcher address.
        if insn.op == ida_hexrays.cit_switch and insn.ea == self.target_ea:
            self.found_switch = insn.cswitch
            return TraversalEnum.STOP  # Stop traversal

        return TraversalEnum.CONTINUE


class StateStoreVisitor(ida_hexrays.ctree_visitor_t):
    """
    A ctree visitor that finds all assignments of a constant value
    to our specific state variable, e.g., `state_var = 5;`
    """

    def __init__(self, state_var_idx):
        super().__init__(ida_hexrays.CV_FAST)
        self.state_var_idx = state_var_idx
        # List to store tuples of: (address_of_assignment, next_state_value)
        self.found_stores: list[tuple[int, int]] = []

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> TraversalEnum:
        # We are looking for an assignment instruction: cit_asg
        if insn.cexpr is not None and insn.cexpr.op == ida_hexrays.cot_asg:
            # Destination must be a variable: cot_var
            dest = insn.cexpr.x
            # Source must be a number/constant: cot_num
            src = insn.cexpr.y
            if dest.op == ida_hexrays.cot_var and src.op == ida_hexrays.cot_num:
                if dest.v.getv() == self.state_var_idx:
                    print(
                        f"[+] found store to state variable at 0x{insn.ea:X} - {dest.dstr()} = {src.dstr()}"
                    )
                    addr = insn.ea
                    value = src.n.value(insn.cexpr.type)
                    self.found_stores.append((addr, value))
        return TraversalEnum.CONTINUE


def hook_call(ctx, mem):
    try:
        ip = ctx.getConcreteRegisterValue(ctx.registers.rip)
        ctx.setConcreteRegisterValue(ctx.registers.rax, 0)  # retval
        # Fake a push <return> so 'ret' works
        rsp = ctx.getConcreteRegisterValue(ctx.registers.rsp) - 8
        ctx.setConcreteRegisterValue(ctx.registers.rsp, rsp)
        ctx.setConcreteMemoryValue(rsp, (ip + idc.get_item_size(ip)) & 0xFF)
        # Skip over 'call'
        ctx.setConcreteRegisterValue(ctx.registers.rip, ip + idc.get_item_size(ip))
    except Exception:
        return False  # swallow all errors


def has_sib(op: idaapi.op_t) -> bool:
    return op.type in (idaapi.o_displ, idaapi.o_phrase) and op.specflag1 != 0


def get_sib_components(
    insn: idaapi.insn_t, op: idaapi.op_t
) -> tuple[int, int, int, int]:
    REX_B = 1
    REX_X = 2

    def sib_base(insn, op):
        base = op.specflag2 & 7
        if insn.insnpref & REX_B:
            base |= 8
        return base

    def sib_index(insn, op):
        index = (op.specflag2 >> 3) & 7
        if insn.insnpref & REX_X != 0:
            index |= 8
        return index

    def sib_scale(op):
        scale = (op.specflag1 >> 6) & 3
        return 1 << scale  # Convert to actual scale value (1, 2, 4, 8)

    return sib_base(insn, op), sib_index(insn, op), sib_scale(op), op.addr


def get_operand_type_name(op_type):
    """Convert IDA operand type to readable name"""
    op_types = {
        idaapi.o_void: "void",
        idaapi.o_reg: "register",
        idaapi.o_mem: "memory",
        idaapi.o_phrase: "phrase",
        idaapi.o_displ: "displacement",
        idaapi.o_imm: "immediate",
        idaapi.o_far: "far",
        idaapi.o_near: "near",
    }
    return op_types.get(op_type, "unknown")


def analyze_operand_comprehensive(
    insn: idaapi.insn_t, op: idaapi.op_t, op_num: int
) -> dict:
    """Comprehensive operand analysis incorporating SIB handling"""
    result = {
        "type": op.type,
        "type_name": get_operand_type_name(op.type),
        "display_string": idc.print_operand(insn.ea, op_num),
    }

    if op.type == idaapi.o_mem:
        # Simple memory reference [addr]
        result["address"] = op.addr
        result["displacement"] = idaapi.as_int32(op.addr)

    elif op.type == idaapi.o_displ:
        # Register + displacement [reg + disp] or SIB addressing
        if has_sib(op):
            base_reg_idx, index_reg_idx, scale, disp = get_sib_components(insn, op)
            result["has_sib"] = True
            result["sib_base_reg"] = idaapi.get_reg_name(base_reg_idx, op.dtype)
            result["sib_index_reg"] = (
                idaapi.get_reg_name(index_reg_idx, op.dtype)
                if index_reg_idx != 4
                else None
            )  # 4 = no index
            result["sib_scale"] = scale
            result["displacement"] = idaapi.as_int32(disp)
        else:
            # Simple [reg + disp]
            result["has_sib"] = False
            result["base_reg"] = idaapi.get_reg_name(op.reg, op.dtype)
            result["displacement"] = idaapi.as_int32(idc.get_operand_value(insn.ea, 0))

    elif op.type == idaapi.o_phrase:
        # Register indirect: [reg] or [reg + reg*scale]
        if has_sib(op):
            base_reg_idx, index_reg_idx, scale, disp = get_sib_components(insn, op)
            result["has_sib"] = True
            result["sib_base_reg"] = idaapi.get_reg_name(base_reg_idx, op.dtype)
            result["sib_index_reg"] = (
                idaapi.get_reg_name(index_reg_idx, op.dtype)
                if index_reg_idx != 4
                else None
            )
            result["sib_scale"] = scale
            result["displacement"] = idaapi.as_int32(disp) if disp != 0 else 0
        else:
            result["has_sib"] = False
            result["base_reg"] = idaapi.get_reg_name(op.reg, op.dtype)
            result["displacement"] = idaapi.as_int32(idc.get_operand_value(insn.ea, 0))

    elif op.type == idaapi.o_imm:
        # Immediate value
        result["immediate"] = op.value

    return result


def get_operand_displacement_safe(insn: idaapi.insn_t, op: idaapi.op_t) -> int:
    """Safely get displacement from any operand type"""
    if has_sib(op):
        _, _, _, disp = get_sib_components(insn, op)
        return idaapi.as_signed(disp, op.dtype)
    elif op.type == idaapi.o_displ:
        return idaapi.as_signed(op.disp, op.dtype)  # type: ignore
    elif op.type == idaapi.o_mem:
        return idaapi.as_signed(op.addr, op.dtype)
    elif op.type == idaapi.o_phrase and hasattr(op, "disp"):
        return idaapi.as_signed(op.disp, op.dtype)  # type: ignore
    else:
        return 0


def get_operand_base_register(insn: idaapi.insn_t, op: idaapi.op_t) -> str | None:
    """Get base register name for memory operands"""
    if has_sib(op):
        base_reg_idx, _, _, _ = get_sib_components(insn, op)
        return idaapi.get_reg_name(base_reg_idx, op.dtype)
    elif op.type in (idaapi.o_displ, idaapi.o_phrase):
        return idaapi.get_reg_name(op.reg, op.dtype)
    else:
        return None


def _src_uses_reg(insn: idaapi.insn_t, op: idaapi.op_t, reg: int) -> bool:
    """Does `op` mention `reg` anywhere (base, index, …)?"""
    if op.type == idaapi.o_reg:
        return op.reg == reg
    if has_sib(op):
        base, index, scale, displ = get_sib_components(insn, op)

        print(
            f"[+] op.reg: {op.reg}, reg: {reg}, {op.specflag1 == reg}, index: {index}, base: {base}, scale: {scale}, displ: {displ}"
        )
        # mem op: [base+index*scale+disp]
        return op.reg == reg or index == reg or base == reg
    return False


def _wide(reg: str) -> str:
    """Map sp→rsp, bp→rbp, esp→rsp, ebp→rbp, otherwise unchanged."""
    return {"sp": "rsp", "bp": "rbp", "esp": "rsp", "ebp": "rbp"}.get(reg, reg)


def guess_state_var2(
    cfunc: ida_hexrays.cfuncptr_t, dispatch_ea: int, stack_offset: int
) -> tuple[str, Any, Any]:
    """
    Finds the state variable by inspecting the decompiler's ctree.
    This version uses a deep visitor to find the switch, making it robust against nesting.

    Returns: ("stk", base_reg_name, displacement) or ("reg", reg_name, None).
    """
    print("[+] Guessing state variable using decompiler ctree...")

    # Use our new visitor to find the switch statement, regardless of nesting depth.
    visitor = SpecificSwitchVisitor(dispatch_ea)
    visitor.apply_to(cfunc.body, None)

    main_dispatcher_switch = visitor.found_switch

    if not main_dispatcher_switch:
        raise RuntimeError(
            f"Could not find ctree switch item for dispatcher at 0x{dispatch_ea:X}"
        )

    # The switch expression is our state variable
    switch_expr = main_dispatcher_switch.expr
    if switch_expr.op != idaapi.cot_var:
        raise RuntimeError("Dispatcher switch expression is not a simple variable.")

    lvar = switch_expr.v.getv()  # Get the lvar_t object for the variable

    if lvar.is_stk_var():
        # It's a stack variable. The offset is relative to the frame pointer (RBP).
        stk_offset = lvar.get_stkoff() - stack_offset
        # NOTE: IDA's decompiler considers the frame pointer to be RBP for stack vars.
        return ("stk", "rbp", stk_offset)

    if lvar.is_reg_var():
        # It's a register variable.
        reg_info = cfunc.get_reg_info(lvar.get_reg1())
        reg_name = reg_info.reg_name if reg_info else f"reg{lvar.get_reg1()}"
        return ("reg", reg_name, None)

    raise RuntimeError("State variable is not a register or stack variable.")


def guess_state_var(
    cfunc: ida_hexrays.cfuncptr_t, DISPATCH_EA: int
) -> tuple[str, str | int, int | None]:
    """Return ("reg",name) or ("stk",base,disp) or ("mem",ea)."""
    insn = idaapi.insn_t()
    if not idaapi.decode_insn(insn, DISPATCH_EA):
        raise RuntimeError("cannot decode dispatcher @0x{:X}".format(DISPATCH_EA))

    jop = insn.ops[0]  # type: ignore # operand of jmp rax / jmp [..]

    # If dispatcher already indexes a memory slot, that's the state.
    if jop.type == idaapi.o_displ:
        base = idaapi.get_reg_name(jop.reg, jop.dtype)
        base = _wide(base)
        return ("stk", base, idaapi.as_int32(jop.disp))

    if jop.type != idaapi.o_reg:
        raise RuntimeError("unsupported jmp operand")

    tracked: int = jop.reg  # register that feeds the jmp
    func_start = idaapi.get_func(DISPATCH_EA).start_ea
    ea = idaapi.prev_head(DISPATCH_EA, func_start)
    while ea != idaapi.BADADDR:
        idaapi.decode_insn(insn, ea)
        _disasm_line = idc.generate_disasm_line(ea, 0)
        print(f"[+] @ {hex(ea)} - {_disasm_line}")

        if (
            insn.itype
            in (
                ida_allins.NN_mov,
                ida_allins.NN_lea,
                ida_allins.NN_movzx,
                ida_allins.NN_movsx,
                ida_allins.NN_movsxd,
            )
            and insn.ops[0].type == idaapi.o_reg  # type: ignore
            and insn.ops[0].reg == tracked  # type: ignore
        ):

            src = insn.ops[1]  # type: ignore

            # skip if source *still* uses the same register (e.g. [rbp+rax*4])
            if _src_uses_reg(insn, src, tracked):
                print(
                    f"[+] skipping {_disasm_line}, source uses same register as tracked"
                )
                ea = idaapi.prev_head(ea, func_start)
                print(f"[+] prev_addr: {hex(ea)}")
                continue

            if src.type == idaapi.o_reg:
                return ("reg", _wide(idaapi.get_reg_name(src.reg, src.dtype)), None)

            if src.type == idaapi.o_displ:
                base = idaapi.get_reg_name(src.reg, src.dtype)
                base = _wide(base)
                print(f"[+] base: {base}, disp: {src.addr}")
                return ("stk", base, idaapi.as_int32(src.addr))

            if src.type == idaapi.o_mem:
                return ("mem", src.addr, None)

        ea = idaapi.prev_head(ea, func_start)

    # fallback: treat the register itself as the state
    return ("reg", idaapi.get_reg_name(tracked, insn.ops[0].dtype), None)  # type: ignore


def resolve_jump_chains(edges: set[Edge], block_ea: dict[int, int]) -> dict[int, int]:
    """
    Analyzes the execution trace (edges) to resolve jump chains.
    For a chain A -> B -> C, it will map state A directly to the address of C.

    Args:
        edges: A set of Edge tuples (src, dst, ip) from the emulation.
        block_ea: The original map of {state: address}.

    Returns:
        A new map of {state: final_resolved_address}.
    """
    print("[+] Pass 2: Resolving jump chains from execution trace...")

    # Create a simple directed graph from the state transitions
    successors = {edge.src: edge.dst for edge in edges}

    # Memoization cache for resolved states
    resolved_cache = {}

    def _trace_to_end(start_state: int) -> int:
        """Follows the chain of states to its end and returns the final state."""
        if start_state in resolved_cache:
            return resolved_cache[start_state]

        path = [start_state]
        current_state = start_state

        while current_state in successors:
            next_state = successors[current_state]

            # Check for loops in the chain
            if next_state in path:
                print(
                    f"[!] Detected loop in state chain: {' -> '.join(map(str, path))} -> {next_state}"
                )
                # We break the loop by treating the loop's start as the final destination
                resolved_cache[start_state] = next_state
                return next_state

            path.append(next_state)
            current_state = next_state

        # The final state is the last one we visited
        final_state = path[-1]

        # Cache the result for all nodes in the path to speed up future lookups
        for state in path:
            resolved_cache[state] = final_state

        return final_state

    resolved_map = {}
    for original_state in sorted(block_ea.keys()):
        final_state = _trace_to_end(original_state)

        if final_state not in block_ea:
            # This can happen if a chain leads to an exit state not in the switch
            print(
                f"[!] State {original_state} resolves to non-mappable state {final_state}. Preserving original target."
            )
            resolved_map[original_state] = block_ea[original_state]
            continue

        final_address = block_ea[final_state]
        if original_state != final_state:
            print(
                f"[+]   State {original_state} (0x{block_ea[original_state]:X}) resolves to final state {final_state} (0x{final_address:X})"
            )

        resolved_map[original_state] = final_address

    print("[+] Jump chain resolution complete.")
    return resolved_map


def get_switch_mapping(si: idaapi.switch_info_t, dispatcher_ea: int) -> dict[int, int]:
    cat = idaapi.calc_switch_cases(dispatcher_ea, si)
    cases, targets = cat.cases, cat.targets
    mapping = {}
    for i in range(targets.size()):
        tgt = targets[i]
        mapping.update({int(cv): tgt for cv in cases[i]})
    return mapping


def triton_reg(mapper: IDAToTritonRegisterMapper, name: str):
    """helper to turn that name into a Triton Register"""
    # Triton register names are all lower-case
    return mapper.map_register(name)


def load_dword(tc: TritonContext, addr: int) -> int:
    """Little-endian 32-bit load from Triton memory."""
    return int.from_bytes(tc.getConcreteMemoryAreaValue(addr, 4), "little")


def store_dword(tc: TritonContext, addr: int, value: int):
    tc.setConcreteMemoryAreaValue(addr, value.to_bytes(4, "little"))


# ----------------------------------------------------------------------
# read/write the dispatcher state
# ----------------------------------------------------------------------
def read_state(
    tc: TritonContext, state_kind: str, state_desc: tuple[str, str | int, int | None]
) -> int:
    """
    Return the current value of the dispatcher's state variable.

    Handles every shape returned by guess_state_var():
        ("reg",  reg_name)
        ("stk",  base_reg_name, displacement)
        ("mem",  absolute_ea)
    """
    if state_kind == "reg":
        reg = getattr(tc.registers, state_desc[0].lower())
        return tc.getConcreteRegisterValue(reg) & 0xFFFFFFFF

    if state_kind == "stk":
        base_reg, disp = state_desc  # type: ignore
        base = tc.getConcreteRegisterValue(getattr(tc.registers, base_reg.lower()))
        return int.from_bytes(tc.getConcreteMemoryAreaValue(base + disp, 4), "little")

    if state_kind == "mem":
        addr = state_desc[0]
        return int.from_bytes(tc.getConcreteMemoryAreaValue(addr, 4), "little")

    raise RuntimeError(f"unknown state_kind {state_kind!r}")


def write_state(
    tc: TritonContext,
    state_kind: str,
    state_desc: tuple[str, str | int, int | None],
    value: int,
    mapper: IDAToTritonRegisterMapper,
):
    """Update the dispatcher's state variable (32-bit)."""
    value &= 0xFFFFFFFF
    if state_kind == "reg":
        (reg_name,) = state_desc  # type: ignore
        tc.setConcreteRegisterValue(triton_reg(mapper, reg_name), value)
    elif state_kind == "stk":
        base_reg_name, disp = state_desc  # type: ignore
        base = tc.getConcreteRegisterValue(triton_reg(mapper, base_reg_name))
        store_dword(tc, base + disp, value)
    elif state_kind == "mem":
        (ea,) = state_desc  # type: ignore
        store_dword(tc, int(ea), value)
    else:
        raise RuntimeError(f"unknown state_kind {state_kind!r}")


def is_ret(ea: int, strict: bool = True) -> bool:
    """
    True if the instruction at `ea` is any kind of RET.
    `strict=False` also treats IRET/IRETD/IRETQ as returns.
    """
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    return idaapi.is_ret_insn(insn, strict)


def is_uncond_jmp_reg(ea: int) -> bool:
    """
    True if the instruction at `ea` is an *unconditional* `jmp <register>`.
    That's the pattern most VM dispatchers use to leave the function.
    """
    insn = idaapi.insn_t()
    if not idaapi.decode_insn(insn, ea):
        return False
    return (
        insn.itype == ida_allins.NN_jmp  # the mnemonic is JMP
        and insn.ops[0].type == idaapi.o_reg  # target is a register # type: ignore
    )


def ensure_mapped(tc: TritonContext, ea: int):
    if tc.isConcreteMemoryValueDefined(ea, 1):
        return
    seg = idaapi.getseg(ea)
    if seg:
        tc.setConcreteMemoryAreaValue(
            seg.start_ea, ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
        )


def map_all_segments(tc: TritonContext):
    """
    Maps all executable and read-only segments from the IDA database into the Triton context.
    This ensures that calls to other functions within the same binary are valid.
    """
    print("[+] Mapping all executable and read-only segments into Triton memory...")
    mapped_count = 0
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        # We need executable segments for code and read-only segments for data (like strings, constants)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC or seg.perm & idaapi.SEGPERM_READ):
            seg_name = idaapi.get_segm_name(seg)
            print(
                f"[+] Mapping segment '{seg_name}' from 0x{seg.start_ea:X} to 0x{seg.end_ea:X}"
            )

            try:
                # Use a memory-safe way to get bytes
                seg_bytes = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
                if seg_bytes:
                    tc.setConcreteMemoryAreaValue(seg.start_ea, seg_bytes)
                    mapped_count += 1
                else:
                    print(
                        f"[!] Warning: Segment '{seg_name}' at 0x{seg.start_ea:X} is empty or could not be read."
                    )
            except Exception as e:
                print(f"[!] Error mapping segment '{seg_name}': {e}")

    if mapped_count == 0:
        raise RuntimeError("Failed to map any segments into Triton. Cannot proceed.")
    print(f"[+] Segment mapping complete. Mapped {mapped_count} segments.")


def is_state_store(
    ea: int, state_desc: tuple[str, str | int, int | None], imm: int | None = None
) -> bool:
    """True if "ea" is  mov dword [state], imm  (optionally matching imm)."""
    # C7 /0   mov r/m32, imm32
    if ida_bytes.get_byte(ea) != 0xC7 or idc.print_insn_mnem(ea) != "mov":
        return False

    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)

    if insn.itype != ida_allins.NN_mov or insn.ops[0].type != idaapi.o_displ:  # type: ignore
        return False

    # Use the comprehensive analysis
    op_analysis = analyze_operand_comprehensive(insn, insn.ops[0], 0)  # type: ignore

    if op_analysis.get("has_sib", False):
        base = _wide(op_analysis["sib_base_reg"])
        disp = op_analysis["displacement"]
    else:
        base = _wide(op_analysis["base_reg"])
        disp = op_analysis["displacement"]

    if (base, disp) != tuple(state_desc):  # the slot we identified
        print(
            f"[+] {hex(ea)} - {idc.generate_disasm_line(ea, 0)} - not state store ({state_desc}) (base: {base}, disp: {disp})"
        )
        print(op_analysis)
        return False

    return imm is None or insn.ops[1].value == imm  # type: ignore


# Patch dispatcher head to jump to the TRUE entry case.
def patch_head(
    switch_info: idaapi.switch_info_t,
    DISPATCH_EA: int,
    entry_state: int,
    block_ea: dict[int, int],
    pm: PatchManager,
):
    head_start = switch_info.startea
    head_end = DISPATCH_EA + idc.get_item_size(DISPATCH_EA)
    head_len = head_end - head_start

    if entry_state not in block_ea:
        raise RuntimeError(
            f"Entry state {entry_state} not found in block map. Emulation may have failed."
        )
    entry_ea = block_ea[entry_state]  # Use the dynamically found entry state

    disp = entry_ea - (head_start + 5)
    if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
        head_patch = b"\xe9" + struct.pack("<i", disp)
    else:
        head_patch = b"\x48\xb8" + struct.pack("<Q", entry_ea) + b"\xff\xe0"
    pm.add_patch(head_start, head_patch.ljust(head_len, b"\x90"))
    # Update the log message to be accurate.
    print(f"[+] Dispatcher patched to jump to case {entry_state} at 0x{entry_ea:X}")


def simplify_cfg_with_networkx(
    cfunc: idaapi.cfunc_t,
    pre_dispatcher_si: idaapi.switch_info_t,
    main_dispatcher_si: idaapi.switch_info_t,
    state_desc: tuple[str, Any, Any],
    original_block_ea: dict[int, int],
    G: nx.DiGraph,
    pm: PatchManager,
    stack_offset: int,
):
    """
    Simplifies the CFG by linking each state block to its immediate successor.
    """
    print("[+] Starting CFG simplification using NetworkX graph...")

    # --- Step 1: Patch dispatcher head to jump to the true entry point ---
    # This makes the a2=1 logic the default path, bypassing the pre-dispatcher.
    try:
        entry_state = list(G.successors(0))[0]
        entry_ea = original_block_ea[entry_state]

        # We need to NOP out the entire pre-dispatcher switch and the main dispatcher switch
        # to allow the decompiler to correctly form the 'if' statements.
        # The pre-dispatcher is the first switch in the function.
        if not pre_dispatcher_si:
            raise RuntimeError("Could not find pre-dispatcher switch info.")

        # We patch the main dispatcher's switch_info start, which is the
        # jump table for the state machine. This is correct.
        pre_dispatcher_start = pre_dispatcher_si.startea

        # Create a single JMP at the very start of the pre-dispatcher
        disp = entry_ea - (pre_dispatcher_start + 5)
        patch = (
            (b"\xe9" + struct.pack("<i", disp))
            if -0x8000_0000 <= disp <= 0x7FFF_FFFF
            else (b"\x48\xb8" + struct.pack("<Q", entry_ea) + b"\xff\xe0")
        )

        # Calculate the total area to NOP: from the start of the pre-dispatcher
        # to the end of the main dispatcher's jump.
        main_dispatcher_end = main_dispatcher_si.jumps + idaapi.get_item_size(
            main_dispatcher_si.jumps
        )
        nop_len = main_dispatcher_end - (pre_dispatcher_start + len(patch))

        pm.add_patch(pre_dispatcher_start, patch)
        pm.add_patch(pre_dispatcher_start + len(patch), b"\x90" * nop_len)

        print(
            f"[+] Patched pre-dispatcher at 0x{pre_dispatcher_start:X} to jmp to true entry state {entry_state} (0x{entry_ea:X})"
        )

    except (IndexError, KeyError, RuntimeError) as e:
        print(f"[!] Error during entry point patching: {e}")
        raise

    # --- Step 2: Patch all state transitions to jump to their IMMEDIATE successor ---
    print("[+] Finding all state transitions using ctree...")

    state_lvar = None
    target_offset = state_desc[1]
    for lvar in cfunc.get_lvars():
        if lvar.is_stk_var() and lvar.get_stkoff() - stack_offset == target_offset:
            state_lvar = lvar
            break
    if not state_lvar:
        raise RuntimeError(f"Could not find the lvar for stack offset {target_offset}")

    visitor = StateStoreVisitor(state_lvar)
    visitor.apply_to(cfunc.body, None)
    print(f"[+] Found {len(visitor.found_stores)} state-setting instructions to patch.")

    for addr, current_state_val in visitor.found_stores:
        # Find the immediate successor of this state in our graph
        try:
            # Get the next state in the sequence
            next_state = list(G.successors(current_state_val))[0]
            target_ea = original_block_ea[next_state]

            disp = target_ea - (addr + 5)
            patch = (
                (b"\xe9" + struct.pack("<i", disp))
                if -0x8000_0000 <= disp <= 0x7FFF_FFFF
                else (b"\x48\xb8" + struct.pack("<Q", target_ea) + b"\xff\xe0")
            )

            pm.add_patch(addr, patch.ljust(idaapi.get_item_size(addr), b"\x90"))
            print(
                f"[+]   0x{addr:X}: Patched `mov state, {current_state_val}` to jmp to next state {next_state} (0x{target_ea:X})"
            )
        except (IndexError, KeyError):
            # This state might be a terminal state with no successor in the main loop (e.g., an exit)
            # Or it might be a state not found during emulation. We can just NOP it.
            print(
                f"[!]   0x{addr:X}: State {current_state_val} has no successor in graph. NOP'ing."
            )
            pm.add_patch(addr, b"\x90" * idaapi.get_item_size(addr))
    # --- Step 4: NOP tail jumps to dispatcher (Corrected Logic) ---
    print("[+] NOP'ing tail jumps back to dispatcher...")
    nop_count = 0
    # Used to identify jumps to the dispatcher, we're giving ourselves a 16 byte
    # lookbehind. The end is the final 'jmp rax'. The start is a reasonable number of bytes
    # before it to catch all setup instructions (mov, cmp, etc.).
    # This avoids the unreliability of switch_info.startea.
    head_start = main_dispatcher_si.startea - 0x10

    # Iterate through each case block's starting address
    for state, ea in original_block_ea.items():
        # Find the end of this block by finding the start of the next one.
        # This is the robust way to do it.
        next_block_start = min(
            [addr for addr in original_block_ea.values() if addr > ea], default=FUNC_END
        )

        # The last instruction in our block is right before the next block starts.
        tail_ea = idaapi.prev_head(next_block_start, ea)
        if not tail_ea:
            continue
        # print(
        #     f"[+] tail_ea: {hex(tail_ea)} is prev_head of {hex(next_block_start)}  {idc.generate_disasm_line(tail_ea, 0)}"
        # )
        # Check if this last instruction is a JMP instruction
        insn = idautils.DecodeInstruction(tail_ea)
        if insn is None or insn.itype != idaapi.NN_jmp:
            continue
        # Find where it jumps to
        target_ea = idc.get_operand_value(tail_ea, 0)
        # print(f"[+] target_ea {hex(target_ea)} from {hex(tail_ea)}")
        # If the target is anywhere within the dispatcher's setup code, it's a tail jump.
        # print(
        #     f"[+] head_start: {hex(head_start)} <= target_ea: {hex(target_ea)} <= dispatch_ea: {hex(dispatch_ea)}"
        # )
        if head_start <= target_ea <= main_dispatcher_si.jumps:
            jmp_size = idaapi.get_item_size(tail_ea)
            pm.add_patch(tail_ea, b"\x90" * jmp_size)
            nop_count += 1

    print(f"[+] NOP'd {nop_count} tail jumps.")


@functools.lru_cache()
def get_rbp_offset_from_prologue(func_ea: int, prologue_size: int = 20) -> int:
    """Extract the RBP offset from the function prologue.

    The solver needs to operate with idautils.Heads(FUNC_EA) coordinates because
    that's what Triton sees during execution. The power of IDA's decompiler as
    a discovery tool to find semantically interesting variables is much easier to
    work with, but we then translate them to execution coordinates.

    To do that, we examine the prologue to find an RBP offset, if any. In particular,
    we're looking for a lea rbp, [rsp+offset] instruction in the function prologue.

    The offset is the value after the + sign.

    For example, in the following code:

    sub     rsp, 0A8h           ; Allocate 168 bytes on stack
    lea     rbp, [rsp+80h]      ; Set RBP = RSP + 0x80 (128 bytes)

    The offset is 0x80.

    The following diagram illustrates the memory layout:

            Original RSP (function entry)
            |
            | [168 bytes allocated by sub rsp, 0A8h]
            |
            v
        Current RSP ──┐
            |         │
            |         │ 128 bytes (0x80)
            |         │
            v         │
        RBP ──────────┘  [RBP = RSP + 0x80]
            |
            | [40 bytes above RBP]
            |

    The following diagram illustrates the memory layout on why we cannot use the
    decompiler's `get_stkoff_delta()` to get the offset:

            IDA's Internal Logic:
            ┌─────────────────────────────────────┐
            │ "This function uses RBP+0x80 setup" │ ← IDA's expectation
            │ "This is normal, delta = 0"         │ ← get_stkoff_delta() = 0
            └─────────────────────────────────────┘

            Actual Memory Layout:
            ┌─────────────────┐
            │ Stack Bottom    │ ← IDA's reference point (offset 0)
            │                 │
            │ +128 bytes      │
            │                 │
            │ RBP             │ ← Raw instruction reference point
            │                 │
            │ [RBP+28] = +156 │ ← Same memory location, different coordinates
            └─────────────────┘
    """

    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)

    # Make RSP an unconstrained symbolic variable
    ctx.symbolizeRegister(ctx.registers.rsp)

    seen_mov_rbp = False
    insn = Instruction()

    for ea in idautils.Heads(func_ea, func_ea + prologue_size):
        # grab up to 16 bytes at ea
        raw = idaapi.get_bytes(ea, idaapi.get_item_size(ea))
        if not raw:
            continue

        insn.setOpcode(raw)
        insn.setAddress(ea)
        ctx.processing(insn)  # execute symbolically

        mnem = insn.getDisassembly().split()[0]

        # --- Pattern A: lea rbp, [rsp+disp] ---
        if (
            mnem == "lea"
            and insn.getOperands()[0].getType() == OPERAND.REG
            and insn.getOperands()[0].getName() == "rbp"
            and insn.getOperands()[1].getType() == OPERAND.MEM
            and insn.getOperands()[1].getBaseRegister() == ctx.registers.rsp
        ):

            # AST for RBP now is: (bvadd (bvsub sym_rsp, <sub_imm>) <disp>)
            ast = ctx.getSymbolicRegister(ctx.registers.rbp).getAst()
            simp = ctx.simplify(ast)

            # look for the small constant child under the ADD
            for child in simp.getChildren():
                if child.getType() == AST_NODE.BV and child.getBitvectorSize() <= 64:
                    val = child.evaluate()
                    # make sure it’s positive
                    if val & (1 << 63) == 0:
                        return val

        # --- Pattern B: mov rbp, rsp → sub rsp, imm ---
        if (
            mnem == "mov"
            and insn.getOperands()[0].getType() == OPERAND.REG
            and insn.getOperands()[0].getName() == "rbp"
            and insn.getOperands()[1].getType() == OPERAND.REG
            and insn.getOperands()[1].getBaseRegister() == ctx.registers.rsp
        ):
            seen_mov_rbp = True
            continue

        if (
            seen_mov_rbp
            and mnem == "sub"
            and insn.getOperands()[0].getType() == OPERAND.REG
            and insn.getOperands()[0].getName() == "rsp"
            and insn.getOperands()[1].getType() == OPERAND.IMM
        ):
            return insn.getOperands()[1].getValue()

    # nothing found
    return 0


def find_obfuscation_entry_point(
    func_ea: int,
) -> tuple[ida_hexrays.cfuncptr_t, int, idaapi.switch_info_t, int]:
    """
    Analyzes the decompiled C-tree to find the main state machine dispatcher
    and the argument value required to enter it.

    Returns:
        A tuple of (main_dispatcher_ea, main_dispatcher_si, trigger_seed_value).
    """
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        raise RuntimeError(f"Failed to decompile function at 0x{func_ea:X}")

    if not cfunc:
        raise RuntimeError(f"Could not decompile function at 0x{func_ea:X}")

    finder = CTreeSwitchFinder()
    finder.apply_to(cfunc.body, None)  # type: ignore
    all_switches = finder.switches

    if not all_switches:
        raise RuntimeError("Could not find any switch dispatcher in the function.")

    if len(all_switches) == 1:
        print("[+] Found a single switch dispatcher. Assuming default seed.")
        main_dispatcher_insn = all_switches[0]
        # CORRECT: Address is on the expression.
        main_dispatcher_ea = main_dispatcher_insn.expr.ea  # type: ignore
        main_dispatcher_si = idaapi.get_switch_info(main_dispatcher_ea)
        if not main_dispatcher_si:
            raise RuntimeError(
                f"Could not get switch info for dispatcher at 0x{main_dispatcher_insn.ea:X}"
            )
        return cfunc, main_dispatcher_insn.ea, main_dispatcher_si, 1

    pre_dispatcher_insn = None
    main_dispatcher_insn = None
    lvars = cfunc.get_lvars()

    for s_insn in all_switches:
        is_on_argument = False
        # Access the switch data via .cswitch
        if s_insn.expr.op == ida_hexrays.cot_var:  # type: ignore
            var_idx = s_insn.expr.v.idx  # type: ignore
            if lvars[var_idx].is_arg_var:
                is_on_argument = True

        if is_on_argument:
            pre_dispatcher_insn = s_insn
        else:
            main_dispatcher_insn = s_insn

    if not pre_dispatcher_insn or not main_dispatcher_insn:
        pre_dispatcher_insn, main_dispatcher_insn = all_switches[0], all_switches[1]
        print(
            "[!] Could not identify dispatchers by variable type, falling back to order."
        )
    # print(dir(pre_dispatcher_insn))
    # Use .ea to get the address for printing and analysis
    print(f"[+] Identified pre-dispatcher at 0x{pre_dispatcher_insn.expr.ea:X}")  # type: ignore
    print(f"[+] Identified main dispatcher at 0x{main_dispatcher_insn.expr.ea:X}")  # type: ignore

    # Identify the state variable from the main dispatcher's expression
    main_dispatcher_expr = main_dispatcher_insn.expr  # type: ignore
    if main_dispatcher_expr.op != ida_hexrays.cot_var:  # type: ignore
        print("Main dispatcher does not switch on a simple variable.")
        return None, None, None, None  # type: ignore

    state_var_idx = main_dispatcher_expr.v.idx
    state_var_name = lvars[state_var_idx].name
    print(
        f"[+] Main state variable identified as '{state_var_name}' (index {state_var_idx})"
    )

    # Now, search each case of the pre-dispatcher for an assignment to this variable
    for case in pre_dispatcher_insn.cases:  # type: ignore
        checker = CTreeContainsVisitor(state_var_idx)
        checker.apply_to(case, pre_dispatcher_insn.expr)  # type: ignore
        if checker.found:
            print(f"[+] Found state variable initialization in case at 0x{case.ea:X}")
            if not case.values:
                raise RuntimeError(
                    "Main dispatcher is in the default case, cannot determine seed."
                )

            trigger_value = case.values[0]
            main_dispatcher_si = idaapi.get_switch_info(main_dispatcher_insn.expr.ea)  # type: ignore
            if not main_dispatcher_si:
                raise RuntimeError(
                    f"Could not get switch info for dispatcher at 0x{main_dispatcher_insn.ea:X}"
                )

            print(f"[+] Found trigger value: {trigger_value}")
            return cfunc, main_dispatcher_insn.expr.ea, main_dispatcher_si, trigger_value  # type: ignore

    print("Could not find a path from pre-dispatcher to main dispatcher!")
    return None, None, None, None  # type: ignore


def find_main_dispatcher(
    cfunc: ida_hexrays.cfuncptr_t,
) -> tuple[int, idaapi.switch_info_t, int]:
    """
    Finds the main state machine dispatcher switch in the function.
    The main dispatcher is the one that does NOT operate on a function argument.
    """
    lvars = cfunc.get_lvars()
    finder = CTreeSwitchFinder()
    finder.apply_to(cfunc.body, None)

    for s_insn in finder.switches:
        if s_insn.expr.op == ida_hexrays.cot_var:
            var_idx = s_insn.expr.v.idx
            if not lvars[var_idx].is_arg_var:
                # This is our main dispatcher
                main_si = idaapi.get_switch_info(s_insn.expr.ea)
                if main_si:
                    print(f"[+] Found main dispatcher switch at 0x{s_insn.expr.ea:X}")
                    return s_insn.expr.ea, main_si, var_idx

    raise RuntimeError("Could not find the main dispatcher switch.")


def run_solver(
    tc: TritonContext,
    si: idaapi.switch_info_t,
    state_kind: str,
    state_desc: tuple[str, str | int, int | None],
    G: nx.DiGraph,
    mapper: IDAToTritonRegisterMapper,  # The mapper is part of the solver's context
):
    """
    Execute Triton until we've visited every switch case once or until
    `max_steps` is reached.  Safe to call from any thread.
    """

    def within_function(ip: int) -> bool:
        return FUNC_EA <= ip < FUNC_END

    @CheckContinuePrompt(
        metadata={"max_steps": MAX_STEPS},
        cancel_func=lambda: None,
        enable_prompt=True,
    )
    def worker():
        print("[+] Worker started with call-aware emulation loop.")

        # We only care about state changes that happen *inside* the target function.
        # Initialize prev_state when we are inside.
        prev_state = read_state(tc, state_kind, state_desc)
        G.add_node(prev_state)

        steps = 0
        call_depth = 0  # Start at depth 0, in the main function.

        ip = tc.getConcreteRegisterValue(tc.registers.rip)

        while steps < MAX_STEPS:
            # print(f"[+] ip: 0x{ip:X} - {steps}")

            # Stop condition: if we return from the initial function call.
            if call_depth < 0:
                print(
                    f"[+] Emulation returned from initial function at 0x{ip:X}. Stopping."
                )
                break

            # Ensure memory is mapped for the current instruction
            ensure_mapped(tc, ip)

            try:
                size = idaapi.get_item_size(ip)
                if not size:
                    print(f"[!] Could not get instruction size at 0x{ip:X}. Stopping.")
                    break
                opcode = ida_bytes.get_bytes(ip, size)
                if not opcode:
                    print(
                        f"[!] Could not read instruction bytes at 0x{ip:X}. Stopping."
                    )
                    break
            except Exception as e:
                print(f"[!] Error reading instruction at 0x{ip:X}: {e}")
                break

            # Create and process the instruction
            instr = Instruction()
            instr.setAddress(ip)
            instr.setOpcode(opcode)
            mnem = idc.print_insn_mnem(ip)

            # print(f"[+] ip: 0x{ip:X} - {mnem} - (size: {size})")
            # 1) Detect helper CALLs early
            if mnem == "call":
                callee = idc.print_operand(ip, 0)
                if callee:

                    # ––– STUB –––
                    rsp = tc.getConcreteRegisterValue(tc.registers.rsp) - 8
                    tc.setConcreteRegisterValue(tc.registers.rsp, rsp)
                    tc.setConcreteMemoryAreaValue(rsp, struct.pack("<Q", ip + size))
                    tc.setConcreteRegisterValue(tc.registers.rax, 0)
                    print(f"[+] callee:  - stubbed to 0x{ip + size:X} @0x{ip:X}")
                    ip = ip + size
                    steps += 1
                    continue  # skip tc.processing()
            elif mnem == "nop":
                # print(f"[+] nop @0x{ip:X}")
                ip = ip + size
                steps += 1
                continue

            # 2. Early exit on RET/JMP to outside the function
            if is_ret(ip):
                ret_addr = tc.getConcreteMemoryValue(
                    tc.getConcreteRegisterValue(tc.registers.rsp)
                )
                if not within_function(ret_addr):
                    print(f"[!] Early stop on RET @0x{ip:X} to 0x{ret_addr:X}")
                    break

            if is_uncond_jmp_reg(ip):
                # This is tricky as we don't know the register's value without emulation.
                # We'll let tc.processing handle it and the loop condition will catch the exit.
                pass

            # Track call depth
            if False and instr.isControlFlow():
                if mnem == "call":
                    call_depth += 1
                elif mnem == "ret":
                    call_depth -= 1

            try:
                tc.processing(instr)
                # print(
                #     f"[!] Triton failed to process instruction at 0x{ip:X}: {instr.getDisassembly()}"
                # )
                # break
            except Exception as e:
                print(
                    f"[!] Triton exception at 0x{ip:X}:  {instr.getDisassembly()} - error message: {e}"
                )
                traceback.print_exc()
                break

            steps += 1
            if steps % 1000 == 0:
                print(
                    f"[+] 0x{ip:X} - cur_state: {cur_state}, prev_state: {prev_state}"
                )
            # Get the next instruction pointer from the emulator
            next_ip = tc.getConcreteRegisterValue(tc.registers.rip)

            # --- STATE CHANGE RECORDING ---
            # We only care about state transitions that are committed *inside* the target function.
            if within_function(ip):
                cur_state = read_state(tc, state_kind, state_desc)
                if cur_state != prev_state:
                    if not G.has_node(cur_state):
                        print(f"[+] Discovered new state: {cur_state}")

                    G.add_node(prev_state)
                    G.add_node(cur_state)
                    G.add_edge(prev_state, cur_state, ip=ip)

                    print(
                        f"[+] State transition: {prev_state} -> {cur_state} at 0x{ip:X} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)"
                    )
                    prev_state = cur_state

                # --- Intelligent Stop Condition ---
                if G.number_of_nodes() >= si.ncases:
                    if G.has_node(cur_state) and G.out_degree(cur_state) > 0:
                        print(
                            f"[+] All {si.ncases} states discovered and returned to a known path. Stopping."
                        )
                        break

            # Update ip for the next iteration
            ip = next_ip

        print(
            f"[+] Solver finished. Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges in {steps} steps."
        )

    # run the worker in a cancel-able background job
    ida_kernwin.execute_sync(worker, ida_kernwin.MFF_FAST)


def main():
    print(f"[+] analyzing 0x{FUNC_EA:X}..0x{FUNC_END:X}")

    try:
        cfunc = ida_hexrays.decompile(FUNC_EA)
    except ida_hexrays.DecompilationFailure:
        raise RuntimeError(f"Failed to decompile function at 0x{FUNC_EA:X}")

    # --- Step 1 & 2: Find the main dispatcher and the state variable ---
    lvars = cfunc.get_lvars()
    finder = CTreeSwitchFinder()
    finder.apply_to(cfunc.body, None)

    main_dispatcher_switch = None
    pre_dispatcher_switch = None

    for s_insn in finder.switches:
        if s_insn.expr.op == ida_hexrays.cot_var:
            var_idx = s_insn.expr.v.idx
            if lvars[var_idx].is_arg_var:
                pre_dispatcher_switch = s_insn
            else:
                main_dispatcher_switch = s_insn

    if not main_dispatcher_switch or not pre_dispatcher_switch:
        raise RuntimeError("Could not distinguish pre-dispatcher and main dispatcher.")

    main_dispatcher_si = idaapi.get_switch_info(main_dispatcher_switch.expr.ea)
    state_var_idx = main_dispatcher_switch.expr.v.idx
    state_lvar = cfunc.get_lvars()[state_var_idx]
    dispatch_ea = main_dispatcher_switch.expr.ea
    print(f"[+] Main dispatcher at 0x{dispatch_ea:X} on var '{state_lvar.name}'")

    # --- Step 3: Isolate the 'case 1' block and find the state-set within it ---
    case_1_block = pre_dispatcher_switch.cases[0]
    target_seed = case_1_block.values[0]

    entry_visitor = StateStoreVisitor(state_lvar)
    entry_visitor.apply_to(case_1_block, None)
    if not entry_visitor.found_stores:
        raise RuntimeError(
            f"Could not find the state-setting instruction within 'case {target_seed}:'"
        )

    true_entry_patch_addr, initial_state_val = entry_visitor.found_stores[0]
    print(
        f"[+] Found true entry point: instruction at 0x{true_entry_patch_addr:X} sets state to {initial_state_val}"
    )

    # --- Step 4: Emulate to build the graph ---
    print(f"[+] Emulating with seed value a2 = {target_seed} to trace the main logic.")
    tc = TritonContext()
    tc.setArchitecture(ARCH.X86_64)
    tc.setMode(MODE.ALIGNED_MEMORY, False)  # Keep this for robustness
    mapper = IDAToTritonRegisterMapper(tc)

    map_all_segments(tc)
    tc.setConcreteMemoryAreaValue(TEB_AREA, bytearray(TEB_SIZE))
    tc.setConcreteRegisterValue(tc.registers.gs, TEB_AREA)
    tc.setConcreteMemoryAreaValue(DUMMY_ARG_REGION, bytearray(DUMMY_ARG_SIZE))
    tc.setConcreteMemoryAreaValue(STACK_TOP - STACK_SIZE, bytearray(STACK_SIZE))

    tc.setConcreteRegisterValue(tc.registers.rip, FUNC_EA)
    tc.setConcreteRegisterValue(tc.registers.rsp, STACK_TOP - 8)
    tc.setConcreteRegisterValue(tc.registers.rbp, STACK_TOP)

    # Set the arguments for this specific run
    tc.setConcreteRegisterValue(tc.registers.rcx, DUMMY_ARG_REGION)
    tc.setConcreteRegisterValue(tc.registers.rdx, target_seed)

    stack_offset = get_rbp_offset_from_prologue(FUNC_EA)
    state_kind, *state_desc = guess_state_var2(cfunc, dispatch_ea, stack_offset)
    print(f"[+] State variable is a {state_kind}: {state_desc}")

    G = nx.DiGraph()
    run_solver(tc, main_dispatcher_si, state_kind, state_desc, G, mapper)  # type: ignore

    if G.number_of_edges() == 0:
        print(
            "[!] Emulation did not produce any state transitions. Cannot deobfuscate."
        )
        return

    # --- Final, Corrected Patching ---
    pm = PatchManager(dry_run=not ENABLE_PATCHING)
    original_block_ea = get_switch_mapping(main_dispatcher_si, dispatch_ea)

    # 4a: Patch the true entry point (`n2 = 2;`)
    try:
        # The target is the block corresponding to the value being set.
        target_state = initial_state_val  # This is 2
        target_ea = original_block_ea[target_state]

        success, patch_bytes = idautils.Assemble(
            true_entry_patch_addr, f"jmp {target_ea}"
        )
        if not success:
            raise RuntimeError(
                f"Failed to assemble jump at 0x{true_entry_patch_addr:X}"
            )
        assert isinstance(patch_bytes, bytes)
        pm.add_patch(
            true_entry_patch_addr,
            patch_bytes.ljust(idaapi.get_item_size(true_entry_patch_addr), b"\x90"),
        )
        print(
            f"[+] Patched true entry at 0x{true_entry_patch_addr:X} to jmp to state {target_state} (0x{target_ea:X})"
        )
    except (IndexError, KeyError, RuntimeError) as e:
        raise RuntimeError(f"Could not patch true entry point: {e}")

    all_main_dispatcher_stores = []
    for case_block in main_dispatcher_switch.cases:
        case_visitor = StateStoreVisitor(state_lvar)
        # Apply the visitor to the c-block of each case
        case_visitor.apply_to(case_block, None)
        # Add any found stores to our master list
        all_main_dispatcher_stores.extend(case_visitor.found_stores)

    print(
        f"[+] Found {len(all_main_dispatcher_stores)} state-setting instructions within the main dispatcher to patch."
    )

    for addr, current_state_val in all_main_dispatcher_stores:
        try:
            # The target is the block corresponding to the value being set.
            target_state = current_state_val
            if target_state not in original_block_ea:
                print(
                    f"[!] Warning: State {target_state} has no corresponding case block. NOP'ing at 0x{addr:X}."
                )
                pm.add_patch(addr, b"\x90" * idaapi.get_item_size(addr))
                continue

            target_ea = original_block_ea[target_state]

            success, patch_bytes = idautils.Assemble(addr, f"jmp {target_ea}")
            if not success:
                print(
                    f"[!] Warning: Failed to assemble jump at 0x{addr:X}. Skipping patch."
                )
                continue
            assert isinstance(patch_bytes, bytes)
            pm.add_patch(addr, patch_bytes.ljust(idaapi.get_item_size(addr), b"\x90"))
            print(
                f"[+]   0x{addr:X}: Patched `mov state, {current_state_val}` to jmp to state {target_state} (0x{target_ea:X})"
            )
        except Exception as e:
            print(f"[!] Error patching 0x{addr:X}: {e}. NOP'ing.")
            pm.add_patch(addr, b"\x90" * idaapi.get_item_size(addr))
    # 4c: NOP out the main dispatcher's jump table
    # pm.add_patch(dispatch_ea, b"\x90" * idaapi.get_item_size(dispatch_ea))
    # This replaces the previous, less complete NOP'ing logic.
    nop_len = (
        dispatch_ea - main_dispatcher_si.defjump + idaapi.get_item_size(dispatch_ea)
    )

    if nop_len > 0:
        print(
            f"[+] NOP'ing entire switch mechanism from 0x{main_dispatcher_si.defjump:X} to 0x{main_dispatcher_switch.expr.ea:X} ({nop_len} bytes)"
        )
        pm.add_patch(main_dispatcher_si.defjump, b"\x90" * nop_len)
    else:
        print(f"[!] Warning: Could not determine size of switch mechanism to NOP.")

    pm.apply_all()

    # Final cleanup and re-analysis
    ida_xref.delete_switch_table(main_dispatcher_si.startea, main_dispatcher_si)
    ida_nalt.del_switch_info(main_dispatcher_si.startea)
    print("[+] Re-analyzing function...")
    ida_auto.auto_mark_range(FUNC_EA, FUNC_END, ida_auto.AU_USED)
    ida_auto.auto_wait()

    print("[+] Patching complete – press <F5> in IDA to re-decompile")
    print("[✓] done")


if __name__ == "__main__":
    main()
