"""
unflatten_virtualized_api_resolver.py
------------------------------------

Run inside IDA Pro (tested 8.3 & 9.3) with Triton 1.1-dev.

pip install --target=<IDA>/python python-triton==1.1 networkx graphviz
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

import triton
from triton import ARCH, CALLBACK, MODE, Instruction, TritonContext

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

# ──────────────────────────────────────────────────────────────────────
# 1. Gather basic info
# ──────────────────────────────────────────────────────────────────────
if FUNC_EA == idc.BADADDR:
    raise RuntimeError(f"label {FUNC_EA:X} not found")


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
        print(
            "looking for",
            self.state_var_idx,
            " and im currently at",
            idc.generate_disasm_line(insn.ea, 0),
        )
        print(
            insn.op,
            " looking for",
            ida_hexrays.cot_asg,
            " -- ",
            idc.get_operand_value(insn.ea, 0),
            " ++ ",
            idc.get_operand_value(insn.ea, 1),
        )
        if self.found:
            return 1  # Stop traversal
        # We are looking for an assignment instruction, e.g., `v1 = 0;`
        if idc.get_operand_value(insn.ea, 1) == ida_hexrays.cot_asg:
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


def find_obfuscation_entry_point(func_ea: int) -> tuple[int, idaapi.switch_info_t, int]:
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
    finder.apply_to(cfunc.body, None)
    all_switches = finder.switches

    if not all_switches:
        raise RuntimeError("Could not find any switch dispatcher in the function.")

    if len(all_switches) == 1:
        print("[+] Found a single switch dispatcher. Assuming default seed.")
        main_dispatcher_insn = all_switches[0]
        # CORRECT: Address is on the expression.
        main_dispatcher_ea = main_dispatcher_insn.expr.ea
        main_dispatcher_si = idaapi.get_switch_info(main_dispatcher_ea)
        if not main_dispatcher_si:
            raise RuntimeError(
                f"Could not get switch info for dispatcher at 0x{main_dispatcher_insn.ea:X}"
            )
        return main_dispatcher_insn.ea, main_dispatcher_si, 1

    pre_dispatcher_insn = None
    main_dispatcher_insn = None
    lvars = cfunc.get_lvars()

    for s_insn in all_switches:
        is_on_argument = False
        # Access the switch data via .cswitch
        if s_insn.expr.op == ida_hexrays.cot_var:
            var_idx = s_insn.expr.v.idx
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
    print(f"[+] Identified pre-dispatcher at 0x{pre_dispatcher_insn.expr.ea:X}")
    print(f"[+] Identified main dispatcher at 0x{main_dispatcher_insn.expr.ea:X}")

    # Identify the state variable from the main dispatcher's expression
    main_dispatcher_expr = main_dispatcher_insn.expr
    if main_dispatcher_expr.op != ida_hexrays.cot_var:
        print("Main dispatcher does not switch on a simple variable.")
        return None, None, None

    state_var_idx = main_dispatcher_expr.v.idx
    state_var_name = lvars[state_var_idx].name
    print(
        f"[+] Main state variable identified as '{state_var_name}' (index {state_var_idx})"
    )

    # Now, search each case of the pre-dispatcher for an assignment to this variable
    for case in pre_dispatcher_insn.cases:
        checker = CTreeContainsVisitor(state_var_idx)
        checker.apply_to(case, pre_dispatcher_insn.expr)
        if checker.found:
            print(f"[+] Found state variable initialization in case at 0x{case.ea:X}")
            if not case.values:
                raise RuntimeError(
                    "Main dispatcher is in the default case, cannot determine seed."
                )

            trigger_value = case.values[0]
            main_dispatcher_si = idaapi.get_switch_info(main_dispatcher_insn.expr.ea)
            if not main_dispatcher_si:
                raise RuntimeError(
                    f"Could not get switch info for dispatcher at 0x{main_dispatcher_insn.ea:X}"
                )

            print(f"[+] Found trigger value: {trigger_value}")
            return main_dispatcher_insn.expr.ea, main_dispatcher_si, trigger_value

    print("Could not find a path from pre-dispatcher to main dispatcher!")
    return None, None, None


print(f"[+] analysing 0x{FUNC_EA:X}..0x{FUNC_END:X}")

# Use the new Hex-Rays based function to get all the info we need
DISPATCH_EA, switch_info, SEED_VALUE = find_obfuscation_entry_point(FUNC_EA)
if not all((DISPATCH_EA, switch_info, SEED_VALUE)):
    raise RuntimeError("Failed to find obfuscation entry point")

print(f"[+] Main dispatcher at 0x{DISPATCH_EA:X} -> {switch_info.ncases} cases")
print(f"[+] Using seed value {SEED_VALUE} for the second function argument (RDX).")


# ──────────────────────────────────────────────────────────────────────
# 2. Triton initialisation
# ──────────────────────────────────────────────────────────────────────
tc = TritonContext()
tc.setArchitecture(ARCH.X86_64)
tc.setMode(MODE.ALIGNED_MEMORY, True)
tc.setMode(MODE.SYMBOLIZE_LOAD, False)
tc.setMode(MODE.SYMBOLIZE_STORE, False)
mapper = IDAToTritonRegisterMapper(tc)


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


tc.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, hook_call)

# Load the function's bytes into Triton memory
for ea in idautils.FuncItems(FUNC_EA):
    tc.setConcreteMemoryAreaValue(ea, idc.get_bytes(ea, idc.get_item_size(ea)))


tc.setConcreteMemoryAreaValue(STACK_TOP - STACK_SIZE, bytearray(STACK_SIZE))
tc.setConcreteRegisterValue(tc.registers.rip, FUNC_EA)
tc.setConcreteRegisterValue(tc.registers.rsp, STACK_TOP)  # dummy stack
tc.setConcreteRegisterValue(tc.registers.rbp, STACK_TOP)

# Seed argument in correct register (Windows x64: RCX, RDX)
tc.setConcreteRegisterValue(tc.registers.rcx, 0x600000)  # fake &bytecodeTable
tc.setConcreteRegisterValue(tc.registers.rdx, SEED_VALUE)


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
        return idaapi.as_signed(op.disp, op.dtype)
    elif op.type == idaapi.o_mem:
        return idaapi.as_signed(op.addr, op.dtype)
    elif op.type == idaapi.o_phrase and hasattr(op, "disp"):
        return idaapi.as_signed(op.disp, op.dtype)
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


def guess_state_var() -> tuple[str, str | int, int | None]:
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


state_kind, *state_desc = guess_state_var()
print(f"[+] state variable is a {state_kind}: {state_desc}")

# If the state variable lives on the stack, give it an initial value 0.
if state_kind == "stk":
    base_reg, disp = state_desc
    addr = tc.getConcreteRegisterValue(tc.registers.rbp) + (
        disp if base_reg == idautils.procregs.bp.reg else 0
    )
    tc.setConcreteMemoryValue(addr, 0)


# ──────────────────────────────────────────────────────────────────────
# 3. Emulation loop – record transitions
# ──────────────────────────────────────────────────────────────────────


def simplify_control_flow_graph(
    block_ea: dict[int, int], func_end: int
) -> dict[int, int]:
    """
    Resolves redirector blocks in a state machine.
    A redirector block is a case that only contains a 'goto' to another case's label.

    Args:
        block_ea: A map of {state: address}.
        func_end: The end address of the function.

    Returns:
        A simplified map of {state: resolved_address}.
    """
    print("[+] Simplifying control flow graph...")
    resolved_ea = {}

    # Create a reverse map for easy label lookup
    addr_to_state = {v: k for k, v in block_ea.items()}

    for state in sorted(block_ea.keys()):
        current_addr = block_ea[state]

        # Follow the chain of jumps
        visited_addrs = {current_addr}
        while True:
            # Determine the end of the current block
            next_state_addr = min(
                [addr for addr in block_ea.values() if addr > current_addr],
                default=func_end,
            )

            # Check if this block is just a single, unconditional jump
            heads = list(idautils.Heads(current_addr, next_state_addr))

            # Find the first non-NOP instruction
            first_real_insn_ea = idaapi.BADADDR
            for head in heads:
                if idc.print_insn_mnem(head) not in ("nop", ""):
                    first_real_insn_ea = head
                    break

            if first_real_insn_ea == idaapi.BADADDR:
                # Empty block, something is wrong or it's a dead end. Stop.
                break

            insn = idaapi.insn_t()
            if not (
                idaapi.decode_insn(insn, first_real_insn_ea)
                and insn.itype == ida_allins.NN_jmp
            ):
                # This block has real code (it doesn't start with a jmp). This is our final target.
                break

            # It's a jump. Is it the *only* instruction?
            # A simple check: is the next instruction address the end of our block?
            next_head = idaapi.next_head(first_real_insn_ea, next_state_addr)
            if next_head != idaapi.BADADDR and next_head < next_state_addr:
                # There are more instructions after the jump. This is real code.
                break

            # This is a redirector block. Get the target.
            target_addr = insn.ops[0].addr

            if target_addr in visited_addrs:
                print(
                    f"[!] Detected loop in jump chain at 0x{target_addr:X}. Stopping resolution."
                )
                current_addr = (
                    target_addr  # Break the loop but resolve to the loop start
                )
                break

            # Continue chasing the jump
            current_addr = target_addr
            visited_addrs.add(current_addr)

        if block_ea[state] != current_addr:
            print(
                f"[+]   State {state} (0x{block_ea[state]:X}) resolved to 0x{current_addr:X}"
            )

        resolved_ea[state] = current_addr

    return resolved_ea


def get_switch_mapping(si: idaapi.switch_info_t) -> dict[int, int]:
    cat = idaapi.calc_switch_cases(DISPATCH_EA, si)  # IDA ≥ 8.0 form
    cases, targets = cat.cases, cat.targets
    mapping = {}
    for i in range(targets.size()):
        tgt = targets[i]
        mapping.update({int(cv): tgt for cv in cases[i]})
    return mapping


Edge = namedtuple("Edge", "src dst ip")


edges: set[Edge] = set()
original_block_ea: dict[int, int] = get_switch_mapping(switch_info)
block_ea = simplify_control_flow_graph(original_block_ea, FUNC_END)
visited: set[int] = set()
steps = 0


# ─── 2. helper to turn that name into a Triton Register ───────────────
def triton_reg(name: str):
    # Triton register names are all lower-case
    return mapper.map_register(name)
    # return getattr(tc.registers, name.lower())


def load_dword(addr: int) -> int:
    """Little-endian 32-bit load from Triton memory."""
    return int.from_bytes(tc.getConcreteMemoryAreaValue(addr, 4), "little")


def store_dword(addr: int, value: int):
    tc.setConcreteMemoryAreaValue(addr, value.to_bytes(4, "little"))


# ----------------------------------------------------------------------
# read/write the dispatcher state
# ----------------------------------------------------------------------
def read_state() -> int:
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
        base_reg, disp = state_desc
        base = tc.getConcreteRegisterValue(getattr(tc.registers, base_reg.lower()))
        return int.from_bytes(tc.getConcreteMemoryAreaValue(base + disp, 4), "little")

    if state_kind == "mem":
        addr = state_desc[0]
        return int.from_bytes(tc.getConcreteMemoryAreaValue(addr, 4), "little")

    raise RuntimeError(f"unknown state_kind {state_kind!r}")


def write_state(value: int):
    """Update the dispatcher's state variable (32-bit)."""
    value &= 0xFFFFFFFF
    if state_kind == "reg":
        (reg_name,) = state_desc
        tc.setConcreteRegisterValue(triton_reg(reg_name), value)
    elif state_kind == "stk":
        base_reg_name, disp = state_desc
        base = tc.getConcreteRegisterValue(triton_reg(base_reg_name))
        store_dword(base + disp, value)
    elif state_kind == "mem":
        (ea,) = state_desc
        store_dword(int(ea), value)
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


def ensure_mapped(ea: int):
    if tc.isConcreteMemoryValueDefined(ea, 1):
        return
    seg = idaapi.getseg(ea)
    if seg:
        tc.setConcreteMemoryAreaValue(
            seg.start_ea, ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
        )


def run_solver(si: idaapi.switch_info_t):
    """
    Execute Triton until we've visited every switch case once or until
    `max_steps` is reached.  Safe to call from any thread.
    """

    @CheckContinuePrompt(
        metadata={"max_steps": MAX_STEPS},
        cancel_func=lambda: None,
        enable_prompt=True,
    )
    def worker():
        print(f"[+] worker started")
        prev_state = read_state()
        steps = 0
        while steps < MAX_STEPS:
            ip = tc.getConcreteRegisterValue(tc.registers.rip)
            ensure_mapped(ip)
            # -- hard stop: left function -----------------------------
            if not (FUNC_EA <= ip < func_end):
                print(f"[!] left function at 0x{ip:X}")
                break
            size = idc.get_item_size(ip)
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
                    tc.setConcreteRegisterValue(tc.registers.rip, ip + size)

                    continue  # skip tc.processing()
            elif mnem == "nop" or mnem == "jmp":
                tc.setConcreteRegisterValue(tc.registers.rip, ip + size)
                continue

            # -- single-step ------------------------------------------
            try:
                instr = Instruction()
                instr.setOpcode(idc.get_bytes(ip, 16))  # max
                instr.setAddress(ip)
                tc.processing(instr)
            except Exception as e:
                print(f"[!] Triton error @0x{ip:X}: {e}")
                break

            steps += 1

            # -- early stop on RET/JMP --------------------------------
            if is_ret(ip) or is_uncond_jmp_reg(ip):
                print(f"[!] early stop on RET/JMP @0x{ip:X}")
                break

            # -- record state change ----------------------------------
            cur_state = read_state()
            if steps % 1000 == 0:
                print(
                    f"[+] 0x{ip:X} - cur_state: {cur_state}, prev_state: {prev_state}"
                )
            if cur_state != prev_state:
                edges.add(Edge(prev_state, cur_state, ip))
                prev_state = cur_state
            visited.add(cur_state)
            if len(visited) == si.ncases:
                if cur_state == 0:
                    print(f"[!] visited all {si.ncases} cases")
                    break
        print(f"[+] visited {len(edges)} edges in {steps} steps")

    # run the worker in a cancel-able background job
    ida_kernwin.execute_sync(worker, ida_kernwin.MFF_FAST)


run_solver(switch_info)


if GRAPH_DOT:
    # ──────────────────────────────────────────────────────────────────────
    # 4. Build graph and show
    # ──────────────────────────────────────────────────────────────────────
    import networkx as nx

    G = nx.DiGraph()
    for e in edges:
        G.add_edge(e.src, e.dst)

    # Save .dot & render to PDF
    with tempfile.NamedTemporaryFile(
        dir="herpa", suffix=".dot", delete=False
    ) as dot_file:
        dot_name = dot_file.name
        nx.drawing.nx_pydot.write_dot(G, dot_name)
        print(f"[+] graph written to {dot_name}")


def is_state_store(ea: int, imm: int | None = None) -> bool:
    """True if "ea" is  mov dword [state], imm  (optionally matching imm)."""
    # C7 /0   mov r/m32, imm32
    if ida_bytes.get_byte(ea) != 0xC7 or idc.print_insn_mnem(ea) != "mov":
        return False

    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)

    if insn.itype != ida_allins.NN_mov or insn.ops[0].type != idaapi.o_displ:
        return False

    # Use the comprehensive analysis
    op_analysis = analyze_operand_comprehensive(insn, insn.ops[0], 0)

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

    return imm is None or insn.ops[1].value == imm


# Find the true entry state from the emulation trace.
# It's the destination state from the initial state (which we know is 0).
try:
    entry_state = next(edge.dst for edge in edges if edge.src == 0)
except StopIteration:
    raise RuntimeError(
        "Could not determine the entry state from the emulation trace. "
        "The state machine may not have been entered correctly."
    )

print(f"[+] True entry state determined to be: {entry_state}")

pm = PatchManager(dry_run=not ENABLE_PATCHING)


# Patch dispatcher head to jump to the TRUE entry case.
def patch_head():
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


print("[+] Preserving pre-dispatcher logic at case 0")
# Patch each block's state-setting instructions
# for state in sorted(block_ea.keys()):
#     ea = block_ea[state]
#     # Determine block end (next block or function end)
#     next_state = min([s for s in block_ea if s > state], default=None)
#     next_ea = block_ea[next_state] if next_state is not None else FUNC_END

#     # Patch all mov [state], imm instructions
#     for head in idautils.Heads(ea, next_ea):
#         try:
#             is_state_var = is_state_store(head)
#         except Exception as e:
#             print(f"[!] Error checking state store at 0x{head:X}: {e}")
#             print(f"[!] {idc.generate_disasm_line(head, 0)}")
#             tb_str = "".join(
#                 traceback.format_exception(e.__class__, e, e.__traceback__)
#             )
#             print(tb_str)
#             exit(1)
#         else:
#             if not is_state_var:
#                 continue

#         imm = idc.get_operand_value(head, 1)
#         if imm not in block_ea:
#             continue

#         target_ea = block_ea[imm]
#         disp = target_ea - (head + 5)
#         if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
#             patch = b"\xe9" + struct.pack("<i", disp)
#         else:
#             patch = b"\x48\xb8" + struct.pack("<Q", target_ea) + b"\xff\xe0"
#         mov_size = idc.get_item_size(head)  # Typically 7 bytes
#         pm.add_patch(head, patch.ljust(mov_size, b"\x90"))
#         print(f"[+] 0x{head:X}: Patched mov [state], {imm} to jmp 0x{target_ea:X}")
# Patch each block's state-setting instructions USING THE SIMPLIFIED MAP
for state in sorted(original_block_ea.keys()):  # Iterate over original states
    ea = original_block_ea[state]  # The physical address of the block

    # Determine block end (next physical block or function end)
    next_state_addr = min(
        [addr for addr in original_block_ea.values() if addr > ea], default=FUNC_END
    )

    # Patch all mov [state], imm instructions within this physical block
    for head in idautils.Heads(ea, next_state_addr):
        if not is_state_store(head):
            continue

        imm = idc.get_operand_value(head, 1)
        if imm not in block_ea:  # Use the resolved map here
            # This state transition leads to a block we couldn't map.
            # Could be an exit state.
            continue

        # The magic is here: we get the *final* target from our simplified map
        target_ea = block_ea[imm]

        disp = target_ea - (head + 5)
        if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
            patch = b"\xe9" + struct.pack("<i", disp)
        else:
            patch = b"\x48\xb8" + struct.pack("<Q", target_ea) + b"\xff\xe0"
        mov_size = idc.get_item_size(head)
        pm.add_patch(head, patch.ljust(mov_size, b"\x90"))
        print(f"[+] 0x{head:X}: Patched mov [state], {imm} to jmp 0x{target_ea:X}")
    # --- CORRECTED TAIL JUMP PATCHING LOGIC ---

    # Patch the tail jump to NOPs ONLY if it's a jmp to the main dispatcher
    tail_ea = idc.prev_head(next_state_addr, ea)
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, tail_ea) and insn.itype == ida_allins.NN_jmp:
        # Check if it's an unconditional jmp (not a jcc)
        # For x86/x64, NN_jmp is unconditional.

        # Get the jump target address
        op = insn.ops[0]
        target_ea = idaapi.BADADDR
        if op.type == idaapi.o_near:
            target_ea = op.addr

        # Only patch the jump if it explicitly goes back to the dispatcher head
        if target_ea == DISPATCH_EA:
            jmp_size = idc.get_item_size(tail_ea)
            pm.add_patch(tail_ea, b"\x90" * jmp_size)
            print(f"[+] 0x{tail_ea:X}: Tail jump to dispatcher patched to NOPs")
        else:
            # This is a jump, but not to our dispatcher. Leave it alone.
            # This is critical for preserving the logic of nested dispatchers.
            print(
                f"[+] 0x{tail_ea:X}: Skipping tail jump patch (target is 0x{target_ea:X}, not dispatcher)"
            )
    else:
        # The last instruction is not a jmp, so there's nothing to patch.
        # This is expected for blocks that end in 'retn'.
        print(f"[+] 0x{tail_ea:X}: Skipping tail patch (not a jmp instruction)")
        
pm.apply_all()

# Clean up and re-analyze
ida_xref.delete_switch_table(DISPATCH_EA, switch_info)
ida_nalt.del_switch_info(DISPATCH_EA)
ida_auto.auto_mark_range(FUNC_EA, FUNC_END, ida_auto.AU_USED)
ida_auto.auto_wait()
print("[+] Patching complete – press <Space> in IDA to re-decompile")

print("[✓] done")
