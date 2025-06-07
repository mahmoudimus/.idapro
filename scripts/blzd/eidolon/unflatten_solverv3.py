"""
unflatten_virtualized_api_resolver.py (Enhanced with Multi-Pass NetworkX CFG)
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
from collections import defaultdict, namedtuple
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# NetworkX for advanced CFG operations
import networkx as nx
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
ENABLE_PATCHING = False  # True → rewrite code
MAX_STEPS = 250000  # safety
GRAPH_DOT = False
USE_MULTIPASS = True  # Set to True to use NetworkX multi-pass approach

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
            return TraversalEnum.STOP  # Stop traversal
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


# ──────────────────────────────────────────────────────────────────────
# Multi-Pass NetworkX CFG Classes
# ──────────────────────────────────────────────────────────────────────


@dataclass
class SwitchDescriptor:
    """Describes a discovered switch statement."""

    ea: int  # Address of the switch
    switch_info: idaapi.switch_info_t
    switch_var_idx: int  # Variable index being switched on
    switch_var_name: str  # Variable name
    cases: Dict[int, int]  # case_value -> case_ea mapping
    parent_switch: Optional["SwitchDescriptor"] = None
    nested_switches: List["SwitchDescriptor"] = dataclasses.field(default_factory=list)


@dataclass
class CFGNode:
    """Represents a node in the control flow graph."""

    state_id: int
    ea: int
    switch_level: int
    switch_descriptor: SwitchDescriptor
    is_parameter_dependent: bool = False
    preserve_original: bool = False


@dataclass
class ControlFlowEdge:
    """Represents a control flow transition."""

    src_state: int
    dst_state: int
    ea: int
    switch_level: int  # Which switch level this edge belongs to
    switch_descriptor: SwitchDescriptor


class MultiPassUnflattener:
    """Multi-pass control flow unflattener for obfuscated switch statements."""

    def __init__(self, func_ea: int):
        self.func_ea = func_ea
        self.func_end = idaapi.get_func(func_ea).end_ea
        self.discovered_switches: List[SwitchDescriptor] = []
        self.switch_hierarchy: Dict[int, List[SwitchDescriptor]] = defaultdict(list)
        self.all_edges: List[ControlFlowEdge] = []

        # NetworkX graphs for different switch levels
        self.parameter_cfg = nx.DiGraph()  # Parameter-dependent control flow
        self.state_machine_cfg = nx.DiGraph()  # Obfuscated state machine flow
        self.merged_cfg = nx.DiGraph()  # Final merged control flow

        # Node and edge metadata
        self.cfg_nodes: Dict[int, CFGNode] = {}
        self.linear_order: List[int] = []

    def discover_all_switches(self) -> List[SwitchDescriptor]:
        """Pass 1: Discover all switch statements in the function."""
        try:
            cfunc = ida_hexrays.decompile(self.func_ea)
        except ida_hexrays.DecompilationFailure:
            raise RuntimeError(f"Failed to decompile function at 0x{self.func_ea:X}")

        finder = CTreeSwitchFinder()
        finder.apply_to(cfunc.body, None)  # type: ignore

        lvars = cfunc.get_lvars()
        main_switch_found = False

        for switch_insn in finder.switches:
            # Get switch info
            switch_ea = switch_insn.expr.ea  # type: ignore
            switch_info_local = idaapi.get_switch_info(switch_ea)
            if not switch_info_local:
                continue

            # Get variable info
            if switch_insn.expr.op != ida_hexrays.cot_var:  # type: ignore
                continue

            var_idx = switch_insn.expr.v.idx  # type: ignore
            var_name = lvars[var_idx].name

            # Get case mapping
            cases = get_switch_mapping(switch_info_local)

            descriptor = SwitchDescriptor(
                ea=switch_ea,
                switch_info=switch_info_local,
                switch_var_idx=var_idx,
                switch_var_name=var_name,
                cases=cases,
            )
            # Mark if this is the main dispatcher we already found
            if switch_ea == DISPATCH_EA:
                main_switch_found = True
                print(
                    f"[+] Found main dispatcher switch: {var_name} at 0x{switch_ea:X}"
                )
            else:
                print(f"[+] Found additional switch: {var_name} at 0x{switch_ea:X}")
            self.discovered_switches.append(descriptor)

        # If CTreeSwitchFinder missed switches that find_obfuscation_entry_point found,
        # we need to ensure we have both the parameter switch and state machine switch
        if len(self.discovered_switches) < 2:
            print(
                f"[!] Only found {len(self.discovered_switches)} switches, but expected parameter + state machine switches"
            )
            print(
                f"[!] This might be because the parameter switch is implemented as if/else rather than switch"
            )

            # Create a synthetic descriptor for the parameter logic if missing
            if len(self.discovered_switches) == 1 and main_switch_found:
                print("[+] Creating synthetic parameter switch descriptor")
                param_descriptor = SwitchDescriptor(
                    ea=FUNC_EA,  # Function start as parameter entry
                    switch_info=None,  # No switch_info for if/else logic
                    switch_var_idx=-1,  # Synthetic
                    switch_var_name="a2_parameter",  # Parameter name
                    cases={0: FUNC_EA},  # Synthetic case mapping
                )
                self.discovered_switches.insert(
                    0, param_descriptor
                )  # Insert at beginning

        print(f"[+] Discovered {len(self.discovered_switches)} switch statements")
        return self.discovered_switches

    def build_switch_hierarchy(self):
        """Pass 2: Build hierarchy of nested switches."""
        # Sort switches by address to establish containment relationships
        switches_by_addr = sorted(self.discovered_switches, key=lambda s: s.ea)

        for i, switch in enumerate(switches_by_addr):
            # Check if this switch is contained within any case of a previous switch
            for prev_switch in switches_by_addr[:i]:
                if self._is_switch_nested_in_case(switch, prev_switch):
                    switch.parent_switch = prev_switch
                    prev_switch.nested_switches.append(switch)
                    break

        # Organize by levels
        for switch in self.discovered_switches:
            level = self._get_switch_level(switch)
            self.switch_hierarchy[level].append(switch)

        print(f"[+] Built hierarchy with {len(self.switch_hierarchy)} levels")

    def _is_switch_nested_in_case(
        self, nested_switch: SwitchDescriptor, parent_switch: SwitchDescriptor
    ) -> bool:
        """Check if nested_switch is contained within a case of parent_switch."""
        nested_ea = nested_switch.ea

        # Check each case of the parent switch
        for case_value, case_ea in parent_switch.cases.items():
            # Find the end of this case (start of next case or end of switch)
            case_end = self._get_case_end(parent_switch, case_value)

            if case_ea <= nested_ea < case_end:
                return True
        return False

    def _get_case_end(self, switch: SwitchDescriptor, case_value: int) -> int:
        """Get the end address of a specific case."""
        case_start = switch.cases[case_value]

        # Find next case or end of function
        next_case_start = min(
            (ea for ea in switch.cases.values() if ea > case_start),
            default=self.func_end,
        )

        return next_case_start

    def _get_switch_level(self, switch: SwitchDescriptor) -> int:
        """Get the nesting level of a switch (0 = top level)."""
        level = 0
        current = switch
        while current.parent_switch:
            level += 1
            current = current.parent_switch
        return level

    def _is_parameter_dependent_case(
        self, switch: SwitchDescriptor, case_value: int
    ) -> bool:
        """Check if a case contains parameter-dependent logic that should be preserved."""
        # Use the original find_obfuscation_entry_point analysis
        # The original script already identified which cases are parameter-dependent

        if switch.ea == DISPATCH_EA:
            # For the main state machine, check if this is case 0 (which contained the a2 logic)
            if case_value == 0:
                print(
                    f"[+] Case 0 identified as parameter-dependent (contains a2 switch logic)"
                )
                return True

        # Check if this is a synthetic parameter switch
        if switch.switch_var_name == "a2_parameter":
            print(
                f"[+] Synthetic parameter switch case {case_value} is parameter-dependent"
            )
            return True

        # Use the existing CTreeContainsVisitor logic for more detailed analysis
        case_ea = switch.cases.get(case_value)
        if not case_ea:
            return False
        case_end = self._get_case_end(switch, case_value)

        # Check if this case contains switches on function arguments
        try:
            cfunc = ida_hexrays.decompile(self.func_ea)
            lvars = cfunc.get_lvars()

            # Look for switches on argument variables within this case
            for nested_switch in switch.nested_switches:
                if case_ea <= nested_switch.ea < case_end:
                    # Check if nested switch is on a function argument
                    nested_var_idx = nested_switch.switch_var_idx
                    if nested_var_idx >= 0 and nested_var_idx < len(lvars):
                        if lvars[nested_var_idx].is_arg_var:
                            print(
                                f"[+] Case {case_value} contains switch on argument variable {lvars[nested_var_idx].name}"
                            )
                            return True

            # Additional heuristic: look for conditional jumps that might be parameter checks
            insn_count = 0
            conditional_jumps = 0
            for ea in range(case_ea, min(case_end, case_ea + 200)):  # Limit scan range
                if idc.is_head(ea):
                    insn_count += 1
                    mnem = idc.print_insn_mnem(ea)
                    if mnem in [
                        "je",
                        "jne",
                        "jz",
                        "jnz",
                        "jl",
                        "jg",
                        "jle",
                        "jge",
                        "ja",
                        "jb",
                        "jae",
                        "jbe",
                    ]:
                        conditional_jumps += 1

            # If this case has many conditional jumps, it's likely parameter checking
            if conditional_jumps >= 2 and insn_count >= 5:
                print(
                    f"[+] Case {case_value} has {conditional_jumps} conditional jumps in {insn_count} instructions - likely parameter checking"
                )
                return True

        except Exception as e:
            print(f"[!] Error analyzing case {case_value}: {e}")

        return False

    def analyze_control_flow(self):
        """Pass 3: Analyze control flow for each switch level."""
        for level in sorted(self.switch_hierarchy.keys()):
            print(f"[+] Analyzing control flow for level {level}")

            for switch in self.switch_hierarchy[level]:
                edges = self._emulate_switch_flow(switch)
                self.all_edges.extend(edges)

    def _emulate_switch_flow(self, switch: SwitchDescriptor) -> List[ControlFlowEdge]:
        """Emulate execution for a specific switch to discover edges."""
        # The original script already ran Triton and discovered the control flow
        level = self._get_switch_level(switch)
        discovered_edges = []

        if switch.ea == DISPATCH_EA:
            # This is the main state machine switch - use the global edges
            print(f"[+] Using existing Triton emulation results ({len(edges)} edges)")
            for edge in edges:
                control_edge = ControlFlowEdge(
                    src_state=edge.src,
                    dst_state=edge.dst,
                    ea=edge.ip,
                    switch_level=level,
                    switch_descriptor=switch,
                )
                discovered_edges.append(control_edge)
        else:
            # This is a parameter switch or other switch
            print(f"[+] Creating synthetic edges for parameter switch")
            # For parameter switches, create edges based on the original analysis
            # The original find_obfuscation_entry_point found that parameter value 1 leads to state machine
            if switch.switch_var_name == "a2_parameter":
                # Create edges representing parameter flow: a2=1 -> main state machine
                try:
                    # Find the entry state from the original analysis
                    entry_state = next(edge.dst for edge in edges if edge.src == 0)
                    control_edge = ControlFlowEdge(
                        src_state=1,  # a2 = 1 case
                        dst_state=entry_state,  # leads to main state machine entry
                        ea=switch.ea,
                        switch_level=level,
                        switch_descriptor=switch,
                    )
                    discovered_edges.append(control_edge)
                    print(f"[+] Created parameter edge: a2=1 -> state {entry_state}")
                except StopIteration:
                    print("[!] Could not find entry state from original emulation")
            else:
                # For other switches, create placeholder edges
                for src_case, dst_case in [(0, 1), (1, 2)]:  # Placeholder
                    if src_case in switch.cases and dst_case in switch.cases:
                        edge = ControlFlowEdge(
                            src_state=src_case,
                            dst_state=dst_case,
                            ea=switch.cases.get(src_case, 0),
                            switch_level=level,
                            switch_descriptor=switch,
                        )
                        discovered_edges.append(edge)

        print(
            f"[+] Found {len(discovered_edges)} edges for switch {switch.switch_var_name}"
        )
        return discovered_edges

    def _validate_cfg_consistency(self) -> bool:
        """Validate consistency between NetworkX graphs and cfg_nodes."""
        issues_found = 0

        # Check merged_cfg nodes
        for node in self.merged_cfg.nodes():
            if node not in self.cfg_nodes:
                print(f"[!] Node {node} in merged_cfg but missing from cfg_nodes")
                issues_found += 1

        # Check parameter_cfg nodes
        for node in self.parameter_cfg.nodes():
            if node not in self.cfg_nodes:
                print(f"[!] Node {node} in parameter_cfg but missing from cfg_nodes")
                issues_found += 1

        # Check state_machine_cfg nodes
        for node in self.state_machine_cfg.nodes():
            if node not in self.cfg_nodes:
                print(
                    f"[!] Node {node} in state_machine_cfg but missing from cfg_nodes"
                )
                issues_found += 1

        if issues_found == 0:
            print("[+] CFG consistency validation passed")
            return True
        else:
            print(f"[!] CFG consistency validation failed with {issues_found} issues")
            return False

    def merge_control_flows(self):
        """Pass 4: Merge all discovered flows using NetworkX graph operations."""
        print("[+] Merging nested control flows with NetworkX...")

        # Build separate graphs for different flow types
        self._build_parameter_cfg()
        self._build_state_machine_cfg()

        # Validate consistency before merging
        self._validate_cfg_consistency()

        # Merge graphs intelligently
        self._merge_graphs()

        # Linearize the merged graph
        self._linearize_merged_cfg()

        print(
            f"[+] Merged CFG has {len(self.merged_cfg.nodes)} nodes and {len(self.merged_cfg.edges)} edges"
        )

    def _build_parameter_cfg(self):
        """Build CFG for parameter-dependent control flow."""
        print("[+] Building parameter CFG...")

        # Find switches that contain parameter-dependent logic
        for switch in self.discovered_switches:
            switch_level = self._get_switch_level(switch)

            for case_value, case_ea in switch.cases.items():
                if self._is_parameter_dependent_case(switch, case_value):
                    node_id = self._encode_state_id(switch_level, case_value)
                    node = CFGNode(
                        state_id=node_id,
                        ea=case_ea,
                        switch_level=switch_level,
                        switch_descriptor=switch,
                        is_parameter_dependent=True,
                        preserve_original=True,
                    )
                    self.cfg_nodes[node_id] = node
                    self.parameter_cfg.add_node(node_id, **node.__dict__)
                    print(f"[+] Added parameter node: {node_id} at 0x{case_ea:X}")

        # Add edges for parameter-dependent flow
        param_edges = [
            e
            for e in self.all_edges
            if e.switch_descriptor.switch_var_name == "a2_parameter"
        ]
        for edge in param_edges:
            src_id = self._encode_state_id(edge.switch_level, edge.src_state)
            dst_id = self._encode_state_id(edge.switch_level, edge.dst_state)

            print(
                f"[+] Checking parameter edge: {edge.src_state} -> {edge.dst_state} (encoded: {src_id} -> {dst_id})"
            )
            if src_id in self.parameter_cfg and dst_id in self.parameter_cfg:
                self.parameter_cfg.add_edge(
                    src_id, dst_id, ea=edge.ea, edge_type="parameter"
                )
                print(f"[+] Added parameter edge: {src_id} -> {dst_id}")
            else:
                print(
                    f"[!] Skipping parameter edge: src_id {src_id} in graph={src_id in self.parameter_cfg}, dst_id {dst_id} in graph={dst_id in self.parameter_cfg}"
                )
        print(
            f"[+] Parameter CFG: {len(self.parameter_cfg.nodes)} nodes, {len(self.parameter_cfg.edges)} edges"
        )

    def _build_state_machine_cfg(self):
        """Build CFG for obfuscated state machine flow."""
        print("[+] Building state machine CFG...")

        # Find the main state machine switch (the one from DISPATCH_EA)
        main_switch = None
        for switch in self.discovered_switches:
            if switch.ea == DISPATCH_EA:
                main_switch = switch
                break

        if not main_switch:
            print("[!] Could not find main state machine switch")
            return

        switch_level = self._get_switch_level(main_switch)
        print(f"[+] Main switch level: {switch_level}")
        # Add nodes for non-parameter-dependent cases
        for case_value, case_ea in main_switch.cases.items():
            if not self._is_parameter_dependent_case(main_switch, case_value):
                node_id = self._encode_state_id(switch_level, case_value)
                node = CFGNode(
                    state_id=node_id,
                    ea=case_ea,
                    switch_level=switch_level,
                    switch_descriptor=main_switch,
                    is_parameter_dependent=False,
                    preserve_original=False,
                )
                self.cfg_nodes[node_id] = node
                self.state_machine_cfg.add_node(node_id, **node.__dict__)
                print(f"[+] Added state machine node: {node_id} at 0x{case_ea:X}")

        # Add state machine edges (from the original Triton emulation)
        sm_edges = [e for e in self.all_edges if e.switch_descriptor.ea == DISPATCH_EA]
        print(f"[+] Found {len(sm_edges)} state machine edges from Triton emulation")
        for edge in sm_edges:
            src_id = self._encode_state_id(edge.switch_level, edge.src_state)
            dst_id = self._encode_state_id(edge.switch_level, edge.dst_state)
            print(
                f"[+] Checking state machine edge: {edge.src_state} -> {edge.dst_state} (encoded: {src_id} -> {dst_id})"
            )

            # Only add edges between state machine nodes (not parameter nodes)
            if src_id in self.state_machine_cfg and dst_id in self.state_machine_cfg:
                self.state_machine_cfg.add_edge(
                    src_id, dst_id, ea=edge.ea, edge_type="state_machine"
                )
                print(
                    f"[+] Added state machine edge: {edge.src_state} -> {edge.dst_state}"
                )
            else:
                print(
                    f"[!] Skipping state machine edge: src_id {src_id} in graph={src_id in self.state_machine_cfg}, dst_id {dst_id} in graph={dst_id in self.state_machine_cfg}"
                )

        print(
            f"[+] State machine CFG: {len(self.state_machine_cfg.nodes)} nodes, {len(self.state_machine_cfg.edges)} edges"
        )

    def _merge_graphs(self):
        """Merge parameter and state machine CFGs using NetworkX."""
        print("[+] Starting graph merge process...")

        # Start with parameter-dependent structure
        self.merged_cfg = self.parameter_cfg.copy()
        print(
            f"[+] Initial merged_cfg from parameter_cfg: {len(self.merged_cfg.nodes)} nodes"
        )

        # Debug: show what's in the initial graph
        for node in self.merged_cfg.nodes():
            if node in self.cfg_nodes:
                print(f"[+] Initial node {node}: ea=0x{self.cfg_nodes[node].ea:X}")
            else:
                print(f"[!] Initial node {node}: NOT IN cfg_nodes")
        # Find connection points between parameter and state machine flows
        connection_points = self._find_connection_points()
        print(
            f"[+] Found {len(connection_points)} connection points: {connection_points}"
        )

        # Merge state machine subgraphs at connection points
        for param_node, sm_entry_node in connection_points.items():
            print(
                f"[+] Merging state machine subgraph at connection {param_node} -> {sm_entry_node}"
            )

            # Get the state machine subgraph reachable from entry node
            if sm_entry_node in self.state_machine_cfg:
                sm_subgraph = self._get_reachable_subgraph(
                    self.state_machine_cfg, sm_entry_node
                )
                print(f"[+] State machine subgraph has {len(sm_subgraph.nodes)} nodes")

                # Debug: show what's in the subgraph
                for node in sm_subgraph.nodes():
                    if node in self.cfg_nodes:
                        print(
                            f"[+] Subgraph node {node}: ea=0x{self.cfg_nodes[node].ea:X}"
                        )
                    else:
                        print(f"[!] Subgraph node {node}: NOT IN cfg_nodes")

                # Compose the subgraph into the merged CFG
                self.merged_cfg = nx.compose(self.merged_cfg, sm_subgraph)
                print(
                    f"[+] After compose: merged_cfg has {len(self.merged_cfg.nodes)} nodes"
                )

                # Connect parameter node to state machine entry
                if param_node in self.merged_cfg and sm_entry_node in self.merged_cfg:
                    self.merged_cfg.add_edge(
                        param_node, sm_entry_node, edge_type="parameter_to_sm"
                    )
                    print(f"[+] Added connection edge: {param_node} -> {sm_entry_node}")
                else:
                    print(
                        f"[!] Cannot add connection edge: param_node {param_node} in graph={param_node in self.merged_cfg}, sm_entry_node {sm_entry_node} in graph={sm_entry_node in self.merged_cfg}"
                    )
            else:
                print(
                    f"[!] State machine entry node {sm_entry_node} not found in state_machine_cfg"
                )

        # Debug final merged graph
        print(f"[+] Final merged_cfg: {len(self.merged_cfg.nodes)} nodes")
        for node in self.merged_cfg.nodes():
            if node in self.cfg_nodes:
                print(f"[+] Final node {node}: ea=0x{self.cfg_nodes[node].ea:X}")
            else:
                print(f"[!] Final node {node}: NOT IN cfg_nodes (THIS IS THE PROBLEM)")

        # Remove cycles in state machine portions (linearize)
        self._break_state_machine_cycles()

    def _find_connection_points(self) -> Dict[int, int]:
        """Find where parameter-dependent flow connects to state machine."""
        connections = {}

        print(
            "[+] Looking for connection points between parameter and state machine flows..."
        )

        # Look for edges that cross from parameter level to state machine level
        for edge in self.all_edges:
            print(
                f"[+] Checking edge: {edge.src_state} -> {edge.dst_state} (switch: {edge.switch_descriptor.switch_var_name}, level: {edge.switch_level})"
            )

            if edge.switch_level == 0:  # Parameter level
                # Check if this edge leads to a state machine entry
                dst_encoded = self._encode_state_id(
                    1, edge.dst_state
                )  # Assume level 1 is main SM
                print(f"[+] Encoded destination: {dst_encoded}")

                if dst_encoded in self.state_machine_cfg:
                    src_encoded = self._encode_state_id(0, edge.src_state)
                    connections[src_encoded] = dst_encoded
                    print(
                        f"[+] Found connection: parameter node {src_encoded} -> state machine node {dst_encoded}"
                    )
                else:
                    print(
                        f"[!] Destination {dst_encoded} not found in state_machine_cfg"
                    )
            elif edge.switch_descriptor.ea == DISPATCH_EA:
                # This is a state machine edge - check if it connects to parameter logic
                if (
                    edge.src_state == 0
                ):  # Coming from case 0 (which might be parameter-dependent)
                    # Find if there's a parameter case that should connect here
                    main_switch = None
                    for switch in self.discovered_switches:
                        if switch.ea == DISPATCH_EA:
                            main_switch = switch
                            break

                    if main_switch and self._is_parameter_dependent_case(
                        main_switch, 0
                    ):
                        # Case 0 is parameter-dependent, so this is a connection point
                        param_node_id = self._encode_state_id(0, 0)  # Case 0 at level 0
                        sm_node_id = self._encode_state_id(
                            edge.switch_level, edge.dst_state
                        )

                        if (
                            param_node_id in self.parameter_cfg
                            and sm_node_id in self.state_machine_cfg
                        ):
                            connections[param_node_id] = sm_node_id
                            print(
                                f"[+] Found connection from parameter case 0: {param_node_id} -> {sm_node_id}"
                            )

        print(f"[+] Total connections found: {len(connections)}")
        return connections

    def _get_reachable_subgraph(self, graph: nx.DiGraph, start_node: int) -> nx.DiGraph:
        """Get all nodes reachable from start_node."""
        reachable = nx.descendants(graph, start_node)
        reachable.add(start_node)  # Include the start node itself
        return graph.subgraph(reachable).copy()

    def _break_state_machine_cycles(self):
        """Convert state machine cycles to linear flow using topological insights."""
        # Find strongly connected components (cycles)
        sccs = list(nx.strongly_connected_components(self.merged_cfg))

        for scc in sccs:
            if len(scc) > 1:  # It's a cycle
                self._linearize_scc(scc)

    def _linearize_scc(self, scc: Set[int]):
        """Linearize a strongly connected component (cycle)."""
        # Create a subgraph of just this SCC
        scc_subgraph = self.merged_cfg.subgraph(scc)

        # Use a heuristic to find a good linear order
        # Could use various strategies: DFS, address order, etc.
        linear_order = self._compute_linear_order(scc_subgraph)

        # Remove back edges to break cycles
        for i, node in enumerate(linear_order[:-1]):
            next_node = linear_order[i + 1]

            # Remove all outgoing edges from current node
            out_edges = list(self.merged_cfg.successors(node))  # type: ignore
            for successor in out_edges:
                if successor in scc:
                    self.merged_cfg.remove_edge(node, successor)

            # Add single forward edge to next node
            self.merged_cfg.add_edge(node, next_node, edge_type="linearized")

    def _compute_linear_order(self, subgraph: nx.DiGraph) -> List[int]:
        """Compute a good linear order for nodes in a subgraph."""
        # Sort by address order as a simple heuristic
        nodes_with_ea = []
        for node in subgraph.nodes():
            if node in self.cfg_nodes:
                nodes_with_ea.append((node, self.cfg_nodes[node].ea))
            else:
                print(
                    f"[!] Warning: Node {node} missing from cfg_nodes during linear ordering"
                )
                # Use node ID as fallback address
                nodes_with_ea.append((node, node))
        return [node for node, ea in sorted(nodes_with_ea, key=lambda x: x[1])]

    def _linearize_merged_cfg(self):
        """Create final linear order using topological sort."""
        try:
            # Topological sort gives us a linear order respecting dependencies
            self.linear_order = list(nx.topological_sort(self.merged_cfg))
            print(f"[+] Created linear order with {len(self.linear_order)} nodes")
        except nx.NetworkXError:
            # Graph has cycles - should have been handled by _break_state_machine_cycles
            print("[!] Warning: CFG still has cycles after linearization attempt")
            # Fallback to simple address-based ordering with error checking
            nodes_with_ea = []
            for node in self.merged_cfg.nodes():
                if node in self.cfg_nodes:
                    nodes_with_ea.append((node, self.cfg_nodes[node].ea))
                else:
                    print(
                        f"[!] Warning: Node {node} missing from cfg_nodes during linearization"
                    )
                    # Use node ID as fallback address
                    nodes_with_ea.append((node, node))

            self.linear_order = [
                node for node, ea in sorted(nodes_with_ea, key=lambda x: x[1])
            ]
        except Exception as e:
            print(f"[!] Error during CFG linearization: {e}")
            # Emergency fallback - just use the nodes as-is
            self.linear_order = (
                list(self.merged_cfg.nodes()) if self.merged_cfg.nodes() else []
            )

    def _encode_state_id(self, level: int, state: int) -> int:
        """Encode switch level and state into a unique ID."""
        return (level << 16) | state

    def _simple_merge_fallback(self):
        """Fallback merge logic when NetworkX is not available."""
        print("[+] Using simple merge fallback")
        # Simple fallback logic - preserve parameter cases, linearize others
        main_switch = self.switch_hierarchy[0][0] if self.switch_hierarchy[0] else None
        if main_switch:
            for case_value, case_ea in main_switch.cases.items():
                if self._is_parameter_dependent_case(main_switch, case_value):
                    node = CFGNode(
                        state_id=case_value,
                        ea=case_ea,
                        switch_level=0,
                        switch_descriptor=main_switch,
                        is_parameter_dependent=True,
                        preserve_original=True,
                    )
                    self.cfg_nodes[case_value] = node

    def generate_patches(self) -> PatchManager:
        """Pass 5: Generate patches based on NetworkX merged CFG."""
        pm = PatchManager(dry_run=not ENABLE_PATCHING)

        print("[+] Generating patches from CFG analysis...")
        # Early exit if there are too many inconsistencies
        total_merged_nodes = len(self.merged_cfg.nodes())
        valid_cfg_nodes = len(self.cfg_nodes)
        orphan_ratio = 0.0

        print(
            f"[+] Merged CFG nodes: {total_merged_nodes}, Valid CFG nodes: {valid_cfg_nodes}"
        )

        # If more than 50% of nodes are orphaned, fall back immediately
        if total_merged_nodes > 0:
            orphaned_nodes = sum(
                1 for node in self.merged_cfg.nodes() if node not in self.cfg_nodes
            )
            orphan_ratio = orphaned_nodes / total_merged_nodes

            print(
                f"[+] Orphaned nodes: {orphaned_nodes}/{total_merged_nodes} ({orphan_ratio:.1%})"
            )

            if orphan_ratio > 0.5:
                print(
                    f"[!] Too many orphaned nodes ({orphan_ratio:.1%}) - falling back to original algorithm"
                )
                return self._generate_fallback_patches(pm)

        # Check if NetworkX analysis produced useful results
        if total_merged_nodes > 0 and valid_cfg_nodes > 0 and orphan_ratio <= 0.5:
            print(f"[+] Using NetworkX-based patching ({total_merged_nodes} nodes)")
            return self._generate_networkx_patches(pm)
        else:
            print("[!] No merged CFG nodes found, skipping patching")
            print(
                "[!] NetworkX analysis didn't produce useful results, falling back to original algorithm"
            )
            return self._generate_fallback_patches(pm)

    def _generate_fallback_patches(self, pm: PatchManager) -> PatchManager:
        """Generate patches using original algorithm as fallback."""
        print("[+] Using original algorithm for patching")

        # Check if case 0 should be preserved (contains parameter logic)
        preserve_case_0 = False
        main_switch = None

        # Find the main switch from discovered switches
        for switch in self.discovered_switches:
            if switch.ea == DISPATCH_EA:
                main_switch = switch
                break

        if main_switch and 0 in main_switch.cases:
            preserve_case_0 = self._is_parameter_dependent_case(main_switch, 0)

        if preserve_case_0:
            print(
                "[+] Preserving case 0 (parameter-dependent logic) - using minimal patching"
            )
            # Only patch non-parameter cases
            for case_value, case_ea in main_switch.cases.items():
                if case_value != 0 and not self._is_parameter_dependent_case(
                    main_switch, case_value
                ):
                    print(f"[+] Would patch case {case_value} (state machine logic)")
                    # Add state machine patching logic here if needed
        else:
            print("[+] No parameter logic detected, delegating to original algorithm")
            # The main unflatten_original() function will handle this

        return pm

    def _generate_networkx_patches(self, pm: PatchManager) -> PatchManager:
        """Generate patches using NetworkX analysis."""
        # Handle preserved parameter-dependent nodes
        preserved_nodes = set()

        for node in self.merged_cfg.nodes():
            if node in self.cfg_nodes:
                if self.cfg_nodes[node].preserve_original:
                    preserved_nodes.add(node)
            else:
                print(
                    f"[!] Warning: Node {node} in merged_cfg but not in cfg_nodes - skipping"
                )

        print(f"[+] Preserving {len(preserved_nodes)} parameter-dependent nodes")

        # Generate patches for linearized flow using the linear order
        patched_nodes = 0
        for i, node in enumerate(self.linear_order):
            if node in preserved_nodes:
                print(f"[+] Skipping preserved node {node}")
                continue

            # Check if node exists in cfg_nodes
            if node not in self.cfg_nodes:
                print(
                    f"[!] Warning: Node {node} in linear_order but not in cfg_nodes - skipping"
                )
                continue

            current_node_info = self.cfg_nodes[node]

            # Find next node in linear order for direct jumps
            next_node_info = None
            if i + 1 < len(self.linear_order):
                next_node_id = self.linear_order[i + 1]
                if next_node_id in self.cfg_nodes:
                    next_node_info = self.cfg_nodes[next_node_id]
                else:
                    print(f"[!] Warning: Next node {next_node_id} not in cfg_nodes")
            # Generate patches based on NetworkX edge analysis
            try:
                self._patch_node_transitions(pm, current_node_info, next_node_info)
                patched_nodes += 1
            except Exception as e:
                print(f"[!] Error patching node {node}: {e}")
                continue

        print(f"[+] Successfully patched {patched_nodes} nodes")

        # Handle dispatcher head patching
        try:
            self._patch_dispatcher_head(pm, preserved_nodes)
        except Exception as e:
            print(f"[!] Error patching dispatcher head: {e}")

        return pm

    # def _generate_simple_patches(self, pm: PatchManager) -> PatchManager:
    #     """Generate patches using simple fallback logic."""
    #     preserved_cases = set()
    #     main_switch = self.switch_hierarchy[0][0] if self.switch_hierarchy[0] else None

    #     if main_switch:
    #         for case_value, case_ea in main_switch.cases.items():
    #             if self._is_parameter_dependent_case(main_switch, case_value):
    #                 preserved_cases.add(case_value)
    #                 print(f"[+] Preserving case {case_value} - no patches")

    #     print(f"[+] Simple patches - preserved {len(preserved_cases)} cases")
    #     return pm

    def _patch_node_transitions(
        self, pm: PatchManager, node: CFGNode, next_node: Optional[CFGNode]
    ):
        """Generate patches for a specific node's transitions."""
        # Find state-setting instructions in this node's basic block
        node_end = next_node.ea if next_node else self.func_end

        for ea in range(node.ea, node_end):
            if not idc.is_head(ea):
                continue

            # Use existing is_state_store logic
            if self._is_state_store_for_node(ea, node):
                target_ea = next_node.ea if next_node else node.ea
                self._generate_jump_patch(pm, ea, target_ea)

    def _patch_dispatcher_head(self, pm: PatchManager, preserved_nodes: Set[int]):
        """Patch the main dispatcher head, respecting preserved nodes."""
        if not preserved_nodes:
            # No parameter-dependent logic - can jump directly to linearized flow
            if self.linear_order:
                first_node = self.cfg_nodes[self.linear_order[0]]
                main_switch = self.switch_hierarchy[0][0]
                self._generate_dispatcher_jump_patch(pm, main_switch, first_node.ea)
        else:
            print("[+] Preserving original dispatcher due to parameter-dependent logic")

    def _is_state_store_for_node(self, ea: int, node: CFGNode) -> bool:
        """Check if instruction at ea is a state store relevant to this node."""
        # Use existing is_state_store logic but adapted for the node's switch
        return is_state_store(ea)  # Placeholder - use existing function

    def _generate_jump_patch(self, pm: PatchManager, ea: int, target_ea: int):
        """Generate a jump patch from ea to target_ea."""
        disp = target_ea - (ea + 5)
        if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
            patch = b"\xe9" + struct.pack("<i", disp)
        else:
            patch = b"\x48\xb8" + struct.pack("<Q", target_ea) + b"\xff\xe0"

        mov_size = idc.get_item_size(ea)
        pm.add_patch(ea, patch.ljust(mov_size, b"\x90"))

    def _generate_dispatcher_jump_patch(
        self, pm: PatchManager, switch: SwitchDescriptor, target_ea: int
    ):
        """Generate patch for the main dispatcher."""
        head_start = switch.switch_info.startea
        head_end = switch.ea + idc.get_item_size(switch.ea)
        head_len = head_end - head_start

        disp = target_ea - (head_start + 5)
        if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
            head_patch = b"\xe9" + struct.pack("<i", disp)
        else:
            head_patch = b"\x48\xb8" + struct.pack("<Q", target_ea) + b"\xff\xe0"

        pm.add_patch(head_start, head_patch.ljust(head_len, b"\x90"))

    def export_cfg_visualization(self, output_dir: str = "cfg_debug"):
        """Export NetworkX graphs for debugging visualization."""
        import os

        os.makedirs(output_dir, exist_ok=True)

        # Export individual graphs
        if self.parameter_cfg.nodes():
            nx.drawing.nx_pydot.write_dot(
                self.parameter_cfg, f"{output_dir}/parameter_cfg.dot"
            )
            print(f"[+] Parameter CFG exported to {output_dir}/parameter_cfg.dot")

        if self.state_machine_cfg.nodes():
            nx.drawing.nx_pydot.write_dot(
                self.state_machine_cfg, f"{output_dir}/state_machine_cfg.dot"
            )
            print(
                f"[+] State machine CFG exported to {output_dir}/state_machine_cfg.dot"
            )

        if self.merged_cfg.nodes():
            nx.drawing.nx_pydot.write_dot(
                self.merged_cfg, f"{output_dir}/merged_cfg.dot"
            )
            print(f"[+] Merged CFG exported to {output_dir}/merged_cfg.dot")

        # Export linear order as a simple graph
        if self.linear_order:
            linear_graph = nx.DiGraph()
            for i, node in enumerate(self.linear_order):
                linear_graph.add_node(node, **self.cfg_nodes[node].__dict__)
                if i > 0:
                    linear_graph.add_edge(
                        self.linear_order[i - 1], node, edge_type="linearized"
                    )

            nx.drawing.nx_pydot.write_dot(
                linear_graph, f"{output_dir}/linear_order.dot"
            )
            print(f"[+] Linear order exported to {output_dir}/linear_order.dot")


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
block_ea: dict[int, int] = get_switch_mapping(switch_info)
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
            if not (FUNC_EA <= ip < FUNC_END):
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


# ──────────────────────────────────────────────────────────────────────
# Multi-Pass or Original Unflattening Logic
# ──────────────────────────────────────────────────────────────────────


def unflatten_with_multipass(func_ea: int, export_debug: bool = False):
    """Enhanced multi-pass control flow unflattening with NetworkX."""
    print("[+] Using multi-pass NetworkX unflattening approach")
    unflattener = MultiPassUnflattener(func_ea)

    try:
        # Pass 1: Discovery
        unflattener.discover_all_switches()

        # Pass 2: Hierarchy
        unflattener.build_switch_hierarchy()

        # Pass 3: Control Flow Analysis
        unflattener.analyze_control_flow()

        # Pass 4: Merge using NetworkX
        unflattener.merge_control_flows()

        # Optional: Export debug visualizations
        if export_debug:
            unflattener.export_cfg_visualization()

        # Check if multi-pass produced useful results
        if len(unflattener.cfg_nodes) == 0 or len(unflattener.merged_cfg.nodes()) == 0:
            print("[!] Multi-pass analysis didn't produce useful results")
            print("[!] Falling back to original proven algorithm")
            return unflatten_original()

        # Pass 5: Patch Generation
        pm = unflattener.generate_patches()

        # Check if patches were actually generated
        if len(pm) == 0:
            print("[!] No patches generated by multi-pass approach")
            print("[!] Falling back to original proven algorithm")
            return unflatten_original()

        # Apply the patches
        success = pm.apply_all()
        if not success:
            print("[!] Multi-pass patching failed")
            print("[!] Falling back to original proven algorithm")
            return unflatten_original()

        print("[+] Multi-pass unflattening complete")

        # Clean up and re-analyze like original algorithm
        ida_xref.delete_switch_table(DISPATCH_EA, switch_info)
        ida_nalt.del_switch_info(DISPATCH_EA)
        ida_auto.auto_mark_range(FUNC_EA, FUNC_END, ida_auto.AU_USED)
        ida_auto.auto_wait()
        print("[+] Patching complete – press <Space> in IDA to re-decompile")

    except Exception as e:
        tb_str = "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
        print(f"[!] Multi-pass approach failed with error: {e}: \n{tb_str}")
        print("[!] Falling back to original proven algorithm")
        return unflatten_original()


def unflatten_original():
    """Original unflattening algorithm as fallback."""
    print("[+] Using original unflattening algorithm")

    # Check if multi-pass analysis detected parameter-dependent case 0
    preserve_case_0 = False

    # If we have multi-pass results, check if case 0 should be preserved
    if USE_MULTIPASS:
        try:
            # Quick check: does case 0 look like parameter-dependent logic?
            case_0_ea = block_ea.get(0)
            if case_0_ea:
                # Simple heuristic: count conditional jumps in case 0
                conditional_jumps = 0
                case_1_ea = block_ea.get(1, FUNC_END)

                for ea in range(case_0_ea, min(case_1_ea, case_0_ea + 200)):
                    if idc.is_head(ea):
                        mnem = idc.print_insn_mnem(ea)
                        if mnem in ["je", "jne", "jz", "jnz", "jl", "jg", "jle", "jge"]:
                            conditional_jumps += 1

                if conditional_jumps >= 2:
                    preserve_case_0 = True
                    print(
                        f"[+] Detected {conditional_jumps} conditional jumps in case 0 - preserving parameter logic"
                    )
        except:
            pass

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

    # MODIFIED: Only patch dispatcher head if case 0 doesn't need preservation
    if preserve_case_0:
        print(
            "[+] Preserving case 0 (parameter-dependent logic) - keeping original dispatcher"
        )
    else:
        # Original logic: Patch dispatcher head to jump to the TRUE entry case
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
        print(f"[+] Dispatcher patched to jump to case {entry_state} at 0x{entry_ea:X}")

    # MODIFIED: Patch each block's state-setting instructions (skip case 0 if preserving)
    skip_cases = {0} if preserve_case_0 else set()

    for state in sorted(block_ea.keys()):
        if state in skip_cases:
            print(f"[+] Skipping case {state} (preserved for parameter logic)")
            continue

        ea = block_ea[state]
        # Determine block end (next block or function end)
        next_state = min([s for s in block_ea if s > state], default=None)
        next_ea = block_ea[next_state] if next_state is not None else FUNC_END

        # Patch all mov [state], imm instructions
        for head in idautils.Heads(ea, next_ea):
            try:
                is_state_var = is_state_store(head)
            except Exception as e:
                print(f"[!] Error checking state store at 0x{head:X}: {e}")
                print(f"[!] {idc.generate_disasm_line(head, 0)}")
                tb_str = "".join(
                    traceback.format_exception(e.__class__, e, e.__traceback__)
                )
                print(tb_str)
                exit(1)
            else:
                if not is_state_var:
                    continue

            imm = idc.get_operand_value(head, 1)
            if imm not in block_ea or imm in skip_cases:
                continue

            target_ea = block_ea[imm]
            disp = target_ea - (head + 5)
            if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
                patch = b"\xe9" + struct.pack("<i", disp)
            else:
                patch = b"\x48\xb8" + struct.pack("<Q", target_ea) + b"\xff\xe0"
            mov_size = idc.get_item_size(head)  # Typically 7 bytes
            pm.add_patch(head, patch.ljust(mov_size, b"\x90"))
            print(f"[+] 0x{head:X}: Patched mov [state], {imm} to jmp 0x{target_ea:X}")

        # Patch tail jump to NOPs (assumes last instruction is jmp)
        tail_ea = idc.prev_head(next_ea, ea)
        if not idc.print_insn_mnem(tail_ea) == "jmp":
            continue
        jmp_size = idc.get_item_size(tail_ea)
        pm.add_patch(tail_ea, b"\x90" * jmp_size)
        print(f"[+] 0x{tail_ea:X}: Tail jump patched to NOPs")

    pm.apply_all()

    # Clean up and re-analyze
    ida_xref.delete_switch_table(DISPATCH_EA, switch_info)
    ida_nalt.del_switch_info(DISPATCH_EA)
    ida_auto.auto_mark_range(FUNC_EA, FUNC_END, ida_auto.AU_USED)
    ida_auto.auto_wait()
    print("[+] Patching complete - press <Space> in IDA to re-decompile")


# ──────────────────────────────────────────────────────────────────────
# Main Execution Logic
# ──────────────────────────────────────────────────────────────────────


def main():
    """Main execution function - choose between multi-pass or original approach."""
    print(f"[+] Control Flow Unflattening Script")
    print(f"[+] Function: 0x{FUNC_EA:X} -> 0x{FUNC_END:X}")
    print(f"[+] Multi-pass Mode: {USE_MULTIPASS}")

    if USE_MULTIPASS:
        # Use enhanced multi-pass approach
        unflatten_with_multipass(FUNC_EA, export_debug=GRAPH_DOT)
    else:
        # Use original approach
        unflatten_original()

    print("[✓] Unflattening complete!")


# Execute the main function
if __name__ == "__main__":
    main()
