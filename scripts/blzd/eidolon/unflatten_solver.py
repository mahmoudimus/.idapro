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
import ida_kernwin
import ida_nalt
import ida_xref
import idaapi
import idautils
import idc

# ──────────────────────────────────────────────────────────────────────
# USER SETTINGS ─ change these if needed
# ──────────────────────────────────────────────────────────────────────
FUNC_EA = idaapi.get_func(idaapi.get_screen_ea()).start_ea  # start EA
SEED_VALUE = 0  # argv[2]
ENABLE_PATCHING = True  # True → rewrite code
MAX_STEPS = 250000  # safety

# Convenience colours
COL_DISPATCHER = 0x0080FF
COL_CASE = 0x00FF80
COL_EDGE_TRUE = 0xF07070
COL_EDGE_FALSE = 0x70A0FF

# ──────────────────────────────────────────────────────────────────────
# 1. Gather basic info
# ──────────────────────────────────────────────────────────────────────
if FUNC_EA == idc.BADADDR:
    raise RuntimeError(f"label {FUNC_EA:X} not found")

func_end = idc.get_func_attr(FUNC_EA, idc.FUNCATTR_END)
print(f"[+] analysing 0x{FUNC_EA:X}..0x{func_end:X}")

# Locate the first switch (dispatcher).  Hex-Rays normally creates a
# switch_xrefs structure we can query; fall back to pattern search.
switch_info = None
for ea in idautils.FuncItems(FUNC_EA):
    if (si := idaapi.get_switch_info(ea)) is not None:
        switch_info = si
        DISPATCH_EA = ea
        break
if not switch_info:
    raise RuntimeError("can't find the switch dispatcher")

print(f"[+] dispatcher at 0x{DISPATCH_EA:X}, {switch_info.ncases} cases")


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


# ──────────────────────────────────────────────────────────────────────
# 2. Triton initialisation
# ──────────────────────────────────────────────────────────────────────
tc = TritonContext()
tc.setArchitecture(ARCH.X86_64)
tc.setMode(MODE.ALIGNED_MEMORY, True)
tc.setMode(MODE.SYMBOLIZE_LOAD, False)
tc.setMode(MODE.SYMBOLIZE_STORE, False)

# Stubs: every non-returning helper call returns 0 (or a constant if
# you want).  Adjust for your binary as necessary.
CALL_STUB_RETVAL = 0
helper_re = re.compile(r"sub_180[0-9A-F]{5,}")
mapper = IDAToTritonRegisterMapper(tc)


def is_helper_call(ea):
    callee = idc.print_operand(ea, 0)
    return callee and helper_re.match(callee)


# def hook_call_old(ctx):
#     ip = ctx.getConcreteRegisterValue(ctx.registers.rip)
#     callee_str = idc.print_operand(ip, 0)
#     if not callee_str:
#         return
#     # Force the stub return value in RAX / EAX depending on op size
#     sz = 8 if ctx.isRegister(ctx.registers.rax) else 4
#     ctx.setConcreteRegisterValue(
#         ctx.registers.rax, CALL_STUB_RETVAL & ((1 << (sz * 8)) - 1)
#     )
#     # Skip over the call
#     ctx.setConcreteRegisterValue(ctx.registers.rip, ip + idc.get_item_size(ip))


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

# ── map an artificial 64‑KiB stack so Triton accepts all [rsp+disp] accesses
STACK_TOP = 0x7FFF0000
STACK_SIZE = 0x10000

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
    INDEX_NONE = 4

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
        return scale

    return sib_base(insn, op), sib_index(insn, op), sib_scale(op), op.addr


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
        return ("stk", base, idaapi.as_signed(jop.disp, 32))

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
                return ("stk", base, idaapi.as_signed(src.addr, 32))

            if src.type == idaapi.o_mem:
                return ("mem", src.addr, None)

        ea = idaapi.prev_head(ea, func_start)

    # fallback: treat the register itself as the state
    return ("reg", idaapi.get_reg_name(tracked, insn.ops[0].dtype), None)  # type: ignore


# def guess_state_var() -> tuple[str, str | int, int | None]:
#     """
#     Detect the 'state' location used by the virtualised switch.

#     Returns one of
#         ("reg",  "rax")               - 32-bit value in a register
#         ("stk",  "rsp", 0x30)         - DWORD at [rsp+0x30]
#         ("mem",  0x14001234, None)    - absolute DWORD in .data
#     """
#     insn = idaapi.insn_t()
#     if not idaapi.decode_insn(insn, DISPATCH_EA):
#         raise RuntimeError("cannot decode dispatcher @0x{:X}".format(DISPATCH_EA))

#     # The operand feeding “jmp rax”
#     jop = insn.ops[0]  # type: ignore

#     if jop.type == idaapi.o_displ:
#         base = idaapi.get_reg_name(jop.reg, jop.dtype)
#         disp = idaapi.as_signed(jop.disp, 32)  # sign-extend 32-bit disp
#         return ("stk", base, disp)  # («rsp», -0xF0) for example
#         # return ("stk", base, jop.addr if jop.addr else jop.disp)
#     elif jop.type != idaapi.o_reg:
#         raise RuntimeError("unrecognised jmp operand")

#     tracked_reg: int = jop.reg  # type: ignore
#     # Walk backwards inside same BB to find the *last* def of tracked_reg
#     fc = idaapi.FlowChart(idaapi.get_func(DISPATCH_EA))
#     bb = next(b for b in fc if b.start_ea <= DISPATCH_EA < b.end_ea)

#     ea = ida_bytes.prev_head(DISPATCH_EA, bb.start_ea)
#     while ea != idaapi.BADADDR:
#         idaapi.decode_insn(insn, ea)
#         print(f"[+] insn: {idaapi.print_insn_mnem(ea)}, {hex(ea)}")
#         if (
#             insn.itype
#             in (
#                 ida_allins.NN_mov,
#                 ida_allins.NN_lea,
#                 ida_allins.NN_movsxd,
#                 ida_allins.NN_movzx,
#                 ida_allins.NN_movsx,
#             )
#             and insn.ops[0].type == idaapi.o_reg  # type: ignore
#             and insn.ops[0].reg == tracked_reg  # type: ignore
#         ):
#             src = insn.ops[1]  # type: ignore

#             if src.type == idaapi.o_reg:
#                 return ("reg", idaapi.get_reg_name(src.reg, src.dtype), None)

#             if src.type == idaapi.o_displ:
#                 base = idaapi.get_reg_name(src.reg, src.dtype)
#                 print(f"[+] base: {base}, disp: {src.addr}")
#                 disp = idaapi.as_signed(src.addr, 32)  # sign-extend 32-bit disp
#                 return ("stk", base, disp)  # («rsp», -0xF0) for example
#                 # return ("stk", base, src.disp)

#             if src.type == idaapi.o_mem:
#                 return ("mem", src.addr, None)

#         ea = ida_bytes.prev_head(ea, bb.start_ea)

#     # fallback: state *is* the tracked register
#     return ("reg", idaapi.get_reg_name(tracked_reg, insn.ops[0].dtype), None)  # type: ignore


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

# ──────────────────────────────────────────────────────────────────────
# 4. Build graph and show
# ──────────────────────────────────────────────────────────────────────
import networkx as nx

G = nx.DiGraph()
for e in edges:
    G.add_edge(e.src, e.dst)

# Save .dot & render to PDF
with tempfile.NamedTemporaryFile(dir="herpa", suffix=".dot", delete=False) as dot_file:
    dot_name = dot_file.name
    nx.drawing.nx_pydot.write_dot(G, dot_name)
    print(f"[+] graph written to {dot_name}")

# Show in IDA graph view
# gv = idaapi.create_generic_graph("Unflattened CFG", len(G.nodes), True)
# for n in G.nodes:
#     idx = gv.add_node(n, str(n))
#     gv[node_t(idx)].color = COL_CASE
# for src, dst in G.edges:
#     eid = gv.add_edge(src, dst, "")
#     gv[edge_t(eid)].color = COL_EDGE_TRUE
# idaapi.display_generic_graph(gv, False)

# ──────────────────────────────────────────────────────────────────────
# 5. (optional) patch dispatcher → direct jumps
# ──────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────
# 5. (optional) fully de‑virtualise control‑flow
#     – patch every ‘mov [state], imm; jmp dispatcher’ tail
#     – patch the dispatcher head
#     – drop switch‑info so Hex‑Rays re‑decompiles cleanly
# ──────────────────────────────────────────────────────────────────────

# def is_state_store(ea: int) -> bool:
#     """Return True if instruction is  mov dword ptr [state], imm32."""
#     if ida_bytes.get_byte(ea) != 0xC7:        # C7 /0
#         return False
#     insn = idaapi.insn_t()
#     idaapi.decode_insn(insn, ea)
#     if insn.itype != ida_allins.NN_mov:
#         return False
#     op0, op1 = insn.ops[0], insn.ops[1]
#     if op0.type != idaapi.o_displ or op1.type != idaapi.o_imm:
#         return False
#     base = _wide(idaapi.get_reg_name(op0.reg, op0.dtype))
#     disp = idaapi.as_signed(op0.disp, 32)
#     return (base, disp) == tuple(state_desc[:2])


# def patch_case_tails():
#     disp_blk = DISPATCH_EA  # jmp rax
#     state_base, state_disp = state_desc  # ('rsp', 0x30)

#     for tail in idautils.CodeRefsTo(disp_blk, 0):
#         # tail points at the *jmp*; the previous instruction should
#         # store the next state value
#         mov_ea = idc.prev_head(tail)
#         if idc.print_insn_mnem(mov_ea) != "mov":
#             continue

#         # Is it  mov dword ptr [state], imm ?
#         insn = idaapi.insn_t()
#         idaapi.decode_insn(insn, mov_ea)
#         op0, op1 = insn.ops[0], insn.ops[1]

#         if (
#             op0.type == idaapi.o_displ
#             and _wide(idaapi.get_reg_name(op0.reg, op0.dtype)) == state_base
#             and idaapi.as_signed(op0.disp, 32) == state_disp
#             and op1.type == idaapi.o_imm
#         ):
#             imm = op1.value & 0xFFFFFFFF
#             tgt = block_ea.get(imm)
#             if tgt is None:
#                 continue  # sparse/default → skip

#             disp = tgt - (mov_ea + 5)
#             if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
#                 jmp_bytes = b"\xe9" + struct.pack("<i", disp)  # near-jmp
#             else:
#                 jmp_bytes = b"\x48\xb8" + struct.pack("<Q", tgt) + b"\xff\xe0"

#             size = idc.get_item_size(mov_ea) + idc.get_item_size(tail)
#             ida_bytes.patch_bytes(mov_ea, jmp_bytes.ljust(size, b"\x90"))
#             print(f"[+] tail @0x{mov_ea:X} patched → 0x{tgt:X}")


def is_state_store(ea: int, imm: int | None = None) -> bool:
    """True if "ea" is  mov dword [state], imm  (optionally matching imm)."""
    # C7 /0   mov r/m32, imm32
    if ida_bytes.get_byte(ea) != 0xC7 or idc.print_insn_mnem(ea) != "mov":
        return False
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    if insn.itype != ida_allins.NN_mov or insn.ops[0].type != idaapi.o_displ:
        return False
    if not has_sib(insn.ops[0]):
        base = _wide(idaapi.get_reg_name(insn.ops[0].reg, insn.ops[0].dtype))
        disp = idaapi.as_signed(insn.ops[0].disp, 32)
    else:
        base, scale, index, disp = get_sib_components(insn, insn.ops[0])
        base = _wide(idaapi.get_reg_name(base, scale))

    if (base, disp) != tuple(state_desc):  # the slot we identified
        print(
            f"[+] {hex(ea)} - {idc.generate_disasm_line(ea, 0)} - not state store ({state_desc}) (base: {base}, disp: {disp})"
        )
        return False
    return imm is None or insn.ops[1].value == imm


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


pm = PatchManager(dry_run=not ENABLE_PATCHING)

# Patch dispatcher head to jump to case 0
head_start = switch_info.startea
head_end = DISPATCH_EA + idc.get_item_size(DISPATCH_EA)
head_len = head_end - head_start
entry_ea = block_ea[0]
disp = entry_ea - (head_start + 5)
if -0x8000_0000 <= disp <= 0x7FFF_FFFF:
    head_patch = b"\xe9" + struct.pack("<i", disp)
else:
    head_patch = b"\x48\xb8" + struct.pack("<Q", entry_ea) + b"\xff\xe0"
pm.add_patch(head_start, head_patch.ljust(head_len, b"\x90"))
print(f"[+] Dispatcher patched to jump to case 0 at 0x{entry_ea:X}")

# Patch each block's state-setting instructions
for state in sorted(block_ea.keys()):
    ea = block_ea[state]
    # Determine block end (next block or function end)
    next_state = min([s for s in block_ea if s > state], default=None)
    next_ea = block_ea[next_state] if next_state is not None else func_end

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
        if imm not in block_ea:
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
ida_auto.auto_mark_range(FUNC_EA, func_end, ida_auto.AU_USED)
ida_auto.auto_wait()
print("[+] Patching complete – press <Space> in IDA to re-decompile")

print("[✓] done")
