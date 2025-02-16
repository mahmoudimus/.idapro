import enum
import functools
import inspect
import os
import time
import types
import typing
from collections import defaultdict
from dataclasses import dataclass

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_problems
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
import unicorn


def clear_window(window):
    form = ida_kernwin.find_widget(window)
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


def clear_output():
    clear_window("Output window")


def decode_to_instr(address: int) -> ida_ua.insn_t:
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, address)  # corrected function name
    return insn


def format_addr(addr: int) -> str:
    """Return the address formatted as a string: 0x{address:02X}"""
    return f"0x{addr:02X}"


def refresh_idaview(force=False):
    if not force:
        ida_kernwin.refresh_navband(True)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.request_refresh(ida_kernwin.IWID_FUNCS)
    else:
        ida_kernwin.refresh_idaview_anyway()
        idaapi.require_refresh()


# Exhaustive list of x86_64 instructions that do not affect flags (or set them to a known state).
# These entries include conditions under which the instruction leaves the flags either unchanged or forces a known state,
# e.g. shift instructions with a zero count, or logical operations that clear CF and OF.
NONFLAG_INSTRUCTIONS = [
    {"mnemonic": "mov", "condition": "operands identical (no flag update)"},
    {
        "mnemonic": "xchg",
        "condition": "exchange of same register or effective no-op (flags not modified)",
    },
    {"mnemonic": "lea", "condition": "always does not affect flags"},
    {"mnemonic": "nop", "condition": "no operation; flags remain unchanged"},
    {"mnemonic": "sal", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "shl", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "sar", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "shr", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "rol", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "ror", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "rcl", "condition": "if shift count == 0, no flag update"},
    {"mnemonic": "rcr", "condition": "if shift count == 0, no flag update"},
    {
        "mnemonic": "test",
        "condition": "results in CF=0 and OF=0 regardless of other flags",
    },
    {
        "mnemonic": "and",
        "condition": "results in CF=0 and OF=0 regardless of other flags",
    },
    {
        "mnemonic": "xor",
        "condition": "results in CF=0 and OF=0 regardless of other flags",
    },
    {
        "mnemonic": "or",
        "condition": "results in CF=0 and OF=0 regardless of other flags",
    },
    {"mnemonic": "clc", "condition": "explicitly clears the carry flag (CF=0)"},
    {"mnemonic": "stc", "condition": "explicitly sets the carry flag (CF=1)"},
    {"mnemonic": "movzx", "condition": "does not affect flags"},
    {"mnemonic": "movsx", "condition": "does not affect flags"},
    {
        "mnemonic": "movaps",
        "condition": "move aligned packed single-precision floating-point values, no flag modification",
    },
    {
        "mnemonic": "movupd",
        "condition": "move unaligned packed double-precision floating-point values, no flag modification",
    },
    {
        "mnemonic": "movups",
        "condition": "move unaligned packed single-precision floating-point values, no flag modification",
    },
    {
        "mnemonic": "movdqa",
        "condition": "move aligned double quadword, no flag modification",
    },
    {
        "mnemonic": "movdqu",
        "condition": "move unaligned double quadword, no flag modification",
    },
    {
        "mnemonic": "cmov",
        "condition": "conditional move instructions do not affect flags",
    },
]

# List of conditional jumps based on flag tests
CONDITIONAL_JUMPS = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
CALL_INSTRUCTIONS = set((idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni))
LOOP_INSTRUCTIONS = set(
    (
        idaapi.NN_loopw,
        idaapi.NN_loop,
        idaapi.NN_loopd,
        idaapi.NN_loopq,
        idaapi.NN_loopwe,
        idaapi.NN_loope,
        idaapi.NN_loopde,
        idaapi.NN_loopqe,
        idaapi.NN_loopwne,
        idaapi.NN_loopne,
        idaapi.NN_loopdne,
        idaapi.NN_loopqne,
    )
)

_ALLOWED_MNEMONICS = {
    "jae",
    "jb",
    "jc",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jnae",
    "jnb",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
}


class ConditionalJumps(enum.IntFlag):
    """

    >>> print(ConditionalJumps.is_jcc("je"))
    True
    >>> print(ConditionalJumps.is_jcc("jexxx"))
    False
    >>> print(ConditionalJumps.is_jcc(decode_to_instr(idc.here())))
    True
    """

    ja = ida_allins.NN_ja
    jae = ida_allins.NN_jae
    jb = ida_allins.NN_jb
    jbe = ida_allins.NN_jbe
    jc = ida_allins.NN_jc
    jcxz = ida_allins.NN_jcxz
    jecxz = ida_allins.NN_jecxz
    jrcxz = ida_allins.NN_jrcxz
    je = ida_allins.NN_je
    jg = ida_allins.NN_jg
    jge = ida_allins.NN_jge
    jl = ida_allins.NN_jl
    jle = ida_allins.NN_jle
    jna = ida_allins.NN_jna
    jnae = ida_allins.NN_jnae
    jnb = ida_allins.NN_jnb
    jnbe = ida_allins.NN_jnbe
    jnc = ida_allins.NN_jnc
    jne = ida_allins.NN_jne
    jng = ida_allins.NN_jng
    jnge = ida_allins.NN_jnge
    jnl = ida_allins.NN_jnl
    jnle = ida_allins.NN_jnle
    jno = ida_allins.NN_jno
    jnp = ida_allins.NN_jnp
    jns = ida_allins.NN_jns
    jnz = ida_allins.NN_jnz
    jo = ida_allins.NN_jo
    jp = ida_allins.NN_jp
    jpe = ida_allins.NN_jpe
    jpo = ida_allins.NN_jpo
    js = ida_allins.NN_js
    jz = ida_allins.NN_jz

    @functools.singledispatch
    @staticmethod
    def is_jcc(instr: ida_ua.insn_t):
        """Is conditional branch?
        refer to intel.hpp/inline bool insn_jcc(const insn_t &insn)
        """
        return instr.itype in ConditionalJumps._value2member_map_

    @is_jcc.register(int)
    def _(ea: int):  # //NOSONAR
        """Is conditional branch?
        refer to intel.hpp/inline bool insn_jcc(const insn_t &insn)
        """
        return ea in ConditionalJumps._value2member_map_

    @is_jcc.register(str)
    def _(jump_str: str):
        """Is conditional branch based on mnemonic string.
        Returns True if the given string (case-insensitive) is a recognized conditional jump mnemonic.
        """
        is_allowed = jump_str.lower() in _ALLOWED_MNEMONICS
        is_valid_enum = getattr(ConditionalJumps, jump_str.lower(), None) is not None
        # if not all([is_allowed, is_valid_enum]):
        #     print(
        #         f"{jump_str} is {is_allowed or 'NOT'} in the ALLOWED_MNEMONICS but {is_valid_enum or 'NOT'} a valid enum value"
        #     )
        return is_allowed or is_valid_enum


class ProgressDialog:
    def __init__(self, message="Please wait...", hide_cancel=False):
        self._default_msg: str
        self.hide_cancel: bool
        self.__user_canceled = False
        self.configure(message, hide_cancel)

    def _message(self, message=None, hide_cancel=None):
        display_msg = self._default_msg if message is None else message
        hide_cancel = self.hide_cancel if hide_cancel is None else hide_cancel
        prefix = "HIDECANCEL\n" if hide_cancel else ""
        return prefix + display_msg

    def configure(self, message="Please wait...", hide_cancel=False):
        self._default_msg = message
        self.hide_cancel = hide_cancel
        return self

    __call__ = configure

    def __enter__(self):
        ida_kernwin.show_wait_box(self._message())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        ida_kernwin.hide_wait_box()
        if self.__user_canceled:
            ida_kernwin.warning("Canceled")

    def replace_message(self, new_message, hide_cancel=False):
        msg = self._message(message=new_message, hide_cancel=hide_cancel)
        ida_kernwin.replace_wait_box(msg)

    def user_canceled(self):
        self.__user_canceled = ida_kernwin.user_cancelled()
        return self.__user_canceled

    user_cancelled = user_canceled


class ida_tguidm:

    def __init__(self, iterable, total=None, initial=0):
        self.iterable = iterable

        if total is None and iterable is not None:
            if isinstance(iterable, types.GeneratorType) or inspect.isgeneratorfunction(
                iterable
            ):
                self.iterable = list(iterable)
                iterable = self.iterable
            try:
                total = len(iterable)
            except (TypeError, AttributeError):
                total = None

        if total == float("inf"):
            # Infinite iterations, behave same as unknown
            total = None
        self.total = total
        self.n = initial

    def __iter__(self):
        # Inlining instance variables as locals (speed optimization)
        iterable = self.iterable
        total = self.total
        with ProgressDialog("Executing") as pd:
            for idx, item in enumerate(iterable, start=1):
                if pd.user_canceled():
                    break
                pd.replace_message(f"Processing ({idx}/{total})")
                try:
                    yield item
                except Exception as e:
                    ida_kernwin.warning(f"Unexpected error {e}")
                    break


def is_call(instr: ida_ua.insn_t):
    return instr.itype in CALL_INSTRUCTIONS or idaapi.is_call_insn(instr)


def is_ret(instr: ida_ua.insn_t):
    """Is the instruction a return instruction."""
    return idaapi.is_ret_insn(instr)


def is_indirect_jump(instr: ida_ua.insn_t):
    """Is the instruction an indirect jump instruction."""
    return idaapi.is_indirect_jump_insn(instr)


def is_jmp(instr: ida_ua.insn_t):
    """Is this an indirect jump?"""
    return instr.itype == idaapi.NN_jmp


is_jcc = ConditionalJumps.is_jcc


def basic_block_size(bb: idaapi.BasicBlock) -> int:
    """calculate size of basic block"""
    return bb.end_ea - bb.start_ea


def get_function_blocks(f: idaapi.func_t):
    """yield basic blocks contained in specified function"""
    # leverage idaapi.FC_NOEXT flag to ignore useless external blocks referenced by the function
    yield from idaapi.FlowChart(f, flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT))


def force_reanalyze_target(jump_target: int) -> int:
    """
    Forces IDA to re-disassemble code starting exactly from the 'jump_target' address.
    If the target falls in the middle of an already defined instruction (which may include junk bytes),
    delete that instruction and recreate it.
    """
    aligned_head = idc.get_item_head(jump_target)
    if aligned_head < jump_target:
        print(
            "Jump target 0x{:X} is in the middle of an instruction. Forcing reanalysis.".format(
                jump_target
            )
        )
        # Delete the existing disassembly at the target address.
        idc.del_items(jump_target, idc.DELIT_SIMPLE)
        # Force disassemble starting from the jump target.
        if not idc.create_insn(jump_target):
            print("Failed to create a new instruction at 0x{:X}".format(jump_target))
    return jump_target


# It should correctly identify the basic blocks in the function.
def identify_basic_blocks_in_function():
    func_addr = 0x14000DF50  # Starting address of the obfuscated function
    func = ida_funcs.get_func(func_addr)
    if not func:
        print(f"Function at address {hex(func_addr)} not found.")
        return
    print(
        f"Function at address {hex(func.start_ea)}, processing until: {hex(func.end_ea)}."
    )
    # 1. Disassembly and Basic Block Identification
    basic_blocks = {}
    instruction_count = 0
    for block_ea in ida_tguidm(idautils.Chunks(func.start_ea)):
        instructions = []
        for head in idautils.Heads(block_ea[0], block_ea[1]):
            instruction_count += 1
            instr = decode_to_instr(head)
            instructions.append((head, ida_ua.ua_mnem(head)))
            if (
                is_call(instr) or is_ret(instr) or is_jmp(instr) or is_jcc(instr)
            ):  # Use helper functions for CFG instructions
                basic_blocks[block_ea[0]] = instructions

    print(
        f"Identified {len(basic_blocks)} basic blocks, and {instruction_count} instructions total."
    )
    print("Basic Blocks Identified (Refined):")
    for start_addr, instrs in basic_blocks.items():
        print(f"Block at {hex(start_addr)}:")
        for addr, mnem in instrs:
            print(f"  {hex(addr)}: {mnem}")


def evaluate_jcc_condition(address: int, uc) -> bool:
    """
    Evaluates a conditional jump instruction at 'address' given the current CPU flags.
    Returns True if the condition is met (i.e. the jump is taken) and False otherwise.
    This modification ensures the address is aligned to the start of the instruction and
    covers all conditional jumps from the comprehensive jump table.
    """
    mnem = idc.print_insn_mnem(address).lower()
    if not mnem:
        # Most likely junk bytes precede the instruction.
        aligned_addr = force_reanalyze_target(address)
        mnem = idc.print_insn_mnem(aligned_addr).lower()

    # First handle register-based conditions.
    if mnem in ["jcxz"]:
        return uc.reg_read(unicorn.x86_const.UC_X86_REG_CX) == 0
    elif mnem in ["jecxz"]:
        return uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX) == 0
    elif mnem in ["jrcxz"]:
        return uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX) == 0

    # Read EFLAGS for flag-based conditions.
    eflags = uc.reg_read(unicorn.x86_const.UC_X86_REG_EFLAGS)
    # Extract standard flags from EFLAGS.
    cf = bool(eflags & 0x1)  # Carry Flag (bit 0)
    pf = bool(eflags & 0x4)  # Parity Flag (bit 2)
    zf = bool(eflags & 0x40)  # Zero Flag (bit 6)
    sf = bool(eflags & 0x80)  # Sign Flag (bit 7)
    of = bool(eflags & 0x800)  # Overflow Flag (bit 11)

    match mnem:
        case "je" | "jz":
            return zf
        case "jne" | "jnz":
            return not zf
        case "jb" | "jnae" | "jc":
            return cf
        case "ja" | "jnbe":
            return not cf and not zf
        case "jbe" | "jna":  # Below or equal (CF set or ZF set)
            return cf or zf
        case "jae" | "jnb" | "jnc":  # Not below (not CF set)
            return not cf
        case "jg" | "jnle":
            return not zf and (sf == of)
        case "jge" | "jnl":
            return sf == of
        case "jl" | "jnge":
            return sf != of
        case "jle" | "jng":
            return zf or (sf != of)
        case "js":
            return sf
        case "jns":
            return not sf
        case "jo":
            return of
        case "jno":
            return not of
        case "jp" | "jpe":
            return pf
        case "jnp" | "jpo":
            return not pf
        case _:
            print("Unknown conditional jump mnemonic:", mnem)
            return False


class PatchType(enum.Enum):
    UNCONDITIONAL = 1
    NOP = 2
    INT3 = 3


@dataclass
class JumpPatch:
    jump_address: int
    fall_through: int
    target: int
    patch_type: PatchType
    instr_size: int

    def __format__(self, format_spec: str) -> str:
        return repr(self)

    def __repr__(self):
        return f"{self.__class__.__name__}(jump_address={format_addr(self.jump_address)}, fall_through={format_addr(self.fall_through)}, target={format_addr(self.target)}, patch_type={self.patch_type}, instr_size={self.instr_size})"


class PatchError(Exception):
    pass


def append_cmt(addr, cmt, dry=False):
    if dry:
        print(f"DRY: Would add comment '{cmt}' at address {addr:#x}")
        return
    e_cmt = idaapi.get_cmt(addr, False) or ""
    if cmt in e_cmt:
        e_cmt = e_cmt.replace(cmt, "")
    else:
        e_cmt += " " + cmt
    idaapi.set_cmt(addr, e_cmt, 0)


def run_autoanalysis(start, end=None):
    if not end:
        end = start + 1
    idaapi.plan_and_wait(start, end)
    idaapi.auto_wait()


def plan_and_wait(address: int, patch_len: int, orig_func_end: int, wait=False):
    if not wait:
        return
    # ask IDA to re-analyze the patched area
    if orig_func_end == idc.BADADDR:
        # only analyze patched bytes, otherwise it would take a lot of time to re-analyze the whole binary
        idaapi.auto_make_code(address)
        idaapi.plan_and_wait(address, address + patch_len + 1)
    else:
        idaapi.auto_make_code(address)
        idaapi.plan_and_wait(address, orig_func_end)
        # try to fix IDA function re-analyze issue after patching
        idc.set_func_end(address, orig_func_end)
    refresh_idaview()
    idaapi.auto_wait()


def patch_bytes(address: int, opcodes, dryrun=False, wait=False):
    opcodes_str = (
        opcodes.hex().upper()
        if isinstance(opcodes, (bytes, bytearray))
        else f"{opcodes:02X}"
    )
    print(f"[+] patching: addr @ 0x{address:02X} with {opcodes_str}")

    # save original function end to fix IDA re-analyze issue after patching
    orig_func_end = idc.get_func_attr(address, idc.FUNCATTR_END)
    if dryrun:
        return

    if isinstance(opcodes, (bytes, bytearray)):
        patched_len = len(opcodes)
        for i, byte in enumerate(opcodes):
            if not ida_bytes.patch_byte(address + i, byte):
                print(
                    f"failed to patch byte at 0x{address + i:02X} with {byte:02X}, already patched?"
                )
    else:
        patched_len = 1
        if not ida_bytes.patch_byte(address, opcodes):
            print(
                f"failed to patch 0x{address:02X} with {opcodes_str}, already patched?"
            )

    if idc.create_insn(address) > 0:
        plan_and_wait(address, patched_len, orig_func_end)
        return

    ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE, 1)
    if idc.create_insn(address) > 0:
        plan_and_wait(address, patched_len, orig_func_end, wait)
        return

    # undefining also helps. Last try (thx IgorS)
    ins = typing.cast(ida_ua.insn_t, idautils.DecodeInstruction(address))
    if not ins.size:
        print(f"WARN: failed to create instruction {address:x}")
        plan_and_wait(address, patched_len, orig_func_end, wait)
        return

    ida_bytes.del_items(address, ida_bytes.DELIT_EXPAND, ins.size)
    if idc.create_insn(address) <= 0:
        print(f"WARN: failed to create instruction {address:x}")

    plan_and_wait(address, patched_len, orig_func_end, wait)


def assemble(addr, what):
    succ, code = idautils.Assemble(addr, what)
    if not succ:
        raise PatchError("failed to assemble " + what)
    return code


def name_at(ea):
    result = idc.get_name(ea)
    if not result:
        result = f"{ea:X}h"
    return result


def to_unconditional_jump(addr):
    instr = decode_to_instr(addr)
    if not is_jcc(instr):
        raise PatchError("not a conditional jump!")
    print(f"to_unconditional_jump (0x{addr:02X})")
    target_addr = idc.get_operand_value(addr, 0)
    ida_bytes.del_items(target_addr)
    # run_autoanalysis(target_addr)
    return patch_ins(addr, "jmp " + name_at(target_addr), force=True)


def patch_ins(address, asm, force=False):
    print(f"patch_ins (0x{address:02X}, {asm})")
    insn_t = decode_to_instr(address)
    new_code = assemble(address, asm)
    new_code_len = len(new_code)

    if not force and insn_t.size < new_code_len:
        raise PatchError(
            f"patching instruction at {address:02X} to {asm} requires more code than current instruction"
        )
    nop(address, new_code_len)
    patch_bytes(address, new_code)
    # for b in new_code:
    #     patch_bytes(address, b)
    #     address += 1
    # assert address == address + new_code_len, f"{address} + {new_code_len} != {address}"
    print(
        f"{format_addr(address)} == {format_addr(address + new_code_len)}? {address == address + new_code_len}"
    )
    return address


def get_nop_instruction():
    """Gets the processor-specific NOP instruction bytes."""
    processor_name = idc.get_inf_attr(idc.INF_PROCNAME)
    if processor_name in (
        "metapc",
        "8086",
        "80286",
        "80386",
        "80486",
        "80586",
        "80686",
    ):
        return b"\x90"
    elif processor_name == "ARM":
        if idc.get_sreg(idc.here(), "T") == 0:
            return b"\x00\x00\xA0\xE3"
        else:
            return b"\x00\xBF"
    elif processor_name == "PPC":
        return b"\x60\x00\x00\x00"
    elif processor_name == "MIPS":
        return b"\x00\x00\x00\x00"
    print(f"Warning: No NOP instruction defined for processor '{processor_name}'")
    return None


def get_single_byte_nop():
    """Gets a single-byte NOP instruction if available."""
    processor_name = idc.get_inf_attr(idc.INF_PROCNAME)
    if processor_name in (
        "metapc",
        "8086",
        "80286",
        "80386",
        "80486",
        "80586",
        "80686",
    ):
        return b"\x90"
    return None


nop_instruction = get_nop_instruction()
single_byte_nop = get_single_byte_nop()


def nop(address, c=None):
    print(f"nop (0x{address:02X}, {c if c else 'whole_instruction'})")
    if not c:
        c = idc.get_item_size(address)
    patch_bytes(address, nop_instruction * (c // len(nop_instruction)))


def hook_code(uc, address, size, user_data):
    # Initialize printed_addresses set if not already present
    if "printed_addresses" not in user_data:
        user_data["printed_addresses"] = set()
    # Only print the disassembly if this address hasn't been printed before
    if address not in user_data["printed_addresses"]:
        disasm_line = idc.generate_disasm_line(address, idc.GENDSM_FORCE_CODE)
        print("0x{:X}: {} ({} bytes)".format(address, disasm_line, size))
        user_data["printed_addresses"].add(address)
    user_data["count"] += 1
    current_instr = decode_to_instr(address)
    if is_jcc(current_instr):
        # Extract jump target first
        jump_target = idc.get_operand_value(address, 0)
        # Check if we've seen this jump target before in user_data to detect loops
        if "visited_jumps" not in user_data:
            user_data["visited_jumps"] = set()
        if jump_target in user_data["visited_jumps"]:
            print(
                "Jump at 0x{:X} has been seen before (likely part of a loop); skipping patching.".format(
                    address
                )
            )
            user_data["resolved_jcc"] = jump_target
            uc.emu_stop()
            return
        user_data["visited_jumps"].add(jump_target)

        # Evaluate the jump condition using the current CPU flags.
        taken = evaluate_jcc_condition(address, uc)
        instr_size = idc.get_item_size(address)
        fall_through = address + instr_size
        if taken:
            print(
                "Conditional jump {} at 0x{:X} always taken. Scheduling patch to replace with unconditional jump. Next instruction: 0x{:X}, Jump operand: 0x{:X}".format(
                    ida_ua.ua_mnem(address), address, fall_through, jump_target
                )
            )
            patch_type = PatchType.UNCONDITIONAL
        else:
            print(
                "Conditional jump {} at 0x{:X} never taken. Scheduling patch to remove jump (NOP). Next instruction: 0x{:X}, Jump operand: 0x{:X}".format(
                    ida_ua.ua_mnem(address), address, fall_through, jump_target
                )
            )
            patch_type = PatchType.NOP
        if "patches" not in user_data:
            user_data["patches"] = []
        patch = JumpPatch(
            jump_address=address,
            fall_through=fall_through,
            target=jump_target,
            patch_type=patch_type,
            instr_size=instr_size,
        )
        user_data["patches"].append(patch)
        # Set resolved jump for emulation: jump target if taken; otherwise, fall-through.
        resolved = jump_target if taken else fall_through
        user_data["resolved_jcc"] = resolved
        uc.emu_stop()
        return
    elif is_jmp(current_instr):
        jump_target = idc.get_operand_value(address, 0)
        real_head = idc.get_item_head(jump_target)
        if jump_target != real_head:
            gap_size = jump_target - real_head
            print(
                "Unconditional jump at 0x{:X} has an opaque predicate: its operand target 0x{:X} falls in the middle of an instruction starting at 0x{:X} (gap size: {} bytes). Recording a JumpPatch.".format(
                    address, jump_target, real_head, gap_size
                )
            )
            patch = JumpPatch(
                jump_address=real_head,  # start of misaligned instruction
                fall_through=real_head,
                target=jump_target,
                patch_type=PatchType.INT3,
                instr_size=gap_size,
            )
            if "patches" not in user_data:
                user_data["patches"] = []
            user_data["patches"].append(patch)
        if "patched_uncond" not in user_data:
            user_data["patched_uncond"] = set()
        user_data["patched_uncond"].add(address)

    if (
        user_data["max_instructions"]
        and user_data["count"] >= user_data["max_instructions"]
    ):
        print("Max instructions reached: stopping emulation")
        uc.emu_stop()


def emulate_block(uc, start_addr, state):
    """
    Run emulation starting at start_addr.

    Optionally stop when stop_addr is reached or after max_instructions have executed.

    Enhanced to resolve conditional jumps:
      - On encountering a jcc instruction, the hook function evaluates the CPU flags.
      - It then computes the next block address: if the condition is true, the jump's target
        is used; otherwise, execution continues to the next instruction.
    """

    uc.hook_add(unicorn.UC_HOOK_CODE, hook_code, user_data=state)

    try:
        uc.emu_start(start_addr, 0)
    except unicorn.UcError as e:
        current_pc = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        print("Emulation error at 0x{:X}: {}".format(current_pc, e))

    return state.get("resolved_jcc")


def map_combined_segments(uc, seg_name, prot, PAGE_SIZE=0x1000, copy_content=True):
    segs = []
    for seg_ea in idautils.Segments():
        if idc.get_segm_name(seg_ea) == seg_name:
            seg_start = seg_ea
            seg_end = idc.get_segm_end(seg_ea)
            segs.append((seg_start, seg_end))

    if not segs:
        print("No segments found for", seg_name)
        return

    # Compute the union of all segments.
    min_start = min(seg[0] for seg in segs)
    max_end = max(seg[1] for seg in segs)

    # Align the union to page boundaries.
    aligned_start = min_start & ~(PAGE_SIZE - 1)
    aligned_end = (max_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    size = aligned_end - aligned_start

    print(
        f"Mapping combined segment {seg_name}: {hex(aligned_start)} - {hex(aligned_end)} (size: 0x{size:X})"
    )

    # Map the combined region.
    uc.mem_map(aligned_start, size, prot)

    if copy_content:
        # Optionally, write data from each segment into the mapped region.
        for seg_start, seg_end in segs:
            seg_size = seg_end - seg_start
            seg_bytes = idc.get_bytes(seg_start, seg_size)
            if seg_bytes:
                uc.mem_write(seg_start, seg_bytes)
    return aligned_start, size


def dump_registers(uc):
    """Dump all x86_64 registers in a formatted output."""
    registers = {
        "RAX": unicorn.x86_const.UC_X86_REG_RAX,
        "RBX": unicorn.x86_const.UC_X86_REG_RBX,
        "RCX": unicorn.x86_const.UC_X86_REG_RCX,
        "RDX": unicorn.x86_const.UC_X86_REG_RDX,
        "RSI": unicorn.x86_const.UC_X86_REG_RSI,
        "RDI": unicorn.x86_const.UC_X86_REG_RDI,
        "RBP": unicorn.x86_const.UC_X86_REG_RBP,
        "RSP": unicorn.x86_const.UC_X86_REG_RSP,
        "RIP": unicorn.x86_const.UC_X86_REG_RIP,
        "R8": unicorn.x86_const.UC_X86_REG_R8,
        "R9": unicorn.x86_const.UC_X86_REG_R9,
        "R10": unicorn.x86_const.UC_X86_REG_R10,
        "R11": unicorn.x86_const.UC_X86_REG_R11,
        "R12": unicorn.x86_const.UC_X86_REG_R12,
        "R13": unicorn.x86_const.UC_X86_REG_R13,
        "R14": unicorn.x86_const.UC_X86_REG_R14,
        "R15": unicorn.x86_const.UC_X86_REG_R15,
        "EFLAGS": unicorn.x86_const.UC_X86_REG_EFLAGS,
    }

    print("\n--- Register Dump (x86_64) ---")
    for reg_name, reg_id in registers.items():
        value = uc.reg_read(reg_id)
        padded_reg_name = reg_name.rjust(3)
        print(f"{padded_reg_name}: 0x{value:016X}")
    print("-----------------------------\n")


def hook_exception(uc, access, address, size, value, user_data):
    """Robust exception hook: attempt to map missing memory so that emulation can continue.
    If the access error is due to unmapped memory, map a page at the aligned address and resume.
    Otherwise, if mapping fails, stop execution."""
    print(
        f"Exception: access={access} at address: 0x{address:016X}, size={size}, value={value}"
    )
    dump_registers(uc)

    PAGE_SIZE = 0x1000
    aligned_addr = address & ~(PAGE_SIZE - 1)

    try:
        # Try to map a new page at the missing address with all permissions
        uc.mem_map(aligned_addr, PAGE_SIZE, unicorn.UC_PROT_ALL)
        print(
            f"Mapped missing memory at 0x{aligned_addr:016X} (size: 0x{PAGE_SIZE:X}). Resuming emulation."
        )
        return True  # Resume emulation
    except unicorn.UcError as e:
        print(f"Failed to handle exception at 0x{address:016X}: {e}")
        return False


def deobfuscate_code(display_basic_blocks=False, memo: dict = None):
    """Dynamic emulation pass using Unicorn to trace execution and resolve conditional jumps.
    Optionally, collect resolved jumps in memo under key 'dynamic_jumps'."""
    func_addr = 0x14000DF55  # Starting address of the obfuscated function
    func = ida_funcs.get_func(func_addr)
    if not func:
        print(f"Function at address {hex(func_addr)} not found.")
        return

    print("Waiting for IDA auto-analysis to finish...")
    run_autoanalysis(func.start_ea, func.end_ea)

    print(
        f"Function at address {hex(func.start_ea)}, processing until: {hex(func.end_ea)}."
    )

    # Initialize Unicorn emulator
    uc = unicorn.Uc(
        unicorn.UC_ARCH_X86, unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN
    )
    # Set up exception hook
    uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, hook_exception)

    # Map low memory to cover gs:[rax] accesses (e.g., from 0x0 to 0x1000)
    uc.mem_map(0x0, 0x1000, unicorn.UC_PROT_ALL)
    seg_bytes = idc.get_bytes(0x0, 0x100)
    if seg_bytes:
        uc.mem_write(0x0, seg_bytes)

    # Map memory regions (adjust addresses and sizes as needed)
    code_segment = ida_segment.get_segm_by_name(".text")  # Get code segment
    stack_base = 0x004000000  # Higher stack base address
    stack_size = 8 * 1024 * 1024  # 8MB stack size
    uc.mem_map(
        code_segment.start_ea,
        code_segment.end_ea - code_segment.start_ea,
        unicorn.UC_PROT_ALL,
    )

    map_combined_segments(uc, ".data", unicorn.UC_PROT_ALL)
    uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_ALL)  # Map stack

    code_bytes = idc.get_bytes(
        code_segment.start_ea, code_segment.end_ea - code_segment.start_ea
    )
    uc.mem_write(code_segment.start_ea, code_bytes)

    # Set initial registers (example)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, stack_base + stack_size - 0x1000)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, 0x0)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, 0x49)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, 0x1)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RBP, 0x0)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDI, 0x1)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_R8, 0x0)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_R10, 0x0)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_R14, 0x1)

    # (Optional) Perform disassembly and basic block identification.
    basic_blocks = {}
    instruction_count = 0
    for bb in get_function_blocks(func):
        instructions = []
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            instruction_count += 1
            instructions.append((head, ida_ua.ua_mnem(head)))
        basic_blocks[bb.start_ea] = instructions

    print(
        f"Identified {len(basic_blocks)} basic blocks, and {instruction_count} instructions total."
    )
    if display_basic_blocks:
        for start_addr, instrs in basic_blocks.items():
            print(f"Block at {hex(start_addr)}:")
            for addr, mnem in instrs:
                print(f"  {hex(addr)}: {mnem}")

    # --- Control Flow Simulation via Resolved Conditional Jumps ---
    current_addr = func.start_ea

    # key: basic block start address, value: number of times visited
    visited = defaultdict(int)

    memo.update(
        {
            "count": 0,
            "resolved_jcc": None,
            "stop_addr": None,
            "max_instructions": 0,
            "patches": [],
            # List to record resolved jump addresses dynamically
            "dynamic_jumps": [],
        }
    )

    while func.start_ea <= current_addr < func.end_ea:
        visited[current_addr] += 1
        if visited[current_addr] > 5:
            print(
                f"Potential infinite loop detected at block {format_addr(current_addr)} (visited {visited[current_addr]} times). Skipping this block."
            )
            current_addr += idc.get_item_size(current_addr)
            continue
        print(f"\nEmulating basic block starting at {format_addr(current_addr)}...")
        next_addr = emulate_block(uc, current_addr, state=memo)
        if next_addr is None:
            print("No conditional jump was hit, using the PC reported by Unicorn.")
            next_addr = uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
        if memo.get("resolved_jcc") is not None:
            print(f"Dynamic jump taken: {format_addr(memo['resolved_jcc'])}")
            memo["dynamic_jumps"].append(format_addr(memo["resolved_jcc"]))
            current_addr = memo["resolved_jcc"]
        else:
            print(f"Resolved next basic block address: {format_addr(next_addr)}")
            current_addr = next_addr

    print(
        "\nSymbolic Execution Completed (Basic Block Emulation with Conditional Jump Resolution)."
    )


def update_flag_state(flag_state, address):
    """Update the static flag state for a given instruction address."""
    mnem = idc.print_insn_mnem(address)
    if not mnem:
        return flag_state
    mnem_lower = mnem.lower()
    # Deterministic instructions that set flags to a known state
    if mnem_lower in ("test", "and", "xor", "or"):
        return {"CF": 0, "OF": 0}
    elif mnem_lower == "clc":
        new_state = flag_state.copy() if flag_state is not None else {}
        new_state["CF"] = 0
        return new_state
    elif mnem_lower == "stc":
        new_state = flag_state.copy() if flag_state is not None else {}
        new_state["CF"] = 1
        return new_state
    # Instructions that do not affect flags
    elif mnem_lower in ("mov", "lea", "nop", "xchg"):
        return flag_state
    # Shift instructions: if shift count is 0 then flags remain unchanged
    elif mnem_lower in ("sal", "shl", "sar", "shr", "rol", "ror", "rcl", "rcr"):
        try:
            count = idc.get_operand_value(address, 1)
            return flag_state if count == 0 else None
        except Exception:
            return None
    # CMOV instructions do not affect flags
    elif mnem_lower.startswith("cmov"):
        return flag_state
    # For jumps, flags are not modified
    elif mnem_lower.startswith("j"):
        return flag_state
    # For any other instruction, we assume flags become undetermined
    else:
        return None


def static_evaluate_jcc_condition(flag_state, mnem):
    """Evaluate a conditional jump instruction statically using flag_state.
    Returns True if the condition is deterministically met, False if not met, or None if unknown.
    Only handles CF/OF dependent jumps."""
    if flag_state is None:
        return None
    # jno: jump if no overflow (OF == 0)
    if mnem in ("jno",):
        if "OF" in flag_state:
            return not flag_state["OF"]
        return None
    # jb, jnae, jc: jump if below/unsigned, condition: CF == 1
    elif mnem in ("jb", "jnae", "jc"):
        if "CF" in flag_state:
            return bool(flag_state["CF"])
        return None
    # jae, jnb, jnc: jump if above or equal / not below, condition: CF == 0
    elif mnem in ("jae", "jnb", "jnc"):
        if "CF" in flag_state:
            return not bool(flag_state["CF"])
        return None
    else:
        return None


def first_pass_identify_impossible_jumps(func_addr, display_detailed=False, memo=None):
    """First pass static analysis to identify impossible conditional jumps in a function.
    It iterates over basic blocks, simulating flag state from deterministic instructions.
    When a conditional jump is encountered and its condition can be resolved using CF/OF,
    it prints whether the jump is always taken or never taken. Results are recorded in memo if provided.
    """
    func = ida_funcs.get_func(func_addr)
    if not func:
        print("Function at address {} not found.".format(hex(func_addr)))
        return
    print(
        "\nAnalyzing function at {} to identify impossible jumps.".format(
            hex(func.start_ea)
        )
    )
    results = []
    # Iterate over basic blocks in the function
    for bb in get_function_blocks(func):
        flag_state = None
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            mnem = idc.print_insn_mnem(head)
            if not mnem:
                continue
            mnem_lower = mnem.lower()
            # Update flag state with the current instruction
            flag_state = update_flag_state(flag_state, head)
            # Check if instruction is a conditional jump (but not an unconditional jmp)
            if ConditionalJumps.is_jcc(mnem_lower):
                formatted_head = format_addr(head)
                resolved = static_evaluate_jcc_condition(flag_state, mnem_lower)
                if resolved is not None:
                    jump_target = idc.get_operand_value(head, 0)
                    if resolved:
                        formatted_jump = format_addr(jump_target)
                        result_str = (
                            "Conditional jump {} at {} always TAKEN to {}".format(
                                mnem, formatted_head, formatted_jump
                            )
                        )
                    else:
                        next_addr = head + idc.get_item_size(head)
                        formatted_next = format_addr(next_addr)
                        result_str = "Conditional jump {} at {} never TAKEN (fallthrough always) to {}".format(
                            mnem, formatted_head, formatted_next
                        )
                    results.append(result_str)
                    if display_detailed:
                        print(result_str)
    print("\nSummary of statically resolved jumps:")
    for res in results:
        print(res)

    # Store results in memo if provided
    if memo is not None:
        memo["static_impossible_jumps"] = results


def patch_impossible_jumps(func_addr, display_detailed=False):
    """Patch statically-resolved impossible conditional jumps in the function to unconditional jumps.
    For each conditional jump that is deterministically always or never taken, it patches the instruction to an unconditional jump
    and appends a comment documenting the original instruction.

    Note: Although the static analysis pass records results in the memo (see first_pass_identify_impossible_jumps),
    we re-iterate over the function's basic blocks during patching to operate on the current disassembly state.
    This ensures that any modifications or reanalyses performed after the static pass are accounted for.
    """
    func = ida_funcs.get_func(func_addr)
    if not func:
        print(f"Function at address {hex(func_addr)} not found.")
        return

    print(f"Patching impossible jumps in function at {hex(func.start_ea)}...")
    patches = []
    for bb in get_function_blocks(func):
        flag_state = None
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            mnem = idc.print_insn_mnem(head)
            if not mnem:
                continue
            mnem_lower = mnem.lower()
            flag_state = update_flag_state(flag_state, head)
            if ConditionalJumps.is_jcc(mnem_lower):
                resolved = static_evaluate_jcc_condition(flag_state, mnem_lower)
                if resolved is not None:
                    original_disasm = (
                        idc.generate_disasm_line(head, idc.GENDSM_FORCE_CODE) or "N/A"
                    )
                    patches.append((head, original_disasm))

    for head, original_disasm in patches:
        comment = f"Patched jmp, original: {original_disasm.strip()}"
        append_cmt(head, comment, dry=False)
        try:
            to_unconditional_jump(head)
            if display_detailed:
                jt = idc.get_operand_value(head, 0)
                print(
                    f"Patched jump at {hex(head)} to unconditional jump to {name_at(jt)}"
                )
        except Exception as e:
            print(f"Failed to patch jump at {hex(head)}: {e}")
            import traceback

            traceback.print_exc()
    print("Patching of impossible jumps completed.\n")


def patch_dynamic_jumps(func_addr, memo, display_detailed=False):
    """Patch conditional jumps based on dynamic emulation results recorded in memo["dynamic_jumps"].
    For each conditional jump in the function, if its jump target matches one of the dynamically resolved targets,
    patch it to an unconditional jump."""
    if not memo or "patches" not in memo:
        print("No dynamic patches recorded in memo.")
        return

    patches = memo["patches"]
    func = ida_funcs.get_func(func_addr)
    if not func:
        print(f"Function at address {hex(func_addr)} not found.")
        return

    print(f"Patching dynamic jumps in function at {hex(func.start_ea)}...")
    for patch in patches:
        head = patch.jump_address
        original_disasm = idc.generate_disasm_line(head, idc.GENDSM_FORCE_CODE) or "N/A"
        if patch.patch_type == PatchType.UNCONDITIONAL:
            comment = f"Patched dynamic jump, original: {original_disasm.strip()}"
            append_cmt(head, comment, dry=False)
            try:
                to_unconditional_jump(head)
                if display_detailed:
                    print(
                        f"Patched dynamic jump at {format_addr(head)} to unconditional jump to {name_at(patch.target)}"
                    )
            except Exception as e:
                print(f"Failed to patch dynamic jump at {format_addr(head)}: {e}")
        elif patch.patch_type == PatchType.NOP:
            comment = f"Nopped opaque dynamic jump (never taken), original: {original_disasm.strip()}"
            append_cmt(head, comment, dry=False)
            try:
                item_size = patch.instr_size
                nop(head, item_size)
                if display_detailed:
                    print(f"Nopped opaque dynamic jump at {format_addr(head)}")
            except Exception as e:
                print(f"Failed to nop dynamic jump at {format_addr(head)}: {e}")
        elif patch.patch_type == PatchType.INT3:
            comment = f"INT3'd opaque dynamic jump (never taken), original: {original_disasm.strip()}"
            append_cmt(head, comment, dry=False)
            try:
                item_size = patch.instr_size
                nop(head, item_size)
                if display_detailed:
                    print(f"INT3'd opaque dynamic jump at {format_addr(head)}")
            except Exception as e:
                print(f"Failed to int3 dynamic jump at {format_addr(head)}: {e}")
    print("Patching of dynamic jumps completed.")


def cleanup_junk_bytes(func_addr, display_detailed=False):
    """Clean up junk bytes between disassembled instructions in the function by NOP-ing them out."""
    func = ida_funcs.get_func(func_addr)
    if not func:
        print(f"Function at {format_addr(func_addr)} not found for cleanup!")
        return

    start = func.start_ea
    end = func.end_ea
    prev_end = start
    for head in idautils.Heads(start, end):
        if head > prev_end:
            gap_size = head - prev_end
            print(
                f"Cleaning up junk bytes from {format_addr(prev_end)} to {format_addr(head)} (size: {gap_size} bytes)"
            )
            nop(prev_end, gap_size)
        head_size = idc.get_item_size(head)
        prev_end = head + head_size
    if prev_end < end:
        gap_size = end - prev_end
        print(
            f"Cleaning up junk bytes from {format_addr(prev_end)} to {format_addr(end)} (size: {gap_size} bytes)"
        )
        nop(prev_end, gap_size)
    print("Cleanup of junk bytes completed.")

    # Additional cleanup: fix misaligned jump targets that land in the middle of an instruction.
    patched_ranges = []
    for head in idautils.Heads(start, end):
        decoded = decode_to_instr(head)
        if is_jmp(decoded) or is_jcc(decoded) or is_call(decoded):
            target = idc.get_operand_value(head, 0)
            if not target:
                continue
            real_head = idc.get_item_head(target)
            if target > real_head:
                gap = target - real_head
                # Check if this range has already been patched
                if any(
                    real_head >= rng[0] and target <= rng[1] for rng in patched_ranges
                ):
                    continue
                print(
                    f"Detected misaligned jump at {format_addr(head)}: target {format_addr(target)} falls into middle of instruction starting at {format_addr(real_head)}. Cleaning up junk bytes from {format_addr(real_head)} to {format_addr(target)} (size: {gap} bytes)"
                )
                nop(real_head, gap)
                patched_ranges.append((real_head, target))
    print("Additional misaligned jump cleanup completed.")


def decompile_function(func_start: int):
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)

    ida_auto.auto_wait()


def reset_problems_in_function(func_start: int, func_end: int):
    """
    There's a bug in IDA's API.
    If one undefines and redefines a function's data, the operands are marked as a disassembly problem.
    This resets each problem in the reanalyzed functions.
    """
    current_address: int = func_start
    while current_address != func_end:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        current_address = current_address + 1


def reanalyze_function(func_start: int, func_end: int = None, decompile: bool = False):
    if not func_end:
        func_end = idc.find_func_end(func_start)

    size = func_end - func_start
    ida_bytes.del_items(func_start, 0, size)
    for i in range(size):
        idaapi.create_insn(func_start + i)
    ida_funcs.add_func(func_start, func_end)
    idaapi.auto_wait()
    if decompile:
        decompile_function(func_start)
    print(f"Fixed function {hex(func_start)}")
    reset_problems_in_function(func_start, func_end)


# --- New Deflow Pass for Jump Collision Resolution ---


def is_in_range(ea):
    """Check if the address is in the .text segment. This can be refined if needed to target a specific function range."""
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    return idaapi.get_segm_name(seg) == ".text"


def deflow_chunk(address, already_discovered, dry=False):
    """
    Process a chunk starting at the given address, checking for jump collisions.
    Returns a list of new addresses discovered.
    Dry mode (dry=True) will print out the planned patches instead of applying them.
    """
    new_chunks = []
    is_negative = ((address >> 63) & 1) == 1
    address = address & (~(1 << 63))

    if address in already_discovered:
        return new_chunks
    already_discovered.add(address)

    last_branch = 0
    last_branch_size = 0
    last_target = 0

    ea = address
    while True:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            if last_target == 0:
                return new_chunks
            break

        mnem = insn.get_canon_mnem().lower()
        size = insn.size

        if mnem == "ret":
            if last_target == 0:
                return new_chunks
            break

        is_jmp_instr = False
        target = 0

        if is_jcc(insn):
            if last_target == 0:
                target = idc.get_operand_value(ea, 0)
                if is_in_range(target):
                    if size > 2:
                        is_jmp_instr = False
                        new_chunks.append(target)
                    else:
                        is_jmp_instr = True
                else:
                    is_jmp_instr = False
            else:
                is_jmp_instr = False

        elif mnem in ["jmp", "call"]:
            if last_target == 0:
                new_address = idc.get_operand_value(ea, 0)
                if is_in_range(new_address):
                    if mnem == "call":
                        next_ea = ea + size
                        new_chunks.append(next_ea)
                    new_chunks.append(new_address)
                    return new_chunks

        location = ea
        steps_left = (last_target - location) if last_target != 0 else 0

        if last_target == 0 and is_jmp_instr:
            last_branch = location
            last_branch_size = size
            last_target = target
        else:
            if last_target != 0 and steps_left <= 0:
                if steps_left != 0:
                    count = last_target - last_branch
                    if count > 0:
                        buffer_offset = last_branch
                        # Determine opcode and comment based on is_negative
                        instr_opcode = 0x90 if is_negative else 0xCC
                        instr_comment = "NOP" if is_negative else "INT3"
                        for i in range(count - last_branch_size):
                            current_patch_addr = buffer_offset + last_branch_size + i
                            patch_bytes(current_patch_addr, instr_opcode, dryrun=dry)
                            append_cmt(current_patch_addr, instr_comment, dry=dry)
                        if not is_negative:
                            patch_bytes(
                                buffer_offset, 0xEB, dryrun=dry
                            )  # Unconditional jump
                            append_cmt(buffer_offset, "Unconditional jump", dry=dry)
                        if dry:
                            print(
                                f"DRY: Would add new chunk with address {last_target:#x}"
                            )
                        new_chunks.append(last_target)
                        return new_chunks
                    else:
                        negative_addr = last_target | (1 << 63)
                        if dry:
                            print(
                                f"DRY: Would add new chunk with negative address {negative_addr:#x}"
                            )
                        new_chunks.append(negative_addr)
                        return new_chunks
                else:
                    if dry:
                        print(
                            f"DRY: Would add new chunks with addresses {(last_branch + last_branch_size):#x} and {last_target:#x}"
                        )
                    new_chunks.append(last_branch + last_branch_size)
                    new_chunks.append(last_target)
                    return new_chunks
        ea += size
    return new_chunks


def deflow(function_list, already_discovered):
    """
    Run deflow pass on a list of function entry addresses.
    Iteratively discovers new chunks from jump instructions and patches collisions.
    """
    for fn in ida_tguidm(function_list):
        chunks = deflow_chunk(fn, already_discovered)
        while chunks:
            new_chunks = []
            for c in chunks:
                new_chunks.extend(deflow_chunk(c, already_discovered))
            if not new_chunks:
                break
            chunks = new_chunks


def run_deflow_on_function(func_addr, already_discovered):
    """
    Run the deflow pass on a specific function given its entry address.
    """
    print("Running deflow pass on function at {:#X}".format(func_addr))
    deflow([func_addr], already_discovered)


def main(phases=None, wait_time=5):
    if not phases:
        phases = ["deflow", "static", "dynamic"]
    clear_output()
    memo = {}
    already_discovered = set()
    while phases:
        phase = phases.pop(0)
        match phase:
            case "deflow_text_section":
                print("Running deflow pass on text section...")
                textsec = idaapi.getsegm_by_name(".text")
                deflow(
                    idautils.Functions(textsec.start_ea, textsec.end_ea),
                    already_discovered,
                )
                refresh_idaview()
            case "deflow":
                print("Running deflow pass...")
                run_deflow_on_function(0x14000DF55, already_discovered)
                refresh_idaview()
            case "static":
                print("Running static analysis pass...")
                first_pass_identify_impossible_jumps(
                    0x14000DF55, display_detailed=True, memo=memo
                )
            case "dynamic":
                # Run dynamic emulation pass
                print("Running dynamic emulation pass...")
                deobfuscate_code(display_basic_blocks=False, memo=memo)
            case "cleanup":
                print("Cleaning up junk bytes...")
                cleanup_junk_bytes(0x14000DF55, display_detailed=True)
                refresh_idaview()
            case "patch_impossible_jumps":
                print("Patching impossible jumps...")
                patch_impossible_jumps(0x14000DF55, display_detailed=True)
                refresh_idaview()
            case "patch_dynamic_jumps":
                print("Patching dynamic jumps...")
                patch_dynamic_jumps(0x14000DF55, memo, display_detailed=True)
                refresh_idaview()
            case "wait":
                print(f"Waiting for {wait_time} seconds...")
                time.sleep(wait_time)
                refresh_idaview()
            case "reanalyze":
                print("Reanalyzing function...")
                reanalyze_function(0x14000DF55, decompile=False)
                refresh_idaview()
            case _:
                print(f"Unknown phase: {phase}")
                break

    # # Run static analysis pass with default function address and detailed output enabled
    # print("Running static analysis pass...")
    # first_pass_identify_impossible_jumps(0x14000DF55, display_detailed=True, memo=memo)

    # # Patch impossible jumps to unconditional jumps (static resolution)
    # print("Patching impossible jumps...")
    # patch_impossible_jumps(0x14000DF55, display_detailed=True)
    # time.sleep(5)
    # refresh_idaview()

    # # Run deflow pass before dynamic emulation
    # print("Running deflow pass...")
    # run_deflow_on_function(0x14000DF55)
    # refresh_idaview()

    # # Patch dynamic jumps recorded during emulation
    # print("Patching dynamic jumps...")
    # patch_dynamic_jumps(0x14000DF55, memo, display_detailed=True)
    # refresh_idaview()

    # # Clean up junk bytes between patched jumps
    # print("Cleaning up junk bytes...")
    # cleanup_junk_bytes(0x14000DF55, display_detailed=True)
    # refresh_idaview()

    print("\nMemo object contents:")
    for key, value in memo.items():
        print(f"{key} => {value}")


# --- Modified __main__ block to include deflow pass ---
if __name__ == "__main__":
    # Run deflow pass on text section

    # main(
    #     phases=[
    #         "deflow_text_section",
    #         "wait",
    #         "reanalyze",
    #     ],
    #     wait_time=5,
    # )
    main(
        phases=[
            # "deflow",
            # "wait",
            # "patch_impossible_jumps",
            # "wait",
            # "reanalyze",
            # "wait",
            "dynamic",
            "wait",
            "patch_dynamic_jumps",
            "wait",
            "reanalyze",
            "wait",
        ],
        wait_time=5,
    )


"""
text:0000000140015E31 EB 17                                               jmp     short near ptr loc_140015E45+5 ;  Patched jmp, original: jno     short near ptr loc_140015E45+5
.text:0000000140015E33                                     ; ---------------------------------------------------------------------------
.text:0000000140015E33 C0 EE 00                                            shr     dh, 0
.text:0000000140015E36 90                                                  nop                     ;  Nopped opaque dynamic jump (never taken), original: jo      short near ptr loc_140015E45+5
.text:0000000140015E37 90                                                  nop
.text:0000000140015E38 F6 DE                                               neg     dh
.text:0000000140015E3A 80 EA B7                                            sub     dl, 0B7h
.text:0000000140015E3D 80 ED 8D                                            sub     ch, 8Dh
.text:0000000140015E40 80 ED 09                                            sub     ch, 9
.text:0000000140015E43 F6 DB                                               neg     bl
.text:0000000140015E45
.text:0000000140015E45                                     loc_140015E45:                          ; CODE XREF: TlsInitialization_Internal(void *,syshdr::win::DllLoadReason,void *)+7EE1↑j
.text:0000000140015E45 83 9C EC 0C D6 48 8B 84                             sbb     [rsp+rbp*8+var_74B729F4], 0FFFFFF84h
"""
