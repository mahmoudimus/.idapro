from __future__ import annotations
import functools
import typing
from collections.abc import Sized
from dataclasses import dataclass, field

import ida_allins
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_segment
import ida_ua
import idaapi
import idautils
import idc

import ida_t00lz
import ida_t00lz.settable_generator

SettableGenerator = ida_t00lz.settable_generator.SettableGenerator
# ida_idaapi.require("SettableGenerator", "ida_t00lz.settable_generator")
# # ida_idaapi.require("ida_t00lz.settable_generator")
# print(SettableGenerator)
# if typing.TYPE_CHECKING:
#     # import ida_t00lz
#     # import ida_t00lz.settable_generator
#     ...


def clear_window(window):
    form = ida_kernwin.find_widget(window)
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


def clear_output():
    clear_window("Output window")


def plan_and_wait(address: int, patch_len: int, orig_func_end: int):
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
    idaapi.refresh_idaview_anyway()
    idaapi.auto_wait()


def patch_bytes(addr: "Instruction", opcodes, dryrun=False):
    print(f"[+] patching: {addr:x} with 0x{opcodes:02X}")
    address = addr.address
    # save original function end to fix IDA re-analyze issue after patching
    orig_func_end = idc.get_func_attr(address, idc.FUNCATTR_END)
    if dryrun:
        return

    patched_len = len(opcodes) if isinstance(opcodes, Sized) else 1

    # Convert to code and define as function
    ida_bytes.patch_byte(address, opcodes)
    if idc.create_insn(address) > 0:
        plan_and_wait(address, patched_len, orig_func_end)
        return

    ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE, 1)
    if idc.create_insn(address) > 0:
        plan_and_wait(address, patched_len, orig_func_end)
        return

    # undefining also helps. Last try (thx IgorS)
    ins = typing.cast(ida_ua.insn_t, idautils.DecodeInstruction(address))
    if not ins.size:
        print(f"WARN: failed to create instruction {address:x}")
        plan_and_wait(address, patched_len, orig_func_end)
        return

    ida_bytes.del_items(address, ida_bytes.DELIT_EXPAND, ins.size)
    if idc.create_insn(address) <= 0:
        print(f"WARN: failed to create instruction {address:x}")

    plan_and_wait(address, patched_len, orig_func_end)


# ---------------------------------------------------------------------------
# Conditional jump (Jcc) instructions
# conditional_jumps = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
JCC_INSTRUCTIONS = {
    idaapi.NN_ja,
    idaapi.NN_jae,
    idaapi.NN_jb,
    idaapi.NN_jbe,
    idaapi.NN_jc,
    idaapi.NN_je,
    idaapi.NN_jg,
    idaapi.NN_jge,
    idaapi.NN_jl,
    idaapi.NN_jle,
    idaapi.NN_jna,
    idaapi.NN_jnae,
    idaapi.NN_jnb,
    idaapi.NN_jnbe,
    idaapi.NN_jnc,
    idaapi.NN_jne,
    idaapi.NN_jng,
    idaapi.NN_jnge,
    idaapi.NN_jnl,
    idaapi.NN_jnle,
    idaapi.NN_jno,
    idaapi.NN_jnp,
    idaapi.NN_jns,
    idaapi.NN_jnz,
    idaapi.NN_jo,
    idaapi.NN_jp,
    idaapi.NN_jpe,
    idaapi.NN_jpo,
    idaapi.NN_js,
    idaapi.NN_jz,
}


CALL_INSTRUCTIONS = {
    idaapi.NN_call,
    idaapi.NN_callfi,
    idaapi.NN_callni
}

LOOP_INSTRUCTIONS = {
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
}

# List of jump instructions
jumps = [
    ida_allins.NN_ja,
    ida_allins.NN_jae,
    ida_allins.NN_jb,
    ida_allins.NN_jbe,
    ida_allins.NN_jc,
    ida_allins.NN_jcxz,
    ida_allins.NN_jecxz,
    ida_allins.NN_jrcxz,
    ida_allins.NN_je,
    ida_allins.NN_jg,
    ida_allins.NN_jge,
    ida_allins.NN_jl,
    ida_allins.NN_jle,
    ida_allins.NN_jna,
    ida_allins.NN_jnae,
    ida_allins.NN_jnb,
    ida_allins.NN_jnbe,
    ida_allins.NN_jnc,
    ida_allins.NN_jne,
    ida_allins.NN_jng,
    ida_allins.NN_jnge,
    ida_allins.NN_jnl,
    ida_allins.NN_jnle,
    ida_allins.NN_jno,
    ida_allins.NN_jnp,
    ida_allins.NN_jns,
    ida_allins.NN_jnz,
    ida_allins.NN_jo,
    ida_allins.NN_jp,
    ida_allins.NN_jpe,
    ida_allins.NN_jpo,
    ida_allins.NN_js,
    ida_allins.NN_jz,
]


@functools.total_ordering
@dataclass
class Instruction:
    address: int

    _insn: ida_ua.insn_t = field(init=False)

    def __format__(self, format_spec: str) -> str:
        return repr(self)

    @property
    def is_negative(self):
        return (self.address >> 63) == 1

    def __bool__(self):
        return self.address != 0

    def __abs__(self):
        return Instruction(
            self.address & ~(1 << 63)) if self.is_negative else self

    def __hash__(self):
        return hash(self.address)

    def __repr__(self):
        return f'<{"-" if self.is_negative else ""}0x{abs(self.address):08x}>'

    def __lt__(self, other):
        return self.address < other

    def __eq__(self, other):
        return self.address == other

    def __mod__(self, other):
        return self.address % other

    def __add__(self, other):
        return self.address + other

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        return self.address - other

    def __rsub__(self, other):
        return other.__sub__(self.address)

    def __neg__(self):
        return -self.address

    def __pos__(self):
        return +self

    def __mul__(self, other):
        return self.address * other

    def __rmul__(self, other):
        return self.__mul__(other)

    def __invert__(self):
        return ~self.address

    def __rshift__(self, other):
        return self.address >> other

    def __lshift__(self, other):
        return self.address << other

    def __rlshift__(self, other):
        return other << self.address

    def __rrshift__(self, other):
        return other >> self.address

    def __and__(self, other):
        return self.address & other

    def __rand__(self, other):
        return other & self.address

    def __xor__(self, other):
        return self.address ^ other

    def __rxor__(self, other):
        return other ^ self.address

    def __or__(self, other):
        return self.address | other

    def __ror__(self, other):
        return other | self.address

    def __int__(self):
        return self.address

    def __post_init__(self):
        decoded_instr = idautils.DecodeInstruction(self.address)
        self._insn = typing.cast(ida_ua.insn_t, decoded_instr)

    @property
    def is_call(self):
        """Is the instruction a call instruction."""
        return (self._insn.itype in CALL_INSTRUCTIONS) or idaapi.is_call_insn(
            self._insn
        )

    @property
    def is_test(self):
        """Is this a test instruction?"""
        return self._insn.itype == idaapi.NN_test

    @property
    def is_ret(self):
        """Is the instruction a return instruction."""
        return idaapi.is_ret_insn(self._insn)

    @property
    def is_indirect_jump(self):
        """Is the instruction an indirect jump instruction."""
        return idaapi.is_indirect_jump_insn(self._insn)

    @property
    def is_jmp(self):
        """Is this an indirect jump?"""
        return self._insn.itype == idaapi.NN_jmp

    @property
    def is_jcc(self):
        """Is conditional branch?
        refer to intel.hpp/inline bool insn_jcc(const insn_t &insn)
        """
        return self._insn.itype in JCC_INSTRUCTIONS

    def jump_target(self) -> "Instruction":
        if any([self.is_jcc, self.is_jmp, self.is_indirect_jump]):
            # print(self, self.disasm, idc.get_operand_value(self.address, 0))
            # print(self, self.disasm, idc.get_operand_value(self.address, 1))
            return Instruction(idc.get_operand_value(self.address, 0))
        raise TypeError(f"Instruction {self.insn_t} @ {self} is not a jump!")

    def call_target(self) -> "Instruction":
        if self.is_call:
            return Instruction(idc.get_operand_value(self.address, 0))
        raise TypeError(f"Instruction {self.insn_t} @ {self} is not a call!")

    def displacement_operand(self) -> "Instruction":
        return Instruction(idc.get_operand_value(self.address, 0))

    @property
    def is_loop(self):
        return self._insn.itype in LOOP_INSTRUCTIONS

    @property
    def is_bp(self):
        return self._insn.itype == idaapi.NN_int3

    @property
    def insn_t(self) -> ida_ua.insn_t:
        return self._insn

    @property
    def disasm(self):
        return idc.GetDisasm(self.address)

    @property
    def is_decodable(self):
        return ida_ua.can_decode(self.address)

    # Make code at the given address
    def make_code(self) -> "Instruction":
        ea = self.address
        if ida_bytes.is_code(ida_bytes.get_flags(ea)) and idc.get_item_head(
                ea) == ea:
            return Instruction(idc.get_item_head(ea))

        address = ea

        if idc.create_insn(address) <= 0:
            idaapi.auto_wait()
            ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE)
            if idc.create_insn(address) <= 0:
                idaapi.auto_wait()
                # undefining also helps. Last try (thx IgorS)
                ins = typing.cast(ida_ua.insn_t,
                                  idautils.DecodeInstruction(address))
                if not ins or not ins.size:
                    print(f"WARN: failed to create instruction {address:x}")
                    idaapi.auto_wait()
                    return BADADDR

                ida_bytes.del_items(address, ida_bytes.DELIT_EXPAND, ins.size)
                if idc.create_insn(address) <= 0:
                    print(f"WARN: failed to create instruction {address:x}")
                    return BADADDR

        idaapi.auto_wait()
        # cmd = ida_ua.insn_t()
        # idaapi.auto_wait()
        # if ida_ua.create_insn(ea, cmd) <= 0:
        #     # ida_bytes.del_items(ea, 0, 10)
        #     cmd = ida_ua.insn_t()
        #     if ida_ua.create_insn(ea, cmd) <= 0:
        #         print(f"create_insn(ea, cmd) failed {ea:x}, don't know what to do")
        #         return BADADDR
        #     idaapi.auto_wait()

        return Instruction(idc.get_item_head(ea))

    def within_section(self, section: ida_segment.segment_t) -> bool:
        return self.within_range(textsec.start_ea, textsec.end_ea)

    def within_range(self, start_addr, end_addr):
        return start_addr <= self.address <= end_addr

    def prev_head(self):
        return Instruction(idc.prev_head(self.address))

    def next_head(self):
        return Instruction(idc.next_head(self.address))

    def next_addr(self):
        return Instruction(idc.next_addr(self.address))

    def prev_addr(self):
        return Instruction(idc.prev_addr(self.address))

    def is_middle_of_instruction(self):
        return self.address != idc.get_item_head(self.address)

    def append_cmt(self, cmt):
        e_cmt = idaapi.get_cmt(self.address, False) or ""
        if cmt in e_cmt:
            e_cmt = e_cmt.replace(cmt, "")
        else:
            e_cmt += " " + cmt
        idaapi.set_cmt(self.address, e_cmt, 0)

    def assemble(self, what):
        succ, code = idautils.Assemble(self.address, what)
        if not succ:
            raise Exception("failed to assemble " + what)
        return code

    def to_unconditional_jump(self):
        if not self.is_jcc:
            raise Exception("not a conditional jump!")
        print("make_jump_unconditional (", self, ")")
        target_addr = self.displacement_operand()
        ida_bytes.del_items(target_addr.address)
        run_autoanalysis(target_addr.address)
        return self.patch_ins("jmp " + name_at(target_addr.address), force=True)

    def patch_ins(self, asm, force=False):
        print("patch_ins (", self, ", '", asm, "')")
        new_code = self.assemble(asm)
        new_code_len = len(new_code)
        if not force and self.insn_t.size < new_code_len:
            raise Exception(
                f"patching instruction at {self} to {asm} requires more code than current instruction")
        self.nop(new_code_len)
        address = self.address
        for b in new_code:
            patch_bytes(Instruction(address), b)
            address += 1
        assert address == self.address + new_code_len, f"{self.address} + {new_code_len} != {address}"
        return Instruction(address)

    def nop(self, c=None):
        print("nop (", self, ", ", c if c else "whole_instruction", ")")
        if not c:
            c = idc.get_item_size(self.address)
        address = self.address
        while c:
            new_code = self.assemble("nop")
            for b in new_code:
                patch_bytes(Instruction(address), b)
            c -= 1
            address += 1


def name_at(ea):
    result = idc.get_name(ea)
    if not result:
        result = f"{ea:X}h"
    return result


def run_autoanalysis(start, end=None):
    if not end:
        end = start + 1
    idaapi.plan_and_wait(start, end)
    idaapi.auto_wait()


BADADDR = Instruction(idc.BADADDR)


@dataclass
class Memo:
    #: Indicates our last conditional jump address
    lastBranch: typing.Annotated[
        Instruction, "Indicates our last conditional jump address"
    ] = Instruction(0)
    #: Size of the last conditional jump address
    lastBranchSize: typing.Annotated[
        int, "Size of the last conditional jump address"
    ] = 0
    #: Target location of the last conditional jump
    lastTarget: typing.Annotated[
        Instruction, "Target location of the last conditional jump"
    ] = Instruction(0)
    #: Steps (bytes) left to reach lastTarget from current address
    stepsLeft: typing.Annotated[
        int, "Steps (bytes) left to reach lastTarget from current address"
    ] = 0


class ida_tguidm:

    def __init__(self, iterable, total=None, initial=0):
        self.iterable = iterable

        if total is None and iterable is not None:
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
        ida_kernwin.show_wait_box(f"Executing...")
        for idx, item in enumerate(iterable, start=1):
            # did the user cancel?
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()
                ida_kernwin.warning("Canceled")
                return
            ida_kernwin.replace_wait_box(f"Processing ({idx}/{total})")
            try:
                yield item
            except Exception as e:
                ida_kernwin.warning(f"Unexpected error {e}")
                break

        ida_kernwin.hide_wait_box()


class Deflow:
    def __init__(self):
        # Initialize a set to track already discovered addresses
        self._alreadyDiscovered = set()

    # Buffer is a copy of the .text section
    # Function to deflow the given buffer and functions
    def deflow(self, textsec, functions: list[Instruction]):
        breakpoint()
        for func in ida_tguidm(functions):
            newDiscovered = 0
            chunks = self.deflow_chunk(textsec, func)
            # print("[+] deflowed chunks: ", len(chunks))
            while len(chunks) != 0:
                newChunks = []
                for c in chunks:
                    newChunks.extend(self.deflow_chunk(textsec, c))
                newDiscovered += len(chunks)
                chunks = newChunks

    # Function to process each chunk of the buffer
    def deflow_chunk(self, textsec, address: Instruction) -> list[Instruction]:
        newChunks: list[Instruction] = []

        # 63rd bit indicates if this address was extracted from a negative jump or not
        isNegative = address.is_negative
        address = Instruction(address & ~(1 << 63))

        # Check if already discovered
        if address in self._alreadyDiscovered:
            return newChunks

        self._alreadyDiscovered.add(address)

        memo = Memo()

        while True:
            # Disassemble and decode instructions at the given address
            ea = address.make_code()
            if ea == BADADDR:
                # next_head = Instruction(idc.next_head(address.address))
                # print(f"{address} is badaddr, iterating to next head. {next_head}")
                # address = next_head
                # continue

                # breakpoint()

                # if steps left is > 0 and we're in invalid instructions, keep going
                # to either nop and take the last jump as non conditional
                if memo.lastTarget != 0:
                    # we are down a path in the conditional jump, however, we hit some bad opcodes.
                    # 1. so, we set the address to the last target so we can visit it.
                    # 2. we write the jump in the last target location
                    self.patch_instructions(address, memo, isNegative)
                    newChunks.insert(0, memo.lastTarget)

                return newChunks  # Only accept when no lastTarget as we may be looking at junk code

            cmd: ida_ua.insn_t = address.insn_t
            size = cmd.size
            print(f"working on {ea!r}, size: {size} {ea.disasm}")

            target = Instruction(0)
            isJmp = True  # ea.is_jcc or ea.is_jmp

            # Stop analyzing when we encounter an invalid or return instruction
            # while we have no lastTarget
            if not ea.is_decodable or ea.is_ret:
                if memo.lastTarget == 0:
                    return newChunks  # Only accept when no lastTarget as we may be looking at junk code
            elif ea.is_jcc:
                if memo.lastTarget == 0:
                    target = ea.jump_target()
                    # Addr(cmd.Op1.addr) is 0..
                    # assert target == (_jt := ea.jump_target()), f"{target} != {_jt}"
                    # Helper to see if target address is located in our Buffer
                    if not target.within_section(textsec):
                        print(
                            f"target {target} is not in the buffer range: {textsec.start_ea:x} -> {textsec.end_ea:x}"
                        )
                        isJmp = False
                    # Check if instruction is bigger than 2
                    if size > 2:
                        # if so it won't be obfuscated but we
                        # do want to analyze the target location
                        isJmp = False
                        newChunks.append(target)
                else:
                    # Do not accept this conditional jump while we already have
                    # a target (might be looking at junk code)
                    isJmp = False
            elif ea.is_jmp or ea.is_call:
                if memo.lastTarget == 0:
                    newAddress = ea.displacement_operand()
                    if not newAddress.within_section(textsec):
                        isJmp = False
                    # Add target and next instruction IF not JMP (CALL does return, JMP not)
                    if cmd.itype == ida_allins.NN_call:
                        next_ea = ea.next_addr()
                        if next_ea != ea + cmd.size:
                            print(
                                "!! => address of next instruction is not"
                                f" valid! {next_ea!r} != {ea + cmd.size:x}"
                            )
                        newChunks.append(next_ea)
                    # Add instruction target for further analyses
                    newChunks.append(newAddress)
                    return newChunks

            # Calculate location and steps left to reach lastTarget
            # location = address + idc.op_plain_offset(ea, cmd.size, textsec.start_ea)
            location = address + cmd.size
            # address + cmd.size
            # print(f"difference between: {location:x} and {address + cmd.size:x}")
            # Only valid if we have a lastTarget!
            memo.stepsLeft = int(memo.lastTarget - location)
            # print(f"stepsLeft = lastTarget({memo.lastTarget!r}) - location({location!r}) -> {memo.stepsLeft:x}")

            # Setup a new target if current instruction is conditional jump while there is no lastTarget
            if memo.lastTarget == 0 and isJmp:
                memo.lastBranch = location  # ea
                memo.lastBranchSize = cmd.size
                memo.lastTarget = target
            elif memo.stepsLeft <= 0 and memo.lastTarget != 0:
                # If stepsLeft isn't zero then our lastTarget is located slightly above us,
                # meaning that we are partly located inside the previous instruction and thus we are hidden (obfuscated)
                if memo.stepsLeft != 0:
                    # Calculate how many bytes we are in the next instruction
                    count = int(memo.lastTarget - memo.lastBranch)
                    if count > 0:
                        self.patch_instructions(address, memo, isNegative)
                        # Add next instruction for analysis and exit current analysis
                    else:
                        # We are a negative jump, set 63rd bit to indicate negative jump
                        memo.lastTarget = Instruction(memo.lastTarget | 1 << 63)
                        # Add target to analyzer and exit current analysis
                else:
                    # StepsLeft was zero, meaning there is no collision
                    # Add both target address and next instruction address so we can exit current analysis
                    newChunks.append(
                        Instruction(memo.lastBranch + memo.lastBranchSize))

                newChunks.append(memo.lastTarget)
                return newChunks

            address = Instruction(address + cmd.size)

    def patch_instructions(self, address: Instruction, memo: Memo,
                           isNegative: bool):
        # Calculate how many bytes we are in the next instruction
        count = int(memo.lastTarget - memo.lastBranch)
        # Making sure we are a positive jump
        # 1. Subtract base from our address so we can write to our local buffer
        bufferOffset = int(memo.lastBranch - memo.lastTarget)
        # NOP slide everything except our own instruction
        for i in range(count - memo.lastBranchSize):
            # We use NOP for negative jumps and int3 for positive
            opcode = 0x90 if isNegative else 0xCC
            # print(
            #     "[+] patching:",
            #     Instruction(address + bufferOffset + memo.lastBranchSize + i),
            #     " with:",
            #     f"0x{opcode:02x}",
            # )
            # ida_bytes.patch_byte(bufferOffset + memo.lastBranchSize + i, opcode)
            patch_bytes(
                Instruction(address + bufferOffset + memo.lastBranchSize + i),
                opcode
            )
        if not isNegative:
            # print("[+] patching:", Instruction(address + bufferOffset), " with: 0xEB")
            patch_bytes(
                Instruction(address + bufferOffset), 0xEB
            )
            # ida_bytes.patch_byte(bufferOffset, 0xEB)  # Force unconditional Jump


def affects_flags(mnemonic):
    """
    Determines if the instruction affects the zero or carry flags.
    """
    return mnemonic in ["add", "sub", "xor", "or", "and", "cmp", "test", "inc",
                        "dec"]


def clears_flags(mnemonic):
    """
    Determines if the instruction clears the zero or carry flags.
    """
    return mnemonic in ["xor", "or", "test", "and"]


def is_nop(mnemonic):
    """
    Determines if the instruction is a nop.
    """
    return mnemonic in ["nop"]


def trace_back_from_address(ea, visited=None):
    """
    Traces backward from the given address to find instructions that affect the zero and carry flags.
    Returns True if the last instruction cleared the flags, False otherwise.
    """
    if visited is None:
        visited = set()

    current_ea = ea

    while current_ea != idc.BADADDR and current_ea not in visited:
        visited.add(current_ea)
        mnemonic = idc.print_insn_mnem(current_ea).lower()
        print(f"Address: {hex(current_ea)}, Instruction: {mnemonic}")

        if is_nop(mnemonic):
            current_ea = idc.prev_head(current_ea)
            continue

        if clears_flags(mnemonic):
            print(f"Instruction at {hex(current_ea)} clears flags.")
            return True

        if affects_flags(mnemonic):
            print(f"Instruction at {hex(current_ea)} affects flags.")
            return False

        # Handle jump destinations by following the jump target
        refs = list(idautils.CodeRefsTo(current_ea, 0))
        for ref in refs:
            if ref not in visited:
                result = trace_back_from_address(ref, visited)
                if result is not None:
                    return result

        current_ea = idc.prev_head(current_ea)


def analyze_and_refresh_code(start_ea, end_ea):
    """
    Analyzes and refreshes the code between the given start and end addresses.
    Forces conversion of the marked range to instructions.
    """
    # Ensure the range is valid
    if start_ea >= end_ea:
        print("Invalid address range")
        return

    # Mark the range for re-analysis
    idaapi.auto_mark_range(start_ea, end_ea, idaapi.AU_CODE)

    # Force conversion to instructions
    ea = start_ea
    while ea < end_ea:
        # if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
        #     # If already code, skip to the next address
        #     ea = idc.next_head(ea, end_ea)
        #     continue

        # Attempt to create an instruction at this address
        if idc.create_insn(ea):
            print(f"Converted to instruction at {hex(ea)}")
        else:
            print(f"Failed to convert to instruction at {hex(ea)}")

        # Move to the next address
        ea = idc.next_head(ea, end_ea)

    # Perform analysis
    idaapi.auto_wait()

    # Refresh the view
    idaapi.refresh_idaview_anyway()

    print(
        f"Code analysis and refresh completed from {hex(start_ea)} to {hex(end_ea)}.")


def instructions(func: ida_funcs.func_t, stop=None):
    # func TlsCallback_0 ranges from 140004300 until 14000534b
    print(
        f"func {idaapi.get_func_name(func.start_ea)} ranges from {func.start_ea:x} until {func.end_ea:x}"
    )
    loop_guard = 0
    current_addr = func.start_ea
    while current_addr <= func.end_ea:
        if stop and stop == loop_guard:
            return
        instruction = Instruction(current_addr)
        print(instruction, instruction.disasm, instruction.is_decodable)
        tmp = None
        if not instruction.is_decodable:
            print("Bad instruction found @ ", instruction)
        else:
            tmp = yield instruction
            if tmp:
                print("recieved this back: ", hex(tmp))
                analyze_and_refresh_code(func.start_ea, func.end_ea)

        loop_guard += 1
        current_addr = tmp or idc.next_head(current_addr)


def runv4(instr):
    funct: ida_funcs.func_t = idaapi.get_func(instr.address)
    da_instructions = SettableGenerator(instructions(funct, stop=50))
    breakpoint()
    for instruction in da_instructions:
        breakpoint()
        print(instruction, "received")
        if not (
                instruction.is_jmp or instruction.is_call or instruction.is_indirect_jump or instruction.is_jcc):
            continue

        displacement_addr = instruction.displacement_operand()
        if not displacement_addr.within_range(funct.start_ea, funct.end_ea):
            print(displacement_addr,
                  "is an external func, not within func's range")
            continue

        print("displacement: ", displacement_addr, " from:", instruction)
        if not displacement_addr.is_middle_of_instruction():
            continue

        print("JUMP TO MID OF INSTRUCTION FOUND AT: ", instruction)
        print("prev addr:", instruction.prev_head())

        # XXX: what if distance is negative?
        if instruction.is_jcc and instruction.prev_head().is_test:
            print("MOST LIKELY OPAQUE FOUND AT: ", instruction)
            count = int(displacement_addr - instruction)
            if count < 0:
                print("backward jump detected")
                start_of_expr = Instruction(
                    idc.get_item_head(displacement_addr.address))
                start_of_expr.nop(abs(count))
                analyze_and_refresh_code(funct.start_ea, funct.end_ea)

                # analyze_and_refresh_code(
                #     instruction.prev_head().address,
                #     instruction.address
                # )

            next_instr = instruction.to_unconditional_jump()
            count = int(displacement_addr - next_instr)
            if count > 0:
                next_instr.nop(c=count)
                analyze_and_refresh_code(funct.start_ea, funct.end_ea)

                # analyze_and_refresh_code(
                #     instruction.prev_head().address,
                #     displacement_addr.address
                # )

        elif instruction.is_jcc and instruction.insn_t.itype in [
            ida_allins.NN_jno,
            ida_allins.NN_jo
        ] and trace_back_from_address(instruction.address):
            print("MOST LIKELY OPAQUE FOUND AT: ", instruction)
            count = int(displacement_addr - instruction)
            if count < 0:
                print("backward jump detected")
                start_of_expr = Instruction(
                    idc.get_item_head(displacement_addr.address)
                )
                start_of_expr.nop(abs(count))

                # analyze_and_refresh_code(
                #     instruction.prev_head().address, instruction.address
                # )

            next_instr = instruction.to_unconditional_jump()
            count = int(displacement_addr - next_instr)
            if count > 0:
                next_instr.nop(c=count)

                # analyze_and_refresh_code(
                #     instruction.prev_head().address, displacement_addr.address
                # )

        # run_autoanalysis(instruction.address, displacement_addr.address)
        analyze_and_refresh_code(funct.start_ea, funct.end_ea)
        da_instructions.set(displacement_addr.address)


# print((z := idc.get_operand_value(idc.here(), 0)) == idc.get_item_head(z))
if __name__ == "__main__":
    clear_output()
    ida_kernwin.hide_wait_box()

    # Get the .text section of the loaded binary
    textsec = idaapi.get_segm_by_name(".text")
    # buffer = ida_bytes.get_bytes(textsec.start_ea, textsec.size())
    # NOTE: base = BaseAddress + .text offset
    base_address = textsec.start_ea  # Base address calculation
    # Get the list of function addresses in the .text section
    # functions = list(map(Addr, idautils.Functions(textsec.start_ea, textsec.end_ea)))
    functions = [
        Instruction(0x140004300),
        Instruction(0x140005E44),
        Instruction(0x140006383),
        Instruction(0x140007290),
        Instruction(0x140007300),
    ]
    instr = Instruction(0x140004300)
    runv4(instr)

# Initialize and run the Deflow algorithm
# deflow = Deflow()
# deflow.deflow(textsec, functions[:5])
# deflow.deflow(textsec, functions)
