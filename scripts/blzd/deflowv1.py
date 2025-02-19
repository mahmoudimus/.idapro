import inspect
import time  # Import time module for tracking execution time
import types
import typing

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_segment
import idaapi
import idautils
import idc
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn


def clear_window(window):
    form = ida_kernwin.find_widget(window)
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


def clear_output():
    clear_window("Output window")


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
        self.start_time = None  # Track start time
        self.n = initial

    def __iter__(self):
        # Inlining instance variables as locals (speed optimization)
        iterable = self.iterable
        total = self.total
        self.start_time = time.time()  # Start tracking time
        with ProgressDialog("Executing") as pd:
            for idx, item in enumerate(iterable, start=1):
                if pd.user_canceled():
                    break

                elapsed_time = time.time() - self.start_time
                avg_time_per_item = elapsed_time / idx if idx > 0 else 0
                remaining_time = (total - idx) * avg_time_per_item if total else None

                if remaining_time is not None:
                    eta_str = f" | ETA: {int(remaining_time)}s"
                else:
                    eta_str = ""

                pd.replace_message(f"Processing ({idx}/{total}){eta_str}")

                try:
                    yield item
                except Exception as e:
                    ida_kernwin.warning(f"Unexpected error {e}")
                    break


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


CONDITIONAL_JUMPS = [
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jcxz",
    "jecxz",
    "jrcxz",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
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
]

# A global list to track discovered addresses
_already_discovered = set()


def deflow(functions=None, text_seg_buffer=False):
    """
    // Buffer is a copy of the .text section.
    // 'functions' is an iterable of function entry points (start addresses) in the .text section.
    // This uses IDA's Python API to retrieve and patch bytes in the .text section.
    """

    # Get the start of the .text segment and its size in IDA.
    # Adjust these as needed for your environment:
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        print("[-] Could not find .text segment.")
        return
    base_address = text_seg.start_ea
    buffer = None
    # if do not pass functions, we will use the entire .text segment as buffer.
    if not functions:
        functions = idautils.Functions(text_seg.start_ea, text_seg.end_ea)
        text_seg_buffer = True

    if text_seg_buffer:
        seg_size = text_seg.end_ea - text_seg.start_ea
        # Read .text bytes into a local buffer.
        # In many IDA versions, get_bytes can retrieve the segment's bytes:
        buffer = ida_bytes.get_bytes(base_address, seg_size)

    for func_addr in ida_tguidm(functions):
        # if buffer is None, we use the function's entire range as buffer
        # unless we asked to use the entire .text segment as buffer.
        if functions and not text_seg_buffer:
            func = ida_funcs.get_func(func_addr)
            buffer_size = func.end_ea - func_addr
            buffer = ida_bytes.get_bytes(func_addr, buffer_size)
            print(f"@ func: {func_addr} with buffer size: {buffer_size}")

        chunks = deflow_chunk(buffer, base_address, func_addr)
        while chunks:
            new_chunks = []
            for c in chunks:
                new_chunks.extend(deflow_chunk(buffer, base_address, c))
            chunks = new_chunks


def deflow_chunk(buffer, base_address, address):
    """
    function DeflowChunk(address)
        List<ulong> newChunks;

        // 63th bit indicates if this address was extracted from a negative jump or not
        bool isNegative = address >> 63 == 1;
        address &= 1 << 63;

        // Check if already discovered
        if(_alreadyDiscovered.Contains(address))
            return newChunks;

        ...
    """

    new_chunks = []

    is_negative = address < 0
    address = abs(address)

    # Check if we have already discovered this address
    if address in _already_discovered:
        return new_chunks

    _already_discovered.add(address)

    # We'll keep track of potential obfuscated branches
    last_branch = 0  # Indicates our last conditional jump address
    last_branch_size = 0  # Size of the last conditional jump instruction
    last_target = 0  # Target location of the last conditional jump
    steps_left = 0  # Steps (bytes) left to reach lastTarget from current address

    # NOTE: base = baseAddress + .text offset.
    # We'll create a Capstone disassembler for x86_64.
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Calculate the offset in 'buffer' corresponding to 'address'.
    # If address < base_address, handle accordingly (in_range checks, etc.).
    start_offset = address - base_address
    if start_offset < 0 or start_offset >= len(buffer):
        # Address not within the buffer range—nothing to do
        return new_chunks

    # Disassemble from 'address' until we run out of bytes
    for insn in md.disasm(buffer[start_offset:], address):
        insn = typing.cast(CsInsn, insn)
        # We'll track potential jump targets
        target = 0
        is_jmp = True

        #
        # The original pseudocode uses a switch on insn.Mnemonic:
        # switch(insn.Mnemonic)
        #
        # We'll approximate by checking groups of mnemonics:
        #

        # 1) Check for invalid / return instructions
        #    // Stop analyzing when we encounter an invalid or return instruction
        #    // while we have no lastTarget.
        if (
            insn.id == 0
            or insn.mnemonic in ["ret", "retn"]
            or insn.mnemonic.startswith("ret")
        ):
            # In Capstone, invalid instructions won't usually appear,
            # but you can check insn.id == 0 if needed, or break on disassembly failure.
            # This covers the "ud_mnemonic_code.Invalid" and "ud_mnemonic_code.Ret" logic:
            if last_target == 0:
                return new_chunks  # Only accept when no lastTarget
            # If there is a last_target, continue analysis.

        # 2) Check for conditional jump instructions
        elif insn.mnemonic in CONDITIONAL_JUMPS:
            # if(lastTarget == 0)
            if last_target == 0:
                target = calc_target_jump(insn)

                # Check if in range
                if not is_in_range(target, base_address, len(buffer)):
                    is_jmp = False
                else:
                    # Check if instruction is bigger than 2,
                    # if so it won't be obfuscated but we do want to analyze the target location
                    if insn.size > 2:
                        is_jmp = False
                        new_chunks.append(target)
            else:
                # We already have a last_target (might be looking at junk code)
                is_jmp = False
        # 3) Check for unconditional jumps or calls
        elif insn.mnemonic in ["jmp", "call"] and last_target == 0:
            new_address = calc_target_jump(insn)
            if not is_in_range(new_address, base_address, len(buffer)):
                is_jmp = False
            else:
                # If it's a CALL, add the next instruction
                # (since CALL returns eventually)
                if insn.mnemonic == "call":
                    # address + insn.size => next instruction's address
                    next_insn_addr = address + insn.size
                    new_chunks.append(next_insn_addr)
                # Add instruction target for further analysis
                new_chunks.append(new_address)
                return new_chunks

        #
        # "quick mafs" from the original snippet:
        #
        location = insn.address  # In Capstone, insn.address is the runtime address
        steps_left = last_target - location  # Only valid if we have a last_target

        # Setup a new target if current instruction is a conditional jump
        # while there is no last_target
        if last_target == 0 and is_jmp:
            last_branch = location
            last_branch_size = insn.size
            last_target = target
        elif steps_left == 0 and last_target != 0:
            # stepsLeft was zero, meaning no collision
            # add both target address and next instruction address
            # so we can exit current analysis
            new_chunks.append(last_branch + last_branch_size)
            new_chunks.append(last_target)
            return new_chunks
        elif steps_left < 0 and last_target != 0:
            # stepsLeft != 0 => collision within the instruction => obfuscated
            # int count = lastTarget = lastBranch;
            # (The original code is a bit ambiguous, but the comment suggests
            #  we measure how many bytes we are "into" the next instruction)
            count = last_target - last_branch
            if count > 0:
                # making sure we are a positive jump
                buffer_offset = last_branch - base_address  # index in local buffer

                # NOP slide everything except our own instruction
                # for (int i = 0; i < count - lastBranchSize; i++)
                for i in range(count - last_branch_size):
                    ida_bytes.patch_byte(
                        base_address + buffer_offset + last_branch_size + i,
                        # We use NOP (0x90) for negative jumps
                        # and int3 (0xCC) for positive
                        0x90 if is_negative else 0xCC,
                    )

                if not is_negative:
                    # Force unconditional jump
                    ida_bytes.patch_byte(base_address + buffer_offset, 0xEB)

                # add next instruction for analysis and exit current analysis
                new_chunks.append(last_target)
                return new_chunks
            else:
                # we are a negative jump, set 63rd bit to indicate negative jump
                last_target = -last_target
                # add target to analyzer and exit current analysis
                new_chunks.append(last_target)
                return new_chunks

    return new_chunks


#
# Helper stubs you will need to implement or adjust to your environment
#


def calc_target_jump(insn: CsInsn):
    """
    Helper to extract jump or call target from an instruction.
    In Capstone, you can often inspect insn.operands[0].imm for near branches.
    """
    operand = idc.get_operand_value(insn.address, 0)
    print(
        f"@ insn.address: {format_addr(insn.address)} with jump target: {format_addr(operand)}"
    )
    # doesn't work for some reason
    # capstone_operand = 0
    # if len(insn.operands) > 0:
    #     op = insn.operands[0]
    #     if op.type == 1:  # IMMEDIATE type in Capstone (depending on version).
    #         capstone_operand = op.imm
    # if capstone_operand != operand:
    #     print(
    #         f"*** Capstone operand: {format_addr(capstone_operand)}, IDA operand: {format_addr(operand)}"
    #     )
    return operand


def is_in_range(addr, base_address, buf_size):
    """
    Helper to see if 'addr' is located within our buffer range.
    """
    if addr < base_address:
        return False
    if addr >= (base_address + buf_size):
        return False
    return True


if __name__ == "__main__":
    clear_output()
    func = ida_funcs.get_func(idc.here())
    # deflow()
    deflow(functions=[func.start_ea], text_seg_buffer=False)
