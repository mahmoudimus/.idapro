from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn
import ida_bytes
import ida_segment
import ida_kernwin
import types
import inspect
import typing
import idc
import idaapi
import idautils
import time  # Import time module for tracking execution time

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


# A global list to track discovered addresses
_already_discovered = set()


def deflow(functions=None):
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
    if not functions:
        functions = idautils.Functions(text_seg.start_ea, text_seg.end_ea)
    base_address = text_seg.start_ea
    seg_size = text_seg.end_ea - text_seg.start_ea

    # Read .text bytes into a local buffer.
    # In many IDA versions, get_bytes can retrieve the segment's bytes:
    buffer = ida_bytes.get_bytes(base_address, seg_size)

    for func_addr in ida_tguidm(functions):
        while True:
            new_discovered = 0
            chunks = deflow_chunk(buffer, base_address, func_addr)
            while len(chunks) != 0:
                new_chunks = []
                for c in chunks:
                    new_chunks.extend(deflow_chunk(buffer, base_address, c))
                new_discovered += len(chunks)
                chunks = new_chunks

            # If no new chunks discovered, we break out
            if new_discovered == 0:
                break


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

    # 63rd bit indicates if this address was extracted from a negative jump or not
    is_negative = (address >> 63) == 1
    # Clear the 63rd bit in the actual address
    address = address & 0x7FFFFFFFFFFFFFFF

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
        last_addr_start = 0  # Only if needed, here just a placeholder
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
        if insn.mnemonic in ["ret", "retn"] or insn.mnemonic.startswith("ret"):
            # In Capstone, invalid instructions won't usually appear,
            # but you can check insn.id == 0 if needed, or break on disassembly failure.
            # This covers the "ud_mnemonic_code.Invalid" and "ud_mnemonic_code.Ret" logic:
            if last_target == 0:
                return new_chunks  # Only accept when no lastTarget
            # If there is a last_target, continue analysis.

        # 2) Check for conditional jump instructions
        elif insn.mnemonic in [
            "ja",
            "jae",
            "jb",
            "jbe",
            "jc",
            "je",
            "jg",
            "jge",
            "jl",
            "jle",
            "jna",
            "jnae",
            "jnbe",
            "jne",
            "jnz",
            "jz",
            "jrcxz",
            "jcxz",
            # "loop",
            # "loopz",
            # "loope",
            # "loopnz",
            # "loopne",
        ]:
            # if(lastTarget == 0)
            if last_target == 0:
                # target = calcTargetJump(insn); // Helper to extract jump location
                target = calc_target_jump(insn)  # You must implement this

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
        elif insn.mnemonic in ["jmp", "call"]:
            if last_target == 0:
                new_address = calc_target_jump(insn)
                if not is_in_range(new_address, base_address, len(buffer)):
                    is_jmp = False
                else:
                    # If it's a CALL, add the next instruction (since CALL returns eventually)
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
        steps_left = int(last_target - location)  # Only valid if we have a last_target

        # Setup a new target if current instruction is a conditional jump
        # while there is no last_target
        if last_target == 0 and is_jmp:
            last_branch = location
            last_branch_size = insn.size
            last_target = target

        # else if (stepsLeft <= 0 && lastTarget != 0)
        elif steps_left <= 0 and last_target != 0:
            # if(stepsLeft != 0) => collision within the instruction => obfuscated
            if steps_left != 0:
                # int count = lastTarget = lastBranch;
                # (The original code is a bit ambiguous, but the comment suggests
                #  we measure how many bytes we are "into" the next instruction)
                count = last_target - last_branch
                if count > 0:
                    # making sure we are a positive jump
                    buffer_offset = last_branch - base_address  # index in local buffer

                    # NOP slide everything except our own instruction
                    # for (int i = 0; i < count - lastBranchSize; i++)
                    for i in range(int(count - last_branch_size)):
                        if is_negative:
                            # We use NOP (0x90) for negative jumps
                            ida_bytes.patch_byte(
                                base_address + buffer_offset + last_branch_size + i,
                                0x90,
                            )
                        else:
                            # We use int3 (0xCC) for positive
                            ida_bytes.patch_byte(
                                base_address + buffer_offset + last_branch_size + i,
                                0xCC,
                            )

                    if not is_negative:
                        # Force unconditional jump
                        ida_bytes.patch_byte(base_address + buffer_offset, 0xEB)

                    # add next instruction for analysis and exit current analysis
                    new_chunks.append(last_target)
                    return new_chunks
                else:
                    # we are a negative jump, set 63rd bit to indicate negative jump
                    last_target |= 1 << 63

                    # add target to analyzer and exit current analysis
                    new_chunks.append(last_target)
                    return new_chunks

            else:
                # stepsLeft was zero, meaning no collision
                # add both target address and next instruction address so we can exit current analysis
                new_chunks.append(last_branch + last_branch_size)
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
    return idc.get_operand_value(insn.address, 0)
    # if len(insn.operands) > 0:
    #     op = insn.operands[0]
    #     if op.type == 1:  # IMMEDIATE type in Capstone (depending on version).
    #         return op.imm
    # return 0


def is_in_range(addr, base_address, buf_size):
    """
    Helper to see if 'addr' is located within our .text buffer range.
    """
    if addr < base_address:
        return False
    if addr >= (base_address + buf_size):
        return False
    return True
