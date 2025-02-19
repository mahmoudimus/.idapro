import inspect
import logging
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

logger = logging.getLogger("deflowv1")


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
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Starting deflow with functions: %s, text_seg_buffer: %s",
            ", ".join([format_addr(f) for f in functions]),
            text_seg_buffer,
        )

    # Get the start of the .text segment and its size in IDA.
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
        buffer = ida_bytes.get_bytes(base_address, seg_size)
        logger.debug(
            "Loaded .text segment into buffer: base_address=0x%x, size=%d",
            base_address,
            seg_size,
        )

    for func_addr in ida_tguidm(functions):
        logger.debug("Processing function at address: 0x%x", func_addr)
        # if buffer is None, we use the function's entire range as buffer
        # unless we asked to use the entire .text segment as buffer.
        if functions and not text_seg_buffer:
            func = ida_funcs.get_func(func_addr)
            buffer_size = func.end_ea - func_addr
            buffer = ida_bytes.get_bytes(func_addr, buffer_size)
            logger.debug("Function 0x%x: buffer size %d", func_addr, buffer_size)

        chunks = deflow_chunk(buffer, base_address, func_addr)
        logger.debug(
            "Initial chunks from deflow_chunk for function 0x%x: %s", func_addr, chunks
        )
        while chunks:
            new_chunks = []
            for c in chunks:
                logger.debug("Processing chunk at 0x%x", c)
                new_chunks.extend(deflow_chunk(buffer, base_address, c))
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "New chunks after iteration: %s",
                    ", ".join([format_addr(c) for c in new_chunks]),
                )
            chunks = new_chunks


def deflow_chunk(buffer, base_address, address):
    logger.debug("Starting deflow_chunk analysis for address: 0x%x", address)
    new_chunks = []

    is_negative = address < 0
    address = abs(address)

    # Check if we have already discovered this address
    if address in _already_discovered:
        logger.debug("Address 0x%x already discovered, skipping.", address)
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
        logger.debug(
            "Address 0x%x out of range in buffer, offset: %d", address, start_offset
        )
        return new_chunks

    # Disassemble from 'address' until we run out of bytes
    for insn in md.disasm(buffer[start_offset:], address):
        logger.debug(
            "Disassembled instruction at 0x%x: %s %s",
            insn.address,
            insn.mnemonic,
            insn.op_str,
        )
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
            logger.debug(
                "Encountered return or invalid instruction at 0x%x", insn.address
            )
            if last_target == 0:
                return new_chunks  # Only accept when no lastTarget
            # If there is a last_target, continue analysis.

        # 2) Check for conditional jump instructions
        elif insn.mnemonic in CONDITIONAL_JUMPS:
            # if(lastTarget == 0)
            if last_target == 0:
                target = calc_target_jump(insn)
                logger.debug(
                    "Conditional jump at 0x%x with target 0x%x", insn.address, target
                )

                # Check if in range
                if not is_in_range(target, base_address, len(buffer)):
                    logger.debug("Target 0x%x out of range", target)
                    is_jmp = False
                else:
                    # Check if instruction is bigger than 2,
                    # if so it won't be obfuscated but we do want to analyze the target location
                    if insn.size > 2:
                        logger.debug(
                            "Instruction size > 2 at 0x%x; adding target 0x%x and stopping jump analysis",
                            insn.address,
                            target,
                        )
                        is_jmp = False
                        new_chunks.append(target)
            else:
                # We already have a last_target (might be looking at junk code)
                logger.debug(
                    "Skipping conditional jump at 0x%x due to existing last_target 0x%x",
                    insn.address,
                    last_target,
                )
                is_jmp = False
        # 3) Check for unconditional jumps or calls
        elif insn.mnemonic in ["jmp", "call"] and last_target == 0:
            target = calc_target_jump(insn)
            real_head = idc.get_item_head(target)
            logger.debug(
                "Unconditional %s at 0x%x with target 0x%x",
                insn.mnemonic,
                insn.address,
                target,
            )
            if not is_in_range(target, base_address, len(buffer)):
                logger.debug("New address 0x%x out of range", target)
                is_jmp = False
            elif target == real_head:
                # If it's a CALL, add the next instruction
                # (since CALL returns eventually)
                if insn.mnemonic == "call":
                    # address + insn.size => next instruction's address
                    next_insn_addr = address + insn.size
                    logger.debug(
                        "Call instruction: adding next instruction address 0x%x",
                        next_insn_addr,
                    )
                    new_chunks.append(next_insn_addr)
                # Add instruction target for further analysis
                new_chunks.append(target)
                return new_chunks
            else:
                logger.debug(
                    "Unconditional %s at 0x%x with target 0x%x is obfuscated",
                    insn.mnemonic,
                    insn.address,
                    target,
                )
                new_chunks.append(target)
        #
        # "quick mafs" from the original snippet:
        #
        location = insn.address  # In Capstone, insn.address is the runtime addres
        steps_left = last_target - location  # Only valid if we have a last_target

        # Setup a new target if current instruction is a conditional jump
        # while there is no last_target
        if last_target == 0 and is_jmp:
            last_branch = location
            last_branch_size = insn.size
            last_target = target
            logger.debug(
                "Setting branch info: last_branch=0x%x, last_branch_size=%d, last_target=0x%x",
                last_branch,
                last_branch_size,
                last_target,
            )
        elif steps_left == 0 and last_target != 0:
            logger.debug(
                "Exact collision at 0x%x; adding 0x%x and 0x%x",
                location,
                last_branch + last_branch_size,
                last_target,
            )
            new_chunks.append(last_branch + last_branch_size)
            new_chunks.append(last_target)
            return new_chunks
        elif steps_left < 0 and last_target != 0:
            # stepsLeft != 0 => collision within the instruction => obfuscated
            # int count = lastTarget = lastBranch;
            # (The original code is a bit ambiguous, but the comment suggests
            #  we measure how many bytes we are "into" the next instruction)
            count = last_target - last_branch
            logger.debug(
                "Obfuscated branch detected at 0x%x; count: %d", last_branch, count
            )
            if count > 0:
                # making sure we are a positive jump
                buffer_offset = last_branch - base_address  # index in local buffer

                # NOP slide everything except our own instruction
                # for (int i = 0; i < count - lastBranchSize; i++)
                for i in range(count - last_branch_size):
                    patch_addr = base_address + buffer_offset + last_branch_size + i
                    patch_byte = 0x90 if is_negative else 0xCC
                    ida_bytes.patch_byte(patch_addr, patch_byte)
                    logger.debug(
                        "Patching byte at 0x%x with 0x%x", patch_addr, patch_byte
                    )

                if not is_negative:
                    # Force unconditional jump
                    ida_bytes.patch_byte(base_address + buffer_offset, 0xEB)
                    logger.debug(
                        "Forced unconditional jump at 0x%x",
                        base_address + buffer_offset,
                    )

                # add next instruction for analysis and exit current analysis
                new_chunks.append(last_target)
                logger.debug("Added new chunk target 0x%x", last_target)
                return new_chunks
            else:
                # we are a negative jump, set 63rd bit to indicate negative jump
                last_target = -last_target
                logger.debug(
                    "Negative jump encountered. Adjusted last_target: 0x%x", last_target
                )
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
    logger.debug(
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


def configure_logging(log, debug=False):
    log.propagate = False
    log.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = logging.Formatter("[%(levelname)s] @ %(asctime)s %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)

    log.handlers = []
    log.addHandler(handler)


if __name__ == "__main__":
    clear_output()
    configure_logging(logger, debug=False)
    func = ida_funcs.get_func(idc.here())
    deflow()
    # deflow(functions=[func.start_ea], text_seg_buffer=True)
