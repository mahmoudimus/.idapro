import collections
import itertools
import logging
import re
import struct
import typing
from dataclasses import dataclass, field

import capstone
import ida_allins
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
from mutilz.helpers.ida import clear_output, format_addr
from mutilz.logconf import configure_debug_logging

logger = logging.getLogger(__name__)
configure_debug_logging(logger)

# fmt: off
# NOP patterns from the source code
NOP_PATTERNS = [
    # 1-byte NOP
    [0x90],
    # 2-byte XCHG AX,AX
    [0x66, 0x90],
    # 3-byte NOP DWORD ptr [RAX]
    [0x0F, 0x1F, 0x00],
    # 4-byte NOP DWORD ptr [RAX + 0]
    [0x0F, 0x1F, 0x40, 0x00],
    # 5-byte NOP DWORD ptr [RAX + RAX + 0]
    [0x0F, 0x1F, 0x44, 0x00, 0x00],
    # 6-byte NOP WORD ptr [RAX + RAX + 0]
    [0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
    # 7-byte NOP DWORD ptr [RAX + 0] (variant)
    [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00],
    # 8-byte NOP DWORD ptr [RAX + RAX + 0] (variant)
    [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 9-byte NOP WORD ptr [RAX + RAX + 0] (variant)
    [0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 10-byte NOP with extra prefix
    [0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 11-byte NOP with three 0x66 prefixes
    [0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
]

CONDITIONAL_JUMPS = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
ALL_JUMPS = CONDITIONAL_JUMPS + [ida_allins.NN_jmp]
CALL_INSTRUCTIONS = {ida_allins.NN_call, ida_allins.NN_callfi, ida_allins.NN_callni}
CONDITIONAL_JUMPS_MNEMONICS = [
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


# Define padding pattern (common in anti-disassembly sequences)
PADDING = rb"((\xC0[\xE0-\xFF]\x00)|(\x86|\x8A)[\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF])"

# Multi-part jump patterns: pairs of conditional jumps with optional padding
MULTI_PART_PATTERNS = [
    rb"\x70." + PADDING + rb"*\x71.",  # JO ... JNO
    rb"\x71." + PADDING + rb"*\x70.",  # JNO ... JO
    rb"\x72." + PADDING + rb"*\x73.",  # JB ... JAE
    rb"\x73." + PADDING + rb"*\x72.",  # JAE ... JB
    rb"\x74." + PADDING + rb"*\x75.",  # JE ... JNE
    rb"\x75." + PADDING + rb"*\x74.",  # JNE ... JE
    rb"\x76." + PADDING + rb"*\x77.",  # JBE ... JA
    rb"\x77." + PADDING + rb"*\x76.",  # JA ... JBE
    rb"\x78." + PADDING + rb"*\x79.",  # JS ... JNS
    rb"\x79." + PADDING + rb"*\x78.",  # JNS ... JS
    rb"\x7A." + PADDING + rb"*\x7B.",  # JP ... JNP
    rb"\x7B." + PADDING + rb"*\x7A.",  # JNP ... JP
    rb"\x7C." + PADDING + rb"*\x7D.",  # JL ... JGE
    rb"\x7D." + PADDING + rb"*\x7C.",  # JGE ... JL
    rb"\x7E." + PADDING + rb"*\x7F.",  # JLE ... JG
    rb"\x7F." + PADDING + rb"*\x7E.",  # JG ... JLE
]

# Single-part jump patterns: prefix instruction + optional padding + conditional jump
SINGLE_PART_PATTERNS = [
    rb"\xF8" + PADDING + rb"?\x73.",  # CLC ... JAE
    rb"\xF9" + PADDING + rb"?\x76.",  # STC ... JBE
    rb"\xF9" + PADDING + rb"?\x72.",  # STC ... JB
    rb"\xA8." + PADDING + rb"?\x71.",  # TEST AL, imm8 ... JNO
    rb"\xA9...." + PADDING + rb"?\x71.",  # TEST EAX, imm32 ... JNO
    rb"\xF6.." + PADDING + rb"?\x71.",  # TEST r/m8, imm8 ... JNO
    rb"\xF7....." + PADDING + rb"?\x71.",  # TEST r/m32, imm32 ... JNO
    rb"\x84." + PADDING + rb"?\x71.",  # TEST r/m8, r8 ... JNO
    rb"\x85." + PADDING + rb"?\x71.",  # TEST r/m32, r32 ... JNO
    rb"\xA8." + PADDING + rb"?\x73.",  # TEST AL, imm8 ... JAE
    rb"\xA9...." + PADDING + rb"?\x73.",  # TEST EAX, imm32 ... JAE
    rb"\xF6.." + PADDING + rb"?\x73.",  # TEST r/m8, imm8 ... JAE
    rb"\xF7....." + PADDING + rb"?\x73.",  # TEST r/m32, imm32 ... JAE
    rb"\x84." + PADDING + rb"?\x73.",  # TEST r/m8, r8 ... JAE
    rb"\x85." + PADDING + rb"?\x73.",  # TEST r/m32, r32 ... JAE
    rb"\x80[\xE0-\xE7]\xFF" + PADDING + rb"?\x71.",  # AND r/m8, 0xFF ... JNO
    rb"\x24\xFF" + PADDING + rb"?\x71.",  # AND AL, 0xFF ... JNO
    rb"\x80[\xC8-\xCF]\x00" + PADDING + rb"?\x71.",  # OR r/m8, 0x00 ... JNO
    rb"\x0C\x00" + PADDING + rb"?\x71.",  # OR AL, 0x00 ... JNO
    rb"\x80[\xF0-\xF7]\x00" + PADDING + rb"?\x71.",  # XOR r/m8, 0x00 ... JNO
    rb"\x34\x00" + PADDING + rb"?\x71.",  # XOR AL, 0x00 ... JNO
    rb"\x80[\xE0-\xE7]\xFF" + PADDING + rb"?\x73.",  # AND r/m8, 0xFF ... JAE
    rb"\x24\xFF" + PADDING + rb"?\x73.",  # AND AL, 0xFF ... JAE
    rb"\x80[\xC8-\xCF]\x00" + PADDING + rb"?\x73.",  # OR r/m8, 0x00 ... JAE
    rb"\x0C\x00" + PADDING + rb"?\x73.",  # OR AL, 0x00 ... JAE
    rb"\x80[\xF0-\xF7]\x00" + PADDING + rb"?\x73.",  # XOR r/m8, 0x00 ... JAE
    rb"\x34\x00" + PADDING + rb"?\x73.",  # XOR AL, 0x00 ... JAE
]

JUNK_PATTERNS = [
    (rb"\x0F\x31", "RDTSC"),
    (rb"\x0F[\x80-\x8F]..[\x00\x01]\x00", "TwoByte Conditional Jump"),
    (rb"\xE8..[\x00\x01]\x00", "Invalid CALL"),
    (rb"\x81[\xC0-\xC3\xC5-\xC7]....", "ADD reg32, imm32"),
    (rb"\x80[\xC0-\xC3\xC5-\xC7].", "ADD reg8, imm8"),
    (rb"\x83[\xC0-\xC3\xC5-\xC7].", "ADD reg32, imm8"),
    (rb"\xC6[\xC0-\xC3\xC5-\xC7].", "MOV reg8, imm8"),
    (rb"\xC7[\xC0-\xC3\xC5-\xC7]....", "MOV reg32, imm32"),
    (rb"\xF6[\xD8-\xDB\xDD-\xDF]", "NEG reg8"),
    (rb"\x80[\xE8-\xEB\xED-\xEF].", "AND reg8, imm8"),
    (rb"\x81[\xE8-\xEB\xED-\xEF]....", "AND reg32, imm32"),
    (rb"\x68....", "PUSH imm32"),
    (rb"\x6A.", "PUSH imm8"),
    (rb"[\x70-\x7F].", "Random 112-127"),
    (rb"[\x50-\x5F]", "Single-byte PUSH/POP"),
]
    
# Define "big instruction" opcode arrays
SINGLE_BYTE_OPCODES = b"\xc8\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x68\xa0\xa1\xa2\xa3\xa9\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xe8\xe9\x69\x81\xc7\xf7"
MED_OPCODES = b"\xa0\xa1\xa2\xa3\x00\x01\x02\x03\x08\x09\x0a\x0b\x0f\x10\x11\x12\x13\x18\x19\x1a\x1b\x20\x21\x22\x23\x28\x29\x2a\x2b\x30\x31\x32\x33\x38\x39\x3a\x3b\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x6b\x80\x83\xf6"
BIG_OPCODES = b"\x69\x81\x6b\x80\x83\xc0\xc1\xf6"
ANTI_DISASM_EXTRA_BYTE = 0xF4
SINGLE_BYTE_OPCODE_SET = set(SINGLE_BYTE_OPCODES)
MED_OPCODE_SET = set(MED_OPCODES)
BIG_OPCODE_SET = set(BIG_OPCODES)
# fmt: on


class MemHelper:
    def __init__(self, start: int, end: int):
        self.mem_results = b""
        self.mem_offsets = []
        self.start = start
        self.end = end
        if not self.mem_results:
            self._get_memory(start, end)

    def _get_memory(self, start: int, end: int):
        result = idc.get_bytes(start, end - start)
        self.mem_results = result
        self.mem_offsets.append((start, end - start))


@dataclass(repr=False)
class PatchOperation:
    """Class to store patch operations that will be applied later."""

    address: int
    byte_values: bytes

    def apply(self):
        """Apply the patch operation."""
        ida_bytes.patch_bytes(self.address, self.byte_values)
        logger.debug(
            f"Applied patch at 0x{self.address:x} with value {self.byte_values.hex()}"
        )

    def __str__(self):
        """String representation with hex formatting."""
        return f"{self.__class__.__name__}(address=0x{self.address:X} , byte_values={self.byte_values.hex()})"

    __repr__ = __str__


@dataclass(repr=False)
class UnconditionalJumpOperation(PatchOperation):
    """Class to store unconditional jump patch operations."""

    byte_values: bytes = b"\xeb"

    def apply(self):
        """Apply the patch operation."""
        ida_bytes.patch_bytes(self.address, self.byte_values)

    def __str__(self):
        return super().__str__()


def is_x64():
    # Check if the current architecture is x64
    return ida_ida.inf_is_64bit()


def format_bytes(bytes_list):
    """
    Format a list of bytes as a string of hex values.

    Args:
        bytes_list (bytes or list): The bytes to format.

    Returns:
        str: A string of comma-separated hex values.
    """
    return ", ".join(["0x{:02X}".format(b) for b in bytes_list])


def parse_hex_string(hex_string):
    """
    Parse a string of hex values into a bytes object.

    Args:
        hex_string (str): A string of comma-separated hex values.

    Returns:
        bytes: A bytes object containing the parsed hex values.
    """
    # Remove whitespace and split by commas
    hex_values = hex_string.replace(" ", "").split(",")

    # Convert each hex value to an integer
    bytes_list = []
    for val in hex_values:
        # Remove '0x' prefix if present
        val = val.strip().lower()
        if val.startswith("0x"):
            val = val[2:]

        # Convert to integer
        bytes_list.append(int(val, 16))

    return bytes(bytes_list)


class DeFlow:
    """
    Class for detecting and removing control flow obfuscation from binaries.

    This class can work with either a direct function address in IDA or a provided byte buffer.
    It detects and patches opaque predicates and other control flow obfuscation techniques.
    """

    def __init__(self):
        self._already_discovered = set()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    @staticmethod
    def is_in_range(addr, base_address, buffer_end_ea):
        """
        Helper to see if 'addr' is located within our buffer range.
        """
        return base_address <= addr < buffer_end_ea

    def deflow_functions(self, functions=None):
        """
        Main entry point for deobfuscating functions.

        Args:
            functions: Optional iterable of function entry points (start addresses) in the .text section.
            text_seg_buffer: Whether to use the entire .text segment as buffer.

        Returns:
            None
        """

        # Get the start of the .text segment and its size in IDA.
        text_seg = ida_segment.get_segm_by_name(".text")
        if not text_seg:
            print("[-] Could not find .text segment.")
            return

        if not functions:
            functions = idautils.Functions(text_seg.start_ea, text_seg.end_ea)

        logger.debug(
            "Processing %d functions in text segment range: base_address=0x%x, end_address=0x%x, size=%d",
            len(functions),
            text_seg.start_ea,
            text_seg.end_ea,
            text_seg.end_ea - text_seg.start_ea,
        )

        # Reset discovered addresses for a new deflow run
        self._already_discovered = set()

        for func_addr in functions:
            logger.debug("Processing function at address: 0x%x", func_addr)

            func = ida_funcs.get_func(func_addr)
            logger.debug(
                "Function 0x%x: start_ea=0x%x, end_ea=0x%x, size=%d",
                func_addr,
                func.start_ea,
                func.end_ea,
                func.end_ea - func.start_ea,
            )
            patch_operations = self.deflow(
                text_seg.start_ea, text_seg.end_ea, func_addr, func.end_ea
            )
            for operation in patch_operations:
                operation.apply()

    def deflow(
        self,
        segment_start_ea,
        segment_end_ea,
        chunk_start_ea,
        chunk_end_ea,
        apply_patches=False,
    ):
        patch_operations = []
        chunks = self.deflow_chunk(
            segment_start_ea,
            segment_end_ea,
            chunk_start_ea,
            chunk_end_ea,
            patch_operations,
        )
        logger.debug(
            "Initial chunks from deflow_chunk for function 0x%x: %s",
            chunk_start_ea,
            ", ".join([format_addr(c) for c in chunks]),
        )
        while True:
            if not chunks:
                break
            new_chunks = []
            for c in chunks:
                logger.debug("Processing chunk at 0x%x", c)
                new_chunks.extend(
                    self.deflow_chunk(
                        segment_start_ea,
                        segment_end_ea,
                        c,
                        chunk_end_ea,
                        patch_operations,
                    )
                )
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "New chunks after iteration: %s",
                    ", ".join([format_addr(c) for c in new_chunks]),
                )
            chunks = new_chunks

        if apply_patches:
            logger.debug(
                f"Applying {len(patch_operations)} patch operations for chunk 0x{chunk_start_ea:x}"
            )
            for operation in patch_operations:
                operation.apply()
        return patch_operations

    def deflow_chunk(
        self,
        buffer_start_ea,
        buffer_end_ea,
        address,
        ending_address,
        patch_operations,
        provided_buffer=None,
    ):
        """
        Analyze and deobfuscate a chunk of code.

        Args:
            buffer_start_ea: Start address of the buffer being analyzed
            buffer_end_ea: End address of the buffer being analyzed
            address: Address of the chunk to analyze
            ending_address: End address of the function containing the chunk
            patch_operations: List to store patch operations
            provided_buffer: Optional byte buffer to use instead of reading from IDA

        Returns:
            List of new chunks to analyze
        """
        logger.debug("Starting deflow_chunk analysis for address: 0x%x", address)
        new_chunks = []

        is_negative = address < 0
        address = abs(address)

        # Check if we have already discovered this address
        if address in self._already_discovered:
            logger.debug("Address 0x%x already discovered, skipping.", address)
            return new_chunks

        self._already_discovered.add(address)

        # We'll keep track of potential obfuscated branches
        last_branch = 0  # Indicates our last conditional jump address
        last_branch_size = 0  # Size of the last conditional jump instruction
        last_target = 0  # Target location of the last conditional jump

        # Calculate the offset in 'buffer' corresponding to 'address'.
        if not self.is_in_range(address, buffer_start_ea, buffer_end_ea):
            logger.debug(
                "Address %s out of range [%s - %s]",
                format_addr(address),
                format_addr(buffer_start_ea),
                format_addr(buffer_end_ea),
            )
            return new_chunks

        # Use provided buffer or get bytes from IDA
        if provided_buffer is None:
            # Disassemble from 'address' until we run out of bytes
            buffer_size = ending_address - address
            if buffer_size < 0:
                buffer_size = 0x8000  # just take 512kb from the buffer size

            buffer = ida_bytes.get_bytes(address, buffer_size)
        else:
            buffer = provided_buffer

        insn = None
        for insn in self.md.disasm(buffer, address):
            logger.debug(
                "Disassembled instruction at 0x%x: %s %s",
                insn.address,
                insn.mnemonic,
                insn.op_str,
            )
            insn = typing.cast(capstone.CsInsn, insn)

            # We'll track potential jump targets
            target = 0
            is_jmp = True

            # 1) Check for invalid / return instructions
            if (
                insn.id == 0
                or insn.mnemonic in ["ret", "retn"]
                or insn.mnemonic.startswith("ret")
                or insn.mnemonic == "int"
            ):
                logger.debug(
                    "Encountered return or invalid instruction at 0x%x", insn.address
                )
                if last_target == 0:
                    return new_chunks  # Only accept when no lastTarget
                # If there is a last_target, continue analysis.

            # 2) Check for conditional jump instructions
            elif insn.mnemonic in CONDITIONAL_JUMPS_MNEMONICS:
                # if(lastTarget == 0)
                if last_target == 0:
                    target = self.calc_target_jump(insn)
                    logger.debug(
                        "Conditional jump at 0x%x with target 0x%x",
                        insn.address,
                        target,
                    )

                    # Check if in range
                    if not self.is_in_range(target, buffer_start_ea, buffer_end_ea):
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
                    # Do not accept any conditional jumps if we already have a last_target
                    # (might be looking at junk code)
                    logger.debug(
                        "Skipping conditional jump at 0x%x due to existing last_target 0x%x",
                        insn.address,
                        last_target,
                    )
                    is_jmp = False
            # 3) Check for unconditional jumps or calls
            elif insn.mnemonic in ["jmp", "call"] and last_target == 0:
                target = self.calc_target_jump(insn)
                real_head = idc.get_item_head(target)
                logger.debug(
                    "Unconditional %s at 0x%x with target 0x%x",
                    insn.mnemonic,
                    insn.address,
                    target,
                )
                if not self.is_in_range(target, buffer_start_ea, buffer_end_ea):
                    logger.debug("New address 0x%x out of range", target)
                    is_jmp = False
                else:
                    if insn.mnemonic == "call":
                        # address + insn.size => next instruction's address
                        next_insn_addr = idc.next_addr(insn.address)
                        if next_insn_addr != (address + insn.size):
                            logger.warning(
                                "Call instruction: next instruction address 0x%x is not the expected 0x%x. Reverting",
                                next_insn_addr,
                                address + insn.size,
                            )
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
                # it's not a jump, so we can't handle it
                is_jmp = False

            # Call the extracted function to handle branch instructions
            result, last_branch, last_branch_size, last_target = (
                self.handle_branch_instruction(
                    insn,
                    insn.address,  # In Capstone, insn.address is the runtime address
                    last_branch,
                    last_branch_size,
                    last_target,
                    buffer_start_ea,
                    is_jmp,
                    target,
                    is_negative,
                    new_chunks,
                    patch_operations,
                )
            )

            if result is not None:
                return result

        else:
            if insn:
                logger.debug(
                    "last instruction disassembled: %s @ 0x%x and last_target: 0x%x",
                    insn.mnemonic,
                    insn.address,
                    last_target,
                )
                target_head = idc.prev_head(last_target)
                if last_target != 0 and target_head != last_target:
                    # create an artifical collision by using the previous head of the last target
                    A = idc.get_item_size(target_head)
                    B = last_target - target_head
                    location = target_head + B + 1  # go past last_target by just 1 byte
                    logger.debug(
                        "idc.prev_head(0x%x) = 0x%x, location: 0x%x, last_branch: 0x%x, last_branch_size: %d, last_target: 0x%x, is_jmp: %s, target: 0x%x, is_negative: %s",
                        last_target,
                        target_head,
                        location,
                        last_branch,
                        last_branch_size,
                        last_target,
                        is_jmp,
                        target,
                        is_negative,
                    )
                    result, last_branch, last_branch_size, last_target = (
                        self.handle_branch_instruction(
                            insn,
                            location,
                            last_branch,
                            last_branch_size,
                            last_target,
                            buffer_start_ea,
                            is_jmp,
                            target,
                            is_negative,
                            new_chunks,
                            patch_operations,
                        )
                    )

        return new_chunks

    def handle_branch_instruction(
        self,
        insn,
        location,
        last_branch,
        last_branch_size,
        last_target,
        buffer_start_ea,
        is_jmp,
        target,
        is_negative,
        new_chunks,
        patch_operations,
    ):
        """
        Handle branch instruction analysis for opaque predicate detection and removal.

        Args:
            insn: Current instruction being analyzed
            location: Address of the current instruction
            last_branch: Address of the last branch instruction
            last_branch_size: Size of the last branch instruction
            last_target: Target address of the last branch
            buffer_start_ea: Start address of the buffer being analyzed
            is_jmp: Whether the current instruction is a jump
            target: Target address of the current jump instruction
            is_negative: Whether the jump is negative
            new_chunks: List of new code chunks to analyze
            patch_operations: List to store patch operations

        Returns:
            Tuple of (result, last_branch, last_branch_size, last_target)
        """
        # Steps (bytes) left to reach lastTarget from current address
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
            return None, last_branch, last_branch_size, last_target
        elif steps_left == 0 and last_target != 0:
            logger.debug(
                "Exact collision at 0x%x; adding 0x%x and 0x%x",
                location,
                last_branch + last_branch_size,
                last_target,
            )
            new_chunks.append(last_branch + last_branch_size)
            new_chunks.append(last_target)
            return new_chunks, last_branch, last_branch_size, last_target
        elif steps_left < 0 and last_target != 0:
            # stepsLeft != 0 => collision within the instruction => obfuscated
            count = last_target - last_branch
            logger.debug(
                "Obfuscated branch detected at 0x%x; count: %d", last_branch, count
            )
            if count > 0:
                # making sure we are a positive jump
                buffer_offset = last_branch - buffer_start_ea  # index in local buffer

                # NOP slide everything except our own instruction
                patch_byte = b"\x90" if is_negative else b"\xcc"
                patch_bytes: bytes = patch_byte * (count - last_branch_size)
                patch_operations.append(
                    PatchOperation(
                        buffer_start_ea + buffer_offset + last_branch_size, patch_bytes
                    )
                )
                logger.debug(
                    "Patching bytes at 0x%x with %s",
                    buffer_start_ea + buffer_offset,
                    patch_bytes.hex(),
                )

                if not is_negative:
                    # Force unconditional jump
                    patch_operations.append(
                        UnconditionalJumpOperation(buffer_start_ea + buffer_offset)
                    )
                    logger.debug(
                        "Forced unconditional jump at 0x%x",
                        buffer_start_ea + buffer_offset,
                    )

                # add next instruction for analysis and exit current analysis
                new_chunks.append(last_target)
                logger.debug("Added new chunk target 0x%x", last_target)
                return new_chunks, last_branch, last_branch_size, last_target
            else:
                # we are a negative jump, set 63rd bit to indicate negative jump
                last_target = -last_target
                logger.debug(
                    "Negative jump encountered. Adjusted last_target: 0x%x", last_target
                )
                # add target to analyzer and exit current analysis
                new_chunks.append(last_target)
                return new_chunks, last_branch, last_branch_size, last_target

        return None, last_branch, last_branch_size, last_target

    def calc_target_jump(self, insn: capstone.CsInsn):
        """
        Helper to extract jump or call target from an instruction.

        Args:
            insn: Capstone instruction object

        Returns:
            Target address of the jump or call instruction
        """
        operand = idc.get_operand_value(insn.address, 0)
        op = insn.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            target = op.imm
            logger.debug(
                "@ insn.address: %s with jump target: %s",
                format_addr(insn.address),
                format_addr(target),
            )
        else:
            logger.debug("Operand not immediate at %s", format_addr(insn.address))
        return operand

    @staticmethod
    def disassemble(ea):
        """
        Get the disassembly text associated with an address.

        Args:
            ea: Effective address to disassemble

        Returns:
            String containing the disassembly text
        """
        return idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE)


def deflow(matches):
    deflow = DeFlow()
    patch_operations = []
    BUFFER_SIZE = 129  # Max size of anti-disassembly block
    for match_start, match_len, desc, match_bytes in matches:
        match_end = match_start + match_len
        block_end = match_start + BUFFER_SIZE
        patch_operations.extend(
            deflow.deflow(match_start, block_end, match_start, match_end)
        )
    print(f"operations: {patch_operations}")
    return patch_operations


@dataclass
class JumpTargetAnalyzer:
    # Input parameters for processing jumps.
    match_bytes: bytes  # The bytes in which we're matching jump instructions.
    match_start: int  # The address where match_bytes starts.
    block_end: int  # End address of the allowed region.
    start_ea: int  # Base address of the memory block (used for bounds checking).

    # Define jump patterns to search within match_bytes.
    jump_patterns: list = field(
        init=False,
        default_factory=lambda: [
            (rb"[\xEB\xE9].", "short_jump", 2),  # JMP rel8
            (rb"[\x70-\x7F].", "short_conditional", 2),  # Jcc rel8
        ],
    )
    # Internal storage for jump statistics.
    jump_targets: collections.Counter = field(
        init=False, default_factory=collections.Counter
    )
    jump_details: list = field(init=False, default_factory=list)

    def process(self, mem: MemHelper):
        # Process each jump match in match_bytes.
        for jump_match in re.finditer(rb"[\xEB\x70-\x7F]", self.match_bytes):
            jump_offset = jump_match.start()
            jump_ea = self.match_start + jump_offset
            final_target = self.follow_jump_chain(mem, jump_ea)
            if final_target and self.match_start <= final_target < self.block_end:
                self.jump_targets[final_target] += 1
                self.jump_details.append((jump_ea, final_target))
                print(
                    f"  Found {jump_match.group().hex()} @ 0x{jump_ea:X} targeting 0x{final_target:X}"
                )
        return self

    def follow_jump_chain(self, mem, current_ea, visited=None):
        """
        Follow a chain of jumps starting from current_ea.
        Avoid loops or out-of-bounds jumps.
        """
        if visited is None:
            visited = set()
        # Avoid loops or jumps outside the memory block.
        if (
            current_ea in visited
            or current_ea < self.start_ea
            or current_ea >= self.start_ea + len(mem.mem_results)
        ):
            return None
        visited.add(current_ea)
        current_offset = current_ea - self.start_ea
        try:
            current_bytes = mem.mem_results[current_offset : current_offset + 6]
        except IndexError:
            print(f"IndexError at {current_ea} with offset {current_offset}")
            return None
        # Try matching each jump pattern.
        for pattern, jump_type, jump_len in self.jump_patterns:
            match = re.match(pattern, current_bytes)
            if match:
                if jump_type in ["short_jump", "short_conditional"]:
                    offset = struct.unpack("<b", match.group()[-1:])[0]
                    target = current_ea + jump_len + offset
                else:  # near_jump or other types (if needed)
                    offset = struct.unpack("<i", match.group()[1:])[0]
                    target = current_ea + jump_len + offset
                # If the jump target is within the valid conditional range,
                # continue following the chain.
                if self.match_start <= target < self.block_end:
                    return self.follow_jump_chain(mem, target, visited)
                # Otherwise, if the target is within the overall memory block, return it.
                return (
                    target
                    if self.start_ea <= target < self.start_ea + len(mem.mem_results)
                    else None
                )
        # If no jump pattern matches, end of the chain; return the current address.
        return current_ea

    def sorted_targets(self):
        """
        Return a sorted list of (final_target, count) tuples.
        Sorted by count descending; if counts are equal, sort by final_target descending.
        """
        return sorted(
            self.jump_targets.items(), key=lambda item: (item[1], item[0]), reverse=True
        )

    def __iter__(self):
        """
        Iterate over the most likely targets.
        For each candidate target, check for a multi-part jump:
        if there's a jump whose starting address equals candidate + 1,
        yield its final target instead.
        """
        for candidate, count in self.sorted_targets():
            final_candidate = candidate
            # Check for a jump starting at candidate + 1.
            for jump_ea, target in self.jump_details:
                if jump_ea == candidate + 1:
                    final_candidate = target
                    break
            yield final_candidate


@dataclass
class MatchSegment:
    start: int
    length: int
    description: str
    matched_bytes: bytes


class MatchChain:
    def __init__(self, base_address: int):
        self.base_address = base_address
        self.segments: typing.List[MatchSegment] = []

    def add_segment(self, segment: MatchSegment):
        self.segments.append(segment)

    def overall_start(self) -> int:
        return self.segments[0].start if self.segments else 0

    def overall_length(self) -> int:
        if not self.segments:
            return 0
        first = self.segments[0]
        last = self.segments[-1]
        return (last.start + last.length) - first.start

    def overall_matched_bytes(self) -> bytes:
        return b"".join(seg.matched_bytes for seg in self.segments)

    def append_junk(
        self, junk_start: int, junk_len: int, junk_desc: str, junk_bytes: bytes
    ):
        seg = MatchSegment(
            start=junk_start,
            length=junk_len,
            description=junk_desc,
            matched_bytes=junk_bytes,
        )
        self.add_segment(seg)

    def update_description(self, new_desc: str):
        if self.segments:
            self.segments[0].description = new_desc


def find_stage1(mem, ea, end_ea):
    print("Searching for stage1 patterns from 0x{:X} to 0x{:X}".format(ea, end_ea))

    # Combine all patterns, keeping your original format
    patterns = [
        (MULTI_PART_PATTERNS, "Multi-Part Conditional Jumps"),
        (SINGLE_PART_PATTERNS, "Single-Part Conditional Jumps"),
    ]

    all_matches = []
    for pattern_group, desc in patterns:
        if not isinstance(pattern_group, list):
            pattern_group = [pattern_group]
        print(f"\nLooking for {desc} patterns:")
        for pattern in pattern_group:
            match = re.finditer(pattern, mem.mem_results, re.DOTALL)
            for m in match:
                found = ea + m.start()
                # Optionally remove this check for anti-disassembly sequences
                # if idc.get_item_head(found) != found:
                #     continue
                match_len = m.end() - m.start()
                matched_bytes = mem.mem_results[m.start() : m.start() + match_len]
                all_matches.append(
                    (
                        found,
                        match_len,
                        desc,
                        mem.mem_results[m.start() : m.end()],
                    )
                )

    for found, match_len, desc, matched_bytes in all_matches:
        print(
            f"{desc.rjust(32, ' ')} @ 0x{found:X} - "
            f"{matched_bytes.hex()[:16]}"
            f"{'...' if match_len >= 15 else ''}"
        )
    return all_matches


# Function to find junk instructions after stage1 matches
def find_junk_instructions_after_stage1(mem, stage1_matches, start_ea, func_end):
    """
    - Register-based operations (0-57): ~58% chance.
    - RDTSC (58-60): ~3% chance.
    - PUSH imm32 (61-62): ~2% chance.
    - PUSH imm8 (63-65): ~3% chance.
    - Single-byte instructions (66-75): ~10% chance.
    - Conditional jumps with 8-bit offset (76-80): ~5% chance.
    - Conditional jumps with 32-bit offset (81-90): ~10% chance.
    - CALL instruction (91-99): ~9% chance.
    """
    print(
        f"\nPhase 2: Checking for junk instructions immediately following Stage1 matches"
    )

    updated_matches = []
    for (
        stage1_start,
        stage1_len,
        stage1_desc,
        stage1_bytes,
    ) in stage1_matches:
        # Calculate the position immediately after the Stage1 match in mem_results
        current_pos = stage1_start + stage1_len - start_ea
        if current_pos >= len(mem.mem_results):
            print(f"No room for junk after {stage1_desc} @ 0x{stage1_start:X}")
            updated_matches.append(
                (stage1_start, stage1_len, stage1_desc, stage1_bytes)
            )
            continue

        # Extract the buffer after the Stage1 match
        post_stage1_buffer = mem.mem_results[current_pos:]
        junk_sequence = []
        junk_descriptions = []
        total_junk_len = 0

        print(
            f"\nSearching for junk instruction sequence after {stage1_desc} at 0x{stage1_start:X} "
            f"(starting from 0x{stage1_start + stage1_len:X})"
        )

        # Iterate while there's enough space for another junk instruction (> 6 bytes)
        while len(post_stage1_buffer) > 6:
            junk_found = False
            for junk_pattern, junk_desc in JUNK_PATTERNS:
                match = re.match(junk_pattern, post_stage1_buffer)
                if match:
                    junk_len = match.end() - match.start()
                    junk_bytes = post_stage1_buffer[:junk_len]
                    junk_sequence.append(junk_bytes)
                    junk_descriptions.append(junk_desc)
                    total_junk_len += junk_len
                    post_stage1_buffer = post_stage1_buffer[junk_len:]
                    junk_found = True
                    print(
                        f"  Found {junk_desc} @ 0x{stage1_start + stage1_len + total_junk_len - junk_len:X} "
                        f"({junk_len} bytes: {junk_bytes.hex()})"
                    )
                    break  # Move to the next portion of the buffer

            if not junk_found:
                print(
                    f"  No more junk instructions match with {len(post_stage1_buffer)} bytes remaining"
                )
                break  # Exit if no junk instruction matches

        # Combine Stage1 with any junk instructions found
        if junk_sequence:
            combined_junk_bytes = b"".join(junk_sequence)
            combined_desc = " -> ".join([stage1_desc] + junk_descriptions)
            updated_matches.append(
                (
                    stage1_start,
                    stage1_len + total_junk_len,
                    combined_desc,
                    stage1_bytes + combined_junk_bytes,
                )
            )
            print(
                f"Combined sequence: {combined_desc} (total length: {stage1_len + total_junk_len} bytes)"
            )
        else:
            updated_matches.append(
                (stage1_start, stage1_len, stage1_desc, stage1_bytes)
            )
            print(f"No junk instructions follow {stage1_desc}")

    # Optionally sort and display matches (similar to your original code)
    for match_start, match_len, desc, match_bytes in updated_matches:
        print(
            f"{desc.rjust(32, ' ')} @ 0x{match_start:X} - "
            f"{match_bytes.hex()[:16]}{'...' if match_len > 16 else ''}"
        )

    return updated_matches  # Return only updated_matches for consistency


def find_big_instruction(buffer_bytes, is_x64=False):
    """
    Find the 'big instruction' in a 6-byte buffer, checking specific positions from the end.
    According to the constraints, the buffer will always be exactly 6 bytes.

    Args:
        buffer_bytes (bytes): The 6-byte buffer to analyze.
        is_x64 (bool): Whether to check for REX prefixes (x64 mode).

    Returns:
        dict: A dictionary containing information about the found instruction.
    """
    assert len(buffer_bytes) == 6, "Buffer must be exactly 6 bytes"

    # Function to check if a byte is a valid REX prefix (0x40-0x4F)
    def is_rex_prefix(byte):
        return 0x40 <= byte <= 0x4F

    # Function to check if a byte is a valid ModR/M byte (0x80-0xBF)
    def is_valid_modrm(byte):
        return 0x80 <= byte <= 0xBF

    # Ensure we have a 6-byte buffer
    if len(buffer_bytes) != 6:
        return {
            "type": None,
            "name": "Invalid buffer size",
            "instruction": [],
            "position": -1,
            "junk_before": buffer_bytes,
            "junk_after": [],
        }

    # 1. First check for 3-byte instructions in x64 mode (highest priority)
    if is_x64:
        # Check all possible positions for 3-byte instructions (REX + opcode + ModR/M)
        for pos in range(4):  # Start positions 0, 1, 2, 3
            if pos + 2 >= len(buffer_bytes):
                continue

            rex = buffer_bytes[pos]
            opcode = buffer_bytes[pos + 1]
            modrm = buffer_bytes[pos + 2]

            if is_rex_prefix(rex):
                # Check if it forms a valid 3-byte instruction
                if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
                    # Get junk bytes at the end (based on position)
                    junk_after = buffer_bytes[pos + 3 :]

                    # Verify junk bytes constraint for 3-byte instructions
                    expected_junk_bytes = max(0, 3 - pos)
                    if len(junk_after) == expected_junk_bytes:
                        return {
                            "type": "3-byte",
                            "name": "REX + Two-byte Med instruction",
                            "instruction": [rex, opcode, modrm],
                            "position": pos,
                            "junk_before": buffer_bytes[:pos],
                            "junk_after": junk_after,
                        }

                elif opcode in BIG_OPCODE_SET and is_valid_modrm(modrm):
                    # Get junk bytes at the end (based on position)
                    junk_after = buffer_bytes[pos + 3 :]

                    # Verify junk bytes constraint for 3-byte instructions
                    expected_junk_bytes = max(0, 3 - pos)
                    if len(junk_after) == expected_junk_bytes:
                        return {
                            "type": "3-byte",
                            "name": "REX + Two-byte Big instruction",
                            "instruction": [rex, opcode, modrm],
                            "position": pos,
                            "junk_before": buffer_bytes[:pos],
                            "junk_after": junk_after,
                        }

    # 2. Next check for 2-byte instructions
    for pos in range(5):  # Start positions 0, 1, 2, 3, 4
        if pos + 1 >= len(buffer_bytes):
            continue

        opcode = buffer_bytes[pos]
        modrm = buffer_bytes[pos + 1]

        # Check if it forms a valid 2-byte instruction
        if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
            # Get junk bytes at the end (based on position)
            junk_after = buffer_bytes[pos + 2 :]

            # Verify junk bytes constraint for 2-byte instructions
            expected_junk_bytes = max(0, 4 - pos)
            if len(junk_after) == expected_junk_bytes:
                return {
                    "type": "2-byte",
                    "name": "Two-byte Med instruction",
                    "instruction": [opcode, modrm],
                    "position": pos,
                    "junk_before": buffer_bytes[:pos],
                    "junk_after": junk_after,
                }

        elif opcode in BIG_OPCODE_SET and is_valid_modrm(modrm):
            # Get junk bytes at the end (based on position)
            junk_after = buffer_bytes[pos + 2 :]

            # Verify junk bytes constraint for 2-byte instructions
            expected_junk_bytes = max(0, 4 - pos)
            if len(junk_after) == expected_junk_bytes:
                return {
                    "type": "2-byte",
                    "name": "Two-byte Big instruction",
                    "instruction": [opcode, modrm],
                    "position": pos,
                    "junk_before": buffer_bytes[:pos],
                    "junk_after": junk_after,
                }

    # 3. Finally check for 1-byte instructions (lowest priority)
    pos = 5  # Only valid position for 1-byte instruction (last byte)
    if pos < len(buffer_bytes):
        byte = buffer_bytes[pos]
        if byte in SINGLE_BYTE_OPCODE_SET:
            return {
                "type": "1-byte",
                "name": "Single-byte big instruction",
                "instruction": [byte],
                "position": pos,
                "junk_before": buffer_bytes[:pos],
                "junk_after": [],  # No junk after 1-byte instruction at the end
            }

    # No valid instruction found
    return {
        "type": None,
        "name": "No match found",
        "instruction": [],
        "position": -1,
        "junk_before": buffer_bytes,
        "junk_after": [],
    }


def find_ending_big_instructions(mem, matches, start_ea, func_end):

    # Define big instruction patterns
    big_patterns = [
        (rb"[" + SINGLE_BYTE_OPCODES + rb"]", "Single-byte big instruction"),
        (rb"[" + MED_OPCODES + rb"][\x80-\xBF]", "Two-byte Med instruction"),
        (rb"[" + BIG_OPCODES + rb"][\x80-\xBF]", "Two-byte Big instruction"),
    ]
    if is_x64():
        big_patterns.append(
            (
                rb"[\x48-\x4F][" + MED_OPCODES + rb"][\x80-\xBF]",
                "REX + Two-byte Med instruction",
            )
        )
        big_patterns.append(
            (
                rb"[\x48-\x4F][" + BIG_OPCODES + rb"][\x80-\xBF]",
                "REX + Two-byte Big instruction",
            )
        )

    print(
        f"\nPhase 3: Checking for big instructions to find end of anti-disassembly block"
    )
    updated_matches = []
    BUFFER_SIZE = 129  # Max size of anti-disassembly block

    for match_start, match_len, desc, match_bytes in matches:
        match_end = match_start + match_len
        print(f"Analyzing match: {desc} @ 0x{match_start:X} (length: {match_len})")

        # Define the full anti-disassembly block
        block_end = match_start + BUFFER_SIZE

        # By the time this function, find_ending_big_instructions(), is called,
        # we've determined that the anti-disassembly stub is nearing its end, with
        # at most 6 bytes remaining before the transition to unobfuscated code.

        jump_targets = JumpTargetAnalyzer(
            match_bytes, match_start, block_end, start_ea
        ).process(mem=mem)
        for most_likely_target in jump_targets:
            # The most_likely_target represents the most likely jump target within the
            # stub—likely the point where execution exits to the unobfuscated code.
            # however, if we do not find a match, then we want to continue searching
            # previous targets and use those in decending order until we find a match
            print(
                f"most_likely_target: {most_likely_target:X}, block_end: {block_end:X}"
            )

            # Anti-disassembly stubs often use a "big instruction"
            # (e.g., one with a 32-bit operand, up to 6 bytes) just before the
            # final jump target to confuse disassemblers. Since most_likely_target
            # is the exit point, the big instruction must be located in the 6 bytes before it.
            search_start = most_likely_target - 6
            search_bytes = mem.mem_results[
                search_start - start_ea : most_likely_target - start_ea
            ]

            print(f"search_bytes: {search_bytes.hex()}")

            result = find_big_instruction(search_bytes, is_x64=is_x64())

            if not result["type"]:
                print("No valid instruction found.")
                # if we do not find a match, then we want to find the previous targets and use those
                # in decending order until we find a match
                continue

            junk_len = len(result["junk_after"]) if result["junk_after"] else 0
            if junk_len > 0:
                _m = f"    Junk bytes: {result['junk_after'].hex()} ({junk_len} bytes)"
                print(_m)
            instruction_bytes = bytes(result["instruction"])
            print(f"    Detected {result['name']}: {instruction_bytes.hex()} bytes")
            new_desc = f"{desc} -> {result['name']}"
            new_len = (search_start + 6) - match_start
            new_bytes = mem.mem_results[
                match_start - start_ea : search_start + 6 - start_ea
            ]
            # check for multiple anti-disassembly bytes after search_start + 6
            # if found, then we want to add them to the new_bytes
            for i in itertools.count():
                if (
                    mem.mem_results[search_start - start_ea + 6 + i]
                    == ANTI_DISASM_EXTRA_BYTE
                ):
                    new_bytes = bytes(mem.mem_results[search_start - start_ea + 6 + i])
                    new_len += 1
                    continue
                break
            updated_matches.append((match_start, new_len, new_desc, new_bytes))
            break
        else:
            updated_matches.append((match_start, match_len, desc, match_bytes))
            print("No big instruction found...hmm, unlikely!")

    return updated_matches


def process(func, patch_operations, using_deflow):
    start_ea = func.start_ea
    end_ea = func.end_ea
    mem = MemHelper(start_ea, end_ea)
    all_matches = find_stage1(mem, start_ea, end_ea)
    if not all_matches:
        print("No stage1 matches found!")
        return

    updated_matches = find_junk_instructions_after_stage1(
        mem, all_matches, start_ea, end_ea
    )
    if using_deflow:
        patch_operations.extend(deflow(updated_matches))
    else:
        updated_matches = find_ending_big_instructions(
            mem, updated_matches, start_ea, end_ea
        )
        print("=== Updated matches ===")
        updated_matches.sort()
        for found_addr, match_len, desc, matched_bytes in updated_matches:
            print(
                f"{desc.rjust(96, ' ')} @ 0x{found_addr:X} - "
                f"{matched_bytes.hex()} "
                f"length: {match_len * 2} (0x{match_len * 2:X}) "
                f"byte size: {match_len}"
            )
            patch_operations.append(PatchOperation(found_addr, b"\x90" * match_len))
    return patch_operations


def main(using_deflow=False):
    print("Starting search...")
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    patch_operations = []
    if func:
        process(func, patch_operations, using_deflow)
    print("\nSearch completed.")
    print("Applying patches...")
    for patch in patch_operations:
        patch.apply()
    print("Patches applied.")


if __name__ == "__main__":
    clear_output()
    main(using_deflow=False)
