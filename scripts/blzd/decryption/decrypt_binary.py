import argparse
import os
import re
import struct
import sys
import typing

import ida_bytes
import ida_ida
import ida_loader
import ida_nalt
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
from mutilz.fastaf.cython import crc4, cyfnv1a
from mutilz.helpers.ida import clear_output

fnv1a = cyfnv1a.fnv1a_hash


# --- Constants and Data Structures ---

PAGE_SIZE = 0x1000

# Get the PE header using IDA's peutils_t helper.
PE = idautils.peutils_t()
IMPORT_TABLE_OFFSET = 0x80


class Game:
    NONE = 0
    WOW = 1
    OVERWATCH = 2
    DIABLO = 3


class Patterns:
    def __init__(self, start_offsets, crypt_keys, validation):
        self.start_offsets = start_offsets
        self.crypt_keys = crypt_keys
        self.validation = validation

        # Property indicating whether the validation list contains a wildcard (-1).
        self.use_regex = False
        # If regex is needed, this will store the compiled regex.
        self.validation_regex = None

        # Check if the validation list contains a wildcard value (-1).
        if -1 in validation:
            self.use_regex = True
            # Compile the regex pattern with DOTALL flag to ensure '.' matches every byte.
            self.validation_regex = self.create_regex_from_bytes(validation)
        else:
            # convert to bytes so we can find() it
            self.validation = bytes(validation)

    @staticmethod
    def create_regex_from_bytes(byte_list):
        """
        Converts a list of integers into a regex pattern.
        A value of -1 in the list is treated as a wildcard that matches any single byte.

        Args:
            byte_list (list of int): List of integers representing bytes.
                                    Use -1 to denote a wildcard.

        Returns:
            A compiled regular expression object that can be used to search in bytes/bytearray.
        """
        regex_parts = []
        for byte in byte_list:
            if byte == -1:
                # Wildcard: match any single byte
                regex_parts.append(b".")
            else:
                # Append the specific byte as an escape sequence.
                # Format the byte value as a two-digit hexadecimal number.
                regex_parts.append(f"\\x{byte & 0xFF:02x}".encode("utf-8"))
        # Join the parts into one bytes pattern
        pattern = b"".join(regex_parts)
        # Compile the pattern with DOTALL flag so that '.' matches any byte including newline.
        return re.compile(pattern, flags=re.DOTALL)

    def __repr__(self):
        if self.use_regex:
            return (
                f"Patterns(start_offsets={self.start_offsets}, crypt_keys={self.crypt_keys}, "
                f"validation={self.validation}, use_regex=True, validation_regex={self.validation_regex.pattern})"
            )
        else:
            return (
                f"Patterns(start_offsets={self.start_offsets}, crypt_keys={self.crypt_keys}, "
                f"validation={self.validation}, use_regex=False)"
            )


class WowPatterns(Patterns):
    def __init__(self):
        super().__init__(
            # fmt: off
            start_offsets=[
                [0x00, 0x48, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48, 0x8D],
                [0xFF, 0xFF, 0x48, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48, 0x8D],
                [0x00, 0x4C, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48],
                [0xFF, 0xFF, 0x4C, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48]
            ],
            crypt_keys=[
                [0x4C, 0x8D, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA]
            ],
            # fmt: on
            validation=[0xB9, 0xF1, 0xD8, 0x27, 0x98],
        )


class DiabloPatterns(Patterns):
    def __init__(self):
        super().__init__(
            # fmt: off
            start_offsets=[
                [0x00, 0x48, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48, 0x8D],
                [0xFF, 0xFF, 0x48, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48, 0x8D],
                [0x00, 0x4C, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48],
                [0xFF, 0xFF, 0x4C, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48]
            ],
            crypt_keys=[
                [0x4C, 0x8D, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA],
                [0x4C, 0x8D, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xF3, 0xAA]
            ],
            # # fmt: on
            validation=[0x81, -1, 0x98, 0x2F, 0x8A, 0x42],
        )


# --- Helper Functions ---
def find_signature(ida_signature: str) -> list:
    binary_pattern = idaapi.compiled_binpat_vec_t()
    idaapi.parse_binpat_str(binary_pattern, ida_ida.inf_get_min_ea(), ida_signature, 16)
    results = []
    ea = ida_ida.inf_get_min_ea()
    while True:
        occurence, _ = ida_bytes.bin_search(
            ea,
            ida_ida.inf_get_max_ea(),
            binary_pattern,
            ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_FORWARD,
        )
        if occurence == idaapi.BADADDR:
            break
        results.append(occurence)
        ea = occurence + 1
    return results


# TODO (mr): use find_bytes
# https://github.com/mandiant/capa/issues/2339
def find_byte_sequence(start: int, end: int, seq: list[int]) -> typing.Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        start: min virtual address
        end: max virtual address
        seq: bytes to search e.g. b"\x01\x03"
    """
    patterns = ida_bytes.compiled_binpat_vec_t()

    seqstr = " ".join([f"{b:02x}" if b != -1 else "?" for b in seq])
    err = ida_bytes.parse_binpat_str(
        patterns,
        start,
        seqstr,
        16,
        ida_nalt.get_default_encoding_idx(  # use one byte-per-character encoding
            ida_nalt.BPU_1B
        ),
    )

    if err:
        return

    while True:
        ea = ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)
        # "drc_t" in IDA 9
        ea = ea[0]
        if ea == idaapi.BADADDR:
            break
        start = ea + 1
        yield ea


# def scan(pattern):
#     ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
#     print("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase()))


# def fullscan(pattern):
#     ea = 0
#     while True:
#         ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
#         if ea == idc.BADADDR:
#             break
#         print("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase()))


def get_section_by_name(seg_name) -> ida_segment.segment_t:
    """Gets a section by its name."""
    return idaapi.get_segm_by_name(seg_name)


def assemble_instruction(ea, assembly_string):
    """Assembles an instruction using IDA's built-in assembler."""
    result, assembled_bytes = idautils.Assemble(ea, assembly_string)
    if result:
        return assembled_bytes, len(assembled_bytes), None
    else:
        return (
            None,
            0,
            assembled_bytes,
        )  # assembled_bytes will contain the error message


# --- Core Decryption Logic ---


class GameClientCryptHelper:
    def __init__(self, patterns):
        self.patterns = patterns

    def get_crypt_key(self, offset=0):
        """
        Retrieves the decryption key from the binary.
        Uses IDA's segment information for calculations.
        """

        if offset != 0:
            rdata_seg = get_section_by_name(".rdata")
            if not rdata_seg:
                print("Error: .rdata section not found.")
                return bytearray()

            rdata_start = rdata_seg.start_ea
            rdata_end = rdata_seg.end_ea  # corrected to virtual addresses
            rdata_size = rdata_end - rdata_start
            # Check if the segment exists and has a valid size
            if not rdata_seg or rdata_size <= 0:
                print("Error: .rdata section not found or has invalid size.")
                return bytearray()

            # Ensure 'offset' is within the valid range of the .rdata section
            if not (rdata_start <= offset < rdata_end):
                print(
                    f"Error: Offset 0x{offset:X} is outside the .rdata section bounds."
                )
                return bytearray()

            rdata_va = rdata_seg.start_ea  # keep virtual addresses for IDA
            rdata_offset = rdata_va - (
                rdata_start - ida_loader.get_fileregion_offset(rdata_start)
            )  # corrected: use file offset

            import_table_va = idaapi.get_import_module_qty()  # not quite right

            text_seg = get_section_by_name(".text")
            if not text_seg:
                print("Error: .text section not found.")
                return bytearray()

            base_of_code_va = text_seg.start_ea

            # Ensure offset is within .rdata bounds (important for safety)
            if not (rdata_start <= offset < rdata_end):
                print(f"Error: Offset 0x{offset:X} is outside of .rdata section.")
                return bytearray()
            raise Exception("Not implemented")
            # return binary[
            #     offset
            #     - rdata_offset : (import_table_va - rdata_offset + base_of_code_va)
            #     - rdata_offset
            # ]

        for p in self.patterns.crypt_keys:

            text_seg = get_section_by_name(".text")
            for ea in find_byte_sequence(text_seg.start_ea, text_seg.end_ea, p):
                decoded_instruction: ida_ua.insn_t = idautils.DecodeInstruction(ea)

                # --- Changed: get decoded value correctly using helper function
                if decoded_instruction:
                    key = extract_decoded_key(decoded_instruction, ea)
                    if key:
                        return key
        print("No crypt key found.")
        return bytearray()

    def get_crypt_start_offsets(self):

        text_seg = get_section_by_name(".text")
        if not text_seg:
            print("Error: .text section not found.")
            yield -1, -1
            return

        text_va = text_seg.start_ea
        text_offset_diff = text_va - (
            text_seg.start_ea - ida_loader.get_fileregion_offset(text_seg.start_ea)
        )

        found_results = {}

        for p in self.patterns.start_offsets:
            for start_offset_pattern_result in find_byte_sequence(
                text_seg.start_ea, text_seg.end_ea, p
            ):
                if p[0] == 0xFF:
                    start_offset_pattern_result += 1

                load_stmt = idc.next_head(start_offset_pattern_result)

                inst: ida_ua.insn_t = idautils.DecodeInstruction(load_stmt)
                assert (
                    inst.itype == idaapi.NN_lea
                ), f"Expected load instruction at {load_stmt:X}"

                found_results[inst.Op2.addr] = start_offset_pattern_result

            # Find the entry with the largest (memoryPageOffset - startOffsetPatternResult).

        sorted_results = sorted(
            found_results.items(), key=lambda item: item[0] - item[1], reverse=True
        )  # Sort by diff

        for memory_page_offset, pattern_addr in sorted_results:
            # the maximum garbage blob offset is 0x2000 (hardcoded!)
            aligned_offset = (memory_page_offset + (2 * PAGE_SIZE)) & (
                ~(PAGE_SIZE - 1) - memory_page_offset
            )
            aligned = aligned_offset + memory_page_offset
            file_page_offset = aligned - 0xC00
            print(
                f"aligned_offset: 0x{aligned_offset:X}",
                f"memory_page_offset: {memory_page_offset:X}",
                f"pattern_addr: 0x{pattern_addr:X}",
                f"aligned: 0x{aligned:X}",
                f"file_page_offset: 0x{file_page_offset:X}",
                sep=os.linesep,
            )
            # we actually do not need to calculate the file page offset
            # because we are doing this in IDA Pro, so we can just get
            # idc.get_bytes(ea, PAGE_SIZE)
            yield memory_page_offset, aligned

    def validate(self, binary):
        """Validates the decrypted binary."""
        if not self.patterns.use_regex:
            return binary.find(self.patterns.validation) != -1
        else:
            return self.patterns.validation_regex.search(binary) is not None


def extract_decoded_key(decoded_instruction, ea):
    """
    Extracts the crypt key from the binary using information from the decoded instruction.

    Args:
        decoded_instruction (ida_ua.insn_t): The decoded instruction.
        ea (int): The effective address of the instruction.

    Returns:
        bytearray: The extracted key if successful. Returns an empty bytearray on error,
                   or None if the operand type is unexpected.
    """

    rdata_seg = get_section_by_name(".rdata")
    text_seg = get_section_by_name(".text")

    rdata_va = rdata_seg.start_ea  # use virtual address
    rdata_offset = rdata_va - (
        rdata_seg.start_ea - ida_loader.get_fileregion_offset(rdata_seg.start_ea)
    )
    text_va = text_seg.start_ea  # use virtual address
    text_offset_diff = text_va - (
        text_seg.start_ea - ida_loader.get_fileregion_offset(text_seg.start_ea)
    )
    # Check if it's a memory operand instruction before accessing memory displacement.
    if decoded_instruction.ops[0].type == ida_ua.o_reg:
        decoded_value = (
            ea
            - idaapi.get_imagebase()
            + (decoded_instruction.ops[1].addr - rdata_offset + text_offset_diff)
        )
        print(
            f"Decoded {idc.GetDisasm(ea)} from reg operand. g_bufCryptoKey is @ 0x{decoded_value:X} "
        )
    else:
        print(
            f"Warning: Expected operand instruction @ address 0x{ea:X} , but found {idc.GetDisasm(ea)}. "
            f"In particular, {decoded_instruction.get_canon_mnem()} has type = {decoded_instruction.ops[0].type}, "
            f"with operand[1] addr @ 0x{decoded_instruction.ops[1].addr:X}"
        )
        # Return None so that the caller can decide how to handle an unexpected type.
        return None

    print("decoded_instruction.ops[1].addr is 0x%x" % decoded_instruction.ops[1].addr)
    print(
        "file region offset is 0x%x"
        % idaapi.get_fileregion_offset(decoded_instruction.ops[1].addr)
    )

    # assert (
    #     idaapi.get_fileregion_offset(decoded_instruction.ops[1].addr) == decoded_value,
    #     (
    #         f"The file region offset is 0x{idaapi.get_fileregion_offset(decoded_instruction.ops[1].addr):X} and the decoded value is 0x{decoded_value:X}"
    #     ),
    # )
    rdata_offset_diff = (
        rdata_seg.start_ea
        - ida_loader.get_fileregion_offset(rdata_seg.start_ea)
        - idaapi.get_imagebase()
    )
    print("rdata_offset_diff is 0x%x" % rdata_offset_diff)

    # Extract the Import Table RVA (4 bytes at offset 0x80)
    import_table_va_bytes = PE.header()[IMPORT_TABLE_OFFSET : IMPORT_TABLE_OFFSET + 4]
    import_table_va = struct.unpack("I", import_table_va_bytes)[0]
    print("import_table_va is 0x%x" % import_table_va)
    base_of_code_va = text_seg.start_ea - idaapi.get_imagebase()
    print("base_of_code_va is 0x%x" % base_of_code_va)
    # (_peHeaders.PEHeader.ImportTableDirectory.RelativeVirtualAddress - rdataOffsetDiff + _peHeaders.PEHeader.BaseOfCode)
    # bro is this just the import table va?
    end_offset = import_table_va - rdata_offset_diff + base_of_code_va
    key_length = end_offset - idaapi.get_fileregion_offset(
        decoded_instruction.ops[1].addr
    )
    print("end_offset is 0x%x" % end_offset)
    crypto_key = bytearray(idc.get_bytes(decoded_value, key_length))
    print(
        "crypto_key of length %x (%d) found at 0x%x"
        % (len(crypto_key), key_length, decoded_value)
    )
    return crypto_key


# class GameClientCrypt:
#     def __init__(self, encrypt_mode=False):
#         self.encrypt_mode = encrypt_mode
#         self.page_hash = 0

#     def decrypt_page(self, binary, crypt_key, crypt_offset_base, start_offset, const1):
#         """Decrypts a single page."""
#         if self.encrypt_mode:
#             raise ValueError("Cannot decrypt when encryption mode is enabled.")
#         if start_offset == 0xBC8FC:
#             print(
#                 f"==>  First qword at offset 0xbc8fc: {binary[0xbc8fc : 0xbc8fc + 8].hex().lower()}"
#             )
#         first_qword = binary[start_offset : start_offset + 8]
#         print(
#             f"Bruteforce check - First qword at offset 0x{start_offset:X}: {first_qword.hex().lower()}"
#         )
#         print(f"TryFullDecrypt - size: 0x{PAGE_SIZE:X}, const1: 0x{const1:X}")
#         print(f"Processing page - cryptOffsetBase: 0x{crypt_offset_base:X}")
#         self.page_hash = crc4.decrypt_page(
#             binary,
#             crypt_key,
#             crypt_offset_base,
#             start_offset,
#             const1,
#             self.encrypt_mode,
#             self.page_hash,
#             PAGE_SIZE * 24,
#         )
#         print(f"Decrypted page hash: 0x{self.page_hash:X}")
#         # key_state = self.initialize_key_state(crypt_key, const1, crypt_offset_base)
#         # self.process(binary, start_offset, key_state)
#         # self.page_hash = fnv1a(
#         #     memoryview(binary[start_offset : start_offset + PAGE_SIZE])
#         # )
#         return False  # Consistent with original C# - always returns false.

#     def encrypt_page(self, binary, crypt_key, start_offset, const1, const2):
#         """Encrypts a single page."""
#         if not self.encrypt_mode:
#             raise ValueError("Cannot encrypt when encryption mode is disabled.")

#         crypt_offset_base = const1 * ((start_offset[1] // PAGE_SIZE) % const2)
#         key_state = self.initialize_key_state(crypt_key, const1, crypt_offset_base)
#         self.page_hash = fnv1a(
#             binary[start_offset[0] : start_offset[0] + PAGE_SIZE]
#         )  # Calculate hash *before* encryption
#         self.process(binary, start_offset, key_state)

#     def reset_state(self):
#         """Resets the internal state (page hash)."""
#         self.page_hash = 0

#     def initialize_key_state(self, crypt_key, const1, crypt_offset_base):
#         """Initializes the key state array."""
#         return crc4.initialize_key_state(
#             crypt_key, const1, crypt_offset_base, self.page_hash
#         )
#         # key_state = bytearray([0] * (const1 + 0x100))

#         # for i in range(const1):
#         #     key_state[i + 0x100] = (
#         #         crypt_key[crypt_offset_base + i]
#         #         ^ struct.pack("<Q", self.page_hash)[i & 7]
#         #     )

#         # for i in range(0x100):
#         #     key_state[i] = i

#         # prev_key_state_offset = 0
#         # for j in range(0x100):
#         #     curr_key_state = key_state[j]
#         #     prev_key_state_offset = (
#         #         prev_key_state_offset + key_state[j % const1 + 0x100] + curr_key_state
#         #     ) & 0xFF
#         #     key_state[j], key_state[prev_key_state_offset] = (
#         #         key_state[prev_key_state_offset],
#         #         key_state[j],
#         #     )

#         # return key_state

#     def process(self, binary, start_offset, key_state):
#         """Performs the core decryption/encryption process."""
#         mv_binary = memoryview(binary)
#         mv_key_state = memoryview(key_state)
#         crc4.process(mv_binary, start_offset, mv_key_state)

#         # prev_key_state_offset = 0
#         # for i in range(PAGE_SIZE):
#         #     curr_key_state_index = (i + 1) % 0x100
#         #     curr_key_state = key_state[curr_key_state_index]

#         #     binary_index = i + start_offset
#         #     if binary_index < len(binary):  # crucial bounds check!
#         #         binary[binary_index] ^= curr_key_state

#         #     prev_key_state_offset = (prev_key_state_offset + curr_key_state) & 0xFF
#         #     # Swap key states
#         #     key_state[curr_key_state_index], key_state[prev_key_state_offset] = (
#         #         key_state[prev_key_state_offset],
#         #         key_state[curr_key_state_index],
#         #     )


# # --- Decryption Logic ---
# def decrypt_with_constants(
#     crypt_engine, crypt_helper, binary, crypt_key, starting_offsets, const1, const2
# ):
#     """Attempts to decrypt with given constants. Returns True if successful."""
#     crypt_engine.reset_state()
#     decrypted_successfully = False

#     for start_offset, ending_offset in starting_offsets:
#         start_offset -= idaapi.get_imagebase()
#         ending_offset -= idaapi.get_imagebase()
#         print(
#             f"decrypting from start_offset: {start_offset:X}, ending_offset: {ending_offset:X}"
#         )
#         while start_offset < ending_offset:
#             crypt_offset_base = const1 * ((start_offset // PAGE_SIZE) % const2)
#             if crypt_offset_base + const1 >= len(crypt_key):
#                 print(
#                     f"Skipping constants {const1:X}, {const2:X} - cryptOffsetBase (0x{crypt_offset_base:X}) + i would exceed cryptKey length"
#                 )
#                 return
#             print(
#                 f"Trying constants - const1: 0x{const1:X}, const2: 0x{const2:X}, cryptOffsetBase: 0x{crypt_offset_base:X}"
#             )
#             crypt_engine.decrypt_page(
#                 binary, crypt_key, crypt_offset_base, start_offset, const1
#             )

#             start_offset += PAGE_SIZE

#         # Validate *after* attempting to decrypt the entire range
#         if crypt_helper.validate(binary):
#             # Apply changes to the main binary if successful
#             decrypted_successfully = True
#             break  # Exit loop if one offset works
#         else:
#             print(f"Validation failed for const1=0x{const1:X}, const2=0x{const2:X}")

#     if decrypted_successfully:
#         print(f"Decryption successful with const1=0x{const1:X}, const2=0x{const2:X}")
#         # --- Apply changes to IDA database ---
#         return True
#         current_offset = 0
#         for seg_ea in idautils.Segments():
#             start = seg_ea
#             end = idc.get_segm_end(seg_ea)
#             seg_size = end - start
#             idc.patch_bytes(
#                 start,
#                 bytes(local_binary[current_offset : current_offset + seg_size]),
#             )  # Apply patch in segments
#             current_offset += seg_size
#         idaapi.refresh_idaview_anyway()  # Refresh IDA view
#         return True
#     return False


# def bruteforce_decrypt(crypt_engine, crypt_helper, crypt_key, crypt_start_offsets):
#     """Attempts to brute-force crypt constants for decryption."""
#     # Load the entire binary into a bytearray.  This is necessary because we need
#     # to modify the bytes in place during decryption.
#     # IMPORTANT: We're operating on a *copy* of the binary data, not directly
#     # modifying the IDA database until we're sure the decryption is correct.
#     # NOW we load it, after we find offsets and key
#     binary = bytearray()
#     for seg_ea in idautils.Segments():
#         binary.extend(idc.get_bytes(seg_ea, idc.get_segm_end(seg_ea) - seg_ea))
#     print("Getting crypt constants...")
#     decrypted = False
#     for const1 in range(0x1FF, 0xFF, -1):  # Corrected loop bounds
#         for const2 in range(0xFF, 0xF, -1):  # Corrected loop bounds

#             if decrypt_with_constants(
#                 crypt_engine,
#                 crypt_helper,
#                 binary,
#                 crypt_key,
#                 crypt_start_offsets,
#                 const1,
#                 const2,
#             ):
#                 decrypted = True
#                 break
#         if decrypted:
#             break


#     if not decrypted:
#         print("Decryption failed: No valid constants found.")
class GameClientCrypt:
    def __init__(self, encrypt_mode=False):
        self.encrypt_mode = encrypt_mode
        self.page_hash = 0

    def decrypt_page(self, binary, crypt_key, crypt_offset_base, start_offset, const1):
        """Decrypts a single page."""
        if self.encrypt_mode:
            raise ValueError("Cannot decrypt when encryption mode is enabled.")

        # Process a single page; if you need to process multiple pages, adjust the size accordingly.
        self.page_hash = crc4.decrypt_page(
            binary,
            crypt_key,
            crypt_offset_base,
            start_offset,
            const1,
            self.encrypt_mode,
            self.page_hash,
            PAGE_SIZE,
        )
        print(f"Decrypted page hash: 0x{self.page_hash:X}")
        if start_offset == 0xBC8FC:
            print(
                f"==>  First qword at offset 0xbd000: {binary[0xbd000 : 0xbd000 + 8].hex().lower()}"
            )
            print(
                f"==>  First qword at offset 0xbc400: {binary[0xbc400 : 0xbc400 + 8].hex().lower()}"
            )
        first_qword = binary[start_offset : start_offset + 8]
        print(
            f"Bruteforce check - First qword at offset 0x{start_offset:X}: {first_qword.hex().lower()}"
        )
        print(f"TryFullDecrypt - size: 0x{PAGE_SIZE:X}, const1: 0x{const1:X}")
        print(f"Processing page - cryptOffsetBase: 0x{crypt_offset_base:X}")
        return False  # Consistent with original C# - always returns false.

    def encrypt_page(self, binary, crypt_key, start_offset, const1, const2):
        """Encrypts a single page."""
        if not self.encrypt_mode:
            raise ValueError("Cannot encrypt when encryption mode is disabled.")

        # Use start_offset directly as a single offset (no tuple)
        crypt_offset_base = const1 * ((start_offset // PAGE_SIZE) % const2)
        key_state = self.initialize_key_state(crypt_key, const1, crypt_offset_base)
        self.page_hash = fnv1a(
            binary[start_offset : start_offset + PAGE_SIZE]
        )  # Calculate hash *before* encryption
        self.process(binary, start_offset, key_state)

    def reset_state(self):
        """Resets the internal state (page hash)."""
        self.page_hash = 0

    def initialize_key_state(self, crypt_key, const1, crypt_offset_base):
        """Initializes the key state array."""
        return crc4.initialize_key_state(
            crypt_key, const1, crypt_offset_base, self.page_hash
        )

    def process(self, binary, start_offset, key_state):
        """Performs the core decryption/encryption process."""
        mv_binary = memoryview(binary)
        mv_key_state = memoryview(key_state)
        crc4.process(mv_binary, start_offset, mv_key_state)


# --- Decryption Logic ---
def decrypt_with_constants(
    crypt_engine, crypt_helper, binary, crypt_key, starting_offsets, const1, const2
):
    """Attempts to decrypt with given constants. Returns True if successful."""
    crypt_engine.reset_state()
    decrypted_successfully = False

    for start_offset, ending_offset in starting_offsets:
        # Adjust offsets if needed; here we assume start_offset and ending_offset are already proper integer offsets.
        print(
            f"decrypting from start_offset: 0x{start_offset:X}, ending_offset: 0x{ending_offset:X}"
        )
        current_offset = start_offset
        while current_offset < ending_offset:
            crypt_offset_base = const1 * ((current_offset // PAGE_SIZE) % const2)
            if crypt_offset_base + const1 >= len(crypt_key):
                print(
                    f"Skipping constants {const1:X}, {const2:X} - cryptOffsetBase (0x{crypt_offset_base:X}) + const1 would exceed cryptKey length"
                )
                current_offset += PAGE_SIZE
                continue  # Instead of aborting, skip to the next page.
            print(
                f"Trying constants - const1: 0x{const1:X}, const2: 0x{const2:X}, cryptOffsetBase: 0x{crypt_offset_base:X}"
            )
            crypt_engine.decrypt_page(
                binary, crypt_key, crypt_offset_base, current_offset, const1
            )
            current_offset += PAGE_SIZE

        # Validate *after* attempting to decrypt the entire range
        if crypt_helper.validate(binary):
            decrypted_successfully = True
            break  # Exit loop if one offset works
        else:
            print(f"Validation failed for const1=0x{const1:X}, const2=0x{const2:X}")

    if decrypted_successfully:
        print(f"Decryption successful with const1=0x{const1:X}, const2=0x{const2:X}")
        # --- Apply changes to the main binary if needed ---
        return True
    return False


def bruteforce_decrypt(crypt_engine, crypt_helper, crypt_key, crypt_start_offsets):
    """Attempts to brute-force crypt constants for decryption."""
    # Load the entire binary into a bytearray because we need to modify the bytes in place.
    binary = bytearray()
    for seg_ea in idautils.Segments():
        binary.extend(idc.get_bytes(seg_ea, idc.get_segm_end(seg_ea) - seg_ea))
    print("Getting crypt constants...")
    decrypted = False
    # Loop over const1 and const2 ranges (adjusted from C# ranges)
    for const1 in range(0x1FF, 0xFF, -1):  # 0x1FF to 0x100 inclusive
        for const2 in range(0xFF, 0xF, -1):  # 0xFF to 0x10 inclusive
            if decrypt_with_constants(
                crypt_engine,
                crypt_helper,
                binary,
                crypt_key,
                crypt_start_offsets,
                const1,
                const2,
            ):
                decrypted = True
                break
        if decrypted:
            break

    if not decrypted:
        print("Decryption failed: No valid constants found.")


# --- Main Script Logic ---


def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Decrypts WoW/Diablo client binaries.")
    parser.add_argument(
        "--game",
        choices=["wow", "diablo"],
        default="wow",
        help="The game to decrypt (default: wow).",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        default=False,
        help="Enable encryption mode (default: False).",
    )
    parser.add_argument(
        "--multi",
        action="store_true",
        help="Enable multi-offset attempts (default: False).",
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        default=True,
        help="Enable brute-force search for crypt constants (default: False).",
    )

    args = parser.parse_args(args)

    if args.encrypt:
        parser.error("Encryption mode is not yet fully supported within IDA.")

    # Make sure our header is large enough to contain the Import Directory entry.
    if not PE or len(PE.header()) < IMPORT_TABLE_OFFSET + 4:
        parser.error("PE header is too short!")

    # Determine which game we're dealing with.  Assume WoW for this example.
    game = Game.WOW if args.game == "wow" else Game.DIABLO

    if game == Game.WOW:
        patterns = WowPatterns()
    elif game == Game.DIABLO:
        patterns = DiabloPatterns()
    else:
        parser.error("Unsupported game.")

    crypt_helper = GameClientCryptHelper(patterns)
    crypt_engine = GameClientCrypt(
        encrypt_mode=args.encrypt
    )  # Set to True for encryption.

    print("Getting crypt offsets...")
    crypt_start_offsets = list(crypt_helper.get_crypt_start_offsets())
    print(
        [
            f"0x{offset_start:X} - 0x{offset_end:X}"
            for offset_start, offset_end in crypt_start_offsets
        ]
    )
    print("Getting crypt key...")
    crypt_key = crypt_helper.get_crypt_key()
    if not crypt_key:
        print("Failed to retrieve crypt key!")
        return

    # print(f"Crypt Key: {crypt_key}")

    if args.bruteforce or args.encrypt:
        bruteforce_decrypt(crypt_engine, crypt_helper, crypt_key, crypt_start_offsets)
    else:
        print("Skipping brute-force search for crypt constants.")


if __name__ == "__main__":
    clear_output()
    main()
