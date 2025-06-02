import argparse
import binascii
import builtins
import json
import logging
import os
import pathlib
import re
import struct
import sys
import time
import typing
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

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
from mutilz.logconf import EveryNFilter, configure_debug_logging, dprint

logger = logging.getLogger(__name__)

print = dprint(builtins.print, every_n=500)

PAGE_SIZE = 0x1000  # 4 KB pages

PE = idautils.peutils_t()
IMPORT_TABLE_OFFSET = 0x80


def get_pe_header_bytes_from_header_segment() -> bytes:
    """
    Retrieves the entire PE header bytes from the header segment.
    Assumes that the header segment starts at the imagebase.
    """
    imagebase = idaapi.get_imagebase()
    header_seg = ida_segment.getseg(imagebase)
    if not header_seg:
        print("No segment found at the imagebase (0x{:X})".format(imagebase))
        return b""
    header_start = header_seg.start_ea
    header_end = header_seg.end_ea
    header_size = header_end - header_start
    header_bytes = idc.get_bytes(header_start, header_size)
    if not header_bytes:
        print(
            "Failed to get header bytes from segment! (0x{:X}-0x{:X})".format(
                header_start, header_end
            )
        )
        return b""
    return header_bytes


def get_section_sizeofrawdata_from_header_seg(section_name: str) -> int:
    """
    Returns the SizeOfRawData for the specified section name by parsing the PE header
    retrieved from the header segment.

    Parameters:
        section_name (str): Name of the section (e.g. ".text")

    Returns:
        int: The SizeOfRawData for the section or 0 if not found.
    """
    header_bytes = get_pe_header_bytes_from_header_segment()
    if not header_bytes:
        return 0

    # Read e_lfanew from the DOS header at offset 0x3C.
    e_lfanew = struct.unpack_from("<I", header_bytes, 0x3C)[0]
    # Verify the PE signature ("PE\0\0")
    if header_bytes[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        print("Invalid PE header signature in header segment")
        return 0

    # IMAGE_FILE_HEADER follows immediately after the 4-byte PE signature.
    file_header_offset = e_lfanew + 4
    # NumberOfSections is at offset 2 in IMAGE_FILE_HEADER (2 bytes)
    num_sections = struct.unpack_from("<H", header_bytes, file_header_offset + 2)[0]
    # SizeOfOptionalHeader is at offset 16 of IMAGE_FILE_HEADER.
    size_of_optional_header = struct.unpack_from(
        "<H", header_bytes, file_header_offset + 16
    )[0]

    # Section headers follow after IMAGE_FILE_HEADER (20 bytes) and the Optional Header.
    section_headers_offset = file_header_offset + 20 + size_of_optional_header

    for i in range(num_sections):
        sect_offset = (
            section_headers_offset + i * 40
        )  # each section header is 40 bytes.
        sect_name_bytes = header_bytes[sect_offset : sect_offset + 8]
        # Section names are null-terminated.
        sect_name_str = sect_name_bytes.split(b"\0")[0].decode("utf-8", errors="ignore")
        if sect_name_str == section_name:
            # SizeOfRawData is a 4-byte value at offset 16 in the section header.
            size_of_rawdata = struct.unpack_from("<I", header_bytes, sect_offset + 16)[
                0
            ]
            return size_of_rawdata

    print(f"Section {section_name} not found in the header segment")
    return 0


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
                [0x00, 0x48, 0x8D, -1, -1, -1,       0x0A, 0x00, 0x48, 0x8D],
                [0xFF, 0xFF, 0x48, 0x8D, -1, -1, -1, 0x0A, 0x00, 0x48, 0x8D],
                [0x00, 0x4C, 0x8D, -1, -1, -1,       0x0A, 0x00, 0x48],
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


def extract_decoded_key(decoded_instruction: ida_ua.insn_t, ea: int) -> bytearray:
    """
    Extracts the crypt key from the binary using information from the decoded instruction.

    Args:
        decoded_instruction (ida_ua.insn_t): The decoded instruction.
        ea (int): The effective address of the instruction.

    Returns:
        bytearray: The extracted key if successful. Returns an empty bytearray on error,
                   or None if the operand type is unexpected.
    """

    # Check if it's a memory operand instruction before accessing memory displacement.
    if decoded_instruction.ops[0].type == ida_ua.o_reg:
        crypto_key_ea = decoded_instruction.ops[1].addr
        print(
            f"Decoded {idc.GetDisasm(ea)} from reg operand. g_bufCryptoKey is @ 0x{crypto_key_ea:X} "
        )
    else:
        print(
            f"Warning: Expected operand instruction @ address 0x{ea:X} , but found {idc.GetDisasm(ea)}. "
            f"In particular, {decoded_instruction.get_canon_mnem()} has type = {decoded_instruction.ops[0].type}, "
            f"with operand[1] addr @ 0x{decoded_instruction.ops[1].addr:X}"
        )
        # Return None so that the caller can decide how to handle an unexpected type.
        sys.exit(1)

    print("crypto_key_ea is 0x%x" % crypto_key_ea)
    print("file region offset is 0x%x" % idaapi.get_fileregion_offset(crypto_key_ea))

    text_seg = idaapi.get_segm_by_name(".text")
    rdata_seg = idaapi.get_segm_by_name(".rdata")
    rdata_offset_diff = (
        rdata_seg.start_ea
        - ida_loader.get_fileregion_offset(rdata_seg.start_ea)
        - idaapi.get_imagebase()
    )
    print("rdata_offset_diff is 0x%x" % rdata_offset_diff)

    # Extract the Import Table RVA (4 bytes at offset 0x80)
    import_table_va_bytes = PE.header()[IMPORT_TABLE_OFFSET : IMPORT_TABLE_OFFSET + 4]
    import_table_va = struct.unpack("I", import_table_va_bytes)[0]
    # import_table_va = PE_PARSER.pe_header.import_table_rva
    print("import_table_va is @ 0x%x" % import_table_va)
    base_of_code_va = text_seg.start_ea - idaapi.get_imagebase()
    print("base_of_code_va is 0x%x" % base_of_code_va)
    # (_peHeaders.PEHeader.ImportTableDirectory.RelativeVirtualAddress - rdataOffsetDiff + _peHeaders.PEHeader.BaseOfCode)
    # bro is this just the import table va?
    end_offset = import_table_va - rdata_offset_diff + base_of_code_va
    key_length = end_offset - idaapi.get_fileregion_offset(crypto_key_ea)
    print("end_offset is 0x%x" % end_offset)
    crypto_key = bytearray(idc.get_bytes(crypto_key_ea, key_length))
    print(
        "crypto_key of length %x (%d) found at 0x%x"
        % (len(crypto_key), key_length, crypto_key_ea)
    )
    return crypto_key


class KeyExtractor:
    def __init__(self, patterns: Patterns):
        self.patterns = patterns

    def find_crypt_key(self) -> tuple[bytearray, int]:
        """
        Searches the .text segment for known byte patterns.
        For each match, decode the instruction and attempt to extract the key.
        Returns the first successful key found or an empty bytearray otherwise.
        """
        text_seg = idaapi.get_segm_by_name(".text")
        if not text_seg:
            print("[!] No .text segment found!")
            return bytearray(), idaapi.BADADDR

        for p in self.patterns.crypt_keys:
            # Look for each pattern 'p' in .text
            for ea in find_byte_sequence(text_seg.start_ea, text_seg.end_ea, p):
                print(
                    f"Found crypt key pattern at 0x{ea:X} (file region offset: 0x{idaapi.get_fileregion_offset(ea):X})"
                )
                decoded_instruction = idautils.DecodeInstruction(ea)
                if decoded_instruction:
                    key = extract_decoded_key(decoded_instruction, ea)
                    if key:
                        print(f"[+] Found crypt key at 0x{ea:X}: {key[:16].hex()}")
                        return key, ea
        print("[!] No crypt key found.")
        return bytearray(), idaapi.BADADDR


def get_garbage_blobs():
    """
    Yields pairs of (garbage_blog_ea, aligned)
    """
    text_seg = idaapi.get_segm_by_name(".text")
    if not text_seg:
        print("Error: .text section not found.")
        return
    for xref in idautils.XrefsTo(text_seg.start_ea):
        ea = xref.frm
        if idc.get_segm_name(ea) != ".text":
            continue

        if idc.GetMnem(ea) == "lea":
            yield ea


def get_aligned_offset(memory_page_offset: int) -> int:
    # the maximum garbage blob offset is 0x2000 (hardcoded!)
    aligned_offset = (memory_page_offset + (2 * PAGE_SIZE)) & (
        ~(PAGE_SIZE - 1) - memory_page_offset
    )
    # aligned = aligned_offset + memory_page_offset
    aligned = (memory_page_offset + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1)
    print(
        f"aligned_offset: 0x{aligned_offset:X}",
        f"aligned: 0x{aligned:X}",
        sep=os.linesep,
    )
    return aligned


class OffsetExtractor:
    def __init__(self, patterns: Patterns):
        self.patterns = patterns

    def get_crypt_start_offsets(self):
        """
        Scans the .text segment for known patterns that indicate crypt start offsets.
        For each pattern match, it decodes the next instruction (expected to be LEA)
        and extracts the operand address (memory_page_offset). Then does some
        alignment math and yields (memory_page_offset, aligned).

        This function is a generator: it yields pairs instead of returning a list.
        """
        text_seg = idaapi.get_segm_by_name(".text")
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
                print(f"pattern: {p} found at {start_offset_pattern_result:X}")
                load_stmt = idc.next_head(start_offset_pattern_result)

                inst: ida_ua.insn_t = idautils.DecodeInstruction(load_stmt)
                if inst.itype != idaapi.NN_lea:
                    print(f"Expected load instruction at {load_stmt:X}")
                    continue

                found_results[inst.Op2.addr] = start_offset_pattern_result

            # Find the entry with the largest (memoryPageOffset - startOffsetPatternResult).

        sorted_results = sorted(
            found_results.items(), key=lambda item: item[0] - item[1], reverse=True
        )  # Sort by diff

        for garbage_blog_ea, pattern_addr in sorted_results:
            # the garbage blobs are minimum 0x1000 to maximum 0x2000 (hardcoded!)
            # so we align the garbage blog ea to the nearest multiple of 0x1000
            aligned = get_aligned_offset(garbage_blog_ea)
            # file_page_offset = aligned - 0xC00
            print(
                f"garbage_blog_ea: 0x{garbage_blog_ea:X}",
                f"pattern_addr: {pattern_addr:X}",
                f"aligned: 0x{aligned:X}",
                sep=os.linesep,
            )
            # we actually do not need to calculate the file page offset
            # because we are doing this in IDA Pro, so we can just get
            # idc.get_bytes(ea, PAGE_SIZE)
            yield aligned
            # yield file_page_offset, aligned

    def validate(self, binary):
        """Validates the decrypted binary."""
        if not self.patterns.use_regex:
            return binary.find(self.patterns.validation) != -1
        else:
            return self.patterns.validation_regex.search(binary) is not None


def decrypt_page(
    binary,
    crypt_key,
    crypt_offset_base: int,
    start_offset: int,
    key_length: int,
    encrypt_mode: bool,
    page_hash: int,
    page_size: int,
) -> int:
    """
    Decrypt a page of data in-place.

    :param binary:      A memoryview (or bytearray) of the data buffer.
    :param crypt_key:   A memoryview (or bytes) containing key data.
    :param crypt_offset_base: Base offset into crypt_key.
    :param start_offset:  MemoryOffset.
    :param key_length:   The length of the key.
    :param encrypt_mode: Must be False for decryption; otherwise, an error is raised.
    :param page_hash:    The current 64-bit page hash.
    """
    key_state = crc4.initialize_key_state(
        crypt_key, key_length, crypt_offset_base, page_hash
    )
    crc4.process(binary, start_offset, key_state, page_size)
    # Update and return the page hash (assuming fnv1a returns a 64-bit integer).
    new_page_hash = cyfnv1a.fnv1a_hash(
        memoryview(binary[start_offset : start_offset + page_size])
    )
    return new_page_hash


def validate_brute_force_page(
    ea: int, end_ea: int, key_length: int, num_keys: int, crypt_key: bytes
) -> bool:
    """
    Validates a decrypted page using a brute force check based on the first qword within the page.

    If the first 8 bytes (qword) of the page are zero, it will validate the remaining pages in the
    text segment by computing a cryptographic offset base for each page. If the computed offset exceeds
    the decryption key length, the validation fails.

    Parameters:
        ea (int): The effective address where the current page begins.
        data (bytes): The bytes from the newly decrypted page.
        key_length (int): The length of the key.
        num_keys (int): The number of keys.
        crypt_key (bytes): The decryption key used for further validation.

    Returns:
        bool: True if the page (and subsequent pages, when needed) are validated successfully;
              False if validation fails.
    """

    print("Found zero qword, validating remaining pages until 0x%x" % end_ea)

    # Loop through pages from the current effective address until the end of the .text section.
    while ea < end_ea:
        page_index = ea // PAGE_SIZE
        key_index = key_length * (page_index % num_keys)
        # print(
        #     f"Validating page at offset 0x{ea:X}, key_index: 0x{key_index:X}"
        # )
        if key_index + key_length >= len(crypt_key):
            print(
                "Validation failed - key_index + key_length would exceed cryptKey length"
            )
            return False
        ea += PAGE_SIZE

    print("All pages validated successfully")
    return True


def try_full_decrypt(
    crypt_key: bytes,
    encrypted_page_address: int,
    size: int,
    full_size: int,
    key_length: int,
    num_keys: int,
    brute_force_check: bool,
    dry_run: bool = False,
) -> bool:
    """
    :param crypt_key:        The key bytes
    :param start_ea:         Where to begin in IDA
    :param size:             How many bytes to process (24 pages? full size?)
    :param const1, const2:   The two brute-forced constants
    :param brute_force_check If True, we do partial checks (the "bf" logic)
    :return: True if we found data that passes the "zero QWORD" or other check
             (and thus might be a correct guess).
    """
    ea = encrypted_page_address - idaapi.get_imagebase()
    end_ea = ea + size
    if size != full_size:
        dbg_str = "Partial"
    else:
        dbg_str = "Full"
    print(
        f"{dbg_str} size decrypt from rva {ea:X} to {end_ea:X} (0x{encrypted_page_address:X} - 0x{encrypted_page_address + size:X})"
    )

    page_hash = 0
    for ea in range(ea, end_ea + PAGE_SIZE, PAGE_SIZE):
        # Derive key_index for this page
        page_index = ea // PAGE_SIZE
        key_index = key_length * (page_index % num_keys)

        # Check we won't read outside crypt_key
        if key_index + key_length >= len(crypt_key):
            print(f"key_index + key_length would exceed cryptKey length @ EA {ea:X}")
            return False

        # Decrypt 4 KB in place
        data = bytearray(idc.get_bytes(ea + idaapi.get_imagebase(), PAGE_SIZE))
        # print(f"encrypted data: {data[:16].hex()}")
        if not data:
            print(f"Failed to read data from EA {ea:X}")
            return False

        encrypted_data = data[:16].hex()

        page_hash = decrypt_page(
            # no need to use start_offset here because we've fetched the data
            # already from IDA from the ea with PAGE_SIZE length.
            data,
            crypt_key,
            key_index,
            0,
            key_length,
            False,
            page_hash,
            PAGE_SIZE,
        )
        # print(f"Decrypted page hash: 0x{page_hash:X}")
        # If we're brute-forcing, check the first QWORD for 0
        if brute_force_check:
            # read first 8 bytes from the newly decrypted page
            if len(data) >= 8:
                first_qword = struct.unpack_from("<Q", data, 0)[0]
            else:
                first_qword = 0

            # print(f"  BF check @ EA {ea:X}, first_qword=0x{first_qword:X}")
            if first_qword == 0:
                return validate_brute_force_page(
                    ea, (ea + full_size), key_length, num_keys, crypt_key
                )
        else:
            if dry_run:
                func = builtins.print if ea + PAGE_SIZE >= end_ea else print
                func(
                    f"Dry run: decrypted page at 0x{ea + idaapi.get_imagebase():X} with current page hash 0x{page_hash:X}",
                    f"Dry run: encrypted data: {encrypted_data}",
                    f"Dry run: decrypted data: {data[:16].hex(sep='-').upper()}",
                    sep=os.linesep,
                )
            else:
                # patch the decrypted data in place
                idaapi.put_bytes(ea + idaapi.get_imagebase(), bytes(data))

    return False


# ---------------------------------------------------------------------------
# The main "DecryptSingleOffset" logic from C#:
# We try (const1, const2) ranges, do partial decrypt, then if it looks good,
# we do a full decrypt + final validation.
# ---------------------------------------------------------------------------
def decrypt_single_ea(
    crypt_key: bytes,
    encrypted_page_address: int,
    offset_extractor: OffsetExtractor,
    full_size: int,
    partial_pages: int = 24,  # mimic "pageSize * 24"
    dry_run: bool = False,
) -> bool:
    """
    Equivalent to the second Decrypt(...) method in C#.
    We'll do a partial decrypt of 'partial_pages' pages,
    then if it looks good, do a full decrypt and validate.
    """
    print(f"Starting decryption of partial pages @ 0x{encrypted_page_address:X}")

    partial_size = PAGE_SIZE * partial_pages

    # We'll do the big brute force over const1/const2:
    print("Getting crypt constants...")
    print("  Searching key_length range: 512 down to 256")
    print("  Searching num_keys range: 200 down to 30")

    KEY_LENGTH_RANGE = range(512, 256 - 1, -1)
    NUM_KEYS_RANGE = range(200, 30 - 1, -1)
    KEY_LENGTH_RANGE = range(0x169, 0x192, -1)
    NUM_KEYS_RANGE = range(0x5a, 0x9A, -1)
    for key_length in KEY_LENGTH_RANGE:
        for num_keys in NUM_KEYS_RANGE:
            # But let's see if it even fits in crypt_key:
            page_index = (encrypted_page_address - idaapi.get_imagebase()) // PAGE_SIZE
            key_index = key_length * (page_index % num_keys)
            if key_index + key_length >= len(crypt_key):
                # skip early
                # this matches your "Skipping constants..."
                continue

            print(
                f"Trying key_length=0x{key_length:X}, num_keys=0x{num_keys:X}, key_index=0x{key_index:X}"
            )

            if try_full_decrypt(
                crypt_key,
                encrypted_page_address,
                partial_size,
                full_size,
                key_length,
                num_keys,
                brute_force_check=True,
                dry_run=dry_run,
            ):
                print(
                    f"  Found potential key dimensions: key_length={key_length}, num_keys={num_keys}"
                )
                print("  Attempting full decryption...")

                # Full decrypt
                try_full_decrypt(
                    crypt_key,
                    encrypted_page_address,
                    full_size,
                    full_size,
                    key_length,
                    num_keys,
                    brute_force_check=False,
                    dry_run=dry_run,
                )
                if dry_run:
                    return key_length, num_keys
                idaapi.auto_make_code(encrypted_page_address)
                idaapi.plan_and_wait(encrypted_page_address, full_size)
                # try to fix IDA function re-analyze issue after patching
                idaapi.refresh_idaview_anyway()
                idaapi.auto_wait()
                # Validate
                # read the newly decrypted data
                data = idc.get_bytes(encrypted_page_address, full_size)
                if not data:
                    continue
                print("  Validating decrypted data...")
                if offset_extractor.validate(data):
                    print("  Validation success!")
                    return key_length, num_keys
                else:
                    print("  Validation failed, continuing search...")

    print("Decryption failed :(")
    return None, None


# ---------------------------------------------------------------------------
# The main "Decrypt" logic from C# that tries multiple starting EAs.
# ---------------------------------------------------------------------------
def _decrypt(
    crypt_key: bytes,
    decryption_addresses: list[int],
    offset_extractor: OffsetExtractor,
    dry_run: bool,
) -> bool:
    size_of_text_seg = get_section_sizeofrawdata_from_header_seg(".text")
    print(f"ending offset of .text segment: 0x{size_of_text_seg:X}")
    for address in decryption_addresses:
        print(f"Decrypting from 0x{address:X}")
        key_length, num_keys = decrypt_single_ea(
            crypt_key,
            address,
            offset_extractor,
            size_of_text_seg - (address - idaapi.get_imagebase()),
            dry_run=dry_run,
        )
        if key_length and num_keys:
            return key_length, num_keys
    return None, None


# --- Main Script Logic ---


class DecryptException(Exception):
    pass


def execute(decrypt=False, dry_run=False):
    # Make sure our header is large enough to contain the Import Directory entry.
    if not PE or len(PE.header()) < IMPORT_TABLE_OFFSET + 4:
        raise DecryptException("PE header is too short!")

    patterns = WowPatterns()
    extractor = KeyExtractor(patterns)
    crypt_key, _key_addr = extractor.find_crypt_key()
    if crypt_key:
        print(
            f"[*] Key found: {crypt_key[:16].hex()}... with initial size of {len(crypt_key)}"
        )
    else:
        print("[!] No key extracted")
        return -1
    offset_extractor = OffsetExtractor(patterns)
    start_decryption_offsets = list(offset_extractor.get_crypt_start_offsets())
    if not start_decryption_offsets:
        print("[!] No offsets found")
        return -1
    print(f"[*] Found {len(start_decryption_offsets)} offsets")

    if decrypt:
        key_length, num_keys = _decrypt(
            crypt_key, start_decryption_offsets, offset_extractor, dry_run
        )
        if key_length and num_keys:
            print(
                f"Decryption succeeded! key located @ 0x{_key_addr:X} with num_keys={num_keys} and key_length={key_length}"
            )
            dump_key(key_num_keys=num_keys, key_length=key_length, key_offset=_key_addr)
        else:
            print("Decryption did not succeed.")
    else:
        size_of_text_seg = get_section_sizeofrawdata_from_header_seg(".text")
        print(f"ending offset of .text segment: 0x{size_of_text_seg:X}")


def dump_key(
    key_num_keys: int,
    key_length: int,
    key_offset: int = None,
    output_file: pathlib.Path = None,
):
    if key_offset is None:
        patterns = WowPatterns()
        extractor = KeyExtractor(patterns)
        crypt_key, key_offset = extractor.find_crypt_key()
        if crypt_key:
            print(f"[*] Key found: 0x{key_offset:X}")
        else:
            print("[!] No key extracted")
            return -1
    if output_file is None:
        input_path = pathlib.Path(idc.get_input_file_path())
        output_file = input_path.with_name("g_bufCryptKey.json")
    print(f"Dumping key to {output_file}")

    # Get the complete binary blob of keys.
    crypt_key = idc.get_bytes(key_offset, key_length * key_num_keys)
    if crypt_key is None:
        print("Failed to retrieve key bytes!")
        return

    # Create a 2D array: each key chunk is an array of bytes.
    keys = [
        list(crypt_key[i * key_length : (i + 1) * key_length])
        for i in range(key_num_keys)
    ]

    # Construct JSON data according to the schema.
    json_data = {
        "encryption_key": keys,
        "key_length": key_length,
        "num_keys": key_num_keys,
        "key_offset": f"0x{key_offset:X}",
    }

    # Write the JSON to the file.
    with output_file.open("w+") as f:
        json.dump(json_data, f, indent=4)


def cli(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Decrypt a binary file.")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the binary")
    parser.add_argument("--dry-run", action="store_true", help="Dry run the decryption")
    args = parser.parse_args()
    execute(decrypt=args.decrypt, dry_run=args.dry_run)


if __name__ == "__main__":
    clear_output()
    configure_debug_logging(log=logger)
    execute(decrypt=True, dry_run=False)
    # dump_key(key_num_keys=0x9B, key_length=0x193)
