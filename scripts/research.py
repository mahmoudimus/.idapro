import re
import typing

import ida_allins
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_search
import idaapi
import idautils
import idc


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


class _MemHelper:
    def __init__(self):
        self.mem_results = b""
        self.mem_offsets = []
        if not self.mem_results:
            self._get_memory()

    def _get_memory(self):
        result = b""
        segments_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segments_starts:
            end = idc.get_segm_end(start)
            result += idc.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        self.mem_results = result
        self.mem_offsets = offsets

    def to_virtual_address(self, offset):
        va_offset = 0
        for seg in self.mem_offsets:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset


class MemHelper:
    def __init__(self, start: int, end: int):
        self.mem_results = b""
        self.mem_offsets = []
        if not self.mem_results:
            self._get_memory(start, end)

    def _get_memory(self, start: int, end: int):
        result = b""
        offsets = []
        result = idc.get_bytes(start, end - start)
        offsets.append((start, end))
        self.mem_results = result
        self.mem_offsets = offsets

    def to_virtual_address(self, offset):
        va_offset = 0
        for seg in self.mem_offsets:
            if seg[0] <= offset < seg[1]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset


def find_junk_instructions(ea, end_ea):

    # JunkRegOps patterns with register values 0, 1, 2, 3, 5, 6, 7 added to RegOp
    junk_reg_ops = [
        # 0x80, 0xC0, 1 - ADD reg, imm8 (0xC0 + [0,1,2,3,5,6,7] = C0,C1,C2,C3,C5,C6,C7)
        b"\x80[\xc0-\xc3\xc5-\xc7]",
        # 0x81, 0xC0, 4 - ADD reg, imm32
        b"\x81[\xc0-\xc3\xc5-\xc7][\x00-\xff]{4}",
        # 0x83, 0xC0, 1 - ADD reg, imm8
        b"\x83[\xc0-\xc3\xc5-\xc7]",
        # 0xC6, 0xC0, 1 - MOV reg, imm8
        b"\xc6[\xc0-\xc3\xc5-\xc7]",
        # 0xC7, 0xC0, 4 - MOV reg, imm32
        b"\xc7[\xc0-\xc3\xc5-\xc7][\x00-\xff]{4}",
        # 0xF6, 0xD8, 0 - NEG reg (0xD8 + [0,1,2,3,5,6,7] = D8,D9,DA,DB,DD,DE,DF)
        b"\xf6[\xd8-\xdb\xdd-\xdf]",
        # 0x80, 0xE8, 1 - AND reg, imm8 (0xE8 + [0,1,2,3,5,6,7] = E8,E9,EA,EB,ED,EE,EF)
        b"\x80[\xe8-\xeb\xed-\xef]",
        # 0x81, 0xE8, 4 - AND reg, imm32
        b"\x81[\xe8-\xeb\xed-\xef][\x00-\xff]{4}",
    ]

    # Define patterns based on your C++ code and constants
    patterns = [
        # 1. JunkRegOps (0-57): Using specific opcodes from JunkRegOps array
        (junk_reg_ops, "JunkRegOp"),
        # 2. TwoByte0F31 (58-60): 0F 31
        (rb"\x0F\x31", "RDTSC"),
        # 3. PushImm32 (61-62): 68 xx xx xx xx
        (rb"\x68[\x00-\xFF]{4}", "PUSH Imm32"),
        # 4. PushImm8 (63-65): 6A xx
        (rb"\x6A[\x00-\xFF]", "PUSH Imm8"),
        # 5. Random80_95 (66-75): 80-95 single byte
        (rb"[\x80-\x95]", "Random 80-95"),
        # 6. Random112_127 (76-80): 112-127 + random byte
        (rb"[\x70-\x7F][\x00-\xFF]", "Random 112-127"),
        # 7. TwoByte0F (81-90): 0F 80-8F + 2 bytes + 0/1 + 00
        (rb"\x0F[\x80-\x8F][\x00-\xFF]{2}[\x00\x01]\x00", "TwoByte Conditional Jump"),
        # 8. CallRel (91-99): E8 xx xx + 0/1 + 00
        (rb"\xE8[\x00-\xFF]{2}[\x00\x01]\x00", "Call Relative"),
    ]

    print("Searching for junk instructions from 0x{:X} to 0x{:X}".format(ea, end_ea))

    mem = MemHelper(ea, end_ea)

    for pattern_group, desc in patterns:
        if not isinstance(pattern_group, list):
            pattern_group = [pattern_group]
        print(f"\nLooking for {desc} patterns:")
        for pattern in pattern_group:
            match = re.finditer(pattern, mem.mem_results)
            if not match:
                continue
            for m in match:
                found = ea + m.start()
                if idc.get_item_head(found) != found:
                    # this is a partial match, skip it
                    continue
                insn_len = ida_bytes.get_item_size(found)
                if insn_len == 0:
                    insn_len = m.end() - m.start()
                print(
                    f"{desc} @ 0x{found:X} - {ida_bytes.get_bytes(found, insn_len).hex()[:16]}{'...' if insn_len > 16 else ''}"
                )


def main():
    print("Starting junk instruction finder...")
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        start_ea = func.start_ea
        end_ea = func.end_ea
        find_junk_instructions(start_ea, end_ea)
    print("\nSearch completed.")


if __name__ == "__main__":
    main()
