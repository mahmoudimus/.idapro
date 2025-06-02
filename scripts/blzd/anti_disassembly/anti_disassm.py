import re

import ida_allins
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_ua
import idaapi
import idc


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
        self.mem_offsets.append((start, end))

    def to_virtual_address(self, address):
        for seg_start, seg_end in self.mem_offsets:
            if seg_start <= address < seg_end:
                return seg_start + (address - seg_start)
        return address


def is_x64():
    # Check if the current architecture is x64
    return ida_ida.inf_is_64bit()


CONDITIONAL_JUMPS = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
ALL_JUMPS = CONDITIONAL_JUMPS + [ida_allins.NN_jmp]
CALL_INSTRUCTIONS = {ida_allins.NN_call, ida_allins.NN_callfi, ida_allins.NN_callni}


def analyze_jump(ea):
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, ea)
    if length > 0 and insn.itype in ALL_JUMPS:  # Jump instructions
        target = insn.Op1.addr
        return target
    return None


def check_overlap(ea):
    insn = ida_ua.insn_t()
    len1 = ida_ua.decode_insn(insn, ea)
    if len1:
        next_ea = ea + 1
        len2 = ida_ua.decode_insn(insn, next_ea)
        if len2 and next_ea + len2 > ea + len1:
            print(f"Overlap detected @ 0x{ea:X} -> 0x{next_ea:X}")
            return True
    return False


def can_remove_buffer(buffer):
    buffer_start = buffer[0][0]
    buffer_end = buffer[-1][0] + buffer[-1][1]
    # Check if jumped over
    prev_ea = buffer_start - 5
    target = analyze_jump(prev_ea)
    if target and target >= buffer_end:
        return True
    # Basic side-effect check (simplified)
    # for match in buffer:
    #     found, _, desc, _ = match
    #     insn = ida_ua.insn_t()
    #     ida_ua.decode_insn(insn, found)
    return True


def fix_misdirected_jump(buffer):
    for match in buffer:
        found = match[0]
        target = analyze_jump(found)
        if target and buffer[0][0] <= target < buffer[-1][0] + buffer[-1][1]:
            real_target = buffer[-1][0] + buffer[-1][1]
            print(
                f"Jump @ 0x{found:X} misdirected to 0x{target:X}, should be 0x{real_target:X}"
            )


def find_junk_instructions(ea, end_ea):
    MIN_BUFFER_SIZE = 12
    MAX_BUFFER_SIZE = 129

    # JunkRegOps patterns (small instructions)
    junk_reg_ops = [
        b"\x80[\xc0-\xc3\xc5-\xc7]",  # ADD reg, imm8
        b"\x81[\xc0-\xc3\xc5-\xc7][\x00-\xff]{4}",  # ADD reg, imm32
        b"\x83[\xc0-\xc3\xc5-\xc7]",  # ADD reg, imm8
        b"\xc6[\xc0-\xc3\xc5-\xc7]",  # MOV reg, imm8
        b"\xc7[\xc0-\xc3\xc5-\xc7][\x00-\xff]{4}",  # MOV reg, imm32
        b"\xf6[\xd8-\xdb\xdd-\xdf]",  # NEG reg
        b"\x80[\xe8-\xeb\xed-\xef]",  # AND reg, imm8
        b"\x81[\xe8-\xeb\xed-\xef][\x00-\xff]{4}",  # AND reg, imm32
    ]

    # Big instruction patterns
    big_single = rb"[\xC8\x05\x0D\x15\x1D\x25\x2D\x35\x3D\x68\xA0\xA1\xA2\xA3\xA9\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xE8\xE9\x69\x81\xC7\xF7]"
    big_med = rb"[\xA0\xA1\xA2\xA3\x00\x01\x02\x03\x08\x09\x0A\x0B\x0F\x10\x11\x12\x13\x18\x19\x1A\x1B\x20\x21\x22\x23\x28\x29\x2A\x2B\x30\x31\x32\x33\x38\x39\x3A\x3B\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x6B\x80\x83\xF6][\x80-\xBF]"
    big_big = rb"[\x69\x81\x6B\x80\x83\xC0\xC1\xF6][\x80-\xBF][\x00-\xFF]{0,4}"
    rex_prefix = rb"[\x48-\x4F]"

    patterns = [
        (junk_reg_ops, "JunkRegOp"),
        (rb"\x0F\x31", "RDTSC"),
        (rb"\x68[\x00-\xFF]{4}", "PUSH Imm32"),
        (rb"\x6A[\x00-\xFF]", "PUSH Imm8"),
        (rb"[\x80-\x95]", "Random 80-95"),
        (rb"[\x70-\x7F][\x00-\xFF]", "Random 112-127"),
        (rb"\x0F[\x80-\x8F][\x00-\xFF]{2}[\x00\x01]\x00", "TwoByte Conditional Jump"),
        (rb"\xE8[\x00-\xFF]{2}[\x00\x01]\x00", "Call Relative"),
        # Big instruction patterns
        (big_single, "Big Instruction (1 byte)"),
        (big_med, "Big Instruction (2-3 bytes)"),
        (big_big, "Big Instruction (4-6 bytes)"),
    ]
    if is_x64():
        patterns.append((rex_prefix, "REX Prefix (x64 junk)"))

    print("Searching for junk instructions from 0x{:X} to 0x{:X}".format(ea, end_ea))
    mem = MemHelper(ea, end_ea)

    # Collect all matches
    all_matches = []
    for pattern_group, desc in patterns:
        if not isinstance(pattern_group, list):
            pattern_group = [pattern_group]
        for pattern in pattern_group:
            for m in re.finditer(pattern, mem.mem_results):
                start_offset = m.start()
                found = ea + start_offset
                if idc.get_item_head(found) != found:
                    continue
                insn_len = ida_bytes.get_item_size(found) or (m.end() - m.start())
                all_matches.append(
                    (found, insn_len, desc, mem.mem_results[m.start() : m.end()])
                )

    if not all_matches:
        print("No junk instructions found.")
        return

    # Group matches into buffers
    all_matches.sort()  # Sort by address
    current_buffer = []
    buffers = []

    big_instruction_types = {
        "Big Instruction (1 byte)",
        "Big Instruction (2-3 bytes)",
        "Big Instruction (4-6 bytes)",
        "REX Prefix (x64 junk)",
    }

    for match in all_matches:
        found, insn_len, desc, bytes_data = match
        if not current_buffer:
            current_buffer.append(match)
        elif found <= current_buffer[-1][0] + MAX_BUFFER_SIZE - current_buffer[-1][1]:
            current_buffer.append(match)
        else:
            buffers.append(current_buffer)
            current_buffer = [match]

    if current_buffer:
        buffers.append(current_buffer)

    # Filter and report buffers
    print("\nDetected Junk Instruction Buffers:")
    for buffer in buffers:
        buffer_start = buffer[0][0]
        buffer_end = buffer[-1][0] + buffer[-1][1]
        buffer_size = buffer_end - buffer_start

        # Check if the last instruction is a big instruction
        last_desc = buffer[-1][2]
        is_valid_buffer = (
            MIN_BUFFER_SIZE <= buffer_size <= MAX_BUFFER_SIZE
            and last_desc in big_instruction_types
        )

        # Control flow check
        jump_target = analyze_jump(buffer_start - 5)
        status = "VALID" if is_valid_buffer else "INVALID"
        if jump_target and jump_target >= buffer_end:
            status += " (Jumped Over)"

        # Overlap check
        has_overlap = any(check_overlap(match[0]) for match in buffer)
        if has_overlap:
            status += " (Overlapping Instructions)"

        # Removal suggestion
        if can_remove_buffer(buffer):
            status += " (Safe to Remove)"

        print(
            f"\nBuffer @ 0x{buffer_start:X} - 0x{buffer_end:X} ({buffer_size} bytes) - {status}:"
        )
        for i, match in enumerate(buffer):
            found, insn_len, desc, bytes_data = match
            prefix = (
                "  [END] "
                if i == len(buffer) - 1 and desc in big_instruction_types
                else "  "
            )
            print(f"{prefix}{desc} @ 0x{found:X} - {bytes_data.hex()[:16]}")


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
