import binascii
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

    def to_virtual_address(self, offset):
        for seg_start, seg_end in self.mem_offsets:
            if seg_start <= offset < seg_end:
                return seg_start + (offset - seg_start)
        return offset


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
    """Check if instruction at ea overlaps with the next byte's instruction"""
    insn = ida_ua.insn_t()
    len1 = ida_ua.decode_insn(insn, ea)
    if len1:
        next_ea = ea + 1
        len2 = ida_ua.decode_insn(insn, next_ea)
        if len2 and next_ea + len2 > ea + len1:
            print(f"Overlap detected @ 0x{ea:X} -> 0x{next_ea:X}")
            return True
    return False


def count_overlaps(start_ea, end_ea):
    """Count number of overlapping instructions in a range"""
    overlap_count = 0
    for ea in range(start_ea, end_ea):
        if check_overlap(ea):
            overlap_count += 1
    return overlap_count


def is_big_instruction(ea):
    """Check if the instruction at ea matches known big instruction patterns"""
    if ea is None:
        return False, None

    opcode = ida_bytes.get_byte(ea)

    # Single byte big instructions
    big_single = [
        0xC8,
        0x05,
        0x0D,
        0x15,
        0x1D,
        0x25,
        0x2D,
        0x35,
        0x3D,
        0x68,
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0xA9,
        0xB8,
        0xB9,
        0xBA,
        0xBB,
        0xBC,
        0xBD,
        0xBE,
        0xBF,
        0xE8,
        0xE9,
        0x69,
        0x81,
        0xC7,
        0xF7,
    ]

    if opcode in big_single:
        return True, f"Big Instruction (1 byte): {idc.generate_disasm_line(ea, 0)}"

    # 2-3 byte instructions with ModR/M byte
    big_med = [
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0x00,
        0x01,
        0x02,
        0x03,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x20,
        0x21,
        0x22,
        0x23,
        0x28,
        0x29,
        0x2A,
        0x2B,
        0x30,
        0x31,
        0x32,
        0x33,
        0x38,
        0x39,
        0x3A,
        0x3B,
        0x84,
        0x85,
        0x86,
        0x87,
        0x88,
        0x89,
        0x8A,
        0x8B,
        0x8C,
        0x8D,
        0x8E,
        0x8F,
        0x6B,
        0x80,
        0x83,
        0xF6,
    ]

    if opcode in big_med:
        # Check if there's a ModR/M byte and it's in the correct range
        if ida_bytes.get_byte(ea + 1) >= 0x80 and ida_bytes.get_byte(ea + 1) <= 0xBF:
            return (
                True,
                f"Big Instruction (2-3 bytes): {idc.generate_disasm_line(ea, 0)}",
            )

    # 4-6 byte instructions with ModR/M byte
    big_big = [0x69, 0x81, 0x6B, 0x80, 0x83, 0xC0, 0xC1, 0xF6]

    if opcode in big_big:
        # Check if there's a ModR/M byte and it's in the correct range
        if ida_bytes.get_byte(ea + 1) >= 0x80 and ida_bytes.get_byte(ea + 1) <= 0xBF:
            return (
                True,
                f"Big Instruction (4-6 bytes): {idc.generate_disasm_line(ea, 0)}",
            )

    # REX prefix for x64
    if is_x64() and opcode >= 0x48 and opcode <= 0x4F:
        return True, f"REX Prefix (x64): {idc.generate_disasm_line(ea, 0)}"

    return False, None


def find_junk_sequences(mem_data, start_addr, end_addr):
    """Find potential junk instruction sequences"""
    # JunkRegOps patterns (small instructions)
    junk_reg_ops = [
        rb"\x80[\xc0-\xc7].",  # ADD/OR/ADC/SBB/AND/SUB/XOR/CMP reg, imm8
        rb"\x81[\xc0-\xc7]....",  # ADD/OR/ADC/SBB/AND/SUB/XOR/CMP reg, imm32
        rb"\x83[\xc0-\xc7].",  # ADD/OR/ADC/SBB/AND/SUB/XOR/CMP reg, imm8 (sign-extended)
        rb"\xc6[\xc0-\xc7].",  # MOV reg, imm8
        rb"\xc7[\xc0-\xc7]....",  # MOV reg, imm32
        rb"\xf6[\xd8-\xdf]",  # NEG reg
        rb"\x80[\xe8-\xef].",  # SUB reg, imm8
        rb"\x81[\xe8-\xef]....",  # SUB reg, imm32
    ]

    # Common junk patterns
    common_junk = [
        rb"\x0F\x31",  # RDTSC
        rb"\x68....",  # PUSH Imm32
        rb"\x6A.",  # PUSH Imm8
        rb"[\x50-\x57]",  # PUSH Reg
        rb"[\x58-\x5F]",  # POP Reg
        rb"[\x70-\x7F].",  # Conditional JMP Short
        rb"\xEB.",  # JMP Short
        rb"\xE8....",  # CALL Relative
        rb"\x0F[\x94-\x9F][\xC0-\xFF]",  # SETcc reg
        rb"\x0F[\x80-\x8F]....",  # Jcc near
        rb"\x86[\xC0-\xFF]",  # XCHG reg, reg
        rb"\x8A[\xC0-\xFF]",  # MOV reg, reg
    ]

    # Find all matches for junk patterns
    junk_matches = []
    for pattern_list in [junk_reg_ops, common_junk]:
        for pattern in pattern_list:
            for m in re.finditer(pattern, mem_data, re.DOTALL):
                addr = start_addr + m.start()
                size = m.end() - m.start()
                junk_matches.append((addr, size))

    # Sort matches by address
    junk_matches.sort()

    # Cluster matches that are close together
    junk_clusters = []
    current_cluster = []

    for addr, size in junk_matches:
        if not current_cluster:
            current_cluster = [(addr, size)]
        elif (
            addr - (current_cluster[-1][0] + current_cluster[-1][1]) <= 3
        ):  # Allow small gaps
            current_cluster.append((addr, size))
        else:
            if len(current_cluster) >= 3:  # Require at least 3 junk instructions
                junk_clusters.append(current_cluster)
            current_cluster = [(addr, size)]

    if current_cluster and len(current_cluster) >= 3:
        junk_clusters.append(current_cluster)

    return junk_clusters


class PatchOperation:
    """Class to store patch operations that will be applied later."""

    def __init__(self, address, byte_values):
        self.address = address
        self.byte_values = byte_values

    def apply(self):
        """Apply the patch operation."""
        ida_bytes.patch_bytes(self.address, self.byte_values)
        print(
            f"Applied patch at 0x{self.address:x} with value {self.byte_values.hex()[:16]}{'...' if len(self.byte_values) > 16 else ''}"
        )


def find_anti_disassembly_stubs(ea, end_ea):
    """Find anti-disassembly stubs using heuristic detection"""
    MIN_BUFFER_SIZE = 12
    MAX_BUFFER_SIZE = 129

    print(f"Searching for anti-disassembly stubs from 0x{ea:X} to 0x{end_ea:X}")

    # Get memory for analysis
    mem = MemHelper(ea, end_ea)

    # Find clusters of junk instructions
    junk_clusters = find_junk_sequences(mem.mem_results, ea, end_ea)

    if not junk_clusters:
        print("No suspicious junk instruction sequences found.")
        return

    print(f"Found {len(junk_clusters)} potential junk instruction clusters")

    # Analyze each cluster to see if it's an anti-disassembly stub
    stubs = []

    for i, cluster in enumerate(junk_clusters):
        cluster_start = cluster[0][0]
        cluster_end = cluster[-1][0] + cluster[-1][1]
        cluster_size = cluster_end - cluster_start

        # Skip if too small or too large
        if cluster_size < MIN_BUFFER_SIZE or cluster_size > MAX_BUFFER_SIZE:
            continue

        # Check if there are overlapping instructions in this cluster
        overlap_count = count_overlaps(cluster_start, cluster_end)

        # Check if there are big instructions at the end (last 6 bytes)
        has_big_at_end = False
        big_instr_addr = None

        # Scan the last 6 bytes for big instructions
        for offset in range(6):
            if cluster_end - offset - 1 < cluster_start:
                break

            test_addr = cluster_end - offset - 1
            is_big, desc = is_big_instruction(test_addr)

            if is_big:
                has_big_at_end = True
                big_instr_addr = test_addr
                break

        # Count jumps in the cluster
        jumps = []
        for j in range(cluster_start, cluster_end):
            target = analyze_jump(j)
            if target is not None:
                jumps.append((j, target))

        # Check if any jumps target within the cluster or back to the beginning
        has_internal_jumps = False
        for jump_addr, target in jumps:
            if cluster_start <= target < cluster_end:
                has_internal_jumps = True
                break

        # For a stub to be valid, it should:
        # 1. Be the right size (12-129 bytes)
        # 2. Have overlapping instructions (likely anti-disassembly)
        # 3. Have big instructions at the end (last 6 bytes)
        # 4. Optionally have internal jumps (misdirection)

        score = 0
        if MIN_BUFFER_SIZE <= cluster_size <= MAX_BUFFER_SIZE:
            score += 1
        if overlap_count > 0:
            score += 2  # Strong indicator
        if has_big_at_end:
            score += 3  # Very strong indicator
        if has_internal_jumps:
            score += 1

        # Consider it a stub if score is high enough
        if score >= 3:  # At least some key indicators
            stubs.append(
                {
                    "start": cluster_start,
                    "end": cluster_end,
                    "size": cluster_end - cluster_start,
                    "overlaps": overlap_count,
                    "has_big_at_end": has_big_at_end,
                    "big_instr_addr": big_instr_addr,
                    "internal_jumps": has_internal_jumps,
                    "jumps": jumps,
                    "score": score,
                }
            )

    # Report findings
    if not stubs:
        print("No anti-disassembly stubs found.")
        return

    print(f"\nFound {len(stubs)} potential anti-disassembly stubs:")
    patch_operations = []
    for i, stub in enumerate(stubs):
        print(
            f"\n[{i+1}] Stub @ 0x{stub['start']:X} - 0x{stub['end']:X} ({stub['size']} bytes) - Score: {stub['score']}"
        )

        print(f"  Overlapping instructions: {stub['overlaps']}")

        if stub["has_big_at_end"]:
            is_big, desc = is_big_instruction(stub["big_instr_addr"])
            print(
                f"  Big instruction at end: Yes @ 0x{stub['big_instr_addr']:X} - {desc}"
            )
        else:
            print("  Big instruction at end: No")

        if stub["internal_jumps"]:
            print("  Contains internal jumps (misdirection):")
            for jump_addr, target in stub["jumps"]:
                if stub["start"] <= target < stub["end"]:
                    print(f"    Jump @ 0x{jump_addr:X} to 0x{target:X} (internal)")

        # Check if any jumps before the stub could be skipping it
        found_skip = False
        for j in range(max(ea, stub["start"] - 10), stub["start"]):
            target = analyze_jump(j)
            if target and target > stub["end"]:
                print(f"  Jumped over by instruction @ 0x{j:X} to 0x{target:X}")
                found_skip = True
                break

        # Show disassembly of the stub
        print("  Disassembly:")
        current_ea = stub["start"]
        while current_ea < stub["end"]:
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, current_ea)
            if size == 0:
                # If we can't decode, try next byte
                current_ea += 1
                continue

            # Get disassembly and check if it's an interesting instruction
            disasm = idc.generate_disasm_line(current_ea, 0)

            # Check if this is a jump
            is_jump = False
            for jump_addr, target in stub["jumps"]:
                if jump_addr == current_ea:
                    is_jump = True
                    break

            # Check if this is a big instruction at the end
            is_big_end = stub["has_big_at_end"] and current_ea == stub["big_instr_addr"]

            # Add indicators for special instructions
            prefix = "    "
            if is_jump:
                prefix = "    [JMP] "
            elif is_big_end:
                prefix = "    [END] "
            elif check_overlap(current_ea):
                prefix = "    [OVR] "

            print(f"{prefix}0x{current_ea:X}: {disasm}")
            current_ea += size

        # Provide patching recommendation
        print("\n  Recommendation:")
        print(
            f"    This appears to be an anti-disassembly stub that can likely be safely patched"
        )
        print(
            f"    ida_bytes.patch_bytes(0x{stub['start']:X}, b'\\x90' * {stub['size']})  # Replace with NOPs"
        )
        patch_operations.append(PatchOperation(stub["start"], b"\x90" * stub["size"]))

    for patch_operation in patch_operations:
        patch_operation.apply()


def main():
    print("Starting Anti-Disassembly Stub Finder (Heuristic Method)...")
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)

    if func:
        start_ea = func.start_ea
        end_ea = func.end_ea
        find_anti_disassembly_stubs(start_ea, end_ea)
    else:
        # If no function, search a reasonable range around current address
        search_range = 1024  # 1KB in each direction
        find_anti_disassembly_stubs(ea - search_range, ea + search_range)

    print("\nSearch completed.")


if __name__ == "__main__":
    main()
