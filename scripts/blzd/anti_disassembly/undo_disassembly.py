import idaapi
import idautils
import idc

# Define opcodes based on typical protector behavior
JUMP_OPCODES = set(range(0x70, 0x80)) | {0xEB, 0xE9}  # Jumps (short, near, conditional)
JUNK_OPCODES = {
    0x80,
    0x81,
    0x83,
    0xC6,
    0xC7,
    0xF6,
    0xE8,
    0x68,
    0x6A,
}  # Common junk opcodes
BIG_INSTR_OPCODES = {
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
}  # Typical "big" instructions marking stub ends
MAX_STUB_SIZE = 129  # Maximum stub size in bytes
MIN_STUB_SIZE = 12  # Minimum stub size in bytes

# Register encodings for RAX (0), RCX (1), RDX (2), RBX (3), RBP (5), RSI (6), RDI (7)
REGISTER_FIELDS = [0, 1, 2, 3, 5, 6, 7]


def is_jump_instruction(ea):
    """Check if the address contains a jump instruction."""
    opcode = idc.get_bytes(ea, 1)[0]
    if opcode in JUMP_OPCODES:
        if opcode == 0x0F:  # Two-byte conditional jumps (0x0F 0x8X)
            next_byte = idc.get_bytes(ea + 1, 1)[0]
            return next_byte >= 0x80 and next_byte <= 0x8F
        return True
    return False


def get_jump_target(ea):
    """Calculate the jump target and instruction size."""
    opcode = idc.get_bytes(ea, 1)[0]
    if opcode in range(0x70, 0x80) or opcode == 0xEB:  # Short jump (2 bytes)
        offset = int.from_bytes(idc.get_bytes(ea + 1, 1), "little", signed=True)
        size = 2
        target = ea + size + offset
    elif opcode == 0xE9:  # Near jump (5 bytes)
        offset = int.from_bytes(idc.get_bytes(ea + 1, 4), "little", signed=True)
        size = 5
        target = ea + size + offset
    elif opcode == 0x0F:  # Near conditional jump (6 bytes)
        next_byte = idc.get_bytes(ea + 1, 1)[0]
        if next_byte >= 0x80 and next_byte <= 0x8F:
            offset = int.from_bytes(idc.get_bytes(ea + 2, 4), "little", signed=True)
            size = 6
            target = ea + size + offset
        else:
            return None, 0
    else:
        return None, 0
    return target, size


def is_junk_instruction(ea):
    """Check if the instruction is likely junk based on opcode and register usage."""
    opcode = idc.get_bytes(ea, 1)[0]
    if opcode in JUNK_OPCODES:
        # For opcodes with ModR/M bytes, check register usage
        if opcode in {0x80, 0x81, 0x83, 0xC6, 0xC7, 0xF6} and ea + 1 < idc.get_segm_end(
            ea
        ):
            modrm = idc.get_bytes(ea + 1, 1)[0]
            reg = (modrm >> 3) & 0x7  # Extract register field from ModR/M
            if reg in REGISTER_FIELDS:  # Matches Utils::Random::Register()
                return True
        # Simple junk instructions like PUSH imm or CALL
        elif opcode in {0x68, 0x6A, 0xE8}:
            return True
    return False


def is_junk_region(start_ea, end_ea):
    """Determine if a region is mostly junk or undefined bytes."""
    ea = start_ea
    junk_count = 0
    total_bytes = end_ea - start_ea
    while ea < end_ea:
        if idc.is_code(idc.get_full_flags(ea)):
            if is_junk_instruction(ea):
                junk_count += idc.get_item_size(ea)
        else:
            junk_count += 1  # Undefined bytes count as junk
        ea += idc.get_item_size(ea) or 1
    # Heuristic: >50% junk or undefined bytes
    return junk_count > total_bytes * 0.5


def ends_with_big_instruction(ea, region_end):
    """Check if the region ends with a big instruction."""
    last_insn_ea = idc.prev_head(region_end, ea)
    if last_insn_ea < ea or last_insn_ea >= region_end:
        return False
    opcode = idc.get_bytes(last_insn_ea, 1)[0]
    return opcode in BIG_INSTR_OPCODES


def neutralize_stub(start_ea, end_ea):
    """Replace the stub with NOPs and redefine as code."""
    length = end_ea - start_ea
    print(f"Neutralizing stub at 0x{start_ea:x} - 0x{end_ea:x} ({length} bytes)")
    for ea in range(start_ea, end_ea):
        idc.patch_byte(ea, 0x90)  # NOP
    idc.del_items(start_ea, 0, length)
    idc.create_insn(start_ea)


def neutralize_segment(seg_start, seg_end):
    print(f"Scanning segment 0x{seg_start:x} - 0x{seg_end:x}")
    patched_count = 0
    ea = seg_start
    while ea < seg_end:
        if is_jump_instruction(ea):
            target, jmp_size = get_jump_target(ea)
            if target is None or target <= ea or target > ea + MAX_STUB_SIZE:
                ea += 1
                continue
            if target - ea >= MIN_STUB_SIZE:
                if is_junk_region(ea + jmp_size, target):
                    if ends_with_big_instruction(ea, target) or is_jump_instruction(
                        target
                    ):
                        neutralize_stub(ea, target)
                        patched_count += 1
                        ea = target
                        continue
        ea += idc.get_item_size(ea) or 1
    return patched_count


def find_and_neutralize_all_segments():
    """Scan executable segments for anti-disassembly stubs and neutralize them."""
    patched_count = 0
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        seg_start = seg.start_ea
        seg_end = seg.end_ea

        patched_count += neutralize_segment(seg_start, seg_end)

    print(f"Patched {patched_count} anti-disassembly stubs.")


if __name__ == "__main__":
    idaapi.auto_wait()  # Ensure IDA analysis is complete
    text_seg = idaapi.get_segm_by_name(".text")
    patched_count = neutralize_segment(text_seg.start_ea, text_seg.end_ea)
    print(f"Patched {patched_count} anti-disassembly stubs.")
