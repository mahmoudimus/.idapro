"""
Aegis Anti-Disassembly Unpatcher

This script identifies and removes Aegis anti-disassembly protections.
It works by detecting patterns characteristic of the protection, analyzing
the instruction flow, and patching the binary to restore proper disassembly.
"""

import logging
import struct
import time
from collections import defaultdict, deque

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_segment
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

logger = logging.getLogger("aegis_unpatcher")

# # Set up logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# )
# logger = logging.getLogger('aegis_unpatcher')

# # Enable file logging
# file_handler = logging.FileHandler('aegis_unpatcher.log')
# file_handler.setLevel(logging.DEBUG)
# logger.addHandler(file_handler)

# Constants derived from Aegis protection
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

# Mapping of jump opcodes to their conditional jump types
JUMP_OPCODES = {
    0x70: "jo",
    0x71: "jno",
    0x72: "jb",
    0x73: "jnb",
    0x74: "je",
    0x75: "jne",
    0x76: "jbe",
    0x77: "ja",
    0x78: "js",
    0x79: "jns",
    0x7A: "jp",
    0x7B: "jnp",
    0x7C: "jl",
    0x7D: "jge",
    0x7E: "jle",
    0x7F: "jg",
    0xEB: "jmp",
}

# Jump pairs from x86.hpp
JUMP_PAIRS = [
    [0x70, 0x71],
    [0x72, 0x73],
    [0x74, 0x75],
    [0x76, 0x77],
    [0x78, 0x79],
    [0x7A, 0x7B],
    [0x7C, 0x7D],
    [0x7E, 0x7F],
]

# Junk register operations from x86.hpp
JUNK_REG_OPS = [
    [0x80, 0xC0, 1],
    [0x81, 0xC0, 4],
    [0x83, 0xC0, 1],
    [0xC6, 0xC0, 1],
    [0xC7, 0xC0, 4],
    [0xF6, 0xD8, 0],
    [0x80, 0xE8, 1],
    [0x81, 0xE8, 4],
]

# No-effect byte operations
BYTE_OPS_CLEAR_CFOF = [
    # AND with FF (no effect)
    {"al_specific": 0x24, "generic_opcode": [0x80, 0xE0], "no_effect_value": 0xFF},
    # OR with 0 (no effect)
    {"al_specific": 0x0C, "generic_opcode": [0x80, 0xC8], "no_effect_value": 0x00},
    # XOR with 0 (no effect)
    {"al_specific": 0x34, "generic_opcode": [0x80, 0xF0], "no_effect_value": 0x00},
]

# NOP patterns from 1 to 11 bytes
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

# Track discovered and processed addresses
discovered_addresses = set()
patched_addresses = set()


def read_bytes(addr, size):
    """Read bytes from the binary."""
    return bytearray(ida_bytes.get_bytes(addr, size))


def patch_byte(addr, value):
    """Patch a byte in the binary and record the action."""
    if addr not in patched_addresses:
        original_byte = ida_bytes.get_byte(addr)
        logger.debug(
            f"Patching byte at 0x{addr:X}: 0x{original_byte:02X} -> 0x{value:02X}"
        )
        ida_bytes.patch_byte(addr, value)
        patched_addresses.add(addr)
    else:
        logger.debug(f"Address 0x{addr:X} already patched, skipping.")


def is_nop(addr):
    """
    Check if the instruction at addr is a NOP.
    Returns the length of the NOP if found, 0 otherwise.
    """
    for pattern_length, pattern in enumerate(NOP_PATTERNS, 1):
        # Check if we have enough bytes for this pattern
        bytes_at_addr = read_bytes(addr, len(pattern))
        if bytes_at_addr[: len(pattern)] == bytes(pattern):
            return pattern_length
    return 0


def is_junk_instruction(addr):
    """
    Check if the instruction at addr is likely junk.
    Returns True if it's a junk instruction, False otherwise.
    """
    # Check for FLAG operations followed by conditional jumps
    if ida_bytes.get_byte(addr) in [0xF8, 0xF9]:  # CLD, STD
        next_byte = ida_bytes.get_byte(addr + 1)
        if 0x70 <= next_byte <= 0x7F:  # Conditional jumps
            return True

    # Check for no-effect byte operations
    for op in BYTE_OPS_CLEAR_CFOF:
        # Check AL-specific opcode
        if ida_bytes.get_byte(addr) == op["al_specific"]:
            next_byte = ida_bytes.get_byte(addr + 1)
            if next_byte == op["no_effect_value"]:
                return True

        # Check generic opcode
        if ida_bytes.get_byte(addr) == op["generic_opcode"][0]:
            next_byte = ida_bytes.get_byte(addr + 1)
            if (next_byte & 0xF8) == op["generic_opcode"][1] and ida_bytes.get_byte(
                addr + 2
            ) == op["no_effect_value"]:
                return True

    # Check for known junk register operations
    for op in JUNK_REG_OPS:
        if ida_bytes.get_byte(addr) == op[0]:
            next_byte = ida_bytes.get_byte(addr + 1)
            if (next_byte & 0xF8) == op[1]:  # Checking register bits
                return True

    return False


def evaluate_jump(addr):
    """
    Evaluate a jump instruction at addr.
    Returns (jump_target, jump_size) or (None, 0) if not a jump.
    Based on EvaluateJump_X64 in the source code.
    """
    first_byte = ida_bytes.get_byte(addr)

    # Short conditional jumps (0x70-0x7F) or short JMP (0xEB)
    if (0x70 <= first_byte <= 0x7F) or first_byte == 0xEB:
        # 2-byte instruction: opcode (1 byte) + relative offset (1 byte)
        offset = ida_bytes.get_byte(addr + 1)
        if offset > 127:  # Treat as signed byte
            offset -= 256
        size = 2
        dest = addr + size + offset
        return dest, size

    # Near JMP (0xE9)
    elif first_byte == 0xE9:
        # 5-byte instruction: opcode (1 byte) + relative offset (4 bytes)
        offset_bytes = read_bytes(addr + 1, 4)
        offset = struct.unpack("<i", bytes(offset_bytes))[0]  # Treat as signed int
        size = 5
        dest = addr + size + offset
        return dest, size

    # Near conditional jumps (0x0F 0x80-0x8F)
    elif first_byte == 0x0F and 0x80 <= ida_bytes.get_byte(addr + 1) <= 0x8F:
        # 6-byte instruction: opcode (2 bytes) + relative offset (4 bytes)
        offset_bytes = read_bytes(addr + 2, 4)
        offset = struct.unpack("<i", bytes(offset_bytes))[0]  # Treat as signed int
        size = 6
        dest = addr + size + offset
        return dest, size

    return None, 0


def is_correct_jump_destination(jump_dest, expected_dest):
    """
    Check if jump_dest is a valid jump destination relative to expected_dest.
    Based on IsCorrectJumpDestination in the source code.
    """
    # Case 1: Direct match
    if jump_dest == expected_dest:
        return True

    # Case 2: Check if jump_dest points to a NOP that leads to expected_dest
    nop_len = is_nop(jump_dest)
    if nop_len > 0 and jump_dest + nop_len == expected_dest:
        return True

    # Case 3: No match
    return False


def find_opaque_predicates(func_addr):
    """
    Find opaque predicates in the function at func_addr.
    Returns a list of addresses where opaque predicates were found.
    """
    opaque_predicates = []

    # Get function boundaries
    func = ida_funcs.get_func(func_addr)
    if not func:
        logger.warning(f"No function at 0x{func_addr:X}")
        return opaque_predicates

    func_start = func.start_ea
    func_end = func.end_ea

    # Iterate through all instructions in the function
    addr = func_start
    while addr < func_end:
        insn = idaapi.insn_t()
        insn_size = ida_ua.decode_insn(insn, addr)
        if insn_size == 0:
            addr = idc.next_head(addr)
            if addr == idc.BADADDR:
                break
            continue

        # Look for conditional jumps
        if insn.itype >= idaapi.NN_ja and insn.itype <= idaapi.NN_jz:
            # Get jump target
            target = insn.Op1.addr

            # Check if this is an opaque predicate
            # 1. Look for complementary jumps nearby
            for offset in range(1, 20):
                next_addr = addr + offset
                if next_addr >= func_end:
                    break

                next_insn = idaapi.insn_t()
                next_size = ida_ua.decode_insn(next_insn, next_addr)
                if next_size == 0:
                    continue

                # Check if the next instruction is a conditional jump
                if next_insn.itype >= idaapi.NN_ja and next_insn.itype <= idaapi.NN_jz:
                    next_target = next_insn.Op1.addr

                    # Check for complementary pair (both can't be true)
                    try:
                        if (
                            idc.print_insn_mnem(addr)
                            == CONDITIONAL_JUMPS[
                                CONDITIONAL_JUMPS.index(idc.print_insn_mnem(next_addr))
                                ^ 1
                            ]
                        ):
                            opaque_predicates.append((addr, next_addr))
                            break
                    except (IndexError, ValueError) as e:
                        logger.info(f"Error: {e} @ 0x{addr:X}, skipping")

            # 2. Look for unconditional jumps to nearby addresses
            if target - addr < 32 and target > addr:
                # Check if there's an instruction overlap
                heads_in_range = list(idautils.Heads(addr, target))
                if len(heads_in_range) > 1 and heads_in_range[-1] < target:
                    opaque_predicates.append(addr)

        addr = idc.next_head(addr)
        if addr == idc.BADADDR:
            break

    return opaque_predicates


def analyze_anti_disasm_chunk(addr, max_size=129):
    """
    Analyze a potential anti-disassembly chunk starting at addr.
    Returns (is_anti_disasm, chunk_size, fix_info) where:
    - is_anti_disasm: True if this is an anti-disassembly chunk
    - chunk_size: Size of the anti-disassembly chunk
    - fix_info: Information needed to fix the chunk
    """
    # Check if the chunk is within valid size range (24-129 bytes)
    chunk_bytes = read_bytes(addr, max_size)

    # Look for key anti-disassembly patterns
    jumps = []
    junk_instructions = []
    nops = []

    # Analyze instructions within the chunk
    current_addr = addr
    end_addr = addr + max_size

    while current_addr < end_addr:
        # Check for jumps
        jump_dest, jump_size = evaluate_jump(current_addr)
        if jump_size > 0:
            jumps.append((current_addr, jump_dest, jump_size))
            current_addr += jump_size
            continue

        # Check for NOPs
        nop_size = is_nop(current_addr)
        if nop_size > 0:
            nops.append((current_addr, nop_size))
            current_addr += nop_size
            continue

        # Check for junk instructions
        if is_junk_instruction(current_addr):
            # Get instruction size
            insn = idaapi.insn_t()
            insn_size = ida_ua.decode_insn(insn, current_addr)
            if insn_size > 0:
                junk_instructions.append((current_addr, insn_size))
                current_addr += insn_size
                continue

        # Default: move to next byte
        current_addr += 1

    # Analyze the jump pattern
    circular_jumps = []
    for i, (jump_addr, jump_dest, jump_size) in enumerate(jumps):
        # Look for jumps that target within this chunk
        if addr <= jump_dest < end_addr:
            # Check for circular jumps (those that target earlier addresses)
            if jump_dest < jump_addr:
                circular_jumps.append((jump_addr, jump_dest))

            # Check for jumps that target other jumps
            for j, (other_addr, other_dest, _) in enumerate(jumps):
                if i != j and jump_dest == other_addr:
                    # Found a jump chain
                    circular_jumps.append((jump_addr, other_addr))

    # Determine if this is likely an anti-disassembly chunk
    is_anti_disasm = False
    if len(jumps) >= 2 and (len(junk_instructions) > 0 or len(circular_jumps) > 0):
        is_anti_disasm = True

    # Prepare fix information
    fix_info = {
        "jumps": jumps,
        "circular_jumps": circular_jumps,
        "junk_instructions": junk_instructions,
        "nops": nops,
    }

    # Calculate chunk size (distance from start to last significant instruction)
    significant_addrs = (
        [j[0] + j[2] for j in jumps]
        + [j[0] + j[1] for j in junk_instructions]
        + [n[0] + n[1] for n in nops]
    )
    chunk_size = max(significant_addrs) - addr if significant_addrs else 0

    return is_anti_disasm, chunk_size, fix_info


def fix_anti_disasm_chunk(addr, fix_info):
    """
    Fix an anti-disassembly chunk starting at addr using the provided fix_info.
    Returns True if the chunk was fixed, False otherwise.
    """
    # Handle circular jumps first
    for jump_addr, jump_dest in fix_info["circular_jumps"]:
        # Convert conditional jumps to unconditional ones if they form circular patterns
        first_byte = ida_bytes.get_byte(jump_addr)
        if 0x70 <= first_byte <= 0x7F:  # Conditional jump
            # Replace with unconditional jump (JMP)
            patch_byte(jump_addr, 0xEB)
            logger.info(
                f"Fixed circular jump at 0x{jump_addr:X} (conditional → unconditional)"
            )

    # Handle jump chains
    jump_targets = {}
    for jump_addr, jump_dest, jump_size in fix_info["jumps"]:
        # If a jump targets another jump, analyze the chain
        chain_found = False
        current = jump_dest
        visited = {jump_addr}

        while current:
            if current in visited:
                # Circular reference - break the chain
                chain_found = True
                break

            visited.add(current)
            found_jump = False

            for j_addr, j_dest, j_size in fix_info["jumps"]:
                if j_addr == current:
                    current = j_dest
                    found_jump = True
                    break

            if not found_jump:
                # End of chain
                break

        if chain_found:
            # Convert the initial jump to point directly to the final destination
            if current not in jump_targets:
                # Find a valid exit point for the chain
                for j_addr, j_dest, j_size in fix_info["jumps"]:
                    if j_addr in visited and not (addr <= j_dest < addr + 129):
                        # This jump goes outside the chunk - use it as exit
                        jump_targets[jump_addr] = j_dest
                        break
                else:
                    # No external jump found - use the last address in the chain
                    jump_targets[jump_addr] = current

    # Apply jump target fixes
    for jump_addr, new_target in jump_targets.items():
        # Get current jump information
        old_target, jump_size = evaluate_jump(jump_addr)
        if old_target == new_target:
            continue

        # Calculate the new offset
        offset = new_target - (jump_addr + jump_size)

        # Check if we can use a short jump
        if -128 <= offset <= 127:
            # Short jump - patch the offset byte
            patch_byte(jump_addr, 0xEB)  # Unconditional JMP
            patch_byte(jump_addr + 1, offset & 0xFF)
            logger.info(
                f"Fixed jump chain at 0x{jump_addr:X} to point to 0x{new_target:X}"
            )
        else:
            # Need a near jump (5 bytes)
            # First NOP out the old instruction
            for i in range(jump_size):
                patch_byte(jump_addr + i, 0x90)  # NOP

            # Then place a near jump if there's room
            if jump_size >= 5:
                patch_byte(jump_addr, 0xE9)  # Near JMP
                # Write the 4-byte offset
                offset = new_target - (jump_addr + 5)
                offset_bytes = struct.pack("<i", offset)
                for i, b in enumerate(offset_bytes):
                    patch_byte(jump_addr + 1 + i, b)

    # NOP out junk instructions
    for junk_addr, junk_size in fix_info["junk_instructions"]:
        for i in range(junk_size):
            patch_byte(junk_addr + i, 0x90)  # NOP
        logger.info(
            f"NOPed out junk instruction at 0x{junk_addr:X} ({junk_size} bytes)"
        )

    return True


def fix_function_flow(func_addr):
    """
    Find and fix all anti-disassembly patterns in the function at func_addr.
    Returns the number of fixed patterns.
    """
    fixed_count = 0

    # Get function boundaries
    func = ida_funcs.get_func(func_addr)
    if not func:
        logger.warning(f"No function at 0x{func_addr:X}")
        return fixed_count

    func_start = func.start_ea
    func_end = func.end_ea

    # Mark as already processed
    discovered_addresses.add(func_addr)

    # Find opaque predicates first
    opaque_predicates = find_opaque_predicates(func_addr)
    for op_addr in opaque_predicates:
        # If it's a pair, we need to handle it specially
        if isinstance(op_addr, tuple):
            addr1, addr2 = op_addr
            # Keep the first jump, convert the second to NOP
            insn = idaapi.insn_t()
            insn_size = ida_ua.decode_insn(insn, addr2)
            for i in range(insn_size):
                patch_byte(addr2 + i, 0x90)  # NOP
            logger.info(
                f"Fixed complementary jumps: kept 0x{addr1:X}, NOPed 0x{addr2:X}"
            )
        else:
            # Convert to unconditional jump
            patch_byte(op_addr, 0xEB)
            logger.info(
                f"Fixed opaque predicate at 0x{op_addr:X} (conditional → unconditional)"
            )
        fixed_count += 1

    # Scan for anti-disassembly chunks
    addr = func_start
    while addr < func_end:
        # Skip if already processed
        if addr in discovered_addresses:
            addr = idc.next_head(addr)
            if addr == idc.BADADDR:
                break
            continue

        # Analyze this chunk
        is_anti_disasm, chunk_size, fix_info = analyze_anti_disasm_chunk(addr)

        if is_anti_disasm:
            # Fix the anti-disassembly chunk
            if fix_anti_disasm_chunk(addr, fix_info):
                fixed_count += 1
                logger.info(
                    f"Fixed anti-disassembly chunk at 0x{addr:X} ({chunk_size} bytes)"
                )

            # Mark chunk as processed
            for i in range(chunk_size):
                discovered_addresses.add(addr + i)

            # Move to next chunk
            addr += chunk_size
        else:
            # Move to next instruction
            discovered_addresses.add(addr)
            addr = idc.next_head(addr)
            if addr == idc.BADADDR:
                break

    return fixed_count


def create_anti_junk_pattern_scanners():
    """Create pattern scanners for junk assembly patterns used in anti-disassembly."""
    patterns = [
        # F8/F9 (CLD/STD) followed by conditional jumps
        (b"\xf8[\x70-\x7f]", "CLD + conditional jump"),
        (b"\xf9[\x70-\x7f]", "STD + conditional jump"),
        # No-effect byte operations
        (b"\x24\xff", "AND AL, 0xFF (no effect)"),
        (b"\x0c\x00", "OR AL, 0 (no effect)"),
        (b"\x34\x00", "XOR AL, 0 (no effect)"),
        # Generic register ops with no effect
        (b"\x80[\xe0-\xe7]\xff", "AND reg, 0xFF (no effect)"),
        (b"\x80[\xc8-\xcf]\x00", "OR reg, 0 (no effect)"),
        (b"\x80[\xf0-\xf7]\x00", "XOR reg, 0 (no effect)"),
    ]

    return patterns


def convert_pattern_to_ida(pattern_str):
    """Convert a regex-like pattern string to IDA binary search pattern."""
    result = ""
    i = 0
    while i < len(pattern_str):
        if pattern_str[i] == "[" and "]" in pattern_str[i:]:
            end = pattern_str.index("]", i)
            range_str = pattern_str[i + 1 : end]
            if "-" in range_str:
                start, end = range_str.split("-")
                result += f" {int.from_bytes(start, 'big'):02X} ? "
            else:
                # List of alternatives
                result += " ? "
            i = end + 1
        else:
            result += f" {pattern_str[i]:02X}"
            i += 1
    return result.strip()


def _bin_search(start, end, pattern):
    patterns = ida_bytes.compiled_binpat_vec_t()
    seqstr = pattern
    # try:
    #     seqstr = " ".join([f"{b:02x}" if b != -1 else "?" for b in pattern])
    # except ValueError:
    #     seqstr = pattern
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
        return idaapi.BADADDR

    return ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)


def scan_for_anti_disasm_patterns(start_ea=None, end_ea=None):
    """
    Scan the entire binary for anti-disassembly patterns.
    Returns a list of potential anti-disassembly addresses.
    """
    potential_addresses = []

    # Get the text segment
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        logger.error("Could not find .text segment")
        return potential_addresses

    # Create pattern scanners
    patterns = create_anti_junk_pattern_scanners()
    start_ea = start_ea or text_seg.start_ea
    end_ea = end_ea or text_seg.end_ea

    # Scan for each pattern
    for pattern_bytes, pattern_name in patterns:
        # Convert pattern to IDA format
        ida_pattern = convert_pattern_to_ida(pattern_bytes)

        # Search for pattern
        ea = start_ea
        while ea != idc.BADADDR and ea < end_ea:
            ea, _ = _bin_search(ea, end_ea, ida_pattern)
            if ea == idc.BADADDR:
                break

            # Check if this could be an anti-disassembly chunk
            is_anti_disasm, chunk_size, _ = analyze_anti_disasm_chunk(
                ea - 20, 150
            )  # Look a bit before the pattern
            if is_anti_disasm:
                potential_addresses.append(ea - 20)
                logger.info(
                    f"Found potential anti-disassembly at 0x{ea-20:X} matching '{pattern_name}'"
                )
                ea += chunk_size
            else:
                ea += 1

    return potential_addresses


def identify_extra_validations(start_ea=None, end_ea=None):
    """
    Identify potential ExtraValidation sections based on Aegis patterns.
    Returns a list of addresses that might have validation code.
    """
    validations = []

    # Get the .text segment
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        logger.error("Could not find .text segment")
        return validations

    start_ea = start_ea or text_seg.start_ea
    end_ea = end_ea or text_seg.end_ea

    # Scan all functions
    for func_ea in idautils.Functions(start_ea, end_ea):
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Check each instruction in the function
        addr = func.start_ea
        while addr < func.end_ea:
            # Check if this is a potential validation pattern
            # Look for ADD-SUBS-B.NE pattern as seen in GetEndSignatureSize_ARM64
            insn = idaapi.insn_t()
            insn_size = ida_ua.decode_insn(insn, addr)
            if insn_size == 0:
                addr = idc.next_head(addr)
                continue

            # Check for ADD pattern
            if insn.itype == idaapi.NN_add and idc.print_operand(addr, 1) == "SP":
                # Look ahead for SUBS
                next_addr = idc.next_head(addr)
                if next_addr == idc.BADADDR:
                    addr = next_addr
                    continue

                next_insn = idaapi.insn_t()
                next_size = ida_ua.decode_insn(next_insn, next_addr)
                if next_size == 0:
                    addr = next_addr
                    continue

                if (
                    next_insn.itype == idaapi.NN_sub
                    and "SUBS" in idc.print_insn_mnem(next_addr).upper()
                ):
                    # Check if operands match
                    if idc.print_operand(next_addr, 0) == idc.print_operand(
                        next_addr, 1
                    ) and idc.print_operand(next_addr, 0) == idc.print_operand(addr, 0):
                        # Look ahead for B.NE
                        bnot_addr = idc.next_head(next_addr)
                        if bnot_addr == idc.BADADDR:
                            addr = next_addr
                            continue

                        bnot_insn = idaapi.insn_t()
                        bnot_size = ida_ua.decode_insn(bnot_insn, bnot_addr)
                        if bnot_size == 0:
                            addr = bnot_addr
                            continue

                        if (
                            bnot_insn.itype == idaapi.NN_cond_jmp
                            and "NE" in idc.print_insn_mnem(bnot_addr).upper()
                        ):
                            # Found potential validation pattern
                            validations.append(addr)
                            logger.info(f"Found potential validation at 0x{addr:X}")

            addr = idc.next_head(addr)

    return validations


def fix_jump_table_references(start_ea=None, end_ea=None):
    """
    Fix jump table references that might have been broken by the anti-disassembly protection.
    Returns the number of fixed references.
    """
    fixed_count = 0

    # Get the .text segment
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        logger.error("Could not find .text segment")
        return fixed_count

    # Scan for switch tables
    start_ea = start_ea or text_seg.start_ea
    end_ea = end_ea or text_seg.end_ea

    for func_ea in idautils.Functions(start_ea, end_ea):
        # Skip functions we've already processed
        if func_ea in discovered_addresses:
            continue

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # Look for potential switch tables
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = idaapi.insn_t()
            insn_size = ida_ua.decode_insn(insn, head)
            if insn_size == 0:
                continue

            # Check if this is a jump instruction with a memory reference
            if insn.itype in [
                idaapi.NN_jmp,
                idaapi.NN_jmpfi,
                idaapi.NN_jmpni,
            ] and insn.Op1.type in [idaapi.o_mem, idaapi.o_displ]:
                # This could be a jump table reference
                target = insn.Op1.addr

                # Check if this points to a valid code area
                if not (text_seg.start_ea <= target < text_seg.end_ea):
                    continue

                # Check if target is properly defined
                flags = ida_bytes.get_flags(target)
                if not ida_bytes.is_code(flags):
                    # Create code here
                    ida_ua.create_insn(target)
                    ida_xref.add_cref(head, target, ida_xref.fl_JN)
                    fixed_count += 1
                    logger.info(
                        f"Fixed jump table reference at 0x{head:X} to 0x{target:X}"
                    )

    return fixed_count


def main():
    """
    Main function to remove Aegis anti-disassembly protection.
    """
    logger.info("Starting Aegis anti-disassembly unpatcher")

    # Wait for IDA analysis to complete
    idaapi.auto_wait()

    # Get the .text segment
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        logger.error("Could not find .text segment")
        return

    logger.info(f"Text segment: 0x{text_seg.start_ea:X} - 0x{text_seg.end_ea:X}")
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func:
        start_ea = func.start_ea
        end_ea = func.end_ea
    else:
        start_ea, end_ea = idaapi.read_range_selection(idaapi.get_current_viewer())
        if start_ea != idaapi.BADADDR and end_ea != idaapi.BADADDR:
            # reset ea to start_ea since we selected a range specifically to the
            # start and end of the range
            ea = start_ea
        else:
            start_ea = ea
            print("No range selected.")
            end_ea = ida_kernwin.ask_addr(start_ea, "Enter end address for selection:")
            if end_ea is None:
                print("Selection cancelled.")
                return
            if end_ea <= start_ea:
                print("Error: End address must be greater than start address.")
                return
        print(f"Selection start: 0x{start_ea:X}, end: 0x{end_ea:X} (user-defined)")

    # Scan for anti-disassembly patterns across the binary
    potential_addresses = scan_for_anti_disasm_patterns(start_ea, end_ea)
    logger.info(
        f"Found {len(potential_addresses)} potential anti-disassembly locations"
    )

    # Process each potential anti-disassembly location
    fixed_pattern_count = 0
    for addr in potential_addresses:
        # Find the function containing this address
        func = ida_funcs.get_func(addr)
        if not func:
            # Try to create a function here
            if not ida_funcs.add_func(addr):
                logger.warning(f"Could not create function at 0x{addr:X}")
                # Try to fix just this chunk
                is_anti_disasm, chunk_size, fix_info = analyze_anti_disasm_chunk(addr)
                if is_anti_disasm:
                    if fix_anti_disasm_chunk(addr, fix_info):
                        fixed_pattern_count += 1
                continue
            func = ida_funcs.get_func(addr)

        # Fix function flow
        fixed_count = fix_function_flow(func.start_ea)
        fixed_pattern_count += fixed_count

    # Process all functions in the binary
    logger.info("Processing all functions in the binary")
    total_funcs = 0
    fixed_funcs = 0
    for func_ea in idautils.Functions(start_ea, end_ea):
        total_funcs += 1
        if func_ea not in discovered_addresses:
            fixed_count = fix_function_flow(func_ea)
            if fixed_count > 0:
                fixed_funcs += 1
                fixed_pattern_count += fixed_count

    # Fix jump table references
    fixed_refs = fix_jump_table_references(start_ea, end_ea)
    logger.info(f"Fixed {fixed_refs} jump table references")

    # Identify validation patterns
    validations = identify_extra_validations(start_ea, end_ea)
    logger.info(f"Found {len(validations)} potential validation patterns")

    # Final statistics
    logger.info(f"Total functions: {total_funcs}")
    logger.info(f"Functions with fixed patterns: {fixed_funcs}")
    logger.info(f"Total fixed anti-disassembly patterns: {fixed_pattern_count}")
    logger.info(f"Total bytes patched: {len(patched_addresses)}")

    # Refresh IDA's view
    idaapi.refresh_idaview_anyway()

    print(f"\nAegis anti-disassembly unpatcher complete:")
    print(f"- Fixed {fixed_pattern_count} anti-disassembly patterns")
    print(f"- Fixed {fixed_refs} jump table references")
    print(f"- Found {len(validations)} potential validation patterns")
    print(f"- Total bytes patched: {len(patched_addresses)}")
    print("\nSee aegis_unpatcher.log for details")


if __name__ == "__main__":
    main()
