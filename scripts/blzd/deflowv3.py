import ida_bytes
import ida_funcs
import ida_idp
import ida_name
import ida_search
import ida_segment
import ida_ua
import ida_xref
import idaapi
import idc

# Anti-disassembly signature (from AntidisasmSignature in the source code)
ANTI_DISASM_SIGNATURE = [
    0x65,
    0x48,
    0x81,
    0x04,
    0x25,
    0x41,
    0x45,
    0x47,
    0x49,
    0x53,
    0x5F,
]

# NOP patterns from the source code
NOP_PATTERNS = [
    [0x90],  # 1-byte NOP
    [0x66, 0x90],  # 2-byte XCHG AX, AX
    [0x0F, 0x1F, 0x00],  # 3-byte NOP DWORD ptr [RAX]
    [0x0F, 0x1F, 0x40, 0x00],  # 4-byte NOP DWORD ptr [RAX + 0]
    [0x0F, 0x1F, 0x44, 0x00, 0x00],  # 5-byte NOP DWORD ptr [RAX + RAX + 0]
    [0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],  # 6-byte NOP WORD ptr [RAX + RAX + 0]
    [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],  # 7-byte NOP DWORD ptr [RAX + 0]
    [
        0x0F,
        0x1F,
        0x84,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ],  # 8-byte NOP DWORD ptr [RAX + RAX + 0]
    [0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # 9-byte NOP
    [0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  # 10-byte NOP
    [
        0x66,
        0x66,
        0x66,
        0x0F,
        0x1F,
        0x84,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ],  # 11-byte NOP
]

# Jump pairs from the source code
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

# ByteOp patterns from the source code
BYTE_OPS_CLEAR_CFOF = [
    {
        "alSpecificOpcode": 0x24,
        "genericOpcode": [0x80, 0xE0],
        "noEffectValue": 0xFF,
    },  # AND
    {
        "alSpecificOpcode": 0x0C,
        "genericOpcode": [0x80, 0xC8],
        "noEffectValue": 0x00,
    },  # OR
    {
        "alSpecificOpcode": 0x34,
        "genericOpcode": [0x80, 0xF0],
        "noEffectValue": 0x00,
    },  # XOR
]

# JunkRegOps from the source code
JUNK_REG_OPS = [
    {"Opcode": 0x80, "RegOp": 0xC0, "immSize": 1},
    {"Opcode": 0x81, "RegOp": 0xC0, "immSize": 4},
    {"Opcode": 0x83, "RegOp": 0xC0, "immSize": 1},
    {"Opcode": 0xC6, "RegOp": 0xC0, "immSize": 1},
    {"Opcode": 0xC7, "RegOp": 0xC0, "immSize": 4},
    {"Opcode": 0xF6, "RegOp": 0xD8, "immSize": 0},
    {"Opcode": 0x80, "RegOp": 0xE8, "immSize": 1},
    {"Opcode": 0x81, "RegOp": 0xE8, "immSize": 4},
]


def patch_bytes(ea, values):
    """Patch bytes at specified address"""
    for i, value in enumerate(values):
        ida_bytes.patch_byte(ea + i, value)


def nop_range(start, end):
    """NOP out a range of bytes"""
    for i in range(start, end):
        ida_bytes.patch_byte(i, 0x90)  # NOP


def find_anti_disasm_signatures():
    """Find all occurrences of the anti-disassembly signature in the binary"""
    signatures = []
    pattern = " ".join([f"{b:02X}" for b in ANTI_DISASM_SIGNATURE])

    print(f"[*] Searching for pattern: {pattern}")
    ea = ida_search.find_binary(0, idaapi.BADADDR, pattern, 16, ida_search.SEARCH_DOWN)

    while ea != idaapi.BADADDR:
        signatures.append(ea)
        ea = ida_search.find_binary(
            ea + 1, idaapi.BADADDR, pattern, 16, ida_search.SEARCH_DOWN
        )

    return signatures


def is_nop(ea):
    """Check if the instruction at address is a NOP pattern, returns (is_nop, length)"""
    for pattern in NOP_PATTERNS:
        match = True
        for i, byte in enumerate(pattern):
            if ida_bytes.get_byte(ea + i) != byte:
                match = False
                break
        if match:
            return True, len(pattern)
    return False, 0


def evaluate_jump_x64(ea):
    """Evaluate a jump instruction at address, returns (is_jump, destination, size)"""
    # Check for short conditional jumps (0x70-0x7F) or short JMP (0xEB)
    op_byte = ida_bytes.get_byte(ea)
    if (op_byte >= 0x70 and op_byte <= 0x7F) or op_byte == 0xEB:
        offset = ida_bytes.get_byte(ea + 1)
        if offset >= 0x80:  # Handle negative offsets
            offset -= 0x100
        jump_size = 2
        dest = ea + jump_size + offset
        return True, dest, jump_size

    # Check for near JMP (0xE9)
    elif op_byte == 0xE9:
        offset = ida_bytes.get_dword(ea + 1)
        if offset >= 0x80000000:  # Handle negative offsets
            offset -= 0x100000000
        jump_size = 5
        dest = ea + jump_size + offset
        return True, dest, jump_size

    # Check for near conditional jumps (0x0F 0x80-0x8F)
    elif (
        op_byte == 0x0F
        and ida_bytes.get_byte(ea + 1) >= 0x80
        and ida_bytes.get_byte(ea + 1) <= 0x8F
    ):
        offset = ida_bytes.get_dword(ea + 2)
        if offset >= 0x80000000:  # Handle negative offsets
            offset -= 0x100000000
        jump_size = 6
        dest = ea + jump_size + offset
        return True, dest, jump_size

    return False, 0, 0


def is_correct_jump_destination(jump_dest, expected_dest):
    """Check if jump_dest is a valid jump destination relative to expected_dest"""
    # Direct match
    if jump_dest == expected_dest:
        return True

    # Check if jump_dest points to a NOP instruction that leads to expected_dest
    is_nop_result, nop_len = is_nop(jump_dest)
    if is_nop_result:
        return (jump_dest + nop_len) == expected_dest

    return False


def get_end_signature_size_x64(ea, extra_bytes):
    """Calculate the size of an anti-disassembly signature ending for x64"""
    jump_search_start = ea + extra_bytes + 13

    # Search for a jump instruction up to 32 bytes (0x20)
    for i in range(0x20):
        current = jump_search_start + i

        is_jump, jump_dest, jump_size = evaluate_jump_x64(current)
        if is_jump:
            # Check if the jump destination points to the beginning of the signature
            if is_correct_jump_destination(jump_dest, ea):
                # Found the correct jump, calculate the end size
                return (current + jump_size) - jump_search_start
            else:
                # Might be a chained jump - continue searching
                continue_dest = jump_dest
                i += jump_size - 1

                while i < 0x20:
                    current = jump_search_start + i
                    is_jump, jump_dest, jump_size = evaluate_jump_x64(current)

                    if is_jump and is_correct_jump_destination(jump_dest, ea):
                        # Found the correct jump in the chain, calculate the end size
                        end = current + jump_size

                        # Check if an intermediate jump needs to be bridged
                        if continue_dest and continue_dest != end:
                            jmp_displacement = continue_dest - end

                            if jmp_displacement >= 127 or jmp_displacement <= -128:
                                # Need a 5-byte near jump
                                end -= 5
                            else:
                                # Need a 2-byte short jump
                                end -= 2

                        return end - jump_search_start

                    if is_jump:
                        continue_dest = jump_dest
                        i += jump_size - 1

                    i += 1

    # If we reach here, we couldn't find the end signature size
    print(f"[!] Warning: Could not determine end signature size for block at 0x{ea:x}")
    return 0


def parse_anti_disasm_block(ea):
    """Parse the structure of an anti-disassembly block"""
    # Get extraBytes and type
    extra_bytes = ida_bytes.get_byte(ea + 11)
    type_byte = ida_bytes.get_byte(ea + 12)

    # Jump search begins at blockStart + extraBytes + 13
    jump_search_start = ea + extra_bytes + 13

    # Find the end signature size
    if idaapi.get_inf_structure().is_64bit():
        end_size = get_end_signature_size_x64(ea, extra_bytes)
    else:
        # Handle x86 (should be similar for this protection)
        end_size = get_end_signature_size_x64(ea, extra_bytes)

    # Calculate total block size: signatureSize(11) + extraBytes + endSize + 2
    total_size = 11 + extra_bytes + end_size + 2

    return {
        "start": ea,
        "extra_bytes": extra_bytes,
        "type": type_byte,
        "jump_search_start": jump_search_start,
        "end_size": end_size,
        "total_size": total_size,
    }


def fix_opaque_predicates(ea, size):
    """Fix opaque predicates in an anti-disassembly block"""
    end_ea = ea + size
    current_ea = ea

    while current_ea < end_ea:
        # Decode the instruction
        insn = ida_ua.insn_t()
        insn_size = ida_ua.decode_insn(insn, current_ea)
        if insn_size == 0:
            current_ea += 1
            continue

        # Check for F8/F9 (CLD/STD) followed by conditional jumps
        if ida_bytes.get_byte(current_ea) in [0xF8, 0xF9]:
            next_ea = current_ea + 1
            if next_ea < end_ea:
                next_byte = ida_bytes.get_byte(next_ea)
                if next_byte >= 0x70 and next_byte <= 0x7F:
                    # This is likely an opaque predicate pattern
                    print(
                        f"[*] Found F8/F9 opaque predicate at 0x{current_ea:x}, patching..."
                    )

                    # Patch the CLD/STD to NOP
                    ida_bytes.patch_byte(current_ea, 0x90)  # NOP

                    # Get the jump destination
                    is_jump, jump_dest, jump_size = evaluate_jump_x64(next_ea)
                    if is_jump:
                        # Convert the conditional jump to an unconditional jump
                        ida_bytes.patch_byte(next_ea, 0xEB)  # JMP short

        # Check for byte operations with no effect
        elif ida_bytes.get_byte(current_ea) in [
            0x24,
            0x0C,
            0x34,
        ]:  # AND AL, OR AL, XOR AL
            if (
                (
                    ida_bytes.get_byte(current_ea) == 0x24
                    and ida_bytes.get_byte(current_ea + 1) == 0xFF
                )  # AND AL, 0xFF
                or (
                    ida_bytes.get_byte(current_ea) == 0x0C
                    and ida_bytes.get_byte(current_ea + 1) == 0x00
                )  # OR AL, 0x00
                or (
                    ida_bytes.get_byte(current_ea) == 0x34
                    and ida_bytes.get_byte(current_ea + 1) == 0x00
                )
            ):  # XOR AL, 0x00
                # This is a byte operation with no effect
                print(
                    f"[*] Found no-effect byte operation at 0x{current_ea:x}, patching..."
                )

                # Patch to NOPs
                nop_range(current_ea, current_ea + 2)

                # Check if followed by a conditional jump
                next_ea = current_ea + 2
                if next_ea < end_ea:
                    next_byte = ida_bytes.get_byte(next_ea)
                    if next_byte >= 0x70 and next_byte <= 0x7F:
                        # This is likely part of an opaque predicate pattern
                        ida_bytes.patch_byte(next_ea, 0xEB)  # Convert to JMP short

        # Check for complementary conditional jumps
        elif (
            ida_bytes.get_byte(current_ea) >= 0x70
            and ida_bytes.get_byte(current_ea) <= 0x7F
        ):
            # Get the jump destination
            is_jump, jump_dest, jump_size = evaluate_jump_x64(current_ea)
            if is_jump:
                # Check the next instruction
                next_ea = current_ea + jump_size
                if next_ea < end_ea:
                    next_byte = ida_bytes.get_byte(next_ea)
                    if next_byte >= 0x70 and next_byte <= 0x7F:
                        # Check if they are complementary
                        op1 = ida_bytes.get_byte(current_ea)
                        op2 = next_byte

                        for pair in JUMP_PAIRS:
                            if (op1 == pair[0] and op2 == pair[1]) or (
                                op1 == pair[1] and op2 == pair[0]
                            ):
                                # These are complementary conditional jumps
                                print(
                                    f"[*] Found complementary conditional jumps at 0x{current_ea:x}, patching..."
                                )

                                # For complementary jumps, we can safely NOP out the first one
                                # and convert the second to an unconditional jump
                                nop_range(current_ea, current_ea + jump_size)
                                ida_bytes.patch_byte(next_ea, 0xEB)  # JMP short

                                # Skip the second jump in the next iteration
                                current_ea = next_ea
                                break

        current_ea += insn_size


def fix_circular_jumps(ea, size):
    """Fix circular jumps in an anti-disassembly block"""
    end_ea = ea + size

    # Track jumps and their destinations
    jumps = {}

    # First pass: collect all jumps
    current_ea = ea
    while current_ea < end_ea:
        # Decode the instruction
        insn = ida_ua.insn_t()
        insn_size = ida_ua.decode_insn(insn, current_ea)
        if insn_size == 0:
            current_ea += 1
            continue

        # Check for jumps
        if (
            ida_bytes.get_byte(current_ea) in [0xE9, 0xEB]
            or (
                ida_bytes.get_byte(current_ea) >= 0x70
                and ida_bytes.get_byte(current_ea) <= 0x7F
            )
            or (
                ida_bytes.get_byte(current_ea) == 0x0F
                and ida_bytes.get_byte(current_ea + 1) >= 0x80
                and ida_bytes.get_byte(current_ea + 1) <= 0x8F
            )
        ):
            is_jump, jump_dest, _ = evaluate_jump_x64(current_ea)
            if is_jump and jump_dest >= ea and jump_dest < end_ea:
                jumps[current_ea] = jump_dest

        current_ea += insn_size

    # Second pass: detect and fix circular jumps
    for jump_ea, dest_ea in jumps.items():
        # Check for self-jump
        if jump_ea == dest_ea:
            # Self-jump, NOP it out
            print(f"[*] Found self-jump at 0x{jump_ea:x}, patching...")
            insn_size = ida_ua.decode_insn(ida_ua.insn_t(), jump_ea)
            nop_range(jump_ea, jump_ea + insn_size)
            continue

        # Check for circular jump chain
        visited = {jump_ea}
        current = dest_ea

        while current in jumps and current not in visited:
            visited.add(current)
            current = jumps[current]

        if current in visited:
            # Circular jump detected
            print(
                f"[*] Found circular jump chain starting at 0x{jump_ea:x}, patching..."
            )

            # NOP out the first jump
            insn_size = ida_ua.decode_insn(ida_ua.insn_t(), jump_ea)
            nop_range(jump_ea, jump_ea + insn_size)


class AntiDisasmDeflower:
    """Implements the DeFlow algorithm to restore correct control flow"""

    def __init__(self, block):
        self.block = block
        self.visited = set()
        self.pending = []

    def process(self):
        """Apply the DeFlow algorithm to the anti-disassembly block"""
        print(f"[*] Applying DeFlow algorithm to block at 0x{self.block['start']:x}")

        # Start from the beginning of the block
        self.deflower_chunk(self.block["start"])

        # Process any pending chunks
        while self.pending:
            ea = self.pending.pop(0)
            if ea not in self.visited:
                self.deflower_chunk(ea)

    def deflower_chunk(self, ea):
        """Process a chunk of code using the DeFlow algorithm"""
        last_target = None
        steps_left = 0
        is_jmp = False

        if ea in self.visited:
            return

        self.visited.add(ea)
        current_ea = ea

        # Process instructions until we reach the end of the block
        while current_ea < self.block["start"] + self.block["total_size"]:
            # Decode the instruction
            insn = ida_ua.insn_t()
            insn_size = ida_ua.decode_insn(insn, current_ea)
            if insn_size == 0:
                current_ea += 1
                continue

            # Check if we have a last_target set and if so, calculate steps_left
            if last_target is not None:
                steps_left = last_target - current_ea

                if steps_left <= 0:
                    # We've reached or passed the target - this is likely an opaque predicate
                    print(
                        f"[*] Found likely opaque predicate at 0x{current_ea:x}, patching..."
                    )

                    # If the current instruction is a conditional jump, convert it to unconditional
                    op_byte = ida_bytes.get_byte(current_ea)
                    if op_byte >= 0x70 and op_byte <= 0x7F:
                        # Convert conditional jump to unconditional
                        ida_bytes.patch_byte(current_ea, 0xEB)

                    # Reset for next iteration
                    last_target = None
                    steps_left = 0
                    is_jmp = False

            # Check for different types of instructions
            op_byte = ida_bytes.get_byte(current_ea)

            # RET instruction
            if op_byte in [0xC3, 0xC2]:
                if last_target is None:
                    # End of chunk
                    break

            # Unconditional jumps (JMP near/short)
            elif op_byte in [0xE9, 0xEB]:
                is_jump, jump_dest, _ = evaluate_jump_x64(current_ea)
                if is_jump:
                    # Check if the jump is within the block
                    if (
                        jump_dest >= self.block["start"]
                        and jump_dest < self.block["start"] + self.block["total_size"]
                    ):
                        # Add to pending if not visited
                        if jump_dest not in self.visited:
                            self.pending.append(jump_dest)

                # End of chunk
                break

            # Conditional jumps
            elif (op_byte >= 0x70 and op_byte <= 0x7F) or (
                op_byte == 0x0F
                and ida_bytes.get_byte(current_ea + 1) >= 0x80
                and ida_bytes.get_byte(current_ea + 1) <= 0x8F
            ):
                is_jump, jump_dest, _ = evaluate_jump_x64(current_ea)
                if is_jump:
                    # Check if the jump is within the block
                    if (
                        jump_dest >= self.block["start"]
                        and jump_dest < self.block["start"] + self.block["total_size"]
                    ):
                        if last_target is None:
                            # Set last_target to jump destination
                            last_target = jump_dest
                            is_jmp = True
                        else:
                            # Add to pending if not visited
                            if jump_dest not in self.visited:
                                self.pending.append(jump_dest)

            # CALL instruction - might be part of anti-disassembly
            elif op_byte == 0xE8:
                is_jump, jump_dest, _ = evaluate_jump_x64(current_ea)
                if is_jump:
                    # Check if the call is within the block
                    if (
                        jump_dest >= self.block["start"]
                        and jump_dest < self.block["start"] + self.block["total_size"]
                    ):
                        # Add to pending if not visited
                        if jump_dest not in self.visited:
                            self.pending.append(jump_dest)

            # Move to next instruction
            current_ea += insn_size


def fix_anti_disassembly():
    """Main function to identify and fix Aegis anti-disassembly protection"""
    print("[*] Aegis Anti-Disassembly Unpatcher - Starting")
    print("[*] Looking for Aegis anti-disassembly signatures...")

    signatures = find_anti_disasm_signatures()
    print(f"[+] Found {len(signatures)} anti-disassembly signatures")

    if not signatures:
        print("[!] No anti-disassembly signatures found.")
        return

    # Process each block
    blocks_fixed = 0
    for ea in signatures:
        print(f"\n[*] Processing anti-disassembly block at 0x{ea:x}")

        try:
            # Parse the block structure
            block = parse_anti_disasm_block(ea)
            print(
                f"[+] Block details: extra_bytes={block['extra_bytes']}, type={block['type']}, total_size={block['total_size']}"
            )

            # Fix opaque predicates
            fix_opaque_predicates(ea, block["total_size"])

            # Fix circular jumps
            fix_circular_jumps(ea, block["total_size"])

            # Apply the DeFlow algorithm
            deflower = AntiDisasmDeflower(block)
            deflower.process()

            blocks_fixed += 1
            print(f"[+] Successfully processed block at 0x{ea:x}")
        except Exception as e:
            print(f"[!] Error processing block at 0x{ea:x}: {str(e)}")

    # Refresh IDA's view
    idaapi.refresh_idaview_anyway()

    print(
        f"\n[+] Anti-disassembly protection removal complete. Fixed {blocks_fixed} blocks."
    )


if __name__ == "__main__":
    fix_anti_disassembly()
