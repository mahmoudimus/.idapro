import re
import typing
from dataclasses import dataclass
from enum import Enum

import ida_bytes
import idaapi
import idautils
import idc


# Assuming PatternCategory is an Enum defined elsewhere
class PatternCategory(Enum):
    FUNCTION_PADDING = 1


@dataclass
class RegexPatternMetadata:
    category: PatternCategory
    pattern: bytes
    description: typing.Optional[str] = None
    compiled: typing.Optional[typing.Pattern] = None

    def compile(self, flags=0):
        if self.compiled is None:
            self.compiled = re.compile(self.pattern, flags)
        return self.compiled

    @property
    def group_names(self):
        return self.compile().groupindex


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


# # Check for special sequence (e.g., 0x66 0x90 or 0x66 0x0F)
# def is_special_sequence(ea):
#     byte0 = idc.get_bytes(ea, 1)[0] if idc.get_bytes(ea, 1) else None
#     if byte0 != 0x66:
#         return False
#     byte1 = idc.get_bytes(ea + 1, 1)[0] if idc.get_bytes(ea + 1, 1) else None
#     if byte1 is None:
#         return False
#     if byte1 == 0x90 or byte1 == 0x0F:
#         return True
#     byte2 = idc.get_bytes(ea + 2, 1)[0] if idc.get_bytes(ea + 2, 1) else None
#     return byte1 == 0x66 and byte2 == 0x0F


def is_special_sequence(ea):
    bytes_at_ea = idc.get_bytes(ea, 3)
    if not bytes_at_ea or len(bytes_at_ea) < 2:
        return False
    sequences = [b"\x66\x90", b"\x66\x0f", b"\x66\x66\x0f"]
    return any(bytes_at_ea.startswith(seq) for seq in sequences)


# Check if an address is in a non-executable section
def is_non_executable(ea):
    seg = idaapi.getseg(ea)
    if not seg:
        return False
    return (seg.perm & idaapi.SEGPERM_EXEC) == 0


# Main function with dry-run option
def undo_function_padding_patching(start_ea, end_ea, dry_run=True):
    print(
        "[+] Starting function padding unpatching (Dry Run: {})...".format(
            "Enabled" if dry_run else "Disabled"
        )
    )

    # Get file boundaries
    start_ea = start_ea or idc.get_inf_attr(idc.INF_MIN_EA)
    end_ea = end_ea or idc.get_inf_attr(idc.INF_MAX_EA)
    print(f"[+] File EA range: {hex(start_ea)} - {hex(end_ea)}")
    # Initialize MemHelper to retrieve memory bytes
    mem_helper = MemHelper(start_ea, end_ea)

    # Define regex pattern to find 0xC3 (RET instruction)
    pattern_metadata = RegexPatternMetadata(
        category=PatternCategory.FUNCTION_PADDING,
        pattern=b"\xc3",
        description="Find RET instructions",
    )
    pattern = pattern_metadata.compile()

    patched_count = 0
    # Find all occurrences of 0xC3 in the memory
    for match in pattern.finditer(mem_helper.mem_results):
        # Convert match offset to EA
        offset = match.start()
        ea_c3 = mem_helper.start + offset
        p_patch_bytes = ea_c3 + 1  # Start of the sequence to patch

        # Find the end of the sequence
        p_end = p_patch_bytes
        while p_end < mem_helper.end:
            # Stop if we reach an executable section
            # if not is_non_executable(p_end):
            #     break

            # Calculate RVA relative to image base
            rva = p_end - idaapi.get_imagebase()

            # Check end conditions: 16-byte alignment or special sequence
            if (rva & 0xF) == 0 or is_special_sequence(p_end):
                sequence_length = p_end - p_patch_bytes
                if sequence_length >= 5:
                    # Valid sequence found
                    print(
                        f"[+] Candidate at EA {hex(p_patch_bytes)} to {hex(p_end - 1)}"
                    )
                    if dry_run:
                        print(
                            f"    [Dry Run] Would patch {sequence_length} bytes to 0xCC"
                        )
                    else:
                        # Patch the sequence to 0xCC
                        ida_bytes.patch_bytes(p_patch_bytes, b"\xcc" * sequence_length)
                        print(f"    Patched {sequence_length} bytes to 0xCC")
                    patched_count += 1
                break  # Move to next match
            p_end += 1

    print(f"[+] Unpatching complete. Found {patched_count} sequences.")


# Run the script (dry-run by default)
if __name__ == "__main__":
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        print("No .text section found.")
        exit(-1)
    start = seg.start_ea
    end = seg.end_ea
    undo_function_padding_patching(
        start, end, dry_run=True
    )  # Set to False to apply patches
