import logging
import re
import typing
from dataclasses import dataclass
from enum import Enum

import ida_bytes
import ida_funcs
import idaapi
import idautils
import idc

# Initialize logger
logger = logging.getLogger(__name__)
# Basic configuration (can be adjusted or handled externally)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


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


# --- Added helper function ---
def _determine_alignment_exponent(address: int) -> int:
    """
    Determines the alignment exponent (log2) based on the address.
    Checks for 16, 8, 4, 2 byte alignment. Returns 0 if none match.
    """
    if (address % 16) == 0:
        return 4  # log2(16)
    elif (address % 8) == 0:
        return 3  # log2(8)
    elif (address % 4) == 0:
        return 2  # log2(4)
    elif (address % 2) == 0:
        return 1  # log2(2)
    else:
        return 0  # No specific alignment (or 1-byte aligned)


# Main function with dry-run option
def undo_function_padding_patching(start_ea, end_ea, dry_run=True):
    logger.info(
        "Starting function padding unpatching (Dry Run: %s)...",
        "Enabled" if dry_run else "Disabled",
    )

    # Get file boundaries
    start_ea = start_ea or idc.get_inf_attr(idc.INF_MIN_EA)
    end_ea = end_ea or idc.get_inf_attr(idc.INF_MAX_EA)
    logger.info(f"File EA range: {hex(start_ea)} - {hex(end_ea)}")
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
            # Calculate RVA relative to image base
            rva = p_end - idaapi.get_imagebase()

            # Check if end conditions are NOT met
            is_aligned = (rva & 0xF) == 0
            is_special = is_special_sequence(p_end)

            if not (is_aligned or is_special):
                p_end += 1
                continue  # Continue searching if neither condition is met

            # --- End conditions met, process the sequence ---
            sequence_length = p_end - p_patch_bytes
            if sequence_length >= 5:
                # Valid sequence found
                logger.info(f"Candidate at EA {hex(p_patch_bytes)} to {hex(p_end - 1)}")
                if dry_run:
                    logger.info(
                        f"    [Dry Run] Would patch {sequence_length} bytes to 0xCC and align"
                    )
                else:
                    # Patch the sequence to 0xCC
                    logger.info(f"    Patching {sequence_length} bytes to 0xCC...")
                    ida_bytes.patch_bytes(p_patch_bytes, b"\xcc" * sequence_length)
                    logger.info(f"    Patched {sequence_length} bytes to 0xCC.")

                    # --- Add alignment logic ---
                    next_ea = (
                        p_end  # Address immediately following the patched sequence
                    )
                    align_exponent = _determine_alignment_exponent(next_ea)
                    align_val = 1 << align_exponent

                    logger.info(
                        f"    Attempting to undefine and align patched range to {align_val} bytes (exponent {align_exponent})..."
                    )

                    # Undefine padding first
                    if not ida_bytes.del_items(
                        p_patch_bytes, ida_bytes.DELIT_EXPAND, sequence_length
                    ):
                        logger.warning(
                            f"    Could not fully undefine padding range at 0x{p_patch_bytes:X} before alignment."
                        )

                    # Create the alignment directive
                    if align_exponent > 0:
                        if ida_bytes.create_align(
                            p_patch_bytes, sequence_length, align_exponent
                        ):
                            logger.info(
                                f"    Successfully created align {align_val} directive for patched range."
                            )
                        else:
                            logger.warning(
                                f"    Failed to create align directive for patched range at 0x{p_patch_bytes:X}."
                            )
                    else:
                        logger.info(
                            f"    No specific alignment needed (exponent is 0, next_ea=0x{next_ea:X})."
                        )
                    # --- End alignment logic ---

                patched_count += 1
                return
            # Break the inner while loop since we found the end or the sequence wasn't valid
            break
            # The p_end += 1 is now handled by the continue statement above

    logger.info(f"Unpatching complete. Found {patched_count} sequences.")


# Run the script (dry-run by default)
if __name__ == "__main__":
    # Optional: Configure logger here if you want specific settings for standalone runs
    # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    curr_ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(curr_ea)
    if not func:
        # Consider using logger.error or raising an exception
        print(
            "No function found at current cursor position."
        )  # Kept print for initial error before logging might be set up
        exit(-1)
    end = func.end_ea

    # Using func.start_ea instead of curr_ea for the start range seems more appropriate
    # Also, end + 0x100 might go too far, using func.end_ea is safer unless padding is known to extend significantly
    undo_function_padding_patching(
        curr_ea, end + 0x100, dry_run=True
    )  # Set to False to apply patches
