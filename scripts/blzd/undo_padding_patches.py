# -*- coding: utf-8 -*-
import logging

import ida_bytes
import ida_kernwin
import ida_nalt  # Needed for _bin_search encoding
import ida_ua
import idaapi


# --- Basic Setup ---
def clear_output():
    ida_kernwin.msg_clear()
    print("Output window cleared.")


def configure_logging(log, level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] @ %(asctime)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log.setLevel(level)


logger = logging.getLogger("FunctionBoundaryFinder")


# --- Binary Search Helper ---
def _bin_search(start, end, pattern) -> "ea_t":
    """
    Searches for a binary pattern within a range.

    Args:
        start (int): Start address.
        end (int): End address (exclusive).
        pattern (list[int]): List of bytes to search for (-1 for wildcard).

    Returns:
        int: Address where the pattern was found, or idaapi.BADADDR if not found.
    """
    patterns = ida_bytes.compiled_binpat_vec_t()
    # Allow wildcard '?' or -1
    seqstr = " ".join(
        [f"{b:02x}" if isinstance(b, int) and b != -1 else "?" for b in pattern]
    )

    # Use default 1-byte encoding
    enc_idx = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
    err = ida_bytes.parse_binpat_str(patterns, start, seqstr, 16, enc_idx)  # Radix 16

    if err:
        logger.error(f"Failed to parse binary pattern string: {seqstr} (Error: {err})")
        return idaapi.BADADDR

    # Perform the search
    found_ea = ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)

    # bin_search returns -1 (BADADDR) if not found
    return found_ea


# --- Reusable Helpers (from previous script) ---
def is_cc_byte(ea):
    """Check if the byte at the given address is 0xCC."""
    try:
        return ida_bytes.is_loaded(ea) and ida_bytes.get_byte(ea) == 0xCC
    except Exception:
        return False


def is_special_sequence(ea):
    """Check if the address starts with a special alignment/padding sequence."""
    if not ida_bytes.is_loaded(ea):
        return False
    # Read more bytes to check longer sequences if necessary
    bytes_at_ea = ida_bytes.get_bytes(ea, 3)  # Check up to 3 bytes for the C++ examples
    if not bytes_at_ea:
        return False
    # Sequences mentioned in C++ patcher: 66 90, 66 0F, 66 66 0F
    if bytes_at_ea[0] == 0x66:
        if len(bytes_at_ea) > 1:
            if bytes_at_ea[1] == 0x90 or bytes_at_ea[1] == 0x0F:
                return True
            if (
                bytes_at_ea[1] == 0x66
                and len(bytes_at_ea) > 2
                and bytes_at_ea[2] == 0x0F
            ):
                return True
    # Add other common sequences if desired
    # sequences = [b"\x0F\x1F\x00", ...]
    # if any(bytes_at_ea.startswith(seq) for seq in sequences): return True
    return False


# --- Main Finder Class ---
class FunctionBoundaryFinder:

    def __init__(self, start_ea=None, end_ea=None):
        """
        Initializes the finder.

        Args:
            start_ea (int, optional): Start address for search. Defaults to .text start.
            end_ea (int, optional): End address for search (exclusive). Defaults to .text end.
        """
        if start_ea is None or end_ea is None:
            text_seg = idaapi.get_segm_by_name(".text")
            if not text_seg:
                raise ValueError("Could not find .text segment and no range specified.")
            self.start_ea = text_seg.start_ea
            self.end_ea = text_seg.end_ea
            logger.info(
                f"Using .text segment range: 0x{self.start_ea:X} - 0x{self.end_ea:X}"
            )
        else:
            self.start_ea = start_ea
            self.end_ea = end_ea
            logger.info(
                f"Using specified range: 0x{self.start_ea:X} - 0x{self.end_ea:X}"
            )

        if not ida_bytes.is_loaded(self.start_ea) or not ida_bytes.is_loaded(
            self.end_ea - 1
        ):
            logger.warning(
                f"Search range 0x{self.start_ea:X} - 0x{self.end_ea:X} may not be fully loaded."
            )

    def find_and_create_boundaries(self):
        """
        Searches for potential function boundaries (0xC3) not marked as code
        and prompts the user to create instructions/trigger analysis.
        """
        search_ea = self.start_ea
        ret_pattern = [0xC3]  # ret instruction
        processed_count = 0
        created_count = 0

        while search_ea < self.end_ea:
            (ret_ea,) = _bin_search(search_ea, self.end_ea, ret_pattern)

            if ret_ea == idaapi.BADADDR:
                logger.info("No more 0xC3 instructions found in range.")
                break

            processed_count += 1
            logger.debug(f"Found 0xC3 at 0x{ret_ea:X}")

            # --- Filter 1: Check if already code ---
            # Use get_item_head to see if it belongs to an existing item start
            item_head = ida_bytes.get_item_head(ret_ea)
            flags = ida_bytes.get_full_flags(ret_ea)

            # is_code checks if the *start* of the item is code. We want to know if *this specific byte* is code.
            # A simpler check: if flags indicate it's part of *any* instruction byte (FF_CODE)
            if ida_bytes.is_code(flags):
                logger.debug(f"Skipping 0x{ret_ea:X}: Already defined as code.")
                search_ea = ret_ea + 1  # Continue search after this ret
                continue

            # --- Optional Confidence Check ---
            confidence_reason = "Not code"
            next_ea = ret_ea + 1
            if is_cc_byte(next_ea):
                confidence_reason += ", followed by 0xCC"
            elif is_special_sequence(next_ea):
                confidence_reason += ", followed by special sequence"
            elif ida_bytes.is_loaded(next_ea) and (next_ea & 0xF) == 0:
                confidence_reason += ", followed by 16-byte aligned addr"
            else:
                confidence_reason += ", followed by other byte/data"
            logger.info(
                f"Potential boundary found at 0x{ret_ea:X} ({confidence_reason})"
            )

            # --- Action: Prompt and Create Instruction ---
            prompt_msg = (
                f"Potential function boundary found at 0x{ret_ea:X}.\n"
                f"({confidence_reason}).\n\n"
                f"This address is not currently marked as code.\n"
                f"Attempt to create instruction here (may trigger function analysis)?"
            )

            user_choice = ida_kernwin.ask_yn(1, prompt_msg)  # Default to Yes

            if user_choice == 1:  # Yes
                logger.info(
                    f"User confirmed. Attempting ida_ua.create_insn(0x{ret_ea:X})"
                )
                # Create the instruction
                insn_len = ida_ua.create_insn(ret_ea)
                if insn_len > 0:
                    logger.info(
                        f"Successfully created instruction at 0x{ret_ea:X} (length {insn_len}). IDA auto-analysis may follow."
                    )
                    created_count += 1
                    # Optional: Force reanalysis of the area
                    # ida_analysis.plan_and_wait(ret_ea, ret_ea + insn_len)
                else:
                    logger.error(f"Failed to create instruction at 0x{ret_ea:X}.")
            elif user_choice == 0:  # No
                logger.info(f"User skipped creating instruction at 0x{ret_ea:X}.")
            else:  # Cancel
                logger.info("User cancelled the process.")
                break  # Stop searching

            # Continue searching from the byte after the current ret
            search_ea = ret_ea + 1

        logger.info(
            f"Search finished. Processed {processed_count} potential boundaries. Created instructions at {created_count} locations."
        )


# --- Main Execution Logic ---
def run_boundary_finder():
    """Runs the function boundary finder."""
    try:
        # You could add ida_kernwin.ask_addr or similar here to select range
        finder = FunctionBoundaryFinder()  # Uses .text segment by default
        finder.find_and_create_boundaries()
    except ValueError as e:
        logger.error(f"Initialization failed: {e}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")  # Log full traceback


# --- Script Entry Point ---
if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(log=logger, level=logging.INFO)  # Use DEBUG for more detail
    run_boundary_finder()
    idaapi.refresh_idaview_anyway()
