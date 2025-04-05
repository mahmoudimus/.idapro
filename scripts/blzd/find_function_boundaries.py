# -*- coding: utf-8 -*-
import logging
import math  # Needed for log2 if create_align needs exponent, but we'll try value first
import typing
from enum import Enum, auto

import ida_auto  # Added
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_problems  # Added
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

# --- Configuration ---
FORWARD_SEARCH_LIMIT = 0x1000
PROLOGUE_SEARCH_LIMIT = 0x40
PROLOGUE_INSTR_CHECK_LIMIT = 5
BACKWARD_SEARCH_LIMIT = 0x300  # For fallback search from end
NEAR_CURSOR_SEARCH_LIMIT = 0x80  # How far back from cursor to check first
ADJACENT_PADDING_SEARCH_LIMIT = 0x20  # How far to look for CC padding before/after func
MAX_ALIGNMENT_CHECK = 16  # Check alignment up to this boundary (e.g., 16 bytes)

# --- Logging Setup ---
log_boundary = logging.getLogger("FuncBoundary")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
log_boundary.setLevel(logging.DEBUG)


# --- Helper Function to Reset Disassembly Problems ---
def reset_problems_in_function(func_start: int, func_end: int):
    """
    Clears potential PR_DISASM problems within a given range, often needed
    after re-analysis or function creation/modification.
    func_end is exclusive.
    """
    log_boundary.debug(
        f"Resetting disassembly problems in range 0x{func_start:X} - 0x{func_end-1:X}"
    )
    current_address: int = func_start
    # Iterate using next_head to handle variable instruction/item sizes
    while current_address < func_end and current_address != idaapi.BADADDR:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        next_addr = idc.next_head(current_address, func_end)
        if next_addr <= current_address:  # Prevent infinite loops
            log_boundary.warning(
                f"Stuck resetting problems at 0x{current_address:X}, stopping."
            )
            break
        current_address = next_addr
    log_boundary.debug(f"Finished resetting problems up to 0x{current_address:X}")


# --- Search Strategy Enum ---
class SearchStrategy(Enum):
    BACKWARD_SCAN = auto()
    FORWARD_CHUNK = auto()


# --- Search Function (_search_range) ---
# (Implementation remains the same as previous version)
def _search_range(
    ea: int,
    check_instruction: typing.Callable[[ida_ua.insn_t], bool],
    max_range: int = 0x200,
    strategy: SearchStrategy = SearchStrategy.BACKWARD_SCAN,
) -> typing.Optional[int]:
    found_ea = idaapi.BADADDR
    if strategy == SearchStrategy.BACKWARD_SCAN:
        start_addr = max(ea - max_range, 0)
        current = idc.prev_head(ea)  # Start checking *before* ea
        while current != idaapi.BADADDR and current >= start_addr:
            insn = ida_ua.insn_t()
            # Use get_item_size to handle potential data items correctly
            item_size = ida_bytes.get_item_size(current)
            if item_size == 0:  # Should not happen if prev_head works, but safety check
                current = idc.prev_head(current)
                continue

            # Decode only if it's likely code or undefined
            flags = ida_bytes.get_flags(current)
            if ida_bytes.is_code(flags) or not ida_bytes.is_data(flags):
                decoded_len = ida_ua.decode_insn(insn, current)
                if decoded_len > 0:
                    if check_instruction(insn):
                        found_ea = current
                        break
                # else: handle decode failure? For now, prev_head moves on.
            # else: it's data, skip checking via check_instruction

            current = idc.prev_head(current)  # Move to previous head regardless

    elif strategy == SearchStrategy.FORWARD_CHUNK:
        current = ea
        end_addr = ea + max_range
        while current < end_addr:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, current)
            if insn_len > 0:
                if check_instruction(insn):
                    found_ea = current
                    break
                current += insn.size
            else:
                # If decode fails, advance by 1 byte to avoid getting stuck
                current += 1
    if found_ea != idaapi.BADADDR:
        log_boundary.debug(f"_search_range found match at 0x{found_ea:X}")
        return found_ea
    else:
        return None


# --- Binary Search Helper ---
# (Implementation remains the same as previous version)
def _bin_search(start, end, pattern) -> int:
    patterns = ida_bytes.compiled_binpat_vec_t()
    if not pattern:
        return idaapi.BADADDR
    try:
        # Handle bytes, ints (-1 for wildcard), and strings
        seq_parts = []
        for b in pattern:
            if isinstance(b, int):
                seq_parts.append(f"{b:02x}" if 0 <= b <= 0xFF else "?")
            elif isinstance(b, bytes):
                seq_parts.append(b.hex())
            else:  # Assume string hex byte
                seq_parts.append(str(b))
        seqstr = " ".join(seq_parts)

    except Exception as e:
        log_boundary.error(f"Pattern format error {pattern}: {e}")
        return idaapi.BADADDR

    enc_idx = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
    err = ida_bytes.parse_binpat_str(patterns, start, seqstr, 16, enc_idx)
    if err:
        log_boundary.error(f"Parse binpat failed: '{seqstr}' Err: {err}")
        return idaapi.BADADDR

    # Ensure end address is valid
    try:
        last_seg = ida_segment.get_last_seg()
        max_ea = last_seg.end_ea if last_seg else idaapi.BADADDR
        if max_ea == idaapi.BADADDR:
            log_boundary.error("Could not determine maximum address.")
            return idaapi.BADADDR
        end = min(end, max_ea)
    except Exception as e:
        log_boundary.error(f"Error getting segment end: {e}")
        return idaapi.BADADDR

    if start >= end:
        # log_boundary.debug(f"Search range invalid: 0x{start:X}-0x{end:X}")
        return idaapi.BADADDR

    # Check if range is loaded (check start and end-1)
    if not ida_bytes.is_loaded(start) or (
        end > start and not ida_bytes.is_loaded(end - 1)
    ):
        log_boundary.warning(f"Search range 0x{start:X}-0x{end:X} not fully loaded.")
        # Allow search even if partially loaded, bin_search might handle it
        # return idaapi.BADADDR # Optional: be stricter

    return ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)


# --- Reusable Padding Finder ---
# (Implementation remains the same as previous version)
class FunctionPaddingFinder:
    @staticmethod
    def is_cc_byte(ea):
        return ida_bytes.get_byte(ea) == 0xCC

    @classmethod
    def find_cc_sequences(cls, start_ea, end_ea, min_length=1):
        result = []
        current_start = None
        ea = start_ea
        while ea < end_ea:
            if cls.is_cc_byte(ea):
                if current_start is None:
                    current_start = ea
            else:
                if current_start is not None:
                    seq_len = ea - current_start
                    if seq_len >= min_length:
                        result.append((current_start, ea - 1, seq_len))
                    current_start = None  # Reset sequence tracking
            # Ensure we handle potential invalid addresses during iteration
            try:
                # Advance byte by byte for simple CC check
                ea += 1
            except:
                break  # Stop if issues occur

        # Handle sequence ending exactly at end_ea
        if current_start is not None:
            seq_len = end_ea - current_start
            if seq_len >= min_length:
                # The end address in the tuple is inclusive
                result.append((current_start, end_ea - 1, seq_len))
        return result

    @staticmethod
    def is_special_sequence(ea):
        bytes_at_ea = ida_bytes.get_bytes(ea, 5)
        if not bytes_at_ea:
            return False
        sequences = [
            b"\x66\x90",
            b"\x0f\x1f\x00",
            b"\x0f\x1f\x40\x00",
            b"\x0f\x1f\x44\x00\x00",
            b"\x66\x0f\x1f\x44\x00\x00",
            b"\x0f\x1f\x80\x00\x00\x00\x00",
            b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
            b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
            b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
            b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
        ]
        short_sequences = [s for s in sequences if len(s) <= len(bytes_at_ea)]
        return any(bytes_at_ea.startswith(seq) for seq in short_sequences)


# --- Prologue/Epilogue Analysis ---
# (Implementation remains the same as previous version)
def is_likely_prologue(prologue_ea: int, search_limit_bytes: int = 0x20) -> bool:
    insn = ida_ua.insn_t()
    current_ea = prologue_ea
    instr_count = 0
    push_count = 0
    found_sub_rsp = False
    found_mov_rbp_rsp = False

    # NEW: Check for 0x66 0x90 followed by an additional alignment NOP pattern.
    # If the first two bytes equal 0x66 0x90 and the following bytes also match a special alignment sequence,
    # then we immediately consider this a likely prologue.
    initial_bytes = ida_bytes.get_bytes(prologue_ea, 2)
    if initial_bytes == b"\x66\x90" and FunctionPaddingFinder.is_special_sequence(
        prologue_ea + 2
    ):
        log_boundary.debug(
            f"0x{prologue_ea:X}: Found 0x66 0x90 followed by an alignment NOP sequence."
        )
        return True

    # Original check for initial alignment NOPs.
    is_initial_nop = FunctionPaddingFinder.is_special_sequence(current_ea)
    if is_initial_nop:
        log_boundary.debug(f"0x{prologue_ea:X}: Starts with Alignment NOP.")
        # Skip initial NOPs to check what follows
        temp_ea = current_ea
        while FunctionPaddingFinder.is_special_sequence(temp_ea):
            nop_insn = ida_ua.insn_t()
            nop_size = ida_ua.decode_insn(nop_insn, temp_ea)
            if nop_size <= 0:
                break
            temp_ea += nop_size
            if temp_ea >= prologue_ea + search_limit_bytes:
                break  # Don't search too far
        current_ea = temp_ea  # Start checking instructions after NOPs

    end_search_ea = prologue_ea + search_limit_bytes

    while current_ea < end_search_ea and instr_count < PROLOGUE_INSTR_CHECK_LIMIT:

        size = ida_ua.decode_insn(insn, current_ea)
        if size <= 0:
            # Failed to decode, might be data or invalid instruction
            break

        mnem = insn.get_canon_mnem()
        log_boundary.debug(f"0x{current_ea:X}: {mnem} {insn.ops}")
        # Standard Frame Setup: push rbp; mov rbp, rsp
        # Check if this is the *first* non-NOP instruction
        if (
            instr_count == 0
            and mnem == "push"
            and insn.ops[0].type == ida_ua.o_reg
            and insn.ops[0].reg == idautils.procregs.rbp.reg
        ):
            next_ea = current_ea + size
            next_insn = ida_ua.insn_t()
            next_size = ida_ua.decode_insn(next_insn, next_ea)
            if next_size > 0 and next_insn.get_canon_mnem() == "mov":
                op0 = next_insn.ops[0]
                op1 = next_insn.ops[1]
                if (
                    op0.type == ida_ua.o_reg
                    and op0.reg == idautils.procregs.rbp.reg
                    and op1.type == ida_ua.o_reg
                    and op1.reg == idautils.procregs.rsp.reg
                ):
                    log_boundary.debug(
                        f"0x{prologue_ea:X}: Found push rbp; mov rbp, rsp."
                    )
                    found_mov_rbp_rsp = True  # Mark this pattern found
                    # Don't return immediately, check for sub rsp too

        # Alternative: Multiple Pushes (common in non-frame pointer optimized code)
        if mnem == "push" and insn.ops[0].type == ida_ua.o_reg:
            push_count += 1

        # Stack Allocation: sub rsp, imm
        if (
            mnem == "sub"
            and insn.ops[0].type == ida_ua.o_reg
            and insn.ops[0].reg == idautils.procregs.rsp.reg
            and insn.ops[1].type == ida_ua.o_imm
        ):
            found_sub_rsp = True
            log_boundary.debug(f"0x{current_ea:X}: Found sub rsp, imm.")
        # Less common but possible: lea rsp, [rsp-imm] or similar stack adjustments

        current_ea += size
        instr_count += 1
        # If we found the standard frame setup, and maybe a sub rsp, that's good enough
        if found_mov_rbp_rsp:
            return True

    # Heuristics based on observed patterns after the loop:
    if found_mov_rbp_rsp:
        return True  # If standard frame was found
    if push_count >= 1 and found_sub_rsp:  # push reg(s); sub rsp, N
        log_boundary.debug(
            f"0x{prologue_ea:X}: Found {push_count} push(es) and sub rsp early."
        )
        return True
    if push_count >= 2 and instr_count <= 3:  # Multiple pushes early on
        log_boundary.debug(f"0x{prologue_ea:X}: Found {push_count} pushes early.")
        return True

    # If we only found alignment NOPs at the very start and nothing else significant
    if is_initial_nop and instr_count == 0:
        log_boundary.debug(
            f"0x{prologue_ea:X}: Only found initial NOP(s). Considering it a potential start boundary."
        )
        return True  # Consider it a start if NOPs are present

    return False


# --- Check Functions for _search_range ---
# (Implementations remain the same as previous version)
def _check_is_int3(insn: ida_ua.insn_t) -> bool:
    return insn.get_canon_mnem() == "int3"


def _check_is_align_nop(insn: ida_ua.insn_t) -> bool:
    return FunctionPaddingFinder.is_special_sequence(insn.ea)


def _check_is_push_rbp(insn: ida_ua.insn_t) -> bool:
    return (
        insn.get_canon_mnem() == "push"
        and insn.ops[0].type == ida_ua.o_reg
        and insn.ops[0].reg == idautils.procregs.rbp.reg
    )


def _check_is_ret_or_jmp(insn: ida_ua.insn_t) -> bool:
    mnem = insn.get_canon_mnem()
    return mnem == "retn" or mnem.startswith("j")


# --- Function Start Finders ---
# (Implementations remain the same as previous version)
def find_start_near_cursor(
    cursor_ea: int, limit: int = NEAR_CURSOR_SEARCH_LIMIT
) -> int:
    """
    Searches backward from cursor_ea for a likely function start indicator
    (padding, alignment, or prologue). Prioritizes padding/alignment.
    """
    log_boundary.debug(
        f"Searching near cursor backward from 0x{cursor_ea:X} (limit 0x{limit:X})."
    )
    current_ea = cursor_ea
    best_prologue_candidate = idaapi.BADADDR
    checked_prologues = set()  # Avoid re-checking the same prologue address

    # Limit iterations to prevent infinite loops in unusual cases
    search_boundary = max(0, cursor_ea - limit)
    iteration_count = 0
    max_iterations = limit * 2  # Generous limit based on byte limit

    while (
        current_ea != idaapi.BADADDR
        and current_ea >= search_boundary
        and iteration_count < max_iterations
    ):
        iteration_count += 1
        # Check current address first (cursor might be on the prologue)
        item_head = idc.get_item_head(current_ea)  # Work with item heads
        if item_head == idaapi.BADADDR:
            item_head = current_ea  # Fallback

        if item_head not in checked_prologues:
            log_boundary.debug(f"Checking prologue candidate at 0x{item_head:X}")
            if is_likely_prologue(item_head):
                log_boundary.debug(
                    f"Near cursor: Found prologue candidate at 0x{item_head:X}"
                )
                # Store the highest address prologue found so far that's <= cursor_ea
                if item_head <= cursor_ea and (
                    best_prologue_candidate == idaapi.BADADDR
                    or item_head > best_prologue_candidate
                ):
                    best_prologue_candidate = item_head
            checked_prologues.add(item_head)

        # Check what precedes the current item head
        prev_ea = idc.prev_head(
            item_head
        )  # Look at the head of the item *before* the current one

        if (
            prev_ea == idaapi.BADADDR
            or prev_ea >= item_head
            or prev_ea < search_boundary
        ):
            break  # Stop if invalid, no progress, or limit exceeded

        # Check if prev_ea is padding (0xCC) or alignment NOP
        # We need to check the *byte* at prev_ea, not the whole item
        is_padding = FunctionPaddingFinder.is_cc_byte(prev_ea)
        # Check if the item starting at prev_ea is an alignment sequence
        is_align = FunctionPaddingFinder.is_special_sequence(prev_ea)

        if is_padding or is_align:
            # The function start is the address *after* the padding/alignment, which is item_head
            potential_start = item_head
            boundary_type = "CC padding" if is_padding else "Alignment NOP"
            log_boundary.info(
                f"Near cursor: Found start 0x{potential_start:X} preceded by {boundary_type} at 0x{prev_ea:X}."
            )
            # Ensure this potential start is also a likely prologue for higher confidence
            if is_likely_prologue(potential_start):
                log_boundary.debug(
                    f"Confirmed start 0x{potential_start:X} is also a prologue."
                )
                return potential_start
            else:
                # If preceded by padding/align, it's likely the start even if prologue isn't standard
                log_boundary.debug(
                    f"Start 0x{potential_start:X} after padding/align is NOT a typical prologue, but accepting due to boundary."
                )
                return potential_start

        # Move to the previous item head for the next iteration
        current_ea = prev_ea

    # If loop finished without finding padding/alignment boundary, return best prologue found
    if best_prologue_candidate != idaapi.BADADDR:
        log_boundary.info(
            f"Near cursor: No padding/alignment found. Using best prologue candidate 0x{best_prologue_candidate:X}."
        )
        return best_prologue_candidate
    else:
        log_boundary.debug(
            "Near cursor: No likely start (padding, alignment, or prologue) found within limit."
        )
        return idaapi.BADADDR


def find_function_start_backward(
    search_start_ea: int, limit: int = BACKWARD_SEARCH_LIMIT
) -> int:
    """Searches backward from function end using _search_range (Fallback)."""
    log_boundary.debug(
        f"Fallback: Searching backward from 0x{search_start_ea:X} (limit 0x{limit:X})."
    )
    boundary_starts = []
    search_end_ea = search_start_ea  # Where the search originates (e.g., function end)
    search_limit_addr = max(0, search_start_ea - limit)

    # --- Search for potential boundaries ---
    # Search for INT3 (0xCC)
    found_int3_ea = _search_range(
        search_end_ea,
        _check_is_int3,
        max_range=limit,
        strategy=SearchStrategy.BACKWARD_SCAN,
    )
    if found_int3_ea is not None:
        start_after = idc.next_head(found_int3_ea)
        if start_after != idaapi.BADADDR and start_after < search_end_ea:
            log_boundary.debug(
                f"Found potential start 0x{start_after:X} after INT3 at 0x{found_int3_ea:X}"
            )
            boundary_starts.append(start_after)

    # Search for Alignment NOPs
    found_align_ea = _search_range(
        search_end_ea,
        _check_is_align_nop,
        max_range=limit,
        strategy=SearchStrategy.BACKWARD_SCAN,
    )
    if found_align_ea is not None:
        # Alignment NOPs can be multi-byte, find the end of the instruction/item
        align_end = idc.get_item_end(found_align_ea)
        start_after = align_end  # Start is immediately after the alignment sequence
        if start_after != idaapi.BADADDR and start_after < search_end_ea:
            log_boundary.debug(
                f"Found potential start 0x{start_after:X} after Align NOP at 0x{found_align_ea:X}"
            )
            boundary_starts.append(start_after)

    # Search for RET or JMP (less reliable boundary, but possible)
    found_ret_jmp_ea = _search_range(
        search_end_ea,
        _check_is_ret_or_jmp,
        max_range=limit,
        strategy=SearchStrategy.BACKWARD_SCAN,
    )
    if found_ret_jmp_ea is not None:
        start_after = idc.next_head(found_ret_jmp_ea)
        if start_after != idaapi.BADADDR and start_after < search_end_ea:
            log_boundary.debug(
                f"Found potential start 0x{start_after:X} after RET/JMP at 0x{found_ret_jmp_ea:X}"
            )
            boundary_starts.append(start_after)

    # --- Search for Prologues directly ---
    # Search for PUSH RBP (common prologue start)
    found_push_rbp_ea = _search_range(
        search_end_ea,
        _check_is_push_rbp,
        max_range=limit,
        strategy=SearchStrategy.BACKWARD_SCAN,
    )
    # Check if the found 'push rbp' is actually part of a likely prologue sequence
    if found_push_rbp_ea is not None and is_likely_prologue(found_push_rbp_ea):
        log_boundary.debug(
            f"Found potential start (push rbp prologue) at 0x{found_push_rbp_ea:X}"
        )
        boundary_starts.append(found_push_rbp_ea)
    elif found_push_rbp_ea is not None:
        log_boundary.debug(
            f"Found push rbp at 0x{found_push_rbp_ea:X}, but not deemed likely prologue start."
        )

    # --- Determine Best Candidate ---
    best_boundary_start = idaapi.BADADDR
    if boundary_starts:
        # Filter valid starts within the search range and prefer higher addresses (closer to search_start_ea)
        valid_boundary_starts = [
            ea
            for ea in boundary_starts
            if ea != idaapi.BADADDR and ea < search_end_ea and ea >= search_limit_addr
        ]
        if valid_boundary_starts:
            # Prioritize starts that are also likely prologues
            prologue_starts = [
                ea for ea in valid_boundary_starts if is_likely_prologue(ea)
            ]
            if prologue_starts:
                best_boundary_start = max(
                    prologue_starts
                )  # Take the highest address prologue start
                log_boundary.info(
                    f"Fallback: Determined start (boundary + prologue): 0x{best_boundary_start:X}"
                )
            else:
                # If no prologue starts found among boundaries, take the highest boundary address found
                best_boundary_start = max(valid_boundary_starts)
                log_boundary.info(
                    f"Fallback: Determined start (boundary only, highest address): 0x{best_boundary_start:X}"
                )

    # If no boundary found, but a standalone push rbp was found (and verified as prologue), use it
    # This condition might be redundant now due to the check inside the loop, but keep for safety
    if (
        best_boundary_start == idaapi.BADADDR
        and found_push_rbp_ea is not None
        and found_push_rbp_ea in boundary_starts
    ):
        best_boundary_start = found_push_rbp_ea
        log_boundary.info(
            f"Fallback: Determined start (push rbp prologue): 0x{best_boundary_start:X}"
        )

    if best_boundary_start != idaapi.BADADDR:
        return best_boundary_start
    else:
        log_boundary.warning(
            f"Fallback: Could not determine function start backward from 0x{search_start_ea:X}."
        )
        return idaapi.BADADDR


# --- NEW: Helper to Determine Alignment ---
def _determine_alignment(address: int, max_check: int = MAX_ALIGNMENT_CHECK) -> int:
    """
    Determines the alignment boundary (power of 2) for a given address.
    Returns the largest power of 2 (up to max_check) that divides the address.
    Returns 1 if not aligned to 2 or higher.
    """
    if address == idaapi.BADADDR or address == 0:
        return 1  # Cannot determine alignment for invalid or zero address

    # Check from largest power of 2 down to 2
    alignment = max_check
    while alignment >= 2:
        # Check if alignment is a power of 2 (optional sanity check)
        # if (alignment & (alignment - 1)) == 0:
        if (address % alignment) == 0:
            return alignment
        # Reduce alignment check (e.g., 16 -> 8 -> 4 -> 2)
        # A simple way is integer division by 2
        alignment //= 2
        # Or, more robustly for any max_check: find next lower power of 2
        # alignment = 1 << (alignment.bit_length() - 2) # Example if needed

    return 1  # Default: 1-byte alignment


# --- UPDATED: Helper to Undefine and Align Adjacent CC Padding ---
def undefine_and_align_adjacent_cc_padding(
    boundary_ea: int, direction: str, limit: int = ADJACENT_PADDING_SEARCH_LIMIT
):
    """
    Finds a contiguous block of 0xCC bytes immediately before (backward)
    or after (forward) boundary_ea, undefines it, and then attempts
    to create an alignment directive based on the address being aligned.
    """
    log_boundary.debug(
        f"Checking for CC padding {direction} from 0x{boundary_ea:X} (limit {limit})"
    )
    if direction not in ["backward", "forward"]:
        log_boundary.error(
            "Invalid direction for undefine_and_align_adjacent_cc_padding"
        )
        return

    padding_start_ea = idaapi.BADADDR
    padding_end_ea = idaapi.BADADDR  # Exclusive end address
    count = 0

    if direction == "backward":
        current_ea = boundary_ea - 1
        first_cc_ea = idaapi.BADADDR
        for i in range(limit):
            if not FunctionPaddingFinder.is_cc_byte(current_ea):
                break  # End of sequence
            first_cc_ea = current_ea
            count += 1
            # Move backward safely
            prev = idc.prev_head(current_ea)
            if (
                prev == idaapi.BADADDR or prev >= current_ea
            ):  # Stop if invalid or no progress
                current_ea = idaapi.BADADDR  # Mark end of search
                break
            current_ea = prev

        if count > 0 and first_cc_ea != idaapi.BADADDR:
            # The start of the padding block is the *lowest* address CC byte found
            padding_start_ea = first_cc_ea - (count - 1)  # Calculate actual start
            padding_end_ea = (
                boundary_ea  # End address for del_items/create_align is exclusive
            )

    elif direction == "forward":
        current_ea = boundary_ea
        last_cc_ea = idaapi.BADADDR
        for i in range(limit):
            if not FunctionPaddingFinder.is_cc_byte(current_ea):
                break  # End of sequence
            if count == 0:
                padding_start_ea = current_ea  # Mark start on first CC
            last_cc_ea = current_ea
            count += 1
            # Move forward safely
            next_ea = idc.next_head(current_ea)
            if (
                next_ea == idaapi.BADADDR or next_ea <= current_ea
            ):  # Stop if invalid or no progress
                current_ea = idaapi.BADADDR
                break
            current_ea = next_ea

        if count > 0 and padding_start_ea != idaapi.BADADDR:
            # End address is one byte *after* the last CC byte
            padding_end_ea = last_cc_ea + 1

    # --- Undefine and Align ---
    if (
        count > 0
        and padding_start_ea != idaapi.BADADDR
        and padding_end_ea != idaapi.BADADDR
    ):
        padding_len = padding_end_ea - padding_start_ea
        if padding_len <= 0:  # Sanity check
            log_boundary.error(
                f"Invalid padding length calculated: {padding_len} at 0x{padding_start_ea:X}"
            )
            return

        log_boundary.info(
            f"Found {count} CC padding bytes from 0x{padding_start_ea:X} to 0x{padding_end_ea-1:X}."
        )

        # 1. Undefine the padding block
        log_boundary.debug(
            f"Undefining range 0x{padding_start_ea:X} (len {padding_len})"
        )
        if not ida_bytes.del_items(
            padding_start_ea, ida_bytes.DELIT_SIMPLE, padding_len
        ):
            log_boundary.warning(
                f"Failed to undefine CC padding at 0x{padding_start_ea:X}. May already be undefined or error."
            )
            # Proceed even if undefine fails, maybe it's already undefined

        # 2. Determine the address being aligned
        aligned_address = idaapi.BADADDR
        if direction == "backward":
            aligned_address = boundary_ea  # Padding before func aligns the func start
        elif direction == "forward":
            aligned_address = (
                padding_end_ea  # Padding after func aligns the item *after* the padding
            )

        # 3. Determine the alignment value
        alignment_value = 1
        if aligned_address != idaapi.BADADDR:
            alignment_value = _determine_alignment(aligned_address, MAX_ALIGNMENT_CHECK)

        # 4. Create the alignment directive if alignment > 1
        if alignment_value > 1:
            log_boundary.info(
                f"Applying ALIGN {alignment_value} directive at 0x{padding_start_ea:X} (length {padding_len}) for address 0x{aligned_address:X}"
            )
            # ida_bytes.create_align expects the alignment *value* (e.g., 16, 8, 4, 2)
            if ida_bytes.create_align(padding_start_ea, padding_len, alignment_value):
                log_boundary.debug("Alignment directive created successfully.")
            else:
                log_boundary.warning(
                    f"Failed to create ALIGN {alignment_value} directive at 0x{padding_start_ea:X}."
                )
                # Maybe try creating data if align fails?
                # ida_bytes.create_data(padding_start_ea, ida_bytes.FF_BYTE, 1, idaapi.BADADDR) # Example: mark as byte
        else:
            log_boundary.debug(
                f"No specific alignment (>1) detected for address 0x{aligned_address:X}. Padding at 0x{padding_start_ea:X} left undefined or as bytes."
            )
            # Optionally, mark as data bytes if no alignment
            # if count > 0:
            #    ida_bytes.create_data(padding_start_ea, ida_bytes.FF_BYTE, count, idaapi.BADADDR)

    else:
        log_boundary.debug(
            f"No adjacent CC padding found {direction} from 0x{boundary_ea:X}."
        )


# --- Main Orchestration Function ---
def find_and_define_function_boundary():
    cursor_ea = idaapi.get_screen_ea()
    if cursor_ea == idaapi.BADADDR:
        log_boundary.error("Invalid cursor position.")
        ida_kernwin.warning(
            "Cannot determine function boundary: Invalid cursor position."
        )
        return

    log_boundary.info(f"Starting boundary search from cursor: 0x{cursor_ea:X}")
    search_ea = cursor_ea
    func_end_ea = idaapi.BADADDR
    func_end_search_limit = cursor_ea + FORWARD_SEARCH_LIMIT

    # --- Find Potential End ---
    while search_ea < func_end_search_limit:
        # Find the next 0xC3 byte
        ret_ea, _ = _bin_search(search_ea, func_end_search_limit, [0xC3])
        if ret_ea == idaapi.BADADDR:
            log_boundary.debug(f"No further 'retn' (0xC3) found after 0x{search_ea:X}.")
            break  # Stop searching for end if no more retn found

        log_boundary.debug(f"Potential 'retn' at 0x{ret_ea:X}")

        # Check if the byte is actually part of an instruction defined as retn
        temp_insn = ida_ua.insn_t()
        is_actual_ret = False
        if (
            ida_ua.decode_insn(temp_insn, ret_ea) > 0
            and temp_insn.get_canon_mnem() == "retn"
        ):
            is_actual_ret = True
        # If not code, or decode fails, or it's not retn, it might be data (0xC3 byte)
        if not is_actual_ret:
            log_boundary.debug(
                f"0x{ret_ea:X} contains 0xC3 but is not defined as 'retn' instruction. Skipping."
            )
            search_ea = ret_ea + 1  # Continue searching after this byte
            continue

        # Now we have a confirmed 'retn' instruction at ret_ea
        next_ea = ret_ea + temp_insn.size  # Next address is after the retn instruction

        # Heuristic 1: Check for standard 0xCC padding immediately after retn
        if FunctionPaddingFinder.is_cc_byte(next_ea):
            log_boundary.info(
                f"Found CC padding immediately after retn @ 0x{ret_ea:X}. Assuming end."
            )
            func_end_ea = ret_ea
            break

        # Heuristic 2: Check for alignment NOPs or a likely function prologue shortly after retn
        prologue_search_start = next_ea
        found_next_boundary = False
        # Skip any initial alignment NOPs right after the retn
        temp_ea = prologue_search_start
        skipped_nop_count = 0
        while (
            FunctionPaddingFinder.is_special_sequence(temp_ea) and skipped_nop_count < 5
        ):  # Limit NOP skip
            nop_insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(nop_insn, temp_ea)
            if size <= 0:
                break
            temp_ea += size
            skipped_nop_count += 1

        prologue_search_start = temp_ea  # Start checking for prologue after NOPs

        # Check within a small range after retn (+ skipped NOPs) for a prologue
        for i in range(PROLOGUE_SEARCH_LIMIT // 4):  # Check a few alignment offsets
            potential_prologue_ea = idc.get_item_head(prologue_search_start + i)
            if (
                potential_prologue_ea == idaapi.BADADDR
                or potential_prologue_ea
                >= prologue_search_start + PROLOGUE_SEARCH_LIMIT
            ):
                continue  # Skip invalid or too far addresses

            # Avoid re-checking the same head address if i > 0
            if i > 0 and potential_prologue_ea == idc.get_item_head(
                prologue_search_start + i - 1
            ):
                continue

            # Ensure we don't check inside the current function's potential range
            if potential_prologue_ea <= ret_ea:
                continue

            log_boundary.debug(
                f"Checking for next function prologue near 0x{potential_prologue_ea:X}"
            )
            if is_likely_prologue(potential_prologue_ea):
                log_boundary.info(
                    f"Found next function prologue near 0x{potential_prologue_ea:X}. Assuming end @ 0x{ret_ea:X}."
                )
                func_end_ea = ret_ea
                found_next_boundary = True
                break
        if found_next_boundary:
            break  # Found end based on next prologue

        # If neither padding nor next prologue found, this retn might be spurious
        log_boundary.debug(
            f"No padding or likely next prologue found after retn @ 0x{ret_ea:X}. Continuing search."
        )
        search_ea = next_ea  # Continue searching *after* this retn instruction

    # --- Final End Determination ---
    if func_end_ea == idaapi.BADADDR:
        log_boundary.error(
            "Could not determine function end within search limit or based on heuristics."
        )
        ida_kernwin.warning("Could not determine function end.")
        return

    # The function end address for add_func should be exclusive, so it's func_end_ea + size_of_retn
    # Let's re-decode the retn at func_end_ea to be sure of its size
    retn_insn = ida_ua.insn_t()
    retn_size = ida_ua.decode_insn(retn_insn, func_end_ea)
    if retn_size <= 0:
        log_boundary.warning(
            f"Could not decode final retn instruction at 0x{func_end_ea:X}. Using size 1."
        )
        retn_size = 1
    # The actual end for add_func is the address *after* the retn
    add_func_end_addr = func_end_ea + retn_size
    # The inclusive end address (last byte of the function) is func_end_ea + retn_size - 1
    inclusive_func_end_ea = add_func_end_addr - 1

    log_boundary.info(
        f"Determined function end instruction at 0x{func_end_ea:X}. Inclusive end: 0x{inclusive_func_end_ea:X}. Add_func end: 0x{add_func_end_addr:X}"
    )

    # --- Find Potential Start (Prioritize Near Cursor) ---
    func_start_ea = find_start_near_cursor(cursor_ea)

    if func_start_ea == idaapi.BADADDR:
        log_boundary.info(
            "Near-cursor search failed. Using fallback: search backward from function end."
        )
        # Use the determined end address (inclusive) as the starting point for backward search
        func_start_ea = find_function_start_backward(
            inclusive_func_end_ea
        )  # Search back from the last byte
        
    # --- Validate and Define ---
    if func_start_ea == idaapi.BADADDR:
        log_boundary.error("Could not determine function start.")
        ida_kernwin.warning(
            f"Determined end 0x{inclusive_func_end_ea:X}, but could not determine start."
        )
        return

    # Final sanity check on boundaries: start must be less than the *exclusive* end address
    if func_start_ea >= add_func_end_addr:
        log_boundary.error(
            f"Boundary validation failed: Start 0x{func_start_ea:X} >= Exclusive End 0x{add_func_end_addr:X}."
        )
        ida_kernwin.warning("Boundary calculation failed (start >= end).")
        return

    log_boundary.info(
        f"Proposed boundaries: START=0x{func_start_ea:X}, END (inclusive)=0x{inclusive_func_end_ea:X}"
    )
    prompt_msg = f"Likely boundaries:\nStart: 0x{func_start_ea:X}\nEnd:   0x{inclusive_func_end_ea:X} (inclusive)\n\nDefine function?"
    user_choice = ida_kernwin.ask_yn(1, prompt_msg)

    if user_choice == 1:
        log_boundary.info("User confirmed. Defining function.")
        # Calculate length for del_items (exclusive end - start)
        func_len = add_func_end_addr - func_start_ea

        # 1. Check for any function overlapping the candidate range and delete it.
        existing_func = ida_funcs.get_func(func_start_ea)
        if existing_func is not None:
            log_boundary.info(
                f"Overlapping function found at 0x{existing_func.start_ea:X}. Deleting it."
            )
            if not ida_funcs.del_func(existing_func.start_ea):
                log_boundary.warning(
                    f"Failed to delete overlapping function at 0x{existing_func.start_ea:X}."
                )
            ida_auto.auto_wait()

        # 2. Undefine the range.
        log_boundary.debug(
            f"1. Undefining range 0x{func_start_ea:X} - 0x{inclusive_func_end_ea:X} (length {func_len})"
        )
        if not ida_bytes.del_items(func_start_ea, ida_bytes.DELIT_SIMPLE, func_len):
            log_boundary.warning("Undefine range failed (maybe already undefined?).")

        # 3. Mark the range as code and force reanalysis.
        log_boundary.debug(
            f"2. Marking range 0x{func_start_ea:X} - 0x{add_func_end_addr:X} as code"
        )
        ida_auto.auto_mark_range(func_start_ea, add_func_end_addr, ida_auto.AU_CODE)
        ida_auto.plan_and_wait(func_start_ea, add_func_end_addr, True)
        ida_auto.auto_wait()

        # 4. Attempt to create the function.
        log_boundary.debug(
            f"3. Calling add_func(0x{func_start_ea:X}, 0x{add_func_end_addr:X})"
        )
        if ida_funcs.add_func(func_start_ea, add_func_end_addr):
            log_boundary.info(f"Successfully created function at 0x{func_start_ea:X}")
            ida_kernwin.info(
                f"Function created: 0x{func_start_ea:X} - 0x{inclusive_func_end_ea:X}"
            )

            # Re-analyze the function range.
            log_boundary.debug(
                f"4. Re-analyzing range 0x{func_start_ea:X} - 0x{add_func_end_addr:X}"
            )
            ida_auto.plan_and_wait(func_start_ea, add_func_end_addr, True)

            # Reset disassembly problems.
            log_boundary.debug(
                f"5. Resetting problems in range 0x{func_start_ea:X} - 0x{add_func_end_addr:X}"
            )
            reset_problems_in_function(func_start_ea, add_func_end_addr)

            # Cleanup adjacent CC padding.
            log_boundary.debug("6. Cleaning up adjacent padding")
            try:
                undefine_and_align_adjacent_cc_padding(
                    func_start_ea, "backward", limit=ADJACENT_PADDING_SEARCH_LIMIT
                )
                undefine_and_align_adjacent_cc_padding(
                    add_func_end_addr, "forward", limit=ADJACENT_PADDING_SEARCH_LIMIT
                )
            except Exception as e:
                log_boundary.error(f"Error during adjacent padding cleanup: {e}")

            # Refresh views and jump.
            log_boundary.debug(f"7. Refreshing views and jumping to 0x{func_start_ea:X}")
            ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
            ida_kernwin.refresh_idaview_anyway()
            ida_kernwin.jumpto(func_start_ea)
        else:
            log_boundary.error(
                f"ida_funcs.add_func(0x{func_start_ea:X}, 0x{add_func_end_addr:X}) failed."
            )
            ida_kernwin.warning(
                "Failed to create function in IDA. The range might be left in an inconsistent state (undefined but marked as code)."
            )
            ida_auto.plan_and_wait(func_start_ea, add_func_end_addr, True)
            reset_problems_in_function(func_start_ea, add_func_end_addr)
            ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
            ida_kernwin.refresh_idaview_anyway()
    elif user_choice == 0:
        log_boundary.info("User declined function creation.")
    else:  # user_choice == -1
        log_boundary.info("User cancelled.")

# --- Main Execution ---
if __name__ == "__main__":
    idaapi.auto_wait()
    print("--- Function Boundary Finder ---")
    find_and_define_function_boundary()
    print("--- Search Complete ---")
