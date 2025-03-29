# -*- coding: utf-8 -*-
import logging
import math
import typing

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt  # For _bin_search encoding
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

# --- Configuration ---
FORWARD_SEARCH_LIMIT = 0x1000  # How far to search forward for 0xC3
PROLOGUE_SEARCH_LIMIT = 0x40  # How far after 0xC3 to look for next prologue
PROLOGUE_INSTR_CHECK_LIMIT = 5  # How many instructions to check in is_likely_prologue
BACKWARD_SEARCH_LIMIT = 0x300  # How far back to search for function start

# --- Logging Setup ---
log_boundary = logging.getLogger("FuncBoundary")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
log_boundary.setLevel(logging.DEBUG)  # Be verbose during development


# --- Binary Search Helper ---
def _bin_search(start, end, pattern) -> int:
    """returns the address if found, else idaapi.BADADDR"""
    patterns = ida_bytes.compiled_binpat_vec_t()
    # Handle potential None/empty pattern
    if not pattern:
        log_boundary.error("Empty pattern provided to _bin_search")
        return idaapi.BADADDR
    # Allow integers or bytes objects in pattern list
    try:
        seqstr = " ".join(
            [
                (
                    f"{b:02x}"
                    if isinstance(b, int) and b != -1
                    else (
                        "?"
                        if isinstance(b, int) and b == -1
                        else b.hex() if isinstance(b, bytes) else "?"
                    )
                )
                for b in pattern
            ]
        )
    except Exception as e:
        log_boundary.error(f"Error formatting pattern {pattern}: {e}")
        return idaapi.BADADDR

    # Use default 1-byte encoding
    enc_idx = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
    err = ida_bytes.parse_binpat_str(patterns, start, seqstr, 16, enc_idx)

    if err:
        log_boundary.error(
            f"Failed to parse binary pattern string: '{seqstr}' Error: {err}"
        )
        return idaapi.BADADDR

    # Ensure start and end are valid
    if not ida_bytes.is_loaded(start) or not ida_bytes.is_loaded(
        end - 1 if end > start else start
    ):
        log_boundary.warning(f"Search range 0x{start:X}-0x{end:X} is not fully loaded.")
        # Adjust end if necessary, or return error? Let's try adjusting.
        max_ea = ida_segment.get_last_seg().end_ea
        end = min(end, max_ea)
        if start >= end:
            return idaapi.BADADDR

    return ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)


# --- Reusable Padding Finder ---
# (Simplified version from previous script)
class FunctionPaddingFinder:
    @staticmethod
    def is_cc_byte(ea):
        try:
            return ida_bytes.is_loaded(ea) and ida_bytes.get_byte(ea) == 0xCC
        except Exception:
            return False

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
                    current_start = None
            ea += 1
        if current_start is not None:
            last_ea = end_ea - 1
            if cls.is_cc_byte(last_ea):
                seq_len = end_ea - current_start
                if seq_len >= min_length:
                    result.append((current_start, last_ea, seq_len))
        return result

    @staticmethod
    def is_special_sequence(ea):
        # Check for common alignment NOPs
        if not ida_bytes.is_loaded(ea):
            return False
        b = ida_bytes.get_bytes(ea, 3)
        if not b:
            return False
        if b.startswith(b"\x66\x90"):
            return True  # xchg ax,ax
        if b.startswith(b"\x0f\x1f"):
            return True  # NOP DWORD/QWORD ptr [EAX+...]
        if b.startswith(b"\x66\x0f\x1f"):
            return True  # NOP WORD ptr [EAX+...]
        # Add more if needed
        return False


# --- Prologue/Epilogue Analysis ---


def is_likely_prologue(prologue_ea: int, search_limit_bytes: int = 0x20) -> bool:
    """Checks if instructions starting at prologue_ea resemble a function prologue."""
    if not ida_bytes.is_loaded(prologue_ea):
        return False

    insn = ida_ua.insn_t()
    current_ea = prologue_ea
    instr_count = 0
    push_count = 0
    found_mov_rbp_rsp = False
    found_sub_rsp = False

    # Check for initial alignment NOPs
    if FunctionPaddingFinder.is_special_sequence(current_ea):
        log_boundary.debug(f"0x{prologue_ea:X}: Starts with alignment NOP.")
        return True

    while (
        current_ea < prologue_ea + search_limit_bytes
        and instr_count < PROLOGUE_INSTR_CHECK_LIMIT
    ):
        size = ida_ua.decode_insn(insn, current_ea)
        if size <= 0:
            # Decoding failed or reached end of defined code
            break

        mnem = insn.get_canon_mnem()

        if (
            instr_count == 0
            and mnem == "push"
            and insn.ops[0].type == ida_ua.o_reg
            and insn.ops[0].reg == idaapi.R_BP
        ):
            # Check for push rbp; mov rbp, rsp
            next_instr_ea = current_ea + size
            next_insn = ida_ua.insn_t()
            next_size = ida_ua.decode_insn(next_insn, next_instr_ea)
            if next_size > 0:
                next_mnem = next_insn.get_canon_mnem()
                if (
                    next_mnem == "mov"
                    and next_insn.ops[0].type == ida_ua.o_reg
                    and next_insn.ops[0].reg == idaapi.R_BP
                    and next_insn.ops[1].type == ida_ua.o_reg
                    and next_insn.ops[1].reg == idaapi.R_SP
                ):
                    log_boundary.debug(
                        f"0x{prologue_ea:X}: Found push rbp; mov rbp, rsp."
                    )
                    return True

        if mnem == "push" and insn.ops[0].type == ida_ua.o_reg:
            push_count += 1

        if (
            mnem == "sub"
            and insn.ops[0].type == ida_ua.o_reg
            and insn.ops[0].reg == idaapi.R_SP
            and insn.ops[1].type == ida_ua.o_imm
        ):
            found_sub_rsp = True

        # Add other checks if needed (e.g., specific register setups)

        current_ea += size
        instr_count += 1

    # Heuristic: Multiple pushes or a sub rsp early on are good signs
    if push_count >= 2:
        log_boundary.debug(f"0x{prologue_ea:X}: Found {push_count} pushes.")
        return True
    if found_sub_rsp and instr_count <= 3:  # sub rsp usually happens early
        log_boundary.debug(f"0x{prologue_ea:X}: Found sub rsp early.")
        return True

    return False


def find_function_start_backward(
    search_start_ea: int, limit: int = BACKWARD_SEARCH_LIMIT
) -> int:
    """Searches backward for a likely function start indicator."""
    log_boundary.debug(
        f"Searching backward from 0x{search_start_ea:X} for function start (limit 0x{limit:X})."
    )
    current_ea = search_start_ea
    potential_start_push_rbp = idaapi.BADADDR
    potential_start_after_pad = idaapi.BADADDR

    for _ in range(limit):  # Limit iterations to prevent infinite loops
        prev_ea = idc.prev_head(current_ea)
        if (
            prev_ea == idaapi.BADADDR
            or prev_ea >= current_ea
            or (search_start_ea - prev_ea) > limit
        ):
            log_boundary.debug("Backward search limit reached or invalid prev_ea.")
            break

        current_ea = prev_ea
        if not ida_bytes.is_loaded(current_ea):
            continue

        flags = ida_bytes.get_flags(current_ea)

        # If we hit padding/alignment, the code *after* it is the start
        if ida_bytes.is_byte(flags) and FunctionPaddingFinder.is_cc_byte(current_ea):
            potential_start_after_pad = idc.next_head(current_ea)
            log_boundary.debug(
                f"Found potential start after CC padding: 0x{potential_start_after_pad:X}"
            )
            break  # Assume this is the boundary
        if ida_bytes.is_align(flags) or FunctionPaddingFinder.is_special_sequence(
            current_ea
        ):
            potential_start_after_pad = idc.next_head(current_ea)
            # Need to potentially skip multiple alignment bytes
            while potential_start_after_pad < search_start_ea and (
                ida_bytes.is_align(ida_bytes.get_flags(potential_start_after_pad))
                or FunctionPaddingFinder.is_special_sequence(potential_start_after_pad)
            ):
                potential_start_after_pad = idc.next_head(potential_start_after_pad)
            log_boundary.debug(
                f"Found potential start after alignment: 0x{potential_start_after_pad:X}"
            )
            break  # Assume this is the boundary

        # If we hit code, check for prologue start
        if ida_bytes.is_code(flags):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, current_ea) > 0:
                mnem = insn.get_canon_mnem()
                # push rbp is a strong indicator
                if (
                    mnem == "push"
                    and insn.ops[0].type == ida_ua.o_reg
                    and insn.ops[0].reg == idaapi.R_BP
                ):
                    potential_start_push_rbp = current_ea
                    log_boundary.debug(
                        f"Found potential start 'push rbp': 0x{current_ea:X}"
                    )
                    # Don't break immediately, might find padding further back

                # If we hit another ret or jmp, the function likely started after it
                if mnem == "retn" or mnem.startswith("j"):
                    potential_start_after_pad = idc.next_head(current_ea)
                    log_boundary.debug(
                        f"Found '{mnem}', assuming start is after: 0x{potential_start_after_pad:X}"
                    )
                    break
        else:
            # Hit non-code, non-padding data? Function likely started after this.
            potential_start_after_pad = idc.next_head(current_ea)
            log_boundary.debug(
                f"Found non-code/non-pad, assuming start is after: 0x{potential_start_after_pad:X}"
            )
            break

    # Prioritize start found after padding/alignment/jmp/ret
    if potential_start_after_pad != idaapi.BADADDR:
        log_boundary.info(
            f"Determined function start (after pad/align/branch): 0x{potential_start_after_pad:X}"
        )
        return potential_start_after_pad
    elif potential_start_push_rbp != idaapi.BADADDR:
        log_boundary.info(
            f"Determined function start (push rbp): 0x{potential_start_push_rbp:X}"
        )
        return potential_start_push_rbp
    else:
        log_boundary.warning(
            f"Could not reliably determine function start backward from 0x{search_start_ea:X}."
        )
        return idaapi.BADADDR


# --- Main Orchestration Function ---


def find_and_define_function_boundary():
    """
    Finds the end of the function at the cursor, determines start, and defines it.
    """
    cursor_ea = idaapi.get_screen_ea()
    log_boundary.info(f"Starting boundary search from cursor: 0x{cursor_ea:X}")

    search_ea = cursor_ea
    func_start_ea = idaapi.BADADDR
    func_end_ea = idaapi.BADADDR

    while search_ea < cursor_ea + FORWARD_SEARCH_LIMIT:
        ret_ea, _ = _bin_search(search_ea, cursor_ea + FORWARD_SEARCH_LIMIT, [0xC3])
        if ret_ea == idaapi.BADADDR:
            log_boundary.warning("No 'retn' (0xC3) found within forward search limit.")
            break

        log_boundary.debug(f"Found potential 'retn' at 0x{ret_ea:X}")

        next_ea = ret_ea + 1
        if not ida_bytes.is_loaded(next_ea):
            log_boundary.debug(
                f"Address after retn (0x{next_ea:X}) not loaded. Assuming end."
            )
            func_end_ea = ret_ea
            break  # Treat as end

        # Scenario A: Check for standard padding
        cc_seqs = FunctionPaddingFinder.find_cc_sequences(
            next_ea, next_ea + 16, min_length=1
        )
        if cc_seqs and cc_seqs[0][0] == next_ea:
            pad_start, pad_end, pad_len = cc_seqs[0]
            log_boundary.info(
                f"Found standard CC padding after retn: 0x{pad_start:X} (len {pad_len}). Assuming function end."
            )
            func_end_ea = ret_ea
            break  # Found likely end

        # Scenario B: Check for next function prologue
        found_prologue = False
        prologue_search_start = next_ea
        # Adjust start if alignment NOPs follow retn
        while (
            FunctionPaddingFinder.is_special_sequence(prologue_search_start)
            and prologue_search_start < next_ea + 16
        ):
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, prologue_search_start)
            if size <= 0:
                break
            prologue_search_start += size

        for i in range(
            PROLOGUE_SEARCH_LIMIT // 2
        ):  # Check potential instruction starts
            potential_prologue_ea = idc.get_item_head(
                prologue_search_start + i
            )  # More robust than next_head sometimes
            if (
                potential_prologue_ea == idaapi.BADADDR
                or potential_prologue_ea
                >= prologue_search_start + PROLOGUE_SEARCH_LIMIT
            ):
                break
            if potential_prologue_ea < prologue_search_start:  # Ensure we move forward
                continue

            log_boundary.debug(f"Checking for prologue at 0x{potential_prologue_ea:X}")
            if is_likely_prologue(potential_prologue_ea):
                log_boundary.info(
                    f"Found likely next function prologue starting near 0x{potential_prologue_ea:X}. Assuming function end."
                )
                func_end_ea = ret_ea
                found_prologue = True
                break  # Found likely end
            # Optimization: if we checked an address, don't check bytes within it again
            # next_check = idc.get_item_end(potential_prologue_ea)
            # if next_check > prologue_search_start + i:
            #      i = next_check - prologue_search_start -1 # Advance loop counter

        if found_prologue:
            break  # Exit outer while loop

        # Scenario C: False positive, continue search
        log_boundary.debug(
            f"No padding or prologue found after 0x{ret_ea:X}. Assuming false positive retn."
        )
        search_ea = ret_ea + 1
        # End of while loop, will search for next 0xC3

    # --- After Loop: Determine Start and Define ---
    if func_end_ea == idaapi.BADADDR:
        log_boundary.error("Could not determine a likely function end address.")
        ida_kernwin.warning("Could not determine function end.")
        return

    func_start_ea = find_function_start_backward(func_end_ea)

    if func_start_ea == idaapi.BADADDR:
        log_boundary.error("Could not determine function start address.")
        ida_kernwin.warning("Determined function end, but could not find start.")
        return

    # Ensure start is before end
    if func_start_ea >= func_end_ea:
        log_boundary.error(
            f"Calculated start 0x{func_start_ea:X} is not before end 0x{func_end_ea:X}."
        )
        ida_kernwin.warning("Function boundary calculation failed (start >= end).")
        return

    log_boundary.info(
        f"Proposed function boundaries: START=0x{func_start_ea:X}, END=0x{func_end_ea:X}"
    )

    # --- User Confirmation ---
    prompt_msg = (
        f"Found likely function boundaries:\n"
        f"Start: 0x{func_start_ea:X}\n"
        f"End:   0x{func_end_ea:X} (inclusive)\n\n"
        f"Define this function?"
    )
    user_choice = ida_kernwin.ask_yn(1, prompt_msg)  # Default Yes

    if user_choice == 1:
        log_boundary.info("User confirmed. Defining function.")
        func_len = func_end_ea - func_start_ea + 1
        add_func_end = func_end_ea + 1  # add_func end is exclusive

        # Undefine first
        log_boundary.debug(f"Undefining range 0x{func_start_ea:X} - 0x{func_end_ea:X}")
        if not ida_bytes.del_items(func_start_ea, ida_bytes.DELIT_EXPAND, func_len):
            # This might fail partially, but add_func might still work
            log_boundary.warning(
                "Failed to fully undefine range before function creation."
            )

        # Create function
        if ida_funcs.add_func(func_start_ea, add_func_end):
            log_boundary.info(f"Successfully created function at 0x{func_start_ea:X}")
            ida_kernwin.info(
                f"Function created: 0x{func_start_ea:X} - 0x{func_end_ea:X}"
            )
            # Optional: Jump to the start
            # idc.jumpto(func_start_ea)
        else:
            log_boundary.error(
                f"ida_funcs.add_func(0x{func_start_ea:X}, 0x{add_func_end:X}) failed."
            )
            ida_kernwin.warning("Failed to create function using add_func.")

    elif user_choice == 0:
        log_boundary.info("User declined function definition.")
    else:  # Cancel
        log_boundary.info("User cancelled operation.")


# --- Main Execution ---
if __name__ == "__main__":
    idaapi.auto_wait()
    # Clear output? Maybe not for this script, user might want to see logs
    # ida_kernwin.msg_clear()
    print("--- Function Boundary Finder ---")
    find_and_define_function_boundary()
    print("--- Search Complete ---")
    # No refresh needed, add_func usually triggers it
