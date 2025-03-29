import logging
import typing
from enum import Enum, auto

import ida_bytes
import ida_funcs
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc
from mutilz.helpers.ida import clear_output, find_byte_sequence
from mutilz.logconf import configure_logging

logger = logging.getLogger("wsigs")


class SearchStrategy(Enum):
    BACKWARD_SCAN = auto()
    FORWARD_CHUNK = auto()


def _search_range(
    ea: int,
    check_instruction: typing.Callable[[ida_ua.insn_t], bool],
    max_range: int = 0x200,
    strategy: SearchStrategy = SearchStrategy.BACKWARD_SCAN,
) -> typing.Optional[int]:
    # (Implementation remains the same as previous correct version)
    if strategy == SearchStrategy.BACKWARD_SCAN:
        start_addr = max(ea - max_range, 0)
        current = ea
        while current >= start_addr:
            if not ida_bytes.is_loaded(current):
                current -= 1
                continue
            insn = ida_ua.insn_t()
            prev_head_ea = idc.prev_head(current)
            if prev_head_ea == idc.BADADDR or prev_head_ea < start_addr:
                break
            if not ida_bytes.is_loaded(prev_head_ea):
                current = prev_head_ea
                continue
            if ida_ua.decode_insn(insn, prev_head_ea) > 0:
                if check_instruction(insn):
                    return insn.ea
                current = prev_head_ea
            else:
                current -= 1
    elif strategy == SearchStrategy.FORWARD_CHUNK:
        current = ea
        end_addr = ea + max_range
        while current < end_addr:
            if not ida_bytes.is_loaded(current):
                current += 1
                continue
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, current)
            if insn_len > 0:
                if check_instruction(insn):
                    return current
                current += insn.size
            else:
                current += 1
    logger.debug(
        "No anchor found within range [0x%X - 0x%X] relative to 0x%X",
        max_range,
        max_range,
        ea,
    )
    return None


def set_type(ea, type_str, name):
    """
    Applies a C-style type declaration and name to an address in IDA,
    undefining the required range first.
    """
    logger.debug(f"Attempting to set type at 0x{ea:X}: '{type_str}' with name '{name}'")

    tif = ida_typeinf.tinfo_t()
    # Parse first to get type information
    if not idaapi.parse_decl(tif, None, type_str, 0):  # Flags=0 (default)
        logger.error(f"Error parsing type declaration: '{type_str}'")
        if idaapi.set_name(ea, name, idaapi.SN_NOCHECK | idaapi.SN_FORCE):
            logger.info(f"Parsed type failed, but set name '{name}' at 0x{ea:X}.")
        else:
            logger.error(
                f"Parsed type failed AND failed to set name '{name}' at 0x{ea:X}."
            )
        return False

    # *** CORRECTED: Get size using the tinfo_t object's get_size() method ***
    size = tif.get_size()
    # get_size() returns BADSIZE on error or unknown size. BADSIZE is typically idc.BADADDR.
    # Also check for zero size, which is usually invalid for data types.
    if size == idaapi.BADSIZE or size == 0:
        logger.error(
            f"Could not determine valid size for type '{type_str}' at 0x{ea:X}. Calculated size: {size} (BADSIZE={idaapi.BADSIZE})"
        )
        # Optionally try setting name anyway? Let's return False.
        return False

    logger.debug(
        f"Type requires size: {size} bytes. Undefining range 0x{ea:X} to 0x{ea + size - 1:X}."
    )

    # Undefine the entire range needed for the type
    # Using ida_bytes.DELIT_EXPAND is generally safer
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size):
        logger.warning(
            f"Could not fully undefine {size} bytes at 0x{ea:X} before applying type. Proceeding anyway."
        )

    # Now attempt to apply the type
    if idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
        logger.info(f"Type applied successfully at 0x{ea:X}.")
        # Set name using idaapi
        if idaapi.set_name(ea, name, idaapi.SN_NOCHECK | idaapi.SN_FORCE):
            logger.info(f"Name '{name}' set successfully at 0x{ea:X}.")
            return True
        else:
            logger.warning(
                f"Type applied at 0x{ea:X}, but failed to rename to '{name}'."
            )
            return True  # Type applied, so return True
    else:
        logger.error(
            f"Failed to apply type '{type_str}' at 0x{ea:X} (size {size}). Range might still contain conflicting items."
        )
        # Attempt to set name even if apply_tinfo failed
        if idaapi.set_name(ea, name, idaapi.SN_NOCHECK | idaapi.SN_FORCE):
            logger.info(f"Applied type failed, but set name '{name}' at 0x{ea:X}.")
        else:
            logger.error(
                f"Applied type failed AND failed to set name '{name}' at 0x{ea:X}."
            )
        return False


def apply_signature(ea, sig):
    """
    Applies a function signature using idaapi.
    """
    name = idc.get_func_name(ea)
    if not name:
        name = f"sub_{ea:X}"
        logger.warning(
            f"Address 0x{ea:X} is not the start of a function, using default name '{name}'"
        )

    ret, args = sig
    logger.info(f"Applying signature to 0x{ea:x} ({name})")
    decl = "{} {}({})".format(ret, name, args)

    tif = ida_typeinf.tinfo_t()
    if idaapi.parse_decl(tif, None, decl, 0):
        if idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
            logger.info(f"Successfully applied signature to {name}")
            idaapi.set_name(ea, name, idaapi.SN_NOCHECK)
        else:
            logger.error(f"Failed to apply signature tinfo to {name} at 0x{ea:X}")
    else:
        logger.error(f"Failed to parse signature declaration: {decl}")


# --- Rest of the classes (GarbageBlobFinder, FunctionPaddingFinder) ---
# --- and execute() function remain the same as the previous correct version ---


class GarbageBlobFinder:
    # (Implementation remains the same as previous correct version)
    @staticmethod
    def _check(insn: ida_ua.insn_t) -> bool:
        mnem = insn.get_canon_mnem().lower()
        if mnem == "lea" and insn.ops[0].type == ida_ua.o_reg:
            dest_reg = idaapi.get_reg_name(insn.ops[0].reg, 8)
            if dest_reg and (dest_reg.lower() == "rdi" or dest_reg.lower() == "rdx"):
                if insn.ops[1].type == ida_ua.o_imm:
                    logger.debug("Found matching lea (rdi/rdx, imm) @ 0x%X", insn.ea)
                    return True
                elif insn.ops[1].type in [ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far]:
                    target_ea = idc.get_operand_value(insn.ea, 1)
                    if target_ea != idc.BADADDR:
                        logger.debug(
                            "Found matching lea (rdi/rdx, mem) @ 0x%X -> 0x%X",
                            insn.ea,
                            target_ea,
                        )
                        return True
        return False

    @classmethod
    def get_garbage_blobs(cls):
        text_seg = idaapi.get_segm_by_name(".text")
        if not text_seg:
            logger.error("Error: .text section not found.")
            return
        first_xref_to_text = None
        for xref in idautils.XrefsTo(text_seg.start_ea, 0):
            if not ida_bytes.is_loaded(xref.frm):
                continue
            seg_name = idc.get_segm_name(xref.frm)
            if seg_name == ".text":
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, xref.frm) > 0:
                    mnem = insn.get_canon_mnem().lower()
                    op1_type = insn.ops[0].type
                    op1_reg_name = ""
                    if op1_type == ida_ua.o_reg:
                        op1_reg_name = idaapi.get_reg_name(insn.ops[0].reg, 8)
                        if op1_reg_name:
                            op1_reg_name = op1_reg_name.lower()
                    op2_val = idc.get_operand_value(xref.frm, 1)
                    if (
                        mnem == "lea"
                        and op1_type == ida_ua.o_reg
                        and op1_reg_name == "rdi"
                        and op2_val == text_seg.start_ea
                    ):
                        logger.info(
                            f"Found potential blob 0 init: lea rdi, 0x{text_seg.start_ea:X} at 0x{xref.frm:X}"
                        )
                        first_xref_to_text = xref
                        yield xref
                        break
        if not first_xref_to_text:
            logger.warning("Could not find initial 'lea rdi, .text_start' instruction.")
            for xref in idautils.XrefsTo(text_seg.start_ea, 0):
                if not ida_bytes.is_loaded(xref.frm):
                    continue
                seg_name = idc.get_segm_name(xref.frm)
                if seg_name == ".text":
                    logger.warning(
                        f"Using fallback xref to .text start from 0x{xref.frm:X}"
                    )
                    first_xref_to_text = xref
                    yield xref
                    break
            if not first_xref_to_text:
                logger.error("No xref found to .text segment start from within .text.")
                return
        search_base_ea = first_xref_to_text.frm
        found_blob12 = False
        next_addr = idc.next_head(search_base_ea)
        if next_addr != idc.BADADDR and ida_bytes.is_loaded(next_addr):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, next_addr) > 0 and cls._check(insn):
                op_val = idc.get_operand_value(next_addr, 1)
                if op_val != idc.BADADDR and op_val > text_seg.start_ea:
                    try:
                        xref_to_blob12 = next(idautils.XrefsTo(op_val, 0))
                        logger.info(
                            f"Found potential blob 12 init (next insn): 0x{next_addr:X} -> 0x{op_val:X}"
                        )
                        yield xref_to_blob12
                        found_blob12 = True
                    except StopIteration:
                        logger.warning(
                            f"Instruction at 0x{next_addr:X} points to 0x{op_val:X}, but no xrefs found *to* it."
                        )
        if not found_blob12:
            prev_addr = idc.prev_head(search_base_ea)
            if prev_addr != idc.BADADDR and ida_bytes.is_loaded(prev_addr):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, prev_addr) > 0 and cls._check(insn):
                    op_val = idc.get_operand_value(prev_addr, 1)
                    if op_val != idc.BADADDR and op_val > text_seg.start_ea:
                        try:
                            xref_to_blob12 = next(idautils.XrefsTo(op_val, 0))
                            logger.info(
                                f"Found potential blob 12 init (prev insn): 0x{prev_addr:X} -> 0x{op_val:X}"
                            )
                            yield xref_to_blob12
                            found_blob12 = True
                        except StopIteration:
                            logger.warning(
                                f"Instruction at 0x{prev_addr:X} points to 0x{op_val:X}, but no xrefs found *to* it."
                            )
        if not found_blob12:
            search_strategies = [
                (SearchStrategy.BACKWARD_SCAN, search_base_ea),
                (SearchStrategy.FORWARD_CHUNK, idc.next_head(search_base_ea)),
            ]
            for strategy, start_ea in search_strategies:
                if start_ea == idc.BADADDR:
                    continue
                if not ida_bytes.is_loaded(start_ea):
                    logger.debug(
                        f"Skipping search from non-loaded address 0x{start_ea:X}"
                    )
                    continue
                logger.debug(
                    f"Searching for blob 12 init near 0x{start_ea:X} using {strategy.name}"
                )
                found_ea = _search_range(
                    start_ea, cls._check, max_range=0x50, strategy=strategy
                )
                if found_ea:
                    op_val = idc.get_operand_value(found_ea, 1)
                    if (
                        op_val != idc.BADADDR
                        and op_val != text_seg.start_ea
                        and op_val > text_seg.start_ea
                    ):
                        try:
                            xref_to_blob12 = next(idautils.XrefsTo(op_val, 0))
                            logger.info(
                                f"Found potential blob 12 init (nearby search): 0x{found_ea:X} -> 0x{op_val:X}"
                            )
                            yield xref_to_blob12
                            found_blob12 = True
                            break
                        except StopIteration:
                            logger.warning(
                                f"Instruction at 0x{found_ea:X} points to 0x{op_val:X}, but no xrefs found *to* it."
                            )
                if found_blob12:
                    break
        if not found_blob12:
            logger.warning(
                "Could not find a likely candidate for blob 12 initialization near blob 0."
            )

    @classmethod
    def get_tls_region(cls):
        blob_addresses = set()
        for xref in cls.get_garbage_blobs():
            if ida_bytes.is_loaded(xref.to):
                blob_addresses.add(xref.to)
            else:
                logger.warning(f"Xref target 0x{xref.to:X} is not loaded, skipping.")
        blobs = sorted(list(blob_addresses))
        logger.info(
            f"Identified potential blob start addresses: {[hex(b) for b in blobs]}"
        )
        return blobs


class FunctionPaddingFinder:
    # (Implementation remains the same as previous correct version)
    @staticmethod
    def is_cc_byte(ea):
        try:
            if ida_bytes.is_loaded(ea):
                return ida_bytes.get_byte(ea) == 0xCC
            return False
        except Exception as e:
            return False

    @classmethod
    def find_cc_sequences(cls, start_ea, end_ea, min_length=2):
        result = []
        current_start = None
        ea = start_ea
        logger.debug(f"Scanning for CC sequences from 0x{start_ea:X} to 0x{end_ea:X}")
        while ea < end_ea:
            if cls.is_cc_byte(ea):
                if current_start is None:
                    current_start = ea
            else:
                if current_start is not None:
                    seq_len = ea - current_start
                    if seq_len >= min_length:
                        logger.debug(
                            f"Found CC sequence: 0x{current_start:X}-0x{ea-1:X} (len {seq_len})"
                        )
                        result.append((current_start, ea - 1, seq_len))
                    current_start = None
            ea += 1
        if current_start is not None:
            last_ea = end_ea - 1
            if cls.is_cc_byte(last_ea):
                seq_len = end_ea - current_start
                if seq_len >= min_length:
                    logger.debug(
                        f"Found CC sequence ending at boundary: 0x{current_start:X}-0x{last_ea:X} (len {seq_len})"
                    )
                    result.append((current_start, last_ea, seq_len))
        logger.debug(f"Found {len(result)} CC sequences in total.")
        return result

    @staticmethod
    def is_special_sequence(ea):
        if not ida_bytes.is_loaded(ea):
            return False
        bytes_at_ea = ida_bytes.get_bytes(ea, 3)
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

    @classmethod
    def find_padding_from_cursor(
        cls,
        cursor_pos,
        iteration_count,
        start_offset=0x1000,
        ending_offset=0x2000,
        min_len=2,
    ) -> bool:
        start_range = cursor_pos + start_offset
        end_range = cursor_pos + ending_offset
        if not ida_bytes.is_loaded(start_range) or not ida_bytes.is_loaded(
            end_range - 1
        ):
            logger.warning(
                f"Search range 0x{start_range:X} - 0x{end_range:X} is not fully loaded. Aborting search."
            )
            return False
        print(f"Searching for CC padding from 0x{start_range:X} to 0x{end_range:X}...")
        cc_sequences = cls.find_cc_sequences(start_range, end_range, min_length=min_len)
        if not cc_sequences:
            print("No CC padding found in the specified range.")
            return False
        found_and_defined = False
        for seq_start, seq_end, seq_len in cc_sequences:
            next_ea = seq_end + 1
            if not ida_bytes.is_loaded(next_ea):
                logger.debug(
                    f"Address after CC sequence (0x{next_ea:X}) is not loaded. Skipping."
                )
                continue
            is_aligned = (next_ea & 0xF) == 0
            is_special = cls.is_special_sequence(next_ea)
            if is_aligned or is_special:
                predicate_reason = "aligned" if is_aligned else "special sequence"
                print(
                    f"Found {seq_len} CC bytes at 0x{seq_start:X} - 0x{seq_end:X} (predicate match: {predicate_reason} at 0x{next_ea:X})"
                )
                array_length = seq_start - cursor_pos
                print(
                    f"  -> Calculated array length relative to 0x{cursor_pos:X}: {array_length} (0x{array_length:X})"
                )
                if array_length <= 0:
                    logger.warning(
                        f"Calculated array length is non-positive ({array_length}). Skipping."
                    )
                    continue
                name = f"g_bufInitBlob{iteration_count}"
                type_str = f"const unsigned __int8 {name}[{array_length}];"
                prompt_msg = (
                    f"Found potential blob at 0x{cursor_pos:X}.\n"
                    f"Padding starts at 0x{seq_start:X} (length {seq_len}).\n"
                    f"Calculated array size: {array_length} (0x{array_length:X}).\n\n"
                    f"Define as:\n{type_str}\n\n"
                    f"Proceed?"
                )
                user_choice = ida_kernwin.ask_yn(0, prompt_msg)
                if user_choice == 1:  # Yes
                    logger.info(
                        f"User confirmed. Attempting to define array at 0x{cursor_pos:X}: {type_str}"
                    )
                    # Calls the updated set_type function
                    if set_type(cursor_pos, type_str, name):
                        logger.info(f"Successfully defined {name} at 0x{cursor_pos:X}")
                        found_and_defined = True
                        break
                    else:
                        logger.error(
                            f"Failed to define {name} at 0x{cursor_pos:X}. Check logs."
                        )
                        found_and_defined = False
                        break
                elif user_choice == 0:  # No
                    logger.info(f"User declined to define array at 0x{cursor_pos:X}.")
                    break
                else:  # Cancel (-1)
                    logger.info(f"User cancelled operation at 0x{cursor_pos:X}.")
                    break
            else:
                print(
                    f"Found {seq_len} CC bytes at 0x{seq_start:X} - 0x{seq_end:X} (does not match predicate at 0x{next_ea:X})"
                )
        if not found_and_defined and cc_sequences:
            print(
                "Found CC sequences, but either none matched the predicate, the user declined/cancelled, or definition failed."
            )
        return found_and_defined


def execute():
    """
    Main execution function.
    """
    garbage_blobs = GarbageBlobFinder.get_tls_region()
    if not garbage_blobs:
        logger.error("Could not identify any garbage blob start addresses. Aborting.")
        return

    garbage_blob0 = garbage_blobs[0]
    logger.info(
        "Using garbage_blob0: 0x%X as base for array definition.", garbage_blob0
    )

    if len(garbage_blobs) > 1:
        garbage_blob12 = garbage_blobs[1]
        logger.info("Identified garbage_blob12: 0x%X", garbage_blob12)
        for i, blob_ea in enumerate(garbage_blobs[2:]):
            logger.info(f"Identified additional blob {i+2}: 0x{blob_ea:X}")

    print("\n=== Function Padding Finder ===")
    iteration_count = 0

    print(f"Processing padding relative to cursor: 0x{garbage_blob0:X}")
    if not ida_bytes.is_loaded(garbage_blob0):
        logger.error(
            f"Base address garbage_blob0 (0x{garbage_blob0:X}) is not loaded. Cannot proceed."
        )
        return

    if FunctionPaddingFinder.find_padding_from_cursor(garbage_blob0, iteration_count):
        iteration_count += 1
        print(f"Successfully defined array for g_bufInitBlob{iteration_count-1}")
    else:
        print(f"Did not define array based on padding relative to 0x{garbage_blob0:X}")

    print("\nScript execution completed!")


if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(
        log=logger, level=logging.INFO
    )  # Set to DEBUG for more verbose output
    execute()
    idaapi.refresh_idaview_anyway()


"""
export void prep_crc(HANDLE hProcess) {
    const auto results = pattern_scan_module(hProcess, "48 ?? ?? 1E 0F 83", true);
    if (results.empty()) return;

    for (const auto addr : results) {
        auto instruction_start = addr + 4;
        std::vector<uint8_t> instructions(6);

        if (!read_memory(hProcess, instruction_start, instructions))
            continue;

        if (is_unconditional_jump(instructions))
            continue;

        if (is_jump(instructions)) {
            int32_t jump_size = *reinterpret_cast<int32_t*>(&instructions[2]);
            int32_t new_jump_size = jump_size + 1;

            std::vector<uint8_t> jump_bytes = { 0xE9 };
            jump_bytes.insert(jump_bytes.end(), reinterpret_cast<uint8_t*>(&new_jump_size), reinterpret_cast<uint8_t*>(&new_jump_size) + sizeof(new_jump_size));

            write_memory(hProcess, instruction_start, jump_bytes);
        }
    }
}

export void prep_protected(HANDLE hProcess) {
    modify_function(hProcess, "E8 ?? ?? ?? ?? 84 C0 74 ?? 8B 83 ?? ?? ?? ?? 2B C7", { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 });
}

export void prep_ret_check(HANDLE hProcess) {
    modify_function(hProcess, "E8 ?? ?? ?? ?? 48 8B ?? ?? 8B ?? 48 8B ?? ?? 48 8B ?? ?? 48 8D ?? ?? ?? C3", { 0xC2, 0x00, 0x00 });
}

"""
