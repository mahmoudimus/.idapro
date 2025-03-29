import logging
import sys
import typing
from enum import Enum, auto

import ida_bytes
import ida_kernwin
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

try:
    from mutilz.helpers.ida import clear_output
    from mutilz.logconf import configure_logging
except ImportError:
    # Placeholder for mutilz functions if not available
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


# --- Constants ---
MAX_BLOB_INDEX = 12
BLOB_NAME_PATTERN = "g_bufInitBlob{idx}"
# Use a shared dictionary in __main__ for script states
SHARED_STATE_DICT_NAME = "g_script_state_storage"
# Key specific to this script within the shared dictionary
CACHE_KEY_NAME = "blob_finder_next_index"


logger = logging.getLogger("wowsigs")


# --- Cache Management Functions (Using Shared Dictionary) ---
def _get_shared_state_dict() -> dict:
    """Gets or creates the shared state dictionary in __main__."""
    main_module = sys.modules["__main__"]
    if not hasattr(main_module, SHARED_STATE_DICT_NAME):
        setattr(main_module, SHARED_STATE_DICT_NAME, {})
        logger.debug(f"Created shared state dictionary: {SHARED_STATE_DICT_NAME}")
    # Ensure it's actually a dictionary (in case something else created the name)
    storage = getattr(main_module, SHARED_STATE_DICT_NAME)
    if not isinstance(storage, dict):
        logger.error(f"{SHARED_STATE_DICT_NAME} in __main__ is not a dict! Resetting.")
        setattr(main_module, SHARED_STATE_DICT_NAME, {})
        storage = getattr(main_module, SHARED_STATE_DICT_NAME)
    return storage


def reset_blob_index_cache():
    """Resets this script's cached next blob index in the shared state."""
    storage = _get_shared_state_dict()
    if CACHE_KEY_NAME in storage:
        del storage[CACHE_KEY_NAME]
        logger.info(f"Blob index cache key '{CACHE_KEY_NAME}' reset.")
    else:
        logger.info(f"Blob index cache key '{CACHE_KEY_NAME}' was not set.")


def _populate_blob_index_cache() -> int:
    """
    Scans for the *lowest* available g_bufInitBlob index (0-12).
    Stores the result under this script's key in the shared state dictionary.
    Returns the lowest available index, or MAX_BLOB_INDEX + 1 if full.
    """
    storage = _get_shared_state_dict()
    logger.debug(f"Populating blob index cache key '{CACHE_KEY_NAME}'...")

    next_idx = MAX_BLOB_INDEX + 1  # Default to "full"

    for idx in range(MAX_BLOB_INDEX + 1):  # Check 0 through 12
        name_to_check = BLOB_NAME_PATTERN.format(idx=idx)
        if idc.get_name_ea_simple(name_to_check) == idaapi.BADADDR:
            # Found the first available index (hole)
            logger.debug(f"Found first available index: {idx}")
            next_idx = idx
            break  # Stop searching

    if next_idx > MAX_BLOB_INDEX:
        logger.warning(f"All blob indices (0-{MAX_BLOB_INDEX}) seem to be used.")
    else:
        logger.info(f"Lowest available blob index determined to be: {next_idx}")

    # Store the determined index in the shared dictionary
    storage[CACHE_KEY_NAME] = next_idx
    return next_idx


def get_next_blob_index() -> int:
    """
    Gets the lowest available blob index (0-12). Uses cached value if available,
    otherwise populates the cache. Returns MAX_BLOB_INDEX + 1 if no indices
    are available.
    """
    storage = _get_shared_state_dict()
    cached_index = storage.get(CACHE_KEY_NAME)  # Use .get for safe access

    if cached_index is not None:
        logger.debug(f"Using cached next blob index: {cached_index}")
        return cached_index
    else:
        # Cache key doesn't exist for this script, populate it
        return _populate_blob_index_cache()


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
    Applies a C-style type declaration and name (as PUBLIC) to an address in IDA,
    undefining the required range first.
    """
    logger.debug(f"Setting type at 0x{ea:X}: '{type_str}' name '{name}' (PUBLIC)")

    tif = ida_typeinf.tinfo_t()
    # Parse first to get type information
    if not idaapi.parse_decl(tif, None, type_str, 0):
        logger.error(f"Error parsing type declaration: '{type_str}'")
        # Still try to set name as public even if type parse failed? Let's try.
        name_flags = (
            idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_PUBLIC
        )  # <-- Add SN_PUBLIC
        if idaapi.set_name(ea, name, name_flags):
            logger.info(
                f"Parsed type failed, but set name '{name}' at 0x{ea:X} (PUBLIC)."
            )
        else:
            logger.error(
                f"Parsed type failed AND failed to set name '{name}' at 0x{ea:X} (public)."
            )
        return False

    # Get size
    size = tif.get_size()
    if size == idaapi.BADSIZE or size == 0:
        logger.error(
            f"Could not determine valid size for type '{type_str}' at 0x{ea:X}. Size: {size}"
        )
        return False

    logger.debug(
        f"Type requires size: {size} bytes. Undefining range 0x{ea:X} to 0x{ea + size - 1:X}."
    )

    # Undefine the entire range
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size):
        logger.warning(
            f"Could not fully undefine {size} bytes at 0x{ea:X}. Proceeding anyway."
        )

    # Apply the type
    if idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
        logger.info(f"Type applied successfully at 0x{ea:X}.")
        name_flags = idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_PUBLIC
        if idaapi.set_name(ea, name, name_flags):
            logger.info(f"Name '{name}' set successfully (PUBLIC).")
            return True
        else:
            logger.warning(
                f"Type applied at 0x{ea:X}, but failed to rename to '{name}' (public)."
            )
            return True  # Type applied, so return True
    else:
        logger.error(
            f"Failed to apply type '{type_str}' at 0x{ea:X} (size {size}). Range might still contain conflicting items."
        )
        name_flags = idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_PUBLIC
        if idaapi.set_name(ea, name, name_flags):
            logger.info(
                f"Applied type failed, but set name '{name}' at 0x{ea:X} (PUBLIC)."
            )
        else:
            logger.error(
                f"Applied type failed AND failed to set name '{name}' at 0x{ea:X} (public)."
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
        padding_info = None  # Store result here
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
                    # Store padding info to return, but don't define here
                    padding_info = (seq_start, seq_len, next_ea)
                    break
                elif user_choice == 0:  # No
                    logger.info(f"User declined to define array at 0x{cursor_pos:X}.")
                    break
                else:  # Cancel (-1)
                    logger.info(f"User canceled operation at 0x{cursor_pos:X}.")
                    break
            else:
                print(
                    f"Found {seq_len} CC bytes at 0x{seq_start:X} - 0x{seq_end:X} (does not match predicate at 0x{next_ea:X})"
                )
        if not padding_info and cc_sequences:
            print(
                "Found CC sequences, but either none matched the predicate, the user declined/cancelled, or definition failed."
            )
        return padding_info  # Return None or (pad_start, pad_len, next_ea)


def execute():
    """
    Main execution function using shared state dictionary and finding lowest index.
    """
    # --- Get the lowest available index ---
    current_blob_index = get_next_blob_index()
    if current_blob_index > MAX_BLOB_INDEX:
        logger.error(f"Cannot proceed: All blob indices (0-{MAX_BLOB_INDEX}) are used.")
        ida_kernwin.warning(
            f"All blob indices (0-{MAX_BLOB_INDEX}) appear to be used.\nRun 'reset_blob_index_cache()' if this is incorrect."
        )
        return

    logger.info(
        f"Attempting to find and define blob for lowest available index: {current_blob_index}"
    )

    # --- Find potential blob locations ---
    garbage_blobs = GarbageBlobFinder.get_tls_region()
    if not garbage_blobs:
        logger.error("Could not identify any garbage blob start addresses. Aborting.")
        return

    # --- Target the first identified blob ---
    garbage_blob0 = garbage_blobs[0]
    logger.info("Using garbage_blob0: 0x%X as base.", garbage_blob0)
    if len(garbage_blobs) > 1:
        logger.info("Identified garbage_blob12: 0x%X", garbage_blobs[1])

    print("\n=== Function Padding Finder ===")
    print(f"Processing padding relative to cursor: 0x{garbage_blob0:X}")
    if not ida_bytes.is_loaded(garbage_blob0):
        logger.error(f"Base address 0x{garbage_blob0:X} not loaded.")
        return

    # Call finder - it returns padding info if user confirmed
    padding_result = FunctionPaddingFinder.find_padding_from_cursor(
        garbage_blob0, current_blob_index
    )

    if padding_result:
        pad_start, pad_len, next_ea = padding_result
        blob_name = BLOB_NAME_PATTERN.format(idx=current_blob_index)
        array_len = pad_start - garbage_blob0  # Recalculate or pass from finder
        blob_type_str = f"const unsigned __int8 {blob_name}[{array_len}];"

        logger.info(f"Attempting to define main blob: {blob_type_str}")
        if set_type(garbage_blob0, blob_type_str, blob_name):
            logger.info(f"Successfully defined {blob_name} (PUBLIC).")
            # Reset cache *after* successful definition
            reset_blob_index_cache()

            # --- Now handle the padding alignment ---
            align_exponent = _determine_alignment_exponent(next_ea)
            align_val = 1 << align_exponent  # Calculate 2^exponent
            logger.info(
                f"Attempting to align padding at 0x{pad_start:X} (len {pad_len}) to {align_val} bytes (exponent {align_exponent})."
            )

            # Undefine padding first
            if not ida_bytes.del_items(pad_start, ida_bytes.DELIT_EXPAND, pad_len):
                logger.warning(
                    f"Could not fully undefine padding range at 0x{pad_start:X}."
                )

            # Create the alignment directive
            if ida_bytes.create_align(pad_start, pad_len, align_exponent):
                logger.info(f"Successfully created align directive for padding.")
            else:
                logger.info(
                    f"No specific alignment needed for padding at 0x{pad_start:X} (next_ea=0x{next_ea:X})."
                )
                # As a fallback, maybe just mark as data?
                # ida_bytes.del_items(pad_start, ida_bytes.DELIT_EXPAND, pad_len)
                # ida_bytes.create_data(pad_start, ida_bytes.FF_BYTE, pad_len, ida_idaapi.BADADDR)

        else:
            logger.error(
                f"Failed to define main blob {blob_name}. Skipping padding alignment."
            )
            # Note: Cache was *not* reset because definition failed.

    else:
        # find_padding_from_cursor returned None (no match or user declined/cancelled)
        print(
            f"Did not define array for index {current_blob_index} based on padding relative to 0x{garbage_blob0:X}."
        )

    print("\nScript execution completed!")


# --- Main Execution ---
if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(log=logger, level=logging.INFO)  # Use DEBUG for more cache info
    execute()
    idaapi.refresh_idaview_anyway()

# --- How to Reset Cache ---
# Run manually from IDA Python console:
# try:
#     import sys
#     del sys.modules['__main__'].g_script_state_storage['blob_finder_next_index']
#     print("Blob index cache key reset.")
# except (AttributeError, KeyError):
#     print("Blob index cache key was not set or storage dict doesn't exist.")
#
# Or, if the script module is loaded as 'my_blob_script':
# my_blob_script.reset_blob_index_cache()
