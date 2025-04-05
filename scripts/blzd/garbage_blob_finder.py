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
# Default search range offsets from cursor for padding
DEFAULT_PADDING_SEARCH_START_OFFSET = 0x1000
DEFAULT_PADDING_SEARCH_MAX_DISTANCE = (
    0x2000  # Max distance from cursor for *any* heuristic
)
DEFAULT_MIN_PADDING_LEN = 2


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
    # (Implementation remains the same)
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
        name_flags = idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_PUBLIC
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


# --- GarbageBlobFinder Class (Unchanged) ---
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


# --- FunctionPaddingFinder Class (Modified) ---
class FunctionPaddingFinder:

    @staticmethod
    def is_cc_byte(ea):
        """Checks if the byte at the given address is 0xCC."""
        try:
            if ida_bytes.is_loaded(ea):
                return ida_bytes.get_byte(ea) == 0xCC
            return False
        except Exception:  # Catch potential IDA exceptions
            logger.error(f"Error reading byte at 0x{ea:X}", exc_info=True)
            return False

    @classmethod
    def find_cc_sequences(cls, start_ea, end_ea, min_length=2):
        """Finds sequences of 0xCC bytes within a range."""
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
            # Handle potential errors during byte read
            if not ida_bytes.is_loaded(ea):
                logger.warning(f"Address 0x{ea:X} became unloaded during scan.")
                break  # Stop scan if we hit unloaded memory
            ea += 1

        # Check if a sequence ends exactly at end_ea
        if current_start is not None:
            seq_len = end_ea - current_start
            if seq_len >= min_length:
                logger.debug(
                    f"Found CC sequence ending at boundary: 0x{current_start:X}-0x{end_ea-1:X} (len {seq_len})"
                )
                result.append((current_start, end_ea - 1, seq_len))

        logger.debug(f"Found {len(result)} CC sequences in total in the range.")
        return result

    @staticmethod
    def is_special_sequence(ea):
        """Checks if the address starts with known multi-byte NOP sequences."""
        if not ida_bytes.is_loaded(ea):
            return False
        # Known multi-byte NOPs (Intel Optimization Manual)
        sequences = [
            b"\x66\x90",  # xchg ax,ax
            b"\x0f\x1f\x00",  # nop dword ptr [rax]
            b"\x0f\x1f\x40\x00",  # nop dword ptr [rax + 0]
            b"\x0f\x1f\x44\x00\x00",  # nop dword ptr [rax + rax*1 + 0]
            b"\x66\x0f\x1f\x44\x00\x00",  # nop word ptr [rax + rax*1 + 0]
            b"\x0f\x1f\x80\x00\x00\x00\x00",  # nop dword ptr [rax + 0]
            b"\x0f\x1f\x84\x00\x00\x00\x00\x00",  # nop dword ptr [rax + rax*1 + 0]
            b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # nop word ptr [rax + rax*1 + 0]
            # Add more if needed, up to a reasonable length
        ]
        max_len = max(len(s) for s in sequences)
        bytes_at_ea = ida_bytes.get_bytes(ea, max_len)
        if not bytes_at_ea:
            return False

        return any(bytes_at_ea.startswith(seq) for seq in sequences)

    @classmethod
    def _check_predicate_and_prompt(
        cls,
        cursor_pos: int,
        iteration_count: int,
        seq_start: int,
        seq_len: int,
        next_ea: int,
        heuristic_name: str,
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """
        Helper to check alignment/special sequence predicate and prompt user.
        Returns (seq_start, seq_len, next_ea) if user confirms, else None.
        """
        if not ida_bytes.is_loaded(next_ea):
            logger.debug(
                f"Address after potential padding (0x{next_ea:X}) is not loaded. Skipping."
            )
            return None

        is_aligned = (next_ea % 16) == 0  # Check for 16-byte alignment
        is_special = cls.is_special_sequence(next_ea)

        if is_aligned or is_special:
            predicate_reason = (
                "16-byte aligned" if is_aligned else "special NOP sequence"
            )
            print(
                f"[{heuristic_name}] Found {seq_len} CC bytes at 0x{seq_start:X} - 0x{seq_start + seq_len - 1:X}"
            )
            print(
                f"  -> Predicate match: next address 0x{next_ea:X} is {predicate_reason}."
            )

            array_length = seq_start - cursor_pos
            print(
                f"  -> Calculated array length relative to 0x{cursor_pos:X}: {array_length} (0x{array_length:X})"
            )

            if array_length <= 0:
                logger.warning(
                    f"Calculated array length is non-positive ({array_length}). Skipping."
                )
                return None

            name = BLOB_NAME_PATTERN.format(idx=iteration_count)
            type_str = f"const unsigned __int8 {name}[{array_length}];"
            prompt_msg = (
                f"Found potential blob at 0x{cursor_pos:X} (using {heuristic_name}).\n"
                f"Padding starts at 0x{seq_start:X} (length {seq_len}).\n"
                f"Next item starts at 0x{next_ea:X} ({predicate_reason}).\n"
                f"Calculated array size: {array_length} (0x{array_length:X}).\n\n"
                f"Define as:\n{type_str}\n\n"
                f"Proceed?"
            )
            user_choice = ida_kernwin.ask_yn(0, prompt_msg)

            if user_choice == 1:  # Yes
                logger.info(
                    f"User confirmed. Will define array at 0x{cursor_pos:X}: {type_str}"
                )
                return (seq_start, seq_len, next_ea)
            elif user_choice == 0:  # No
                logger.info(f"User declined to define array at 0x{cursor_pos:X}.")
                return None  # User declined this specific finding
            else:  # Cancel (-1)
                logger.info(f"User canceled operation at 0x{cursor_pos:X}.")
                raise UserWarning("User cancelled operation")  # Propagate cancellation

        else:
            logger.debug(
                f"Found {seq_len} CC bytes at 0x{seq_start:X}-0x{seq_start + seq_len - 1:X}, "
                f"but predicate failed at 0x{next_ea:X} (not aligned or special NOP)."
            )
            return None  # Predicate failed

    @classmethod
    def find_padding_from_cursor(
        cls,
        cursor_pos: int,
        iteration_count: int,
        start_offset: int = DEFAULT_PADDING_SEARCH_START_OFFSET,
        max_search_distance: int = DEFAULT_PADDING_SEARCH_MAX_DISTANCE,
        min_len: int = DEFAULT_MIN_PADDING_LEN,
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """
        Finds padding (CC bytes) after a cursor position using multiple heuristics.

        Args:
            cursor_pos: The starting address (likely blob start).
            iteration_count: The current blob index being searched for (e.g., 0, 1, ...).
            start_offset: The offset from cursor_pos to start the primary search.
            max_search_distance: The maximum offset from cursor_pos to search.
            min_len: The minimum number of CC bytes to consider as padding.

        Returns:
            A tuple (padding_start_ea, padding_length, next_item_ea) if padding
            is found, confirmed by the user, and meets predicates.
            Returns None otherwise.
            Raises UserWarning if the user cancels the operation via the prompt.
        """
        search_start_ea = cursor_pos + start_offset
        search_end_ea = cursor_pos + max_search_distance

        if not ida_bytes.is_loaded(search_start_ea) or not ida_bytes.is_loaded(
            search_end_ea - 1  # Check last byte of range too
        ):
            logger.warning(
                f"Search range 0x{search_start_ea:X} - 0x{search_end_ea:X} is not fully loaded. Aborting search."
            )
            return None

        # --- Heuristic 1: Search for CC sequences in the full range ---
        print(
            f"Searching for CC padding from 0x{search_start_ea:X} to 0x{search_end_ea:X}..."
        )
        cc_sequences = cls.find_cc_sequences(
            search_start_ea, search_end_ea, min_length=min_len
        )

        if cc_sequences:
            logger.info(f"Found {len(cc_sequences)} CC sequence(s) in the range.")
            for seq_start, seq_end, seq_len in cc_sequences:
                next_ea = seq_end + 1
                try:
                    result = cls._check_predicate_and_prompt(
                        cursor_pos,
                        iteration_count,
                        seq_start,
                        seq_len,
                        next_ea,
                        "CC Sequence Scan",
                    )
                    if result:
                        return result  # User confirmed this one
                except UserWarning:
                    return None  # User cancelled

            print(
                "Found CC sequences, but none met the predicate or were confirmed by the user."
            )
        else:
            print("No CC padding sequences found within the primary search range.")

        # --- Heuristic 2: Find next function and check preceding bytes ---
        print(
            f"\nAttempting heuristic: Find next function within 0x{max_search_distance:X} bytes..."
        )
        next_func_ea = idc.get_next_func(cursor_pos)

        if next_func_ea == idaapi.BADADDR:
            print("No function found after the cursor position.")
            return None

        if next_func_ea >= search_end_ea:
            print(
                f"Next function at 0x{next_func_ea:X} is beyond the maximum search distance (0x{search_end_ea:X})."
            )
            return None

        logger.info(
            f"Found next function at 0x{next_func_ea:X}. Checking bytes immediately before it."
        )

        # Scan backwards from next_func_ea - 1 for CC bytes
        pad_end_ea = next_func_ea - 1
        pad_start_ea = idaapi.BADADDR
        current_ea = pad_end_ea
        cc_count = 0

        while current_ea >= cursor_pos:  # Don't scan back past the blob start
            if not ida_bytes.is_loaded(current_ea):
                logger.warning(
                    f"Encountered unloaded byte at 0x{current_ea:X} while scanning backwards from function start."
                )
                break  # Stop if we hit unloaded memory
            if cls.is_cc_byte(current_ea):
                pad_start_ea = current_ea  # Keep track of the earliest CC
                cc_count += 1
                current_ea -= 1
            else:
                break  # End of CC sequence

        if cc_count >= min_len:
            pad_len = cc_count  # Or next_func_ea - pad_start_ea
            logger.info(
                f"Found {pad_len} CC bytes immediately preceding function at 0x{next_func_ea:X} (from 0x{pad_start_ea:X} to 0x{pad_end_ea:X})"
            )
            try:
                # The 'next_ea' for the predicate is the function start itself
                result = cls._check_predicate_and_prompt(
                    cursor_pos,
                    iteration_count,
                    pad_start_ea,
                    pad_len,
                    next_func_ea,
                    "Next Function Boundary",
                )
                if result:
                    return result  # User confirmed this one
            except UserWarning:
                return None  # User cancelled
        else:
            print(
                f"Did not find sufficient CC padding (found {cc_count}, need {min_len}) immediately before function at 0x{next_func_ea:X}."
            )

        # --- All heuristics failed ---
        print("\nAll heuristics failed to find suitable padding.")
        return None


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

    # --- Find potential blob locations (Optional but good context) ---
    # garbage_blobs = GarbageBlobFinder.get_tls_region()
    # if not garbage_blobs:
    #     logger.warning("Could not identify any garbage blob start addresses via LEA analysis. Relying solely on cursor.")
    # return # Or maybe proceed anyway based on cursor? Let's proceed.

    # if garbage_blobs:
    #     logger.info("Using garbage_blob0: 0x%X as potential base.", garbage_blobs[0])
    #     if len(garbage_blobs) > 1:
    #         logger.info("Identified potential garbage_blob12: 0x%X", garbage_blobs[1])

    print("\n=== Function Padding Finder ===")
    current_ea = idaapi.get_screen_ea()
    print(f"Processing padding relative to cursor: 0x{current_ea:X}")
    if not ida_bytes.is_loaded(current_ea):
        logger.error(f"Base address 0x{current_ea:X} not loaded.")
        return

    # Call finder - it returns padding info if user confirmed, or None, or raises UserWarning
    padding_result = None
    try:
        padding_result = FunctionPaddingFinder.find_padding_from_cursor(
            current_ea,
            current_blob_index,
            start_offset=DEFAULT_PADDING_SEARCH_START_OFFSET,
            max_search_distance=DEFAULT_PADDING_SEARCH_MAX_DISTANCE,
            min_len=DEFAULT_MIN_PADDING_LEN,
        )
    except UserWarning as e:
        print(f"\nOperation cancelled by user: {e}")
        return  # Stop execution if user cancelled

    if padding_result:
        pad_start, pad_len, next_ea = padding_result
        blob_name = BLOB_NAME_PATTERN.format(idx=current_blob_index)
        array_len = (
            pad_start - current_ea
        )  # Calculate array length based on where padding starts
        blob_type_str = f"const unsigned __int8 {blob_name}[{array_len}];"

        logger.info(
            f"Attempting to define main blob: {blob_type_str} at 0x{current_ea:X}"
        )
        if set_type(current_ea, blob_type_str, blob_name):
            logger.info(f"Successfully defined {blob_name} (PUBLIC).")
            # Reset cache *after* successful definition
            reset_blob_index_cache()
            logger.info(
                f"Blob index cache reset. Next run will search for index {get_next_blob_index()}."
            )

            # --- Now handle the padding alignment ---
            align_exponent = _determine_alignment_exponent(next_ea)
            align_val = 1 << align_exponent  # Calculate 2^exponent
            logger.info(
                f"Attempting to align padding at 0x{pad_start:X} (len {pad_len}) to {align_val} bytes (exponent {align_exponent}) based on next item at 0x{next_ea:X}."
            )

            # Undefine padding first
            if not ida_bytes.del_items(pad_start, ida_bytes.DELIT_EXPAND, pad_len):
                logger.warning(
                    f"Could not fully undefine padding range 0x{pad_start:X}-0x{pad_start+pad_len-1:X}."
                )

            # Create the alignment directive if needed (exponent > 0)
            if align_exponent > 0:
                # IDA's create_align uses the *length* and the *exponent*
                if ida_bytes.create_align(pad_start, pad_len, align_exponent):
                    logger.info(f"Successfully created align directive for padding.")
                else:
                    logger.error(
                        f"Failed to create align directive for padding at 0x{pad_start:X} (len {pad_len}, exp {align_exponent})."
                    )
                    # Fallback: Mark as byte data if alignment fails
                    logger.info("Marking padding as byte data as fallback.")
                    ida_bytes.create_data(
                        pad_start, ida_bytes.FF_BYTE, pad_len, idaapi.BADADDR
                    )

            else:
                logger.info(
                    f"No specific alignment needed (align=1) for padding at 0x{pad_start:X}. Marking as byte data."
                )
                # Mark as byte data if no alignment needed
                ida_bytes.create_data(
                    pad_start, ida_bytes.FF_BYTE, pad_len, idaapi.BADADDR
                )

        else:
            logger.error(
                f"Failed to define main blob {blob_name}. Skipping padding alignment."
            )
            # Note: Cache was *not* reset because definition failed.

    else:
        # find_padding_from_cursor returned None (no match or user declined)
        print(
            f"\nDid not define array for index {current_blob_index} based on padding relative to 0x{current_ea:X}."
        )

    print("\nScript execution completed!")


# --- Main Execution ---
if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(
        log=logger, level=logging.INFO
    )  # Use DEBUG for more detailed logs
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
