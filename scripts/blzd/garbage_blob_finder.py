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


logger = logging.getLogger("garbage_blob_finder")


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
    def _check_predicate(cls, next_ea: int) -> typing.Tuple[bool, str]:
        """Checks if the next address meets the alignment or special NOP predicate."""
        if not ida_bytes.is_loaded(next_ea):
            logger.debug(
                f"Predicate check failed: Address 0x{next_ea:X} is not loaded."
            )
            return False, "unloaded"

        is_aligned = (next_ea % 16) == 0  # Check for 16-byte alignment
        is_special = cls.is_special_sequence(next_ea)

        if is_aligned:
            return True, "16-byte aligned"
        elif is_special:
            return True, "special NOP sequence"
        else:
            logger.debug(
                f"Predicate check failed at 0x{next_ea:X} (not 16-byte aligned or special NOP)."
            )
            return False, "failed predicate"

    @classmethod
    def _prompt_user(
        cls,
        cursor_pos: int,
        iteration_count: int,
        pad_start: int,
        pad_len: int,
        next_ea: int,
        predicate_reason: str,
        heuristic_name: str,
        is_fixed_size: bool = False,
        fixed_size: int = 0,
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Prompts the user to confirm the found blob definition (single blob)."""
        if is_fixed_size:
            array_length = fixed_size
            blob_end_ea = cursor_pos + array_length
            print(
                f"[{heuristic_name}] Proposing fixed size definition: {array_length} (0x{array_length:X}) bytes."
            )
            print(
                f"  -> Blob would end at 0x{blob_end_ea:X}, which is {predicate_reason}."
            )
            name = BLOB_NAME_PATTERN.format(idx=iteration_count)
            type_str = f"const unsigned __int8 {name}[{array_length}];"
            prompt_msg = (
                f"{heuristic_name}: No padding found or confirmed.\n"
                f"Define blob with fixed size {array_length} (0x{array_length:X})?\n"
                f"Blob would end at 0x{blob_end_ea:X}, which is {predicate_reason}.\n\n"
                f"Define as:\n{type_str}\n\n"
                f"Proceed?"
            )
        else:
            array_length = pad_start - cursor_pos
            print(
                f"[{heuristic_name}] Found potential padding end at 0x{pad_start:X} (length {pad_len})."
            )
            print(
                f"  -> Predicate match: next address 0x{next_ea:X} is {predicate_reason}."
            )
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
                f"Padding starts at 0x{pad_start:X} (length {pad_len}).\n"
                f"Next item starts at 0x{next_ea:X} ({predicate_reason}).\n"
                f"Calculated array size: {array_length} (0x{array_length:X}).\n\n"
                f"Define as:\n{type_str}\n\n"
                f"Proceed?"
            )

        user_choice = ida_kernwin.ask_yn(0, prompt_msg)

        if user_choice == 1:  # Yes
            logger.info(f"User confirmed definition via {heuristic_name}: {type_str}")
            # Return the simulated structure: (address_after_blob, padding_length, address_after_padding)
            # For fixed size, pad_start is the address *after* the blob, and pad_len is 0.
            return_pad_start = pad_start if not is_fixed_size else next_ea
            return_pad_len = pad_len if not is_fixed_size else 0
            return (return_pad_start, return_pad_len, next_ea)
        elif user_choice == 0:  # No
            logger.info(f"User declined definition from {heuristic_name}.")
            return None  # User declined this specific finding
        else:  # Cancel (-1)
            logger.info(f"User canceled operation during {heuristic_name} prompt.")
            raise UserWarning(f"User cancelled operation ({heuristic_name})")

    @classmethod
    def _prompt_user_double_blob(
        cls,
        cursor_pos: int,
        iteration_count: int,
        blob1_len: int,
        blob2_len: int,
        pad_start: int,
        pad_len: int,
        next_ea: int,
        predicate_reason: str,
        heuristic_name: str,
    ) -> typing.Optional[typing.Tuple[int, int, int, int, int]]:
        """Prompts the user to confirm the found double blob definition."""
        blob1_ea = cursor_pos
        blob2_ea = cursor_pos + blob1_len
        blob1_name = BLOB_NAME_PATTERN.format(idx=iteration_count)
        blob2_name = BLOB_NAME_PATTERN.format(idx=iteration_count + 1)
        blob1_type = f"const unsigned __int8 {blob1_name}[{blob1_len}];"
        blob2_type = f"const unsigned __int8 {blob2_name}[{blob2_len}];"

        print(f"[{heuristic_name}] Found potential double blob structure.")
        print(f"  -> Blob 1: 0x{blob1_ea:X} (len {blob1_len})")
        print(f"  -> Blob 2: 0x{blob2_ea:X} (len {blob2_len})")
        print(f"  -> Padding: 0x{pad_start:X} (len {pad_len})")
        print(f"  -> Next Item: 0x{next_ea:X} ({predicate_reason})")

        prompt_msg = (
            f"Found potential double blob structure (using {heuristic_name}).\n\n"
            f"Blob 1:\n  Address: 0x{blob1_ea:X}\n  Length: {blob1_len} (0x{blob1_len:X})\n  {blob1_type}\n\n"
            f"Blob 2:\n  Address: 0x{blob2_ea:X}\n  Length: {blob2_len} (0x{blob2_len:X})\n  {blob2_type}\n\n"
            f"Padding:\n  Starts: 0x{pad_start:X}\n  Length: {pad_len}\n\n"
            f"Next Item:\n  Starts: 0x{next_ea:X} ({predicate_reason})\n\n"
            f"Define these two blobs and the padding?"
        )

        user_choice = ida_kernwin.ask_yn(0, prompt_msg)

        if user_choice == 1:  # Yes
            logger.info(f"User confirmed double blob definition via {heuristic_name}.")
            # Return structure: (blob1_len, blob2_len, pad_start, pad_len, next_ea)
            return (blob1_len, blob2_len, pad_start, pad_len, next_ea)
        elif user_choice == 0:  # No
            logger.info(f"User declined double blob definition from {heuristic_name}.")
            return None
        else:  # Cancel (-1)
            logger.info(f"User canceled operation during {heuristic_name} prompt.")
            raise UserWarning(f"User cancelled operation ({heuristic_name})")

    # --- Heuristic Implementations ---

    @classmethod
    def _heuristic_cc_sequence_scan(
        cls,
        cursor_pos: int,
        iteration_count: int,
        search_start_ea: int,
        search_end_ea: int,
        min_len: int,
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Heuristic 1: Search for CC sequences >= min_len."""
        heuristic_name = "CC Sequence Scan"
        print(
            f"\n[{heuristic_name}] Searching for CC padding (>= {min_len} bytes) from 0x{search_start_ea:X} to 0x{search_end_ea:X}..."
        )
        cc_sequences = cls.find_cc_sequences(
            search_start_ea, search_end_ea, min_length=min_len
        )
        if not cc_sequences:
            print(f"[{heuristic_name}] No CC padding sequences found.")
            return None

        logger.info(
            f"[{heuristic_name}] Found {len(cc_sequences)} CC sequence(s) meeting length requirement."
        )
        for seq_start, seq_end, seq_len in cc_sequences:
            next_ea = seq_end + 1
            predicate_ok, predicate_reason = cls._check_predicate(next_ea)
            if predicate_ok:
                try:
                    result = cls._prompt_user(
                        cursor_pos,
                        iteration_count,
                        seq_start,
                        seq_len,
                        next_ea,
                        predicate_reason,
                        heuristic_name,
                    )
                    if result:
                        return result  # User confirmed, return immediately
                    # If user declined (result is None), continue to next sequence
                except UserWarning:
                    raise  # Propagate cancellation
            else:
                logger.debug(
                    f"[{heuristic_name}] Sequence at 0x{seq_start:X} failed predicate check ({predicate_reason})."
                )

        print(
            f"[{heuristic_name}] Found CC sequences, but none met the predicate or were confirmed."
        )
        return None

    @classmethod
    def _heuristic_next_function_boundary(
        cls, cursor_pos: int, iteration_count: int, search_end_ea: int
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Heuristic 2: Find next function and check preceding bytes (> 0)."""
        heuristic_name = "Next Function Boundary"
        print(
            f"\n[{heuristic_name}] Attempting to find next function before 0x{search_end_ea:X}..."
        )
        next_func_ea = idc.get_next_func(cursor_pos)

        if next_func_ea == idaapi.BADADDR:
            print(f"[{heuristic_name}] No function found after cursor.")
            return None
        if next_func_ea >= search_end_ea:
            print(
                f"[{heuristic_name}] Next function 0x{next_func_ea:X} is at or beyond max distance 0x{search_end_ea:X}."
            )
            return None

        logger.info(
            f"[{heuristic_name}] Found next function at 0x{next_func_ea:X}. Checking bytes immediately before it."
        )
        pad_end_ea = next_func_ea - 1
        pad_start_ea = idaapi.BADADDR
        current_ea = pad_end_ea
        cc_count = 0
        while current_ea >= cursor_pos:
            if not ida_bytes.is_loaded(current_ea):
                logger.warning(
                    f"[{heuristic_name}] Unloaded byte at 0x{current_ea:X} scanning backwards."
                )
                break
            if cls.is_cc_byte(current_ea):
                pad_start_ea = current_ea
                cc_count += 1
                current_ea -= 1
            else:
                break

        if cc_count > 0:
            pad_len = cc_count
            logger.info(
                f"[{heuristic_name}] Found {pad_len} CC byte(s) preceding function 0x{next_func_ea:X} (0x{pad_start_ea:X}-0x{pad_end_ea:X})"
            )
            predicate_ok, predicate_reason = cls._check_predicate(
                next_func_ea
            )  # Check predicate at function start
            if predicate_ok:
                try:
                    result = cls._prompt_user(
                        cursor_pos,
                        iteration_count,
                        pad_start_ea,
                        pad_len,
                        next_func_ea,
                        predicate_reason,
                        heuristic_name,
                    )
                    return result  # Return result (tuple or None) or raise UserWarning
                except UserWarning:
                    raise  # Propagate cancellation
            else:
                logger.debug(
                    f"[{heuristic_name}] Padding before function 0x{next_func_ea:X} failed predicate check ({predicate_reason})."
                )
                print(
                    f"[{heuristic_name}] Padding found, but predicate failed at function start."
                )
                return None
        else:
            print(
                f"[{heuristic_name}] Did not find any CC padding immediately before function 0x{next_func_ea:X}."
            )
            return None

    @classmethod
    def _heuristic_last_cc_before_max(
        cls,
        cursor_pos: int,
        iteration_count: int,
        search_start_ea: int,
        search_end_ea: int,
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Heuristic 3: Find last CC sequence before max distance."""
        heuristic_name = "Last CC Before Max Distance"
        print(
            f"\n[{heuristic_name}] Searching backwards for last CC sequence before 0x{search_end_ea:X}..."
        )
        last_cc_ea = idaapi.BADADDR
        current_ea = search_end_ea - 1
        while current_ea >= search_start_ea:  # Search back until the start offset
            if not ida_bytes.is_loaded(current_ea):
                logger.warning(
                    f"[{heuristic_name}] Unloaded byte at 0x{current_ea:X} scanning backwards."
                )
                break
            if cls.is_cc_byte(current_ea):
                last_cc_ea = current_ea
                break  # Found the last CC byte
            current_ea -= 1

        if last_cc_ea == idaapi.BADADDR:
            print(
                f"[{heuristic_name}] No CC bytes found scanning backwards from 0x{search_end_ea-1:X}."
            )
            return None

        pad_end_ea = last_cc_ea
        pad_start_ea = idaapi.BADADDR
        cc_count = 0
        current_ea = pad_end_ea
        # Find the start of this sequence
        while current_ea >= cursor_pos:
            if not ida_bytes.is_loaded(current_ea):
                logger.warning(
                    f"[{heuristic_name}] Unloaded byte at 0x{current_ea:X} finding sequence start."
                )
                break
            if cls.is_cc_byte(current_ea):
                pad_start_ea = current_ea
                cc_count += 1
                current_ea -= 1
            else:
                break

        if cc_count > 0:
            pad_len = cc_count
            next_ea = pad_end_ea + 1
            logger.info(
                f"[{heuristic_name}] Found last CC sequence at 0x{pad_start_ea:X}-0x{pad_end_ea:X} (len {pad_len})"
            )
            predicate_ok, predicate_reason = cls._check_predicate(next_ea)
            if predicate_ok:
                try:
                    result = cls._prompt_user(
                        cursor_pos,
                        iteration_count,
                        pad_start_ea,
                        pad_len,
                        next_ea,
                        predicate_reason,
                        heuristic_name,
                    )
                    return result  # Return result (tuple or None) or raise UserWarning
                except UserWarning:
                    raise  # Propagate cancellation
            else:
                logger.debug(
                    f"[{heuristic_name}] Last CC sequence failed predicate check ({predicate_reason})."
                )
                print(
                    f"[{heuristic_name}] Last CC sequence found, but predicate failed."
                )
                return None
        else:  # Should not happen if last_cc_ea was valid, but safety check
            logger.error(
                f"[{heuristic_name}] Found last CC at 0x{last_cc_ea:X} but failed to count sequence length."
            )
            return None

    @staticmethod
    def is_likely_function(ea: int) -> bool:
        """
        Checks if an address is likely the start of a real function using heuristics.
        """
        if not ida_bytes.is_loaded(ea):
            return False

        # Heuristic 1: Does IDA already think it's a function? (Basic sanity)
        is_ida_func = idaapi.get_func(ea) is not None
        if not is_ida_func:
            # Check if it's at least marked as code
            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(flags):
                logger.debug(
                    f"is_likely_function(0x{ea:X}): Not code according to IDA flags."
                )
                return False
            logger.debug(
                f"is_likely_function(0x{ea:X}): Not marked as function by IDA, but is code. Proceeding."
            )
        # else: logger.debug(f"is_likely_function(0x{ea:X}): Marked as function by IDA.")

        # Heuristic 2: Xrefs? (Functions are usually called)
        has_xrefs = False
        try:
            next(idautils.XrefsTo(ea, 0))  # Efficiently check for existence
            has_xrefs = True
            logger.debug(f"is_likely_function(0x{ea:X}): Has xrefs.")
        except StopIteration:
            logger.debug(f"is_likely_function(0x{ea:X}): No xrefs found.")

        # Heuristic 3: Common Prologue Instructions?
        prologue_found = False
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, ea)

        if insn_len > 0:
            mnem = insn.get_canon_mnem().lower()
            op0_type = insn.ops[0].type if len(insn.ops) > 0 else -1
            op1_type = insn.ops[1].type if len(insn.ops) > 1 else -1

            # Common patterns (add more as needed)
            if mnem == "endbr64":
                prologue_found = True
                logger.debug(f"is_likely_function(0x{ea:X}): Found 'endbr64'.")
            elif (
                mnem == "push"
                and op0_type == ida_ua.o_reg
                and idaapi.get_reg_name(insn.ops[0].reg, 8).lower() == "rbp"
            ):
                prologue_found = True
                logger.debug(f"is_likely_function(0x{ea:X}): Found 'push rbp'.")
            elif (
                mnem == "mov"
                and op0_type == ida_ua.o_reg
                and idaapi.get_reg_name(insn.ops[0].reg, 8).lower() == "rbp"
                and op1_type == ida_ua.o_reg
                and idaapi.get_reg_name(insn.ops[1].reg, 8).lower() == "rsp"
            ):
                # Check if preceded by push rbp for stronger indication
                prev_insn_ea = idc.prev_head(ea)
                if prev_insn_ea != idaapi.BADADDR:
                    prev_insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(prev_insn, prev_insn_ea) > 0:
                        prev_mnem = prev_insn.get_canon_mnem().lower()
                        prev_op0_type = (
                            prev_insn.ops[0].type if len(prev_insn.ops) > 0 else -1
                        )
                        if (
                            prev_mnem == "push"
                            and prev_op0_type == ida_ua.o_reg
                            and idaapi.get_reg_name(prev_insn.ops[0].reg, 8).lower()
                            == "rbp"
                        ):
                            prologue_found = True
                            logger.debug(
                                f"is_likely_function(0x{ea:X}): Found 'mov rbp, rsp' preceded by 'push rbp'."
                            )
                        # else: logger.debug(f"is_likely_function(0x{ea:X}): Found 'mov rbp, rsp' but not preceded by 'push rbp'.") # Less strong
            elif (
                mnem == "sub"
                and op0_type == ida_ua.o_reg
                and idaapi.get_reg_name(insn.ops[0].reg, 8).lower() == "rsp"
                and op1_type == ida_ua.o_imm
            ):
                prologue_found = True
                logger.debug(f"is_likely_function(0x{ea:X}): Found 'sub rsp, imm'.")
            elif (
                insn.size == 2 and ida_bytes.get_word(ea) == 0x9066
            ):  # 66 90 ('xchg ax, ax')
                prologue_found = True  # Often used for alignment before func start
                logger.debug(f"is_likely_function(0x{ea:X}): Found 'xchg ax, ax'.")
            # Consider adding checks for push rbx, push r12, etc. if needed

        else:
            logger.debug(f"is_likely_function(0x{ea:X}): Failed to decode instruction.")
            return False  # Cannot decode instruction, definitely not a function start

        # --- Decision Logic ---
        # Require evidence: EITHER a prologue pattern OR xrefs.
        # Being marked as a function by IDA is a bonus but not strictly required if other evidence exists.
        if prologue_found:
            logger.info(f"is_likely_function(0x{ea:X}): PASSED (Prologue found).")
            return True
        if has_xrefs:
            # Allow functions that might not have standard prologues but are called
            logger.info(
                f"is_likely_function(0x{ea:X}): PASSED (Xrefs found, no standard prologue detected)."
            )
            return True

        # If neither strong indicator is found
        logger.info(
            f"is_likely_function(0x{ea:X}): FAILED (No compelling evidence - prologue/xrefs)."
        )
        return False

    @classmethod
    def _heuristic_double_blob(
        cls,
        cursor_pos: int,
        iteration_count: int,
        start_offset: int,  # Min blob size
        max_search_distance: int,  # Max blob size
    ) -> typing.Optional[typing.Tuple[int, int, int, int, int]]:
        """
        Heuristic 4: Check for two consecutive blobs followed by padding before a LIKELY function.
        Returns (blob1_len, blob2_len, pad_start, pad_len, next_ea) on success.
        """
        heuristic_name = "Double Blob Detection"
        # initial_search_end_ea = cursor_pos + max_search_distance # Where single blob padding would end
        extended_search_distance = 2 * max_search_distance  # Max space for two blobs
        extended_search_end_ea = (
            cursor_pos + extended_search_distance
        )  # Furthest point to look for func start
        # Function must start *after* enough space for two minimum-sized blobs
        min_func_start_ea = cursor_pos + (2 * start_offset)

        print(
            f"\n[{heuristic_name}] Checking for double blob pattern up to 0x{extended_search_end_ea:X}..."
        )

        # Iterate through potential function starts in the extended range
        candidate_func_ea = cursor_pos  # Start search from cursor
        while True:
            # Find the *next* potential function start according to IDA
            candidate_func_ea = idc.get_next_func(candidate_func_ea)

            if candidate_func_ea == idaapi.BADADDR:
                print(f"[{heuristic_name}] No more functions found by IDA.")
                break  # Exhausted IDA's list

            # Check 1: Is the candidate function beyond the extended search range?
            if candidate_func_ea >= extended_search_end_ea:
                print(
                    f"[{heuristic_name}] Next candidate function 0x{candidate_func_ea:X} is beyond extended search range 0x{extended_search_end_ea:X}."
                )
                break  # Stop searching

            # Check 2: Is the candidate function far enough to allow two blobs?
            if candidate_func_ea < min_func_start_ea:
                logger.debug(
                    f"[{heuristic_name}] Candidate function 0x{candidate_func_ea:X} is too close (< 0x{min_func_start_ea:X}). Skipping."
                )
                continue  # Look for the next function candidate

            # Check 3: Does it look like a *real* function?
            logger.debug(
                f"[{heuristic_name}] Evaluating candidate function at 0x{candidate_func_ea:X}..."
            )
            if not cls.is_likely_function(candidate_func_ea):
                logger.debug(
                    f"[{heuristic_name}] Candidate 0x{candidate_func_ea:X} deemed unlikely to be a function. Skipping."
                )
                continue  # Look for the next function candidate

            # If we reach here, candidate_func_ea is a likely function start within the valid range.
            logger.info(
                f"[{heuristic_name}] Found likely function at 0x{candidate_func_ea:X}. Proceeding with checks..."
            )
            next_func_ea = candidate_func_ea  # Use this as the confirmed function start

            # --- Resume original double-blob logic using this confirmed next_func_ea ---

            # 4. Check for CC padding immediately before this function
            pad_end_ea = next_func_ea - 1
            pad_start_ea = idaapi.BADADDR
            current_ea = pad_end_ea
            cc_count = 0
            # Scan back from function start to find padding start. Stop if we go below where blobs could start.
            min_padding_scan_addr = cursor_pos  # Don't scan into previous structures
            while current_ea >= min_padding_scan_addr:
                if not ida_bytes.is_loaded(current_ea):
                    logger.warning(
                        f"[{heuristic_name}] Unloaded byte at 0x{current_ea:X} scanning backwards for padding."
                    )
                    # If unloaded, assume padding ends here, starts at next byte
                    pad_start_ea = current_ea + 1
                    cc_count = (
                        (pad_end_ea - pad_start_ea) + 1
                        if pad_start_ea <= pad_end_ea
                        else 0
                    )
                    break
                if cls.is_cc_byte(current_ea):
                    pad_start_ea = current_ea  # Keep track of the earliest CC byte
                    cc_count += 1
                    current_ea -= 1
                else:
                    # Found a non-CC byte, padding starts at the next address
                    pad_start_ea = current_ea + 1
                    # cc_count was already incremented for the CCs found
                    break
            else:
                # Loop finished without finding non-CC byte back to min_padding_scan_addr
                # This means padding potentially starts right after cursor_pos or earlier
                # If pad_start_ea is still BADADDR, it means no CCs were found at all.
                if pad_start_ea == idaapi.BADADDR:  # No CCs found
                    cc_count = 0
                # else: pad_start_ea holds the start of the CC sequence found

            if cc_count == 0 or pad_start_ea == idaapi.BADADDR:
                print(
                    f"[{heuristic_name}] No CC padding found immediately before likely function 0x{next_func_ea:X}."
                )
                continue  # Try next function candidate

            pad_len = cc_count
            logger.info(
                f"[{heuristic_name}] Found {pad_len} CC byte(s) at 0x{pad_start_ea:X}-0x{pad_end_ea:X} before function."
            )

            # 5. Calculate total space for the two blobs (must be positive)
            total_blob_len = pad_start_ea - cursor_pos
            if total_blob_len <= 0:
                print(
                    f"[{heuristic_name}] Padding start 0x{pad_start_ea:X} is not after cursor 0x{cursor_pos:X}. Invalid."
                )
                continue  # Try next function candidate
            logger.debug(
                f"[{heuristic_name}] Total space for two blobs: {total_blob_len}"
            )

            # 6. Check if total length is feasible (min 2*start_offset)
            min_total_len = 2 * start_offset
            if total_blob_len < min_total_len:
                print(
                    f"[{heuristic_name}] Total blob space {total_blob_len} is less than minimum required {min_total_len}."
                )
                continue  # Try next function candidate

            # 7. Split the total length (approximately evenly)
            blob1_len = total_blob_len // 2
            blob2_len = total_blob_len - blob1_len
            logger.debug(
                f"[{heuristic_name}] Proposed split: Blob1={blob1_len}, Blob2={blob2_len}"
            )

            # 8. Validate individual blob lengths against [start_offset, max_search_distance]
            if not (start_offset <= blob1_len <= max_search_distance):
                print(
                    f"[{heuristic_name}] Calculated Blob 1 length {blob1_len} is outside allowed range [{start_offset}, {max_search_distance}]."
                )
                continue  # Try next function candidate
            if not (start_offset <= blob2_len <= max_search_distance):
                print(
                    f"[{heuristic_name}] Calculated Blob 2 length {blob2_len} is outside allowed range [{start_offset}, {max_search_distance}]."
                )
                continue  # Try next function candidate

            # 9. Check predicate at the start of the actual next item (the function)
            predicate_ok, predicate_reason = cls._check_predicate(next_func_ea)
            if not predicate_ok:
                print(
                    f"[{heuristic_name}] Predicate check failed at likely function start 0x{next_func_ea:X} ({predicate_reason})."
                )
                continue  # Try next function candidate

            # 10. Prompt user for confirmation
            try:
                # Check availability of the next blob index
                next_blob_idx = iteration_count + 1
                if next_blob_idx > MAX_BLOB_INDEX:
                    print(
                        f"[{heuristic_name}] Cannot propose double blob: next index {next_blob_idx} exceeds maximum {MAX_BLOB_INDEX}."
                    )
                    # Don't continue search, this is a hard limit for this run
                    break
                next_blob_name = BLOB_NAME_PATTERN.format(idx=next_blob_idx)
                if idc.get_name_ea_simple(next_blob_name) != idaapi.BADADDR:
                    print(
                        f"[{heuristic_name}] Cannot propose double blob: name '{next_blob_name}' for index {next_blob_idx} is already taken."
                    )
                    # Don't continue search, this needs manual intervention or cache reset
                    break

                # If all checks pass, prompt
                result = cls._prompt_user_double_blob(
                    cursor_pos,
                    iteration_count,
                    blob1_len,
                    blob2_len,
                    pad_start_ea,
                    pad_len,
                    next_func_ea,
                    predicate_reason,
                    heuristic_name,
                )
                if result:
                    return result  # User confirmed! Exit the loop and return.
                else:
                    # User declined this specific candidate, continue searching for other functions
                    print(
                        f"[{heuristic_name}] User declined. Searching for next candidate function..."
                    )
                    continue  # Continue the while loop

            except UserWarning:
                raise  # Propagate cancellation upwards

        # If loop finishes without returning/raising, no suitable double blob found
        print(
            f"[{heuristic_name}] No suitable double blob structure found and confirmed."
        )
        return None


    @classmethod
    def _heuristic_fixed_size_fallback(
        cls, cursor_pos: int, iteration_count: int, max_search_distance: int
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Heuristic 5: Fallback to fixed size definition."""
        heuristic_name = "Fixed Size Fallback"
        print(
            f"\n[{heuristic_name}] Falling back to fixed size definition (0x{max_search_distance:X} bytes)..."
        )
        fixed_array_length = max_search_distance
        blob_end_ea = (
            cursor_pos + fixed_array_length
        )  # Address immediately AFTER the fixed-size blob
        next_ea = blob_end_ea  # The item to check predicate against is the end address

        predicate_ok, predicate_reason = cls._check_predicate(next_ea)
        if predicate_ok:
            logger.info(
                f"[{heuristic_name}] Fixed size end address 0x{next_ea:X} meets predicate ({predicate_reason})."
            )
            try:
                # Use the modified prompt for this case
                result = cls._prompt_user(
                    cursor_pos,
                    iteration_count,
                    pad_start=next_ea,  # Placeholder, not used for calculation
                    pad_len=0,  # Placeholder, not used for calculation
                    next_ea=next_ea,
                    predicate_reason=predicate_reason,
                    heuristic_name=heuristic_name,
                    is_fixed_size=True,
                    fixed_size=fixed_array_length,
                )
                return result  # Return result (tuple or None) or raise UserWarning
            except UserWarning:
                raise  # Propagate cancellation
        else:
            print(
                f"[{heuristic_name}] Fixed size end address 0x{next_ea:X} failed predicate check ({predicate_reason}). Cannot apply fixed size."
            )
            return None

    # --- Orchestrator Method ---

    @classmethod
    def find_padding_from_cursor(
        cls,
        cursor_pos: int,
        iteration_count: int,
        start_offset: int = DEFAULT_PADDING_SEARCH_START_OFFSET,
        max_search_distance: int = DEFAULT_PADDING_SEARCH_MAX_DISTANCE,
        min_len_heuristic1: int = DEFAULT_MIN_PADDING_LEN,
    ) -> typing.Optional[
        typing.Union[typing.Tuple[int, int, int], typing.Tuple[int, int, int, int, int]]
    ]:
        """
        Finds padding (CC bytes) or double blobs after a cursor position using multiple heuristics.

        Args:
            cursor_pos: The starting address (likely blob start).
            iteration_count: The current blob index being searched for (e.g., 0, 1, ...).
            start_offset: The offset from cursor_pos to start the primary search / min blob size.
            max_search_distance: The maximum offset from cursor_pos for single blob / max blob size.
            min_len_heuristic1: The minimum number of CC bytes for the primary scan heuristic.

        Returns:
            - Tuple (pad_start_ea, pad_length, next_item_ea) for single blob + padding.
            - Tuple (blob1_len, blob2_len, pad_start_ea, pad_length, next_item_ea) for double blob + padding.
            - None otherwise.
            Raises UserWarning if the user cancels the operation via the prompt.
        """
        search_start_ea = cursor_pos + start_offset
        search_end_ea = cursor_pos + max_search_distance

        if not ida_bytes.is_loaded(search_start_ea) or not ida_bytes.is_loaded(
            search_end_ea - 1
        ):
            logger.warning(
                f"Initial search range 0x{search_start_ea:X} - 0x{search_end_ea:X} is not fully loaded. Some heuristics may fail."
            )
            # Don't abort yet, some heuristics might still work or use extended range

        # Define the order of heuristics to try
        heuristics = [
            # Heuristic 1: CC Sequence Scan (within initial range)
            lambda: cls._heuristic_cc_sequence_scan(
                cursor_pos,
                iteration_count,
                search_start_ea,
                search_end_ea,
                min_len_heuristic1,
            ),
            # Heuristic 2: Next Function Boundary (within initial range)
            lambda: cls._heuristic_next_function_boundary(
                cursor_pos, iteration_count, search_end_ea
            ),
            # Heuristic 3: Last CC Before Max (within initial range)
            lambda: cls._heuristic_last_cc_before_max(
                cursor_pos, iteration_count, search_start_ea, search_end_ea
            ),
            # Heuristic 4: Double Blob Detection (extended range)
            lambda: cls._heuristic_double_blob(
                cursor_pos, iteration_count, start_offset, max_search_distance
            ),
            # Heuristic 5: Fixed Size Fallback (initial range size)
            lambda: cls._heuristic_fixed_size_fallback(
                cursor_pos, iteration_count, max_search_distance
            ),
        ]

        try:
            for heuristic_func in heuristics:
                result = heuristic_func()
                if result is not None:
                    # Found a confirmed result (either 3-tuple or 5-tuple)
                    return result
                # If result is None, the heuristic failed or user declined, try next
            # If loop completes, all heuristics failed or were declined
            print(
                "\nAll heuristics failed to find suitable padding or blob definition, or were declined by the user."
            )
            return None
        except UserWarning:
            # User cancelled during one of the prompts
            raise  # Re-raise to be caught by the main execute function


def execute():
    """
    Main execution function using shared state dictionary and finding lowest index.
    Handles both single and double blob definitions.
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
        f"Attempting to find and define blob(s) starting with index: {current_blob_index}"
    )

    print("\n=== Function Padding/Blob Finder ===")
    current_ea = idaapi.get_screen_ea()
    print(f"Processing relative to cursor: 0x{current_ea:X}")
    if not ida_bytes.is_loaded(current_ea):
        logger.error(f"Base address 0x{current_ea:X} not loaded.")
        return

    # Call finder - it returns padding/blob info if user confirmed, or None, or raises UserWarning
    padding_result = None
    try:
        padding_result = FunctionPaddingFinder.find_padding_from_cursor(
            current_ea,
            current_blob_index,
            start_offset=DEFAULT_PADDING_SEARCH_START_OFFSET,
            max_search_distance=DEFAULT_PADDING_SEARCH_MAX_DISTANCE,
            min_len_heuristic1=DEFAULT_MIN_PADDING_LEN,
        )
    except UserWarning as e:
        print(f"\nOperation cancelled by user: {e}")
        return  # Stop execution if user cancelled

    if padding_result:
        is_double_blob = isinstance(padding_result, tuple) and len(padding_result) == 5

        if is_double_blob:
            # --- Handle Double Blob Definition ---
            blob1_len, blob2_len, pad_start, pad_len, next_ea = padding_result
            blob1_idx = current_blob_index
            blob2_idx = (
                current_blob_index + 1
            )  # Already checked for availability in heuristic

            blob1_ea = current_ea
            blob2_ea = current_ea + blob1_len

            blob1_name = BLOB_NAME_PATTERN.format(idx=blob1_idx)
            blob2_name = BLOB_NAME_PATTERN.format(idx=blob2_idx)

            blob1_type_str = f"const unsigned __int8 {blob1_name}[{blob1_len}];"
            blob2_type_str = f"const unsigned __int8 {blob2_name}[{blob2_len}];"

            logger.info(
                f"Attempting to define double blob: {blob1_name} at 0x{blob1_ea:X} and {blob2_name} at 0x{blob2_ea:X}"
            )

            # Define Blob 1
            success1 = set_type(blob1_ea, blob1_type_str, blob1_name)
            if not success1:
                logger.error(f"Failed to define first blob {blob1_name}. Aborting.")
                return  # Don't proceed if first fails

            # Define Blob 2
            success2 = set_type(blob2_ea, blob2_type_str, blob2_name)
            if not success2:
                logger.error(
                    f"Defined {blob1_name} but failed to define second blob {blob2_name}. Manual cleanup may be needed."
                )
                # Cache not reset yet
                return

            # Both blobs defined successfully
            logger.info(
                f"Successfully defined double blobs {blob1_name} and {blob2_name} (PUBLIC)."
            )
            # Reset cache *after* successful definition of BOTH blobs
            reset_blob_index_cache()
            logger.info(
                f"Blob index cache reset. Next run will search for index {get_next_blob_index()}."
            )

            # --- Handle Padding Alignment (if pad_len > 0) ---
            if pad_len > 0:
                align_exponent = _determine_alignment_exponent(next_ea)
                align_val = 1 << align_exponent
                logger.info(
                    f"Attempting to align padding at 0x{pad_start:X} (len {pad_len}) to {align_val} bytes (exponent {align_exponent}) based on next item at 0x{next_ea:X}."
                )
                if not ida_bytes.del_items(pad_start, ida_bytes.DELIT_EXPAND, pad_len):
                    logger.warning(
                        f"Could not fully undefine padding range 0x{pad_start:X}-0x{pad_start+pad_len-1:X}."
                    )
                if align_exponent > 0:
                    if ida_bytes.create_align(pad_start, pad_len, align_exponent):
                        logger.info(
                            f"Successfully created align directive for padding."
                        )
                    else:
                        logger.error(
                            f"Failed to create align directive for padding at 0x{pad_start:X} (len {pad_len}, exp {align_exponent}). Marking as bytes."
                        )
                        ida_bytes.create_data(
                            pad_start, ida_bytes.FF_BYTE, pad_len, idaapi.BADADDR
                        )
                else:
                    logger.info(
                        f"No specific alignment needed (align=1) for padding at 0x{pad_start:X}. Marking as byte data."
                    )
                    ida_bytes.create_data(
                        pad_start, ida_bytes.FF_BYTE, pad_len, idaapi.BADADDR
                    )
            else:
                logger.info(f"No padding (pad_len=0) to align after double blob.")

        else:
            # --- Handle Single Blob Definition ---
            pad_start, pad_len, next_ea = padding_result
            blob_name = BLOB_NAME_PATTERN.format(idx=current_blob_index)

            # Determine array length based on whether it was fixed size or padding-based
            if pad_len == 0 and pad_start == next_ea:  # Fixed size case
                array_len = next_ea - current_ea
            else:  # Padding based case
                array_len = pad_start - current_ea

            if array_len <= 0:
                logger.error(
                    f"Calculated invalid array length ({array_len}) for blob at 0x{current_ea:X}. Aborting definition."
                )
                return

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

                # --- Handle Padding Alignment (only if pad_len > 0) ---
                if pad_len > 0:
                    align_exponent = _determine_alignment_exponent(next_ea)
                    align_val = 1 << align_exponent
                    logger.info(
                        f"Attempting to align padding at 0x{pad_start:X} (len {pad_len}) to {align_val} bytes (exponent {align_exponent}) based on next item at 0x{next_ea:X}."
                    )
                    if not ida_bytes.del_items(
                        pad_start, ida_bytes.DELIT_EXPAND, pad_len
                    ):
                        logger.warning(
                            f"Could not fully undefine padding range 0x{pad_start:X}-0x{pad_start+pad_len-1:X}."
                        )
                    if align_exponent > 0:
                        if ida_bytes.create_align(pad_start, pad_len, align_exponent):
                            logger.info(
                                f"Successfully created align directive for padding."
                            )
                        else:
                            logger.error(
                                f"Failed to create align directive for padding at 0x{pad_start:X} (len {pad_len}, exp {align_exponent}). Marking as bytes."
                            )
                            ida_bytes.create_data(
                                pad_start,
                                ida_bytes.FF_BYTE,
                                pad_len,
                                idaapi.BADADDR,
                            )
                    else:
                        logger.info(
                            f"No specific alignment needed (align=1) for padding at 0x{pad_start:X}. Marking as byte data."
                        )
                        ida_bytes.create_data(
                            pad_start, ida_bytes.FF_BYTE, pad_len, idaapi.BADADDR
                        )
                else:
                    logger.info(
                        f"No padding (pad_len=0) to align after blob {blob_name}."
                    )
            else:
                logger.error(
                    f"Failed to define main blob {blob_name}. Skipping padding alignment."
                )
                # Cache not reset

    else:
        # find_padding_from_cursor returned None (and didn't raise UserWarning)
        print(
            f"\nDid not define blob(s) for index {current_blob_index} based on heuristics relative to 0x{current_ea:X}."
        )

    print("\nScript execution completed!")


# --- Main Execution (Unchanged) ---
if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(log=logger, level=logging.INFO)
    execute()
    idaapi.refresh_idaview_anyway()

# --- How to Reset Cache (Unchanged) ---
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
