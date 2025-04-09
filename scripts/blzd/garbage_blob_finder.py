import logging
import sys
import typing
from dataclasses import dataclass, field
from enum import Enum, auto

import ida_bytes
import ida_funcs  # Import ida_funcs
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
        logger.info("Output window cleared.")

    def configure_logging(log, level=logging.INFO):
        logging.basicConfig(
            level=level,
            format="[%(levelname)s] @ %(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        log.setLevel(level)


# --- Configuration Dataclass ---
@dataclass(frozen=True)  # Use frozen=True for immutable constants
class ScriptConfig:
    MAX_BLOB_INDEX: int = 12
    BLOB_NAME_PATTERN: str = "g_bufInitBlob{idx}"
    SHARED_STATE_DICT_NAME: str = "g_script_state_storage"
    CACHE_KEY_NAME: str = "blob_finder_next_index"
    DEFAULT_PADDING_SEARCH_START_OFFSET: int = (
        0x1000  # Also min blob size for double blob
    )
    DEFAULT_PADDING_SEARCH_MAX_DISTANCE: int = (
        0x2000  # Also max blob size for double blob
    )
    DEFAULT_MIN_PADDING_LEN: int = 2


# Instantiate the config
CONFIG = ScriptConfig()

logger = logging.getLogger("garbage_blob_finder")


# --- Cache Management Functions (Using Config) ---
def _get_shared_state_dict() -> dict:
    """Gets or creates the shared state dictionary in __main__."""
    main_module = sys.modules["__main__"]
    if not hasattr(main_module, CONFIG.SHARED_STATE_DICT_NAME):
        setattr(main_module, CONFIG.SHARED_STATE_DICT_NAME, {})
        logger.debug(
            f"Created shared state dictionary: {CONFIG.SHARED_STATE_DICT_NAME}"
        )
    storage = getattr(main_module, CONFIG.SHARED_STATE_DICT_NAME)
    if not isinstance(storage, dict):
        logger.error(
            f"{CONFIG.SHARED_STATE_DICT_NAME} in __main__ is not a dict! Resetting."
        )
        setattr(main_module, CONFIG.SHARED_STATE_DICT_NAME, {})
        storage = getattr(main_module, CONFIG.SHARED_STATE_DICT_NAME)
    return storage


def reset_blob_index_cache():
    """Resets this script's cached next blob index in the shared state."""
    storage = _get_shared_state_dict()
    if CONFIG.CACHE_KEY_NAME in storage:
        del storage[CONFIG.CACHE_KEY_NAME]
        logger.info(f"Blob index cache key '{CONFIG.CACHE_KEY_NAME}' reset.")
    else:
        logger.info(f"Blob index cache key '{CONFIG.CACHE_KEY_NAME}' was not set.")


def _populate_blob_index_cache() -> int:
    """
    Scans for the *lowest* available g_bufInitBlob index (0-CONFIG.MAX_BLOB_INDEX).
    Stores the result under this script's key in the shared state dictionary.
    Returns the lowest available index, or CONFIG.MAX_BLOB_INDEX + 1 if full.
    """
    storage = _get_shared_state_dict()
    logger.debug(f"Populating blob index cache key '{CONFIG.CACHE_KEY_NAME}'...")

    next_idx = CONFIG.MAX_BLOB_INDEX + 1

    for idx in range(CONFIG.MAX_BLOB_INDEX + 1):
        name_to_check = CONFIG.BLOB_NAME_PATTERN.format(idx=idx)
        if idc.get_name_ea_simple(name_to_check) == idaapi.BADADDR:
            logger.debug(f"Found first available index: {idx}")
            next_idx = idx
            break

    if next_idx > CONFIG.MAX_BLOB_INDEX:
        logger.warning(f"All blob indices (0-{CONFIG.MAX_BLOB_INDEX}) seem to be used.")
    else:
        logger.info(f"Lowest available blob index determined to be: {next_idx}")

    storage[CONFIG.CACHE_KEY_NAME] = next_idx
    return next_idx


def get_next_blob_index() -> int:
    """
    Gets the lowest available blob index (0-CONFIG.MAX_BLOB_INDEX). Uses cached value if available,
    otherwise populates the cache. Returns CONFIG.MAX_BLOB_INDEX + 1 if no indices
    are available.
    """
    storage = _get_shared_state_dict()
    cached_index = storage.get(CONFIG.CACHE_KEY_NAME)

    if cached_index is not None:
        logger.debug(f"Using cached next blob index: {cached_index}")
        return cached_index
    else:
        return _populate_blob_index_cache()


# --- Utility Functions ---
def _determine_alignment_exponent(address: int) -> int:
    """
    Determines the alignment exponent (log2) based on the address.
    Checks for 16, 8, 4, 2 byte alignment. Returns 0 if none match.
    """
    if (address % 16) == 0:
        return 4
    elif (address % 8) == 0:
        return 3
    elif (address % 4) == 0:
        return 2
    elif (address % 2) == 0:
        return 1
    else:
        return 0


class SearchStrategy(Enum):
    BACKWARD_SCAN = auto()
    FORWARD_CHUNK = auto()


def _search_range(
    ea: int,
    check_instruction: typing.Callable[[ida_ua.insn_t], bool],
    max_range: int = 0x200,
    strategy: SearchStrategy = SearchStrategy.BACKWARD_SCAN,
) -> typing.Optional[int]:
    """Searches backward or forward for an instruction matching a predicate."""
    if strategy == SearchStrategy.BACKWARD_SCAN:
        start_addr = max(ea - max_range, 0)
        current = ea
        while current >= start_addr:
            if not ida_bytes.is_loaded(current):
                current -= 1
                continue
            insn = ida_ua.insn_t()
            prev_head_ea = ida_funcs.get_prev_insn_ea(current)  # Use ida_funcs helper
            if prev_head_ea == idaapi.BADADDR or prev_head_ea < start_addr:
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
    if not idaapi.parse_decl(
        tif, None, type_str, ida_typeinf.PT_SILENT
    ):  # Use PT_SILENT
        logger.error(f"Error parsing type declaration: '{type_str}'")
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

    size = tif.get_size()
    if size == idaapi.BADSIZE or size == 0:
        logger.error(
            f"Could not determine valid size for type '{type_str}' at 0x{ea:X}. Size: {size}"
        )
        return False

    logger.debug(
        f"Type requires size: {size} bytes. Undefining range 0x{ea:X} to 0x{ea + size - 1:X}."
    )
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size):
        logger.warning(
            f"Could not fully undefine {size} bytes at 0x{ea:X}. Proceeding anyway."
        )

    if idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
        logger.info(f"Type applied successfully at 0x{ea:X}.")
        name_flags = idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_PUBLIC
        if idaapi.set_name(ea, name, name_flags):
            logger.info(f"Name '{name}' set successfully (PUBLIC).")
        else:
            logger.warning(
                f"Type applied at 0x{ea:X}, but failed to rename to '{name}' (public)."
            )
        return True
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
    """Applies a function signature using idaapi."""
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
    if idaapi.parse_decl(tif, None, decl, ida_typeinf.PT_SILENT):  # Use PT_SILENT
        if idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
            logger.info(f"Successfully applied signature to {name}")
            idaapi.set_name(ea, name, idaapi.SN_NOCHECK)
        else:
            logger.error(f"Failed to apply signature tinfo to {name} at 0x{ea:X}")
    else:
        logger.error(f"Failed to parse signature declaration: {decl}")


# --- GarbageBlobFinder Class (Unchanged from original, uses CONFIG implicitly via BLOB_NAME_PATTERN) ---
class GarbageBlobFinder:
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
        next_addr = ida_funcs.get_next_insn_ea(search_base_ea)  # Use ida_funcs
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
            prev_addr = ida_funcs.get_prev_insn_ea(search_base_ea)  # Use ida_funcs
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
                (
                    SearchStrategy.FORWARD_CHUNK,
                    ida_funcs.get_next_insn_ea(search_base_ea),
                ),
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


# --- Function Prologue Detector ---
class FunctionPrologueDetector:
    """
    Analyzes an address to determine the likelihood it's a function start
    using various heuristics and assigns a score.
    """

    # --- Nested Configuration for Weights and Threshold ---
    @dataclass(frozen=True)
    class DetectorConfig:
        WEIGHT_IDA_FUNC: int = 2
        WEIGHT_IDA_CODE: int = 1
        WEIGHT_CALL_XREF: int = 8
        WEIGHT_ENDBR64: int = 10
        WEIGHT_PUSH_RBP: int = 8
        WEIGHT_MOV_RBP_RSP: int = 7  # Combined weight if preceded by push rbp
        WEIGHT_SUB_RSP_IMM: int = 6
        WEIGHT_XCHG_NOP: int = 4
        LIKELY_FUNCTION_THRESHOLD: int = 6  # Min score to be considered likely

    # Instantiate nested config
    Cfg = DetectorConfig()

    # --- NOP Sequences (can remain class-level) ---
    _NOP_SEQUENCES = [
        b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 11 bytes
        b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 10 bytes
        b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 9 bytes
        b"\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 8 bytes
        b"\x0f\x1f\x80\x00\x00\x00\x00",  # 7 bytes
        b"\x66\x0f\x1f\x44\x00\x00",  # 6 bytes
        b"\x0f\x1f\x44\x00\x00",  # 5 bytes
        b"\x0f\x1f\x40\x00",  # 4 bytes
        b"\x0f\x1f\x00",  # 3 bytes
        b"\x66\x90",  # 2 bytes
        b"\x90",  # 1 byte
    ]
    _MAX_NOP_LEN = max(len(s) for s in _NOP_SEQUENCES)

    @classmethod
    def _is_nop_instruction(cls, insn: ida_ua.insn_t) -> bool:
        """Checks if the decoded instruction is a known NOP."""
        if not insn:
            return False
        if insn.itype == ida_ua.NN_nop:
            return True
        insn_bytes = ida_bytes.get_bytes(insn.ea, insn.size)
        if not insn_bytes:
            return False
        return any(
            insn_bytes == seq for seq in cls._NOP_SEQUENCES if len(seq) == insn.size
        )

    @classmethod
    def _decode_instruction(cls, ea: int) -> typing.Optional[ida_ua.insn_t]:
        """Safely decodes instruction at ea."""
        if not ida_bytes.is_loaded(ea):
            return None
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, ea)
        return insn if insn_len > 0 else None

    # --- Individual Check Methods (Standard Signature) ---
    # Signature: (cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list) -> int

    @classmethod
    def _check_ida_analysis(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks IDA's existing analysis (code/function flags). Ignores insn."""
        score = 0
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_func(flags):
            memo.append(f"IDA marks as func start (weight +{cls.Cfg.WEIGHT_IDA_FUNC})")
            score += cls.Cfg.WEIGHT_IDA_FUNC
        elif ida_bytes.is_code(flags):
            memo.append(f"IDA marks as code (weight +{cls.Cfg.WEIGHT_IDA_CODE})")
            score += cls.Cfg.WEIGHT_IDA_CODE
        else:
            memo.append("Not marked as code/func by IDA")
        return score

    @classmethod
    def _check_call_xrefs(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks for incoming CALL instructions. Ignores insn."""
        try:
            for xref in idautils.XrefsTo(ea, 0):
                xref_insn = cls._decode_instruction(xref.frm)
                if xref_insn and (xref_insn.get_canon_feature() & ida_ua.CF_CALL):
                    memo.append(
                        f"CALL xref from 0x{xref.frm:X} (weight +{cls.Cfg.WEIGHT_CALL_XREF})"
                    )
                    return cls.Cfg.WEIGHT_CALL_XREF
            memo.append("No direct CALL xrefs found")
        except Exception as e:
            logger.warning(f"Error checking xrefs for 0x{ea:X}: {e}")
            memo.append("Error checking xrefs")
        return 0

    @classmethod
    def _check_endbr64(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks for ENDBR64 instruction. Ignores ea."""
        if insn and insn.itype == ida_ua.NN_endbr64:
            memo.append(f"Starts with ENDBR64 (weight +{cls.Cfg.WEIGHT_ENDBR64})")
            return cls.Cfg.WEIGHT_ENDBR64
        return 0

    @classmethod
    def _check_push_rbp(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks for 'push rbp'. Ignores ea."""
        if insn and insn.itype == ida_ua.NN_push:
            op = insn.ops[0]
            if op.type == ida_ua.o_reg and op.reg == ida_ua.R_BP:
                memo.append(f"Starts with PUSH RBP (weight +{cls.Cfg.WEIGHT_PUSH_RBP})")
                return cls.Cfg.WEIGHT_PUSH_RBP
        return 0

    @classmethod
    def _check_mov_rbp_rsp(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks for 'mov rbp, rsp' potentially preceded by 'push rbp'."""
        if insn and insn.itype == ida_ua.NN_mov:
            op0, op1 = insn.ops[0], insn.ops[1]
            if (
                op0.type == ida_ua.o_reg
                and op0.reg == ida_ua.R_BP
                and op1.type == ida_ua.o_reg
                and op1.reg == ida_ua.R_SP
            ):
                prev_ea = ida_funcs.get_prev_insn_ea(ea)  # Use current ea here
                if prev_ea != idaapi.BADADDR:
                    prev_insn = cls._decode_instruction(prev_ea)
                    # Call check_push_rbp with dummy ea/memo
                    if cls._check_push_rbp(prev_ea, prev_insn, []):
                        memo.append(
                            f"PUSH RBP followed by MOV RBP, RSP (weight +{cls.Cfg.WEIGHT_MOV_RBP_RSP})"
                        )
                        return cls.Cfg.WEIGHT_MOV_RBP_RSP
                memo.append("Starts with MOV RBP, RSP (no preceding PUSH RBP found)")
        return 0

    @classmethod
    def _check_sub_rsp_imm(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks for 'sub rsp, imm'. Ignores ea."""
        if insn and insn.itype == ida_ua.NN_sub:
            op0, op1 = insn.ops[0], insn.ops[1]
            if (
                op0.type == ida_ua.o_reg
                and op0.reg == ida_ua.R_SP
                and op1.type == ida_ua.o_imm
            ):
                memo.append(
                    f"Starts with SUB RSP, imm (weight +{cls.Cfg.WEIGHT_SUB_RSP_IMM})"
                )
                return cls.Cfg.WEIGHT_SUB_RSP_IMM
        return 0

    @classmethod
    def _check_xchg_nop_pattern(
        cls, ea: int, insn: typing.Optional[ida_ua.insn_t], memo: list
    ) -> int:
        """Checks for 'xchg ax, ax' followed by a NOP. Ignores ea."""
        if insn and insn.size == 2 and ida_bytes.get_word(insn.ea) == 0x9066:  # 66 90
            next_ea = insn.ea + insn.size
            next_insn = cls._decode_instruction(next_ea)
            if next_insn and cls._is_nop_instruction(next_insn):
                memo.append(
                    f"Starts with XCHG AX, AX + NOP (weight +{cls.Cfg.WEIGHT_XCHG_NOP})"
                )
                return cls.Cfg.WEIGHT_XCHG_NOP
            else:
                memo.append("Starts with XCHG AX, AX (but not followed by NOP)")
        return 0

    # --- Main Likelihood Calculation Method ---

    @classmethod
    def get_likelihood(cls, ea: int) -> typing.Tuple[int, list]:
        """
        Calculates the likelihood score for 'ea' being a function start.

        Returns:
            Tuple (score: int, memo: list[str])
        """
        score = 0
        memo = []

        if not ida_bytes.is_loaded(ea):
            memo.append("Address not loaded")
            return 0, memo

        # Decode the first instruction *once*
        first_insn = cls._decode_instruction(ea)

        # Define the checks to run in order
        checks_to_run = [
            cls._check_ida_analysis,
            cls._check_call_xrefs,
            cls._check_endbr64,
            cls._check_push_rbp,
            cls._check_mov_rbp_rsp,
            cls._check_sub_rsp_imm,
            cls._check_xchg_nop_pattern,
        ]

        # Run checks
        for check_func in checks_to_run:
            score += check_func(ea, first_insn, memo)
            # Optimization: If first instruction failed decode, stop instruction-based checks
            if not first_insn and check_func not in (
                cls._check_ida_analysis,
                cls._check_call_xrefs,
            ):
                if not memo or "Failed to decode first instruction" not in memo[-1]:
                    memo.append(
                        "Failed to decode first instruction, skipping further instruction checks."
                    )
                break

        return score, memo


# --- Function Padding Finder ---
class FunctionPaddingFinder:

    @staticmethod
    def is_cc_byte(ea):
        """Checks if the byte at the given address is 0xCC."""
        try:
            if ida_bytes.is_loaded(ea):
                return ida_bytes.get_byte(ea) == 0xCC
            return False
        except Exception:
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
            if not ida_bytes.is_loaded(ea):
                logger.warning(f"Address 0x{ea:X} became unloaded during scan.")
                break
            ea += 1
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
        # Use the sequences from the detector class for consistency
        max_len = FunctionPrologueDetector._MAX_NOP_LEN
        bytes_at_ea = ida_bytes.get_bytes(ea, max_len)
        if not bytes_at_ea:
            return False
        # Check if bytes start with any known NOP sequence (excluding single 0x90)
        return any(
            bytes_at_ea.startswith(seq)
            for seq in FunctionPrologueDetector._NOP_SEQUENCES
            if len(seq) > 1
        )

    @classmethod
    def _check_predicate(cls, next_ea: int) -> typing.Tuple[bool, str]:
        """Checks if the next address meets the alignment or special NOP predicate."""
        if not ida_bytes.is_loaded(next_ea):
            logger.debug(
                f"Predicate check failed: Address 0x{next_ea:X} is not loaded."
            )
            return False, "unloaded"
        is_aligned = (next_ea % 16) == 0
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
        blob_name = CONFIG.BLOB_NAME_PATTERN.format(idx=iteration_count)
        if is_fixed_size:
            array_length = fixed_size
            blob_end_ea = cursor_pos + array_length
            logger.info(
                f"[{heuristic_name}] Proposing fixed size definition: {array_length} (0x{array_length:X}) bytes."
            )
            logger.info(
                f"  -> Blob would end at 0x{blob_end_ea:X}, which is {predicate_reason}."
            )
            type_str = f"const unsigned __int8 {blob_name}[{array_length}];"
            prompt_msg = (
                f"{heuristic_name}: No padding found or confirmed.\n"
                f"Define blob with fixed size {array_length} (0x{array_length:X})?\n"
                f"Blob would end at 0x{blob_end_ea:X}, which is {predicate_reason}.\n\n"
                f"Define as:\n{type_str}\n\nProceed?"
            )
        else:
            array_length = pad_start - cursor_pos
            logger.info(
                f"[{heuristic_name}] Found potential padding end at 0x{pad_start:X} (length {pad_len})."
            )
            logger.info(
                f"  -> Predicate match: next address 0x{next_ea:X} is {predicate_reason}."
            )
            logger.info(
                f"  -> Calculated array length relative to 0x{cursor_pos:X}: {array_length} (0x{array_length:X})"
            )
            if array_length <= 0:
                logger.warning(
                    f"Calculated array length is non-positive ({array_length}). Skipping."
                )
                return None
            type_str = f"const unsigned __int8 {blob_name}[{array_length}];"
            prompt_msg = (
                f"Found potential blob at 0x{cursor_pos:X} (using {heuristic_name}).\n"
                f"Padding starts at 0x{pad_start:X} (length {pad_len}).\n"
                f"Next item starts at 0x{next_ea:X} ({predicate_reason}).\n"
                f"Calculated array size: {array_length} (0x{array_length:X}).\n\n"
                f"Define as:\n{type_str}\n\nProceed?"
            )
        user_choice = ida_kernwin.ask_yn(0, prompt_msg)
        if user_choice == 1:
            logger.info(f"User confirmed definition via {heuristic_name}: {type_str}")
            return_pad_start = pad_start if not is_fixed_size else next_ea
            return_pad_len = pad_len if not is_fixed_size else 0
            return (return_pad_start, return_pad_len, next_ea)
        elif user_choice == 0:
            logger.info(f"User declined definition from {heuristic_name}.")
            return None
        else:
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
        blob1_name = CONFIG.BLOB_NAME_PATTERN.format(idx=iteration_count)
        blob2_name = CONFIG.BLOB_NAME_PATTERN.format(idx=iteration_count + 1)
        blob1_type = f"const unsigned __int8 {blob1_name}[{blob1_len}];"
        blob2_type = f"const unsigned __int8 {blob2_name}[{blob2_len}];"
        logger.info(f"[{heuristic_name}] Found potential double blob structure.")
        logger.info(f"  -> Blob 1: 0x{blob1_ea:X} (len {blob1_len})")
        logger.info(f"  -> Blob 2: 0x{blob2_ea:X} (len {blob2_len})")
        logger.info(f"  -> Padding: 0x{pad_start:X} (len {pad_len})")
        logger.info(f"  -> Next Item: 0x{next_ea:X} ({predicate_reason})")
        prompt_msg = (
            f"Found potential double blob structure (using {heuristic_name}).\n\n"
            f"Blob 1:\n  Address: 0x{blob1_ea:X}\n  Length: {blob1_len} (0x{blob1_len:X})\n  {blob1_type}\n\n"
            f"Blob 2:\n  Address: 0x{blob2_ea:X}\n  Length: {blob2_len} (0x{blob2_len:X})\n  {blob2_type}\n\n"
            f"Padding:\n  Starts: 0x{pad_start:X}\n  Length: {pad_len}\n\n"
            f"Next Item:\n  Starts: 0x{next_ea:X} ({predicate_reason})\n\n"
            f"Define these two blobs and the padding?"
        )
        user_choice = ida_kernwin.ask_yn(0, prompt_msg)
        if user_choice == 1:
            logger.info(f"User confirmed double blob definition via {heuristic_name}.")
            return (blob1_len, blob2_len, pad_start, pad_len, next_ea)
        elif user_choice == 0:
            logger.info(f"User declined double blob definition from {heuristic_name}.")
            return None
        else:
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
        logger.info(
            f"\n[{heuristic_name}] Searching for CC padding (>= {min_len} bytes) from 0x{search_start_ea:X} to 0x{search_end_ea:X}..."
        )
        cc_sequences = cls.find_cc_sequences(
            search_start_ea, search_end_ea, min_length=min_len
        )
        if not cc_sequences:
            logger.info(f"[{heuristic_name}] No CC padding sequences found.")
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
                        return result
                except UserWarning:
                    raise
            else:
                logger.debug(
                    f"[{heuristic_name}] Sequence at 0x{seq_start:X} failed predicate check ({predicate_reason})."
                )
        logger.info(
            f"[{heuristic_name}] Found CC sequences, but none met the predicate or were confirmed."
        )
        return None

    @classmethod
    def _heuristic_next_function_boundary(
        cls, cursor_pos: int, iteration_count: int, search_end_ea: int
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Heuristic 2: Find next function and check preceding bytes (> 0)."""
        heuristic_name = "Next Function Boundary"
        logger.info(
            f"\n[{heuristic_name}] Attempting to find next function before 0x{search_end_ea:X}..."
        )
        next_func_ea = ida_funcs.get_next_func_ea(cursor_pos)  # Use ida_funcs
        if next_func_ea == idaapi.BADADDR:
            logger.info(f"[{heuristic_name}] No function found after cursor.")
            return None
        if next_func_ea >= search_end_ea:
            logger.info(
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
            predicate_ok, predicate_reason = cls._check_predicate(next_func_ea)
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
                    return result
                except UserWarning:
                    raise
            else:
                logger.debug(
                    f"[{heuristic_name}] Padding before function 0x{next_func_ea:X} failed predicate check ({predicate_reason})."
                )
                logger.info(
                    f"[{heuristic_name}] Padding found, but predicate failed at function start."
                )
                return None
        else:
            logger.info(
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
        logger.info(
            f"\n[{heuristic_name}] Searching backwards for last CC sequence before 0x{search_end_ea:X}..."
        )
        last_cc_ea = idaapi.BADADDR
        current_ea = search_end_ea - 1
        while current_ea >= search_start_ea:
            if not ida_bytes.is_loaded(current_ea):
                logger.warning(
                    f"[{heuristic_name}] Unloaded byte at 0x{current_ea:X} scanning backwards."
                )
                break
            if cls.is_cc_byte(current_ea):
                last_cc_ea = current_ea
                break
            current_ea -= 1
        if last_cc_ea == idaapi.BADADDR:
            logger.info(
                f"[{heuristic_name}] No CC bytes found scanning backwards from 0x{search_end_ea-1:X}."
            )
            return None
        pad_end_ea = last_cc_ea
        pad_start_ea = idaapi.BADADDR
        cc_count = 0
        current_ea = pad_end_ea
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
                    return result
                except UserWarning:
                    raise
            else:
                logger.debug(
                    f"[{heuristic_name}] Last CC sequence failed predicate check ({predicate_reason})."
                )
                logger.info(
                    f"[{heuristic_name}] Last CC sequence found, but predicate failed."
                )
                return None
        else:
            logger.error(
                f"[{heuristic_name}] Found last CC at 0x{last_cc_ea:X} but failed to count sequence length."
            )
            return None

    @classmethod
    def _heuristic_double_blob(
        cls,
        cursor_pos: int,
        iteration_count: int,
        start_offset: int,
        max_search_distance: int,
    ) -> typing.Optional[typing.Tuple[int, int, int, int, int]]:
        """
        Heuristic 4: Check for two consecutive blobs followed by padding before a LIKELY function.
        Uses FunctionPrologueDetector to assess likelihood.
        Returns (blob1_len, blob2_len, pad_start, pad_len, next_ea) on success.
        """
        heuristic_name = "Double Blob Detection"
        extended_search_distance = 2 * max_search_distance
        extended_search_end_ea = cursor_pos + extended_search_distance
        min_func_start_ea = cursor_pos + (2 * start_offset)
        logger.info(
            f"\n[{heuristic_name}] Checking for double blob pattern up to 0x{extended_search_end_ea:X}..."
        )
        candidate_func_ea = cursor_pos
        while True:
            candidate_func_ea = ida_funcs.get_next_func_ea(candidate_func_ea)
            if candidate_func_ea == idaapi.BADADDR:
                logger.info(f"[{heuristic_name}] No more functions found by IDA.")
                break
            if candidate_func_ea >= extended_search_end_ea:
                logger.info(
                    f"[{heuristic_name}] Next candidate function 0x{candidate_func_ea:X} is beyond extended search range 0x{extended_search_end_ea:X}."
                )
                break
            if candidate_func_ea < min_func_start_ea:
                logger.debug(
                    f"[{heuristic_name}] Candidate function 0x{candidate_func_ea:X} is too close (< 0x{min_func_start_ea:X}). Skipping."
                )
                continue

            likelihood, memo = FunctionPrologueDetector.get_likelihood(
                candidate_func_ea
            )
            logger.debug(
                f"[{heuristic_name}] Candidate 0x{candidate_func_ea:X} -> Score: {likelihood}. Checks: {'; '.join(memo)}"
            )
            if likelihood < FunctionPrologueDetector.Cfg.LIKELY_FUNCTION_THRESHOLD:
                logger.debug(
                    f"[{heuristic_name}] Likelihood {likelihood} < {FunctionPrologueDetector.Cfg.LIKELY_FUNCTION_THRESHOLD}. Skipping."
                )
                continue

            logger.info(
                f"[{heuristic_name}] Found likely function (score {likelihood}) at 0x{candidate_func_ea:X}. Proceeding with checks..."
            )
            next_func_ea = candidate_func_ea

            pad_end_ea = next_func_ea - 1
            pad_start_ea = idaapi.BADADDR
            current_ea = pad_end_ea
            cc_count = 0
            min_padding_scan_addr = cursor_pos
            while current_ea >= min_padding_scan_addr:
                if not ida_bytes.is_loaded(current_ea):
                    logger.warning(
                        f"[{heuristic_name}] Unloaded byte at 0x{current_ea:X} scanning backwards for padding."
                    )
                    pad_start_ea = current_ea + 1
                    cc_count = (
                        (pad_end_ea - pad_start_ea) + 1
                        if pad_start_ea <= pad_end_ea
                        else 0
                    )
                    break
                if cls.is_cc_byte(current_ea):
                    pad_start_ea = current_ea
                    cc_count += 1
                    current_ea -= 1
                else:
                    pad_start_ea = current_ea + 1
                    break
            else:
                if pad_start_ea == idaapi.BADADDR:
                    cc_count = 0

            if cc_count == 0 or pad_start_ea == idaapi.BADADDR:
                logger.info(
                    f"[{heuristic_name}] No CC padding found immediately before likely function 0x{next_func_ea:X}."
                )
                continue

            pad_len = cc_count
            logger.info(
                f"[{heuristic_name}] Found {pad_len} CC byte(s) at 0x{pad_start_ea:X}-0x{pad_end_ea:X} before function."
            )

            total_blob_len = pad_start_ea - cursor_pos
            if total_blob_len <= 0:
                logger.info(
                    f"[{heuristic_name}] Padding start 0x{pad_start_ea:X} is not after cursor 0x{cursor_pos:X}. Invalid."
                )
                continue
            logger.debug(
                f"[{heuristic_name}] Total space for two blobs: {total_blob_len}"
            )

            min_total_len = 2 * start_offset
            if total_blob_len < min_total_len:
                logger.info(
                    f"[{heuristic_name}] Total blob space {total_blob_len} is less than minimum required {min_total_len}."
                )
                continue

            blob1_len = total_blob_len // 2
            blob2_len = total_blob_len - blob1_len
            logger.debug(
                f"[{heuristic_name}] Proposed split: Blob1={blob1_len}, Blob2={blob2_len}"
            )

            if not (start_offset <= blob1_len <= max_search_distance):
                logger.info(
                    f"[{heuristic_name}] Calculated Blob 1 length {blob1_len} is outside allowed range [{start_offset}, {max_search_distance}]."
                )
                continue
            if not (start_offset <= blob2_len <= max_search_distance):
                logger.info(
                    f"[{heuristic_name}] Calculated Blob 2 length {blob2_len} is outside allowed range [{start_offset}, {max_search_distance}]."
                )
                continue

            predicate_ok, predicate_reason = cls._check_predicate(next_func_ea)
            if not predicate_ok:
                logger.info(
                    f"[{heuristic_name}] Predicate check failed at likely function start 0x{next_func_ea:X} ({predicate_reason})."
                )
                continue

            try:
                next_blob_idx = iteration_count + 1
                if next_blob_idx > CONFIG.MAX_BLOB_INDEX:
                    logger.info(
                        f"[{heuristic_name}] Cannot propose double blob: next index {next_blob_idx} exceeds maximum {CONFIG.MAX_BLOB_INDEX}."
                    )
                    break
                next_blob_name = CONFIG.BLOB_NAME_PATTERN.format(idx=next_blob_idx)
                if idc.get_name_ea_simple(next_blob_name) != idaapi.BADADDR:
                    logger.info(
                        f"[{heuristic_name}] Cannot propose double blob: name '{next_blob_name}' for index {next_blob_idx} is already taken."
                    )
                    break
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
                    return result
                else:
                    logger.info(
                        f"[{heuristic_name}] User declined. Searching for next candidate function..."
                    )
                    continue
            except UserWarning:
                raise
        logger.info(
            f"[{heuristic_name}] No suitable double blob structure found and confirmed."
        )
        return None

    @classmethod
    def _heuristic_fixed_size_fallback(
        cls, cursor_pos: int, iteration_count: int, max_search_distance: int
    ) -> typing.Optional[typing.Tuple[int, int, int]]:
        """Heuristic 5: Fallback to fixed size definition."""
        heuristic_name = "Fixed Size Fallback"
        logger.info(
            f"\n[{heuristic_name}] Falling back to fixed size definition (0x{max_search_distance:X} bytes)..."
        )
        fixed_array_length = max_search_distance
        blob_end_ea = cursor_pos + fixed_array_length
        next_ea = blob_end_ea
        predicate_ok, predicate_reason = cls._check_predicate(next_ea)
        if predicate_ok:
            logger.info(
                f"[{heuristic_name}] Fixed size end address 0x{next_ea:X} meets predicate ({predicate_reason})."
            )
            try:
                result = cls._prompt_user(
                    cursor_pos,
                    iteration_count,
                    pad_start=next_ea,
                    pad_len=0,
                    next_ea=next_ea,
                    predicate_reason=predicate_reason,
                    heuristic_name=heuristic_name,
                    is_fixed_size=True,
                    fixed_size=fixed_array_length,
                )
                return result
            except UserWarning:
                raise
        else:
            logger.info(
                f"[{heuristic_name}] Fixed size end address 0x{next_ea:X} failed predicate check ({predicate_reason}). Cannot apply fixed size."
            )
            return None

    # --- Orchestrator Method ---
    @classmethod
    def find_padding_from_cursor(
        cls, cursor_pos: int, iteration_count: int
    ) -> typing.Optional[
        typing.Union[typing.Tuple[int, int, int], typing.Tuple[int, int, int, int, int]]
    ]:
        """Finds padding or double blobs. Uses settings from CONFIG."""
        start_offset = CONFIG.DEFAULT_PADDING_SEARCH_START_OFFSET
        max_search_distance = CONFIG.DEFAULT_PADDING_SEARCH_MAX_DISTANCE
        min_len_heuristic1 = CONFIG.DEFAULT_MIN_PADDING_LEN
        search_start_ea = cursor_pos + start_offset
        search_end_ea = cursor_pos + max_search_distance
        if not ida_bytes.is_loaded(search_start_ea) or not ida_bytes.is_loaded(
            search_end_ea - 1
        ):
            logger.warning(
                f"Initial search range 0x{search_start_ea:X} - 0x{search_end_ea:X} is not fully loaded."
            )
        heuristics = [
            lambda: cls._heuristic_cc_sequence_scan(
                cursor_pos,
                iteration_count,
                search_start_ea,
                search_end_ea,
                min_len_heuristic1,
            ),
            lambda: cls._heuristic_next_function_boundary(
                cursor_pos, iteration_count, search_end_ea
            ),
            lambda: cls._heuristic_last_cc_before_max(
                cursor_pos, iteration_count, search_start_ea, search_end_ea
            ),
            lambda: cls._heuristic_double_blob(
                cursor_pos, iteration_count, start_offset, max_search_distance
            ),
            lambda: cls._heuristic_fixed_size_fallback(
                cursor_pos, iteration_count, max_search_distance
            ),
        ]
        try:
            for heuristic_func in heuristics:
                result = heuristic_func()
                if result is not None:
                    return result
            logger.info("\nAll heuristics failed or were declined by the user.")
            return None
        except UserWarning:
            raise


# --- Main Execution Function ---
def execute():
    """
    Main execution function using shared state dictionary and finding lowest index.
    Handles both single and double blob definitions using CONFIG settings.
    """
    current_blob_index = get_next_blob_index()
    if current_blob_index > CONFIG.MAX_BLOB_INDEX:
        logger.error(
            f"Cannot proceed: All blob indices (0-{CONFIG.MAX_BLOB_INDEX}) are used."
        )
        ida_kernwin.warning(
            f"All blob indices (0-{CONFIG.MAX_BLOB_INDEX}) appear to be used.\nRun 'reset_blob_index_cache()' if this is incorrect."
        )
        return

    logger.info(
        f"Attempting to find and define blob(s) starting with index: {current_blob_index}"
    )
    logger.info("\n=== Function Padding/Blob Finder ===")
    current_ea = idaapi.get_screen_ea()
    logger.info(f"Processing relative to cursor: 0x{current_ea:X}")
    if not ida_bytes.is_loaded(current_ea):
        logger.error(f"Base address 0x{current_ea:X} not loaded.")
        return

    padding_result = None
    try:
        padding_result = FunctionPaddingFinder.find_padding_from_cursor(
            current_ea, current_blob_index
        )
    except UserWarning as e:
        logger.info(f"\nOperation cancelled by user: {e}")
        return

    if padding_result:
        is_double_blob = isinstance(padding_result, tuple) and len(padding_result) == 5
        if is_double_blob:
            blob1_len, blob2_len, pad_start, pad_len, next_ea = padding_result
            blob1_idx, blob2_idx = current_blob_index, current_blob_index + 1
            blob1_ea, blob2_ea = current_ea, current_ea + blob1_len
            blob1_name = CONFIG.BLOB_NAME_PATTERN.format(idx=blob1_idx)
            blob2_name = CONFIG.BLOB_NAME_PATTERN.format(idx=blob2_idx)
            blob1_type_str = f"const unsigned __int8 {blob1_name}[{blob1_len}];"
            blob2_type_str = f"const unsigned __int8 {blob2_name}[{blob2_len}];"
            logger.info(
                f"Attempting to define double blob: {blob1_name} at 0x{blob1_ea:X} and {blob2_name} at 0x{blob2_ea:X}"
            )
            success1 = set_type(blob1_ea, blob1_type_str, blob1_name)
            if not success1:
                logger.error(f"Failed to define first blob {blob1_name}. Aborting.")
                return
            success2 = set_type(blob2_ea, blob2_type_str, blob2_name)
            if not success2:
                logger.error(
                    f"Defined {blob1_name} but failed to define second blob {blob2_name}. Manual cleanup may be needed."
                )
                return
            logger.info(
                f"Successfully defined double blobs {blob1_name} and {blob2_name} (PUBLIC)."
            )
            reset_blob_index_cache()
            logger.info(
                f"Blob index cache reset. Next run will search for index {get_next_blob_index()}."
            )
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
        else:  # Single Blob
            pad_start, pad_len, next_ea = padding_result
            blob_name = CONFIG.BLOB_NAME_PATTERN.format(idx=current_blob_index)
            if pad_len == 0 and pad_start == next_ea:
                array_len = next_ea - current_ea
            else:
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
                reset_blob_index_cache()
                logger.info(
                    f"Blob index cache reset. Next run will search for index {get_next_blob_index()}."
                )
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
                    logger.info(
                        f"No padding (pad_len=0) to align after blob {blob_name}."
                    )
            else:
                logger.error(
                    f"Failed to define main blob {blob_name}. Skipping padding alignment."
                )
    else:
        logger.info(
            f"\nDid not define blob(s) for index {current_blob_index} based on heuristics relative to 0x{current_ea:X}."
        )
    logger.info("\nScript execution completed!")


# --- Main Execution ---
if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(
        log=logger, level=logging.INFO
    )  # Set to DEBUG for more verbose output
    execute()
    idaapi.refresh_idaview_anyway()

# --- How to Reset Cache ---
# Run manually from IDA Python console:
# try:
#     import sys
#     # Use config to get names
#     cfg = ScriptConfig()
#     del sys.modules['__main__'].g_script_state_storage[cfg.CACHE_KEY_NAME]
#     # Or use the instance if script is loaded:
#     # del sys.modules['__main__'].g_script_state_storage[CONFIG.CACHE_KEY_NAME]
#     print("Blob index cache key reset.")
# except (NameError, AttributeError, KeyError):
#     print("Blob index cache key was not set or storage dict doesn't exist (or CONFIG not defined).")
#
# Or, if the script module is loaded as 'my_blob_script':
# my_blob_script.reset_blob_index_cache()
