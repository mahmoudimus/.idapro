import logging
import re
import typing
import unittest
from unittest.mock import patch

import ida_bytes
import ida_nalt
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc
import unicorn
from mutilz.helpers.ida import clear_output, find_byte_sequence
from mutilz.logconf import configure_debug_logging
from unicorn.x86_const import *

logger = logging.getLogger(__name__)
configure_debug_logging(logger)


KEY_LENGTH_SIGNATURES = [b"8B C3 48 8B 4C 24 ? FF C3 F7 F1 ? ? ? ? ? ? ? ? ? ? ?"]
NUM_KEYS_SIGNATURES = [
    b"8B 84 24 ? ? ? ? F7 F1",
    b"8B 44 ? ? F7 F1",
]

KEY_OFFSET_SIGNATURES = [
    b"48 C7 ? 24 ? ? ? ? ? ? 8D ? ? ? F4 FF 48 8B ? 24 ? ? ? ? ? 8D ?",
    b"48 C7 ? 24 ? ? ? ? ? ? ? 8D ? ? ? F4 FF 48 8B ? 24 ? ? ? ? ? 8D ?",
    b"48 C7 ? 24 ? ? ? ? ? ? ? ? 8D ? ? ? F4 FF 48 8B ? 24 ? ? ? ? ? 8D ?",
    b"48 C7 ? 24 ? ? ? ? ? ? ? ? ? 8D ? ? ? F4 FF 48 8B ? 24 ? ? ? ? ? 8D ?",
]


def count_digits(n: int) -> int:
    """
    Returns the number of digits in the integer n.
    The sign is ignored (i.e., -123 has 3 digits).

    Can also use this implementation but it's longer:
       math.floor(math.log10(abs(n))) + 1 if n != 0 else 1

    """
    return len(str(abs(n)))


KEY_LENGTH_VALIDATION = [
    lambda x: isinstance(x, int),
    lambda x: count_digits(x) == 3 and 0x100 <= x < 0x200,
]

NUM_KEYS_VALIDATION = [
    lambda x: isinstance(x, int),
    lambda x: count_digits(x) == 2 and 0x1E <= x < 0x100,
]

KEY_OFFSET_VALIDATION = [lambda x: isinstance(x, int)]


class UnicornEmulator:
    def __init__(
        self,
        debug=True,
        stack_base=None,
        stack_size=8 * 1024 * 1024,
        flags: int = unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN,
    ):
        self.mu = unicorn.Uc(unicorn.UC_ARCH_X86, flags)
        self.stack_base = stack_base or 0x004000000  # Higher stack base address
        self.stack_size = stack_size or 8 * 1024 * 1024  # 8MB stack size
        self._init()
        self._install_debug_hook(debug)

    def _install_debug_hook(self, debug):
        if debug:
            # Install a hook to print debug information on every executed instruction.
            self.mu.hook_add(unicorn.UC_HOOK_CODE, self._hook_code)

    def _init(self):
        self.mu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self._hook_exception)
        self._map_low_memory()
        self._map_segments()
        self._init_registers()

    def _map_low_memory(self):
        # Map low memory to cover gs:[rax] accesses (e.g., from 0x0 to 0x1000)
        self.mu.mem_map(0x0, 0x1000, unicorn.UC_PROT_ALL)
        seg_bytes = idc.get_bytes(0x0, 0x100)
        if seg_bytes:
            self.mu.mem_write(0x0, seg_bytes)

    def _map_segments(self):
        # Map our code and stack into Unicorn's memory.
        code_segment = ida_segment.get_segm_by_name(".text")  # Get code segment
        self.mu.mem_map(
            code_segment.start_ea,
            code_segment.end_ea - code_segment.start_ea,
            unicorn.UC_PROT_ALL,
        )
        self._map_combined_segments(".data", unicorn.UC_PROT_ALL)
        self.mu.mem_map(
            self.stack_base, self.stack_size, unicorn.UC_PROT_ALL
        )  # Map stack

        code_bytes = idc.get_bytes(
            code_segment.start_ea, code_segment.end_ea - code_segment.start_ea
        )
        self.mu.mem_write(code_segment.start_ea, code_bytes)

    def _init_registers(self):
        # Initialize registers—all set to 0.
        self.mu.reg_write(UC_X86_REG_RIP, self.stack_base)
        self.mu.reg_write(UC_X86_REG_RAX, 0)
        self.mu.reg_write(UC_X86_REG_RBX, 0)
        self.mu.reg_write(UC_X86_REG_RCX, 0)
        self.mu.reg_write(UC_X86_REG_RDX, 0)
        self.mu.reg_write(UC_X86_REG_RSI, 0)
        self.mu.reg_write(UC_X86_REG_RDI, 0)
        self.mu.reg_write(UC_X86_REG_RSP, self.stack_base + self.stack_size - 0x1000)

    def _dump_registers(self, uc=None):
        """Dump all x86_64 registers in a formatted output."""
        if not uc:
            uc = self.mu
        registers = {
            "RAX": unicorn.x86_const.UC_X86_REG_RAX,
            "RBX": unicorn.x86_const.UC_X86_REG_RBX,
            "RCX": unicorn.x86_const.UC_X86_REG_RCX,
            "RDX": unicorn.x86_const.UC_X86_REG_RDX,
            "RSI": unicorn.x86_const.UC_X86_REG_RSI,
            "RDI": unicorn.x86_const.UC_X86_REG_RDI,
            "RBP": unicorn.x86_const.UC_X86_REG_RBP,
            "RSP": unicorn.x86_const.UC_X86_REG_RSP,
            "RIP": unicorn.x86_const.UC_X86_REG_RIP,
            "R8": unicorn.x86_const.UC_X86_REG_R8,
            "R9": unicorn.x86_const.UC_X86_REG_R9,
            "R10": unicorn.x86_const.UC_X86_REG_R10,
            "R11": unicorn.x86_const.UC_X86_REG_R11,
            "R12": unicorn.x86_const.UC_X86_REG_R12,
            "R13": unicorn.x86_const.UC_X86_REG_R13,
            "R14": unicorn.x86_const.UC_X86_REG_R14,
            "R15": unicorn.x86_const.UC_X86_REG_R15,
            "EFLAGS": unicorn.x86_const.UC_X86_REG_EFLAGS,
        }

        print("\n--- Register Dump (x86_64) ---")
        for reg_name, reg_id in registers.items():
            value = uc.reg_read(reg_id)
            padded_reg_name = reg_name.rjust(3)
            print(f"{padded_reg_name}: 0x{value:016X}")
        print("-----------------------------\n")

    def _hook_exception(self, uc, access, address, size, value, user_data):
        """Robust exception hook: attempt to map missing memory so that emulation can continue.
        If the access error is due to unmapped memory, map a page at the aligned address and resume.
        Otherwise, if mapping fails, stop execution."""
        logger.info(
            f"Exception: access={access} at address: 0x{address:016X}, size={size}, value={value}"
        )
        self._dump_registers(uc)

        PAGE_SIZE = 0x1000
        aligned_addr = address & ~(PAGE_SIZE - 1)

        try:
            # Try to map a new page at the missing address with all permissions
            uc.mem_map(aligned_addr, PAGE_SIZE, unicorn.UC_PROT_ALL)
            logger.info(
                f"Mapped missing memory at 0x{aligned_addr:016X} (size: 0x{PAGE_SIZE:X}). Resuming emulation."
            )
            return True  # Resume emulation
        except unicorn.UcError as e:
            logger.error(f"Failed to handle exception at 0x{address:016X}", e)
            return False

    def _hook_code(self, mu, address, size, user_data):
        """
        This hook is called on every instruction executed.
        It prints the current instruction address, the disassembled line (from IDA),
        and some register values.
        """
        disasm_line = idc.generate_disasm_line(address, 0)
        logger.info("Executing 0x%X: %s", address, disasm_line)
        self._dump_registers()

    def _map_combined_segments(
        self, seg_name, prot, PAGE_SIZE=0x1000, copy_content=True
    ):
        segs = []
        for seg_ea in idautils.Segments():
            if idc.get_segm_name(seg_ea) == seg_name:
                seg_start = seg_ea
                seg_end = idc.get_segm_end(seg_ea)
                segs.append((seg_start, seg_end))

        if not segs:
            logger.info("No segments found for", seg_name)
            return

        # Compute the union of all segments.
        min_start = min(seg[0] for seg in segs)
        max_end = max(seg[1] for seg in segs)

        # Align the union to page boundaries.
        aligned_start = min_start & ~(PAGE_SIZE - 1)
        aligned_end = (max_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        size = aligned_end - aligned_start

        logger.info(
            f"Mapping combined segment {seg_name}: {hex(aligned_start)} - {hex(aligned_end)} (size: 0x{size:X})"
        )

        # Map the combined region.
        self.mu.mem_map(aligned_start, size, prot)

        if copy_content:
            # Optionally, write data from each segment into the mapped region.
            for seg_start, seg_end in segs:
                seg_size = seg_end - seg_start
                seg_bytes = idc.get_bytes(seg_start, seg_size)
                if seg_bytes:
                    self.mu.mem_write(seg_start, seg_bytes)
        return aligned_start, size

    def emulate(self, start_ea, end_ea) -> unicorn.Uc:
        code_size = end_ea - start_ea
        try:
            self.mu.emu_start(start_ea, start_ea + code_size)
        except unicorn.UcError as e:
            print("Emulation error: %s" % e)

        return self.mu


def emulate_range_with_unicorn(start_ea, end_ea):
    """
    Emulate the code between start_ea and end_ea using Unicorn.
    All registers are initialized to zero.
    A hook is installed to print each instruction as it executes.
    Returns the final value in EAX.
    """
    code_size = end_ea - start_ea
    code = ida_bytes.get_bytes(start_ea, code_size)
    if code is None:
        print("Could not retrieve code bytes from 0x%X to 0x%X" % (start_ea, end_ea))
        return None

    print(
        "Emulating code from 0x%X to 0x%X (size=0x%X)" % (start_ea, end_ea, code_size)
    )
    emulator = UnicornEmulator()
    return emulator.emulate(start_ea, end_ea)


def find_anchor_and_emulate(ea: int):
    # First, locate the anchor instruction using your preferred method.
    # Here we assume that the anchor has been located (e.g. by a previous decoding loop)
    # and is stored in the variable "anchor". If not found, we print an error and return.
    anchor = decode_anchor(ea)  # Assume decode_anchor() implements your upward search
    if anchor is None:
        logger.info("No anchor (xor reg, reg) found upward from 0x%X" % ea)
        return None

    # Now traverse downward from the anchor to find the "div ecx" instruction.
    end = None
    current = anchor
    while current != idc.BADADDR:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current) <= 0:
            current = idc.next_head(current)
            continue  # Skip if the instruction cannot be decoded
        logger.debug(
            "decoded %s at 0x%X", idc.generate_disasm_line(current, 0), current
        )
        mnem = insn.get_canon_mnem().lower()
        if mnem != "div":
            current = idc.next_head(current)
            continue  # Not a 'div' instruction, skip to next

        # Use a list comprehension to filter out unused operands.
        ops = [op for op in insn.ops if op.type != ida_ua.o_void]
        # For a DIV instruction, the explicit divisor is typically in operand index 1,
        # but if there's only one operand, fall back to operand index 0.
        op = ops[1] if len(ops) > 1 else ops[0]

        if op.type != ida_ua.o_reg:
            current = idc.next_head(current)
            continue  # Operand is not a register

        logger.debug("register: %s", op.reg)
        reg_name = idaapi.get_reg_name(op.reg, 4)  # 4 bytes for a 32-bit register
        logger.debug("reg_name: %s", reg_name)
        if reg_name.lower() != "ecx":
            current = idc.next_head(current)
            continue  # Register is not ECX

        # Valid 'div ecx' instruction found.
        end = (
            current + insn.size
        )  # Use insn.size (or idc.get_item_size(current) if needed)
        logger.debug(
            "Found 'div ecx' at 0x%X: %s",
            current,
            idc.generate_disasm_line(current, 0),
        )
        break

    if end is None:
        logger.info("No 'div ecx' instruction found downward from anchor.")
        return None

    mu = emulate_range_with_unicorn(anchor, end)
    x = mu.reg_read(UC_X86_REG_RCX)
    logger.info("Final RCX: 0x%X (%d)", x, x)
    return x


# Example helper function to find the anchor using decoding.
def decode_anchor(ea: int):
    """
    Backtracks upward from the given effective address until a MOV instruction that writes an immediate
    constant into a memory operand is found. Returns the anchor address or None if not found.
    """
    current = ea
    while current != idaapi.BADADDR:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current) > 0:
            mnem = insn.get_canon_mnem().lower()
            if mnem != "mov":
                current = idc.prev_head(current)
                continue
            # Check that the first operand is a memory reference and the second is an immediate.
            if (
                insn.ops[0].type in (ida_ua.o_mem, ida_ua.o_displ)
                and insn.ops[1].type == ida_ua.o_imm
            ):
                logger.debug("Found constant assignment anchor at 0x%X", current)
                return current
        current = idc.prev_head(current)
    return None


def process_signatures(segment, signatures, validators, param_name):
    """
    Iterates through the provided signatures to find and validate a parameter.
    Returns a tuple (value, ea) if a valid parameter is found, or (None, None) otherwise.
    """
    for signature in signatures:
        for ea in find_byte_sequence(segment.start_ea, segment.end_ea, signature):
            logger.debug(f"Found at 0x{ea:X}")
            value = find_anchor_and_emulate(ea)
            logger.debug(f"{param_name} value: %d", value)
            if all(validation(value) for validation in validators):
                logger.info("Valid %s: %d", param_name, value)
                return value, ea
    return None, None


def process_key_offset_signature(segment, signatures, validators):
    """
    Iterates through the provided signatures to find and validate a key offset.
    Returns a tuple (value, ea) if a valid key offset is found, or (None, None) otherwise.
    """
    for signature in signatures:
        for ea in find_byte_sequence(segment.start_ea, segment.end_ea, signature):
            logger.debug(f"Found at 0x{ea:X}")
            value = emulate_until_lea_rdi(ea)
            logger.debug(f"key offset value: %d", value)
            if all(validation(value) for validation in validators):
                logger.info("Key address: 0x%X", value)
                return value, ea
    return None, None


def emulate_until_lea_rdi(start_ea: int):
    """
    Emulates code starting at start_ea until a 'lea rdi' instruction is encountered.
    It then executes that 'lea rdi' instruction and returns the value of RDI after execution.

    The emulation is done in two phases:
      1. From start_ea up to (but not including) the target instruction.
      2. Then emulates the target instruction alone.

    Returns:
        The value in RDI after executing the 'lea rdi' instruction, or None on error.
    """
    # --- Phase 1: Locate the target instruction ---
    target_ea = None
    current = start_ea
    while current != idc.BADADDR:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current) <= 0:
            current = idc.next_head(current)
            continue
        mnem = insn.get_canon_mnem().lower()
        if mnem == "lea":
            # Check if the destination operand (first operand) is rdi.
            if insn.ops[0].type == ida_ua.o_reg:
                dest_reg = idaapi.get_reg_name(insn.ops[0].reg, 8)
                if dest_reg.lower() == "rdi":
                    target_ea = current
                    break
        current = idc.next_head(current)

    if target_ea is None:
        logger.info("No 'lea rdi' instruction found starting from 0x%X", start_ea)
        return None

    logger.debug("Found target 'lea rdi' at 0x%X", target_ea)
    mu = emulate_range_with_unicorn(start_ea, idc.next_head(target_ea))
    x = mu.reg_read(UC_X86_REG_RDI)
    logger.info("Final RDI: 0x%X (%d)", x, x)
    return x


def set_type(ea, type_str, name):
    # Parse the declaration into a tinfo_t structure.
    tinfo = idc.parse_decl(type_str, idc.PT_SILENT)
    if not tinfo:
        print("Error parsing type declaration")
        return False
    # Apply the type to the address.
    if idc.apply_type(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
        # Explicitly set the name.
        if idc.set_name(ea, name, idc.SN_NOWARN):
            print("Type and name applied successfully.")
        else:
            print("Type applied but failed to rename.")
        return True
    else:
        print("Failed to apply type.")
        return False


def find_crypto_key():
    segment = ida_segment.get_segm_by_name(".text")
    # Process key length signatures.
    key_length, key_ea = process_signatures(
        segment, KEY_LENGTH_SIGNATURES, KEY_LENGTH_VALIDATION, "key length"
    )
    # Optionally use key_length and key_ea as needed.

    # Process number of keys signatures.
    num_keys, num_ea = process_signatures(
        segment, NUM_KEYS_SIGNATURES, NUM_KEYS_VALIDATION, "num keys"
    )

    # Optionally use num_keys and num_ea as needed.
    key_offset, key_offset_ea = process_key_offset_signature(
        segment, KEY_OFFSET_SIGNATURES, KEY_OFFSET_VALIDATION
    )

    logger.info("unsigned __int8 g_bufCryptoKey[0x%X][0x%X];", num_keys, key_length)
    logger.info("g_bufCryptoKey offset: 0x%X", key_offset)

    if not set_type(
        key_offset,
        f"unsigned __int8 g_bufCryptoKey[{num_keys}][{key_length}]",
        "g_bufCryptoKey",
    ):
        logger.error("Failed to set type for g_bufCryptoKey")
        if not idc.make_array(key_offset, num_keys * key_length):
            logger.error("Failed to make array for g_bufCryptoKey")


# --- Global Fixture Dictionary ---
TEST_CASE = {
    1: {
        0x1400B965E: "48 C7 44 24 78 93 11 00 00    mov     [rsp+3F8h+var_380], 1193h",
        0x1400B9667: "48 C1 E9 20                   shr     rcx, 20h",
        0x1400B966B: "C1 C9 0B                      ror     ecx, 0Bh",
        0x1400B966E: "33 C8                         xor     ecx, eax",
        0x1400B9670: "49 C1 EF 20                   shr     r15, 20h",
        0x1400B9674: "48 8B 44 24 78                mov     rax, [rsp+3F8h+var_380]",
        0x1400B9679: "4C 33 F9                      xor     r15, rcx",
        0x1400B967C: "48 05 29 0D 00 00             add     rax, 0D29h",
        0x1400B9682: "49 C1 E7 20                   shl     r15, 20h",
        0x1400B9686: "48 89 44 24 78                mov     [rsp+3F8h+var_380], rax",
        0x1400B968B: "4C 0B FA                      or      r15, rdx",
        0x1400B968E: "48 8B 44 24 78                mov     rax, [rsp+3F8h+var_380]",
        0x1400B9693: "33 D2                         xor     edx, edx",
        0x1400B9695: "48 05 5A FC FF FF             add     rax, 0FFFFFFFFFFFFFC5Ah",
        0x1400B969B: "4C 89 BC 24 B0 00 00 00       mov     [rsp+3F8h+var_348], r15",
        0x1400B96A3: "48 89 44 24 78                mov     [rsp+3F8h+var_380], rax",
        0x1400B96A8: "48 8B 44 24 78                mov     rax, [rsp+3F8h+var_380]",
        0x1400B96AD: "48 35 16 0B 00 00             xor     rax, 0B16h",
        0x1400B96B3: "48 89 44 24 78                mov     [rsp+3F8h+var_380], rax",
        0x1400B96B8: "48 8B 4C 24 78                mov     rcx, [rsp+3F8h+var_380]",
        0x1400B96BD: "8B 84 24 E0 03 00 00          mov     eax, [rsp+3F8h+var_18]",
        0x1400B96C4: "F7 F1                         div     ecx",
    },
    2: {
        0x14001DA73: "48 C7 44 24 28 CF F4 FF FF    mov     [rsp+930h+var_908], 0FFFFFFFFFFFFF4CFh",
        0x14001DA7C: "33 D2                         xor     edx, edx",
        0x14001DA7E: "48 8B 44 24 28                mov     rax, [rsp+930h+var_908]",
        0x14001DA83: "48 89 44 24 28                mov     [rsp+930h+var_908], rax",
        0x14001DA88: "48 8B 44 24 28                mov     rax, [rsp+930h+var_908]",
        0x14001DA8D: "48 35 5D 0D 00 00             xor     rax, 0D5Dh",
        0x14001DA93: "48 89 44 24 28                mov     [rsp+930h+var_908], rax",
        0x14001DA98: "48 8B 44 24 28                mov     rax, [rsp+930h+var_908]",
        0x14001DA9D: "48 05 D7 07 00 00             add     rax, 7D7h",
        0x14001DAA3: "48 89 44 24 28                mov     [rsp+930h+var_908], rax",
        0x14001DAA8: "48 8B 44 24 28                mov     rax, [rsp+930h+var_908]",
        0x14001DAAD: "48 89 44 24 28                mov     [rsp+930h+var_908], rax",
        0x14001DAB2: "8B C3                         mov     eax, ebx",
        0x14001DAB4: "48 8B 4C 24 28                mov     rcx, [rsp+930h+var_908]",
        0x14001DAB9: "F7 F1                         div     ecx",
    },
}

# Global variable used by the fake IDA API functions.
CURRENT_TEST = {}


# --- Fake IDA API Functions (using CURRENT_TEST) ---
def fake_generate_disasm_line(ea, flags):
    return CURRENT_TEST.get(ea, "")


def fake_print_insn_mnem(ea):
    line = CURRENT_TEST.get(ea, "")
    # Split on 2 or more whitespace characters.
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) >= 2:
        return parts[1]
    # Fallback: return the first alphabetic token.
    tokens = line.split()
    for token in tokens:
        if token.isalpha():
            return token
    return ""


def fake_prev_head(ea):
    addresses = sorted(CURRENT_TEST.keys())
    try:
        idx = addresses.index(ea)
    except ValueError:
        return idaapi.BADADDR
    return addresses[idx - 1] if idx > 0 else idaapi.BADADDR


def fake_next_head(ea):
    addresses = sorted(CURRENT_TEST.keys())
    try:
        idx = addresses.index(ea)
    except ValueError:
        return idaapi.BADADDR
    return addresses[idx + 1] if idx < len(addresses) - 1 else idaapi.BADADDR


def fake_get_item_size(ea):
    # For testing, assume each instruction has a fixed size.
    return 5


# --- Heuristic Function ---
def get_mem_symbol(operand: str) -> str:
    """
    Extracts a symbolic name from a memory operand.
    E.g., from "[rsp+3F8h+var_380]" returns "var_380".
    """
    if "var_" in operand:
        idx = operand.find("var_")
        sym = operand[idx:]
        for term in [" ", "]"]:
            sym = sym.split(term)[0]
        return sym
    return operand


# --- Unit Test Class Using unittest.mock.patch ---
class TestFindAnchor(unittest.TestCase):
    @patch("idc.get_item_size", side_effect=fake_get_item_size)
    @patch("idc.next_head", side_effect=fake_next_head)
    @patch("idc.prev_head", side_effect=fake_prev_head)
    @patch("idc.print_insn_mnem", side_effect=fake_print_insn_mnem)
    @patch("idc.generate_disasm_line", side_effect=fake_generate_disasm_line)
    def test_case_1(self, mock_generate, mock_mnem, mock_prev, mock_next, mock_size):
        global CURRENT_TEST
        CURRENT_TEST = TEST_CASE[1]
        starting_ea = 0x1400B96B8
        anchor = find_anchor_and_emulate(starting_ea)
        print("Test case 1: Anchor found at 0x%X" % anchor)
        self.assertEqual(
            anchor, 0x1400B965E, "Anchor did not match expected value for test case 1."
        )

    @patch("idc.get_item_size", side_effect=fake_get_item_size)
    @patch("idc.next_head", side_effect=fake_next_head)
    @patch("idc.prev_head", side_effect=fake_prev_head)
    @patch("idc.print_insn_mnem", side_effect=fake_print_insn_mnem)
    @patch("idc.generate_disasm_line", side_effect=fake_generate_disasm_line)
    def test_case_2(self, mock_generate, mock_mnem, mock_prev, mock_next, mock_size):
        global CURRENT_TEST
        CURRENT_TEST = TEST_CASE[2]
        starting_ea = 0x14001DAB4
        anchor = find_anchor_and_emulate(starting_ea)
        print("Test case 2: Anchor found at 0x%X" % anchor)
        self.assertEqual(
            anchor, 0x14001DA73, "Anchor did not match expected value for test case 2."
        )


def run_tests():
    try:
        unittest.main()
    except SystemExit as e:
        if e.code != 0:
            print(f"Error running tests: {e}")


if __name__ == "__main__":
    clear_output()
    # run_tests()
    # unittest.main()
    find_crypto_key()
