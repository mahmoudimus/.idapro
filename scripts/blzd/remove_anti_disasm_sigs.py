# -----------------------------------------------------------------------
# IDAPython script to UNDO the anti-disassembly code
# This script:
#  1) Searches for the 11-byte signature (Aegis::X86::AntidisasmSignature).
#  2) Reads the extra bytes (patchBytes[11]) and type byte (patchBytes[12]).
#  3) Uses logic similar to GetEndSignatureSize_X64() to locate the "end" jump.
#  4) Computes total size of the patch region.
#  5) Replaces that entire region with benign instructions (NOPs).
#
# Because we do NOT have the original code, the best we can do is remove
# the random junk. In a real scenario, you might want to fix any cross-references
# or forcibly unify them to one short jump, etc. This script uses the simplest
# approach: turn everything into NOPs. Then you can re-run IDA's auto-analysis.
#
# If you see incomplete references after patching, you can finalize by:
#     Edit -> Segments -> Reanalyze program area
# or by calling idaapi.auto_wait() in a follow-up step, etc.
#
# -----------------------------------------------------------------------

import logging
import ctypes
from dataclasses import dataclass

import ida_bytes
import ida_ida
import ida_nalt
import idaapi
import idautils
import idc
from mutilz.helpers.ida import clear_output, format_addr
from mutilz.logconf import configure_debug_logging

logger = logging.getLogger(__name__)
configure_debug_logging(logger)

# fmt: off
# NOP patterns from the source code
# -----------------------------------------------------------------------
#  Check if 'ea' points to a recognized NOP pattern (x86/x64 multi-byte).
#  If so, returns the length of that pattern in 'nop_len', else 0.
#  The snippet in "IsNop" checks patterns up to 11 bytes. We'll keep it simple:
#  Check for 1-byte 0x90 or a few standard multi-byte sequences. Extend if needed.
# -----------------------------------------------------------------------
NOP_PATTERNS = [
    # 1-byte NOP
    [0x90],
    # 2-byte XCHG AX,AX
    [0x66, 0x90],
    # 3-byte NOP DWORD ptr [RAX]
    [0x0F, 0x1F, 0x00],
    # 4-byte NOP DWORD ptr [RAX + 0]
    [0x0F, 0x1F, 0x40, 0x00],
    # 5-byte NOP DWORD ptr [RAX + RAX + 0]
    [0x0F, 0x1F, 0x44, 0x00, 0x00],
    # 6-byte NOP WORD ptr [RAX + RAX + 0]
    [0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
    # 7-byte NOP DWORD ptr [RAX + 0] (variant)
    [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00],
    # 8-byte NOP DWORD ptr [RAX + RAX + 0] (variant)
    [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 9-byte NOP WORD ptr [RAX + RAX + 0] (variant)
    [0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 10-byte NOP with extra prefix
    [0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    # 11-byte NOP with three 0x66 prefixes
    [0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
]
# fmt: on


# The known 11-byte signature from "Aegis::X86::AntidisasmSignature"
ANTIDISASM_SIG = [0x65, 0x48, 0x81, 0x04, 0x25, 0x41, 0x45, 0x47, 0x49, 0x53, 0x5F]


# -----------------------------------------------------------------------
#  Helper: Convert a list of bytes to a string for ida_bytes.find_binary usage.
# -----------------------------------------------------------------------
def bytes_list_to_hex_string(byte_list):
    # e.g. [0x65, 0x48, 0x81] -> "65 48 81"
    return " ".join("{:02X}".format(b) for b in byte_list)


# -----------------------------------------------------------------------
#  EvaluateJump_X64(inst_ptr):
#     Returns (jmp_dest, jmp_size) if recognized jump, else (None, 0).
#     See EvaluateJump_X64 in your snippet.
# -----------------------------------------------------------------------
def EvaluateJump_X64(ea):
    opcode = idaapi.get_byte(ea)

    # Short jumps: 0x70..0x7F (conditional), 0xEB (unconditional)
    if (0x70 <= opcode <= 0x7F) or (opcode == 0xEB):
        offset = idc.get_operand_value(ea, 0)
        jmp_size = 2
        jmp_dest = ea + jmp_size + offset
        return (jmp_dest, jmp_size)

    # Near jmp (0xE9)
    elif opcode == 0xE9:
        # size = 5 bytes
        offset = idc.get_operand_value(ea, 0)
        jmp_size = 5
        jmp_dest = ea + jmp_size + offset
        return (jmp_dest, jmp_size)

    # Near conditional jumps: 0x0F 0x80..0x8F
    elif opcode == 0x0F:
        opcode2 = idaapi.get_byte(ea + 1)
        if 0x80 <= opcode2 <= 0x8F:
            # size = 6 bytes
            offset = idc.get_operand_value(ea, 0)
            jmp_size = 6
            jmp_dest = ea + jmp_size + offset
            return (jmp_dest, jmp_size)

    # No recognized jump
    return (None, 0)


def is_nop(ea):
    for pattern in NOP_PATTERNS:
        # Read 'len(pattern)' bytes from 'ea'
        read_bytes = idaapi.get_bytes(ea, len(pattern))
        if read_bytes is None:
            continue
        if list(read_bytes) == pattern:
            return len(pattern)
    return 0


# -----------------------------------------------------------------------
#  Check if "jmpDest" is correct jump destination per "IsCorrectJumpDestination".
#  1) direct match?
#  2) if NOP, skip the NOP(s) until we land on patch_start?
# -----------------------------------------------------------------------
def is_correct_jump_destination(jmp_dest, patch_start):
    if jmp_dest == patch_start:
        return True

    # Possibly lands on a NOP region that leads to patch_start
    # We'll do a small loop to skip over consecutive NOP patterns
    ea = jmp_dest
    while True:
        nop_len = is_nop(ea)
        if nop_len == 0:
            break
        ea += nop_len

    return ea == patch_start


# -----------------------------------------------------------------------
#  Emulates "GetEndSignatureSize_X64(pPatchBytes, extraBytes, &endSize)"
#  We do a 32-byte search from 'jump_search_ea' to find a jump that leads
#  back to patch_start. If we don't find it, we fail.
# -----------------------------------------------------------------------
def get_end_signature_size_x64(patch_start, extra_bytes):
    """
    :param patch_start: EA of the anti-disasm signature start
    :param extra_bytes: The 'patchBytes[11]' from the snippet
    :return: end_signature_size or None if failure
    """
    # The snippet: pJmpSearch = pPatchBytes + nExtraBytes + 13
    jump_search_ea = patch_start + extra_bytes + 13

    # We'll search up to 0x20 bytes from jump_search_ea
    for i in range(0x20):
        ea_current = jump_search_ea + i
        jmp_dest, jmp_size = EvaluateJump_X64(ea_current)
        if jmp_dest is not None:
            # Found a jump
            if is_correct_jump_destination(jmp_dest, patch_start):
                # pEnd = ea_current + jmp_size
                p_end = ea_current + jmp_size
                end_size = p_end - jump_search_ea
                return end_size
            else:
                #
                # The code tries to see if there's a "chained" jump
                # and re-check further. We'll replicate that logic in
                # simplified form here. If there's time, keep going
                #
                # We'll keep scanning the remainder of the 0x20 window
                # to see if we eventually find a jump pointing back.
                continue_dest = jmp_dest
                idx = i + jmp_size
                while idx < 0x20:
                    ea_chain = jump_search_ea + idx
                    chain_dest, chain_size = EvaluateJump_X64(ea_chain)
                    if chain_dest is not None:
                        if is_correct_jump_destination(chain_dest, patch_start):
                            # found final jump
                            p_end = ea_chain + chain_size
                            end_size = p_end - jump_search_ea
                            return end_size
                        else:
                            # chain again
                            continue_dest = chain_dest
                            idx += chain_size
                            continue
                    idx += 1
                # if we fail chain, keep searching
    return None


@dataclass(repr=False)
class PatchOperation:
    """Class to store patch operations that will be applied later."""

    address: int
    byte_values: bytes

    def apply(self):
        """Apply the patch operation."""
        ida_bytes.patch_bytes(self.address, self.byte_values)
        logger.debug(
            f"Applied patch at 0x{self.address:x} with value {self.byte_values.hex()}"
        )

    def __str__(self):
        """String representation with hex formatting."""
        return f"{self.__class__.__name__}(address=0x{self.address:X} , byte_values={self.byte_values.hex()})"

    __repr__ = __str__


def _bin_search(start, end, pattern):
    patterns = ida_bytes.compiled_binpat_vec_t()
    seqstr = pattern
    # try:
    #     seqstr = " ".join([f"{b:02x}" if b != -1 else "?" for b in pattern])
    # except ValueError:
    #     seqstr = pattern
    err = ida_bytes.parse_binpat_str(
        patterns,
        start,
        seqstr,
        16,
        ida_nalt.get_default_encoding_idx(  # use one byte-per-character encoding
            ida_nalt.BPU_1B
        ),
    )
    if err:
        return idaapi.BADADDR

    return ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)


# -----------------------------------------------------------------------
#  Main function to locate & unpatch the anti-disassembly code.
# -----------------------------------------------------------------------
def undo_anti_disassembly_x64():
    sig_hex = bytes_list_to_hex_string(ANTIDISASM_SIG)
    ea = 0
    count_patches = 0
    patch_ops = []

    # We use find_binary in a loop, searching from 'ea'
    while True:
        # IDA expression: search for "65 48 81 04 25 41 45 47 49 53 5F"
        ea, _ = _bin_search(ea, idc.get_inf_attr(idc.INF_MAX_EA), sig_hex)
        if ea == idc.BADADDR:
            break  # no more matches

        patch_start = ea
        print("[+] Found anti-disasm signature at 0x{:X}".format(patch_start))

        # Read the next 2 bytes: extraByte = patchBytes[11], typeByte = patchBytes[12]
        # Since signature is 11 bytes, these two are patch_start+11 and patch_start+12
        extra_byte_ea = patch_start + 11
        type_byte_ea = patch_start + 12

        extra_bytes = idaapi.get_byte(extra_byte_ea)
        type_bytes = idaapi.get_byte(type_byte_ea)

        print(
            "    extra_bytes = 0x{:X}, antiDisasmType = 0x{:X}".format(
                extra_bytes, type_bytes
            )
        )

        # Now replicate get_end_signature_size_x64 to find the patch “end”
        end_size = get_end_signature_size_x64(patch_start, extra_bytes)
        if end_size is None:
            print("    [-] Could not find final jump for anti-disasm region. Skipping.")
            # Move EA forward so we don't get stuck re-finding the same signature
            ea = patch_start + 1
            continue

        # The snippet code says:
        #   signatureSize = 11 (the signature)
        #   totalBytes = signatureSize + extraBytes + endSize + 2
        # The +2 presumably accounts for the last "2 bytes" after the jump region, or
        # something. We'll replicate that:
        signature_size = 11
        total_bytes = signature_size + extra_bytes + end_size + 2

        # We'll confirm that we won't overflow or run off memory
        patch_end = patch_start + total_bytes

        # We also want to confirm patch_end is valid
        if patch_end > idc.get_inf_attr(idc.INF_MAX_EA):
            print("    [-] patch_end goes beyond the loaded database. Skipping.")
            ea = patch_start + 1
            continue

        # Let's do the actual patch: we'll NOP out everything from patch_start to patch_end
        print(
            "    Patching out anti-disasm region from 0x{:X} to 0x{:X} (size=0x{:X})".format(
                patch_start, patch_end, total_bytes
            )
        )
        patch_ops = [PatchOperation(patch_start, b"\x90" * (patch_end - patch_start))]

        # # Force IDA to reanalyze
        # idc.create_insn(patch_start)

        count_patches += 1

        # Move 'ea' beyond this patch so we can find the next occurrence
        ea = patch_end

    print("[*] Total anti-disasm patches identified: {}".format(count_patches))

    for patch_op in patch_ops:
        patch_op.apply()


# -----------------------------------------------------------------------
#  Boilerplate to run the script
# -----------------------------------------------------------------------
def main():
    idaapi.auto_wait()  # Wait for initial autoanalysis (optional in IDA >= 7.5)

    # If you're sure the binary is x64, call the function directly.
    # Otherwise, you could detect architecture from idaapi.get_inf_structure().
    is_64 = ida_ida.inf_is_64bit()
    if is_64:
        undo_anti_disassembly_x64()
    else:
        print("[-] This script currently only handles x64 logic. Extend if needed.")


if __name__ == "__main__":
    main()
