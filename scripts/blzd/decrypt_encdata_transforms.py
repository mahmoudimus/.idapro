import collections
import re
import traceback

import capstone
import ida_bytes
import ida_ua
import idaapi
import idautils
import idc
from mutilz.helpers.ida import clear_output


# --- RC4 Implementations ---
# (standard_rc4 and nonstd_rc4 functions remain the same as before)
def nonstd_rc4(input_buf: bytes | bytearray, key: bytes | bytearray) -> bytearray:
    key_size = len(key)
    if key_size == 0:
        raise ValueError("Key size cannot be zero")
    state = bytearray(range(256))
    j = 0
    for k in range(256):
        j = (j + state[k] + key[k % key_size]) & 0xFF
        state[k], state[j] = state[j], state[k]
    x = 0
    y = 0
    output_buf = bytearray(len(input_buf))
    for m in range(len(input_buf)):
        x = (x + 1) & 0xFF
        y = (y + state[x]) & 0xFF
        state[x], state[y] = state[y], state[x]
        keystream_byte = state[y]  # Non-standard: Use state[y] AFTER swap
        output_buf[m] = input_buf[m] ^ keystream_byte
    return output_buf


# --- Utility Functions ---
# (hexdump, decode_instructions_from_bytes, decode_patched_instructions remain the same)
def hexdump(data, addr, bytes_per_line=16, joined=True):
    result = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_values = " ".join(f"{b:02X}" for b in chunk)
        ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        result.append(
            f"{addr+i:08X}: {hex_values.ljust(bytes_per_line*3)} {ascii_values}"
        )
    return "\n".join(result) if joined else result


def compute_i_value():
    """
    Reads the ULONG32 NumberOfPhysicalPages from KUSER_SHARED_DATA (0x7FFE0000 + 0x2E8),
    computes a 64-bit FNV-1a hash using the standard offset basis (0xCBF29CE484222325)
    and prime (0x100000001B3), then sums the hexadecimal nibbles of the result.
    """
    kuser_shared_data = 0x7FFE0000
    num_phys_pages_addr = kuser_shared_data + 0x2E8
    data = idc.get_bytes(num_phys_pages_addr, 4)
    if data is None or len(data) != 4:
        print(
            "Failed to read NumberOfPhysicalPages from KUSER_SHARED_DATA at 0x{:X}".format(
                num_phys_pages_addr
            )
        )
        return None
    fnv_prime = 0x100000001B3
    fnv_offset_basis = 0xCBF29CE484222325
    hash_val = fnv_offset_basis
    for b in data:
        # Each byte 'b' is an integer (in Python 3, get_bytes returns a bytes object)
        hash_val = (hash_val ^ b) * fnv_prime
        hash_val &= 0xFFFFFFFFFFFFFFFF  # ensure 64-bit arithmetic
    # Sum the hexadecimal nibbles of hash_val
    i_val = 0
    tmp = hash_val
    while tmp:
        i_val += tmp & 0xF
        tmp >>= 4
    return i_val


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


def decode_instructions_from_bytes(data_bytes, start_ea, max_lines=20):
    print(
        f"[*] Attempting to decode {len(data_bytes)} bytes starting conceptually at 0x{start_ea:X}:"
    )
    offset = 0
    lines = 0
    data_bytes_len = len(data_bytes)
    while offset < data_bytes_len and lines < max_lines:
        chunk_len = min(16, len(data_bytes) - offset)
        hex_str = " ".join(f"{b:02X}" for b in data_bytes[offset : offset + chunk_len])
        print(
            f"    0x{start_ea + offset:X}: {hex_str} ... (Dry run: Full decode requires patching)"
        )
        break

    disasmed = md.disasm(data_bytes, start_ea)

    while offset < data_bytes_len and lines < max_lines:
        current_ea = start_ea + offset
        try:
            insn = next(disasmed)
        except StopIteration:
            break
        insn_len = insn.size
        if insn_len == 0:
            print(f"    0x{current_ea:X}: Failed to decode instruction.")
            break
        print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        offset += insn_len
        lines += 1

    if offset < data_bytes_len and lines == max_lines:
        print(f"    ... (stopped after {max_lines} lines)")
    elif offset < data_bytes_len and insn_len == 0:
        print(f"    ... (stopped decoding at 0x{start_ea + offset:X})")


def decode_patched_instructions(start_ea, size, max_lines=20):
    print(f"[*] Decoding instructions in IDB from 0x{start_ea:X} (size 0x{size:X}):")
    offset = 0
    insn = ida_ua.insn_t()
    lines = 0
    while offset < size and lines < max_lines:
        current_ea = start_ea + offset
        insn_len = ida_ua.decode_insn(insn, current_ea)
        if insn_len == 0:
            flags = ida_bytes.get_flags(current_ea)
            if not ida_bytes.is_code(flags) and offset > 0:
                print(f"    0x{current_ea:X}: Encountered non-code data.")
            else:
                print(f"    0x{current_ea:X}: Failed to decode instruction.")
            break
        disasm_line = idc.generate_disasm_line(current_ea, 0)
        print(f"    {disasm_line}")
        offset += insn_len
        lines += 1
    if offset < size and lines == max_lines:
        print(f"    ... (stopped after {max_lines} lines)")
    elif offset < size and insn_len == 0:
        print(f"    ... (stopped decoding at 0x{start_ea + offset:X})")


def find_symbol_ea(symbol_name):
    """Finds the effective address of a symbol."""
    ea = idc.get_name_ea_simple(symbol_name)
    if ea == idaapi.BADADDR:
        demangled_symbol_name = idc.demangle_name(
            symbol_name, idc.get_inf_attr(idc.INF_SHORT_DN)
        )

        for n_ea, n_name in idautils.Names():
            demangled_n_name = idc.demangle_name(
                n_name, idc.get_inf_attr(idc.INF_SHORT_DN)
            )

            # Basic substring check, might need refinement for mangled names
            if any(
                [
                    symbol_name in n_name,
                    demangled_symbol_name and demangled_symbol_name in demangled_n_name,
                    demangled_n_name and symbol_name in demangled_n_name,
                ]
            ):
                print(
                    f"[!] Found potential match for '{symbol_name}' -> '{n_name}' at 0x{n_ea:X}"
                )
                ea = n_ea
                break
    if ea == idaapi.BADADDR:
        print(f"[-] ERROR: Symbol '{symbol_name}' not found.")
        return None
    print(f"[+] Found symbol '{symbol_name}' at 0x{ea:X}")
    return ea


def read_ida_bytes(ea, size):
    """Reads bytes from IDA database."""
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size:
        print(
            f"[-] ERROR: Failed to read {size} bytes from 0x{ea:X} (read {len(data) if data else 0})."
        )
        return None
    return data


# --- Main Decryption Logic ---


def undo_aegis_encryption(
    poly_a,
    poly_b,
    poly_c,
    poly_d,
    dry_run=False,
    patch_mode="patch",
    dump_decrypted=False,
    decode_decrypted=False,
):
    """
    Reverses the Aegis transform function encryption in IDA, assuming fixed-size
    blocks due to missing individual size information.

    Args:
        poly_a, poly_b, poly_c, poly_d: Polynomial coefficients.
        dry_run (bool): If True, performs all steps except patching the IDB.
        patch_mode (str): 'patch' or 'put'.
        dump_decrypted (bool): If True, hexdumps the decrypted bytes.
        decode_decrypted (bool): If True, attempts to decode the decrypted bytes.
        use_standard_rc4 (bool): If True, uses standard RC4. False uses variant.
    """
    print("--- Starting Aegis Encryption Reversal (Fixed-Size Assumption) ---")
    if dry_run:
        print("[!] DRY RUN MODE ENABLED: No changes will be made to the IDB.")
    else:
        print(f"[!] Patch Mode: '{patch_mode}'")

    if decode_decrypted and dry_run:
        print("[!] Decode Mode: Limited preview (dry run).")
    elif decode_decrypted:
        print("[!] Decode Mode: Decode from IDB after patch.")

    expected_transform_count = 16
    rc4_key_size = 137  # 0x89
    # Size of the block used for XORing, based on C++ Random::Buffer call
    transform_func_xor_size = 1024
    # Assumed fixed size for each encrypted transform block, based on runtime
    # decryption and XOR source size. THIS MAY NOT MATCH ORIGINAL SIZES.
    assumed_transform_block_size = 1024
    print(
        f"[!] Assuming fixed block size for encrypted transforms: 0x{assumed_transform_block_size:X} bytes."
    )

    # 1. Find essential symbols
    ea_start = find_symbol_ea("EncData_Transform_0")
    if ea_start is None:
        ea_start = find_symbol_ea("?EncData_Transform_0@@YAXAEA_K0@Z")
        return False

    ea_final_transform = find_symbol_ea("Aegis::EncData::EncryptedDataTransform")
    if ea_final_transform is None:
        ea_final_transform = find_symbol_ea(
            "?EncryptedDataTransform@EncData@Aegis@@YAXAEA_K0@Z"
        )
        return False

    # 2. Read the randomized transform function bytes used for XOR
    print(
        f"[*] Reading {transform_func_xor_size} bytes from pFinalTransform (0x{ea_final_transform:X}) for XOR source..."
    )
    randomized_transform_func_bytes = read_ida_bytes(
        ea_final_transform, transform_func_xor_size
    )
    if randomized_transform_func_bytes is None:
        return False
    print(f"[+] Read {len(randomized_transform_func_bytes)} bytes for XOR source.")

    # 3. Calculate key offset and read the RC4 key
    print(
        f"[*] Calculating key offset using PolyA={poly_a}, PolyB={poly_b}, PolyC={poly_c}, PolyD={poly_d}..."
    )
    key_offset = (poly_b << 8) + (poly_a << 12) + poly_d + (16 * poly_c)
    ea_key = ea_start + key_offset
    print(f"[+] Calculated key offset: 0x{key_offset:X}")
    print(f"[+] RC4 key address (ea_key): 0x{ea_key:X}")

    print(f"[*] Reading {rc4_key_size} byte RC4 key from 0x{ea_key:X}...")
    rc4_key = read_ida_bytes(ea_key, rc4_key_size)
    if rc4_key is None:
        return False
    print(f"[+] Read {len(rc4_key)} byte RC4 key.")

    # 4. Select RC4 function
    rc4_func = nonstd_rc4
    print(f"[*] Using non-std RC4 function for decryption.")

    # 5. Decrypt and process each assumed transform block
    print("[*] Processing and decrypting transform blocks...")
    overall_success = True
    processed_count = 0

    for kk in range(expected_transform_count):
        print(f"\n--- Processing Assumed Transform Block {kk} ---")
        processed_count += 1

        # a. Calculate block destination offset
        fn_offset = (
            (kk * kk * poly_b) + (kk * kk * kk * poly_a) + poly_d + (kk * poly_c)
        )
        ea_encrypted_block = ea_start + fn_offset
        print(f"[+] Calculated fnOffset: 0x{fn_offset:X}")
        print(f"[+] Encrypted block location: 0x{ea_encrypted_block:X}")

        # b. Read encrypted data (using assumed fixed size)
        print(
            f"[*] Reading {assumed_transform_block_size} encrypted bytes from 0x{ea_encrypted_block:X}..."
        )
        encrypted_data = read_ida_bytes(
            ea_encrypted_block, assumed_transform_block_size
        )
        if encrypted_data is None:
            overall_success = False
            print(f"[-] Failed to read block {kk}. Skipping.")
            continue

        # c. Decrypt using selected RC4 variant
        print(f"[*] Performing non-std RC4 decryption...")
        try:
            rc4_decrypted = rc4_func(encrypted_data, rc4_key)
        except Exception as e:
            print(f"[-] ERROR: RC4 decryption failed for block {kk}: {e}")
            overall_success = False
            continue

        # d. Reverse the XOR operation (using fixed size)
        print("[*] Reversing XOR operation...")
        if len(rc4_decrypted) != assumed_transform_block_size:
            # This shouldn't happen if read and decrypt worked for the assumed size
            print(
                f"[-] ERROR: Decrypted size mismatch for block {kk}. Expected {assumed_transform_block_size}, got {len(rc4_decrypted)}."
            )
            overall_success = False
            continue

        restored_bytes = bytearray(assumed_transform_block_size)
        xor_success = True
        for z in range(assumed_transform_block_size):
            # XOR with the corresponding byte from the 1024-byte randomized buffer
            # Index z is guaranteed to be < 1024 here
            restored_bytes[z] = rc4_decrypted[z] ^ randomized_transform_func_bytes[z]

        # No need for xor_success check here as loop completes if sizes match

        print("[+] XOR reversal complete.")

        # e. Optional Hexdump
        if dump_decrypted:
            print("[*] Hexdump of restored bytes for block {kk}:")
            print(hexdump(restored_bytes, ea_encrypted_block))

        # f. Optional Decode Preview (Dry Run)
        if decode_decrypted and dry_run:
            decode_instructions_from_bytes(restored_bytes, ea_encrypted_block)

        # g. Patch IDA database (if not dry_run)
        patched_ok = False
        if not dry_run:
            print(
                f"[*] Applying patch to 0x{ea_encrypted_block:X} using '{patch_mode}' mode..."
            )
            patch_data = bytes(restored_bytes)
            if patch_mode != "patch" and patch_mode != "put":
                print(
                    f"[-] ERROR: Invalid patch_mode '{patch_mode}'. Use 'patch' or 'put'."
                )
            else:
                patch_func = getattr(ida_bytes, f"{patch_mode}_bytes")
                patch_func(ea_encrypted_block, patch_data)
                print(f"[+] {patch_mode}_bytes successful.")
                patched_ok = True

            if not patched_ok:
                overall_success = False
        else:
            patched_ok = True
            print("[*] Dry run: Skipping patching.")

        # h. Optional Decode (Post-Patch or Dry Run Preview handled above)
        # Pass the assumed size for decoding context
        if decode_decrypted and not dry_run and patched_ok:
            decode_patched_instructions(
                ea_encrypted_block, assumed_transform_block_size
            )
        elif decode_decrypted and not dry_run and not patched_ok:
            print("[!] Skipping decode because patching failed for this block.")

    print(
        f"\n--- Aegis Encryption Reversal Finished ({processed_count}/{expected_transform_count} blocks processed) ---"
    )
    if overall_success:
        print("[+] Reversal process completed based on fixed-size assumption.")
        if dry_run:
            print("[+] Dry run successful (no changes made).")
        else:
            print("[+] IDB patching operations completed (check output for errors).")
        print(
            "[!] WARNING: Restored code may be incomplete or contain garbage padding if original function sizes were not exactly 1024 bytes."
        )
    else:
        print(
            "[-] Reversal process encountered errors. Some blocks might not be restored or patched correctly."
        )

    return overall_success


# --- How to Run ---
# 1. Load the patched binary into IDA Pro.
# 2. Open the Script Command window (Shift+F2).
# 3. Paste this entire script into the window.
# 4. Configure the options below (Polynomial values, dry_run, etc.).
# 5. Run the script.

# === Configuration ===
# Define the polynomial coefficients used during patching
PolyA = 12
PolyB = 543
PolyC = 17136
PolyD = 51417
# PolyA = 10 # Example alternative set
# PolyB = 498
# PolyC = 11279
# PolyD = 57531

# Set execution options
DRY_RUN = False  # True: Analyze but do not patch. False: Patch the IDB.
PATCH_MODE = (
    "patch"  # 'patch' (undoable) or 'put' (direct) - only used if DRY_RUN is False
)
DUMP_DECRYPTED = True  # True: Show hexdump of decrypted bytes. False: Hide hexdump.
DECODE_DECRYPTED = True  # True: Attempt to show disassembly of decrypted bytes. False: Skip disassembly.

# ====================


if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    try:
        undo_aegis_encryption(
            PolyA,
            PolyB,
            PolyC,
            PolyD,
            dry_run=DRY_RUN,
            patch_mode=PATCH_MODE,
            dump_decrypted=DUMP_DECRYPTED,
            decode_decrypted=DECODE_DECRYPTED,
        )
    except Exception as e:
        print(f"[-] ERROR: {e}")
        traceback.print_exc()
        raise e
