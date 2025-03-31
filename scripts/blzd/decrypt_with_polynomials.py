import struct

import ida_auto
import ida_bytes
import idaapi
import idc


def read_bytes(ea, size):
    b = ida_bytes.get_bytes(ea, size)
    if b is None:
        raise ValueError("Failed to read bytes at 0x{:X}".format(ea))
    return b


def write_bytes(ea, data):
    for i, byte in enumerate(data):
        ida_bytes.patch_byte(ea + i, byte)


def rc4_decrypt(data, key):
    # Implements RC4 KSA and PRGA (encryption and decryption are identical)
    S = list(range(256))
    j = 0
    key_len = len(key)
    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = 0
    j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        result.append(byte ^ k)
    return bytes(result)


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


def key_offset(PolynomialA, PolynomialB, PolynomialC, PolynomialD):
    return (PolynomialB << 8) + (PolynomialA << 12) + PolynomialD + (16 * PolynomialC)


def undo_decryption(
    PolynomialA,
    PolynomialB,
    PolynomialC,
    PolynomialD,
    key_size=0x89,
    G_TLS_MIRROR_BASE=None,
):
    # Dynamically obtain required addresses by symbol name.
    ENC_DATA_BASE = idc.get_name_ea_simple("?EncData_Transform_0@@YAXAEA_K0@Z")
    if ENC_DATA_BASE == idc.BADADDR:
        print("EncData_Transform_0 not found!")
        return
    print("EncData_Transform_0 @ 0x{:X}".format(ENC_DATA_BASE))

    func_name = "?EncryptedDataTransform@EncData@Aegis@@YAXAEA_K0@Z"
    ENC_DATA_TRANSFORM = idc.get_name_ea_simple(func_name)
    if ENC_DATA_TRANSFORM == idc.BADADDR:
        print("Function {} not found.".format(func_name))
        return
    print("{} @ 0x{:X}".format(func_name, ENC_DATA_TRANSFORM))

    g_pAegisImageExeRange = idc.get_name_ea_simple("g_pAegisImageExeRange")
    P_AEGIS_EXE_START = idc.get_qword(
        g_pAegisImageExeRange
    )  # g_pAegisImageExeRange.pStart
    P_AEGIS_EXE_SIZE = idc.get_qword(
        g_pAegisImageExeRange + 8
    )  # g_pAegisImageExeRange.nSize

    # IMAGE_BASE is the base address of the loaded module.
    IMAGE_BASE = idaapi.get_imagebase()

    # Compute the relative virtual address (rva) for the function.
    # Corrected: rva = unk_addr - IMAGE_BASE.
    rva = ENC_DATA_TRANSFORM - IMAGE_BASE
    # secondary_xor_addr = G_TLS_MIRROR_BASE + rva
    # print("Computed secondary XOR address: 0x{:X}".format(secondary_xor_addr))

    # --- Step 1: Compute the 'i' value automatically from KUSER_SHARED_DATA ---
    i_val = compute_i_value()
    if i_val is None:
        print("Failed to compute i value. Aborting.")
        return
    print("Computed i value from KUSER_SHARED_DATA: {}".format(i_val))

    # --- Step 2: Compute the offset into the encrypted blob ---
    # Formula: offset = (i & 0xF) * ((i & 0xF) * (10*(i & 0xF) + 498) + 11279) + 57531


    offset = (
        (i_val & 0xF)
        * (((i_val & 0xF) * (PolynomialA * (i_val & 0xF) + PolynomialB)) + PolynomialC)
    ) + PolynomialD
    print("Computed offset into EncData_Transform_0: 0x{:X}".format(offset))

    # --- Step 3: Read the encrypted 0x400-byte blob ---
    encrypted_blob_addr = ENC_DATA_BASE + offset
    encrypted_blob = read_bytes(encrypted_blob_addr, 0x400)
    print("Read 0x400 bytes from 0x{:X}".format(encrypted_blob_addr))

    # --- Step 4: Build the RC4 key from bytes in EncData_Transform_0 ---
    key = bytearray()
    computed_offset = key_offset(PolynomialA, PolynomialB, PolynomialC, PolynomialD)
    for k in range(256):
        # Key index formula: ENC_DATA_BASE + (k - 137*(k//137) + 406443)
        key_index = ENC_DATA_BASE + (k - key_size * (k // key_size) + computed_offset)
        key_byte = ida_bytes.get_byte(key_index)
        key.append(key_byte)

    # --- Step 5: RC4-like decryption ---
    decrypted_blob = rc4_decrypt(encrypted_blob, key)
    print("RC4 decryption completed.")

    # # --- Step 6: Apply secondary XOR layer ---
    # secondary_xor_bytes = read_bytes(secondary_xor_addr, 0x400)
    # decrypted_blob = bytearray(decrypted_blob)
    # for idx in range(0x400):
    #     decrypted_blob[idx] ^= secondary_xor_bytes[idx]
    # print("Secondary XOR layer applied.")

    # --- Step 7: Patch marker patterns ---
    marker1 = struct.pack("<Q", 0x12910FDC6A1EEB2B)  # 8-byte marker
    marker2 = struct.pack("<Q", 0x5173E4B8939061E5)  # 8-byte marker
    marker3 = struct.pack("<I", 3205752748)  # 4-byte marker

    # Replace markers with bytes from the executable range (g_pAegisImageExeRange.pStart)
    replacement1 = read_bytes(P_AEGIS_EXE_START, 8)
    replacement2 = read_bytes(P_AEGIS_EXE_START, 8)
    replacement3 = read_bytes(P_AEGIS_EXE_START, 4)

    m = 0
    while m < 0x3F8:
        if decrypted_blob[m : m + 8] == marker1:
            print(f"Patching marker1 at 0x{m:X}")
            decrypted_blob[m : m + 8] = replacement1
            m += 8
        else:
            m += 1

    n = 0
    while n < 0x3F8:
        if decrypted_blob[n : n + 8] == marker2:
            print(f"Patching marker2 at 0x{n:X}")
            decrypted_blob[n : n + 8] = replacement2
            n += 8
        else:
            n += 1

    ii = 0
    while ii < 0x3FC:
        if decrypted_blob[ii : ii + 4] == marker3:
            print(f"Patching marker3 at 0x{ii:X}")
            decrypted_blob[ii : ii + 4] = replacement3
            ii += 4
        else:
            ii += 1

    print("Marker patching completed.")

    # --- Step 8: Patch the decrypted blob back into the binary ---
    # The decrypted code is written at the location used by the secondary XOR layer.
    target_addr = ENC_DATA_TRANSFORM
    write_bytes(target_addr, decrypted_blob)
    print("Decrypted blob patched at 0x{:X}".format(target_addr))

    # Optionally, mark the area as code and reanalyze.
    idc.auto_mark_range(target_addr, target_addr + 0x400, idc.AU_CODE)
    ida_auto.auto_wait_range(target_addr, target_addr + 0x400)
    print("Decryption complete.")


if __name__ == "__main__":
    G_TLS_MIRROR_BASE = 0  # <-- need to figure out how to get this?
    PolyA = 10
    PolyB = 498
    PolyC = 11279
    PolyD = 57531
    undo_decryption(PolyA, PolyB, PolyC, PolyD)
