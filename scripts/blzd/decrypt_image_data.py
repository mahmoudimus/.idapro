import ctypes
import sys

import ida_bytes
import ida_kernwin
import idaapi
import idc


def get_required_address(name, description):
    addr = idc.get_name_ea_simple(name)
    if addr == idaapi.BADADDR:
        print(f"Error: Could not find address for {description} ({name})")
        return None
    return addr


# Define the C++ structures using ctypes
class AEGIS_RVA_RANGE(ctypes.Structure):
    _fields_ = [
        ("RVA", ctypes.c_uint),
        ("size", ctypes.c_uint),
    ]

    # Make it easy to represent
    def __repr__(self):
        return f"AEGIS_RVA_RANGE(RVA=0x{self.RVA:08X}, size=0x{self.size:08X})"


class AEGIS_IMAGE_REGION(ctypes.Structure):
    _fields_ = [
        ("RVA", ctypes.c_uint),
        ("size", ctypes.c_uint),
        (
            "mapProt",
            ctypes.c_uint,
        ),  # Corresponds to Windows PAGE_ constants after processing
    ]

    # Make it easy to represent
    def __repr__(self):
        # Simple interpretation of common protection flags
        prot_str = ""
        PAGE_EXECUTE_READ = 0x20
        PAGE_READWRITE = 0x04
        PAGE_READONLY = 0x02
        if self.mapProt & PAGE_EXECUTE_READ:
            prot_str += "X"
        if self.mapProt & PAGE_READWRITE:
            prot_str += "RW"
        elif self.mapProt & PAGE_READONLY:
            prot_str += "R"
        else:
            prot_str += "?"  # Should usually have R or RW if mapped
        return f"AEGIS_IMAGE_REGION(RVA=0x{self.RVA:08X}, size=0x{self.size:08X}, mapProt=0x{self.mapProt:X} ({prot_str}))"


class AEGIS_IMAGE_DATA(ctypes.Structure):
    _fields_ = [
        (
            "nonce",
            ctypes.c_uint,
        ),  # Note: The decryption starts here, but it's part of the struct
        ("originalEntryPoint", ctypes.c_uint),
        ("MappedRegions", AEGIS_IMAGE_REGION * 32),
        ("EncryptedRanges", AEGIS_RVA_RANGE * 32),
        ("ValidatedRanges", AEGIS_RVA_RANGE * 32),
        ("RetguardRange", AEGIS_RVA_RANGE),
        ("VtableRange", AEGIS_RVA_RANGE),
    ]
    # Ensure no padding issues, although likely not needed with uints
    _pack_ = 1


def decrypt_aegis_image_data_with_subtraction():
    """
    Decrypts the g_AegisImageData structure in the IDB using the
    non-standard RC4 variant observed, and then subtracts a constant
    from specific range fields based on analysis.
    """
    try:
        # --- Configuration ---
        ADDR_G_BUF_CRYPTO_KEY = get_required_address(
            "g_bufCryptoKey", "Crypto Key Buffer"
        )
        ADDR_G_AEGIS_IMAGE_DATA = get_required_address(
            "?g_AegisImageData@@3UAEGIS_IMAGE_DATA@@C", "Aegis Image Data Struct"
        )

        AEGIS_DATA_SIZE = ctypes.sizeof(AEGIS_IMAGE_DATA)  # Should be 920 (0x398)
        RC4_KEY_LEN = 0x10  # 16 bytes
        SUBTRACTION_CONSTANT = 0x68E4FF02  # Constant observed in calculations

        ida_kernwin.msg(
            f"AEGIS_IMAGE_DATA size: {AEGIS_DATA_SIZE} bytes (0x{AEGIS_DATA_SIZE:X})\n"
        )
        if AEGIS_DATA_SIZE != 920:
            ida_kernwin.warning(
                f"Warning: Expected AEGIS_IMAGE_DATA size 920, but got {AEGIS_DATA_SIZE}. Decryption loop might be incorrect."
            )

        # --- Read Data from IDA Database ---
        crypto_key_bytes = ida_bytes.get_bytes(ADDR_G_BUF_CRYPTO_KEY, RC4_KEY_LEN)
        if not crypto_key_bytes:
            raise ValueError(
                f"Failed to read crypto key from {ADDR_G_BUF_CRYPTO_KEY:#x}"
            )
        ida_kernwin.msg(
            f"Read {len(crypto_key_bytes)} byte key: {crypto_key_bytes.hex()}\n"
        )

        encrypted_data_bytes = ida_bytes.get_bytes(
            ADDR_G_AEGIS_IMAGE_DATA, AEGIS_DATA_SIZE
        )
        if not encrypted_data_bytes:
            raise ValueError(
                f"Failed to read encrypted AEGIS_IMAGE_DATA from {ADDR_G_AEGIS_IMAGE_DATA:#x}"
            )
        ida_kernwin.msg(
            f"Read {len(encrypted_data_bytes)} encrypted bytes starting at {ADDR_G_AEGIS_IMAGE_DATA:#x}\n"
        )

        # --- RC4 Variant Implementation ---

        # 1. S-box Initialization
        sbox = list(range(256))

        # 2. Key Scheduling Algorithm (KSA)
        j_ksa = 0
        for i_ksa in range(256):
            key_byte = crypto_key_bytes[i_ksa % RC4_KEY_LEN]
            s_i = sbox[i_ksa]
            j_ksa = (j_ksa + s_i + key_byte) % 256
            sbox[i_ksa], sbox[j_ksa] = sbox[j_ksa], s_i
        ida_kernwin.msg("RC4 KSA completed.\n")

        # 3. Non-Standard Pseudo-Random Generation Algorithm (PRGA) & Decryption
        decrypted_data = bytearray(encrypted_data_bytes)  # Create mutable copy
        i_prga = 0
        j_prga = 0
        for k in range(AEGIS_DATA_SIZE):  # Corresponds to nonceIndex loop
            i_prga = (i_prga + 1) % 256
            s_i_orig = sbox[i_prga]
            keystream_byte = s_i_orig
            decrypted_data[k] ^= keystream_byte
            j_prga = (j_prga + s_i_orig) % 256
            sbox[j_prga] = s_i_orig
        ida_kernwin.msg(f"RC4 Decryption loop completed for {AEGIS_DATA_SIZE} bytes.\n")

        # --- Map Decrypted Data to Structure ---
        # Modifications to aegis_data will directly affect decrypted_data
        aegis_data = AEGIS_IMAGE_DATA.from_buffer(decrypted_data)

        # --- Apply Subtraction Hypothesis ---
        ida_kernwin.msg(
            f"Applying subtraction of constant 0x{SUBTRACTION_CONSTANT:08X} to range fields...\n"
        )

        # Define a helper for subtraction with 32-bit unsigned wrap-around
        def subtract32(value, subtrahend):
            return (value - subtrahend) & 0xFFFFFFFF

        # Apply to EncryptedRanges
        for i in range(32):
            # Check for null terminator entries
            if (
                aegis_data.EncryptedRanges[i].RVA == 0
                and aegis_data.EncryptedRanges[i].size == 0
                and i > 0
            ):
                break
            aegis_data.EncryptedRanges[i].RVA = subtract32(
                aegis_data.EncryptedRanges[i].RVA, SUBTRACTION_CONSTANT
            )
            aegis_data.EncryptedRanges[i].size = subtract32(
                aegis_data.EncryptedRanges[i].size, SUBTRACTION_CONSTANT
            )

        # Apply to ValidatedRanges
        for i in range(32):
            # Check for null terminator entries
            if (
                aegis_data.ValidatedRanges[i].RVA == 0
                and aegis_data.ValidatedRanges[i].size == 0
                and i > 0
            ):
                break
            aegis_data.ValidatedRanges[i].RVA = subtract32(
                aegis_data.ValidatedRanges[i].RVA, SUBTRACTION_CONSTANT
            )
            aegis_data.ValidatedRanges[i].size = subtract32(
                aegis_data.ValidatedRanges[i].size, SUBTRACTION_CONSTANT
            )

        # Apply to RetguardRange
        aegis_data.RetguardRange.RVA = subtract32(
            aegis_data.RetguardRange.RVA, SUBTRACTION_CONSTANT
        )
        aegis_data.RetguardRange.size = subtract32(
            aegis_data.RetguardRange.size, SUBTRACTION_CONSTANT
        )

        # Apply to VtableRange
        aegis_data.VtableRange.RVA = subtract32(
            aegis_data.VtableRange.RVA, SUBTRACTION_CONSTANT
        )
        aegis_data.VtableRange.size = subtract32(
            aegis_data.VtableRange.size, SUBTRACTION_CONSTANT
        )

        ida_kernwin.msg("Subtraction applied.\n")

        # --- Print Decrypted & Modified Information ---
        print("-" * 60)
        print(
            f"Decrypted AEGIS_IMAGE_DATA (with 0x{SUBTRACTION_CONSTANT:08X} subtracted from ranges):"
        )
        print("-" * 60)
        print(f"  Nonce (first 4 bytes): 0x{aegis_data.nonce:08X}")
        print(f"  Original Entry Point RVA: 0x{aegis_data.originalEntryPoint:08X}")

        print("\n  Mapped Regions:")
        for i, region in enumerate(aegis_data.MappedRegions):
            if region.RVA == 0 and region.size == 0 and region.mapProt == 0 and i > 0:
                print(f"    ... (found {i} regions)")
                break
            print(f"    [{i:02d}] {region!r}")  # Use __repr__
            if i == 31:
                print("    ... (max 32 regions reached)")

        print("\n  Encrypted Ranges (Modified):")
        for i, range_ in enumerate(aegis_data.EncryptedRanges):
            if range_.RVA == 0 and range_.size == 0 and i > 0:
                print(f"    ... (found {i} ranges)")
                break
            print(f"    [{i:02d}] {range_!r}")  # Use __repr__
            if i == 31:
                print("    ... (max 32 ranges reached)")

        print("\n  Validated Ranges (Modified):")
        for i, range_ in enumerate(aegis_data.ValidatedRanges):
            if range_.RVA == 0 and range_.size == 0 and i > 0:
                print(f"    ... (found {i} ranges)")
                break
            print(f"    [{i:02d}] {range_!r}")  # Use __repr__
            if i == 31:
                print("    ... (max 32 ranges reached)")

        print("\n  Special Ranges (Modified):")
        print(f"    Retguard: {aegis_data.RetguardRange!r}")
        print(f"    VTable:   {aegis_data.VtableRange!r}")
        print("-" * 60)

        # Optional: Patch the bytes in IDA's database
        patch = ida_kernwin.ask_yn(
            1, "Do you want to patch the decrypted data into the database?"
        )
        if patch == 1:
            if ida_bytes.patch_bytes(ADDR_G_AEGIS_IMAGE_DATA, bytes(decrypted_data)):
                ida_kernwin.msg(
                    f"Successfully patched {AEGIS_DATA_SIZE} bytes at {ADDR_G_AEGIS_IMAGE_DATA:#x}\n"
                )
                # You might want to undefine/redefine the data structure in IDA here
                ida_bytes.del_items(
                    ADDR_G_AEGIS_IMAGE_DATA, ida_bytes.DELIT_SIMPLE, AEGIS_DATA_SIZE
                )
                # Consider applying the structure definition (requires TIL setup or manual struct creation)
                # Example: ida_struct.set_struc_member(..., aegis_data_struct_id, ...)
                ida_kernwin.msg(
                    "Consider undefining the old data and applying the AEGIS_IMAGE_DATA structure definition in IDA.\n"
                )
            else:
                ida_kernwin.warning(
                    f"Failed to patch bytes at {ADDR_G_AEGIS_IMAGE_DATA:#x}\n"
                )

    except ValueError as e:
        ida_kernwin.warning(f"Error: {e}\n")
    except Exception as e:
        ida_kernwin.warning(f"An unexpected error occurred: {e}\n{sys.exc_info()[0]}\n")


# --- Run the decryption ---
if __name__ == "__main__":
    decrypt_aegis_image_data_with_subtraction()
