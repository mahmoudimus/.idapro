# -*- coding: utf-8 -*-
import ctypes  # For struct parsing
import struct
import sys
import time
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_segment
import ida_ua
import idaapi  # Correct module for get_imagebase
import idc  # For get_name_ea_simple

# --- Global flag for dry run mode ---
DRY_RUN = True  # Set to False to enable actual patching
if DRY_RUN:
    print("*** DRY RUN MODE ENABLED - NO CHANGES WILL BE MADE TO THE IDB ***")


# --- Patch helper functions ---
def patch_bytes(ea, data):
    """Patches bytes, respecting DRY_RUN flag."""
    if DRY_RUN:
        print(f"[Dry Run] Would patch {len(data)} bytes at {ea:#x}")
        return True
    else:
        if ida_bytes.patch_bytes(ea, data):
            return True
        else:
            print(f"[Error] ida_bytes.patch_bytes failed at {ea:#x}")
            return False


def patch_qword(ea, value):
    """Patches a QWORD, respecting DRY_RUN flag."""
    if DRY_RUN:
        print(f"[Dry Run] Would patch qword at {ea:#x} with {value:#x}")
        return True
    else:
        if ida_bytes.patch_qword(ea, value):
            return True
        else:
            print(f"[Error] ida_bytes.patch_qword failed at {ea:#x}")
            return False


# --- Configuration: Addresses of Global Variables ---
# Attempt to find addresses dynamically using symbol names
# Add error checking in case symbols are not found
def get_required_address(name, description):
    """Helper to get address or raise error."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        raise ValueError(
            f"Could not find address for '{description}' ('{name}'). Please check the name or define manually."
        )
    print(f"Found {description} ('{name}') at {ea:#x}")
    return ea


try:
    ADDR_G_BUF_CRYPTO_KEY = get_required_address("g_bufCryptoKey", "Crypto Key Buffer")
    # ADDR_S_IV: Keep hardcoded or use mangled name if resolvable
    # Example using mangled name (adjust if different):
    # ADDR_S_IV = get_required_address("?s_IV@?1???$rc4SerialDecrypt@W4Operation@Mathfuscate@Aegis@@HW4123@H@Utils@Aegis@@YA_KPEAE0_K01W4Operation@Mathfuscate@2@H2H@Z@4_KA", "Serial IV")
    ADDR_S_IV = 0x1443D9330  # Keeping hardcoded as name is complex
    if ADDR_S_IV == idaapi.BADADDR:
        raise ValueError("ADDR_S_IV is invalid")
    print(f"Using hardcoded address for Serial IV: {ADDR_S_IV:#x}")

    ADDR_G_AEGIS_ORIGINAL_BASE = get_required_address(
        "g_AegisImageOriginalBaseAddress", "Original Image Base"
    )
    ADDR_G_MULTIPAGE_RELOCS = get_required_address(
        "?g_MultipageRelocs@@3PAURelocRegion@ImageUtils@Aegis@@A",
        "Multipage Relocs Array",
    )
    ADDR_G_MULTIPAGE_RELOC_COUNT = get_required_address(
        "?g_MultipageRelocCount@@3IA", "Multipage Reloc Count"
    )
    ADDR_G_BUF_INIT_BLOB0 = get_required_address("g_bufInitBlob0", "Init Blob 0")
    ADDR_G_BUF_INIT_BLOB12 = get_required_address("g_bufInitBlob12", "Init Blob 12")
    ADDR_G_AEGIS_IMAGE_DATA = get_required_address(
        "?g_AegisImageData@@3UAEGIS_IMAGE_DATA@@C", "Aegis Image Data Struct"
    )

except ValueError as e:
    print(f"[Configuration Error] {e}")
    # Optionally, sys.exit(1) here if running non-interactively
    raise e  # Stop script execution if essential addresses are missing

# Constants
PAGE_SIZE = 0x1000
CRYPTO_KEY_BANK_SIZE = 0x5A  # 90
CRYPTO_KEY_SIZE = 0x169  # 361
RC4_STATE_SIZE = 0x100
RELOC_TYPE_HIGHLOW = 3
RELOC_TYPE_DIR64 = 0xA
SERIAL_IV_MULTIPLIER = 0x100000001B3
AEGIS_IMAGE_DATA_DECRYPT_LEN = 920  # 0x398 bytes = size up to end of VtableRange
AEGIS_IMAGE_DATA_KEY_LEN = 16  # 0x10 bytes used for its own decryption
NUM_MAPPED_REGIONS = 32
NUM_ENCRYPTED_RANGES = 32
NUM_VALIDATED_RANGES = 32


# --- Define ctypes Structures ---
class AEGIS_RVA_RANGE(ctypes.Structure):
    _pack_ = 1  # Ensure tight packing like C++
    _fields_ = [("RVA", ctypes.c_uint), ("size", ctypes.c_uint)]

    def __repr__(self):
        return f"AEGIS_RVA_RANGE(RVA={self.RVA:#x}, size={self.size})"


class AEGIS_IMAGE_REGION(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("RVA", ctypes.c_uint),
        ("size", ctypes.c_uint),
        ("mapProt", ctypes.c_uint),
    ]  # Assuming mapProt is also uint

    def __repr__(self):
        return f"AEGIS_IMAGE_REGION(RVA={self.RVA:#x}, size={self.size}, mapProt={self.mapProt:#x})"


class AEGIS_IMAGE_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("nonce", ctypes.c_uint),
        ("originalEntryPoint", ctypes.c_uint),
        ("MappedRegions", AEGIS_IMAGE_REGION * NUM_MAPPED_REGIONS),
        ("EncryptedRanges", AEGIS_RVA_RANGE * NUM_ENCRYPTED_RANGES),
        ("ValidatedRanges", AEGIS_RVA_RANGE * NUM_VALIDATED_RANGES),
        ("RetguardRange", AEGIS_RVA_RANGE),
        ("VtableRange", AEGIS_RVA_RANGE),
    ]

    def __repr__(self):
        return (f"AEGIS_IMAGE_DATA(nonce={self.nonce:#x}, "
                f"originalEntryPoint={self.originalEntryPoint:#x}, "
                f"MappedRegions={list(self.MappedRegions)}, "
                f"EncryptedRanges={list(self.EncryptedRanges)}, "
                f"ValidatedRanges={list(self.ValidatedRanges)}, "
                f"RetguardRange={self.RetguardRange}, "
                f"VtableRange={self.VtableRange})")


# --- RC4 Implementation ---
def rc4_ksa(key):
    """RC4 Key Scheduling Algorithm."""
    key_len = len(key)
    sbox = list(range(RC4_STATE_SIZE))
    j = 0
    for i in range(RC4_STATE_SIZE):
        j = (j + sbox[i] + key[i % key_len]) % RC4_STATE_SIZE
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def rc4_prga(sbox, data_len):
    """RC4 PRGA - returns keystream."""
    i = 0
    j = 0
    keystream = bytearray(data_len)
    sbox_copy = list(sbox)  # Work on a copy
    for k in range(data_len):
        i = (i + 1) % RC4_STATE_SIZE
        j = (j + sbox_copy[i]) % RC4_STATE_SIZE
        sbox_copy[i], sbox_copy[j] = sbox_copy[j], sbox_copy[i]
        keystream_byte = sbox_copy[(sbox_copy[i] + sbox_copy[j]) % RC4_STATE_SIZE]
        keystream[k] = keystream_byte
    return keystream


# --- Relocation Helper ---
# (Keep the apply_relocations function as it was)
def apply_relocations(page_data, page_rva, image_base, delta):
    """Applies PE relocations to the decrypted page data."""
    # print(f"[Reloc] Applying delta {delta:#x} for page RVA {page_rva:#x}")
    reloc_addr = idaapi.get_imagebase()  # Use IDA's relocation info if available
    reloc_size = 0
    fixed_count = 0

    # Find relocation section (this is simplified, real PE parsing is better)
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg and ida_segment.get_segm_name(seg) == ".reloc":
            reloc_addr = seg.start_ea
            reloc_size = seg.size()
            break

    if reloc_size == 0:
        print("[Reloc] Warning: Could not find .reloc section.")
        return page_data  # Return unmodified if no reloc info

    current_reloc_addr = reloc_addr
    end_reloc_addr = reloc_addr + reloc_size

    page_start_rva = page_rva
    page_end_rva = page_rva + PAGE_SIZE

    while current_reloc_addr < end_reloc_addr:
        block_rva = ida_bytes.get_dword(current_reloc_addr)
        block_size = ida_bytes.get_dword(current_reloc_addr + 4)

        if block_rva == 0 or block_size < 8:  # Basic sanity check
            # print(f"[Reloc] End of relocations found or invalid block size at {current_reloc_addr:#x}.")
            break  # End of relocations or invalid block

        # Check if this block affects our page at all
        block_affects_page = False
        num_entries = (block_size - 8) // 2
        entry_addr_check = current_reloc_addr + 8
        # Check if any entry *could* fall within the page
        if block_rva < page_end_rva and (block_rva + PAGE_SIZE) > page_start_rva:
            block_affects_page = True  # More efficient check

        if not block_affects_page:
            current_reloc_addr += block_size
            continue

        # print(f"[Reloc] Processing block RVA {block_rva:#x}, Size {block_size:#x}")
        num_entries = (block_size - 8) // 2
        entry_addr = current_reloc_addr + 8

        for _ in range(num_entries):
            if entry_addr + 2 > end_reloc_addr:  # Bounds check
                print(f"[Reloc] Error: Relocation entry read out of bounds.")
                break
            entry = ida_bytes.get_word(entry_addr)
            reloc_type = entry >> 12
            offset_in_block = entry & 0xFFF
            reloc_rva = block_rva + offset_in_block

            # Check if this specific relocation is within our target page
            if page_start_rva <= reloc_rva < page_end_rva:
                offset_in_page_data = reloc_rva - page_start_rva

                if reloc_type == RELOC_TYPE_HIGHLOW:
                    if offset_in_page_data + 4 <= len(page_data):
                        original_val = struct.unpack(
                            "<I",
                            page_data[offset_in_page_data : offset_in_page_data + 4],
                        )[0]
                        new_val = (original_val + delta) & 0xFFFFFFFF
                        # print(f"[Reloc] Applying HIGHLOW at RVA {reloc_rva:#x} (offset {offset_in_page_data:#x}): {original_val:#x} -> {new_val:#x}")
                        page_data[offset_in_page_data : offset_in_page_data + 4] = (
                            struct.pack("<I", new_val)
                        )
                        fixed_count += 1
                    else:
                        print(
                            f"[Reloc] Warning: HIGHLOW relocation out of bounds at RVA {reloc_rva:#x}"
                        )
                elif reloc_type == RELOC_TYPE_DIR64:
                    if offset_in_page_data + 8 <= len(page_data):
                        original_val = struct.unpack(
                            "<Q",
                            page_data[offset_in_page_data : offset_in_page_data + 8],
                        )[0]
                        new_val = (original_val + delta) & 0xFFFFFFFFFFFFFFFF
                        # print(f"[Reloc] Applying DIR64 at RVA {reloc_rva:#x} (offset {offset_in_page_data:#x}): {original_val:#x} -> {new_val:#x}")
                        page_data[offset_in_page_data : offset_in_page_data + 8] = (
                            struct.pack("<Q", new_val)
                        )
                        fixed_count += 1
                    else:
                        print(
                            f"[Reloc] Warning: DIR64 relocation out of bounds at RVA {reloc_rva:#x}"
                        )
                # elif reloc_type != 0: # IMAGE_REL_BASED_ABSOLUTE (ignore)
                # print(f"[Reloc] Skipping type {reloc_type} at RVA {reloc_rva:#x}")

            entry_addr += 2
        # Ensure we advance by the block size even if inner loop breaks early
        current_reloc_addr += block_size

    if fixed_count > 0:
        print(f"[Reloc] Applied {fixed_count} relocations for page RVA {page_rva:#x}.")
    return page_data


# --- Function to decrypt g_AegisImageData ---
def decrypt_and_parse_g_aegis_image_data():
    """
    Decrypts the first 920 bytes of g_AegisImageData in place
    and returns a parsed ctypes Structure object.
    """
    print("--- Decrypting g_AegisImageData ---")
    try:
        # 1. Get the key (first 16 bytes of g_bufCryptoKey[0])
        rc4_key_image_data = ida_bytes.get_bytes(
            ADDR_G_BUF_CRYPTO_KEY, AEGIS_IMAGE_DATA_KEY_LEN
        )
        if (
            not rc4_key_image_data
            or len(rc4_key_image_data) != AEGIS_IMAGE_DATA_KEY_LEN
        ):
            print(
                f"[Error] Failed to read key for g_AegisImageData from {ADDR_G_BUF_CRYPTO_KEY:#x}"
            )
            return None

        # 2. Read the encrypted data
        encrypted_data = ida_bytes.get_bytes(
            ADDR_G_AEGIS_IMAGE_DATA, AEGIS_IMAGE_DATA_DECRYPT_LEN
        )
        if not encrypted_data or len(encrypted_data) != AEGIS_IMAGE_DATA_DECRYPT_LEN:
            print(
                f"[Error] Failed to read encrypted g_AegisImageData from {ADDR_G_AEGIS_IMAGE_DATA:#x}"
            )
            return None

        # 3. Perform RC4 KSA
        sbox = rc4_ksa(rc4_key_image_data)

        # 4. Perform RC4 PRGA + XOR (stateful version matching the C++ loop)
        decrypted_data_bytes = bytearray(encrypted_data)
        i = 0
        j = 0
        sbox_prga = list(sbox)  # Use a copy for PRGA state updates
        for k in range(AEGIS_IMAGE_DATA_DECRYPT_LEN):
            i = (i + 1) % RC4_STATE_SIZE
            j = (j + sbox_prga[i]) % RC4_STATE_SIZE
            sbox_prga[i], sbox_prga[j] = sbox_prga[j], sbox_prga[i]
            keystream_byte = sbox_prga[(sbox_prga[i] + sbox_prga[j]) % RC4_STATE_SIZE]
            decrypted_data_bytes[k] = encrypted_data[k] ^ keystream_byte

        decrypted_data = bytes(decrypted_data_bytes)

        # 5. Patch the decrypted data back into IDA (using helper)
        if not patch_bytes(ADDR_G_AEGIS_IMAGE_DATA, decrypted_data):
            # Error already printed by helper
            return None  # Failed to patch, cannot proceed reliably

        print(
            f"[Success] Decrypted and patched {AEGIS_IMAGE_DATA_DECRYPT_LEN} bytes of g_AegisImageData at {ADDR_G_AEGIS_IMAGE_DATA:#x}"
        )

        # 6. Parse the decrypted data into a ctypes structure
        try:
            aegis_data_obj = AEGIS_IMAGE_DATA.from_buffer_copy(decrypted_data)
            print("[Info] Parsed decrypted g_AegisImageData structure.")
            # Example access check:
            print(f"  Nonce: {aegis_data_obj.nonce:#x}")
            
            print(
                f"  Encrypted Range 0: RVA={aegis_data_obj.EncryptedRanges[0].RVA:#x}, Size={aegis_data_obj.EncryptedRanges[0].size:#x}"
            )
            print(aegis_data_obj)
            return aegis_data_obj
        except Exception as parse_e:
            print(
                f"[Error] Failed to parse decrypted g_AegisImageData using ctypes: {parse_e}"
            )
            traceback.print_exc()
            return None

    except Exception as e:
        print(f"[Error] Exception during g_AegisImageData decryption/parsing: {e}")
        traceback.print_exc()
        return None


# --- (Keep decrypt_aegis_page function as it was, ensuring it uses the corrected multipage reloc reading) ---
# --- Main Decryption Function (Single Page) ---
def decrypt_aegis_page(rva, image_base_in_ida, current_s_iv_val):
    """
    Decrypts a single Aegis-protected page and returns the new serial IV.
    Takes the current serial IV as input.
    """
    # print(f"--- Decrypting page at RVA {rva:#x} ---") # Reduced verbosity

    page_addr = image_base_in_ida + rva
    # if not ida_bytes.is_loaded(page_addr):
    #     print(f"[Error] Address {page_addr:#x} is not loaded.")
    #     return None  # Indicate failure

    # 1. Read necessary globals (only those needed per page)
    try:
        original_image_base = ida_bytes.get_qword(ADDR_G_AEGIS_ORIGINAL_BASE)
        multipage_reloc_count = ida_bytes.get_dword(ADDR_G_MULTIPAGE_RELOC_COUNT)

        # Read crypto key bank
        page_index = rva // PAGE_SIZE
        key_bank_index = page_index % CRYPTO_KEY_BANK_SIZE
        key_bank_addr = ADDR_G_BUF_CRYPTO_KEY + (key_bank_index * CRYPTO_KEY_SIZE)
        base_key = ida_bytes.get_bytes(key_bank_addr, CRYPTO_KEY_SIZE)
        if not base_key or len(base_key) != CRYPTO_KEY_SIZE:
            print(
                f"[Error] Failed to read base key for page index {page_index} (bank {key_bank_index})"
            )
            return None

        # Read multipage relocs using the CORRECT struct size
        multipage_relocs = []
        if multipage_reloc_count > 0 and multipage_reloc_count < 1024:  # Sanity check
            struct_size = 8  # CORRECTED SIZE
            # print(f"  Reading {multipage_reloc_count} multipage reloc entries (struct size: {struct_size})...")
            for i in range(multipage_reloc_count):
                reloc_entry_addr = (
                    ADDR_G_MULTIPAGE_RELOCS + i * struct_size
                )  # CORRECTED STRIDE
                reloc_rva = ida_bytes.get_dword(reloc_entry_addr)  # Offset 0
                reloc_size = ida_bytes.get_dword(reloc_entry_addr + 4)  # Offset 4
                if reloc_size > 0:  # Add a basic sanity check for size
                    multipage_relocs.append({"rva": reloc_rva, "size": reloc_size})
                # else:
                # print(f"[Debug] Multipage reloc entry {i} has size 0, skipping.")

    except Exception as e:
        print(f"[Error] Failed to read global variables for page {rva:#x}: {e}")
        return None

    # print(f"  Page Index: {page_index}")
    # print(f"  Key Bank Index: {key_bank_index}")
    # print(f"  Using Serial IV: {current_s_iv_val:#x}")
    # print(f"  Original Image Base: {original_image_base:#x}")

    # 2. Read page data
    page_data_enc = ida_bytes.get_bytes(page_addr, PAGE_SIZE)
    if not page_data_enc or len(page_data_enc) != PAGE_SIZE:
        print(f"[Error] Failed to read page data at {page_addr:#x}")
        return None

    page_data = bytearray(page_data_enc)  # Make mutable

    # 3. Skip Pre-Decryption Relocations (for static analysis)

    # 4. Adjust decryption range based on multipage relocs
    decrypt_offset = 0
    decrypt_size = PAGE_SIZE
    page_end_rva = rva + PAGE_SIZE

    for reloc in multipage_relocs:
        reloc_rva = reloc["rva"]
        reloc_size = reloc["size"]
        reloc_end_rva = reloc_rva + reloc_size

        # Overlap at the beginning of the page
        if reloc_rva < rva < reloc_end_rva:
            overlap = reloc_end_rva - rva
            # print(f"[Info] Multipage reloc overlaps start: RVA {reloc_rva:#x}, Size {reloc_size:#x}. Adjusting start by {overlap}.")
            if overlap < decrypt_size:
                decrypt_offset += overlap
                decrypt_size -= overlap
            else:
                # print("[Warning] Multipage reloc covers entire page start?")
                decrypt_size = 0

        # Overlap at the end of the page
        if reloc_rva < page_end_rva < reloc_end_rva:
            overlap = page_end_rva - reloc_rva
            # print(f"[Info] Multipage reloc overlaps end: RVA {reloc_rva:#x}, Size {reloc_size:#x}. Adjusting size by {overlap}.")
            if overlap < decrypt_size:
                decrypt_size -= overlap
            else:
                # print("[Warning] Multipage reloc covers entire page end?")
                decrypt_size = 0

    new_s_iv = current_s_iv_val  # Default if skipping decryption

    if decrypt_size <= 0 or decrypt_offset >= PAGE_SIZE:
        print(
            f"[Info] Page {rva:#x}: Decryption size/offset invalid (size={decrypt_size}, offset={decrypt_offset}) due to multipage relocs. Skipping decryption."
        )
        # Still need to apply post-relocations below
    else:
        # print(f"  Adjusted Decrypt Offset: {decrypt_offset}, Size: {decrypt_size}")

        # 5. RC4 Key Derivation & KSA
        rc4_key = bytearray(CRYPTO_KEY_SIZE)
        for i in range(CRYPTO_KEY_SIZE):
            iv_byte = (current_s_iv_val >> ((i & 7) * 8)) & 0xFF
            rc4_key[i] = base_key[i] ^ iv_byte

        sbox = rc4_ksa(rc4_key)

        # 6. RC4 Decryption (PRGA)
        keystream = rc4_prga(sbox, decrypt_size)  # Use simpler PRGA

        last_processed_byte = 0
        for i in range(decrypt_size):
            data_index = decrypt_offset + i
            # Ensure data_index is within bounds
            if data_index < len(page_data):
                decrypted_byte = page_data[data_index] ^ keystream[i]
                page_data[data_index] = decrypted_byte
                last_processed_byte = (
                    decrypted_byte  # Keep track of the last byte for IV update
                )
            else:
                print(
                    f"[Error] Decryption index {data_index} out of bounds for page data (len {len(page_data)}) at RVA {rva:#x}"
                )
                return None  # Indicate failure

        # 7. Update Serial IV
        new_s_iv = (
            SERIAL_IV_MULTIPLIER * (last_processed_byte ^ current_s_iv_val)
        ) & 0xFFFFFFFFFFFFFFFF
        # print(f"  Last Decrypted Byte: {last_processed_byte:#x}")
        # print(f"  Calculated New Serial IV: {new_s_iv:#x}")
        # IV is patched by the calling function

    # 8. Post-Decryption Relocations
    delta = original_image_base - image_base_in_ida
    if delta != 0:
        page_data = apply_relocations(page_data, rva, image_base_in_ida, delta)
    # else:
    # print("[Reloc] Delta is zero, skipping post-decryption relocations.")

    # 9. Patch IDA Database (using helper)
    if patch_bytes(page_addr, bytes(page_data)):
        # print(f"[Success] Patched {len(page_data)} bytes at {page_addr:#x}") # Reduced verbosity
        # Try to force reanalysis - schedule it
        ida_bytes.del_items(page_addr, ida_bytes.DELIT_SIMPLE, PAGE_SIZE)
        ida_auto.plan_range(page_addr, page_addr + PAGE_SIZE)  # Correct API
        # Try creating the first instruction to help analysis start
        ida_ua.create_insn(page_addr)
        # Mark for function creation if it looks like code
        seg = ida_segment.getseg(page_addr)
        if seg and seg.perm & ida_segment.SEGPERM_EXEC:
            ida_funcs.add_func(page_addr)

        return new_s_iv  # Return the *new* IV for the next iteration
    else:
        # Error already printed by helper
        return None  # Indicate failure


# --- Modified Automated Decryption Function ---
def decrypt_all_aegis_pages():
    """Decrypts all Aegis-protected regions based on the decrypted g_AegisImageData."""
    print("=== Starting Aegis Bulk Decryption ===")
    start_time = time.time()

    # --- STEP 0: Decrypt and Parse g_AegisImageData first ---
    aegis_image_data_obj = decrypt_and_parse_g_aegis_image_data()
    if not aegis_image_data_obj:
        print(
            "[Error] Failed to decrypt or parse g_AegisImageData. Aborting bulk decryption."
        )
        return
    return
    # --- ---

    image_base = idaapi.get_imagebase()  # Correct API
    if image_base == idaapi.BADADDR:
        print("[Error] Could not get image base.")
        return

    abs_blob0_start = ADDR_G_BUF_INIT_BLOB0 - image_base
    abs_blob12_start = ADDR_G_BUF_INIT_BLOB12 - image_base

    print(f"Image Base: {image_base:#x}")
    print(
        f"Skipping decryption for pages in range: [{abs_blob0_start:#x} to {abs_blob12_start:#x})"
    )

    # Read the initial serial IV
    try:
        current_s_iv = ida_bytes.get_qword(ADDR_S_IV)
        print(f"Initial Serial IV: {current_s_iv:#x}")
    except Exception as e:
        print(f"[Error] Failed to read initial Serial IV at {ADDR_S_IV:#x}: {e}")
        return

    decrypted_page_count = 0
    failed_page_count = 0
    processed_region_count = 0

    # --- Iterate using the PARSED EncryptedRanges ---
    # Accessing ctypes array directly
    encrypted_ranges = aegis_image_data_obj.EncryptedRanges
    if not encrypted_ranges:
        print("[Warning] No EncryptedRanges found in parsed g_AegisImageData.")
        return

    for region_index in range(len(encrypted_ranges)):  # Use len() on ctypes array
        region = encrypted_ranges[region_index]  # Access element
        region_rva = region.RVA
        region_size = region.size

        if region_rva == 0 or region_size == 0:
            # print(f"Region {region_index}: Skipped (zero RVA/Size).")
            continue  # Skip zero entries

        processed_region_count += 1
        print(
            f"\nProcessing Region {region_index}: RVA={region_rva:#x}, Size={region_size:#x}"
        )

        # Check alignment AFTER getting the real RVA
        if region_rva % PAGE_SIZE != 0:
            print(
                f"[Warning] Region {region_index} RVA {region_rva:#x} is not page aligned!"
            )
            # Proceeding anyway, page logic should handle it

        current_rva = region_rva
        region_end_rva = region_rva + region_size

        while current_rva < region_end_rva:
            # Align current_rva down to page boundary for processing
            page_rva = current_rva & ~(PAGE_SIZE - 1)
            page_start_addr = image_base + page_rva

            # Check if the page should be skipped
            if abs_blob0_start <= page_start_addr < abs_blob12_start:
                print(f"  Skipping page at RVA {page_rva:#x} (within InitBlob range)")
            else:
                # Decrypt the page and get the *next* IV
                next_s_iv = decrypt_aegis_page(page_rva, image_base, current_s_iv)

                if next_s_iv is not None:
                    # --- IMPORTANT: Update IV for the next iteration ---
                    current_s_iv = next_s_iv
                    # Patch the global IV in IDA *after* successful decryption of a page (using helper)
                    if not patch_qword(ADDR_S_IV, current_s_iv):
                        # Error already printed by helper
                        print(
                            f"[CRITICAL] Failed to patch Serial IV at {ADDR_S_IV:#x} after RVA {page_rva:#x}. Subsequent decryptions will be incorrect."
                        )
                        # return # Uncomment to stop on critical failure
                    decrypted_page_count += 1
                else:
                    print(f"[Error] Failed to decrypt page at RVA {page_rva:#x}")
                    failed_page_count += 1
                    # Decide whether to continue or stop on failure
                    # return # Uncomment to stop on first failure

            # Ensure we always advance by at least one page, even if region RVA wasn't aligned
            current_rva = page_rva + PAGE_SIZE

    end_time = time.time()
    print("\n=== Aegis Bulk Decryption Finished ===")
    print(
        f"Processed {processed_region_count} non-empty regions from g_AegisImageData."
    )
    print(f"Attempted Decryption on Pages: {decrypted_page_count}")
    print(f"Failed Pages: {failed_page_count}")
    print(f"Final Serial IV: {current_s_iv:#x}")
    print(f"Total Time: {end_time - start_time:.2f} seconds")
    if DRY_RUN:
        print("*** DRY RUN COMPLETE - NO CHANGES WERE MADE TO THE IDB ***")
    else:
        print("Please wait for IDA's analysis to complete (may take time).")
        ida_kernwin.refresh_idaview_anyway()
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)  # Refresh disassembly
        ida_kernwin.request_refresh(
            ida_kernwin.IWID_STRUCTS
        )  # Refresh structures if globals changed
        ida_kernwin.request_refresh(ida_kernwin.IWID_SEGS)  # Refresh segments view


# --- (Keep run_decrypt_single_page function) ---
def run_decrypt_single_page():
    """Gets RVA from user and runs decryption for a single page."""
    # --- STEP 0: Ensure g_AegisImageData is decrypted first ---
    # This is less critical for single page, but good practice
    # We won't parse it here, just decrypt if not already done (best effort)
    try:
        # Quick check: Read nonce, if it's zero or looks encrypted, try decrypting
        nonce_check = ida_bytes.get_dword(ADDR_G_AEGIS_IMAGE_DATA)
        # Add a more robust check if possible, e.g., a flag or checking known decrypted values
        if (
            nonce_check == 0 or nonce_check > 0xF0000000
        ):  # Heuristic for potentially encrypted value
            print(
                "[Info] g_AegisImageData appears encrypted, attempting decryption first..."
            )
            if not decrypt_and_parse_g_aegis_image_data():  # Decrypts and patches
                print(
                    "[Error] Failed to decrypt g_AegisImageData. Cannot proceed reliably."
                )
                return
    except Exception as e:
        print(f"[Error] Could not check/decrypt g_AegisImageData: {e}")
        return
    # --- ---

    rva_str = ida_kernwin.ask_str(
        "", 0x1000, "Enter RVA of page to decrypt (e.g., 0x1000):"
    )
    if not rva_str:
        print("Cancelled.")
        return

    try:
        rva = int(rva_str, 16)
        if rva % PAGE_SIZE != 0:
            print(f"[Error] RVA must be page-aligned ({PAGE_SIZE:#x}).")
            return

        image_base = idaapi.get_imagebase()  # Correct API
        current_s_iv = ida_bytes.get_qword(ADDR_S_IV)  # Read current IV
        print(f"Using current Serial IV from IDB: {current_s_iv:#x}")

        new_s_iv = decrypt_aegis_page(rva, image_base, current_s_iv)

        if new_s_iv is not None:
            print(f"Decryption successful. New Serial IV would be: {new_s_iv:#x}")
            # Patch the global IV in IDA (using helper)
            if patch_qword(ADDR_S_IV, new_s_iv):
                print(f"Patched Serial IV in IDB to {new_s_iv:#x}")
            # else: Error already printed by helper
            if not DRY_RUN:
                ida_kernwin.refresh_idaview_anyway()
                ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        else:
            print("Decryption failed.")

    except ValueError:
        print("[Error] Invalid RVA format. Please use hex (e.g., 0x1000).")
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")
        traceback.print_exc()


# --- Add menu items or run directly ---
# Example:
# ida_kernwin.add_menu_item("Edit/Plugins/", "Decrypt Single Aegis Page", "", 0, run_decrypt_single_page, None)
# ida_kernwin.add_menu_item("Edit/Plugins/", "Decrypt All Aegis Pages", "", 0, decrypt_all_aegis_pages, None)

# Or run directly for testing:


print(
    "IDAPython script loaded. Run 'decrypt_all_aegis_pages()' or 'run_decrypt_single_page()'."
)
if DRY_RUN:
    print("DRY RUN IS CURRENTLY ENABLED.")

decrypt_all_aegis_pages()
