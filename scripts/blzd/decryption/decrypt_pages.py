# -*- coding: utf-8 -*-
import struct
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_segment
import ida_ua
import idaapi
import idc

# --- Global flag for dry run mode ---
DRY_RUN = True  # Set to False to enable actual patching


# --- Patch helper functions ---
def patch_bytes(ea, data):
    if DRY_RUN:
        print(f"[Dry Run] Would patch {len(data)} bytes at {ea:#x}")
        return True
    else:
        return ida_bytes.patch_bytes(ea, data)


def patch_qword(ea, value):
    if DRY_RUN:
        print(f"[Dry Run] Would patch qword at {ea:#x} with {value:#x}")
        return True
    else:
        return ida_bytes.patch_qword(ea, value)


# --- Configuration: Addresses of Global Variables (Update these!) ---
ADDR_G_BUF_CRYPTO_KEY = idc.get_name_ea_simple("g_bufCryptoKey")
ADDR_S_IV = 0x1443D9330
ADDR_G_AEGIS_ORIGINAL_BASE = idc.get_name_ea_simple("g_AegisImageOriginalBaseAddress")
ADDR_G_MULTIPAGE_RELOCS = idc.get_name_ea_simple(
    "?g_MultipageRelocs@@3PAURelocRegion@ImageUtils@Aegis@@A"
)
ADDR_G_MULTIPAGE_RELOC_COUNT = idc.get_name_ea_simple("?g_MultipageRelocCount@@3IA")
ADDR_G_BUF_INIT_BLOB0 = idc.get_name_ea_simple("g_bufInitBlob0")
ADDR_G_BUF_INIT_BLOB12 = idc.get_name_ea_simple("g_bufInitBlob12")
ADDR_G_AEGIS_IMAGE_DATA = idc.get_name_ea_simple(
    "?g_AegisImageData@@3UAEGIS_IMAGE_DATA@@C"
)

_ImageBase = idaapi.get_imagebase()
ADDR_ENCRYPTED_REGIONS_ARRAY = _ImageBase + 0x106FE7E
NUM_ENCRYPTED_REGIONS = 32

# Constants
PAGE_SIZE = 0x1000
CRYPTO_KEY_BANK_SIZE = 0x5A  # 90
CRYPTO_KEY_SIZE = 0x169  # 361
RC4_STATE_SIZE = 0x100
RELOC_TYPE_HIGHLOW = 3
RELOC_TYPE_DIR64 = 0xA
SERIAL_IV_MULTIPLIER = 0x100000001B3
AEGIS_IMAGE_DATA_DECRYPT_LEN = 920  # 0x398
AEGIS_IMAGE_DATA_KEY_LEN = 16  # 0x10


# --- RC4 Implementation ---
def rc4_ksa(key):
    key_len = len(key)
    sbox = list(range(RC4_STATE_SIZE))
    j = 0
    for i in range(RC4_STATE_SIZE):
        j = (j + sbox[i] + key[i % key_len]) % RC4_STATE_SIZE
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def rc4_prga(sbox, data_len):
    i = 0
    j = 0
    keystream = bytearray(data_len)
    sbox_copy = list(sbox)
    for k in range(data_len):
        i = (i + 1) % RC4_STATE_SIZE
        j = (j + sbox_copy[i]) % RC4_STATE_SIZE
        sbox_copy[i], sbox_copy[j] = sbox_copy[j], sbox_copy[i]
        keystream_byte = sbox_copy[(sbox_copy[i] + sbox_copy[j]) % RC4_STATE_SIZE]
        keystream[k] = keystream_byte
    return keystream, i, j


def rc4_prga_stateful(sbox, i, j, data_len):
    """RC4 PRGA that updates i, j and returns keystream."""
    keystream = bytearray(data_len)
    sbox_copy = list(sbox)  # Work on a copy
    current_i = i
    current_j = j
    for k in range(data_len):
        current_i = (current_i + 1) % RC4_STATE_SIZE
        current_j = (current_j + sbox_copy[current_i]) % RC4_STATE_SIZE
        sbox_copy[current_i], sbox_copy[current_j] = (
            sbox_copy[current_j],
            sbox_copy[current_i],
        )
        keystream_byte = sbox_copy[
            (sbox_copy[current_i] + sbox_copy[current_j]) % RC4_STATE_SIZE
        ]
        keystream[k] = keystream_byte
    # Note: The C++ code updates the sbox in place during PRGA,
    # but for XORing a block, we just need the keystream.
    # If the *same* RC4 state was reused later (which it isn't here),
    # we'd need to return the modified sbox, i, and j.
    return keystream


def decrypt_g_aegis_image_data():
    """Decrypts the first 920 bytes of g_AegisImageData in place."""
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
            return False

        # 2. Read the encrypted data
        encrypted_data = ida_bytes.get_bytes(
            ADDR_G_AEGIS_IMAGE_DATA, AEGIS_IMAGE_DATA_DECRYPT_LEN
        )
        if not encrypted_data or len(encrypted_data) != AEGIS_IMAGE_DATA_DECRYPT_LEN:
            print(
                f"[Error] Failed to read encrypted g_AegisImageData from {ADDR_G_AEGIS_IMAGE_DATA:#x}"
            )
            return False

        # 3. Perform RC4 KSA
        sbox = rc4_ksa(rc4_key_image_data)

        # 4. Perform RC4 PRGA (stateful version matching the C++ loop)
        decrypted_data = bytearray(encrypted_data)
        i = 0
        j = 0
        sbox_prga = list(sbox)  # Use a copy for PRGA state updates
        for k in range(AEGIS_IMAGE_DATA_DECRYPT_LEN):
            i = (i + 1) % RC4_STATE_SIZE
            j = (j + sbox_prga[i]) % RC4_STATE_SIZE
            sbox_prga[i], sbox_prga[j] = sbox_prga[j], sbox_prga[i]
            keystream_byte = sbox_prga[(sbox_prga[i] + sbox_prga[j]) % RC4_STATE_SIZE]
            decrypted_data[k] = encrypted_data[k] ^ keystream_byte

        # 5. Patch the decrypted data back into IDA
        if patch_bytes(ADDR_G_AEGIS_IMAGE_DATA, bytes(decrypted_data)):
            print(
                f"[Success] Decrypted and patched {AEGIS_IMAGE_DATA_DECRYPT_LEN} bytes of g_AegisImageData at {ADDR_G_AEGIS_IMAGE_DATA:#x}"
            )
            # Mark the data as decrypted (optional, helps avoid re-running)
            # ida_bytes.set_cmt(ADDR_G_AEGIS_IMAGE_DATA, "Decrypted by script", 0)
            return True
        else:
            print(
                f"[Error] Failed to patch decrypted g_AegisImageData at {ADDR_G_AEGIS_IMAGE_DATA:#x}"
            )
            return False

    except Exception as e:
        print(f"[Error] Exception during g_AegisImageData decryption: {e}")
        return False


# --- Relocation Helper ---
def apply_relocations(page_data, page_rva, image_base, delta):
    print(f"[Reloc] Applying delta {delta:#x} for page RVA {page_rva:#x}")
    reloc_addr = idaapi.get_imagebase()
    reloc_size = 0
    fixed_count = 0

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg and ida_segment.get_segm_name(seg) == ".reloc":
            reloc_addr = seg.start_ea
            reloc_size = seg.size()
            break

    if reloc_size == 0:
        print("[Reloc] Warning: Could not find .reloc section.")
        return page_data

    current_reloc_addr = reloc_addr
    end_reloc_addr = reloc_addr + reloc_size

    page_start_rva = page_rva
    page_end_rva = page_rva + PAGE_SIZE

    while current_reloc_addr < end_reloc_addr:
        block_rva = ida_bytes.get_dword(current_reloc_addr)
        block_size = ida_bytes.get_dword(current_reloc_addr + 4)

        if block_rva == 0 or block_size == 0:
            break

        block_affects_page = False
        num_entries = (block_size - 8) // 2
        entry_addr_check = current_reloc_addr + 8
        for _ in range(num_entries):
            entry_check = ida_bytes.get_word(entry_addr_check)
            offset_in_block_check = entry_check & 0xFFF
            reloc_rva_check = block_rva + offset_in_block_check
            if page_start_rva <= reloc_rva_check < page_end_rva:
                block_affects_page = True
                break
            entry_addr_check += 2

        if not block_affects_page:
            current_reloc_addr += block_size
            continue

        num_entries = (block_size - 8) // 2
        entry_addr = current_reloc_addr + 8

        for _ in range(num_entries):
            entry = ida_bytes.get_word(entry_addr)
            reloc_type = entry >> 12
            offset_in_block = entry & 0xFFF
            reloc_rva = block_rva + offset_in_block

            if page_start_rva <= reloc_rva < page_end_rva:
                offset_in_page_data = reloc_rva - page_start_rva

                if reloc_type == RELOC_TYPE_HIGHLOW:
                    if offset_in_page_data + 4 <= len(page_data):
                        original_val = struct.unpack(
                            "<I",
                            page_data[offset_in_page_data : offset_in_page_data + 4],
                        )[0]
                        new_val = (original_val + delta) & 0xFFFFFFFF
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
                        page_data[offset_in_page_data : offset_in_page_data + 8] = (
                            struct.pack("<Q", new_val)
                        )
                        fixed_count += 1
                    else:
                        print(
                            f"[Reloc] Warning: DIR64 relocation out of bounds at RVA {reloc_rva:#x}"
                        )

            entry_addr += 2

        current_reloc_addr += block_size

    if fixed_count > 0:
        print(f"[Reloc] Applied {fixed_count} relocations for page RVA {page_rva:#x}.")
    return page_data


# --- Main Decryption Function (Single Page) ---
def decrypt_aegis_page(rva, image_base_in_ida, current_s_iv_val):
    print(f"--- Decrypting page at RVA {rva:#x} ---")
    page_addr = image_base_in_ida + rva
    # if not ida_bytes.is_loaded(page_addr):
    #     print(f"[Error] Address {page_addr:#x} is not loaded.")
    #     return None

    try:
        original_image_base = ida_bytes.get_qword(ADDR_G_AEGIS_ORIGINAL_BASE)
        multipage_reloc_count = ida_bytes.get_dword(ADDR_G_MULTIPAGE_RELOC_COUNT)
        page_index = rva // PAGE_SIZE
        key_bank_index = page_index % CRYPTO_KEY_BANK_SIZE
        key_bank_addr = ADDR_G_BUF_CRYPTO_KEY + (key_bank_index * CRYPTO_KEY_SIZE)
        base_key = ida_bytes.get_bytes(key_bank_addr, CRYPTO_KEY_SIZE)
        if not base_key or len(base_key) != CRYPTO_KEY_SIZE:
            print(
                f"[Error] Failed to read base key for page index {page_index} (bank {key_bank_index})"
            )
            return None

        multipage_relocs = []
        if multipage_reloc_count > 0 and multipage_reloc_count < 1024:
            struct_size = 8
            print(
                f"  Reading {multipage_reloc_count} multipage reloc entries (struct size: {struct_size})..."
            )
            for i in range(multipage_reloc_count):
                reloc_entry_addr = ADDR_G_MULTIPAGE_RELOCS + i * struct_size
                reloc_rva = ida_bytes.get_dword(reloc_entry_addr)
                reloc_size = ida_bytes.get_dword(reloc_entry_addr + 4)
                if reloc_size > 0:
                    multipage_relocs.append({"rva": reloc_rva, "size": reloc_size})
    except Exception as e:
        print(f"[Error] Failed to read global variables: {e}")
        return None

    print(f"  Page Index: {page_index}")
    print(f"  Key Bank Index: {key_bank_index}")
    print(f"  Using Serial IV: {current_s_iv_val:#x}")

    page_data_enc = ida_bytes.get_bytes(page_addr, PAGE_SIZE)
    if not page_data_enc or len(page_data_enc) != PAGE_SIZE:
        print(f"[Error] Failed to read page data at {page_addr:#x}")
        return None

    page_data = bytearray(page_data_enc)
    decrypt_offset = 0
    decrypt_size = PAGE_SIZE
    page_end_rva = rva + PAGE_SIZE

    for reloc in multipage_relocs:
        reloc_rva = reloc["rva"]
        reloc_size = reloc["size"]
        reloc_end_rva = reloc_rva + reloc_size

        if reloc_rva < rva < reloc_end_rva:
            overlap = reloc_end_rva - rva
            if overlap < decrypt_size:
                decrypt_offset += overlap
                decrypt_size -= overlap
            else:
                decrypt_size = 0

        if reloc_rva < page_end_rva < reloc_end_rva:
            overlap = page_end_rva - reloc_rva
            if overlap < decrypt_size:
                decrypt_size -= overlap
            else:
                decrypt_size = 0

    new_s_iv = current_s_iv_val

    if decrypt_size <= 0:
        print(
            "[Info] Decryption size reduced to zero or less due to multipage relocs. Skipping decryption."
        )
    else:
        rc4_key = bytearray(CRYPTO_KEY_SIZE)
        for i in range(CRYPTO_KEY_SIZE):
            iv_byte = (current_s_iv_val >> ((i & 7) * 8)) & 0xFF
            rc4_key[i] = base_key[i] ^ iv_byte

        sbox = rc4_ksa(rc4_key)
        keystream, _, _ = rc4_prga(sbox, decrypt_size)
        last_processed_byte = 0
        for i in range(decrypt_size):
            data_index = decrypt_offset + i
            if data_index < len(page_data):
                decrypted_byte = page_data[data_index] ^ keystream[i]
                page_data[data_index] = decrypted_byte
                last_processed_byte = decrypted_byte
            else:
                print(
                    f"[Error] Decryption index {data_index} out of bounds for page data (len {len(page_data)})"
                )
                return None

        new_s_iv = (
            SERIAL_IV_MULTIPLIER * (last_processed_byte ^ current_s_iv_val)
        ) & 0xFFFFFFFFFFFFFFFF

    delta = original_image_base - image_base_in_ida
    if delta != 0:
        page_data = apply_relocations(page_data, rva, image_base_in_ida, delta)

    if patch_bytes(page_addr, bytes(page_data)):
        print(f"[Success] Patched {len(page_data)} bytes at {page_addr:#x}")
        ida_bytes.del_items(page_addr, ida_bytes.DELIT_SIMPLE, PAGE_SIZE)
        ida_auto.plan_range(page_addr, page_addr + PAGE_SIZE)
        ida_ua.create_insn(page_addr)
        seg = ida_segment.getseg(page_addr)
        if seg and seg.perm & ida_segment.SEGPERM_EXEC:
            ida_funcs.add_func(page_addr)
        return new_s_iv
    else:
        print(f"[Error] Failed to patch bytes at {page_addr:#x}")
        return None


# --- Automated Decryption Function ---
def decrypt_all_aegis_pages():
    print("=== Starting Aegis Bulk Decryption ===")
    start_time = time.time()

    image_base = idaapi.get_imagebase()
    if image_base == idaapi.BADADDR:
        print("[Error] Could not get image base.")
        return

    abs_blob0_start = image_base + (ADDR_G_BUF_INIT_BLOB0 - 0x140000000)
    abs_blob12_start = image_base + (ADDR_G_BUF_INIT_BLOB12 - 0x140000000)

    print(f"Image Base: {image_base:#x}")
    print(
        f"Skipping decryption for pages in range: [{abs_blob0_start:#x} to {abs_blob12_start:#x})"
    )

    try:
        current_s_iv = ida_bytes.get_qword(ADDR_S_IV)
        print(f"Initial Serial IV: {current_s_iv:#x}")
    except Exception as e:
        print(f"[Error] Failed to read initial Serial IV at {ADDR_S_IV:#x}: {e}")
        return

    decrypted_page_count = 0
    failed_page_count = 0

    for region_index in range(NUM_ENCRYPTED_REGIONS):
        try:
            region_entry_addr = ADDR_ENCRYPTED_REGIONS_ARRAY + region_index * 8
            region_rva = ida_bytes.get_dword(region_entry_addr)
            region_size = ida_bytes.get_dword(region_entry_addr + 4)
        except Exception as e:
            print(
                f"[Error] Failed to read region {region_index} info at {region_entry_addr:#x}: {e}"
            )
            continue

        if region_rva == 0 or region_size == 0:
            print(f"Region {region_index}: Skipping zero RVA/Size.")
            continue

        print(
            f"\nProcessing Region {region_index}: RVA={region_rva:#x}, Size={region_size:#x}"
        )

        current_rva = region_rva
        region_end_rva = region_rva + region_size

        while current_rva < region_end_rva:
            page_start_addr = image_base + current_rva

            if abs_blob0_start <= page_start_addr < abs_blob12_start:
                print(
                    f"  Skipping page at RVA {current_rva:#x} (within InitBlob range)"
                )
            else:
                next_s_iv = decrypt_aegis_page(current_rva, image_base, current_s_iv)

                if next_s_iv is not None:
                    current_s_iv = next_s_iv
                    if not patch_qword(ADDR_S_IV, current_s_iv):
                        print(
                            f"[Error] Failed to patch Serial IV at {ADDR_S_IV:#x} after RVA {current_rva:#x}"
                        )
                    decrypted_page_count += 1
                else:
                    print(f"[Error] Failed to decrypt page at RVA {current_rva:#x}")
                    failed_page_count += 1

            current_rva += PAGE_SIZE

    end_time = time.time()
    print("\n=== Aegis Bulk Decryption Finished ===")
    print(f"Decrypted Pages: {decrypted_page_count}")
    print(f"Failed Pages: {failed_page_count}")
    print(f"Final Serial IV: {current_s_iv:#x}")
    print(f"Total Time: {end_time - start_time:.2f} seconds")
    print("Please wait for IDA's analysis to complete (may take time).")
    ida_kernwin.refresh_idaview_anyway()
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STRUCTS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_SEGS)


# --- Manual Decryption Function (Single Page) ---
def run_decrypt_single_page():
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

        image_base = idaapi.get_imagebase()
        current_s_iv = ida_bytes.get_qword(ADDR_S_IV)
        print(f"Using current Serial IV from IDB: {current_s_iv:#x}")

        new_s_iv = decrypt_aegis_page(rva, image_base, current_s_iv)

        if new_s_iv is not None:
            print(f"Decryption successful. New Serial IV would be: {new_s_iv:#x}")
            if patch_qword(ADDR_S_IV, new_s_iv):
                print(f"Patched Serial IV in IDB to {new_s_iv:#x}")
            else:
                print(f"[Error] Failed to patch Serial IV at {ADDR_S_IV:#x}")
            ida_kernwin.refresh_idaview_anyway()
            ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        else:
            print("Decryption failed.")

    except ValueError:
        print("[Error] Invalid RVA format. Please use hex (e.g., 0x1000).")
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")


# Uncomment the following lines to add menu items or run directly:
# ida_kernwin.add_menu_item("Edit/Plugins/", "Decrypt Single Aegis Page", "", 0, run_decrypt_single_page, None)
# ida_kernwin.add_menu_item("Edit/Plugins/", "Decrypt All Aegis Pages", "", 0, decrypt_all_aegis_pages, None)

# Or run directly for testing:
decrypt_all_aegis_pages()

print(
    "IDAPython script loaded. Run 'decrypt_all_aegis_pages()' or 'run_decrypt_single_page()'."
)
