# test_aegis_vs_decrypt_section.py
import json
import sys
from itertools import chain

sys.path.insert(0, ".")
import idapro  # isort:skip
import aegis_decrypt_section
import decrypt_section

PatchManager = aegis_decrypt_section.PatchManager
Decryptor2 = aegis_decrypt_section.RC4PEDecryptor
Decryptor1 = decrypt_section.RC4PEDecryptor

# adjust these imports to wherever your scripts actually live:


def hexdump(data: bytes, base_addr: int):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexv = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_addr + i:016X}: {hexv:<48} {asc}")
    return "\n".join(lines)


def main():
    # --- load the flattened key as in decrypt_section.py test ---
    data = json.load(open("g_bufCryptoKey.json", "r"))["g_bufCryptoKey"]
    flat_key = bytes(chain.from_iterable(data))

    const2 = 0xB9  # number of keys
    const1 = 0x1A8  # size of each key
    memory_offset = 0xBA000
    base_addr = 0x140000000

    # load up to 4 pages of encrypted data
    page_size = 0x1000
    with open("11.1.0.59888.bin", "rb") as f:
        encrypted = bytearray(f.read(page_size * 4))
    num_pages = len(encrypted) // page_size

    # expected result for the first page (first 32 bytes)
    expected = bytes.fromhex(
        "13 60 5B C2 0A D4 A2 FB 9A 7E 19 20 C1 73 98 57 "
        "06 EC 29 8C E9 D4 02 F7 1B 4F 58 92 2F 3D 30 18"
    )

    # build key-matrix for aegis
    matrix = [flat_key[i * const1 : (i + 1) * const1] for i in range(const2)]

    # prepare both decryptors
    d1 = Decryptor1(
        crypto_key_data=flat_key,
        key_count=const2,
        key_size=const1,
        sections_to_decrypt=[".text"],
        dryrun=True,
    )
    d2 = Decryptor2(
        crypto_matrix=matrix,
        patch_manager=PatchManager(dry_run=True),
        sections_to_decrypt=[".text"],
    )
    d1.reset_state()
    d2.reset_state()

    # create output buffers
    out1 = list(encrypted)  # for decrypt_section.py (list[int])
    out2 = bytearray(encrypted)  # for aegis_decrypt_section (bytearray)

    # decrypt each page
    for page in range(num_pages):
        start = page * page_size
        end = start + page_size
        rva_page = (memory_offset >> 12) + page

        # decrypt_section.py page
        cob = const1 * (rva_page % const2)
        d1.decrypt_page(
            binary=out1,
            crypt_key=flat_key,
            crypt_offset_base=cob,
            start_offset=start,
            const1=const1,
        )

        # aegis_decrypt_section.py page
        key_idx = rva_page % const2
        success, dec_page = d2.decrypt_page(out2[start:end], matrix[key_idx])
        if not success:
            raise RuntimeError(f"Page {page} decryption failed")
        out2[start:end] = dec_page

    # compare and print first 32 bytes of each page
    for page in range(num_pages):
        start = page * page_size
        print(f"\n===== Page {page} (VA=0x{base_addr+memory_offset+start:X}) =====")
        a1 = bytes(out1[start : start + 32])
        a2 = bytes(out2[start : start + 32])
        print("decrypt_section.py  :", hexdump(a1, base_addr + memory_offset + start))
        print("aegis_decrypt_section:", hexdump(a2, base_addr + memory_offset + start))
        print("Match 32 bytes:", a1 == a2)


if __name__ == "__main__":
    main()
