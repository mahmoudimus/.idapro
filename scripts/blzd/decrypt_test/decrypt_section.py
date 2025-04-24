import binascii
import json
from itertools import chain


class RC4PEDecryptor:
    def __init__(
        self,
        crypto_key_data,
        key_count,
        key_size,
        sections_to_decrypt,
        tls_region=None,
        multipage_relocs=None,
        dryrun=False,
        patch_mode="patch",
        max_pages=None,
    ):
        """
        Initialize the RC4 PE decryptor

        Args:
            crypto_key_data: Raw key data bytes
            key_count: Number of keys in the array (const2 in C#)
            key_size: Size of each key in bytes (const1 in C#)
            sections_to_decrypt: List of section names to decrypt
            tls_region: Dictionary with 'start' and 'end' addresses for TLS region to skip
            multipage_relocs: List of dictionaries with 'rva' and 'size' keys
            dryrun: If True, perform decryption without patching IDA database
            patch_mode: "patch" (allows undo) or "put" (destructive)
            max_pages: Maximum number of pages to decrypt (None = all pages)
        """
        self.crypto_key_data = crypto_key_data
        self.key_count = key_count  # const2 in C#
        self.key_size = key_size  # const1 in C#
        self.sections_to_decrypt = sections_to_decrypt
        self.dryrun = dryrun
        self.patch_mode = patch_mode.lower()
        self.max_pages = max_pages
        self.page_size = 0x1000  # 4KB standard page size

        if self.patch_mode not in ["patch", "put"]:
            print("[!] Warning: Invalid patch_mode. Using 'patch' mode by default.")
            self.patch_mode = "patch"

        # Default values for optional parameters
        self.tls_region = tls_region or {"start": 0, "end": 0}
        self.multipage_relocs = multipage_relocs or []

        # Store decryption results when in dryrun mode
        self.decryption_results = {}

        # Running hash for serial encryption (equivalent to _pageHash in C#)
        self.page_hash = 0

    def reset_state(self):
        """Reset the decryption state (page_hash) for a new section"""
        self.page_hash = 0

    def bytes_to_dash_hex(self, data, length=None):
        """Convert bytes to dash-separated hex string, like in C# debug output"""
        if length is None:
            length = len(data)
        length = min(length, len(data))
        return "-".join([f"{b:02X}" for b in data[:length]])

    def initialize_key_state(self, crypt_key, const1, crypt_offset_base):
        """
        Initialize the RC4 key state according to the C# algorithm

        Args:
            crypt_key: The entire crypto key array
            const1: Size of each key (key_size)
            crypt_offset_base: Offset into the crypto key array for this page

        Returns:
            Initialized key state array
        """
        # Create key state array with room for both the S-box and the key data
        key_state = bytearray(const1 + 0x100)

        # Set up the second part of the array with XORed key data
        page_hash_bytes = self.page_hash.to_bytes(8, byteorder="little")

        for i in range(const1):
            if crypt_offset_base + i < len(crypt_key):
                key_state[i + 0x100] = (
                    crypt_key[crypt_offset_base + i] ^ page_hash_bytes[i & 7]
                )

        # Initialize the S-box part (first 0x100 bytes)
        for i in range(0x100):
            key_state[i] = i

        # Key scheduling algorithm (KSA) - match C# implementation exactly
        prev_key_state_offset = 0

        for j in range(0x100):
            curr_key_state = key_state[j]
            prev_key_state_offset = (
                prev_key_state_offset + key_state[j % const1 + 0x100] + curr_key_state
            ) & 0xFF

            # Swap values
            key_state[j], key_state[prev_key_state_offset] = (
                key_state[prev_key_state_offset],
                curr_key_state,
            )

        return key_state

    def process_data(self, binary, start_offset, key_state):
        """
        Process (decrypt/encrypt) data using the C# algorithm

        Args:
            binary: Data buffer to process
            start_offset: Starting offset in the buffer
            key_state: Initialized key state array
        """
        prev_key_state_offset = 0

        # Only process up to page_size (0x1000) bytes
        max_bytes = min(self.page_size, len(binary) - start_offset)

        for i in range(max_bytes):
            # Important: in the C# code, they use (i + 1) % 0x100 to get the current key state
            curr_idx = (i + 1) % 0x100
            curr_key_state = key_state[curr_idx]

            # XOR the byte with the key state
            binary[i + start_offset] ^= curr_key_state

            # Update the offset - note this happens AFTER XOR, different from standard RC4
            prev_key_state_offset = (prev_key_state_offset + curr_key_state) & 0xFF

            # Swap the values
            key_state[curr_idx], key_state[prev_key_state_offset] = (
                key_state[prev_key_state_offset],
                curr_key_state,
            )

    def fnv1a_hash(self, data, max_length=None):
        """
        Compute FNV-1a hash on the data - EXACT match to C# implementation

        Args:
            data: Data to hash
            max_length: Maximum number of bytes to hash (default: page_size)

        Returns:
            64-bit FNV-1a hash
        """
        if max_length is None:
            max_length = min(self.page_size, len(data))
        else:
            max_length = min(max_length, len(data))

        offset_basis = 0xCBF29CE484222325
        prime = 0x100000001B3

        hash_value = offset_basis

        # CRITICAL: The C# implementation multiplies first, not XOR first
        for i in range(max_length):
            hash_value = (prime * (data[i] ^ hash_value)) & 0xFFFFFFFFFFFFFFFF

        return hash_value

    def decrypt_page(self, binary, crypt_key, crypt_offset_base, start_offset, const1):
        """
        Decrypt a page of data using the C# algorithm

        Args:
            binary: Data buffer to decrypt
            crypt_key: The entire crypto key array
            crypt_offset_base: Offset into the key array for this page (calculated from key_index)
            start_offset: Starting offset in the buffer
            const1: Size of each key (key_size)

        Returns:
            True if successful
        """
        try:
            print(
                f"[Debug] Starting DecryptPage with cryptOffsetBase: {crypt_offset_base}, Const1: {const1}, StartOffset: FileOffset={start_offset}"
            )

            # Print first 16 bytes of key
            key_preview = self.bytes_to_dash_hex(
                crypt_key[crypt_offset_base : crypt_offset_base + 16], 16
            )
            print(f"[Debug] CryptKey (first 16 bytes): {key_preview}")

            # Initialize the key state
            key_state = self.initialize_key_state(crypt_key, const1, crypt_offset_base)

            # Print first 16 bytes of initialized key state
            state_preview = self.bytes_to_dash_hex(key_state[:16], 16)
            print(f"[Debug] Initialized keyState (first 16 bytes): {state_preview}")

            # Process the data
            self.process_data(binary, start_offset, key_state)

            # Print first 16 bytes of decrypted data
            data_preview = self.bytes_to_dash_hex(
                binary[start_offset : start_offset + 16], 16
            )
            print(f"[Debug] Decrypted binary (first 16 bytes of page): {data_preview}")

            # Compute FNV-1a hash on the decrypted data
            page_hash_span = binary[start_offset : start_offset + self.page_size]
            print(f"[Debug] Page hash length: {len(page_hash_span)}")

            # Update the page hash for the next page
            self.page_hash = self.fnv1a_hash(page_hash_span, self.page_size)

            print(f"[Debug] Computed page hash: 0x{self.page_hash:X}")

            return True
        except Exception as e:
            print(f"[ERROR] Decryption error: {e}")
            import traceback

            traceback.print_exc()
            return False

    # Other methods remain the same
    def get_pe_sections(self):
        """Get PE section information from IDA"""
        sections = []
        for seg_idx in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(seg_idx)
            if not seg:
                continue

            name = idaapi.get_segm_name(seg)
            sections.append(
                {
                    "name": name,
                    "start": seg.start_ea,
                    "size": seg.end_ea - seg.start_ea,
                    "vaddr": seg.start_ea
                    - idaapi.get_imagebase(),  # Relative virtual address
                }
            )
        return sections

    def hexdump(self, data, addr, bytes_per_line=16):
        """Create a hexdump of data for display"""
        result = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i : i + bytes_per_line]
            hex_values = " ".join(f"{b:02X}" for b in chunk)
            ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            result.append(
                f"{addr+i:08X}: {hex_values.ljust(bytes_per_line*3)} {ascii_values}"
            )
        return "\n".join(result)

    def apply_patch(self, addr, data):
        """Apply the patch using the selected method"""
        if self.patch_mode == "patch":
            return ida_bytes.patch_bytes(addr, data)
        else:  # "put" mode
            return ida_bytes.put_bytes(addr, data)

    def adjust_decryption_for_multipage_relocs(
        self, decrypt_addr, decrypt_size, start_rva
    ):
        """Adjust decryption range for multipage relocations"""
        end_rva = decrypt_size + start_rva

        for reloc in self.multipage_relocs:
            if reloc["rva"] < start_rva and reloc["rva"] + reloc["size"] > start_rva:
                overlap = reloc["rva"] + reloc["size"] - start_rva
                decrypt_addr += overlap
                decrypt_size -= overlap

            if reloc["rva"] < end_rva and reloc["rva"] + reloc["size"] > end_rva:
                decrypt_size -= end_rva - reloc["rva"]

        return decrypt_addr, decrypt_size


def test_specific_page():
    """Test decryption of a specific page using the exact parameters from the C# logs"""
    print("[+] Testing RC4 decryption of specific page")

    # Parse the crypto key
    crypto_key_hex = (
        "D2-FC-BB-89-3D-2C-E4-78-F9-BD-EF-E3-90-A7-96-3E-79-77-82-42-2E-CE-4E-61-FA-65-FC-A2-FD-B5-E7-07-51-D8-13-7E-03-C1-3A-86-"
        "7A-0F-E1-5A-E1-E4-46-4E-10-B6-7D-D9-19-41-FC-2A-C4-3F-B6-33-F2-CA-26-1D-B1-41-23-9E-CA-07-96-43-12-91-14-B3-4D-E1-FE-8D-"
        "E3-83-5D-EF-87-57-9E-A1-8C-39-71-A0-E0-55-88-9F-70-3C-3A-E4-98-2F-55-1D-7E-24-CB-B0-DE-EB-60-DB-22-B2-89-C4-76-F0-6C-50-"
        "94-C7-83-1E-76-16-23-C5-CD-40-74-B3-5F-34-95-B5-28-20-79-D8-26-4A-C2-83-21-2C-7C-53-C8-F7-A5-D9-63-2D-2C-2D-49-82-1A-C1-"
        "6B-56-40-5D-E6-7E-1E-42-B0-CF-C0-7D-E8-9C-30-D3-72-0A-7B-0F-71-41-85-01-3F"
    )
    crypto_key_data = bytes(
        chain.from_iterable(
            json.load(open("g_bufCryptoKey.json", "r"))["g_bufCryptoKey"]
        )
    )

    # Create a test buffer with encrypted data
    # IMPORTANT: You'll need to get this from your IDA database at the right offset
    # In a real implementation, use: encrypted_data = bytearray(idc.get_bytes(decrypt_addr, 0x1000))

    # Use these exact parameters from the C# log
    const2 = 0xB9  # key_count
    const1 = 0x1A8  # key_size
    memory_offset = 0xBA000

    # For testing in IDA, you'd need to adjust this to your IDA database address
    ida_base = 0x140000000  # Adjust as needed for your IDA database
    decrypt_addr = ida_base + memory_offset  # Adjust as needed based on your PE mapping
    print(hex(decrypt_addr))
    # Read the data if in IDA
    with open("11.1.0.59888.bin", "rb") as f:
        encrypted_data = bytearray(f.read())
    print(
        f"[+] Read {len(encrypted_data)} bytes from IDA at address 0x{decrypt_addr:X}"
    )

    # Calculate crypto offset base exactly as in the C# code
    cryptOffsetBase = const1 * ((memory_offset // 0x1000) % const2)
    print(
        f"[+] Using cryptOffsetBase: 0x{cryptOffsetBase:X} for memory offset 0x{memory_offset:X}"
    )

    # Create decryptor
    decryptor = RC4PEDecryptor(
        crypto_key_data=crypto_key_data,
        key_count=const2,
        key_size=const1,
        sections_to_decrypt=[".text"],
        dryrun=True,
    )

    # Reset state
    decryptor.reset_state()

    # Decrypt the page
    decryptor.decrypt_page(
        binary=encrypted_data,
        crypt_key=crypto_key_data,
        crypt_offset_base=cryptOffsetBase,
        start_offset=0,  # Start at beginning of our buffer
        const1=const1,
    )

    # Print result
    print("\n[+] Decryption result (first 32 bytes):")
    print(decryptor.hexdump(encrypted_data[:32], decrypt_addr))

    # Compare with expected
    expected = bytes.fromhex(
        "13 60 5B C2 0A D4 A2 FB 9A 7E 19 20 C1 73 98 57 06 EC 29 8C E9 D4 02 F7 1B 4F 58 92 2F 3D 30 18"
    )
    print("\n[+] Expected result:")
    print(decryptor.hexdump(expected, decrypt_addr))

    print(f"\n[+] Match: {encrypted_data[:32] == expected}")


# If running as a script in IDA
if __name__ == "__main__":
    test_specific_page()
