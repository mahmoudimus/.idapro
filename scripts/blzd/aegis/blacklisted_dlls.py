import struct
from typing import Iterator, TypeVar

# TypeVar allows the function to work generically with str or bytes
T = TypeVar("T", str, bytes)


def sliding_window(sequence: T, n: int) -> Iterator[T]:
    """
    Creates an iterator that yields sliding windows of size 'n' over a sequence.

    The first window starts at index 0 (sequence[0:n]), the second at index 1
    (sequence[1:n+1]), and so on, until the end of the sequence is reached.

    Args:
        sequence: The input string or bytes sequence.
        n: The desired window size (must be positive).

    Yields:
        Subsequences (str or bytes, matching the input type) of length 'n'.

    Raises:
        ValueError: If n is not positive.
        TypeError: If sequence is not a string or bytes-like object supporting slicing.
    """
    if not isinstance(n, int) or n <= 0:
        raise ValueError("Window size 'n' must be a positive integer")

    try:
        seq_len = len(sequence)
    except TypeError:
        raise TypeError("Input 'sequence' must support len()")

    if n > seq_len:
        # If the window size is larger than the sequence, no windows can be formed.
        # An empty iterator is implicitly returned by the loop condition below failing.
        pass

    # Iterate through all possible starting indices for a window of size n
    # The last possible start index is seq_len - n
    for i in range(seq_len - n + 1):
        try:
            yield sequence[i : i + n]
        except TypeError:
            # Catch potential issues if the object supports len() but not slicing
            raise TypeError("Input 'sequence' must support slicing")


def rc4_ksa_variant_blacklist(key_27_bytes):
    """Performs the KSA using the first 27 bytes of the key."""
    if len(key_27_bytes) < 27:
        print("ERROR: Key must be at least 27 bytes long for blacklist KSA.")
        return None

    s = list(range(256))
    ksa_j = 0
    # KSA loop from TlsInitialization_Internal (using temp buffer and key mod 0x1B)
    for ksa_i in range(256):
        key_byte = key_27_bytes[ksa_i % 27]  # Modulo 0x1B
        ksa_j = (ksa_j + s[ksa_i] + key_byte) & 0xFF
        s[ksa_i], s[ksa_j] = s[ksa_j], s[ksa_i]
    return s


def rc4_prga_variant_blacklist(s_box, length):
    """Generates keystream using the PRGA logic for the blacklist."""
    if s_box is None:
        print("ERROR: Invalid S-box provided to rc4_prga_variant_blacklist.")
        return None

    s = list(s_box)  # Work on a copy
    prga_i = 0  # cryptoAccumulator1
    prga_j = 0  # cryptoAccumulator2
    keystream = bytearray()

    # PRGA loop from TlsInitialization_Internal (decrypting pBlacklistList)
    for _ in range(length):
        prga_i = (prga_i + 1) & 0xFF
        keystream_byte_val = s[prga_i]
        prga_j = (prga_j + keystream_byte_val) & 0xFF
        s[prga_i], s[prga_j] = s[prga_j], s[prga_i]  # Swap
        # In the C++ code, the XOR uses the value *before* the final swap
        # *((_BYTE *)&pBlacklistList.hash + loopIndex) = ... ^ v54; where v54 = *v53 (s[prga_i])
        keystream.append(keystream_byte_val)

    return bytes(keystream)


def fnv1a_aegis_hash(name_str):
    """Calculates the FNV-1a variant hash used by Aegis (lowercase)."""
    hash_val = 0x811C9DC5
    fnv_prime = 0x01000193

    for char in name_str.lower():  # Process lowercase version
        hash_val = hash_val ^ ord(char)
        hash_val = (hash_val * fnv_prime) & 0xFFFFFFFF
    return hash_val


# --- Decryption and Analysis ---


def decrypt_and_find_dll(key_27_bytes):
    """Decrypts the blacklist info and tries to find the DLL name."""

    ciphertext = bytes(
        [0x85, 0x8C, 0x9F, 0x52, 0xCC, 0x01, 0xFB, 0xE4, 0x29, 0xDC, 0x01, 0x01]
    )
    print(f"Ciphertext: {ciphertext.hex().upper()}")

    # 1. Perform KSA
    s_box = rc4_ksa_variant_blacklist(key_27_bytes)
    if not s_box:
        return

    # 2. Generate Keystream
    keystream = rc4_prga_variant_blacklist(s_box, 12)
    if not keystream:
        return
    print(f"Keystream : {keystream.hex().upper()}")

    # 3. Decrypt (XOR)
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    print(f"Plaintext : {plaintext.hex().upper()}")

    # 4. Unpack Plaintext Data
    try:
        # Bytes 0-3: Overall structure hash (ignored for name finding)
        _structure_hash = struct.unpack_from("<I", plaintext, 0)[0]
        # Bytes 4-7: DLL Name Hash
        dll_name_hash = struct.unpack_from("<I", plaintext, 4)[0]
        # Bytes 8-9: DLL Name Length
        dll_name_length = struct.unpack_from("<H", plaintext, 8)[0]
        # Byte 10: Wildcard Start
        wildcard_start = bool(plaintext[10])
        # Byte 11: Wildcard End
        wildcard_end = bool(plaintext[11])

        print("-" * 30)
        print(f"Decrypted Blacklist Entry:")
        print(f"  DLL Name Hash  : 0x{dll_name_hash:08X}")
        print(f"  DLL Name Length: {dll_name_length}")
        print(f"  Wildcard Start : {wildcard_start}")
        print(f"  Wildcard End   : {wildcard_end}")
        print("-" * 30)

    except struct.error as e:
        print(f"ERROR: Could not unpack plaintext data - {e}")
        return

    # 5. Find DLL Name by Hash and Length
    # List common analysis/debugging tools and DLLs
    common_dlls = [
        "ida64.dll",
        "ida.dll",
        "idaq64.exe",
        "ida.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
        "ollydbg.exe",
        "ImmunityDebugger.exe",
        "dbghelp.dll",
        "symsrv.dll",
        "ProcessHacker.exe",
        "tcpview.exe",
        "procmon.exe",
        "procexp.exe",
        "procexp64.exe",
        "autoruns.exe",
        "autorunsc.exe",
        "windbg.exe",
        "kd.exe",
        "cdb.exe",
        "reclass.exe",
        "reclass64.exe",
        "ReClass.NET.exe",
        "Scylla.exe",
        "Scylla_x64.exe",
        "Scylla_x86.exe",
        "dnSpy.exe",
        "ILSpy.exe",
        "Fiddler.exe",
        "Wireshark.exe",
        "kernel32.dll",  # Common system DLLs just in case
        "ntdll.dll",
        "user32.dll",
        "gdi32.dll",
        "ws2_32.dll",
        "advapi32.dll",
        "shell32.dll",
        "ole32.dll",
        "rpcrt4.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "dbgcore.dll",  # Debugging related
        "wow64cpu.dll",  # Emulation related
        "apisetschema.dll",  # API sets
        "ext-ms-win-*.dll",  # Placeholder for API sets with wildcards
        "api-ms-win-*.dll",  # Placeholder for API sets with wildcards
        "titanhide.sys",  # Common hiding driver
        "scylla_hide.sys",
        "vboxhook.dll",  # VirtualBox guest additions
        "vmtools.dll",  # VMware tools
        "prl_tools.dll",  # Parallels tools
        "sandboxiedll.dll",  # Sandboxie
        "snxhk.dll",  # Avast sandbox
        "cmd.exe",
        "powershell.exe",
    ]

    found = False
    print("Searching for matching DLL name...")
    for dll_name in common_dlls:
        # Handle potential wildcards (simple check for now)
        effective_length = len(dll_name)
        if dll_name_length > len(dll_name):
            # check if it's an exact match.
            calculated_hash = fnv1a_aegis_hash(dll_name)
            print(
                f"Checking '{dll_name}' (len={len(dll_name)}), hash=0x{calculated_hash:08X}..."
            )
            if calculated_hash != dll_name_hash:
                continue
            print(f"\n>>> MATCH FOUND: The blacklisted DLL is likely '{dll_name}' <<<")
            found = True
            break
            # Stop once exact match found
        if wildcard_start and wildcard_end:
            # If both wildcards, length check is less strict, but hash must match substring
            for window in sliding_window(dll_name, dll_name_length):
                calculated_hash = fnv1a_aegis_hash(window)
                print(
                    f"Checking window '{window}' (len={dll_name_length}) of '{dll_name}', hash=0x{calculated_hash:08X}..."
                )
                if calculated_hash == dll_name_hash:
                    print(
                        f"\n>>> MATCH FOUND: The blacklisted DLL is likely '{dll_name}' <<<"
                    )
                    found = True
                    break  # Stop once exact match found
        elif wildcard_start:
            # Check suffix
            if effective_length >= dll_name_length:
                substring = dll_name[-dll_name_length:]
                calculated_hash = fnv1a_aegis_hash(substring)
                print(
                    f"Checking suffix '{substring}' (len={dll_name_length}) of '{dll_name}', hash=0x{calculated_hash:08X}..."
                )
                if calculated_hash == dll_name_hash:
                    print(
                        f"\n>>> POTENTIAL MATCH (Suffix): '{dll_name}' ends with a string matching hash/length <<<"
                    )
                    found = True
                    # Don't break, might be a more specific match later
            continue  # Move to next DLL
        elif wildcard_end:
            # Check prefix
            if effective_length >= dll_name_length:
                substring = dll_name[:dll_name_length]
                calculated_hash = fnv1a_aegis_hash(substring)
                print(
                    f"Checking prefix '{substring}' (len={dll_name_length}) of '{dll_name}', hash=0x{calculated_hash:08X}..."
                )
                if calculated_hash == dll_name_hash:
                    print(
                        f"\n>>> POTENTIAL MATCH (Prefix): '{dll_name}' starts with a string matching hash/length <<<"
                    )
                    found = True
                    # Don't break
            continue  # Move to next DLL

    if not found:
        print("\n>>> No definite match found in the common list.")
        print("    Consider adding more DLL names or using a larger hash lookup list.")
        print(
            f"    Target Hash: 0x{dll_name_hash:08X}, Target Length: {dll_name_length}, Wildcards: Start={wildcard_start}, End={wildcard_end}"
        )


# --- Provide Key Data and Run ---

key_data_27_bytes = bytes(
    [
        174,
        51,
        28,
        108,
        163,
        12,
        15,
        140,
        213,
        165,
        255,
        79,
        17,
        42,
        239,
        84,
        15,
        127,
        234,
        235,
        35,
        9,
        115,
        67,
        242,
        183,
        132,
    ]
)

print(f"Using provided 27 key bytes: {key_data_27_bytes.hex().upper()}")
decrypt_and_find_dll(key_data_27_bytes)
