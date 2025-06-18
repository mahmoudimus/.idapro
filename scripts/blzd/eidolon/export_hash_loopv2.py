import functools
import pathlib

import pefile

import idautils

# List of DLLs dynamically loaded by BlackByteNT
modules = [
    "C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\advapi32.dll",
    "C:\\Windows\\System32\\user32.dll",
    "C:\\Windows\\System32\\shell32.dll",
    "C:\\Windows\\System32\\rstrtmgr.dll",
    "C:\\Windows\\System32\\netapi32.dll",
    "C:\\Windows\\System32\\shlwapi.dll",
    "C:\\Windows\\System32\\mpr.dll",
    "C:\\Windows\\System32\\psapi.dll",
    "C:\\Windows\\System32\\ole32.dll",
    "C:\\Windows\\System32\\OleAut32.dll",
    "C:\\Windows\\System32\\version.dll",
    "C:\\Windows\\System32\\Winhttp.dll",
    "C:\\Windows\\System32\\IPHLPAPI.dll",
    "C:\\Windows\\System32\\Ws2_32.dll",
    "C:\\Windows\\System32\\Dbghelp.dll",
]

# Returns the hash of the input string


def fnv1a_32(byte_sequence: bytes, lower=True) -> int:
    fnv_prime = 0x01000193
    h = 0x811C9DC5  # FNV1a offset basis
    data_length = len(byte_sequence)
    for byte_val in byte_sequence[:data_length]:
        # Lowercase the byte value itself
        final_byte = byte_val | 0x20 if lower else byte_val
        h = h ^ final_byte
        h = (h * fnv_prime) & 0xFFFFFFFF  # Keep it 32 bits
    return h


def fnv1a_64(byte_sequence: bytes, lower=True) -> int:
    fnv_prime = 0x100000001B3
    h = 0xCBF29CE484222325  # FNV1a offset basis
    data_length = len(byte_sequence)
    for byte_val in byte_sequence[:data_length]:
        # Lowercase the byte value itself
        final_byte = byte_val | 0x20 if lower else byte_val
        h = h ^ final_byte
        h = (h * fnv_prime) & 0xFFFFFFFFFFFFFFFF  # Keep it 64 bits
    return h


HASHES = {""}


def decode_name(byte_sequence: bytes, is_function=False) -> str:
    """
    Decode a byte sequence to a string. DLL names are UTF-16LE, functions are ASCII.
    """
    try:
        if is_function:
            return byte_sequence.decode("ascii", errors="ignore")
        else:
            # original_name = name_bytes[: len(name_bytes)].decode(
            #     "utf-16le", errors="ignore"
            # )
            return byte_sequence.decode("utf-16le", errors="ignore")
    except:
        return "[cannot decode name]"


set_of_64bit_hashes = {
    0xE14B18A7ACF9C443,
    0xA8F42DD374017C56,
    0xACD80F50F7102617,
    0xBB7BB9A74C2F14FB,
}

set_of_32bit_hashes = {
    0x0F42198D,  # kernel32.dll
    0xEFACCA19,  # ntdll.dll
    0x5D756A21,  # NtQueryInformationThread
    0xE049C205,  # NtClose
    0xC1BE16A6,  # NtProtectVirtualMemory
    0x97085561,  # NtSetInformationThread
    0x57F739B7,  # NtDuplicateObject
}


def print_hash_table(debug=True):
    """
    Print a hash table for all DLLs and functions in the database.
    """
    if not debug:
        return
    print("API Hash Lookup Table (32-bit and 64-bit):")
    print("-" * 80)
    for dll_path in map(pathlib.Path, modules):
        if not dll_path.exists():
            continue

        dll_name_utf16le = dll_path.name.encode("utf-16le")
        hash32 = fnv1a_32(dll_name_utf16le)
        hash64 = fnv1a_64(dll_name_utf16le)
        if hash64 in set_of_64bit_hashes:  # or hash32 in set_of_32bit_hashes:
            print(f"\n{dll_path.name} (utf16le):")
            print(f"  DLL Name: {decode_name(dll_name_utf16le)}")
            print(f"    32-bit: 0x{hash32:08X}")
            print(f"    64-bit: 0x{hash64:016X}")

        dll_name = dll_path.name.encode("utf-8")
        hash32 = fnv1a_32(dll_name)
        hash64 = fnv1a_64(dll_name)
        if hash64 in set_of_64bit_hashes:  # or hash32 in set_of_32bit_hashes:
            print(f"\n{dll_path.name}:")
            print(f"  DLL Name: {dll_name}")
            print(f"    32-bit: 0x{hash32:08X}")
            print(f"    64-bit: 0x{hash64:016X}")

        pe = pefile.PE(dll_path)
        # Get hash of all the exported functions in the DLL
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            func_bytes = exp.name.decode()
            func_name = exp.name
            hash32 = fnv1a_32(exp.name)
            hash64 = fnv1a_64(exp.name)
            if hash64 in set_of_64bit_hashes:  # or hash32 in set_of_32bit_hashes:
                print(f"\n{dll_path.name}:")
                print(f"  Function: {func_name}")
                print(f"    32-bit: 0x{hash32:08X}")
                print(f"    64-bit: 0x{hash64:016X}")


def generate_enum_output(enum_name, dll_name_algo, func_name_algo):
    out = pathlib.Path(idaapi.get_input_file_path()).parent / "api_hashes.h"
    with open(out, "w+", encoding="utf-8") as f:
        f.write(f"enum {enum_name}\n")
        f.write("{\n")
        # Print DLL entries with comments
        for dll_path in map(pathlib.Path, modules):
            if not dll_path.exists():
                continue
            dll_name_utf8 = dll_path.name.encode("utf-8")
            hash64 = dll_name_algo(dll_name_utf8)
            dll_name = dll_path.name.replace(".", "_")
            f.write(
                f"    {dll_name_algo.__name__}_{dll_name} = 0x{hash64:016X}, // {dll_path.name}\n"
            )
            f.write("\n")  # Blank line separator

            pe = pefile.PE(dll_path)
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not exp.name:
                    continue
                func_name = exp.name
                hash64 = func_name_algo(func_name)
                func_name_str = func_name.decode("ascii", errors="ignore").replace(
                    ".", "_"
                )
                f.write(
                    f"    {dll_name_algo.__name__}_{dll_name}_{func_name_str} = 0x{hash64:016X}, // {func_name_str}\n"
                )
        f.write("};\n")


generate_enum_output(
    "EidolonApiHashesFnv1a64 : unsigned __int64",
    fnv1a_64,
    functools.partial(fnv1a_64, lower=False),
)
