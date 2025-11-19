import functools
import logging
import pathlib
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import pefile

import idaapi
import idautils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    "F:\\Blizzard\\Wow\\_retail_\\wow_loader.dll",
    "F:\\Blizzard\\Wow\\_retail_\\Wow_loader.dll",
    "F:\\Blizzard\\Wow\\_beta_\\WowB_loader.dll",
    "F:\\Blizzard\\Wow\\_ptr_\\WowT_loader.dll",
    "F:\\Blizzard\\Wow\\_xptr_\\WowT_loader.dll",
    # "F:\\Blizzard\\Wow\\_classic_\\WowClassic_loader.dll",
    # "F:\\Blizzard\\Wow\\_retail_\\WowClassicT_loader.dll",
    # "F:\\Blizzard\\Wow\\_retail_\\WowClassicB_loader.dll",
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


@dataclass
class Dll:
    """
    Represents a DLL with its name, optional path, and exports.
    Can be created from a file path or from a configuration dictionary.
    """

    name: str
    path: Optional[pathlib.Path] = None
    exports: Optional[List[str]] = None

    @classmethod
    def from_path(cls, dll_path: pathlib.Path) -> "Dll":
        """
        Create a Dll instance from a file path.
        Extracts exports from the PE file.
        """
        if not dll_path.exists():
            logger.warning("DLL path does not exist: %s", dll_path)
            return cls(name=dll_path.name, path=dll_path, exports=[])

        exports = []
        try:
            pe = pefile.PE(dll_path)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode("ascii", errors="ignore"))
        except Exception as e:
            logger.error("Failed to parse PE file %s: %s", dll_path, e)

        return cls(name=dll_path.name, path=dll_path, exports=exports)

    @classmethod
    def from_config(cls, config: dict) -> "Dll":
        """
        Create a Dll instance from a configuration dictionary.
        Expected format: {"name": "dll_name.dll", "exports": ["export1", "export2"]}
        """
        name = config.get("name", "")
        exports = config.get("exports", [])
        return cls(name=name, path=None, exports=exports)

    def get_dll_hash(
        self, algo: Callable[[bytes], int], encoding: str = "utf-8"
    ) -> int:
        """
        Get the hash of the DLL name using the specified algorithm and encoding.
        """
        name_bytes = self.name.encode(encoding)
        return algo(name_bytes)

    def get_export_hashes(
        self, algo: Callable[[bytes], int], encoding: str = "ascii"
    ) -> List[Tuple[str, int]]:
        """
        Get a list of (export_name, hash) tuples for all exports.
        """
        if not self.exports:
            return []

        result = []
        for export_name in self.exports:
            export_bytes = export_name.encode(encoding)
            hash_value = algo(export_bytes)
            result.append((export_name, hash_value))
        return result

    def get_all_hashes(
        self,
        algo: Callable[[bytes], int],
        dll_name_encoding: str = "utf-8",
        export_encoding: str = "utf-8",
    ) -> Tuple[int, List[Tuple[str, int]]]:
        """
        Get both DLL name hash and all export hashes using the same algorithm.
        Returns a tuple of (dll_name_hash, list of (export_name, hash) tuples).
        """
        dll_hash = self.get_dll_hash(algo, dll_name_encoding)
        export_hashes = self.get_export_hashes(algo, export_encoding)
        return (dll_hash, export_hashes)


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


def get_algo_name(algo: Callable[[bytes], int]) -> str:
    """
    Get the name of an algorithm function, handling both regular functions and functools.partial.
    """
    if isinstance(algo, functools.partial):
        return algo.func.__name__
    return algo.__name__


def generate_dll_name_hashes(
    dlls: List[Dll],
    enum_name: str,
    output_filename: str,
    dll_name_algo: Callable[[bytes], int],
    dll_name_encoding: str = "utf-8",
):
    """
    Generate an enum file containing DLL name hashes only.
    """
    out = pathlib.Path(idaapi.get_input_file_path()).parent / output_filename
    with open(out, "w+", encoding="utf-8") as f:
        f.write(f"enum {enum_name}\n")
        f.write("{\n")
        for dll in dlls:
            hash_value = dll.get_dll_hash(dll_name_algo, dll_name_encoding)
            dll_name_safe = dll.name.replace(".", "_")
            algo_name = get_algo_name(dll_name_algo)
            f.write(
                f"    {algo_name}_{dll_name_safe} = 0x{hash_value:016X}, // {dll.name}\n"
            )
        f.write("};\n")
    logger.info("Generated DLL name hashes to %s", out)


def generate_export_hashes(
    dlls: List[Dll],
    enum_name: str,
    output_filename: str,
    dll_name_algo: Callable[[bytes], int],
    func_name_algo: Callable[[bytes], int],
    dll_name_encoding: str = "utf-8",
    func_name_encoding: str = "ascii",
):
    """
    Generate an enum file containing export function hashes only.
    DLL names are hashed using dll_name_algo and dll_name_encoding for enum naming.
    """
    out = pathlib.Path(idaapi.get_input_file_path()).parent / output_filename
    with open(out, "w+", encoding="utf-8") as f:
        f.write(f"enum {enum_name}\n")
        f.write("{\n")
        for dll in dlls:
            if not dll.exports:
                continue
            dll_name_safe = dll.name.replace(".", "_")
            dll_algo_name = get_algo_name(dll_name_algo)
            export_hashes = dll.get_export_hashes(func_name_algo, func_name_encoding)
            for export_name, hash_value in export_hashes:
                export_name_safe = export_name.replace(".", "_")
                f.write(
                    f"    {dll_algo_name}_{dll_name_safe}_{export_name_safe} = 0x{hash_value:016X}, // {export_name}\n"
                )
        f.write("};\n")
    logger.info("Generated export hashes to %s", out)


def generate_all_hashes(
    dlls: List[Dll],
    enum_name: str,
    output_filename: str,
    algo: Callable[[bytes], int],
    dll_name_encoding: str = "utf-8",
    export_encoding: str = "utf-8",
):
    """
    Generate an enum file containing both DLL name hashes and export hashes
    using the same algorithm. DLL name entries come first, followed by export entries.
    """
    out = pathlib.Path(idaapi.get_input_file_path()).parent / output_filename
    algo_name = get_algo_name(algo)
    with open(out, "w+", encoding="utf-8") as f:
        f.write(f"enum {enum_name}\n")
        f.write("{\n")
        for dll in dlls:
            dll_hash, export_hashes = dll.get_all_hashes(
                algo, dll_name_encoding, export_encoding
            )
            dll_name_safe = dll.name.replace(".", "_")
            # Write DLL name hash
            f.write(
                f"    {algo_name}_{dll_name_safe} = 0x{dll_hash:016X}, // {dll.name}\n"
            )
            # Write export hashes
            for export_name, hash_value in export_hashes:
                export_name_safe = export_name.replace(".", "_")
                f.write(
                    f"    {algo_name}_{dll_name_safe}_{export_name_safe} = 0x{hash_value:016X}, // {export_name}\n"
                )
        f.write("};\n")
    logger.info("Generated all hashes to %s", out)


# Example: Generate DLL name hashes
# dlls_from_paths = [Dll.from_path(pathlib.Path(p)) for p in modules]
# generate_dll_name_hashes(
#     dlls=dlls_from_paths,
#     enum_name="EidolonApiHashesFnv1a64 : unsigned __int64",
#     output_filename="dll_name_hashes.h",
#     dll_name_algo=fnv1a_64,
#     dll_name_encoding="utf-8",
# )

# Example: Generate export hashes from config
# custom_dlls_config = {
#     "wow_loader": {
#         "name": "wow_loader.dll",
#         "exports": ["eidolon_run", "g_warden_aegis_crash_callback_export"],
#     },
#     "Wow_loader": {
#         "name": "Wow_loader.dll",
#         "exports": ["eidolon_run", "g_warden_aegis_crash_callback_export"],
#     },
# }
# dlls_from_config = [Dll.from_config(config) for config in custom_dlls_config.values()]
# generate_export_hashes(
#     dlls=dlls_from_config,
#     enum_name="AegisApiHashesFnv1a32 : unsigned __int32",
#     output_filename="export_hashes.h",
#     dll_name_algo=fnv1a_32,
#     func_name_algo=fnv1a_32,
#     dll_name_encoding="utf-16le",
#     func_name_encoding="ascii",
# )

# Current usage: Generate DLL name hashes (Eidolon)
dlls_from_paths = [Dll.from_path(pathlib.Path(p)) for p in modules]
# generate_dll_name_hashes(
#     dlls=dlls_from_paths,
#     enum_name="EidolonApiHashesFnv1a64 : unsigned __int64",
#     output_filename="dll_name_hashes.h",
#     dll_name_algo=functools.partial(fnv1a_64, lower=False),
#     dll_name_encoding="utf-8",
# )

# Generate export hashes (Aegis)
# generate_export_hashes(
#     dlls=dlls_from_paths,
#     enum_name="AegisApiHashesFnv1a32 : unsigned __int32",
#     output_filename="export_hashes.h",
#     dll_name_algo=fnv1a_32,
#     func_name_algo=fnv1a_32,
#     dll_name_encoding="utf-16le",
#     func_name_encoding="ascii",
# )

# Example: Generate both DLL name and export hashes using the same algorithm
generate_all_hashes(
    dlls=dlls_from_paths,
    enum_name="EidolonApiHashesFnv1a64 : unsigned __int64",
    output_filename="all_hashes.h",
    algo=functools.partial(fnv1a_64, lower=False),
    dll_name_encoding="utf-8",
    export_encoding="utf-8",
)
