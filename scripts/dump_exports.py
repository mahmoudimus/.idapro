import argparse
import pefile
import re
from pathlib import Path

# --------------------------------------------------------------------------------------
# CONFIG: put full filesystem paths to the DLLs you care about here.
#
# You gave me module names + base addresses, but not file paths.
# On a normal Windows system most of these live in C:\Windows\System32.
#
# You can edit/extend this map as needed. If a dll isn't found, we'll skip it.
# --------------------------------------------------------------------------------------
DLL_CANDIDATES = [
    "advapi32.dll",
    "apphelp.dll",
    "AudioSes.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "cfgmgr32.dll",
    "clbcatq.dll",
    "combase.dll",
    "comctl32.dll",
    "crypt32.dll",
    "cryptbase.dll",
    "cryptnet.dll",
    "cryptsp.dll",
    "d3d11.dll",
    "D3D12.dll",
    "D3D12Core.dll",
    "D3DSCache.dll",
    "dcomp.dll",
    "devobj.dll",
    "dhcpcsvc.dll",
    "dhcpcsvc6.dll",
    "directxdatabasehelper.dll",
    "dnsapi.dll",
    "drvstore.dll",
    "dwmapi.dll",
    "DXCore.dll",
    "dxgi.dll",
    "FWPUCLNT.DLL",
    "gdi32.dll",
    "gdi32full.dll",
    "icm32.dll",
    "igd10um64xe.dll",
    "igdext64.dll",
    "igdgmm2_64.dll",
    "igdgmm64.dll",
    "imagehlp.dll",
    "imm32.dll",
    "IntelControlLib.dll",
    "IPHLPAPI.DLL",
    "kernel.appcore.dll",
    "kernel32.dll",
    "KernelBase.dll",
    "libxell.dll",
    "Microsoft.Internal.WarpPal.dll",
    "midimap.dll",
    "MMDevAPI.dll",
    "msacm32.dll",
    "msacm32.drv",
    "msasn1.dll",
    "mscms.dll",
    "msctf.dll",
    "msvcp140.dll",
    "msvcp_win.dll",
    "msvcrt.dll",
    "mswsock.dll",
    "ncrypt.dll",
    "ncryptsslp.dll",
    "nsi.dll",
    "ntasn1.dll",
    "ntdll.dll",
    "ntmarta.dll",
    "nvapi64.dll",
    "nvgpucomp64.dll",
    "nviewH64.dll",
    "nvldumdx.dll",
    "NvMemMapStoragex.dll",
    "NvMessageBus.dll",
    "nvppex.dll",
    "nvspcap64.dll",
    "nvwgf2umx.dll",
    "ole32.dll",
    "oleaut32.dll",
    "powrprof.dll",
    "profapi.dll",
    "propsys.dll",
    "rasadhlp.dll",
    "rdpendp.dll",
    "ResourcePolicyClient.dll",
    "rpcrt4.dll",
    "rsaenh.dll",
    "schannel.dll",
    "sechost.dll",
    "secur32.dll",
    "ServicingCommon.dll",
    "setupapi.dll",
    "sfc.dll",
    "sfc_os.dll",
    "SHCore.dll",
    "shell32.dll",
    "shlwapi.dll",
    "sspicli.dll",
    "TextInputFramework.dll",
    "ucrtbase.dll",
    "umpdc.dll",
    "user32.dll",
    "userenv.dll",
    "uxtheme.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "version.dll",
    "win32u.dll",
    "windows.storage.dll",
    "winhttp.dll",
    "winmm.dll",
    "winmmbase.dll",
    "winsta.dll",
    "wintrust.dll",
    "WinTypes.dll",
    "wldp.dll",
    "Wow_loader.dll",
    "ws2_32.dll",
    "wtsapi32.dll",
]

# common search roots (System32 first, then cwd)
SEARCH_DIRS = [
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),   # in case of WOW32 modules
    Path.cwd(),                     # current working dir for vendor DLLs like Intel/NVIDIA
]

# --------------------------------------------------------------------------------------
# Utility: guess parameter count from stdcall decoration
# e.g. "RegOpenKeyExW@24" -> 24 bytes / 4 = 6 params
# --------------------------------------------------------------------------------------
STD_CALL_RE = re.compile(r"^(?P<name>[^@]+)@(?P<bits>\d+)$")

def infer_param_count(export_name: str) -> tuple[str, str]:
    """
    Returns (clean_name, param_count_str)
    param_count_str is '?' if we can't infer.
    """
    m = STD_CALL_RE.match(export_name)
    if m:
        clean = m.group("name")
        try:
            total_bytes = int(m.group("bits"))
            # Windows stdcall typically pushes 4-byte args.
            # So arg_count = total_bytes / 4.
            # We'll integer-divide, and if it's not cleanly divisible by 4,
            # we'll still show '/' to make it obvious.
            if total_bytes % 4 == 0:
                arg_count = total_bytes // 4
                return clean, str(arg_count)
            else:
                return clean, f"{total_bytes}/4"
        except ValueError:
            pass
    # no decoration → unknown without symbols
    return export_name, "?"


# --------------------------------------------------------------------------------------
# Utility: resolve a DLL name to an on-disk path using SEARCH_DIRS
# --------------------------------------------------------------------------------------
def find_dll_path(dll_name: str, debug: bool = False) -> Path | None:
    # try exact
    for root in SEARCH_DIRS:
        candidate = root / dll_name
        if candidate.is_file():
            if debug:
                print(f"[DEBUG] Found DLL {dll_name} at {candidate}")
            return candidate

    # sometimes filenames come in with weird casing; try case-insensitive search in each dir
    lower = dll_name.lower()
    for root in SEARCH_DIRS:
        if not root.is_dir():
            continue
        try:
            for f in root.iterdir():
                if f.name.lower() == lower and f.is_file():
                    if debug:
                        print(f"[DEBUG] Found DLL {dll_name} at {f} (case-insensitive match)")
                    return f
        except PermissionError:
            # skip dirs we can't read
            if debug:
                print(f"[DEBUG] Permission denied accessing {root}")
            continue

    if debug:
        print(f"[DEBUG] DLL not found: {dll_name}")
    return None


# --------------------------------------------------------------------------------------
# Main: iterate DLLs, dump exports
# --------------------------------------------------------------------------------------
def dump_exports(dll_list: list[str], output_file: Path, debug: bool = False) -> None:
    with output_file.open('w', encoding='utf-8') as f:
        for dll_name in dll_list:
            path = find_dll_path(dll_name, debug)
            if not path:
                # skip quietly if not present on this machine
                continue

            try:
                pe = pefile.PE(str(path), fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
                )
            except pefile.PEFormatError:
                if debug:
                    print(f"[DEBUG] PE format error for {dll_name} at {path}")
                continue

            # Load export directory
            if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                if debug:
                    print(f"[DEBUG] No export directory for {dll_name} at {path}")
                continue

            # dll "module name" for output: strip extension, lowercase like your example
            mod_no_ext = path.stem.lower()

            if debug:
                print(f"[DEBUG] Processing exports for {dll_name} ({len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} total symbols)")

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not exp.name:
                    # sometimes there are ordinal-only exports
                    if debug:
                        print(f"[DEBUG] Ordinal-only export in {dll_name} (ordinal: {exp.ordinal})")
                    continue

                raw_name = exp.name.decode(errors="ignore")
                clean_name, param_count = infer_param_count(raw_name)

                # write in requested format
                f.write(f"{mod_no_ext};{clean_name};{param_count}\n")

            if debug:
                print(f"[DEBUG] Successfully processed {dll_name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dump exports from system DLLs to a file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Write to exports.txt in current directory
  %(prog)s -o output.txt                # Write to output.txt in current directory
  %(prog)s --output C:/path/to/file.txt # Write to specific file path
  %(prog)s --output C:/path/to/directory # Write to directory/exports.txt
  %(prog)s -d                           # Enable debug mode to see skipped DLLs
  %(prog)s --debug -o exports.txt       # Debug mode with custom output file
        """
    )

    parser.add_argument(
        "-o", "--output",
        default="exports.txt",
        help="Output file path (default: exports.txt)"
    )

    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug mode to show detailed information about skipped DLLs and processing"
    )

    args = parser.parse_args()

    # Use pathlib for output file path
    output_path = Path(args.output)

    # If output is a directory, create a default filename
    if output_path.is_dir():
        output_path = output_path / "exports.txt"

    # Ensure the directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.debug:
        print(f"[DEBUG] Starting export dump to {output_path}")
        print(f"[DEBUG] Processing {len(DLL_CANDIDATES)} DLL candidates...")

    # Call with Path object
    dump_exports(DLL_CANDIDATES, output_path, args.debug)

    if args.debug:
        print(f"[DEBUG] Export dump completed")


if __name__ == "__main__":
    main()