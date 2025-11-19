#!/usr/bin/env python3
"""
Backup a binary file to a versioned directory.

python.exe backup_binary_version.py backup_dir executable_path1 dll_path2 ...
"""
import argparse
import glob
import shutil
from enum import Enum
from pathlib import Path

import win32api


class OS(Enum):
    WIN = "win"
    LINUX = "linux"
    MAC = "mac"  # not implemented yet


def get_file_version_win(file_path):
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        info = win32api.GetFileVersionInfo(str(file_path), "\\")
        ms = info["FileVersionMS"]
        ls = info["FileVersionLS"]
        version = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
        return version
    except Exception as e:
        raise RuntimeError(f"Error retrieving file version: {e}")


def backup_binary_win(version, backup_dir, executable_path):
    backup_dir = Path(backup_dir) / version
    backup_dir.mkdir(parents=True, exist_ok=True)
    executable_path = Path(executable_path)

    if not executable_path.exists():
        raise FileNotFoundError(f"Executable not found: {executable_path}")

    backup_path = backup_dir / executable_path.name
    shutil.copy2(executable_path, backup_path)
    print(f"Backup created at: {backup_path}")


def expand_glob_patterns(file_paths):
    """Expand glob patterns in file paths and return a list of actual files."""
    expanded_files = []
    for file_path in file_paths:
        # Check if the path contains glob patterns
        if "*" in file_path or "?" in file_path:
            # Use glob to find matching files
            matched_files = glob.glob(file_path)
            if not matched_files:
                print(f"Warning: No files found matching pattern: {file_path}")
            expanded_files.extend(matched_files)
        else:
            # No glob pattern, add as is
            expanded_files.append(file_path)
    return expanded_files


def backup_binary(os_type, backup_dir, executable_paths):
    # Expand any glob patterns in the file paths
    all_files = expand_glob_patterns(executable_paths)

    if not all_files:
        print("No files found to backup.")
        return

    # Get version from the first file (assuming all files have the same version)
    first_file = all_files[0]
    if os_type == OS.WIN:
        version = get_file_version_win(first_file)

        # Backup all files to the same version directory
        for file_path in all_files:
            backup_binary_win(version, backup_dir, file_path)
    else:
        raise NotImplementedError(f"Backup for {os_type.value} is not implemented yet.")


def main():
    parser = argparse.ArgumentParser(
        description="Backup binaries to a versioned directory."
    )
    parser.add_argument(
        "backup_directory",
        type=str,
        help="Directory where the backup should be stored.",
    )
    parser.add_argument(
        "executable_paths",
        type=str,
        nargs="+",
        help="Path(s) to the executable file(s). Supports glob patterns like '*.dll'.",
    )
    parser.add_argument(
        "--os",
        type=OS,
        choices=list(OS),
        default=OS.WIN,
        help="Operating system, default is 'win'.",
    )

    args = parser.parse_args()

    try:
        backup_binary(args.os, args.backup_directory, args.executable_paths)
    except (FileNotFoundError, RuntimeError, NotImplementedError) as e:
        print(e)


if __name__ == "__main__":
    main()
