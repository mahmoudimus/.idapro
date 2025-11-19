#!/usr/bin/env python3
"""
Create an ida-plugin.json file for an IDA Pro plugin folder or .py file.
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

VALID_CATEGORIES = [
    "disassembly-and-processor-modules",
    "file-parsers-and-loaders",
    "decompilation",
    "debugging-and-tracing",
    "deobfuscation",
    "collaboration-and-productivity",
    "integration-with-third-parties-interoperability",
    "api-scripting-and-automation",
    "ui-ux-and-visualization",
    "malware-analysis",
    "vulnerability-research-and-exploit-development",
    "other",
]


def find_corresponding_folder(plugin_file):
    """Find a corresponding folder for a plugin file (.py or DLL).

    Checks for folders that match the filename (with or without _plugin suffix).
    Examples:
    - pyclassinformer_plugin.py -> pyclassinformer/
    - idaclu.py -> idaclu/
    - aida.dll -> aida/
    - bindiff8_ida64.dll -> bindiff/ (if exists)
    """
    file_path = Path(plugin_file)
    file_stem = file_path.stem
    file_dir = file_path.parent

    # For DLL files, try to extract base name
    base_name = file_stem
    if file_path.suffix.lower() in [".dll", ".dylib", ".so"]:
        # Try to extract base name by removing common suffixes
        for suffix in ["8_ida64", "_ida64", "64", "_64"]:
            if file_stem.endswith(suffix):
                base_name = file_stem[: -len(suffix)]
                break

    # Try removing _plugin suffix
    if base_name.endswith("_plugin"):
        base_name = base_name[:-7]  # Remove "_plugin"
        folder = file_dir / base_name
        if folder.exists() and folder.is_dir():
            return folder

    # Try exact match with base name
    folder = file_dir / base_name
    if folder.exists() and folder.is_dir():
        return folder

    # Try case-insensitive match
    for item in file_dir.iterdir():
        if item.is_dir() and item.name.lower() == base_name.lower():
            return item

    return None


def find_plugin_file(folder_path):
    """Find the .py plugin file in the folder, or DLL if no .py file exists."""
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"Folder does not exist: {folder_path}")

    # Look for .py files in the folder
    py_files = list(folder.glob("*.py"))

    if py_files:
        # If multiple .py files, prefer one that matches the folder name or is a common plugin name
        folder_name = folder.name.lower()
        for py_file in py_files:
            if py_file.stem.lower() == folder_name:
                return py_file
        # Otherwise, use the first .py file found
        return py_files[0]

    # If no .py files, look for DLL files
    dll_files = (
        list(folder.glob("*.dll"))
        + list(folder.glob("*.dylib"))
        + list(folder.glob("*.so"))
    )
    if dll_files:
        # Prefer one that matches the folder name
        folder_name = folder.name.lower()
        for dll_file in dll_files:
            if dll_file.stem.lower().startswith(folder_name):
                return dll_file
        # Otherwise, use the first DLL found
        return dll_files[0]

    raise ValueError(f"No .py or DLL files found in {folder_path}")


def find_related_files(py_file):
    """Find files and folders related to a .py plugin file.

    Returns a list of paths that should be moved together with the plugin.
    """
    py_path = Path(py_file)
    py_stem = py_path.stem
    py_dir = py_path.parent

    related = []

    # Determine base name (without _plugin suffix)
    if py_stem.endswith("_plugin"):
        base_name = py_stem[:-7]
    else:
        base_name = py_stem

    # Look for sibling folders that match the plugin name
    folder = py_dir / base_name
    if folder.exists() and folder.is_dir():
        related.append(folder)

    # Look for DLL and other binary files that match the plugin name
    # Examples: aida.dll, bindiff8_ida64.dll, bindiff8_ida64.dylib, bindiff8_ida64.so
    binary_extensions = [".dll", ".dylib", ".so", ".pyd"]
    for ext in binary_extensions:
        # Exact match: base_name.dll
        exact_match = py_dir / f"{base_name}{ext}"
        if exact_match.exists() and exact_match.is_file():
            related.append(exact_match)

        # Prefix match: base_name*.dll (e.g., bindiff8_ida64.dll)
        for item in py_dir.glob(f"{base_name}*{ext}"):
            if item.is_file() and item not in related:
                related.append(item)

    # Look for other related files (config files, etc.)
    # Common patterns: .cfg, .json, README.md, LICENSE, etc.
    for pattern in ["*.cfg", "*.json", "README*", "LICENSE*", "*.md"]:
        for item in py_dir.glob(pattern):
            if item.name.startswith(py_stem) or item.name.startswith(base_name):
                if item not in related:
                    related.append(item)

    return related


def organize_plugin(input_path, plugin_name=None):
    """Organize a plugin by creating a folder and moving related files.

    Returns:
        tuple: (target_folder, plugin_file, plugin_name)
    """
    path = Path(input_path)

    if not path.exists():
        raise ValueError(f"Path does not exist: {input_path}")

    # Determine plugin name
    if path.is_file():
        if path.suffix.lower() == ".py":
            if plugin_name is None:
                # Remove _plugin suffix if present for folder name
                stem = path.stem
                if stem.endswith("_plugin"):
                    plugin_name = stem[:-7]  # Remove "_plugin"
                else:
                    plugin_name = stem
            plugin_file = path
            parent_dir = path.parent
        elif path.suffix.lower() in [".dll", ".dylib", ".so"]:
            # DLL file - use stem as plugin name
            if plugin_name is None:
                # Extract base name (e.g., bindiff8_ida64 -> bindiff)
                stem = path.stem
                # Try to extract base name by removing common suffixes
                for suffix in ["8_ida64", "_ida64", "64", "_64"]:
                    if stem.endswith(suffix):
                        plugin_name = stem[: -len(suffix)]
                        break
                else:
                    plugin_name = stem
            plugin_file = path
            parent_dir = path.parent
        else:
            raise ValueError(f"File must be .py, .dll, .dylib, or .so: {input_path}")
    elif path.is_dir():
        if plugin_name is None:
            plugin_name = path.name
        plugin_file = find_plugin_file(path)
        parent_dir = path.parent
        # If the folder itself is the plugin, we might not need to move it
        if path.name.lower() == plugin_name.lower():
            # For DLL files, entry point is the filename with extension; for .py, it's the filename with .py extension
            if plugin_file.suffix.lower() in [".dll", ".dylib", ".so"]:
                entry_point = plugin_file.name
            elif plugin_file.suffix.lower() == ".py":
                entry_point = plugin_file.name
            else:
                entry_point = plugin_file.stem
            return path, plugin_file, entry_point
    else:
        raise ValueError(f"Path must be a folder or .py file: {input_path}")

    # Create target folder
    target_folder = parent_dir / plugin_name

    # Check if target folder already exists
    if target_folder.exists() and target_folder.is_dir():
        # Check if it already has ida-plugin.json
        existing_json = target_folder / "ida-plugin.json"
        if existing_json.exists():
            # Folder already has JSON, proceed normally - just move the plugin file
            print(
                f"Folder {target_folder.name}/ already exists with ida-plugin.json, using it"
            )
        else:
            # Folder exists but no JSON - move it into a subfolder
            subfolder = target_folder / plugin_name
            subfolder.mkdir(parents=True, exist_ok=True)
            # Move all contents of existing folder into subfolder
            for item in target_folder.iterdir():
                if item != subfolder:  # Don't move the subfolder into itself
                    target_item = subfolder / item.name
                    if not target_item.exists():
                        shutil.move(str(item), str(target_item))
                        if item.is_dir():
                            print(
                                f"Moved {item.name}/ -> {target_folder.name}/{subfolder.name}/"
                            )
                        else:
                            print(
                                f"Moved {item.name} -> {target_folder.name}/{subfolder.name}/"
                            )
            print(
                f"Moved existing {target_folder.name}/ contents into {target_folder.name}/{subfolder.name}/"
            )
    else:
        # Target folder doesn't exist, create it
        target_folder.mkdir(exist_ok=True)

    # Move the plugin file if it's not already in the target folder
    if plugin_file.parent != target_folder:
        target_plugin_file = target_folder / plugin_file.name
        if not target_plugin_file.exists():
            shutil.move(str(plugin_file), str(target_plugin_file))
            print(f"Moved {plugin_file.name} -> {target_folder.name}/")
        plugin_file = target_plugin_file

    # Find and move related files/folders
    if path.is_file():
        # For .py files, use find_related_files
        if path.suffix.lower() == ".py":
            related = find_related_files(path)
        else:
            # For DLL files, find related DLLs and folders
            related = []
            base_name = plugin_name
            # Find other DLL files with same base name
            for ext in [".dll", ".dylib", ".so", ".pyd"]:
                for item in parent_dir.glob(f"{base_name}*{ext}"):
                    if item != path and item.is_file() and item not in related:
                        related.append(item)
            # Find matching folder (but exclude target_folder if it's the same)
            folder = parent_dir / base_name
            if folder.exists() and folder.is_dir() and folder != target_folder:
                related.append(folder)

        for item in related:
            if (
                item.exists() and item != target_folder
            ):  # Don't try to move target folder into itself
                target = target_folder / item.name
                if not target.exists():
                    if item.is_dir():
                        shutil.move(str(item), str(target))
                        print(f"Moved folder {item.name}/ -> {target_folder.name}/")
                    else:
                        shutil.move(str(item), str(target))
                        print(f"Moved {item.name} -> {target_folder.name}/")

    # Return the entry point name
    # For DLL files, use the filename with extension; for .py files, use filename with .py extension
    if plugin_file.suffix.lower() in [".dll", ".dylib", ".so"]:
        entry_point_name = plugin_file.name
    elif plugin_file.suffix.lower() == ".py":
        entry_point_name = plugin_file.name
    else:
        entry_point_name = plugin_file.stem
    return target_folder, plugin_file, entry_point_name


def resolve_plugin_path(input_path, organize=False, plugin_name=None):
    """Resolve the plugin path to determine if it's a folder or self-contained .py file.

    Args:
        input_path: Path to plugin file or folder
        organize: If True, organize files into a folder structure
        plugin_name: Optional plugin name (used when organizing)

    Returns:
        tuple: (target_folder, plugin_file, plugin_name)
            - target_folder: Where to create the ida-plugin.json
            - plugin_file: The .py plugin file
            - plugin_name: The plugin name (filename without extension)
    """
    if organize:
        return organize_plugin(input_path, plugin_name)

    path = Path(input_path)

    if not path.exists():
        raise ValueError(f"Path does not exist: {input_path}")

    # If it's a .py or DLL file
    if path.is_file() and path.suffix.lower() in [".py", ".dll", ".dylib", ".so"]:
        # Check if there's a corresponding folder
        folder = find_corresponding_folder(path)
        if folder:
            # Use the folder as target, and the file as the plugin file
            # (whether it's inside the folder or a sibling)
            # For DLL files, entry point is the filename with extension; for .py, it's the filename with .py extension
            if path.suffix.lower() in [".dll", ".dylib", ".so"]:
                entry_point = path.name
            elif path.suffix.lower() == ".py":
                entry_point = path.name
            else:
                entry_point = path.stem
            return folder, path, entry_point
        else:
            # Self-contained file - create JSON in same directory
            # For DLL files, entry point is the filename with extension; for .py, it's the filename with .py extension
            if path.suffix.lower() in [".dll", ".dylib", ".so"]:
                entry_point = path.name
            elif path.suffix.lower() == ".py":
                entry_point = path.name
            else:
                entry_point = path.stem
            return path.parent, path, entry_point

    # If it's a folder
    elif path.is_dir():
        plugin_file = find_plugin_file(path)
        # For DLL files, entry point is the filename with extension; for .py, it's the filename with .py extension
        if plugin_file.suffix.lower() in [".dll", ".dylib", ".so"]:
            entry_point = plugin_file.name
        elif plugin_file.suffix.lower() == ".py":
            entry_point = plugin_file.name
        else:
            entry_point = plugin_file.stem
        return path, plugin_file, entry_point

    else:
        raise ValueError(
            f"Path must be a folder, .py file, or DLL file (.dll, .dylib, .so): {input_path}"
        )


def create_ida_plugin_json(input_path, organize=False, **kwargs):
    """Create an ida-plugin.json file for a plugin folder or .py file."""
    plugin_name_override = kwargs.get("name")
    target_folder, plugin_file, plugin_name = resolve_plugin_path(
        input_path, organize=organize, plugin_name=plugin_name_override
    )

    # Build the JSON structure
    plugin_data = {
        "IDAMetadataDescriptorVersion": 1,
        "plugin": {
            "name": kwargs.get("name", plugin_name),
            "entryPoint": kwargs.get("entryPoint", plugin_name),
            "categories": kwargs.get("categories", ["other"]),
            "idaVersions": kwargs.get("idaVersions", ">=9.0"),
            "description": kwargs.get("description", "A plugin for IDA Pro"),
            "version": kwargs.get("version", "0.1.0"),
        },
    }

    # Add optional fields if provided
    if kwargs.get("logoPath"):
        plugin_data["plugin"]["logoPath"] = kwargs["logoPath"]

    # Write the JSON file
    output_path = target_folder / "ida-plugin.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(plugin_data, f, indent=4)

    print(f"Created {output_path}")
    return output_path


def parse_categories(categories_str):
    """Parse comma-separated categories string into a list and validate against valid categories.

    Args:
        categories_str: Comma-separated string of category names

    Returns:
        List of validated category names

    Raises:
        ValueError: If any category is not in the valid categories list
    """
    if not categories_str:
        return None
    categories = [cat.strip() for cat in categories_str.split(",")]
    invalid = [cat for cat in categories if cat not in VALID_CATEGORIES]
    if invalid:
        raise ValueError(
            f"Invalid categories: {', '.join(invalid)}\n"
            f"Valid categories are: {', '.join(VALID_CATEGORIES)}"
        )
    return categories


def main():
    parser = argparse.ArgumentParser(
        description="Create an ida-plugin.json file for an IDA Pro plugin folder, .py file, or DLL file",
        epilog="""
Examples:
  # Create JSON for a self-contained .py plugin
  %(prog)s plugins/notepad-md.py

  # Create JSON for a .py plugin with a corresponding folder
  %(prog)s plugins/idaclu.py
  %(prog)s plugins/pyclassinformer_plugin.py

  # Create JSON for a DLL plugin
  %(prog)s plugins/aida.dll
  %(prog)s plugins/bindiff8_ida64.dll

  # Create JSON for an existing plugin folder
  %(prog)s plugins/xray

  # Process multiple files at once
  %(prog)s plugins/plugin1.py plugins/plugin2.py plugins/plugin3.dll

  # Organize a plugin: create folder and move related files
  %(prog)s plugins/myplugin.py --organize
  %(prog)s plugins/aida.dll --organize

  # Organize multiple plugins at once
  %(prog)s --organize plugins/diaphora_local.py plugins/diaphora_plugin.py

  # Customize plugin metadata
  %(prog)s plugins/myplugin.py --name "My Plugin" --description "Does something" --version "1.0.0"

  # Set custom categories
  %(prog)s plugins/myplugin.py --categories "decompilation,ui-ux-and-visualization"

  # Set IDA version requirement
  %(prog)s plugins/myplugin.py --ida-versions ">=9.2"

  # Full example with all options
  %(prog)s plugins/myplugin.py --organize \\
      --name "My Plugin" \\
      --description "A useful plugin" \\
      --version "1.0.0" \\
      --categories "decompilation,deobfuscation" \\
      --ida-versions ">=9.0" \\
      --logo-path "logo.png"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "paths",
        nargs="+",
        type=str,
        help="Path(s) to plugin folder(s), .py file(s), or DLL file(s) (.dll, .dylib, .so). Can specify multiple paths.",
    )

    parser.add_argument(
        "--name",
        type=str,
        help="Plugin name (defaults to .py/.dll filename without extension, or folder name)",
    )

    parser.add_argument(
        "--entry-point",
        dest="entryPoint",
        type=str,
        help="Plugin entry point (defaults to .py filename without extension, or DLL filename with extension)",
    )

    parser.add_argument(
        "--categories",
        type=str,
        help="Comma-separated list of categories. Valid categories: "
        "disassembly-and-processor-modules, file-parsers-and-loaders, decompilation, "
        "debugging-and-tracing, deobfuscation, collaboration-and-productivity, "
        "integration-with-third-parties-interoperability, api-scripting-and-automation, "
        "ui-ux-and-visualization, malware-analysis, "
        "vulnerability-research-and-exploit-development, other. "
        "(default: decompilation,deobfuscation,malware-analysis)",
    )

    parser.add_argument(
        "--ida-versions",
        dest="idaVersions",
        type=str,
        default=">=9.0",
        help="IDA Pro version requirement (default: >=9.0)",
    )

    parser.add_argument(
        "--description", type=str, default="", help="Plugin description"
    )

    parser.add_argument("--version", type=str, default="", help="Plugin version")

    parser.add_argument(
        "--logo-path",
        dest="logoPath",
        type=str,
        help="Path to plugin logo (relative to plugin folder)",
    )

    parser.add_argument(
        "--organize",
        action="store_true",
        help="Create a folder with the plugin name and move related files into it. "
        "For .py files: moves the .py file and related folders/DLLs. "
        "For DLL files: moves the DLL and related DLLs (.dll, .dylib, .so) with the same base name.",
    )

    args = parser.parse_args()

    # Convert args to dict, filtering out None values
    kwargs = {
        "name": args.name,
        "entryPoint": args.entryPoint,
        "categories": parse_categories(args.categories),
        "idaVersions": args.idaVersions,
        "description": args.description,
        "version": args.version,
        "logoPath": args.logoPath,
    }

    # Remove None values
    kwargs = {k: v for k, v in kwargs.items() if v is not None}

    # Process each path
    errors = []
    for path in args.paths:
        try:
            create_ida_plugin_json(path, organize=args.organize, **kwargs)
        except Exception as e:
            error_msg = f"Error processing {path}: {e}"
            print(error_msg, file=sys.stderr)
            errors.append(error_msg)

    # Exit with error code if any files failed
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
