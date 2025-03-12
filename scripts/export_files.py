#!/usr/bin/env python3
"""
Implements multiple export strategies:
  1. Export functions by file strings (C/C++ files).
  2. Export functions from a highlighted range in the Functions view.
  3. Export functions from highlighted lines in the Names view.
  4. Export functions whose names match a given regex or prefix.
Exports are saved into a user-specified export directory.
"""

import re
from pathlib import Path

import ida_kernwin
import ida_lines
import idaapi
import idautils
import idc


def clear_window(window):
    form = ida_kernwin.find_widget(window)
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


def clear_output():
    clear_window("Output window")


def ask_export_directory() -> Path | None:
    """
    Ask the user to select an export directory.
    Returns the selected directory as a Path object,
    or None if no directory was chosen.
    """
    export_dir_str = ida_kernwin.ask_file(1, "", "Select export directory:")
    if not export_dir_str:
        print("No export directory selected.")
        return None
    export_dir_path = Path(export_dir_str)
    if not export_dir_path.is_dir():
        # If the chosen file is not a directory, use its parent.
        export_dir_path = export_dir_path.parent
    return export_dir_path


def get_decompiled_function_string(function_address: int) -> str | None:
    """
    Decompile the function at the given address.
    Returns the decompiled text if found, else None.
    """
    temp_file = Path("temp.txt")
    vdrun_newfile = 0
    start_keyword = f"{function_address:X})"
    end_keyword = r"^}"
    idaapi.decompile_many(str(temp_file), [function_address], vdrun_newfile)
    decompiled_function = ""
    start_found = False

    with temp_file.open("rt") as file_obj:
        for line in file_obj:
            if start_found:
                decompiled_function += line
                if re.match(end_keyword, line):
                    return decompiled_function
            if start_keyword in line:
                start_found = True

    return None


def format_filepath(filepath: str, export_dir: Path) -> Path:
    """
    Remove drive letters and convert separators,
    then append the result to export_dir.
    """
    for drive in ("e:\\", "E:\\", "c:\\", "C:\\"):
        filepath = filepath.replace(drive, "")
    filepath = filepath.replace("/", "\\")
    return export_dir / filepath


def create_folder_structure(file_path: Path) -> None:
    """
    Ensure the folder for file_path exists.
    """
    file_path.parent.mkdir(parents=True, exist_ok=True)


def is_valid_file_string(file_str: str) -> bool:
    """
    Returns True if file_str contains a C/C++ filename and a folder separator.
    """
    return (".cpp" in file_str or ".h" in file_str) and ("\\" in file_str)


def process_file_xrefs(file_string, formatted_path: Path) -> None:
    """
    Process xrefs from the given file_string and write decompiled functions
    to formatted_path.
    """
    last_function_address = 0
    with formatted_path.open("wt", encoding="utf-8") as out_file:
        for xref in idautils.XrefsTo(file_string.ea, 0):
            func = idaapi.get_func(xref.frm)
            if not func:
                continue
            function_address = func.start_ea
            if function_address != last_function_address:
                function_str = get_decompiled_function_string(function_address)
                if function_str is not None:
                    out_file.write(function_str + "\n\n")
                    last_function_address = function_address
                else:
                    print(
                        f"Error: {function_address:X}) export failed for {formatted_path}"
                    )


def process_file_string(file_string, export_dir: Path) -> None:
    """
    Process a single file string: format its path, create folder structure,
    and export its functions.
    """
    file_str = str(file_string)
    formatted_path = format_filepath(file_str, export_dir)
    create_folder_structure(formatted_path)
    process_file_xrefs(file_string, formatted_path)


def export_by_file_strings(export_dir: Path) -> None:
    """
    Export functions based on file strings (C/C++ files).
    """
    for file_string in idautils.Strings():
        file_str = str(file_string)
        if is_valid_file_string(file_str):
            process_file_string(file_string, export_dir)


def export_functions_from_addresses(addresses: list[int], output_file: Path) -> None:
    """
    Given a list of function addresses, decompile each function and write to output_file.
    Duplicate addresses are removed and the list is sorted.
    """
    unique_addresses = sorted(set(addresses))
    with output_file.open("wt", encoding="utf-8") as out_file:
        for addr in unique_addresses:
            function_str = get_decompiled_function_string(addr)
            if function_str:
                out_file.write(function_str + "\n\n")
            else:
                print(f"Error: {addr:X} export failed.")


#
# --- Selection extraction helpers ---
#
def get_widget_lines(
    widget, tp0: ida_kernwin.twinpos_t, tp1: ida_kernwin.twinpos_t
) -> list[str]:
    """
    Retrieve text lines from a widget between twinpos_t positions tp0 and tp1.
    Adapted from Hex-Rays' dump_selection.py example.
    """
    ud = ida_kernwin.get_viewer_user_data(widget)
    lnar = ida_kernwin.linearray_t(ud)
    lnar.set_place(tp0.at)
    lines = []
    while True:
        cur_place = lnar.get_place()
        first_line_ref = ida_kernwin.l_compare2(cur_place, tp0.at, ud)
        last_line_ref = ida_kernwin.l_compare2(cur_place, tp1.at, ud)
        if last_line_ref > 0:  # beyond last line
            break
        line = ida_lines.tag_remove(lnar.down())
        if last_line_ref == 0:  # at last line
            line = line[0 : tp1.x]
        elif first_line_ref == 0:  # at first line
            line = " " * tp0.x + line[tp0.x :]
        lines.append(line)
    return lines


def extract_addresses_from_widget_selection(widget) -> list[int]:
    """
    Retrieve the current selection from the given widget and parse it for hex addresses.
    Returns a list of addresses found in the selection.
    """
    tp0 = ida_kernwin.twinpos_t()
    tp1 = ida_kernwin.twinpos_t()
    if not ida_kernwin.read_selection(widget, tp0, tp1):
        print("No selection found in widget.")
        return []
    lines = get_widget_lines(widget, tp0, tp1)
    addresses = []
    for line in lines:
        match = re.match(r"\s*([0-9A-Fa-f]+)", line)
        if match:
            try:
                addr = int(match.group(1), 16)
                addresses.append(addr)
            except Exception:
                continue
    return addresses


def extract_addresses_from_selection() -> list[int]:
    """
    Convenience function that retrieves addresses from the current widget's selection.
    """
    widget = ida_kernwin.get_current_widget()
    return extract_addresses_from_widget_selection(widget)


#
# --- Export strategies using widget selections ---
#
def export_functions_from_functions_view(export_dir: Path) -> None:
    """
    Export functions based on the addresses found in the selection of a Functions view.
    """
    addresses = extract_addresses_from_selection()
    if not addresses:
        print("No functions found in the selection (Functions view).")
        return
    output_file = export_dir / "functions_view_export.txt"
    export_functions_from_addresses(addresses, output_file)
    print(f"Exported {len(addresses)} functions to {output_file}")


def export_functions_from_names_view(export_dir: Path) -> None:
    """
    Export functions based on the addresses found in the selection of a Names view.
    """
    addresses = extract_addresses_from_selection()
    if not addresses:
        print("No valid function addresses found in the selection (Names view).")
        return
    output_file = export_dir / "names_view_export.txt"
    export_functions_from_addresses(addresses, output_file)
    print(f"Exported {len(addresses)} functions to {output_file}")


def export_functions_by_regex(export_dir: Path) -> None:
    """
    Ask the user for a regex or prefix, then export all functions whose names match.
    """
    regex = ida_kernwin.ask_str("", 0, "Enter function name regex or prefix:")
    if not regex:
        print("No regex provided.")
        return

    pattern = re.compile(regex)
    addresses: list[int] = []
    for func_addr in idautils.Functions():
        func_name = idc.get_func_name(func_addr)
        if pattern.match(func_name):
            addresses.append(func_addr)

    if not addresses:
        print("No functions matching the regex were found.")
        return

    output_file = export_dir / "regex_export.txt"
    export_functions_from_addresses(addresses, output_file)
    print(f"Exported {len(addresses)} functions to {output_file}")


def export_functions_by_string_search(export_dir: Path) -> None:
    """
    Ask the user for a prefix, then export all functions whose names contain.
    """
    name = ida_kernwin.ask_str("", 0, "Enter function name prefix or contains:")
    if not name:
        print("No name provided.")
        return

    search = name.lower()
    addresses: list[int] = []
    for func_addr in idautils.Functions():
        func_name = idc.get_func_name(func_addr)
        demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_LONG_DN))
        if demangled_name and search in demangled_name.lower():
            addresses.append(func_addr)
        elif func_name and search in func_name.lower():
            addresses.append(func_addr)  # //NOSONAR

    if not addresses:
        print("No functions matching the regex were found.")
        return

    output_file = export_dir / f"{search}_export.txt"
    export_functions_from_addresses(addresses, output_file)
    print(f"Exported {len(addresses)} functions to {output_file}")


def main() -> None:
    """
    Ask the user for an export directory and which export strategy to use.
    """
    export_dir = ask_export_directory()
    if export_dir is None:
        return

    prompt = (
        "Choose export strategy:\n"
        "1: Export functions by file strings (C/C++ files)\n"
        "2: Export functions from selected text in a Functions view\n"
        "3: Export functions from selected text in a Names view\n"
        "4: Export functions by regex\n"
        "5: Export functions by string search (i.e. name.lower() in func.lower())\n"
        "Enter choice (1-5): "
    )
    choice = ida_kernwin.ask_str("1", 0, prompt)
    if not choice:
        print("No choice provided.")
        return

    if choice == "1":
        export_by_file_strings(export_dir)
    elif choice == "2":
        export_functions_from_functions_view(export_dir)
    elif choice == "3":
        export_functions_from_names_view(export_dir)
    elif choice == "4":
        export_functions_by_regex(export_dir)
    elif choice == "5":
        export_functions_by_string_search(export_dir)
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    clear_output()
    main()
