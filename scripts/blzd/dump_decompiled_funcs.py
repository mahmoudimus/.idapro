import os
import re

import ida_bytes
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_lines
import ida_name
import ida_segment
import ida_ua
import ida_xref
import idaapi


def demangle_name(name):
    """Demangle a function name."""
    demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
    if demangled:
        # Remove any template parameters for file naming
        clean_name = re.sub(r"<.*>", "", demangled)
        return clean_name
    return name


def get_function_name(ea):
    """Get the demangled function name for a given address."""
    func_name = ida_name.get_ea_name(ea)
    return demangle_name(func_name)


def get_called_functions(func_ea):
    """Get addresses of all functions called within the specified function."""
    called_funcs = set()

    # Get the function
    func = ida_funcs.get_func(func_ea)
    if not func:
        return called_funcs

    # Get the function's flow chart
    flow_chart = ida_gdl.FlowChart(func)

    # Iterate through each basic block in the function
    for block in flow_chart:
        # Iterate through each instruction in the block
        ea = block.start_ea
        while ea < block.end_ea:
            # Check for code references from this address
            xref = ida_xref.xrefblk_t()
            if xref.first_from(ea, ida_xref.XREF_FAR):
                while True:
                    # If it's a code reference and it's a call, add it
                    if xref.type == ida_xref.fl_CN or xref.type == ida_xref.fl_CF:
                        target_func = ida_funcs.get_func(xref.to)
                        if target_func:
                            called_funcs.add(target_func.start_ea)

                    if not xref.next_from():
                        break

            # Move to the next instruction
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) == 0:
                ea += 1  # Fallback if decode fails
            else:
                ea += insn.size

    return called_funcs


def get_referenced_globals(func_ea):
    """Get all global variables referenced by this function."""
    globals_list = set()

    # Get the function
    func = ida_funcs.get_func(func_ea)
    if not func:
        return globals_list

    # Get the function's flow chart
    flow_chart = ida_gdl.FlowChart(func)

    # Iterate through each basic block in the function
    for block in flow_chart:
        # Iterate through each instruction in the block
        ea = block.start_ea
        while ea < block.end_ea:
            # Check for data references from this address
            xref = ida_xref.xrefblk_t()
            if xref.first_from(ea, ida_xref.XREF_DATA):
                while True:
                    # Check if the target is likely a global variable
                    seg = idaapi.getseg(xref.to)
                    if (
                        seg
                        and (seg.perm & idaapi.SEGPERM_READ)
                        and not ida_funcs.get_func(xref.to)
                    ):
                        name = ida_name.get_ea_name(xref.to)
                        if name and len(name) > 0:
                            # Add it to our list of globals
                            flags = ida_bytes.get_flags(xref.to)
                            size = ida_bytes.get_item_size(xref.to)
                            globals_list.add((name, xref.to, size))

                    if not xref.next_from():
                        break

            # Move to the next instruction
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) == 0:
                ea += 1  # Fallback if decode fails
            else:
                ea += insn.size

    return globals_list


def should_skip_function(func_name, current_depth):
    """Determine if a function should be skipped based on its name."""
    if current_depth > 0:
        # Skip standard library functions
        if func_name.startswith("std::"):
            return True
        # Skip common runtime functions
        if func_name.startswith("__") and (
            "runtime" in func_name or "cxa" in func_name
        ):
            return True
        # Add other patterns to skip as needed
    return False


def decompile_function(ea):
    """Decompile function at the given address and return pseudocode."""
    try:
        # Ensure decompiler is initialized
        if not ida_hexrays.init_hexrays_plugin():
            return f"// Decompiler not available for function at {hex(ea)}\n"

        # Get the decompiled function
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            # Get the pseudocode as text
            pseudocode = str(cfunc)
            # Clean up the pseudocode (remove IDA's color tags, etc.)
            clean_code = ida_lines.tag_remove(pseudocode)
            return clean_code
    except Exception as e:
        return f"// Failed to decompile function at {hex(ea)}: {str(e)}\n"

    return f"// Failed to decompile function at {hex(ea)}\n"


def recursive_decompile(start_func_ea, max_depth, visited=None, current_depth=0):
    """Recursively decompile functions up to max_depth."""
    if visited is None:
        visited = set()

    if current_depth > max_depth or start_func_ea in visited:
        return {}, set()

    # Mark this function as visited
    visited.add(start_func_ea)

    # Get function name
    func_name = get_function_name(start_func_ea)

    # Skip certain functions based on name
    if should_skip_function(func_name, current_depth):
        return {}, set()

    # Decompile the function
    print(
        f"Decompiling {func_name} at {hex(start_func_ea)} (depth {current_depth}/{max_depth})"
    )
    decompiled_code = decompile_function(start_func_ea)

    # Get global variables referenced by this function
    globals_list = get_referenced_globals(start_func_ea)

    # Get called functions
    called_funcs = get_called_functions(start_func_ea)

    # Initialize results
    result = {start_func_ea: (func_name, decompiled_code)}
    all_globals = globals_list

    # Recursively process called functions
    for called_ea in called_funcs:
        if called_ea not in visited:
            # Only recurse if we haven't hit the depth limit
            if current_depth < max_depth:
                sub_results, sub_globals = recursive_decompile(
                    called_ea, max_depth, visited, current_depth + 1
                )
                result.update(sub_results)
                all_globals.update(sub_globals)

    return result, all_globals


def sanitize_filename(name):
    """Sanitize a string for use as a filename."""
    # Remove invalid filename characters
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", name)
    # Replace spaces with underscores
    sanitized = sanitized.replace(" ", "_")
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized


def save_to_c_file(functions_data, globals_data, base_name):
    """Save decompiled functions and global variables to a C file."""
    # Create a sanitized file name
    safe_name = sanitize_filename(base_name)
    file_path = f"{safe_name}.c"

    with open(file_path, "w") as f:
        # Write header comment
        f.write(f"// Decompiled code for function {base_name} and its callees\n")
        f.write(f"// Generated by IDA Python recursive decompiler\n\n")

        # Write forward declarations for global variables
        if globals_data:
            f.write("// Global variables\n")
            for name, ea, size in globals_data:
                f.write(f"extern /* size: {size} */ {name}; // at {hex(ea)}\n")
            f.write("\n")

        # Write forward declarations for functions
        f.write("// Function declarations\n")
        for ea, (name, _) in functions_data.items():
            f.write(f"// {name} at {hex(ea)}\n")
        f.write("\n")

        # Write function bodies
        f.write("// Function implementations\n")
        for ea, (name, code) in functions_data.items():
            f.write(f"// {name} at {hex(ea)}\n")
            f.write(code)
            f.write("\n\n")

    print(f"Saved decompiled code to {file_path}")
    return file_path


def main():
    """Main function to run the script."""
    # Get the current position in IDA
    current_ea = idaapi.get_screen_ea()

    # Get the current function
    func = ida_funcs.get_func(current_ea)
    if not func:
        print("No function at current position!")
        return

    # Ask user for recursion depth
    max_depth = idaapi.ask_long(3, "Enter maximum recursion depth:")
    if max_depth is None:  # User canceled
        return
    if max_depth < 0:
        max_depth = 0

    print(f"Decompiling function at {hex(func.start_ea)} with max depth {max_depth}...")

    # Make sure Hex-rays decompiler is available
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-rays decompiler is not available!")
        return

    # Get function name for the output file
    base_name = get_function_name(func.start_ea)
    print(f"Base function: {base_name}")

    # Recursively decompile
    functions_data, globals_data = recursive_decompile(func.start_ea, max_depth)

    # Save to C file
    output_file = save_to_c_file(functions_data, globals_data, base_name)

    print(
        f"Recursive decompilation completed. Processed {len(functions_data)} functions."
    )
    print(f"Results saved to {output_file}")


if __name__ == "__main__":
    main()
