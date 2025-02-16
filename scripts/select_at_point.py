import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_problems
import idaapi  # We can use idaapi directly, and it's clearer
import idc  # idc also provides create_insn


def recompile_function_at(ea):
    """Re-decompiles the function at the given address.


    Args:
        ea: The address within the function to re-decompile.
    """
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"No function found at address 0x{ea:X}")
        return False

    # Get the function's start address.  Decompilation works on the whole function.
    func_start = func.start_ea

    # Decompile the function.  The cfunc_t object is the decompiled output.
    cfunc = ida_hexrays.decompile(func_start)

    if cfunc:
        print(f"Successfully re-decompiled function at 0x{func_start:X}")
        # You can now work with the 'cfunc' object (e.g., print it, analyze it)
        # print(cfunc)
        return True
    else:
        print(f"Failed to decompile function at 0x{func_start:X}")
        # Check for Hex-Rays plugin availability
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available.")
        return False


def reanalyze_and_recompile(ea):
    """Reanalyzes and recompiles the function at the given address.

    Args:
        ea: The address within the function.
    """
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"No function found at address 0x{ea:X}")
        return

    start = func.start_ea
    end = func.end_ea

    # 1. Reanalyze the function (important for correct decompilation)
    idaapi.plan_and_wait(start, end)

    # 2. Recompile the function
    recompile_function_at(ea)


def decompile_function(func_start: int):
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)

    ida_auto.auto_wait()


def force_code_range(start_ea, end_ea):
    """Forces a range of bytes in IDA to be disassembled as code."""
    ea = start_ea
    while ea < end_ea:
        flags = ida_bytes.get_flags(ea)

        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            ea = idc.next_head(ea, end_ea)
            continue

        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)

        # Corrected function call:
        if not idaapi.create_insn(ea):  # Or idc.create_insn(ea)
            print(f"Warning: Could not create instruction at 0x{ea:X}")
            ea += 1
        else:
            ea = idc.next_head(ea, end_ea)


def force_code_creation(start, end):
    """Forces undefined bytes in a range to be converted to code.

    Args:
        start: The starting address of the range.
        end: The ending address of the range.
    """
    for ea in range(start, end):
        if ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)  # Delete undefined item
            if not idaapi.create_insn(ea):  # Try to create an instruction
                print(f"Warning: Could not create instruction at 0x{ea:X}")


def reanalyze_function(func_start: int, func_end: int = None):
    if not func_end:
        func_end = idc.find_func_end(func_start)

    size = func_end - func_start
    ida_bytes.del_items(func_start, 0, size)
    for i in range(size):
        idaapi.create_insn(func_start + i)
    ida_funcs.add_func(func_start, func_end)
    idaapi.auto_wait()
    decompile_function(func_start)
    print(f"Fixed function {hex(func_start)}")
    reset_problems_in_function(func_start, func_end)


# There's a bug in Ida's API.
# If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
# This resets each problem in the reanalyzed functions.
def reset_problems_in_function(func_start: int, func_end: int):
    current_address: int = func_start
    while current_address != func_end:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        current_address = current_address + 1


def create_selection():
    """
    Creates a selection in IDA Pro.

    If the current cursor location is within a function, the selection
    extends to the end of the function. Otherwise, the user is prompted
    to enter an end address.
    """

    start_ea = idc.here()
    func = ida_funcs.get_func(start_ea)

    if func:
        end_ea = func.end_ea
        print(f"Selection start: 0x{start_ea:X}, end: 0x{end_ea:X} (end of function)")
    else:
        end_ea = ida_kernwin.ask_addr(start_ea, "Enter end address for selection:")
        if end_ea is None:
            print("Selection cancelled.")
            return
        if end_ea <= start_ea:
            print("Error: End address must be greater than start address.")
            return
        print(f"Selection start: 0x{start_ea:X}, end: 0x{end_ea:X} (user-defined)")

    curr_pos = idc.here()
    try:
        reanalyze_function(start_ea)
    finally:
        idc.jumpto(curr_pos)


create_selection()
