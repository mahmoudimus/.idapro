import ida_funcs
import ida_hexrays
import idc


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
    import idaapi  # Import here to avoid circular dependency issues

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


# Example usage (using the current cursor location):
current_address = idc.get_screen_ea()

# Option 1: Just recompile (assuming analysis is up-to-date)
# recompile_function_at(current_address)

# Option 2: Reanalyze *and* recompile (safer, recommended)
reanalyze_and_recompile(current_address)
