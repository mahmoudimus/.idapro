import ida_bytes
import ida_funcs
import ida_kernwin
import idaapi
import idc


def run_autoanalysis(start, end=None):
    if not end:
        end = start + 1
    idaapi.plan_and_wait(start, end)
    idaapi.auto_wait()


def force_code_creation(start, end):
    """Forces undefined bytes in a range to be converted to code.

    Args:
        start: The starting address of the range.
        end: The ending address of the range.
    """
    for ea in range(start, end):
        if ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)  # Delete undefined item
            if not ida_bytes.create_insn(ea):  # Try to create an instruction
                print(f"Warning: Could not create instruction at 0x{ea:X}")


def analyze_at_point(ea):
    """Analyzes a function or a specified range, forcing code creation.

    Args:
        ea: The address to start analysis.  If a function exists at this
            address, the entire function will be analyzed.  Otherwise,
            the user will be prompted for an end address.
    """

    func = ida_funcs.get_func(ea)

    if func:
        start = func.start_ea
        end = func.end_ea
        print(f"Function starts: 0x{start:02X} and ends: 0x{end:02X}")
        force_code_creation(start, end)  # Force code creation *before* analysis
        run_autoanalysis(start, end)
    else:
        print("No function found at the current address.")
        # Prompt user for an end address
        end = ida_kernwin.ask_addr(ea, "Enter end address")  # Changed to ask_addr
        if end is None:  # Handle cancellation
            print("Analysis cancelled.")
            return
        force_code_creation(ea, end)  # Force code creation *before* analysis
        run_autoanalysis(ea, end)


analyze_at_point(idc.get_screen_ea())
