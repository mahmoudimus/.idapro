import idautils
import idc


def check_stack_variable_usage(var_name):
    """
    Scans the current function for references to the stack variable
    with name `var_name` (e.g. "var_950") and reports its usage.
    If the variable is only used in a chain of local assignments,
    it can be simplified out.
    """
    func_start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
    if func_start is None:
        print("Not inside a function!")
        return

    refs = []
    for ea in idautils.FuncItems(func_start):
        # get the disassembly text for the current instruction
        disasm = idc.generate_disasm_line(ea, 0)
        if disasm is None:
            continue
        # if the stack variable name appears in the disassembly, record it
        if var_name in disasm:
            refs.append((ea, disasm))

    print(
        "Found {} reference(s) to {} in function at 0x{:X}:".format(
            len(refs), var_name, func_start
        )
    )
    for addr, line in refs:
        print("  0x{:X}: {}".format(addr, line))

    # Simple heuristic: if all uses occur in a local chain (e.g. dead stores)
    # then the variable is not really needed.
    if len(refs) > 0:
        print("\nHeuristic check:")
        # In this example the variable is only used to move a value through a series of operations
        # (and its final value is then moved to rax). Thus it is not really needed.
        print(
            "  {} appears to be a local variable that is only used in a chain of assignments."
            "\n  It could be simplified out (i.e. eliminate the unnecessary memory store/load cycle).".format(
                var_name
            )
        )
    else:
        print("No references to {} were found.".format(var_name))


# Usage: in the disassembly view place the cursor inside the function in question,
# then run this script. We check for the variable "var_950" (as seen in the disassembly).
check_stack_variable_usage("var_950")
