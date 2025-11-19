import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_problems
import idaapi
import idautils
import idc


def reset_analysis(
    start: int = ida_ida.inf_get_min_ea(), end: int = ida_ida.inf_get_max_ea()
):
    """
    Reset the analysis of a range of bytes in IDA.
    """
    ida_auto.revert_ida_decisions(start, end)
    ida_auto.plan_and_wait(start, end)


def decompile_function(func_start: int):
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)
    ida_auto.auto_wait()


def reset_problems_in_function(func_start: int, func_end: int):
    """
    There's a bug in IDA's API.
    If one undefines and redefines a function's data, the operands are marked as a disassembly problem.
    This resets each problem in the reanalyzed functions.
    """
    current_address: int = func_start
    while current_address != func_end:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        current_address = current_address + 1


def reanalyze_function(
    func_start: int, func_end: int = idaapi.BADADDR, decompile: bool = False
):
    if func_end == idaapi.BADADDR:
        func_end = idc.find_func_end(func_start)

    size = func_end - func_start
    ida_bytes.del_items(func_start, 0, size)
    for i in range(size):
        idaapi.create_insn(func_start + i)
    ida_funcs.add_func(func_start, func_end)
    idaapi.auto_wait()
    if decompile:
        decompile_function(func_start)
    print(f"Fixed function {hex(func_start)}")
    reset_problems_in_function(func_start, func_end)


text_segment = idaapi.get_segm_by_name(".text")
reset_analysis(text_segment.start_ea, text_segment.end_ea)
for func_ea in idautils.Functions():
    # func_ea is already the start_ea of each function
    reanalyze_function(func_ea)
reset_analysis()
print("Done")
