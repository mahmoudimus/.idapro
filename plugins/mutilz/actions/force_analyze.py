import functools
from dataclasses import dataclass

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_problems
import idaapi
import idc
import mutilz.actions as actions
import mutilz.helpers.ida as ida_helpers


@dataclass
class ForceAnalyzeActionHandler(ida_helpers.BaseActionHandler):
    """Force analysis of a range by deleting all instructions in the range, reanalyzing, and re-decompi"""

    action_name: str = "mutilz:force_analyze"
    action_label: str = "Force Analyze"
    icon: int = 171  # lightning bolt icon

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            start_ea = func.start_ea
            end_ea = func.end_ea
        else:
            is_selected, start_ea, end_ea = idaapi.read_range_selection(
                idaapi.get_current_viewer()
            )
            if is_selected and start_ea != idaapi.BADADDR and end_ea != idaapi.BADADDR:
                # reset ea to start_ea since we selected a range specifically to the
                # start and end of the range
                ea = start_ea
            else:
                start_ea = ea
                print("No range selected.")
                end_ea = ida_kernwin.ask_addr(
                    start_ea, "Enter end address for selection:"
                )
                if end_ea is None:
                    print("Selection cancelled.")
                    return
                if end_ea <= start_ea:
                    print("Error: End address must be greater than start address.")
                    return
            print(f"Selection start: 0x{start_ea:X}, end: 0x{end_ea:X} (user-defined)")

        try:
            self.reanalyze_function(start_ea, end_ea)
            print(f"Forced analysis of range 0x{start_ea:X} - 0x{end_ea:X}")
        finally:
            idc.jumpto(ea)

        return 1

    def update(self, ctx):
        match ctx.widget_type:
            case idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            case _:
                return idaapi.AST_DISABLE_FOR_WIDGET

    @staticmethod
    def force_code_creation(start, end):
        """Forces undefined bytes in a range to be converted to code.

        Args:
            start: The starting address of the range.
            end: The ending address of the range.
        """
        for ea in range(start, end):
            if ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
                ida_bytes.del_items(
                    ea, ida_bytes.DELIT_SIMPLE, 1
                )  # Delete undefined item
                if not idaapi.create_insn(ea):  # Try to create an instruction
                    print(f"Warning: Could not create instruction at 0x{ea:X}")

    @staticmethod
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

    @staticmethod
    def decompile_function(func_start: int):
        hf = ida_hexrays.hexrays_failure_t()
        ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)

        ida_auto.auto_wait()

    # There's a bug in Ida's API.
    # If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
    # This resets each problem in the reanalyzed functions.
    @staticmethod
    def reset_problems_in_function(func_start: int, func_end: int):
        current_address: int = func_start
        while current_address != func_end:
            ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
            current_address = current_address + 1

    @classmethod
    def reanalyze_function(cls, func_start: int, func_end: int = None):
        if not func_end:
            func_end = idc.find_func_end(func_start)

        size = func_end - func_start
        ida_bytes.del_items(func_start, 0, size)
        for i in range(size):
            idaapi.create_insn(func_start + i)
        ida_funcs.add_func(func_start, func_end)
        idaapi.auto_wait()
        cls.decompile_function(func_start)
        print(f"Fixed function {hex(func_start)}")
        cls.reset_problems_in_function(func_start, func_end)


class ForceAnalyzeAction(actions.action_t, metaclass=ida_helpers.HookedActionMeta):
    uihook_class = functools.partial(
        ida_helpers.PopUpHook,
        ForceAnalyzeActionHandler,
        ida_helpers.is_disassembly_widget,
    )


# retrieve the action
def get_action() -> actions.action_t:
    return ForceAnalyzeAction()
