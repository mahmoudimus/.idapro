import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_problems
import idaapi  # We can use idaapi directly, and it's clearer
import idc  # idc also provides create_insn

# --- Constants for Action Names (Good Practice) ---
ACTION_REMOVE_JUNK = "mutilz:remove_junk"
ACTION_FORCE_ANALYZE = "mutilz:force_analyze"
ACTION_REPLACE_HLT = "mutilz:replace_hlt"

# --- Helper Functions (NOP patching and code creation) ---


class InstructionVisitor:
    """Base class for instruction visitors."""

    def visit(self, ea):
        """Visits an instruction at the given address.

        This method dispatches to more specific visit_* methods
        based on the instruction type.
        """
        mnem = idc.print_insn_mnem(ea).lower()

        if mnem == "ud2":
            return self.visit_ud2(ea)
        elif mnem == "nop":
            if self._is_long_nop(ea):
                return self.visit_long_nop(ea)
            else:
                return self.visit_nop(ea)  # Handle regular NOPs if needed
        elif mnem == "hlt":
            return self.visit_hlt(ea)
        elif not ida_bytes.is_code(ida_bytes.get_flags(ea)) or not ida_bytes.is_head(
            ida_bytes.get_flags(ea)
        ):
            return self.visit_invalid(ea)
        return self.visit_other(ea)  # Handle other instructions

    def visit_ud2(self, ea):
        """Handles UD2 instructions."""
        return True  # Default: do nothing, continue visiting

    def visit_long_nop(self, ea):
        """Handles long NOP instructions."""
        return True  # Default: do nothing

    def visit_nop(self, ea):
        """Handles regular (short) NOP instructions."""
        return True

    def visit_invalid(self, ea):
        """Handles invalid instructions (not code or not a head)."""
        return True  # Default: do nothing

    def visit_other(self, ea):
        """Handles all other instructions."""
        return True  # Default: do nothing, continue visiting

    def _is_long_nop(self, ea):
        """(Helper) Checks if an instruction is a 'long NOP'."""
        insn_length = ida_bytes.get_item_size(ea)
        processor_name = idc.get_inf_attr(idc.INF_PROCNAME)
        if processor_name in (
            "metapc",
            "8086",
            "80286",
            "80386",
            "80486",
            "80586",
            "80686",
        ):
            return insn_length > 1
        elif processor_name in ("ARM", "PPC", "MIPS"):
            return True
        else:
            return False


class NopPatcher(InstructionVisitor):
    """Patches invalid instructions, long NOPs, and UD2 instructions with NOPs."""

    def __init__(self):
        self.nop_instruction = get_nop_instruction()
        self.single_byte_nop = get_single_byte_nop()
        if self.nop_instruction is None:
            print("Error: Could not get NOP instruction for the current processor.")

    def _patch_with_nops(self, ea, item_length):
        """Helper function to patch bytes with NOPs."""
        if self.nop_instruction is None:
            return False

        num_nops = item_length // len(self.nop_instruction)
        remaining_bytes = item_length % len(self.nop_instruction)

        patch_bytes = self.nop_instruction * num_nops
        if remaining_bytes > 0:
            if self.single_byte_nop:
                patch_bytes += self.single_byte_nop * remaining_bytes
            else:
                print(f"Warning: Could not create a perfect NOP patch at 0x{ea:X}.")
                patch_bytes += b"\x00" * remaining_bytes

        ida_bytes.patch_bytes(ea, patch_bytes)
        print(f"Patched {item_length} bytes at 0x{ea:X} with NOPs.")
        return True

    def visit_ud2(self, ea):
        item_length = ida_bytes.get_item_size(ea)
        return self._patch_with_nops(ea, item_length)

    visit_hlt = visit_ud2
    visit_long_nop = visit_ud2
    visit_invalid = visit_ud2


def visit_instructions(start, end, visitor):
    """Visits instructions within a range using a visitor."""
    ea = start
    while ea < end:
        if not visitor.visit(ea):
            break
        ea = idc.next_head(ea, end)


def get_nop_instruction():
    """Gets the processor-specific NOP instruction bytes."""
    processor_name = idc.get_inf_attr(idc.INF_PROCNAME)
    if processor_name in (
        "metapc",
        "8086",
        "80286",
        "80386",
        "80486",
        "80586",
        "80686",
    ):
        return b"\x90"
    elif processor_name == "ARM":
        if idc.get_sreg(idc.here(), "T") == 0:
            return b"\x00\x00\xA0\xE3"
        else:
            return b"\x00\xBF"
    elif processor_name == "PPC":
        return b"\x60\x00\x00\x00"
    elif processor_name == "MIPS":
        return b"\x00\x00\x00\x00"
    print(f"Warning: No NOP instruction defined for processor '{processor_name}'")
    return None


def get_single_byte_nop():
    """Gets a single-byte NOP instruction if available."""
    processor_name = idc.get_inf_attr(idc.INF_PROCNAME)
    if processor_name in (
        "metapc",
        "8086",
        "80286",
        "80386",
        "80486",
        "80586",
        "80686",
    ):
        return b"\x90"
    return None


# --- Action Handlers ---


class RemoveJunkAction(idaapi.action_handler_t):
    """Action handler for removing junk instructions (long NOPs, UD2, invalid)."""

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            start = func.start_ea
            end = func.end_ea
            print(f"Function starts: 0x{start:02X} and ends: 0x{end:02X}")
            self.visit_and_patch(start, end)
        else:
            print("No function found at the current address.")
            end = idc.ask_addr(ea, "Enter end address")
            if end is None:
                print("Analysis cancelled.")
                return 0
            self.visit_and_patch(ea, end)
        return 1

    @staticmethod
    def visit_and_patch(ea, end):
        patcher = NopPatcher()
        visit_instructions(ea, end, patcher)
        idaapi.plan_and_wait(ea, end)

    def update(self, ctx):
        return (
            idaapi.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == idaapi.BWN_DISASM
            else idaapi.AST_DISABLE_FOR_WIDGET
        )


class ForceAnalyzeAction(idaapi.action_handler_t):
    """Action handler for forcing analysis of a range."""

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func:
            start_ea = func.start_ea
            end_ea = func.end_ea
        else:
            start_ea, end_ea = idaapi.read_range_selection(idaapi.get_current_viewer())
            if start_ea != idaapi.BADADDR and end_ea != idaapi.BADADDR:
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
        return (
            idaapi.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == idaapi.BWN_DISASM
            else idaapi.AST_DISABLE_FOR_WIDGET
        )

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

    @staticmethod
    def reanalyze_function(func_start: int, func_end: int = None):
        if not func_end:
            func_end = idc.find_func_end(func_start)

        size = func_end - func_start
        ida_bytes.del_items(func_start, 0, size)
        for i in range(size):
            idaapi.create_insn(func_start + i)
        ida_funcs.add_func(func_start, func_end)
        idaapi.auto_wait()
        ForceAnalyzeAction.decompile_function(func_start)
        print(f"Fixed function {hex(func_start)}")
        ForceAnalyzeAction.reset_problems_in_function(func_start, func_end)


class ReplaceHltAction(idaapi.action_handler_t):
    """Action handler for replacing HLT instructions."""

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        self.replace_hlt_with(ea)  # Call the helper function
        return 1

    def update(self, ctx):
        return (
            idaapi.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == idaapi.BWN_DISASM
            else idaapi.AST_DISABLE_FOR_WIDGET
        )

    @staticmethod
    def replace_hlt_with(ea, repl=0x90):
        """Replaces HLT instructions with a specified byte (default: NOP)."""
        func = ida_funcs.get_func(ea)
        if func:
            start = func.start_ea
            end = func.end_ea
        else:
            print("No function found at the current address.")
            end = ida_kernwin.ask_addr(ea, "Enter end address")
            if end is None:
                print("Analysis cancelled.")
                return

        for addr in range(start, end):
            if ida_bytes.get_byte(addr) == 0xF4:  # HLT instruction
                print(f"Patching HLT at: {hex(addr)}")
                ida_bytes.patch_byte(addr, repl)


# --- UI Hook (for context menu) ---


class CustomUIHook(idaapi.UI_Hooks):
    def __init__(self, actions):
        # super().__init__()
        idaapi.UI_Hooks.__init__(self)
        self.actions = actions

    def finish_populating_widget_popup(self, widget, popup):
        widget_type = idaapi.get_widget_type(widget)
        if widget_type == idaapi.BWN_DISASM:
            # t0, t1, view = (
            #     idaapi.twinpos_t(),
            #     idaapi.twinpos_t(),
            #     idaapi.get_current_viewer(),
            # )
            # if (
            #     idaapi.read_selection(view, t0, t1)
            #     or idc.get_item_size(idc.get_screen_ea()) > 1
            # ):
            for action_name in self.actions:
                idaapi.attach_action_to_popup(
                    widget,
                    popup,
                    action_name,
                    "mutilz/",
                )  # "" for separator


# --- Plugin Class ---


class mutilz_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "mutilz"
    help = ""
    wanted_name = "mutilz"
    wanted_hotkey = ""

    def init(self):
        print("mutilz Refactored plugin loaded.")

        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

        global ARCH
        global BITS
        ARCH = idaapi.ph_get_id()

        if idaapi.IDA_SDK_VERSION >= 900:
            if idaapi.inf_is_64bit():
                BITS = 64
            elif idaapi.inf_is_32bit_exactly():
                BITS = 32
            elif idaapi.inf_is_16bit():
                BITS = 16
            else:
                raise ValueError
        else:
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                BITS = 64
            elif info.is_32bit():
                BITS = 32
            else:
                BITS = 16

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(
                ACTION_REMOVE_JUNK,
                "Remove Junk Instructions",
                RemoveJunkAction(),
                None,  # No hotkey (context menu only)
                "Removes junk instructions (long NOPs, UD2, invalid) from the current function.",
                156,  # gear icon
            ),
            idaapi.action_desc_t(
                ACTION_FORCE_ANALYZE,
                "Force Analyze Range",
                ForceAnalyzeAction(),
                None,  # No hotkey
                "Forces analysis of the current function or selected range.",
                171,  # lightning bolt icon
            ),
            idaapi.action_desc_t(
                ACTION_REPLACE_HLT,
                "Replace HLT",
                ReplaceHltAction(),
                None,  # No hotkey
                "Replaces HLT instructions with NOPs (or a specified byte).",
                51,  # Use a suitable icon ID, e.g., a patch icon
            ),
        )
        for action in menu_actions:
            if not idaapi.register_action(action):
                print("[!] Failed to register action: ", action.name)
                continue
            self.registered_actions.append(action.name)

        # Add ui hook
        self.ui_hook = CustomUIHook(self.registered_actions)
        self.ui_hook.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        return

    def term(self):
        if hasattr(self, "ui_hook"):
            self.ui_hook.unhook()

        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)
        print("mutilz plugin unloaded.")
