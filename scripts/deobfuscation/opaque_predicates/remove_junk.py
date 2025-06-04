import ida_bytes
import ida_funcs
import ida_ua
import idaapi
import idc


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


def analyze_at_point(ea):
    """Analyzes a function or range, using the NopPatcher visitor."""
    import idaapi

    func = ida_funcs.get_func(ea)
    if func:
        start = func.start_ea
        end = func.end_ea
        print(f"Function starts: 0x{start:02X} and ends: 0x{end:02X}")
        patcher = NopPatcher()
        visit_instructions(start, end, patcher)
        idaapi.plan_and_wait(start, end)
    else:
        print("No function found at the current address.")
        end = idc.ask_addr(ea, "Enter end address")
        if end is None:
            print("Analysis cancelled.")
            return
        patcher = NopPatcher()
        visit_instructions(ea, end, patcher)
        idaapi.plan_and_wait(ea, end)


# Example usage:
analyze_at_point(idc.get_screen_ea())
