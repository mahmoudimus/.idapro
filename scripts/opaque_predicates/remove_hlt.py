import ida_bytes
import ida_funcs
import ida_ua
import idaapi
import idc


def is_long_nop(ea):
    """Checks if an instruction is a 'long NOP' (multi-byte NOP)."""
    mnem = idc.print_insn_mnem(ea)
    if mnem.lower() != "nop":
        return False
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
    elif processor_name == "ARM":
        return True
    elif processor_name == "PPC":
        return True
    elif processor_name == "MIPS":
        return True
    else:
        return False


def patch_instructions_with_nops(start, end):
    """Patches invalid instructions and long NOPs within a range with NOPs."""
    ea = start
    while ea < end:
        flags = ida_bytes.get_flags(ea)
        item_length = ida_bytes.get_item_size(ea)

        # Corrected instruction check:
        if (
            not ida_bytes.is_code(flags)
            or not ida_bytes.is_head(flags)
            or is_long_nop(ea)
        ):
            # 1. Not code:  This means it's data or undefined.
            # 2. Not a head: This means it's *not* the start of an instruction
            #    (it could be bytes in the middle of an instruction or data).
            # 3. Is a long NOP: We want to replace these.

            nop_instruction = get_nop_instruction()
            if nop_instruction is None:
                print("Error: Could not get NOP instruction for the current processor.")
                return

            num_nops = item_length // len(nop_instruction)
            remaining_bytes = item_length % len(nop_instruction)

            patch_bytes = nop_instruction * num_nops
            if remaining_bytes > 0:
                single_byte_nop = get_single_byte_nop()
                if single_byte_nop:
                    patch_bytes += single_byte_nop * remaining_bytes
                else:
                    print(f"Warning: Could not create a perfect NOP patch at 0x{ea:X}.")
                    patch_bytes += b"\x00" * remaining_bytes

            ida_bytes.patch_bytes(ea, patch_bytes)
            print(f"Patched {item_length} bytes at 0x{ea:X} with NOPs.")
            ea += item_length
        else:
            # It's a valid instruction (and not a long NOP); move to the next *instruction*.
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
    """Analyzes a function or range, patching invalid instructions and long NOPs."""
    import idaapi

    func = ida_funcs.get_func(ea)

    if func:
        start = func.start_ea
        end = func.end_ea
        print(f"Function starts: 0x{start:02X} and ends: 0x{end:02X}")
        patch_instructions_with_nops(start, end)
        idaapi.plan_and_wait(start, end)
    else:
        print("No function found at the current address.")
        end = idc.ask_addr(ea, "Enter end address")
        if end is None:
            print("Analysis cancelled.")
            return
        patch_instructions_with_nops(ea, end)
        idaapi.plan_and_wait(ea, end)


# Example usage:
analyze_at_point(idc.get_screen_ea())
