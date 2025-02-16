import typing

import idc
import idaapi
import ida_bytes
import ida_ua
import ida_kernwin
import ida_funcs
import ida_name
import idautils


def patch_bytes(address, opcodes, dryrun=False):
    print(f"[+] patching: {address:x} with 0x{opcodes:02x}")
    if dryrun:
        return
    
    # Convert to code and define as function
    ida_bytes.patch_byte(address, opcodes)
    if idc.create_insn(address) > 0:
        idaapi.auto_wait()
        return

    ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE, 1)
    if idc.create_insn(address) > 0:
        idaapi.auto_wait()
        return

    # undefining also helps. Last try (thx IgorS)
    ins = typing.cast(ida_ua.insn_t, idautils.DecodeInstruction(address))
    if not ins.size:
        print(f"WARN: failed to create instruction {address:x}")
        idaapi.auto_wait()
        return

    ida_bytes.del_items(address, ins.size, ida_bytes.DELIT_EXPAND)
    if idc.create_insn(address) <= 0:
        print(f"WARN: failed to create instruction {address:x}")

    idaapi.auto_wait()


def run():
    now = ida_kernwin.get_screen_ea()
    print("[+] CurPos: " + hex(now))
    cur_func = ida_name.get_name_ea(idc.BADADDR, ida_funcs.get_func_name(now))
    print("[+] CurFunc: " + hex(cur_func))
    func_start = idc.get_func_attr(now, idc.FUNCATTR_START)
    func_end = idc.get_func_attr(now, idc.FUNCATTR_END)
    print("[+] FuncStart: " + hex(func_start))
    print("[+] FuncEnd: " + hex(func_end))

    curr_addr = func_start
    while curr_addr < func_end:
        disasm = idc.generate_disasm_line(curr_addr, 0)
        print(hex(curr_addr) + "\t" + disasm)

        is_obfuscated = False

        # Obfuscated Pattern Start
        if "short near ptr" in disasm:
            next_disasm = idc.generate_disasm_line(idc.next_head(curr_addr), 0)
            if not "nop" in next_disasm:
                if disasm[0] == "j":
                    is_obfuscated = True
        elif ", cs:dword" in disasm:
            next_disasm = idc.generate_disasm_line(idc.next_head(curr_addr), 0)
            if "add" in next_disasm:
                next_disasm = idc.generate_disasm_line(
                    idc.next_head(idc.next_head(idc.next_head(curr_addr))),
                    0,
                )
                if "cmp" in next_disasm:
                    start_addr = curr_addr
                    end_addr = 0
                    while end_addr == 0:
                        disasm = idc.generate_disasm_line(start_addr, 0)
                        print(hex(start_addr) + " - " + disasm)
                        if ("short" in disasm) and (disasm[0] == "j"):
                            end_addr = start_addr
                            break
                        start_addr = idc.next_head(start_addr)
                    if end_addr:
                        for i in range(curr_addr, end_addr):
                            patch_bytes(i, 0x90)

                        curr_addr = end_addr
                        is_obfuscated = True
        elif "jz" in disasm:
            prev_disasm = idc.generate_disasm_line(idc.prev_head(curr_addr), 0)
            next_disasm = idc.generate_disasm_line(idc.next_head(curr_addr), 0)
            if not "nop" in next_disasm:
                if "cmp" in prev_disasm:
                    if idc.get_operand_value(idc.prev_head(curr_addr), 1) == 0xE8:
                        is_obfuscated = True
        # Obfuscated Pattern End

        if is_obfuscated:
            jmp_addr = idc.get_operand_value(curr_addr, 0)
            jmp_next = idc.next_head(jmp_addr)
            print(
                "[!] Found obfuscated jmp at " + hex(curr_addr) + " to " + hex(jmp_addr)
            )
            for i in range(curr_addr, jmp_addr):
                patch_bytes(i, 0x90)

        curr_addr = idc.next_head(curr_addr)


if __name__ == "__main__":
    run()
