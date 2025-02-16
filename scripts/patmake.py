"""
@file patmake.py
@brief Creates a pattern file from a database
@author neat
"""
import os

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_name
import ida_ua
import idautils


def crc16(bs):
    if not bs or len(bs) == 0:
        return 0
    crc = 0xFFFF
    for b in bs:
        for i in range(8):
            if (crc ^ b) & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            b >>= 1
    crc = ~crc & 0xFFFF
    crc = ((crc << 8) & 0xFF00) | ((crc >> 8) & 0xFF)
    return crc


sigs = []
for curr, func_ea in enumerate(idautils.Functions()):
    func = ida_funcs.get_func(func_ea)
    func_name = ida_funcs.get_func_name(func_ea)
    func_len = func.end_ea - func.start_ea

    total = ida_funcs.get_func_qty()
    if not ida_name.is_uname(func_name) or func_len < 4:
        print("[ %d / %d ] Skipping %s..." % (curr + 1, total, func_name))
        continue
    print("[ %d / %d ] Processing %s..." % (curr + 1, total, func_name))

    vars = []
    refs = []
    ea = func.start_ea
    while ea < func.end_ea:

        def iter_refs():
            for ref in idautils.CodeRefsFrom(ea, False):
                yield ref
            for ref in idautils.DataRefsFrom(ea):
                yield ref

        for ref in iter_refs():
            if ref >= func.start_ea and ref < func.end_ea:
                continue

            ref_name = ida_name.get_name(ref)
            if not ida_name.is_uname(ref_name):
                ref_name = None

            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, ea)

            op_num = 0
            for idx in range(len(insn.ops)):
                if insn.ops[idx].type == ida_ua.o_void:
                    op_num = idx
                    break

            for idx in range(op_num):
                op = insn.ops[idx]
                if op.type not in [
                    ida_ua.o_mem,
                    ida_ua.o_far,
                    ida_ua.o_near,
                ]:
                    continue

                sta = op.offb
                if idx < op_num - 1:
                    end = insn.ops[idx + 1].offb
                else:
                    end = insn.size

                for off in range(sta, end):
                    vars.append(ea + off)

                if ref_name:
                    refs.append((ea + sta, ref_name))
                break

        ea = ida_bytes.next_not_tail(ea)

    sig = ""
    for ea in range(func.start_ea, min(func.start_ea + 32, func.end_ea)):
        if ea in vars:
            sig += ".."
        else:
            sig += "%02X" % ida_bytes.get_byte(ea)

    if func_len > 32:
        crc_len = min(func_len - 32, 0xFF)
        for off in range(crc_len):
            if (func.start_ea + 32 + off) in vars:
                crc_len = off
                break
        crc = crc16(ida_bytes.get_bytes(func.start_ea + 32, crc_len))
    else:
        sig += ".." * (32 - func_len)
        crc_len = 0
        crc = 0

    sig += " %02X" % crc_len
    sig += " %04X" % crc
    sig += " %04X" % func_len

    sig += " :00000000 %s" % func_name
    for ea, ref in refs:
        sig += " ^%08X %s" % (ea - func.start_ea, ref)

    if func_len > 32 + crc_len:
        sig += " "
        for ea in range(
            func.start_ea + 32 + crc_len, min(func.end_ea, func.start_ea + 0x7FFF)
        ):
            if ea in vars:
                sig += ".."
            else:
                sig += "%02X" % ida_bytes.get_byte(ea)

    print(sig)
    sigs.append(sig)


def main():
    root, ext = os.path.splitext(ida_nalt.get_input_file_path())
    filename = ida_kernwin.ask_file(
        True, root + ".pat", "Enter the name of the pattern file"
    )
    with open(filename, "w") as f:
        for sig in sigs:
            f.write("%s\n" % sig)
        f.write("---\n")


if __name__ == "__main__":
    main()
