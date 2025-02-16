import idaapi
import sys
from idautils import *
import binascii
from idc import *
import ipaddress
import struct
from ida_bytes import *
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import *
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.core import asmblock
from miasm.expression.expression import *

from qiling import Qiling
from qiling.const import QL_STOP, QL_VERBOSE
from qiling.os.const import POINTER, DWORD, HANDLE
from qiling.exception import QlErrorSyscallError
from qiling.os.windows import utils
from qiling.os.windows.wdk_const import *
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

import platform
import graphviz


# This routine populates the string table. Pay attention to separator '\x00'
def make_string_table(string_data):
    str_table = []
    for k in string_data.split("\x00"):
        str_table.append(k)
    return str_table


# This routine only prints the string table.
def print_string_table(my_table):
    for j in range(0, len(my_table)):
        print(my_table[j])


# This routine searches for a string in the string table.
# Pay attension: the search is through a given in bytes and not a slot of this table
def string_decrypter_search(arg_string, arg_key, str_addr):
    local_table = []
    for i in range(0, len(arg_string)):
        local_table.append((arg_string[i]) ^ (arg_key[i % len(arg_key)]))
    converted_table = bytes(local_table)[str_addr:].decode("latin").split("\x00")[0]
    return (str_addr, converted_table)


def is_jump_near_pair(addr):
    jcc1 = Byte(addr + 1)
    jcc2 = Byte(addr + 7)
    # do they start like near conditinal jumps?
    if Byte(addr) != 0x0F or Byte(addr + 6) != 0x0F:
        return False
    # are there really 2 consequent near conditional jumps?
    if (jcc1 & 0xF0 != 0x80) or (jcc2 & 0xF0 != 0x80):
        return False
    # are the conditional jumps complementary?
    if abs(jcc1 - jcc2) != 1:
        return False
    # do those 2 conditional jumps point to the same destination?
    dst1 = Dword(addr + 2)
    dst2 = Dword(addr + 8)
    if dst1 - dst2 != 6:
        return False

    return True


def is_jcc8(b):
    return b & 0xF0 == 0x70


def is_j_jmp(addr):
    dst1 = get_dword(addr + 1)
    if dst1 == 0:
        set_cmt(addr, "invalid jmp", 0)
        nop(addr, addr + 5)


def is_jump_short_pair(addr):
    jcc1 = Byte(addr)
    jcc2 = Byte(addr + 2)
    if (not is_jcc8(jcc1)) or (not is_jcc8(jcc2)):
        return False
    if abs(jcc2 - jcc1) != 1:
        return False

    dst1 = Byte(addr + 1)
    dst2 = Byte(addr + 3)
    if dst1 - dst2 != 2:
        return False

    return True


def patch_jcc32(addr):
    patch_byte(addr, 0x90)
    patch_byte(addr + 1, 0xE9)
    patch_word(addr + 6, 0x9090)
    patch_dword(addr + 8, 0x90909090)


def patch_jcc8(addr):
    patch_byte(addr, 0xEB)
    patch_word(addr + 2, 0x9090)


def print_func_asm(ea):
    start = get_func_attr(ea, FUNCATTR_START)
    end_d = get_func_attr(ea, FUNCATTR_END)
    end = end_d - 1
    myaddr = list(FuncItems(ea))
    for addr in myaddr:
        if start <= addr <= end:
            instruction = DecodeInstruction(addr)

            if print_insn_mnem(addr) == "push":
                set_cmt(addr, "start", 0)
                op1 = print_operand(addr, 0)
                j_start = addr
            try:
                op2 = print_operand(addr, 0)
                if print_insn_mnem(addr) == "jmp" and op1 == op2:
                    set_cmt(addr, "end", 0)

                    j_end = addr + instruction.size
                    size = j_end - j_start
                    print(
                        "%X %s size=%X\t" % (addr, generate_disasm_line(addr, 0), size)
                    )
                    if j_start < j_end:
                        # nop(j_start,j_end)
                        emulate_x64_code(j_start, size, instruction.size)
            except UnboundLocalError as e:
                print("%X %s\t", addr, generate_disasm_line(addr, 0))
                j_end = 0
            else:
                pass

            if print_insn_mnem(addr) == "jmp":
                is_j_jmp(addr)


def print_all_functions():
    for function_item in Functions():
        function_flags = get_func_attr(function_item, FUNCATTR_FLAGS)
        if function_flags & FUNC_LIB or function_flags & FUNC_THUNK:
            continue
        # print("0x%X %x\t" % (function_item,function_flags))


def nop(start, end):
    while start < end:
        patch_byte(start, 0x90)
        start += 1


def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True


def print_target_addr(stop_addr, myjit):
    operand = print_operand(stop_addr, 0)
    target = 0
    if operand == "r8":
        target = myjit.cpu.R8
    elif operand == "r9":
        target = myjit.cpu.R9
    elif operand == "r10":
        target = myjit.cpu.R10
    elif operand == "r11":
        target = myjit.cpu.R11
    elif operand == "rdx":
        target = myjit.cpu.RDX
    elif operand == "rax":
        target = myjit.cpu.RAX
    elif operand == "rcx":
        target = myjit.cpu.RCX
    elif operand == "rbp":
        target = myjit.cpu.RBP
    elif operand == "rsi":
        target = myjit.cpu.RSI
    print("ip 0x%X: jmp %s = 0x%X\t" % (stop_addr, operand, target))
    next_addr = next_head(stop_addr, stop_addr + 20)
    if next_addr == target:
        print("We can nop them all\t")
        return True
    return False


def emulate_x64_code(addr, size, inst_size):
    code = get_bytes(addr, size)
    machine = Machine("x86_64")
    loc_db = LocationDB()
    myjit = machine.jitter(loc_db, "python")
    myjit.init_stack()

    run_addr = addr
    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, code)
    myjit.set_trace_log(True, True, False)
    stop_addr = addr + size - inst_size
    print("stop addr: 0x%X operand %s\t" % (stop_addr, print_operand(stop_addr, 0)))
    myjit.add_breakpoint(stop_addr, code_sentinelle)
    myjit.run(run_addr)
    canNop = print_target_addr(stop_addr, myjit)
    if canNop:
        end_addr = next_head(stop_addr, stop_addr + size)
        print("s: %X e: %X\t" % (run_addr, end_addr))
        insn = DecodeInstruction(end_addr)
        end_addr += insn.size
        if run_addr < end_addr:
            nop(run_addr, end_addr)


def tvm():
    ea = 0x1401BC36B
    ea = 0x1401E247F
    ea = 0x14022021D
    ea = 0x14021FEBB
    ea = 0x140220018
    ea = 0x140221295
    ea = 0x1401C05C2
    print_func_asm(ea)


def spr_access(jitter):
    print("stopping the machine")
    return False


instr_count = 0
instr_flow = b""


def instr_hook(jitter):
    global instr_count
    global instr_flow
    instr_count += 1
    ea = jitter.cpu.RIP
    insn = DecodeInstruction(ea)
    size = insn.size
    instr_flow += get_bytes(ea, size)

    mnem = print_insn_mnem(ea)
    if ea == 0x14027A2FE:
        print("0x14027A2FE mnem: %s" % mnem)
    if mnem == "jmp":
        op = get_operand_type(ea, 0)
        if op == o_reg:
            print_target_addr(ea, jitter)
    return True


def print_modified(symb: SymbolicExecutionEngine):
    print("Modified registers:")
    symb.dump(mems=False)
    print("Modified memory (should be empty):")
    symb.dump(ids=False)


def sym_exec(machine: Machine, code):
    loc_db = LocationDB()

    dis_engine = machine.dis_engine

    # link the disasm engine to the bin_stream
    mdis = dis_engine(code, loc_db=loc_db)
    lifter = machine.lifter_model_call(loc_db)

    # Stop disassembler pos
    mdis.dont_dis = [len(code)]

    # Disassemble basic block
    # asm_block = mdis.dis_block(0)

    asm_cfg = mdis.dis_multiblock(0)
    graph = graphviz.Source(asm_cfg.dot())
    graph.render("Visualization")

    # Translate ASM -> IR
    lifter_model_call = machine.lifter_model_call(mdis.loc_db)
    ircfg = lifter_model_call.new_ircfg()
    for block in asm_cfg.blocks:
        lifter_model_call.add_asmblock_to_ircfg(block, ircfg)

    # Instantiate a Symbolic Execution engine with default value for registers
    symb = SymbolicExecutionEngine(lifter_model_call)

    end_offset = len(code)

    # Emulate one IR basic block
    ## Emulation of several basic blocks can be done through .emul_ir_blocks
    cur_addr = symb.run_at(ircfg, 0, step=True)
    # cur_addr = symb.run_at(ircfg,0)
    print_modified(symb)
    # while cur_addr != ExprInt(end_offset,64):
    #     cur_addr = symb.run_at(ircfg,cur_addr,step=True)
    #     print_modified(symb)


def emulate_pubg_code(start_addr):
    global instr_flow
    min_addr = ida_ida.inf_get_min_ea()
    max_addr = ida_ida.inf_get_max_ea()
    size = max_addr - min_addr
    code = get_bytes(min_addr, size)
    machine = Machine("x86_64")
    loc_db = LocationDB()
    myjit = machine.jitter(loc_db, "python")
    myjit.init_stack()

    myjit.vm.add_memory_page(min_addr, PAGE_READ | PAGE_WRITE, code)
    # myjit.set_trace_log(True,True,False)
    # myjit.set_trace_log(True,True,True)
    # myjit.jit.options['jit_maxline'] = 1
    # myjit.jit.options['max_exec_per_call'] = 1
    myjit.exec_cb = instr_hook
    try:
        myjit.init_run(start_addr)
        myjit.continue_run()
    except Exception as e:
        print(e)
        print("RIP: 0x%X Total instr: %d\t" % (myjit.cpu.RIP, instr_count))

    sym_exec(machine, instr_flow)


def zk0():
    ea = idaapi.get_imagebase()
    emulate_pubg_code(ea)


def force_call_dialog_func(ql: Qiling) -> None:
    ql.arch.regs.rcx = 0
    ql.arch.regs.rip = 0x00000001402974A6


def mem_read_invalid(ql, access, addr, size, value):
    print("[+] ERROR: invalid memory read at 0x%x" % addr)
    return True


def mem_unmapped(ql, access, addr, size, value):
    print("[+] ERROR: invalid memory mapped at 0x%x" % addr)
    rip = ql.arch.regs.rip
    next_addr = next_head(rip, rip + 20)
    ql.arch.regs.rip = next_addr
    return True


def mem_invalid(ql, access, addr, size, value):
    print("[+] ERROR: invalid memory at 0x%x" % addr)
    return True


def test_pe_win_x8664_driver():
    # Get the current working directory
    cwd = os.getcwd()

    # Print the current working directory
    # print("Current working directory: {0}".format(cwd))
    # libcache=True,
    ql = Qiling(
        ["./examples/rootfs/x8664_windows/bin/navagio.sys"],
        "./examples/rootfs/x8664_windows",
        stop=QL_STOP.STACK_POINTER,
        verbose=QL_VERBOSE.DISASM,
    )

    driver_object = ql.loader.driver_object

    # ql.hook_address(force_call_dialog_func,0x00000001402974a3)
    ql.hook_mem_read_invalid(mem_read_invalid)
    ql.hook_mem_unmapped(mem_unmapped)
    ql.hook_mem_invalid(mem_invalid)
    # Run the simulation
    ql.run()

    del ql


def main():
    # add_cref(addr_of_jmp_instr,vm_handler,XREF_USER|fl_JN)
    # append_func_tail()
    zk0()
    # test_pe_win_x8664_driver()
    pass


if __name__ == "__main__":
    main()
