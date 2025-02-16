import idaapi
import idautils

import z3
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3


def branch_cannot_be_taken(expression, jump_target):
    # init solver
    solver = z3.Solver()
    # init translator miasm ir -> z3
    translator = TranslatorZ3()
    # add constraint
    solver.add(translator.from_expr(expression) == translator.from_expr(jump_target))
    # check for unsat
    return solver.check() == z3.unsat


# hardcode file path and address
file_path = idaapi.get_input_file_path()
start_addr = idaapi.get_imagebase()

# symbol table
loc_db = LocationDB()

# open the binary for analysis
container = Container.from_stream(open(file_path, "rb"), loc_db)

# cpu abstraction
machine = Machine(container.arch)

# init disassemble engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# initialize lifter to intermediate representation
lifter = machine.lifter_model_call(mdis.loc_db)

# disassemble the function at address
asm_cfg = mdis.dis_multiblock(start_addr)

# translate asm_cfg into ira_cfg
ira_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)

# set opaque predicate counter
opaque_counter = 0

# dictionary of byte patches
patches = {}

# walk over all basic blocks
for basic_block in asm_cfg.blocks:
    # get address of first basic block instruction
    next_line = basic_block.lines
    if not next_line:
        continue
    
    address = next_line[0].offset
    # done_interval += interval([(l.offset, l.offset + l.l)])
    # init symbolic execution engine

    sb = SymbolicExecutionEngine(lifter)

    # symbolically execute basic block
    e = sb.run_block_at(ira_cfg, address)

    # skip if no conditional jump
    if not e.is_cond():
        continue

    # cond ? src1 : src2

    # check if opaque predicate -- jump
    if branch_cannot_be_taken(e, e.src1):
        print(f"opaque predicate at {hex(address)} (jump is never taken)")
        opaque_counter += 1

        # get the jump instruction
        jump_instruction = basic_block.lines[-1]

        # get file offset from virtual address
        offset_of_jump_instruction = container.bin_stream.bin.virt2off(
            jump_instruction.offset
        )

        # walk over all instruction bytes and set corresponding file offsets to 0x90 (nop)
        for index in range(
            offset_of_jump_instruction,
            offset_of_jump_instruction + len(jump_instruction.b),
        ):
            patches[index] = 0x90

    # check if opaque predicate -- fall-through
    elif branch_cannot_be_taken(e, e.src2):
        print(f"opaque predicate at {hex(address)} (always jump)")
        opaque_counter += 1


print(f"number of opaque predicates: {opaque_counter}")


print("patching")

# read raw bytes of file
with open(file_path, "rb") as f:
    raw_bytes = bytearray(f.read())

    # apply patches
    for index, byte in patches.items():
        raw_bytes[index] = byte

    # save patched file
    with open(file_path + "_back.exe", "wb+") as wb:
        wb.write(raw_bytes)
