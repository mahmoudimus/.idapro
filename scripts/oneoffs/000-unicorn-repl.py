import os

import idc
import unicorn


def emulate_block_sequentially(uc, start_addr, end_addr):
    pc = start_addr
    while pc < end_addr:
        instruction_bytes = idc.get_bytes(pc, idc.get_item_size(pc))
        instruction_address = pc

        # Emulate instruction
        try:
            uc.emu_start(instruction_address, end_addr)  # Emulate block until end_addr
        except unicorn.UcError as e:
            print(
                f"emu_start(0x{instruction_address:02X}, 0x{end_addr:02X}) raised an error!",
                e,
                idc.generate_disasm_line(instruction_address, idc.GENDSM_FORCE_CODE),
                sep=os.linesep,
            )  # Disassemble and print the invalid instruction in IDA
            raise
        pc = idc.next_head(pc)  # Move to the next instruction
