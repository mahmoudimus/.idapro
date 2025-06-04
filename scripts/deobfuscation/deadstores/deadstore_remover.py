from triton import *

import ida_bytes
import ida_funcs
import ida_gdl
import ida_kernwin
import ida_ua
import idaapi
from idaapi import PLUGIN_OK, plugin_t


class DeadstoreRemover(plugin_t):
    flags = 0
    wanted_name = "Function Deadstore remover"
    wanted_hotkey = "Ctrl-Shift-T"
    comment = "Remove deadstores within the function at the current cursor position"
    help = "This plugin processes the function at the current cursor position and removes deadstores"

    def init(self):
        self.ctx = TritonContext()
        self.ctx.setArchitecture(ARCH.X86_64)
        self.total_removed = 0
        return PLUGIN_OK

    def run(self, arg):
        self.total_removed = 0
        current_ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(current_ea)
        if func:
            self.process_function(func.start_ea)
            print(f"\nTotal removed count: {self.total_removed}")
        else:
            print("No function found at the current cursor position")

    def term(self):
        pass

    def process_function(self, func_ea):
        func = ida_funcs.get_func(func_ea)
        if not func:
            print(f"No function found at address 0x{func_ea:X}")
            return

        f = ida_gdl.FlowChart(func)
        for block in f:
            self.process_basic_block(block)

    def process_basic_block(self, block):
        sub_blocks = self.split_block_at_calls(block.start_ea, block.end_ea)

        for start_ea, end_ea in sub_blocks:
            instructions = self.get_raw_instructions(start_ea, end_ea)
            if not instructions:
                continue

            original_disassembly = self.disassemble_instructions(instructions)
            simplified_instructions = self.simplify_instructions(instructions)
            simplified_disassembly = self.disassemble_instructions(
                simplified_instructions
            )

            removed_instructions = self.compare_and_print_differences(
                original_disassembly, simplified_disassembly
            )
            self.nop_out_instructions(removed_instructions)

    def split_block_at_calls(self, start_ea, end_ea):
        sub_blocks = []
        current_start = start_ea
        current_ea = start_ea

        while current_ea < end_ea:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, current_ea)

            if insn_len == 0:
                print(f"Failed to decode instruction at 0x{current_ea:X}")
                break

            if insn.itype == idaapi.NN_call:
                sub_blocks.append((current_start, current_ea + insn_len))
                current_start = current_ea + insn_len

            current_ea += insn_len

        if current_start < end_ea:
            sub_blocks.append((current_start, end_ea))

        return sub_blocks

    def get_raw_instructions(self, start_ea, end_ea):
        instructions = []
        curr_ea = start_ea
        while curr_ea < end_ea:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, curr_ea)

            if insn_len == 0:
                print(f"Failed to decode instruction at 0x{curr_ea:X}")
                break

            bytes_str = ida_bytes.get_bytes(curr_ea, insn_len)
            instructions.append((curr_ea, bytes_str))

            curr_ea += insn_len

        return instructions

    def disassemble_instructions(self, instructions):
        disassembled = []
        for addr, bytes_str in instructions:
            instr = Instruction(addr, bytes_str)
            self.ctx.disassembly(instr)
            disassembled.append((addr, instr.getDisassembly()))
        return disassembled

    def simplify_instructions(self, instructions):
        block = BasicBlock(
            [Instruction(addr, bytes_str) for addr, bytes_str in instructions]
        )
        simplified_block = self.ctx.simplify(block)
        return [
            (instr.getAddress(), instr.getOpcode())
            for instr in simplified_block.getInstructions()
        ]

    def compare_and_print_differences(self, original, simplified):
        removed_instructions = []
        orig_index = simp_index = 0

        jump_mnemonics = set(
            [
                "ja",
                "jae",
                "jb",
                "jbe",
                "jc",
                "je",
                "jg",
                "jge",
                "jl",
                "jle",
                "jna",
                "jnae",
                "jnb",
                "jnbe",
                "jnc",
                "jne",
                "jng",
                "jnge",
                "jnl",
                "jnle",
                "jno",
                "jnp",
                "jns",
                "jnz",
                "jo",
                "jp",
                "jpe",
                "jpo",
                "js",
                "jz",
                "jmp",
            ]
        )

        while orig_index < len(original) and simp_index < len(simplified):
            orig_addr, orig_disasm = original[orig_index]
            simp_addr, simp_disasm = simplified[simp_index]

            if orig_disasm == simp_disasm:
                orig_index += 1
                simp_index += 1
                continue

            if (
                orig_disasm.split()[0] in jump_mnemonics
                and orig_disasm.split()[0] == simp_disasm.split()[0]
            ):
                orig_index += 1
                simp_index += 1
                continue

            look_ahead = next(
                (
                    i
                    for i, (_, disasm) in enumerate(
                        original[orig_index:], start=orig_index
                    )
                    if disasm == simp_disasm
                ),
                None,
            )

            if look_ahead is not None:
                for addr, disasm in original[orig_index:look_ahead]:
                    print(f"Removed 0x{addr:X}: {disasm}")
                    removed_instructions.append(addr)
                    self.total_removed += 1
                orig_index = look_ahead
            else:
                print(f"Modified: 0x{orig_addr:X}: {orig_disasm} -> {simp_disasm}")
                orig_index += 1
                simp_index += 1

        for addr, disasm in original[orig_index:]:
            print(f"Removed 0x{addr:X}: {disasm}")
            removed_instructions.append(addr)
            self.total_removed += 1

        return removed_instructions

    def nop(self, address, length):
        nop_bytes = b"\x90" * length
        ida_bytes.patch_bytes(address, nop_bytes)

    def nop_out_instructions(self, addresses):
        for addr in addresses:
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, addr)
            if insn_len == 1:
                self.nop(addr, insn_len)
            elif insn_len > 1:
                self.nop(addr, insn_len)
                for x in range(addr + 1, addr + insn_len):
                    idaapi.hide_item(x)
                    idaapi.set_cmt(addr, f"truncated nops ({insn_len})", False)

        # Refresh the disassembly view
        ida_kernwin.refresh_idaview_anyway()


def PLUGIN_ENTRY():
    return DeadstoreRemover()
