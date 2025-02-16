from idc import *
from ida_ua import *
from ida_bytes import *
from ida_allins import *

"""
based on https://ferib.dev/blog.php?l=post/Reversing_Common_Obfuscation_Techniques
"""

jumps = [NN_jmp, NN_ja, NN_jae, NN_jb, NN_jbe, NN_jc, NN_jcxz, NN_jecxz, NN_jrcxz, NN_je,NN_jg,NN_jge,NN_jl,NN_jle,NN_jna,NN_jnae,NN_jnb,NN_jnbe,NN_jnc,NN_jne,NN_jng,NN_jnge,NN_jnl,NN_jnle,NN_jno,NN_jnp,NN_jns,NN_jnz,NN_jo,NN_jp,NN_jpe,NN_jpo,NN_js,NN_jz]


class FixCode:
    unexplored: set[int] = set()
    explored:  set[int] = set()

    def __init__(self, ea) -> None:
        self.unexplored.add(ea)

    @staticmethod
    def is_valid_jump(cmd):
        jump_to = cmd.Op1.addr
        item_start = get_item_head(jump_to)
        # print(f"{cmd.ea:x} - is_valid_jump: {jump_to:x} =? {get_item_head(jump_to):x}")
        return item_start == jump_to

    # makes code if needed on ea and returns next instr addr
    @staticmethod
    def make_code(ea) -> int:
        # skip if already code
        if is_code(get_flags(ea)) and get_item_head(ea) == ea:
            return get_item_head(ea)

        cmd = insn_t()
        auto_wait()
        if create_insn(ea, cmd) <= 0:
            # try to undef and retry
            del_items(ea, 0, 10)
            cmd = insn_t()
            if create_insn(ea, cmd) <= 0:
                print(f"create_insn(ea, cmd) failed {ea:x}, dont know what to do")
                return BADADDR
            auto_wait()

        return get_item_head(ea)

    @staticmethod
    def append_cmt(ea, cmt):
        e_cmt = get_cmt(ea, False) or ''
        set_cmt(ea, e_cmt + " " + cmt, 0)

    @staticmethod
    def fill_nop(cmd):
        # 2 bytes jump
        FixCode.append_cmt(cmd.ea, f"Patched jmp, original: {GetDisasm(cmd.ea)}")
        patch_byte(cmd.ea, 0xEB)
        for ea in range(get_item_end(cmd.ea), cmd.Op1.addr):
            patch_byte(ea, 0x90)
        # if cmd.itype in NN_call:

    # fix 'chunk' from ea and below, until ret or no code
    def fix_chunk(self, ea):
        start_chunk_ea = ea
        cmd = insn_t()
        print(f"fix_chunk starting ea: {ea:x}")
        FixCode.append_cmt(ea, f"chunk {ea:x} starts here")
        while True:
            ea = get_item_head(ea)
            new_ea = self.make_code(ea)
            if new_ea == BADADDR:
                break
            ea = new_ea
            size = decode_insn(cmd, ea)
            print(f"working on {ea:x}, size: {size} {GetDisasm(ea)}")
            if cmd.itype in jumps:

                # check if jump+X - not valid, obfuscation
                rc = self.is_valid_jump(cmd)
                if rc:
                    if cmd.Op1.addr not in self.explored:
                        FixCode.append_cmt(cmd.ea, "original good jump ")
                        self.explored.add(cmd.Op1.addr)
                        if cmd.itype == NN_jmp:
                            print(f"straight JMP to {cmd.Op1.addr:x} continue there")
                            FixCode.append_cmt(cmd.ea, "JMP, taking it to process")
                            ea = cmd.Op1.addr
                            continue

                        # seems to be valid conditional jump, add addr to process this branch
                        self.unexplored.add(cmd.Op1.addr)
                        print(f"valid jump at {cmd.ea:x}, adding {cmd.Op1.addr:x}")
                        FixCode.append_cmt(cmd.ea, f"good conditional jump, queue as chunk {cmd.Op1.addr:x}")
                    else:
                        print(f"already processed, valid jump at {cmd.ea:x}")
                else:
                    if size > 2:
                        print(f"WARNING, size {size} > 2, obfuscations jumps are 2 byte long")
                        return

                    print(f"obfuscation jump at {cmd.ea:x} to {cmd.Op1.addr:x}, nop it")
                    if cmd.ea > cmd.Op1.addr:
                        print(f"negative jump at {cmd.ea:x} to {cmd.Op1.addr:x}, stop chunk here, idk what to do")
                        return
                    # fill with nops
                    self.fill_nop(cmd)
                    # self.make_code(cmd.Op1.addr)
                    ea = cmd.Op1.addr
                    del_items(ea, 0, 10)
                    auto_wait()
                    continue

            if cmd.itype == NN_retn:
                print(f"reached return. done  {cmd.ea:x} ")
                break

            # advance to next instr
            ea = get_item_end(ea)
        print(f"fix_chunk ends: {start_chunk_ea:x}")
        FixCode.append_cmt(ea, f"chunk {start_chunk_ea:x} ends here")

    def process(self):
        loops = 0
        while len(self.unexplored) > 0:
            ea = self.unexplored.pop()
            self.fix_chunk(ea)
            loops += 1
            _addr = [f"{x:x} " for x in self.unexplored]
            _done = [f"{x:x} " for x in self.explored]
            print(f"addresses to process: {len(self.unexplored)} - {_addr}")
            print(f"addresses done: {len(self.explored)} - {_done}")
            # if loops > 50:
            #     break


if __name__ == "__main__":
    f = FixCode(get_screen_ea())
    f.process()

