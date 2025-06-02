import idaapi
import idautils
import idc


def calc_target_jump(insn):
    if insn.get_canon_mnem() in [
        "jmp",
        "call",
        "jo",
        "jno",
        "js",
        "jns",
        "je",
        "jz",
        "jne",
        "jnz",
        "jb",
        "jnae",
        "jc",
        "jnb",
        "jae",
        "jnc",
        "jbe",
        "jna",
        "ja",
        "jnbe",
        "jl",
        "jnge",
        "jge",
        "jnl",
        "jle",
        "jng",
        "jg",
        "jnle",
        "jp",
        "jpe",
        "jnp",
        "jpo",
        "jcxz",
        "jecxz",
        "jrcxz",
    ]:
        return insn.Op1.addr
    return None


def is_in_range(target):
    return idc.get_segm_start(target) != idc.BADADDR


def analyze_instructions():
    current_addr = idc.get_screen_ea()
    new_chunks = []
    last_target = 0
    is_jmp = True

    for addr in idautils.Heads(
        idc.get_segm_start(current_addr), idc.get_segm_end(current_addr)
    ):
        print("addr: ", hex(addr))
        insn = idaapi.insn_t()
        size = idaapi.decode_insn(insn, addr)
        if size == 0 or not insn:
            continue

        target = 0
        is_jmp = True

        if insn.get_canon_mnem() == "invalid" or insn.get_canon_mnem() == "ret":
            if last_target == 0:
                return new_chunks
            continue

        if insn.get_canon_mnem() in [
            "jo",
            "jno",
            "js",
            "jns",
            "je",
            "jz",
            "jne",
            "jnz",
            "jb",
            "jnae",
            "jc",
            "jnb",
            "jae",
            "jnc",
            "jbe",
            "jna",
            "ja",
            "jnbe",
            "jl",
            "jnge",
            "jge",
            "jnl",
            "jle",
            "jng",
            "jg",
            "jnle",
            "jp",
            "jpe",
            "jnp",
            "jpo",
            "jcxz",
            "jecxz",
            "jrcxz",
        ]:
            if last_target == 0:
                target = calc_target_jump(insn)
                if not is_in_range(target):
                    is_jmp = False
                    continue
                if insn.size > 2:
                    is_jmp = False
                    new_chunks.append(target)
                    continue
            else:
                is_jmp = False
                continue

        if insn.get_canon_mnem() in ["jmp", "call"]:
            if last_target == 0:
                new_address = calc_target_jump(insn)
                if not is_in_range(new_address):
                    is_jmp = False
                    continue
                if insn.get_canon_mnem() == "call":
                    new_chunks.append(addr + insn.size)
                new_chunks.append(new_address)
                return new_chunks

        location = addr + insn.size
        steps_left = last_target - location if last_target != 0 else 0
        
        if steps_left < 0:
            print("Opaque condition detected at address: 0x{:X}".format(addr))
            return new_chunks


if __name__ == "__main__":
    analyze_instructions()
