import builtins

import ida_bytes
import ida_nalt
import idaapi
import idautils
import idc

print = builtins.print


def is_non_executable_section(seg):
    """Check if a segment is non-executable."""
    return not (seg.perm & idaapi.SEGPERM_EXEC)


# def is_special_sequence(addr):
#     """Check if the byte sequence at addr matches a special sequence."""
#     if addr + 2 >= idaapi.get_segm_end(idaapi.getseg(addr)):
#         return False  # Ensure we don't read past segment end
#     byte0 = idc.get_wide_byte(addr)
#     if byte0 != 0x66:
#         return False
#     byte1 = idc.get_wide_byte(addr + 1)
#     if byte1 == 0x90 or byte1 == 0x0F:
#         return True
#     if byte1 == 0x66 and idc.get_wide_byte(addr + 2) == 0x0F:
#         return True
#     return False


def _bin_search(start, end, pattern):
    patterns = ida_bytes.compiled_binpat_vec_t()

    seqstr = " ".join([f"{b:02x}" if b != -1 else "?" for b in pattern])
    err = ida_bytes.parse_binpat_str(
        patterns,
        start,
        seqstr,
        16,
        ida_nalt.get_default_encoding_idx(  # use one byte-per-character encoding
            ida_nalt.BPU_1B
        ),
    )
    if err:
        return idaapi.BADADDR

    return ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)


def is_special_sequence(addr):
    """Check if the address starts with a special sequence like 0x66 0x90 or 0x66 0x0F."""
    seg_end = idaapi.getseg(addr).end_ea
    if addr + 2 >= seg_end:  # Ensure we don’t read past segment
        return False
    byte0 = ida_bytes.get_byte(addr)
    if byte0 != 0x66:  # Must start with 0x66
        return False
    byte1 = ida_bytes.get_byte(addr + 1)
    if byte1 == 0x90 or byte1 == 0x0F:  # 0x66 0x90 or 0x66 0x0F
        return True
    if byte1 == 0x66 and ida_bytes.get_byte(addr + 2) == 0x0F:  # 0x66 0x66 0x0F
        return True
    return False


def undo_function_padding(dry_run=False):
    """Undo function padding randomization in the .text section."""
    patched_count = 0
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        print("No .text section found.")
        return
    start = seg.start_ea
    end = seg.end_ea
    print(f"Processing .text section: {hex(start)} - {hex(end)}")
    addr = start
    while addr < end:
        # Find next 0xC3
        addr, _ = _bin_search(addr, end, [0xC3])
        if addr == idaapi.BADADDR:
            break
        B = addr  # Address of 0xC3
        found_end = False
        for k in range(1, end - B):
            A = B + k  # Potential end address
            # Check if we've reached a qualifying end address.
            if (A & 0xF) == 0 or is_special_sequence(A):
                # If the region is long enough, check whether patching is needed.
                if k >= 6 and not all(idc.get_bytes(B + 1, A - B - 1) == b"\xcc"):
                    print(f"Patching {hex(B + 1)} to {hex(A - 1)}")
                    if not dry_run:
                        ida_bytes.patch_bytes(B + 1, b"\xcc" * (A - B - 1))
                    patched_count += A - B - 1
                found_end = True
                addr = A  # Move to end of sequence
                break
        if not found_end:
            addr += 1  # Move past 0xC3
    print(f"Total patched sequences: {patched_count}")


if __name__ == "__main__":
    # Execute the unprotection
    print("Unprotecting functions...")
    undo_function_padding()
    print("Done.")
