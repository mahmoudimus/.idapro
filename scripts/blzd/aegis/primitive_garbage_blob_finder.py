import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc


def is_cc_byte(ea):
    """Check if the byte at the given address is 0xCC."""
    try:
        return ida_bytes.get_byte(ea) == 0xCC
    except:
        return False


def find_cc_sequences(start_ea, end_ea, min_length=2):
    """Find sequences of consecutive 0xCC bytes in the given range."""
    result = []
    current_start = None

    ea = start_ea
    while ea < end_ea:
        if is_valid_address(ea) and is_cc_byte(ea):
            if current_start is None:
                current_start = ea
        else:
            if current_start is not None:
                seq_len = ea - current_start
                if seq_len >= min_length:
                    result.append((current_start, ea - 1, seq_len))
                current_start = None

        ea += 1

    # Check for sequence that extends to the end
    if current_start is not None:
        seq_len = end_ea - current_start
        if seq_len >= min_length:
            result.append((current_start, end_ea - 1, seq_len))

    return result


def is_valid_address(ea):
    """Check if the address is valid (mapped in memory)."""
    seg = ida_segment.getseg(ea)
    return seg is not None


def is_special_sequence(ea):
    """Check if the address starts with a special sequence like 0x66 0x90 or 0x66 0x0F."""
    bytes_at_ea = idc.get_bytes(ea, 3)
    if not bytes_at_ea or len(bytes_at_ea) < 2:
        return False
    sequences = [b"\x66\x90", b"\x66\x0f", b"\x66\x66\x0f"]
    return any(bytes_at_ea.startswith(seq) for seq in sequences)


def find_padding_from_cursor(
    cursor_pos, start_offset=0x1000, ending_offset=0x2000, min_len=2
):
    """Find CC padding bytes in specified range from cursor."""
    start_range = start_offset + cursor_pos
    end_range = cursor_pos + ending_offset

    print(f"Searching for CC padding from 0x{start_range:X} to 0x{end_range:X}...")

    cc_sequences = find_cc_sequences(start_range, end_range, min_length=min_len)

    if not cc_sequences:
        print("No CC padding found in the specified range.")
    else:
        for seq_start, seq_end, seq_len in cc_sequences:
            # Check if the end of the sequence matches the predicate
            if (seq_end + 1 & 0xF) == 0 or is_special_sequence(seq_end + 1):
                print(
                    f"Found {seq_len} CC bytes at 0x{seq_start:X} - 0x{seq_end:X} (matches predicate)"
                )
            else:
                print(
                    f"Found {seq_len} CC bytes at 0x{seq_start:X} - 0x{seq_end:X} (does not match predicate)"
                )
            print(f"length: {seq_start - cursor_pos:X}")


def main():
    print("=== Function Padding Finder ===")

    print(f"Padding in range from cursor: 0x{idc.here():X}")
    find_padding_from_cursor(idc.here())

    print("\nSearch completed!")


if __name__ == "__main__":
    main()
