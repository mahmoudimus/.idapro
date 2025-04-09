import ctypes
import platform

# Determine if we are on an ARM64 system.
ARM64 = platform.machine().lower() in ("aarch64", "arm64")
# On ARM64 we “align” at 4 bytes; otherwise we use the pointer size.
ALIGN_SIZE = 4 if ARM64 else ctypes.sizeof(ctypes.c_void_p)


# ---- detail functions (simulating patterns::detail) ----


def is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def is_hex_digit(c: str) -> bool:
    return is_digit(c) or ("a" <= c.lower() <= "f")


def get_bits(c: str) -> int:
    return (ord(c) - ord("0")) if is_digit(c) else (ord(c.upper()) - ord("A") + 10)


def stoi_impl(
    s: str, value: int = 0, negative: bool = False, hex_mode: bool = False
) -> int:
    if s == "":
        return -value if negative else value
    if hex_mode:
        if s and is_hex_digit(s[0]):
            return stoi_impl(s[1:], get_bits(s[0]) + value * 16, negative, hex_mode)
    else:
        if s and is_digit(s[0]):
            return stoi_impl(
                s[1:], (ord(s[0]) - ord("0")) + value * 10, negative, hex_mode
            )
    return -value if negative else value


def stoi(s: str, value: int = 0) -> int:
    if s and s[0] == "-":
        s = s[1:]
        if s.startswith("0x") or s.startswith("0X"):
            return stoi_impl(s[2:], 0, True, True)
        return stoi_impl(s, 0, True)
    if s.startswith("0x") or s.startswith("0X"):
        return stoi_impl(s[2:], 0, False, True)
    return stoi_impl(s)


# ARM64‑specific functions
if ARM64:

    def extract_bitfield(insn: int, width: int, offset: int) -> int:
        int_width = 32
        return (insn << (int_width - (offset + width))) >> (int_width - width)

    def decode_masked_match(insn: int, mask: int, pattern: int) -> bool:
        return (insn & mask) == pattern

    def a64_decode_nop(insn: int) -> bool:
        # NOP instruction for arm64.
        return insn == 0b11010101000000110010000000011111

    def a64_decode_b(insn: int) -> (bool, bool, int):
        mask_val = 0b01111100000000000000000000000000
        pattern_val = 0b00010100000000000000000000000000
        if decode_masked_match(insn, mask_val, pattern_val):
            is_bl = bool((insn >> 31) & 0x1)
            offset = extract_bitfield(insn, 26, 0) << 2
            return True, is_bl, offset
        return False, False, 0

    def a64_decode_adr(insn: int) -> (bool, bool, int, int):
        mask_val = 0b00011111000000000000000000000000
        pattern_val = 0b00010000000000000000000000000000
        if decode_masked_match(insn, mask_val, pattern_val):
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = extract_bitfield(insn, 19, 5) << 2
            adrp = (insn >> 31) & 0x1
            offset = (immhi | immlo) * (4096 if adrp else 1)
            return True, bool(adrp), rd, offset
        return False, False, 0, 0

    def a64_decode_ldrh(insn: int) -> (bool, int, int, int):
        mask1 = 0b11111111111000000000010000000000
        pattern1 = 0b01111000010000000000010000000000
        if decode_masked_match(insn, mask1, pattern1):
            offset = extract_bitfield(insn, 9, 12)
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            return True, rn, rt, offset
        mask2 = 0b11111111110000000000000000000000
        pattern2 = 0b01111001010000000000000000000000
        if decode_masked_match(insn, mask2, pattern2):
            offset = extract_bitfield(insn, 12, 10) << 1
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            return True, rn, rt, offset
        return False, 0, 0, 0

    def a64_decode_ldr(insn: int) -> (bool, int, int, int):
        mask1 = 0b10111111111000000000010000000000
        pattern1 = 0b10111000010000000000010000000000
        if decode_masked_match(insn, mask1, pattern1):
            offset = extract_bitfield(insn, 9, 12)
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            return True, rn, rt, offset
        mask2 = 0b10111011110000000000000000000000
        pattern2 = 0b10111001010000000000000000000000
        if decode_masked_match(insn, mask2, pattern2):
            offset = extract_bitfield(insn, 12, 10) << (insn >> 30)
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            return True, rn, rt, offset
        return False, 0, 0, 0

    def a64_decode_str(insn: int) -> (bool, int, int, int):
        mask1 = 0b10111011111000000000010000000000
        pattern1 = 0b10111000000000000000010000000000
        if decode_masked_match(insn, mask1, pattern1):
            offset = extract_bitfield(insn, 9, 12)
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            return True, rn, rt, offset
        mask2 = 0b10111011111000000000000000000000
        pattern2 = 0b10111001000000000000000000000000
        if decode_masked_match(insn, mask2, pattern2):
            offset = extract_bitfield(insn, 12, 10) << (insn >> 30)
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            return True, rn, rt, offset
        return False, 0, 0, 0

    def a64_decode_movz(insn: int) -> (bool, int, int, int):
        mask_val = 0b01111111100000000000000000000000
        pattern_val = 0b01010010100000000000000000000000
        if decode_masked_match(insn, mask_val, pattern_val):
            hw = (insn >> 21) & 0x3
            # When hw is zero, shifting is a no‑op.
            offset = (
                (extract_bitfield(insn, 16, 5) << hw)
                if hw
                else extract_bitfield(insn, 16, 5)
            )
            sf = (insn >> 31) & 0x1
            rd = insn & 0x1F
            return True, sf, rd, offset
        return False, 0, 0, 0

    def a64_decode_arithmetic(insn: int) -> (bool, bool, int, int, int, int):
        mask_val = 0b00111111100000000000000000000000
        pattern_val = 0b00010001000000000000000000000000
        if decode_masked_match(insn, mask_val, pattern_val):
            sf = (insn >> 31) & 0x1
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            is_sub = bool((insn >> 30) & 0x1)
            imm12 = extract_bitfield(insn, 12, 10)
            sh = (insn >> 22) & 0x1
            offset = (imm12 << 12) if sh else imm12
            return True, is_sub, sf, rd, rn, offset
        return False, False, 0, 0, 0, 0


# Non-ARM64 helpers
if not ARM64:

    def relative_value(ptr_bytes: bytes, size: int) -> int:
        # Convert raw bytes to a signed integer (little-endian)
        return int.from_bytes(ptr_bytes[:size], byteorder="little", signed=True)

    def get_inst_len_opt(s: str) -> int:
        if not s or not s[0].isdigit():
            raise ValueError("Invalid data for calculating remaining instruction size!")
        return int(s)


# ---- Pattern base class (simulating patterns::Pattern) ----


class Pattern:
    def __init__(self):
        self.length_ = 0
        self.offset_ = 0
        self.deref_ = False
        if not ARM64:
            self.insn_len_ = 0
            self.size_ = 4  # Default 4-byte relative reading.
            self.rel_ = False
        self.align_ = False

    def length(self) -> int:
        return self.length_

    def offset(self) -> int:
        return self.offset_

    def deref(self) -> bool:
        return self.deref_

    if not ARM64:

        def relative(self) -> bool:
            return self.rel_

    def aligned(self) -> bool:
        return self.align_

    # These methods must be overridden by subclasses.
    def mask(self) -> bytes:
        raise NotImplementedError

    def pattern(self) -> bytes:
        raise NotImplementedError

    def find(self, bytes_data: bytes):
        """
        Scan the provided bytes (e.g. from a module’s memory image) for a match.
        Returns a computed “result” address (an index in bytes_data) based on the pattern and options.
        """
        pat = self.pattern()
        msk = self.mask()
        result = None
        end = len(bytes_data) - self.length_
        # Use the proper step size.
        step = ALIGN_SIZE if self.align_ else 1
        i = 0
        while i < end:
            found = True
            if ARM64:
                if self.align_:
                    for j in range(0, self.length_, ALIGN_SIZE):
                        # Compare a 4-byte chunk (padding if necessary).
                        chunk = pat[j : j + ALIGN_SIZE].ljust(ALIGN_SIZE, b"\x00")
                        mask_chunk = msk[j : j + ALIGN_SIZE].ljust(ALIGN_SIZE, b"\x00")
                        mem_chunk = bytes_data[i + j : i + j + ALIGN_SIZE].ljust(
                            ALIGN_SIZE, b"\x00"
                        )
                        data = int.from_bytes(chunk, byteorder="little")
                        msk_val = int.from_bytes(mask_chunk, byteorder="little")
                        mem_val = int.from_bytes(mem_chunk, byteorder="little")
                        if (data ^ mem_val) & msk_val:
                            found = False
                            break
                else:
                    # Byte-by-byte match (only compare bytes fully fixed by 0xFF mask).
                    for j in range(self.length_):
                        if msk[j] == 0xFF and pat[j] != bytes_data[i + j]:
                            found = False
                            break
            else:
                # For non-ARM64, compare in chunks of pointer size.
                for j in range(0, self.length_, ALIGN_SIZE):
                    chunk = pat[j : j + ALIGN_SIZE].ljust(ALIGN_SIZE, b"\x00")
                    mask_chunk = msk[j : j + ALIGN_SIZE].ljust(ALIGN_SIZE, b"\x00")
                    mem_chunk = bytes_data[i + j : i + j + ALIGN_SIZE].ljust(
                        ALIGN_SIZE, b"\x00"
                    )
                    data = int.from_bytes(chunk, byteorder="little")
                    msk_val = int.from_bytes(mask_chunk, byteorder="little")
                    mem_val = int.from_bytes(mem_chunk, byteorder="little")
                    if (data ^ mem_val) & msk_val:
                        found = False
                        break
            if found:
                return self.get_result(i, bytes_data)
            i += step
        return result

    def __getitem__(self, idx: int) -> int:
        return self.pattern()[idx]

    # --- Protected helper methods ---
    def value(self, s: str) -> int:
        # Expects a string of at least two characters.
        return (get_bits(s[0]) << 4) | get_bits(s[1])

    def handle_options(self, ptr: str):
        for ch in ptr:
            if ARM64:
                if ch == "d":
                    self.deref_ = True
            else:
                if ch == "d":
                    if self.rel_:
                        raise ValueError("Cannot use relative and deref together!")
                    self.deref_ = True
                elif ch == "r":
                    if self.deref_:
                        raise ValueError("Cannot use relative and deref together!")
                    self.rel_ = True
                elif ch == "a":
                    self.align_ = True
                elif "0" <= ch <= "9":
                    self.size_ = int(ch)
                    if (self.size_ & (self.size_ - 1)) != 0:
                        raise ValueError("Size is not a valid data type size!")

    def get_result(self, address_index: int, bytes_data: bytes):
        """
        Compute the “result” based on the found pattern, the current options,
        and (if applicable) instruction decoding.
        """
        if ARM64:
            if self.deref_:
                # Simulate reading a 32-bit instruction from the found index + offset.
                insn_offset = address_index + self.offset_
                if insn_offset + 4 > len(bytes_data):
                    raise ValueError("Not enough bytes for instruction decoding.")
                insn = int.from_bytes(
                    bytes_data[insn_offset : insn_offset + 4], byteorder="little"
                )
                # Try branch decode.
                matched, is_bl, off = a64_decode_b(insn)
                if matched:
                    return address_index + off
                # Try ADR decode.
                matched, is_adrp, rd, off = a64_decode_adr(insn)
                if matched:
                    saved_offset = off
                    saved_rd = rd
                    curr_index = insn_offset + 4
                    while curr_index + 4 <= len(bytes_data):
                        curr_insn = int.from_bytes(
                            bytes_data[curr_index : curr_index + 4], byteorder="little"
                        )
                        matched_arith, is_sub, sf, rd, rn, off2 = a64_decode_arithmetic(
                            curr_insn
                        )
                        if matched_arith and saved_rd == rd and rn == rd:
                            # (In this simulation the sf flag does not alter the arithmetic)
                            saved_offset = (
                                saved_offset - off2 if is_sub else saved_offset + off2
                            )
                            curr_index += 4
                            continue
                        # Allow nops between instructions.
                        if a64_decode_nop(curr_insn):
                            curr_index += 4
                            continue
                        matched_ldr, rn, rt, off2 = a64_decode_ldr(curr_insn)
                        if matched_ldr:
                            if saved_rd == rn:
                                saved_offset += off2
                            break
                        matched_ldrh, rn, rt, off2 = a64_decode_ldrh(curr_insn)
                        if matched_ldrh:
                            if saved_rd == rn:
                                saved_offset += off2
                            break
                        matched_str, rn, rt, off2 = a64_decode_str(curr_insn)
                        if matched_str:
                            if saved_rd == rn:
                                saved_offset += off2
                            break
                        break
                    from_addr = (
                        address_index & ~0xFFF
                    )  # simulate page alignment for ADRP.
                    return from_addr + saved_offset
                # Try other decodings.
                matched_ldr, rn, rt, off = a64_decode_ldr(insn)
                if matched_ldr:
                    return off
                matched_ldrh, rn, rt, off = a64_decode_ldrh(insn)
                if matched_ldrh:
                    return off
                matched_str, rn, rt, off = a64_decode_str(insn)
                if matched_str:
                    return off
                matched_movz, sf, rd, off = a64_decode_movz(insn)
                if matched_movz:
                    return off
                matched_arith, is_sub, sf, rd, rn, off = a64_decode_arithmetic(insn)
                if matched_arith:
                    return off
                raise ValueError("Failed to decode instruction with defined functions")
            else:
                return address_index + self.offset_
        else:
            if self.deref_ or self.rel_:
                # For non-ARM64, read relative value from the bytes.
                start = address_index + self.offset_
                rel_bytes = bytes_data[start : start + self.size_]
                rel_addr = relative_value(rel_bytes, self.size_)
                if self.deref_:
                    return address_index + self.offset_ + self.insn_len_ + rel_addr
                else:
                    return rel_addr
            else:
                return address_index + self.offset_


# ---- RuntimePattern subclass (simulating patterns::RuntimePattern) ----


class RuntimePattern(Pattern):
    def __init__(self, p: str, length: int = None):
        """
        p: A pattern string (for example "48??24DF/da")
           '?' denotes a wildcard nibble.
           'X' (or 'x') marks the offset marker.
           A '/' begins the flag/options section.
        """
        super().__init__()
        self.m_pattern = bytearray()
        self.m_mask = bytearray()
        n = 0
        if length is None:
            length = len(p)
        i = 0
        while i < length:
            ch = p[i]
            if ch == "?":
                self.m_pattern.append(0)
                self.m_mask.append(0)
                n += 1
                i += 1
            elif ch in ("X", "x"):
                self.offset_ = n
                i += 1
                # If next character is not a space, optionally read extra digits.
                if i < length and p[i] != " ":
                    if not ARM64:
                        num_str = ""
                        while i < length and p[i] != " ":
                            num_str += p[i]
                            i += 1
                        self.insn_len_ = int(num_str)
                    else:
                        while i < length and p[i] != " ":
                            i += 1
            elif ch == "/":
                # Everything after '/' are options.
                i += 1
                self.handle_options(p[i:])
                break
            elif ch != " ":
                # Otherwise assume two hex digits represent a fixed byte.
                if i + 1 < length:
                    token = p[i : i + 2]
                    self.m_pattern.append(self.value(token))
                    self.m_mask.append(0xFF)
                    n += 1
                    i += 2
                else:
                    i += 1
            else:
                i += 1

        # Align the pattern length.
        if ARM64:
            while self.align_ and (n % ALIGN_SIZE) != 0:
                self.m_pattern.append(0)
                self.m_mask.append(0)
                n += 1
        else:
            while n % ctypes.sizeof(ctypes.c_void_p):
                self.m_pattern.append(0)
                self.m_mask.append(0)
                n += 1
        self.length_ = n

    def pattern(self) -> bytes:
        return bytes(self.m_pattern)

    def mask(self) -> bytes:
        return bytes(self.m_mask)


# A helper “literal” function similar to a user-defined literal in C++.
def rtpattern(p: str) -> RuntimePattern:
    return RuntimePattern(p)


# ---- Example usage ----
if __name__ == "__main__":
    # For example, create a runtime pattern from a string.
    # Pattern string: two fixed bytes "48", then a wildcard "??", then "24", then "DF",
    # with options (after a '/')—for instance "d" for dereference.
    pat = rtpattern("48??24DF/d")
    # In an actual use-case, you would scan a memory buffer (as a bytes object)
    # Here we simulate a buffer.
    test_bytes = bytes([0x00] * 100)  # dummy data
    # (Note: the find() method returns an index or computed address based on get_result.)
    result = pat.find(test_bytes)
    print("Result index:", result)
