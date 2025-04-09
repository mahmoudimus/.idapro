import ctypes
import unittest

# We always use pointer size for alignment on x86/x64
ALIGN_SIZE = ctypes.sizeof(ctypes.c_void_p)


def relative_value(ptr_bytes: bytes, size: int) -> int:
    return int.from_bytes(ptr_bytes[:size], byteorder="little", signed=True)


def get_inst_len_opt(s: str) -> int:
    if not s or not s[0].isdigit():
        raise ValueError("Invalid data for calculating remaining instruction size!")
    return int(s)


class Pattern:
    def __init__(self):
        self.length_ = 0
        self.offset_ = 0
        self.deref_ = False
        self.insn_len_ = 0
        self.size_ = 4  # Default: read 4 bytes for relative/deref mode
        self.rel_ = False
        self.align_ = False

    def length(self) -> int:
        return self.length_

    def offset(self) -> int:
        return self.offset_

    def deref(self) -> bool:
        return self.deref_

    def relative(self) -> bool:
        return self.rel_

    def aligned(self) -> bool:
        return self.align_

    def mask(self) -> bytes:
        raise NotImplementedError

    def pattern(self) -> bytes:
        raise NotImplementedError

    def find(self, bytes_data: bytes):
        pat = self.pattern()
        msk = self.mask()
        end = len(bytes_data) - self.length_
        i = 0
        # Allow match when i == end (i.e. when data length equals pattern length)
        while i <= end:
            match = True
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
                    match = False
                    break
            if match:
                return self.get_result(i, bytes_data)
            i += ALIGN_SIZE if self.align_ else 1
        return None

    def __getitem__(self, idx: int) -> int:
        return self.pattern()[idx]

    def value(self, s: str) -> int:
        # Convert a two-character hex string to an integer
        return int(s, 16)

    def handle_options(self, ptr: str):
        for ch in ptr:
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
                if self.size_ not in (1, 2, 4, 8):  # Check for standard sizes
                    raise ValueError(
                        f"Size {self.size_} is not a valid data type size (1, 2, 4, or 8)!"
                    )

    def get_result(self, address_index: int, bytes_data: bytes):
        if self.deref_ or self.rel_:
            start = address_index + self.offset_
            # Ensure we don't read past the end of bytes_data
            if start + self.size_ > len(bytes_data):
                raise IndexError(
                    "Attempting to read relative value past end of data buffer"
                )
            rel_bytes = bytes_data[start : start + self.size_]
            # Use int.from_bytes directly
            rel_addr = int.from_bytes(rel_bytes, byteorder="little", signed=True)
            if self.deref_:
                return address_index + self.offset_ + self.insn_len_ + rel_addr
            else:
                return rel_addr
        else:
            return address_index + self.offset_


class RuntimePattern(Pattern):
    def __init__(self, p: str, length: int = None):
        super().__init__()
        self.m_pattern = bytearray()
        self.m_mask = bytearray()

        if length is None:
            length = len(p)

        # Parse the pattern string and get the raw byte count
        n = self._parse_pattern_string(p, length)

        # Apply alignment padding
        self._apply_alignment_padding(n)

    def _parse_pattern_string(self, p: str, length: int) -> int:
        """Parses the main pattern string token by token."""
        i = 0
        n = 0  # Tracks the number of bytes added to pattern/mask
        while i < length:
            ch = p[i]

            if ch == " ":
                i += 1
                continue
            elif ch == "?":
                chars_consumed, bytes_added = self._parse_wildcard(p, i, length)
                n += bytes_added
                i += chars_consumed
            elif ch in ("X", "x"):
                chars_consumed, bytes_added = self._parse_marker(p, i, length, n)
                n += bytes_added
                i += chars_consumed
            elif ch == "/":
                self.handle_options(p[i + 1 :])
                break  # Options mark the end of the pattern part
            else:  # Assume hex character start
                chars_consumed, bytes_added = self._parse_hex_byte(p, i, length)
                n += bytes_added
                i += chars_consumed
        return n

    def _parse_wildcard(self, p: str, i: int, length: int) -> tuple[int, int]:
        """Parses wildcard tokens ('?', '??', '?F')."""
        # Check for a potential second character of the token
        if i + 1 < length and p[i + 1] not in (" ", "/"):
            next_ch = p[i + 1]
            if next_ch == "?":  # Full byte wildcard '??'
                self.m_pattern.append(0)
                self.m_mask.append(0)
                return 2, 1  # Consumed '??', added 1 byte
            else:  # High nibble wildcard '?F'
                try:
                    low_val = int(next_ch, 16)
                    self.m_pattern.append(low_val)
                    self.m_mask.append(0x0F)
                    return 2, 1  # Consumed '?F', added 1 byte
                except ValueError:
                    raise ValueError(
                        f"Invalid hex digit '{next_ch}' following '?' at index {i+1}"
                    )
        else:  # Single '?' wildcard (treated as full byte)
            self.m_pattern.append(0)
            self.m_mask.append(0)
            return 1, 1  # Consumed '?', added 1 byte

    def _parse_marker(
        self, p: str, i: int, length: int, current_byte_count: int
    ) -> tuple[int, int]:
        """Parses the 'X'/'x' marker and optional instruction length."""
        self.offset_ = current_byte_count
        i += 1  # Consume 'X'
        chars_consumed = 1
        bytes_added = 0

        num_str = ""
        start_num_idx = i
        while i < length and p[i].isdigit():
            num_str += p[i]
            i += 1
            chars_consumed += 1

        if num_str:
            try:
                self.insn_len_ = int(num_str)
                # Add wildcards for the instruction length bytes
                for _ in range(self.insn_len_):
                    self.m_pattern.append(0)
                    self.m_mask.append(0)
                    bytes_added += 1
            except (
                ValueError
            ):  # Should not happen if isdigit() is correct, but safeguard
                raise ValueError(
                    f"Invalid instruction length '{num_str}' following 'X' at index {start_num_idx}"
                )
        # No number followed 'X', insn_len_ remains 0

        return chars_consumed, bytes_added

    def _parse_hex_byte(self, p: str, i: int, length: int) -> tuple[int, int]:
        """Parses a two-character hex byte ('FF') or low nibble wildcard ('F?')."""
        if i + 1 < length and p[i + 1] != " ":
            token = p[i : i + 2]
            try:
                if token[1] == "?":  # Low nibble wildcard "F?"
                    high_val = int(token[0], 16)
                    self.m_pattern.append(high_val << 4)
                    self.m_mask.append(0xF0)
                else:  # Fixed byte "FF"
                    val = int(token, 16)
                    self.m_pattern.append(val)
                    self.m_mask.append(0xFF)
                return 2, 1  # Consumed two chars, added 1 byte
            except ValueError:
                # Check if first char was hex, if not it's an invalid start
                try:
                    int(token[0], 16)  # Check if first char is hex
                    # If second char wasn't '?', it's an invalid hex char
                    raise ValueError(
                        f"Invalid hex digit '{token[1]}' in token '{token}' at index {i+1}"
                    )
                except ValueError:
                    raise ValueError(
                        f"Invalid character '{token[0]}' starting hex token at index {i}"
                    )

        else:
            # Single hex character not followed by another hex/wildcard/space
            raise ValueError(
                f"Incomplete hex byte token starting with '{p[i]}' at index {i}"
            )

    def _apply_alignment_padding(self, current_byte_count: int):
        """Pads pattern and mask to align to ALIGN_SIZE."""
        n = current_byte_count
        while n % ALIGN_SIZE != 0:
            self.m_pattern.append(0)
            self.m_mask.append(0)
            n += 1

        # Set the final aligned length
        self.length_ = len(self.m_pattern)  # Use the actual length after padding
        return self.length_

    def pattern(self) -> bytes:
        return bytes(self.m_pattern)

    def mask(self) -> bytes:
        return bytes(self.m_mask)


# A helper "literal" function similar to a C++ user-defined literal.
def rtpattern(p: str) -> RuntimePattern:
    return RuntimePattern(p)


# ---- Extended Unit Tests ----


class TestRuntimePattern(unittest.TestCase):
    def test_compiletime_pattern_beginning_r(self):
        # Pattern: "12 34 X2 AB CD /r"
        # Expected tokens (before padding): [0x12, 0x34, wildcard, wildcard, 0xAB, 0xCD]
        # After padding to 8 bytes: [0x12, 0x34, wildcard, wildcard, 0xAB, 0xCD, 0, 0]
        # /r means get_result returns the 2-byte relative value at offset 2.
        # We'll set the two wildcard bytes in the test buffer to 0x05, 0x00 (little-endian 5).
        pattern_str = "12 34 X2 AB CD /r"
        pt = rtpattern(pattern_str)
        pt.size_ = 2
        # Construct an 8-byte test buffer:
        test_bytes = bytes([0x12, 0x34, 0x05, 0x00, 0xAB, 0xCD, 0x00, 0x00])
        result = pt.find(test_bytes)
        expected = 5  # relative_value([0x05, 0x00]) == 5
        self.assertEqual(
            result,
            expected,
            f"Expected beginning /r pattern result {expected}, got {result}",
        )

    def test_pattern_middle_d(self):
        # Pattern: "AA BB X2 CC DD /d"
        # Expected tokens: [0xAA, 0xBB, wildcard, wildcard, 0xCC, 0xDD, 0, 0]
        # /d mode: get_result = match_index + 2 + 2 + relative_value.
        # Place pattern starting at index 6.
        # Set the two bytes at match_index+offset (index 6+2 = 8) to 0x03, 0x00 (relative value 3).
        pattern_str = "AA BB X2 CC DD /d"
        pt = rtpattern(pattern_str)
        pt.size_ = 2
        buffer = bytearray(16)
        # Build the pattern region (8 bytes):
        # [0xAA, 0xBB, 0x03, 0x00, 0xCC, 0xDD, 0, 0]
        region = bytearray([0xAA, 0xBB, 0x03, 0x00, 0xCC, 0xDD, 0x00, 0x00])
        buffer[6 : 6 + 8] = region
        test_bytes = bytes(buffer)
        result = pt.find(test_bytes)
        expected = 6 + 2 + 2 + 3  # 13
        self.assertEqual(
            result,
            expected,
            f"Expected middle /d pattern result {expected}, got {result}",
        )

    def test_pattern_end_r(self):
        # Pattern: "DE AD BE EF /r"
        # Expected tokens: [0xDE, 0xAD, 0xBE, 0xEF, 0,0,0,0]
        # Place this 8-byte region at the end of a 16-byte buffer.
        pattern_str = "DE AD BE EF /r"
        pt = rtpattern(pattern_str)
        pt.size_ = 4
        region = bytes([0xDE, 0xAD, 0xBE, 0xEF]) + bytes(ALIGN_SIZE - 4)
        buffer = bytearray(16)
        buffer[8 : 8 + 8] = region
        test_bytes = bytes(buffer)
        result = pt.find(test_bytes)
        expected = int.from_bytes(
            bytes([0xDE, 0xAD, 0xBE, 0xEF]), byteorder="little", signed=True
        )
        self.assertEqual(
            result, expected, f"Expected end /r pattern result {expected}, got {result}"
        )

    def test_align_option_found(self):
        # Pattern: "10 20 30 40 /a"
        # Expected tokens: [0x10, 0x20, 0x30, 0x40, 0,0,0,0]
        # Place the pattern at an aligned index (8).
        pattern_str = "10 20 30 40 /a"
        pt = rtpattern(pattern_str)
        region = bytes([0x10, 0x20, 0x30, 0x40]) + bytes(ALIGN_SIZE - 4)
        buffer = bytearray(16)
        buffer[8 : 8 + 8] = region
        test_bytes = bytes(buffer)
        result = pt.find(test_bytes)
        expected = 8
        self.assertEqual(
            result,
            expected,
            f"Expected aligned pattern result {expected}, got {result}",
        )

    def test_align_option_not_found(self):
        # Pattern: "10 20 30 40 /a"
        # Place the pattern at an unaligned index (3).
        pattern_str = "10 20 30 40 /a"
        pt = rtpattern(pattern_str)
        region = bytes([0x10, 0x20, 0x30, 0x40]) + bytes(ALIGN_SIZE - 4)
        buffer = bytearray(16)
        buffer[3 : 3 + 8] = region
        test_bytes = bytes(buffer)
        result = pt.find(test_bytes)
        self.assertIsNone(
            result, "Expected no match when pattern is not aligned, but got a result."
        )

    def test_nibble_pattern_1(self):
        # Pattern: "4? 5A"
        # Expected tokens: For "4?" -> [0x40, mask 0xF0]; "5A" fixed.
        # After padding to 8 bytes: [0x40, 0x5A, 0,0,0,0,0,0]
        # To match "4?", use 0x4F (0x4F & 0xF0 == 0x40), then 0x5A.
        test_buffer = bytes([0x4F, 0x5A] + [0] * 6)
        pattern_str = "4? 5A"
        pt = rtpattern(pattern_str)
        result = pt.find(test_buffer)
        expected = 0  # match at index 0
        self.assertEqual(
            result,
            expected,
            f"Expected nibble pattern 1 result {expected}, got {result}",
        )

    def test_nibble_pattern_2(self):
        # Pattern: "?? 7?"
        # Expected tokens: "??" gives [0, mask 0]; "7?" gives [0x70, mask 0xF0].
        # After padding: [0, 0x70, 0,0,0,0,0,0]
        # To match, we can use any byte for token0; use 0x12, and for token1 use 0x7C (0x7C & 0xF0 == 0x70).
        test_buffer = bytes([0x12, 0x7C] + [0] * 6)
        pattern_str = "?? 7?"
        pt = rtpattern(pattern_str)
        result = pt.find(test_buffer)
        expected = 0  # match at index 0
        self.assertEqual(
            result,
            expected,
            f"Expected nibble pattern 2 result {expected}, got {result}",
        )

    def test_complex_combination(self):
        # Pattern: "FF ?F 8? X1 4B /d"
        # Expected tokens (before padding):
        #   Token0: "FF" -> 0xFF, mask 0xFF.
        #   Token1: "?F" -> parsed as nibble wildcard (treat as high nibble wildcard) -> value = int("F", 16) = 15, mask=0x0F.
        #           (That is, only low nibble fixed; so acceptable bytes have any high nibble with low nibble F.)
        #   Token2: "8?" -> low nibble wildcard -> value = (int("8", 16)<<4)=0x80, mask=0xF0.
        #   Marker "X1": sets offset_ = current token count (3) and inserts 1 wildcard.
        #   Token3 (inserted by marker): wildcard (value=0, mask=0) used for relative value.
        #   Token4: "4B" -> fixed 0x4B, mask=0xFF.
        # After padding to 8 bytes, expected m_pattern: [0xFF, 0x0F, 0x80, 0x00, 0x4B, 0, 0, 0]
        # In /d mode, get_result returns: match_index + offset (3) + insn_len (1) + relative_value (from byte at match_index+3).
        # We'll force pt.size_ = 1.
        # Place pattern at match index 10.
        # In the test buffer, we must supply an 8-byte region starting at index 10 matching the pattern.
        # For token0: buffer[10] must be 0xFF.
        # For token1: with mask 0x0F, we choose 0x2F (0x2F & 0x0F == 0x0F).
        # For token2: with mask 0xF0, choose 0x8A (0x8A & 0xF0 == 0x80).
        # For token3 (marker wildcard): we want relative value = 0x4B.
        # For token4: fixed 0x4B.
        # For tokens 5-7 (padding): 0.
        region = bytearray([0xFF, 0x2F, 0x8A, 0x4B, 0x4B] + [0] * 3)  # total 8 bytes
        buffer = bytearray(30)
        buffer[10 : 10 + 8] = region
        test_bytes = bytes(buffer)
        pattern_str = "FF ?F 8? X1 4B /d"
        pt = rtpattern(pattern_str)
        pt.size_ = 1
        result = pt.find(test_bytes)
        expected = 10 + 3 + 1 + 0x4B  # 10+3+1+75 = 89
        self.assertEqual(
            result,
            expected,
            f"Expected complex combination result {expected}, got {result}",
        )

    def test_instruction_dereference(self):
        # Pattern:
        # "FE ED FA CE E8 X4 ? ? ? ? EF BE AD DE /da"
        #
        # Breakdown:
        # - Tokens:
        #     0: FE
        #     1: ED
        #     2: FA
        #     3: CE
        #     4: E8
        #     Marker "X4": sets offset_ = 5 and insn_len_ = 4,
        #         and inserts 4 wildcard tokens (tokens 5-8).
        #     Then four explicit wildcards: tokens 9-12.
        #     Then tokens: EF, BE, AD, DE: tokens 13-16.
        # - Options /da: sets both dereference (d) and alignment (a).
        #
        # In dereference mode, get_result returns:
        #     result = match_index + offset_ + insn_len_ + relative_value
        # With offset_ = 5 and insn_len_ = 4, if we supply relative_value = 0, then:
        #     expected = match_index + 9.
        #
        # Since /a causes the scan to check only indices that are multiples of ALIGN_SIZE (8),
        # we place the pattern at an aligned index. Here we choose match_index = 16.
        # Thus expected = 16 + 9 = 25.
        pattern_str = "FE ED FA CE E8 X4 ? ? ? ? EF BE AD DE /da"
        pt = rtpattern(pattern_str)
        # Default pt.size_ is 4, so relative value is read from 4 bytes.
        match_index = 16  # must be 8-aligned
        expected = match_index + 5 + 4 + 0  # 16 + 9 = 25

        # Create a buffer large enough (at least match_index + pattern length).
        # Our padded pattern length is 24 bytes.
        buffer = bytearray(40)
        # Build the 24-byte region that should match:
        region = bytearray(24)
        # Tokens 0-4: fixed bytes.
        region[0] = 0xFE
        region[1] = 0xED
        region[2] = 0xFA
        region[3] = 0xCE
        region[4] = 0xE8
        # Tokens 5-8: inserted wildcards from the marker; set to 0 for relative_value = 0.
        for j in range(5, 9):
            region[j] = 0x00
        # Tokens 9-12: explicit wildcards; set to 0.
        for j in range(9, 13):
            region[j] = 0x00
        # Tokens 13-16: fixed bytes EF, BE, AD, DE.
        region[13] = 0xEF
        region[14] = 0xBE
        region[15] = 0xAD
        region[16] = 0xDE
        # Tokens 17-23: padding zeros.
        for j in range(17, 24):
            region[j] = 0x00

        # Insert the region into the buffer at match_index.
        buffer[match_index : match_index + 24] = region
        test_bytes = bytes(buffer)
        result = pt.find(test_bytes)
        self.assertEqual(
            result,
            expected,
            f"Expected instruction dereference result {expected}, got {result}",
        )


# ---- Example usage ----
if __name__ == "__main__":
    unittest.main()
