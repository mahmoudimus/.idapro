import binascii
import re
import typing
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Literal

import idc

UnsignedByte = Annotated[int, "0 <= x < 256"]
ByteElement = Annotated[
    list[Literal[-1] | UnsignedByte], "list of bytes or -1 for wildcard"
]
BytesData = ByteElement | bytes | bytearray


# Assuming PatternCategory is an Enum defined elsewhere
class PatternCategory(Enum):
    FUNCTION_PADDING = 1


@dataclass
class RegexPatternMetadata:
    category: PatternCategory
    pattern: bytes
    description: typing.Optional[str] = None
    compiled: typing.Optional[typing.Pattern] = None

    def compile(self, flags=0):
        if self.compiled is None:
            self.compiled = re.compile(self.pattern, flags)
        return self.compiled

    @property
    def group_names(self):
        return self.compile().groupindex


class MemHelper:

    def __init__(self, start: int, end: int, mem_results: bytes = b""):
        self.mem_results = mem_results
        self.mem_offsets = []
        self.start = start
        self.end = end
        if not self.mem_results:
            self._get_memory(start, end)

    def _get_memory(self, start: int, end: int):
        result = idc.get_bytes(start, end - start)
        self.mem_results = result
        self.mem_offsets.append((start, end - start))


def process_hex_pair(pair: str) -> bytes:
    """
    Convert a two-character hex pair that may contain wildcards to a regex pattern in bytes.

    - "??" is translated to b'.' (any byte).
    - A pair without wildcards is converted to its literal byte.
    - A pair with a single "?" (e.g., "1?" or "?F") creates a regex character class
      matching any allowed byte for that nibble.
    """
    if pair == "??":
        return b"."
    elif "?" not in pair:
        try:
            byte_val = int(pair, 16)
        except ValueError:
            raise ValueError(f"Invalid hex pair: {pair}")
        # Convert the literal byte into a regex-safe form.
        return re.escape(bytes([byte_val]))
    else:
        if len(pair) != 2:
            raise ValueError("Each hex pair must have exactly two characters.")

        # Determine allowed values for the high nibble.
        if pair[0] == "?":
            high_nibbles = list(range(16))
        else:
            try:
                high_nibble = int(pair[0], 16)
            except ValueError:
                raise ValueError(f"Invalid hex digit: {pair[0]}")
            high_nibbles = [high_nibble]

        # Determine allowed values for the low nibble.
        if pair[1] == "?":
            low_nibbles = list(range(16))
        else:
            try:
                low_nibble = int(pair[1], 16)
            except ValueError:
                raise ValueError(f"Invalid hex digit: {pair[1]}")
            low_nibbles = [low_nibble]

        # Compute all allowed byte values for this pair.
        allowed = sorted({(h << 4) | l for h in high_nibbles for l in low_nibbles})

        # If the allowed bytes form a contiguous block, we can use a range.
        if allowed[-1] - allowed[0] == len(allowed) - 1:
            return (
                b"["
                + re.escape(bytes([allowed[0]]))
                + b"-"
                + re.escape(bytes([allowed[-1]]))
                + b"]"
            )
        else:
            # Otherwise, list them explicitly in a character class.
            return b"[" + b"".join(re.escape(bytes([val])) for val in allowed) + b"]"


def hex_pattern_to_regex(hex_pattern: str) -> bytes:
    """
    Convert a hex string (with wildcards) to a regex pattern in bytes.

    Acceptable wildcards:
      - "??" matches any byte.
      - A single "?" surrounded by spaces is equivalent to "??"
      - A single "?" in a hex pair (e.g., "1?" or "?F") matches any nibble in that position.

    Spaces in the input are ignored.
    """
    # Remove spaces and ensure even number of characters.
    hex_pattern = "".join(
        ["??" if p == "?" else p for p in hex_pattern.split(" ") if p]
    )
    if len(hex_pattern) % 2 != 0:
        raise ValueError(
            "Hex pattern length must be even (each byte consists of two hex digits)."
        )

    pattern_parts = []
    for i in range(0, len(hex_pattern), 2):
        pair = hex_pattern[i : i + 2]
        pattern_parts.append(process_hex_pair(pair))
    return b"".join(pattern_parts)


def bytes_to_hex_pattern(bytes_data: BytesData) -> str:
    """
    Convert a `BytesData` type to a hex string with wildcards.

    Acceptable wildcards:
      - `-1` represents any byte.

    This function enforces that bytes_data is either a list of ints (each either -1 or an unsigned byte),
    a bytes object, or a bytearray. In the case of a list, each -1 is converted to "??" (a wildcard)
    and each valid byte is formatted as a two-digit uppercase hex value.

    The constructed hex string is then processed by `hex_pattern_to_regex`
    and the result is returned as a string.
    """
    if not (
        isinstance(bytes_data, (bytes, bytearray))
        or (
            isinstance(bytes_data, list)
            and all(isinstance(b, int) and -1 <= b < 256 for b in bytes_data)
        )
    ):
        raise TypeError(
            "bytes_data must be a list of ints (-1 or 0-255), bytes, or bytearray"
        )

    # Convert each byte to a two-digit uppercase hex string, but for -1, use "??".
    hex_str = " ".join("??" if b == -1 else f"{b:02X}" for b in bytes_data)
    return hex_str


def find_all_hex_pattern_offsets(data: bytes, hex_pattern: str) -> list:
    """
    Search for the hex pattern (with wildcards) in the given binary data.

    Returns a list of offsets (indices) where the pattern is found.
    """
    regex_bytes = hex_pattern_to_regex(hex_pattern)
    # Compile the regex with DOTALL so that '.' matches any byte.
    pattern = re.compile(regex_bytes, re.DOTALL)

    return find_all_pattern_offsets(data, pattern)


def find_all_pattern_offsets(data: bytes, pattern: re.Pattern) -> list:
    # Use finditer to locate all matches.
    return [match.start() for match in pattern.finditer(data)]
