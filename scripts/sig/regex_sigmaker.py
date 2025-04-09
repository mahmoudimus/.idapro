import binascii
import re


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


def extract_bytes_from_stub(stub: str) -> list:
    """
    Extract opcode bytes from a disassembly stub.
    This version splits each line at multiple spaces (to separate opcode bytes from the rest)
    and then filters tokens that are exactly two hex digits.
    """
    bytes_list = []
    for line in stub.splitlines():
        # Split on 2+ spaces to isolate the opcode bytes from the address/mnemonic.
        parts = re.split(r"\s\s+", line.strip())
        if not parts:
            continue
        # The first part should contain the address and the bytes.
        tokens = parts[0].split()
        # Remove a token that looks like an address (contains ':' or is longer than 4 chars).
        if tokens and (":" in tokens[0] or len(tokens[0]) > 4):
            tokens = tokens[1:]
        # Filter tokens that are exactly two hex digits.
        tokens = [tok for tok in tokens if re.fullmatch(r"[0-9A-Fa-f]{2}", tok)]
        bytes_list.extend(tokens)
    return bytes_list


def normalize_token(token: str) -> str:
    """
    Ensure each signature token is two characters.
    A lone "?" is normalized to "??".
    """
    token = token.strip()
    if token == "?":
        return "??"
    if len(token) == 1:
        return token.upper() + "?"
    return token.upper()


def refine_token(token: str, match_byte: str, non_match_byte: str) -> str:
    """
    For each nibble in a token that is a wildcard ('?'),
    fix it to the matching stub’s nibble if it differs from the non-matching stub.
    """
    refined = []
    for i in range(2):
        if token[i] == "?":
            if match_byte[i] != non_match_byte[i]:
                refined.append(match_byte[i])
            else:
                refined.append("?")
        else:
            refined.append(token[i])
    return "".join(refined)


def nibble_to_regex(token: str) -> bytes:
    """
    Convert a two-character token (which may include '?' wildcards)
    into a regex snippet matching one raw byte.
    """
    token = token.encode("utf-8")
    if token == b"??":
        return b"."
    if b"?" not in token:
        return b"\\x" + token

    possibilities = []

    for byte in range(256):
        hex_byte = f"{byte:02X}".encode("utf-8")
        ok = True
        for i in range(2):
            if token[i] != b"?"[0] and token[i] != hex_byte[i]:
                ok = False
                break
        if ok:
            possibilities.append(b"\\x" + hex_byte)
    if not possibilities:
        raise ValueError(f"No possible byte matches token {token}")

    if len(possibilities) == 1:
        return possibilities[0]
    return b"(?:" + b"|".join(possibilities) + b")"


def build_regex_from_tokens(tokens: list) -> re.Pattern:
    """
    Build the complete regex pattern from the list of tokens.
    """
    regex_str = b"".join(nibble_to_regex(token) for token in tokens)
    return re.compile(regex_str, re.DOTALL)


def refine_signature(
    signature_str: str, matching_stub: str, non_matching_stub: str
) -> re.Pattern:
    """
    Given:
      - signature_str: the space‑separated signature tokens
      - matching_stub: a disassembly stub that should match
      - non_matching_stub: a disassembly stub that should NOT match

    This function refines the signature’s wildcard tokens so that the resulting regex,
    when applied to the extracted bytes, accepts the matching stub and rejects the non‑matching stub.
    If the stubs do not contain enough bytes compared to the signature tokens,
    it trims the signature to the minimum available length.
    """
    tokens = [normalize_token(tok) for tok in signature_str.split()]

    matching_bytes = extract_bytes_from_stub(matching_stub)
    non_matching_bytes = extract_bytes_from_stub(non_matching_stub)

    # Determine the common length available.
    min_length = min(len(matching_bytes), len(non_matching_bytes), len(tokens))
    if min_length < len(tokens):
        print(
            f"Warning: Trimming signature tokens from {len(tokens)} to {min_length} due to stub length mismatch."
        )
        tokens = tokens[:min_length]
        matching_bytes = matching_bytes[:min_length]
        non_matching_bytes = non_matching_bytes[:min_length]

    refined_tokens = []
    for i, token in enumerate(tokens):
        m_byte = matching_bytes[i].upper()
        n_byte = non_matching_bytes[i].upper()
        if "?" in token:
            refined = refine_token(token, m_byte, n_byte)
            refined_tokens.append(refined)
        else:
            refined_tokens.append(token)

    regex_pattern = build_regex_from_tokens(refined_tokens)

    # Verify against the stubs.
    m_stub_bytes = bytes(int(b, 16) for b in matching_bytes[:min_length])
    n_stub_bytes = bytes(int(b, 16) for b in non_matching_bytes[:min_length])

    if not regex_pattern.search(m_stub_bytes):
        raise ValueError("Refined regex does not match the matching stub!")
    if regex_pattern.search(n_stub_bytes):
        raise ValueError("Refined regex still matches the non-matching stub!")

    return regex_pattern


def token_to_regex(token: bytes) -> bytes:
    """
    Convert a token from the signature into a regex fragment.

    - If the token is a fixed two-digit hex value (like "48"), it returns "\x48".
    - If the token is a full wildcard (e.g. "?" or "??"), it returns "." (which will match any byte in DOTALL mode).
    - If the token is partially wildcarded (e.g. "4?" or "?C"), it enumerates all possible completions.
    """
    token = token.strip()
    # Normalize a lone "?" to "??"
    if token == b"?":
        token = b"??"

    if len(token) != 2:
        raise ValueError("Each token should be 2 characters after normalization.")

    # Fixed byte: no wildcards.
    if b"?" not in token:
        return b"\\x" + token.upper()

    # Full wildcard: "??"
    if token == b"??":
        return b"."

    # Partially wildcarded: enumerate possibilities.
    possibilities = []
    for byte in range(256):
        hex_byte = f"{byte:02X}".encode("utf-8")
        match = True
        for i in range(2):
            if token[i] != b"?"[0] and token[i].upper() != hex_byte[i]:
                match = False
                break
        if match:
            possibilities.append(b"\\x" + hex_byte)
    if len(possibilities) == 1:
        return possibilities[0]
    # return f"(?:{'|'.join(possibilities)})"
    return b"(?:" + b"|".join(possibilities) + b")"


def signature_to_regex(sig: bytes) -> bytes:
    """
    Convert a space-separated signature (as a bytes literal) into a regex pattern string.
    """
    # Decode and split on whitespace.
    tokens = sig.split()
    regex_parts = [token_to_regex(tok) for tok in tokens]
    # Concatenate all parts (the regex should be compiled with DOTALL so that '.' matches any byte).
    return b"".join(regex_parts)


# --- Example usage ---

non_matching_stub = """
.text:00000001400B6473 48 C7 44 24 70 5B 15 00 00                          mov     [rsp+3D8h+var_368], 155Bh
.text:00000001400B647C 48 8D 35 7D 9B F4 FF                                lea     rsi, cs:140000000h
.text:00000001400B6483 48 8B 44 24 70                                      mov     rax, [rsp+3D8h+var_368]
.text:00000001400B6488 48 8D BE 7F A3 5B 02                                lea     rdi, rva g_bufCryptoKey[rsi]
"""

matching_stub = """
text:00000001400B5F8E 48 C7 84 24 90 00 00 00 42 EF FF FF                 mov     [rsp+3D8h+var_348], 0FFFFFFFFFFFFEF42h
.text:00000001400B5F9A 4C 8D 0D 5F A0 F4 FF                               lea     r9, __ImageBase
.text:00000001400B5FA1 48 8B 84 24 90 00 00 00                            mov     rax, [rsp+3D8h+var_348]
.text:00000001400B5FA9 49 8D B9 99 61 CD 03                               lea     rdi, rva byte_143CD6199[r9]
"""

data = binascii.a2b_hex(
    "48 C7 84 24 90 00 00 00 42 EF FF FF 4C 8D 0D 5F A0 F4 FF 48 8B 84 24 90 00 00 00 49 8D B9 99 61 CD 03".replace(
        " ", ""
    )
)
print(data.hex())

signature = "48 C7 ? 24 ? ? ? ? ? ? ? ? ? 8D ? ? ? F4 FF 48 8B ? 24 ? ? ? ? 49 8D B9"
regex = refine_signature(signature, matching_stub, non_matching_stub)
print("Final regex pattern:", regex.pattern)

# Example signatures:
sig1 = b"48 C7  ? 24 ? ? ? ? ? ? ? ?  ? 8D  ? ? ? F4 FF 48 8B  ? 24 ? ? ? ?  ? 8D ?"
sig2 = b"48 C7 44 24 ? ? ? ? ?       48 8D 35 ? ?  ?  ? 48 8B 44 24 ? ? ? ?  ? 8D ?"

regex1 = signature_to_regex(sig1)
regex2 = signature_to_regex(sig2)

print("Regex for sig1:", regex1)
print("Regex for sig2:", regex2)

print((pos := find_all_pattern_offsets(data, re.compile(regex1, re.DOTALL))))
assert pos == [0]
print((pos := find_all_pattern_offsets(data, re.compile(regex2, re.DOTALL))))
assert pos == []

print((pos := find_all_hex_pattern_offsets(data, signature)))
assert pos == [0]
print((pos := find_all_hex_pattern_offsets(data, sig1.decode("utf-8"))))
assert pos == [0]
print((pos := find_all_hex_pattern_offsets(data, sig2.decode("utf-8"))))
assert pos == []
