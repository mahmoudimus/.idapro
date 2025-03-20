import re


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


def nibble_to_regex(token: str) -> str:
    """
    Convert a two-character token (which may include '?' wildcards)
    into a regex snippet matching one raw byte.
    """
    if token == "??":
        return "."
    if "?" not in token:
        return f"\\x{token}"
    possibilities = []
    for byte in range(256):
        hex_byte = f"{byte:02X}"
        ok = True
        for i in range(2):
            if token[i] != "?" and token[i] != hex_byte[i]:
                ok = False
                break
        if ok:
            possibilities.append(f"\\x{hex_byte}")
    if not possibilities:
        raise ValueError(f"No possible byte matches token {token}")
    if len(possibilities) == 1:
        return possibilities[0]
    return f"(?:{'|'.join(possibilities)})"


def build_regex_from_tokens(tokens: list) -> re.Pattern:
    """
    Build the complete regex pattern from the list of tokens.
    """
    regex_str = "".join(nibble_to_regex(token) for token in tokens)
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


def token_to_regex(token: str) -> str:
    """
    Convert a token from the signature into a regex fragment.

    - If the token is a fixed two-digit hex value (like "48"), it returns "\x48".
    - If the token is a full wildcard (e.g. "?" or "??"), it returns "." (which will match any byte in DOTALL mode).
    - If the token is partially wildcarded (e.g. "4?" or "?C"), it enumerates all possible completions.
    """
    token = token.strip()
    # Normalize a lone "?" to "??"
    if token == "?":
        token = "??"

    if len(token) != 2:
        raise ValueError("Each token should be 2 characters after normalization.")

    # Fixed byte: no wildcards.
    if "?" not in token:
        return f"\\x{token.upper()}"

    # Full wildcard: "??"
    if token == "??":
        return "."

    # Partially wildcarded: enumerate possibilities.
    possibilities = []
    for byte in range(256):
        hex_byte = f"{byte:02X}"
        match = True
        for i in range(2):
            if token[i] != "?" and token[i].upper() != hex_byte[i]:
                match = False
                break
        if match:
            possibilities.append(f"\\x{hex_byte}")
    if len(possibilities) == 1:
        return possibilities[0]
    return f"(?:{'|'.join(possibilities)})"


def signature_to_regex(sig: bytes) -> str:
    """
    Convert a space-separated signature (as a bytes literal) into a regex pattern string.
    """
    # Decode and split on whitespace.
    tokens = sig.decode("ascii").split()
    regex_parts = [token_to_regex(tok) for tok in tokens]
    # Concatenate all parts (the regex should be compiled with DOTALL so that '.' matches any byte).
    return "".join(regex_parts)


# --- Example usage ---

signature = "48 C7 ? 24 ? ? ? ? ? ? ? ? ? 8D ? ? ? F4 FF 48 8B ? 24 ? ? ? ? 49 8D B9"

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

regex = refine_signature(signature, matching_stub, non_matching_stub)
print("Final regex pattern:", regex.pattern)

# Example signatures:
sig1 = b"48 C7  ? 24 ? ? ? ? ? ? ? ?  ? 8D  ? ? ? F4 FF 48 8B  ? 24 ? ? ? ?  ? 8D ?"
sig2 = b"48 C7 44 24 ? ? ? ? ?       48 8D 35 ? ?  ?  ? 48 8B 44 24 ? ? ? ?  ? 8D ?"

regex1 = signature_to_regex(sig1)
regex2 = signature_to_regex(sig2)

print("Regex for sig1:", regex1)
print("Regex for sig2:", regex2)
