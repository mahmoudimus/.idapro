import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, NamedTuple, Optional

import capstone

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- Helper Classes ---
class MatchResult(NamedTuple):
    """Result of a pattern match operation."""

    matched: bool
    start_offset: int = 0
    end_offset: int = 0
    groups: Dict[str, bytes] = {}
    instructions: List[capstone.CsInsn] = []


# --- Enum for Pattern Categories ---
class PatternCategory(Enum):
    MULTI_PART = auto()
    SINGLE_PART = auto()
    JUNK = auto()


# --- Dataclass for Pattern Metadata ---
class PatternMetadata:
    """Base class for instruction pattern metadata."""

    def __init__(
        self, category: PatternCategory, description: str = "", original_regex: str = ""
    ):
        self.category = category
        self.description = description
        self.original_regex = original_regex


class MultiPartPatternMetadata(PatternMetadata):
    """
    Metadata for multi-part jump patterns (pairs of conditional jumps).
    'category' will be set to PatternCategory.MULTI_PART by default internally.
    """

    def __init__(
        self,
        first_jump_opcode: int,
        second_jump_opcode: int,
        description: str = "",
        original_regex: str = "",
    ):
        super().__init__(
            category=PatternCategory.MULTI_PART,
            description=description,
            original_regex=original_regex,
        )
        self.first_jump_opcode = first_jump_opcode
        self.second_jump_opcode = second_jump_opcode


class SinglePartPatternMetadata(PatternMetadata):
    """Metadata for single-part patterns (prefix + optional padding + jump)."""

    def __init__(
        self,
        prefix_opcodes: List[int],
        jump_opcode: int,
        description: Optional[str] = None,
        original_regex: Optional[str] = None,
    ):
        super().__init__(
            category=PatternCategory.SINGLE_PART,
            description=description or "",
            original_regex=original_regex or "",
        )
        self.prefix_opcodes = prefix_opcodes
        self.jump_opcode = jump_opcode


class JunkPatternMetadata(PatternMetadata):
    """Metadata for junk instruction patterns."""

    def __init__(
        self,
        description: Optional[str] = None,
        original_regex: Optional[str] = None,
    ):
        super().__init__(
            category=PatternCategory.JUNK,
            description=description or "",
            original_regex=original_regex or "",
        )


# --- Capstone Disassembly Helper ---
class DisassemblyEngine:
    """Wrapper around Capstone for x86 disassembly."""

    def __init__(self):
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs.detail = True

    def disassemble(self, code: bytes, offset: int = 0) -> List[capstone.CsInsn]:
        """Disassemble bytes into instruction objects."""
        try:
            return list(self.cs.disasm(code, offset))
        except Exception as e:
            logger.warning("Disassembly failed: %s", e)
            return []


# --- Global disassembly engine instance ---
disasm = DisassemblyEngine()


# --- Padding Pattern Detection ---
def is_padding_instruction(insn: capstone.CsInsn) -> bool:
    """
    Check if instruction is padding/junk.

    Original regex: rb"(?:\xc0[\xe0-\xff]\x00|(?:\x86|\x8a)[\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff])"

    Matches:
    - 3-byte SHL reg, 0 with random register encoding
    - 2-byte XCHG or MOV instruction with specific register encodings
    """
    if not insn:
        return False

    # Check for SHL reg, 0 (3-byte instruction)
    if (
        insn.id == capstone.x86.X86_INS_SHL
        and len(insn.bytes) == 3
        and insn.bytes[0] == 0xC0
        and 0xE0 <= insn.bytes[1] <= 0xFF
        and insn.bytes[2] == 0x00
    ):
        return True

    # Check for XCHG or MOV with specific encodings
    if (
        insn.id in [capstone.x86.X86_INS_XCHG, capstone.x86.X86_INS_MOV]
        and len(insn.bytes) == 2
        and insn.bytes[0] in [0x86, 0x8A]
        and insn.bytes[1] in [0xC0, 0xC9, 0xD2, 0xDB, 0xE4, 0xED, 0xF6, 0xFF]
    ):
        return True

    return False


def find_padding_sequence(
    instructions: List[capstone.CsInsn], start_idx: int = 0
) -> int:
    """
    Find length of padding sequence starting at given index.

    Args:
        instructions: List of disassembled instructions
        start_idx: Starting index to check for padding

    Returns:
        Number of consecutive padding instructions found
    """
    count = 0
    for i in range(start_idx, len(instructions)):
        if is_padding_instruction(instructions[i]):
            count += 1
        else:
            break
    return count


# --- Multi-Part Pattern Functions ---
def detect_jo_jno_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JO ... JNO pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x70.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x71.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    # Look for JO followed by optional padding and JNO
    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JO
            and len(instructions[i].bytes) == 2
        ):

            # Find end of padding
            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNO
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                # Calculate byte offsets
                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jno_jo_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JNO ... JO pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x71.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x70.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JNO
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JO
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jb_jae_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JB ... JAE pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x72.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x73.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JB
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JAE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jae_jb_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JAE ... JB pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x73.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x72.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JAE
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JB
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_je_jne_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JE ... JNE pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x74.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x75.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JE
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jne_je_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JNE ... JE pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x75.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x74.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JNE
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jbe_ja_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JBE ... JA pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x76.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x77.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JBE
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JA
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_ja_jbe_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JA ... JBE pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x77.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x76.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JA
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JBE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_js_jns_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JS ... JNS pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x78.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x79.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JS
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNS
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jns_js_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JNS ... JS pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x79.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x78.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JNS
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JS
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jp_jnp_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JP ... JNP pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x7a.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7b.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JP
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNP
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jnp_jp_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JNP ... JP pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x7b.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7a.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JNP
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JP
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jl_jge_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JL ... JGE pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x7c.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7d.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JL
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JGE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jge_jl_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JGE ... JL pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x7d.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7c.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JGE
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JL
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jle_jg_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JLE ... JG pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x7e.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7f.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JLE
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JG
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_jg_jle_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect JG ... JLE pattern with optional padding.

    Original regex: rb"(?P<first_jump>\x7f.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7e.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_JG
            and len(instructions[i].bytes) == 2
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JLE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "first_jump": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "second_jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


# --- Single-Part Pattern Functions ---
def detect_or_al_0_jno_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect OR AL, 0x00 ... JNO pattern with optional padding.

    Original regex: rb"(?P<prefix>\x0c\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_OR
            and len(instructions[i].bytes) == 2
            and instructions[i].bytes == b"\x0c\x00"
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNO
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_or_al_0_jae_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect OR AL, 0x00 ... JAE pattern with optional padding.

    Original regex: rb"(?P<prefix>\x0c\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_OR
            and len(instructions[i].bytes) == 2
            and instructions[i].bytes == b"\x0c\x00"
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JAE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_and_al_ff_jno_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect AND AL, 0xFF ... JNO pattern with optional padding.

    Original regex: rb"(?P<prefix>\x24\xff)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_AND
            and len(instructions[i].bytes) == 2
            and instructions[i].bytes == b"\x24\xff"
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNO
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_and_al_ff_jae_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect AND AL, 0xFF ... JAE pattern with optional padding.

    Original regex: rb"(?P<prefix>\x24\xff)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_AND
            and len(instructions[i].bytes) == 2
            and instructions[i].bytes == b"\x24\xff"
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JAE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_xor_al_0_jno_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect XOR AL, 0x00 ... JNO pattern with optional padding.

    Original regex: rb"(?P<prefix>\x34\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_XOR
            and len(instructions[i].bytes) == 2
            and instructions[i].bytes == b"\x34\x00"
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JNO
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_xor_al_0_jae_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect XOR AL, 0x00 ... JAE pattern with optional padding.

    Original regex: rb"(?P<prefix>\x34\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_XOR
            and len(instructions[i].bytes) == 2
            and instructions[i].bytes == b"\x34\x00"
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JAE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_clc_jae_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect CLC ... JAE pattern with optional padding.

    Original regex: rb"(?P<prefix>\xf8)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_CLC
            and len(instructions[i].bytes) == 1
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JAE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_stc_jb_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect STC ... JB pattern with optional padding.

    Original regex: rb"(?P<prefix>\xf9)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x72.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_STC
            and len(instructions[i].bytes) == 1
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JB
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_stc_jbe_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect STC ... JBE pattern with optional padding.

    Original regex: rb"(?P<prefix>\xf9)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x76.)"
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_STC
            and len(instructions[i].bytes) == 1
        ):

            padding_len = find_padding_sequence(instructions, i + 1)
            next_insn_idx = i + 1 + padding_len

            if (
                next_insn_idx < len(instructions)
                and instructions[next_insn_idx].id == capstone.x86.X86_INS_JBE
                and len(instructions[next_insn_idx].bytes) == 2
            ):

                start_offset = instructions[i].address - offset
                end_offset = (
                    instructions[next_insn_idx].address
                    + instructions[next_insn_idx].size
                    - offset
                )

                groups = {
                    "prefix": instructions[i].bytes,
                    "padding": b"".join(
                        insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                    ),
                    "jump": instructions[next_insn_idx].bytes,
                }

                return MatchResult(
                    True,
                    start_offset,
                    end_offset,
                    groups,
                    instructions[i : next_insn_idx + 1],
                )

    return MatchResult(False)


def detect_cmp_esp_ja_pattern(code: bytes, offset: int = 0) -> MatchResult:
    """
    Detect CMP ESP,0x1C00 ... JA/JAE pattern with optional padding.

    Original regex: rb"(?P<prefix>[\x80\x81\x83]\xfc\x00...)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>(\x77|\x73).)"

    This pattern checks ESP against a value that's always "above" on a real Win x64 stack.
    """
    instructions = disasm.disassemble(code, offset)
    if len(instructions) < 2:
        return MatchResult(False)

    for i in range(len(instructions) - 1):
        if (
            instructions[i].id == capstone.x86.X86_INS_CMP
            and len(instructions[i].operands) >= 2
            and instructions[i].operands[0].reg == capstone.x86.X86_REG_ESP
        ):

            # Check if this matches the specific encoding pattern
            if (
                len(instructions[i].bytes) >= 3
                and instructions[i].bytes[0] in [0x80, 0x81, 0x83]
                and instructions[i].bytes[1] == 0xFC
                and instructions[i].bytes[2] == 0x00
            ):

                padding_len = find_padding_sequence(instructions, i + 1)
                next_insn_idx = i + 1 + padding_len

                if (
                    next_insn_idx < len(instructions)
                    and instructions[next_insn_idx].id
                    in [capstone.x86.X86_INS_JA, capstone.x86.X86_INS_JAE]
                    and len(instructions[next_insn_idx].bytes) == 2
                ):

                    start_offset = instructions[i].address - offset
                    end_offset = (
                        instructions[next_insn_idx].address
                        + instructions[next_insn_idx].size
                        - offset
                    )

                    groups = {
                        "prefix": instructions[i].bytes,
                        "padding": b"".join(
                            insn.bytes for insn in instructions[i + 1 : next_insn_idx]
                        ),
                        "jump": instructions[next_insn_idx].bytes,
                    }

                    return MatchResult(
                        True,
                        start_offset,
                        end_offset,
                        groups,
                        instructions[i : next_insn_idx + 1],
                    )

    return MatchResult(False)


# --- Pattern Registry ---
MULTI_PART_PATTERNS = [
    MultiPartPatternMetadata(
        first_jump_opcode=capstone.x86.X86_INS_JO,
        second_jump_opcode=capstone.x86.X86_INS_JNO,
        description="JO ... JNO",
        original_regex=rb"(?P<first_jump>\x70.)(?P<padding>"
        + rb"...)*(?P<second_jump>\x71.)",
    ),
    MultiPartPatternMetadata(
        first_jump_opcode=capstone.x86.X86_INS_JNO,
        second_jump_opcode=capstone.x86.X86_INS_JO,
        description="JNO ... JO",
        original_regex=rb"(?P<first_jump>\x71.)(?P<padding>"
        + rb"...)*(?P<second_jump>\x70.)",
    ),
    # Add remaining patterns here...
]

SINGLE_PART_PATTERNS = [
    SinglePartPatternMetadata(
        prefix_opcodes=[capstone.x86.X86_INS_OR],
        jump_opcode=capstone.x86.X86_INS_JNO,
        description="OR AL, 0x00 ... JNO",
        original_regex=rb"(?P<prefix>\x0C\x00)(?P<padding>...)?(?P<jump>\x71.)",
    ),
    # Add remaining patterns here...
]


# --- Main Pattern Detection Function ---
def detect_all_patterns(code: bytes, offset: int = 0) -> List[MatchResult]:
    """
    Scan code for all known obfuscation patterns.

    Args:
        code: Raw machine code bytes to analyze
        offset: Base address offset for result calculations

    Returns:
        List of MatchResult objects for all detected patterns
    """
    results = []

    # Multi-part patterns
    pattern_funcs = [
        detect_jo_jno_pattern,
        detect_jno_jo_pattern,
        detect_jb_jae_pattern,
        detect_jae_jb_pattern,
        detect_je_jne_pattern,
        detect_jne_je_pattern,
        detect_jbe_ja_pattern,
        detect_ja_jbe_pattern,
        detect_js_jns_pattern,
        detect_jns_js_pattern,
        detect_jp_jnp_pattern,
        detect_jnp_jp_pattern,
        detect_jl_jge_pattern,
        detect_jge_jl_pattern,
        detect_jle_jg_pattern,
        detect_jg_jle_pattern,
    ]

    # Single-part patterns
    pattern_funcs.extend(
        [
            detect_or_al_0_jno_pattern,
            detect_or_al_0_jae_pattern,
            detect_and_al_ff_jno_pattern,
            detect_and_al_ff_jae_pattern,
            detect_xor_al_0_jno_pattern,
            detect_xor_al_0_jae_pattern,
            detect_clc_jae_pattern,
            detect_stc_jb_pattern,
            detect_stc_jbe_pattern,
            detect_cmp_esp_ja_pattern,
        ]
    )

    for func in pattern_funcs:
        try:
            result = func(code, offset)
            if result.matched:
                results.append(result)
                logger.info("Detected pattern: %s", func.__name__)
        except Exception as e:
            logger.warning("Pattern detection failed for %s: %s", func.__name__, e)

    return results


if __name__ == "__main__":
    text = ida_segment.get_segm_by_name(".text")
    codez = ida_bytes.get_bytes(text.start_ea, text.size())
    detect_all_patterns(codez)
