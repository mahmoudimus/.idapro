# fmt: off
import collections
import itertools
import re
import struct
import typing
from dataclasses import dataclass, field
from enum import Enum, auto

# Import necessary IDA modules
import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_nalt
import ida_problems
import ida_segment
import ida_ua
import idaapi
import idc

# --- Constants ---
CONDITIONAL_JUMPS = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
ALL_JUMPS = CONDITIONAL_JUMPS + [ida_allins.NN_jmp]
CONDITIONAL_JUMPS_MNEMONICS = [
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "jrcxz", "je", "jg",
    "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng",
    "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe",
    "jpo", "js", "jz",
]

# Reusable Padding Pattern (raw bytes)
PADDING_PATTERN = rb"(?:\xC0[\xE0-\xFF]\x00|(?:\x86|\x8A)[\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF])"

SUPERFLULOUS_BYTE = 0xF4
# Opcode sets exactly as provided in the original script
SINGLE_BYTE_OPCODE_SET = {
    129, 5, 13, 21, 29, 160, 161, 162, 163, 37, 169, 45, 53,
    184, 185, 186, 187, 188, 61, 189, 190, 191, 199, 200, 104,
    232, 233, 105, 247
}
MED_OPCODE_SET = {
    0, 1, 2, 3, 132, 133, 134, 135, 8, 9, 10, 11, 136, 137, 138,
    15, 16, 17, 18, 19, 139, 140, 141, 142, 24, 25, 26, 27, 128,
    131, 160, 161, 162, 163, 32, 33, 34, 35, 40, 41, 42, 43, 48,
    49, 50, 51, 56, 57, 58, 59, 143, 107, 246
}
BIG_OPCODE_SET = {128, 129, 192, 131, 193, 105, 107, 246}
# fmt: on

# --- Pattern Definitions ---


class PatternCategory(Enum):
    MULTI_PART = auto()
    SINGLE_PART = auto()
    JUNK = auto()
    BIG_INSTRUCTION = auto()  # Added for clarity in MatchSegment


@dataclass
class RegexPatternMetadata:
    category: PatternCategory
    pattern: bytes
    description: typing.Optional[str] = None
    compiled: typing.Optional[typing.Pattern] = None

    def compile(self, flags=0):
        if self.compiled is None:
            # Use re.DOTALL by default as many patterns use '.'
            self.compiled = re.compile(self.pattern, flags | re.DOTALL)
        return self.compiled

    @property
    def group_names(self):
        return self.compile().groupindex


@dataclass
class MultiPartPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = field(default=PatternCategory.MULTI_PART, init=False)

    def __post_init__(self):
        _ = self.compile()
        required_groups = {"first_jump", "padding", "second_jump"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError(f"MultiPart pattern missing required groups: {missing}")


@dataclass
class SinglePartPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = field(default=PatternCategory.SINGLE_PART, init=False)

    def __post_init__(self):
        _ = self.compile()
        required_groups = {"prefix", "padding", "jump"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError(f"SinglePart pattern missing required groups: {missing}")


@dataclass
class JunkPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = field(default=PatternCategory.JUNK, init=False)

    def __post_init__(self):
        _ = self.compile()
        required_groups = {"junk"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError("Junk pattern must have a 'junk' group.")


# Define patterns using the dataclasses
# (Pattern definitions exactly as provided in the original script)

# Multi-part jump patterns: pairs of conditional jumps with optional padding
MULTI_PART_PATTERNS = [
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x70.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x71.)",
        "JO ... JNO",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x71.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x70.)",
        "JNO ... JO",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x72.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x73.)",
        "JB ... JAE",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x73.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x72.)",
        "JAE ... JB",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x74.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x75.)",
        "JE ... JNE",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x75.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x74.)",
        "JNE ... JE",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x76.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x77.)",
        "JBE ... JA",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x77.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x76.)",
        "JA ... JBE",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x78.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x79.)",
        "JS ... JNS",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x79.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x78.)",
        "JNS ... JS",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x7A.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x7B.)",
        "JP ... JNP",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x7B.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x7A.)",
        "JNP ... JP",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x7C.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x7D.)",
        "JL ... JGE",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x7D.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x7C.)",
        "JGE ... JL",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x7E.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x7F.)",
        "JLE ... JG",
    ),
    MultiPartPatternMetadata(
        rb"(?P<first_jump>\x7F.)(?P<padding>"
        + PADDING_PATTERN
        + rb")*(?P<second_jump>\x7E.)",
        "JG ... JLE",
    ),
]

# Single-part jump patterns: prefix instruction + optional padding + conditional jump
SINGLE_PART_PATTERNS = [
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF8)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "CLC ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF9)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x76.)",
        "STC ... JBE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF9)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x72.)",
        "STC ... JB",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xA8.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "TEST AL, imm8 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xA9....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "TEST EAX, imm32 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF6..)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "TEST r/m8, imm8 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF7.....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "TEST r/m32, imm32 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x84.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "TEST r/m8, r8 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x85.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "TEST r/m32, r32 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xA8.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "TEST AL, imm8 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xA9....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "TEST EAX, imm32 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF6..)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "TEST r/m8, imm8 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\xF7.....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "TEST r/m32, imm32 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x84.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "TEST r/m8, r8 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x85.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "TEST r/m32, r32 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x80[\xE0-\xE7]\xFF)(?P<padding>"
        + PADDING_PATTERN
        + rb")?(?P<jump>\x71.)",
        "AND r/m8, 0xFF ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x24\xFF)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "AND AL, 0xFF ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x80[\xC8-\xCF]\x00)(?P<padding>"
        + PADDING_PATTERN
        + rb")?(?P<jump>\x71.)",
        "OR r/m8, 0x00 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x0C\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "OR AL, 0x00 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x80[\xF0-\xF7]\x00)(?P<padding>"
        + PADDING_PATTERN
        + rb")?(?P<jump>\x71.)",
        "XOR r/m8, 0x00 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x34\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)",
        "XOR AL, 0x00 ... JNO",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x80[\xE0-\xE7]\xFF)(?P<padding>"
        + PADDING_PATTERN
        + rb")?(?P<jump>\x73.)",
        "AND r/m8, 0xFF ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x24\xFF)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "AND AL, 0xFF ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x80[\xC8-\xCF]\x00)(?P<padding>"
        + PADDING_PATTERN
        + rb")?(?P<jump>\x73.)",
        "OR r/m8, 0x00 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x0C\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "OR AL, 0x00 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x80[\xF0-\xF7]\x00)(?P<padding>"
        + PADDING_PATTERN
        + rb")?(?P<jump>\x73.)",
        "XOR r/m8, 0x00 ... JAE",
    ),
    SinglePartPatternMetadata(
        rb"(?P<prefix>\x34\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)",
        "XOR AL, 0x00 ... JAE",
    ),
]


JUNK_PATTERNS = [
    JunkPatternMetadata(rb"(?P<junk>\x0F\x31)", "RDTSC"),
    JunkPatternMetadata(
        rb"(?P<junk>\x0F[\x80-\x8F]..[\x00\x01]\x00)", "TwoByte Conditional Jump"
    ),
    JunkPatternMetadata(rb"(?P<junk>\xE8..[\x00\x01]\x00)", "Invalid CALL"),
    JunkPatternMetadata(rb"(?P<junk>\x81[\xC0-\xC3\xC5-\xC7]....)", "ADD reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x80[\xC0-\xC3\xC5-\xC7].)", "ADD reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\x83[\xC0-\xC3\xC5-\xC7].)", "ADD reg32, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\xC6[\xC0-\xC3\xC5-\xC7].)", "MOV reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\xC7[\xC0-\xC3\xC5-\xC7]....)", "MOV reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\xF6[\xD8-\xDB\xDD-\xDF])", "NEG reg8"),
    JunkPatternMetadata(rb"(?P<junk>\x80[\xE8-\xEB\xED-\xEF].)", "AND reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\x81[\xE8-\xEB\xED-\xEF]....)", "AND reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x68....)", "PUSH imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x6A.)", "PUSH imm8"),
    JunkPatternMetadata(rb"(?P<junk>[\x70-\x7F].)", "Random 112-127"),
    JunkPatternMetadata(rb"(?P<junk>[\x50-\x5F])", "Single-byte PUSH/POP"),
]

# --- Helper Functions ---


def format_addr(addr: int) -> str:
    """Return the address formatted as a string: 0x{address:X}"""
    return f"0x{addr:X}"


def clear_output():
    """Clears the IDA Output window."""
    form = ida_kernwin.find_widget("Output window")
    if form:
        ida_kernwin.activate_widget(form, True)
        ida_kernwin.process_ui_action("msglist:Clear")
    else:
        print("Could not find Output window.")


def is_x64():
    """Check if the current database is for x64."""
    return ida_ida.inf_is_64bit()


def get_text_segment_bounds() -> typing.Optional[typing.Tuple[int, int]]:
    """Gets the start and end addresses of the .text segment."""
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        # Try common alternatives like .textbss or CODE
        for name in [".textbss", "CODE"]:
            text_seg = ida_segment.get_segm_by_name(name)
            if text_seg:
                print(f"Note: Using segment '{name}' as code segment.")
                break
    if not text_seg:
        print("Error: Could not find a suitable code segment (.text, .textbss, CODE).")
        return None
    # Ensure segment end is exclusive for range operations
    return text_seg.start_ea, text_seg.end_ea


# --- Core Classes ---


class MemHelper:
    """Reads and stores memory for a given range."""

    def __init__(self, start: int, end: int):
        self.mem_results = b""
        self.start = start
        self.end = end
        self.length = end - start
        if self.length > 0:
            self._get_memory(start, end)
        else:
            print(
                f"Warning: Invalid memory range provided: {format_addr(start)} to {format_addr(end)}"
            )

    def _get_memory(self, start: int, end: int):
        """Reads bytes from the IDA database."""
        result = ida_bytes.get_bytes(start, end - start)
        if result is None:
            print(
                f"Error: Failed to read memory from {format_addr(start)} to {format_addr(end)}"
            )
            self.mem_results = b""
            self.length = 0
        else:
            self.mem_results = result

    def get_bytes_at(self, ea: int, size: int) -> typing.Optional[bytes]:
        """Safely gets bytes from the cached memory."""
        if not (self.start <= ea < self.end and self.start <= ea + size - 1 < self.end):
            return None
        offset = ea - self.start
        # Ensure the slice doesn't exceed buffer length
        if offset + size > len(self.mem_results):
            return None
        return self.mem_results[offset : offset + size]

    def get_byte_at(self, ea: int) -> typing.Optional[int]:
        """Safely gets a single byte from cached memory."""
        if not (self.start <= ea < self.end):
            return None
        offset = ea - self.start
        if offset >= len(self.mem_results):
            return None
        return self.mem_results[offset]


@dataclass(repr=False)
class PatchOperation:
    """Stores a patch operation (address and bytes)."""

    address: int
    byte_values: bytes

    def apply(self):
        """Applies the patch to the IDA database."""
        if not ida_bytes.patch_bytes(self.address, self.byte_values):
            print(
                f"Error: Failed to patch {len(self.byte_values)} bytes at {format_addr(self.address)}"
            )

    def __str__(self):
        """String representation with hex formatting."""
        hex_bytes = self.byte_values.hex().upper()
        if len(hex_bytes) > 16:
            hex_bytes = hex_bytes[:16] + "..."
        return f"{self.__class__.__name__}(address={format_addr(self.address)}, byte_values={hex_bytes})"

    __repr__ = __str__


class SegmentType(Enum):
    STAGE1_SINGLE = auto()
    STAGE1_MULTIPLE = auto()
    JUNK = auto()
    BIG_INSTRUCTION = auto()


@dataclass
class MatchSegment:
    """Represents a matched segment within a pattern chain."""

    start: int  # Offset relative to the base address of the MatchChain's MemHelper
    length: int
    description: str
    matched_bytes: bytes
    segment_type: SegmentType
    matched_groups: typing.Dict[str, typing.Union[str, bytes]] | None = None


class MatchChain:
    """Represents a sequence of matched segments (Stage1 + Junk + Big Instr)."""

    def __init__(self, base_address: int, segments: typing.List[MatchSegment] = None):
        self.base_address = base_address  # The start EA of the MemHelper block
        self.segments = segments or []

    def add_segment(self, segment: MatchSegment):
        self.segments.append(segment)

    def overall_start(self) -> int:
        """Absolute start address of the first segment."""
        return (
            self.segments[0].start + self.base_address
            if self.segments
            else self.base_address
        )

    def overall_length(self) -> int:
        """Total length from the start of the first segment to the end of the last."""
        if not self.segments:
            return 0
        first = self.segments[0]
        last = self.segments[-1]
        return (last.start + last.length) - first.start

    def overall_end(self) -> int:
        """Absolute end address (exclusive) of the last segment."""
        if not self.segments:
            return self.base_address
        last = self.segments[-1]
        return self.base_address + last.start + last.length

    def overall_matched_bytes(self) -> bytes:
        """Concatenated bytes of all segments in order. Reads from segments."""
        if not self.segments:
            return b""
        # Assumes segments are stored contiguously after finding
        full_bytes = b""
        expected_next_start_offset = self.segments[0].start
        for seg in self.segments:
            if seg.start != expected_next_start_offset:
                print(
                    f"Warning: Gap detected in MatchChain segments at offset {seg.start} (expected {expected_next_start_offset}) for chain starting {format_addr(self.overall_start())}"
                )
                # Handle gap? For now, just append. Might indicate an issue.
            full_bytes += seg.matched_bytes
            expected_next_start_offset = seg.start + seg.length
        return full_bytes

    def append_junk(
        self, junk_start_offset: int, junk_len: int, junk_desc: str, junk_bytes: bytes
    ):
        """Appends a junk segment."""
        seg = MatchSegment(
            start=junk_start_offset,  # Offset relative to base_address
            length=junk_len,
            description=junk_desc,
            matched_bytes=junk_bytes,
            segment_type=SegmentType.JUNK,
        )
        self.add_segment(seg)

    @property
    def description(self) -> str:
        """Generates a description string for the chain."""
        if not self.segments:
            return "Empty Chain"
        base_desc = self.segments[0].description
        has_junk = any(s.segment_type == SegmentType.JUNK for s in self.segments)
        has_big = any(
            s.segment_type == SegmentType.BIG_INSTRUCTION for s in self.segments
        )
        if has_junk:
            base_desc += " + Junk"
        if has_big:
            base_desc += " + BigInstr"
        return base_desc

    @property
    def stage1_type(self) -> typing.Optional[SegmentType]:
        """Returns the type of the first segment, assumed to be Stage1."""
        return self.segments[0].segment_type if self.segments else None

    @property
    def junk_segments(self) -> typing.List[MatchSegment]:
        """Returns a list of junk segments."""
        return [seg for seg in self.segments if seg.segment_type == SegmentType.JUNK]

    @property
    def junk_starts_at_offset(self) -> typing.Optional[int]:
        """Returns the start offset (relative to base_address) of the first junk segment."""
        js = self.junk_segments
        return js[0].start if js else None

    @property
    def junk_length(self) -> int:
        """Returns the total length of the contiguous junk portion."""
        js = self.junk_segments
        if not js:
            return 0
        first_junk = js[0]
        last_junk = js[-1]
        return (last_junk.start + last_junk.length) - first_junk.start

    def __lt__(self, other):
        """Comparison for sorting based on start address."""
        return self.overall_start() < other.overall_start()

    def __repr__(self):
        """Detailed representation of the match chain."""
        start_addr = self.overall_start()
        length = self.overall_length()
        # Get bytes directly from segments for preview
        preview_bytes = b"".join(s.matched_bytes for s in self.segments)
        hex_preview = preview_bytes.hex().upper()[:16]
        ellipsis = "..." if len(preview_bytes) > 8 else ""

        r = [
            f"{self.description.rjust(32)} @ {format_addr(start_addr)} (Len: {length}) - {hex_preview}{ellipsis}",
            "  |",
        ]
        current_offset = self.segments[0].start if self.segments else 0
        for seg in self.segments:
            seg_addr = self.base_address + seg.start
            seg_hex = seg.matched_bytes.hex().upper()
            if len(seg_hex) > 16:
                seg_hex = seg_hex[:16] + "..."
            rel_offset = seg.start - (self.segments[0].start if self.segments else 0)
            _grps = f" - {seg.matched_groups}" if seg.matched_groups else ""
            r.append(
                f"  |_ +{rel_offset:<3d} [{seg.segment_type.name}] {seg.description} @ {format_addr(seg_addr)} (Len: {seg.length}) - {seg_hex}{_grps}"
            )
            current_offset = seg.start + seg.length
        return "\n".join(r)


class MatchChains:
    """Collection of MatchChain objects."""

    def __init__(self):
        self.chains: typing.List[MatchChain] = []

    def add_chain(self, chain: MatchChain):
        self.chains.append(chain)

    def __repr__(self):
        """Summary representation of all chains."""
        if not self.chains:
            return "No match chains found."
        _the_repr = [f"Found {len(self.chains)} potential chains:"]
        for chain in self.chains:
            start_addr = chain.overall_start()
            length = chain.overall_length()
            # Get bytes directly from segments for preview
            preview_bytes = b"".join(s.matched_bytes for s in chain.segments)
            hex_preview = preview_bytes.hex().upper()[:16]
            ellipsis = "..." if len(preview_bytes) > 8 else ""
            _the_repr.append(
                f"  {chain.description.rjust(32)} @ {format_addr(start_addr)} (Len: {length}) - {hex_preview}{ellipsis}"
            )
        return "\n".join(_the_repr)

    def __iter__(self):
        """Iterate over the contained chains."""
        return iter(self.chains)

    def sort(self):
        """Sorts chains by their overall start address."""
        self.chains.sort()

    def __len__(self):
        return len(self.chains)


@dataclass
class JumpTargetAnalyzer:
    """Analyzes jump targets within a potential anti-disassembly stub. Uses original logic."""

    # Input parameters exactly as in the original script
    match_bytes: bytes
    match_start: int  # Absolute EA where match_bytes starts
    block_end: (
        int  # End address of the allowed region (e.g., function end or segment end)
    )
    start_ea: int  # Base address of the memory block (MemHelper.start)

    # Internal structures exactly as in the original script
    jump_targets: collections.Counter = field(
        init=False, default_factory=collections.Counter
    )
    jump_details: list = field(
        init=False, default_factory=list
    )  # (jump_ea, final_target, stage1_type)
    insertion_order: dict = field(
        init=False, default_factory=dict
    )  # final_target -> order index
    target_type: dict = field(
        init=False, default_factory=dict
    )  # final_target -> stage1_type

    # follow_jump_chain exactly as provided in the original script
    def follow_jump_chain(self, mem, current_ea, match_end, visited=None):
        """
        Follow a chain of jumps starting from current_ea.
        Avoid loops or out-of-bounds jumps. (Original Logic)
        """
        if visited is None:
            visited = set()
        # Avoid loops or jumps outside the memory block.
        # Use mem.start and mem.end for bounds checking against the MemHelper cache
        if (
            current_ea in visited
            or current_ea < mem.start  # Check against MemHelper start
            or current_ea >= mem.end  # Check against MemHelper end (exclusive)
        ):
            # print(f"Debug follow_jump_chain: Stop at {format_addr(current_ea)} (visited or OOB {format_addr(mem.start)}-{format_addr(mem.end)})")
            return None  # Return None to indicate failure/stop
        visited.add(current_ea)

        # No need to read current_bytes separately if using IDA APIs or MemHelper.get_byte_at
        # The original logic used IDA APIs implicitly via decode_insn

        # Original logic using ida_ua.decode_insn
        curr_addr = current_ea
        while True:
            insn = ida_ua.insn_t()
            # Decode instruction directly using the absolute address
            length = ida_ua.decode_insn(insn, curr_addr)

            if length == 0:  # Decode failed
                # print(f"Debug follow_jump_chain: Decode failed at {format_addr(curr_addr)}")
                break  # Stop if decode fails

            if insn.itype == ida_allins.NN_nop:
                curr_addr += length
                continue

            # Original check: only care about 2 byte jumps (conditional or short JMP)
            if insn.itype not in ALL_JUMPS or length != 2:
                # print(f"Debug follow_jump_chain: Non-2-byte jump/non-jump at {format_addr(curr_addr)}")
                break  # Stop if not a 2-byte jump

            # Get target address from operand
            target = idaapi.BADADDR
            if insn.Op1.type == idaapi.o_near:
                target = insn.Op1.addr
            else:
                # print(f"Debug follow_jump_chain: Jump at {format_addr(curr_addr)} is not o_near")
                break  # Stop if not a near jump

            # Original logic for checking target location relative to match_end
            # match_end here refers to the end of the stage1+junk part before big instr search
            # The +6 comes from the expectation of the big instruction buffer size.
            if self.match_start <= target < match_end + 6:
                # print(f"Debug follow_jump_chain: Recursing from {format_addr(curr_addr)} to {format_addr(target)} (within match+6)")
                # Need to pass mem object to recursive call
                return self.follow_jump_chain(mem, target, match_end, visited)
            # The original logic had this specific check - keep it.
            elif target == match_end + 6:
                # print(f"Debug follow_jump_chain: Target {format_addr(target)} is exactly match_end+6")
                return target
            # Check if target is within the overall memory block (MemHelper bounds)
            elif mem.start <= target < mem.end:
                # print(f"Debug follow_jump_chain: Target {format_addr(target)} is outside match+6 but inside mem block")
                return target
            else:
                # print(f"Debug follow_jump_chain: Target {format_addr(target)} is outside mem block")
                # If target is outside mem block, return current address as the end point?
                # Original returned current_ea here. Let's stick to that.
                return curr_addr  # Return the address of the jump instruction itself

        # If loop finishes or breaks, return the last valid address
        # print(f"Debug follow_jump_chain: Loop ended, returning {format_addr(curr_addr)}")
        return curr_addr

    # process method exactly as provided in the original script
    def process(self, mem, chain):
        """
        Process each jump match in match_bytes. (Original Logic)
        'chain' is expected to have attributes:
          - overall_start(): int
          - overall_length(): int
          - stage1_type: SegmentType
        """
        # match_end is the end of the stage1 + junk part
        match_end = chain.overall_start() + chain.overall_length()
        # Iterate through the combined bytes of the chain (stage1 + junk)
        chain_bytes = chain.overall_matched_bytes()
        chain_start_ea = chain.overall_start()

        # Use re.finditer on the chain's bytes, looking for 2-byte jump patterns
        # The pattern [\xEB\x70-\x7F]. matches the opcode and the offset byte
        for jump_match in re.finditer(rb"[\xEB\x70-\x7F].", chain_bytes, re.DOTALL):
            jump_offset_in_chain = jump_match.start()
            jump_ea = (
                chain_start_ea + jump_offset_in_chain
            )  # Absolute address of the jump

            # Decode just to be sure it's what we expect (optional, regex is quite specific)
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, jump_ea)
            if length != 2 or insn.itype not in ALL_JUMPS:
                # print(f"Warning: Regex matched jump at {format_addr(jump_ea)}, but decode differs.")
                continue  # Should not happen with this regex

            # Follow the jump chain starting from this jump instruction's *target*
            initial_target = idaapi.BADADDR
            if insn.Op1.type == idaapi.o_near:
                initial_target = insn.Op1.addr
            else:
                continue  # Should be near based on regex/decode

            # print(f"Debug process: Following jump from {format_addr(jump_ea)} (initial target {format_addr(initial_target)})")
            # Call the original follow_jump_chain logic
            # Pass the mem object, initial target, and the calculated match_end
            final_target = self.follow_jump_chain(
                mem, initial_target, match_end
            )  # Pass initial target

            # Original checks for final_target validity
            if not final_target or final_target >= self.block_end:
                # print(f"Debug process: Skipping jump at {format_addr(jump_ea)} - final target {final_target} invalid or >= block_end {format_addr(self.block_end)}")
                continue

            # Original check: target must be within 6 bytes *after* the match_end
            if not (
                match_end <= final_target < match_end + 6
            ):  # Use < match_end + 6 for exclusive upper bound
                # print(f"Debug process: Skipping jump at {format_addr(jump_ea)} - final target {format_addr(final_target)} not in range [{format_addr(match_end)}, {format_addr(match_end + 6)})")
                continue

            # Original assertion - keep it if desired, though checks above should cover it
            # assert self.match_start + chain.junk_length <= final_target < self.block_end
            # Note: The assertion used match_start + junk_length, which might differ slightly from match_end
            # if the chain structure changes. Using match_end seems more consistent here.

            # print(f"Debug process: Valid jump target found: {format_addr(jump_ea)} -> {format_addr(final_target)}")
            self.jump_targets[final_target] += 1
            stage1_type = chain.stage1_type  # Get stage1 type from the chain
            if final_target not in self.insertion_order:
                self.insertion_order[final_target] = len(self.insertion_order)
                self.target_type[final_target] = stage1_type
            self.jump_details.append((jump_ea, final_target, stage1_type))

        return self

    # sorted_targets method exactly as provided in the original script
    def sorted_targets(self):
        """
        Return a sorted list of (final_target, count) tuples. (Original Logic)
        """
        results = []
        for target, count in self.jump_targets.items():
            stype = self.target_type.get(target)
            order = self.insertion_order.get(
                target, float("inf")
            )  # Default order if somehow missing
            if stype == SegmentType.STAGE1_SINGLE:
                # Original logic: higher count, then lower insertion order (first seen)
                key_tuple = (count, -order)  # Negate order for ascending sort on order
            else:  # Includes MULTI_PART and potentially others if target_type is missing
                # Original logic: higher count, then higher address
                key_tuple = (count, target)
            results.append((target, key_tuple))

        # Original sort: reverse=True means descending on the key_tuple components
        # (count descending, -order descending -> order ascending)
        # (count descending, target descending)
        results.sort(key=lambda x: x[1], reverse=True)

        # Return a list of (final_target, count) tuples.
        return [(target, self.jump_targets[target]) for target, _ in results]

    # __iter__ method exactly as provided in the original script
    def __iter__(self):
        """
        Iterate over the most likely targets. (Original Logic)
        """
        # Original logic iterates through sorted targets and yields them.
        # The check for jump_ea == candidate + 1 seems like a specific heuristic
        # that might have been needed for a particular obfuscation case. Keep it.
        for candidate, count in self.sorted_targets():
            final_candidate = candidate
            # Check if any recorded jump *starts* at candidate + 1
            # This seems unusual - perhaps meant to handle jumps landing on padding?
            # Keep the original logic.
            for jump_ea, target, stype in self.jump_details:
                if jump_ea == candidate + 1:
                    # If such a jump exists, yield *its* target instead of the candidate
                    final_candidate = target
                    break  # Found one, stop checking for this candidate
            yield final_candidate


# --- Pattern Finding Functions ---


def find_stage1(mem: MemHelper) -> MatchChains:
    """Finds initial Stage1 patterns (Single/Multi-Part Jumps) in memory."""
    print(
        f"Phase 1: Searching for Stage1 patterns from {format_addr(mem.start)} to {format_addr(mem.end)}"
    )

    patterns_to_search = [
        (
            MULTI_PART_PATTERNS,
            "Multi-Part Conditional Jumps",
            SegmentType.STAGE1_MULTIPLE,
        ),
        (
            SINGLE_PART_PATTERNS,
            "Single-Part Conditional Jumps",
            SegmentType.STAGE1_SINGLE,
        ),
    ]

    all_chains = MatchChains()
    base_ea = mem.start  # Base address for calculating absolute addresses

    for pattern_group, desc, segment_type in patterns_to_search:
        for pattern_meta in pattern_group:
            compiled_pattern = pattern_meta.compile()
            # Search within the entire memory buffer read by MemHelper
            for match in compiled_pattern.finditer(mem.mem_results):
                match_start_offset = match.start()
                match_end_offset = match.end()
                match_len = match_end_offset - match_start_offset
                matched_bytes = mem.mem_results[match_start_offset:match_end_offset]

                matched_groups = {}
                for name, value_bytes in match.groupdict().items():
                    if value_bytes is not None:
                        if name == "padding":
                            matched_groups[name] = value_bytes  # Keep as bytes
                        else:
                            matched_groups[name] = value_bytes.hex().upper()

                # Add target address calculation (absolute EA)
                current_addr = (
                    base_ea + match_start_offset
                )  # Absolute EA of match start
                if (
                    segment_type == SegmentType.STAGE1_SINGLE
                    and "jump" in match.groupdict()
                ):
                    jump_bytes_hex = matched_groups.get("jump")
                    if jump_bytes_hex and len(jump_bytes_hex) == 4:  # e.g., "73FE"
                        jump_bytes = bytes.fromhex(jump_bytes_hex)
                        offset = struct.unpack("<b", jump_bytes[1:])[0]
                        target = current_addr + match_len + offset
                        matched_groups["target"] = format_addr(target)
                elif (
                    segment_type == SegmentType.STAGE1_MULTIPLE
                    and "first_jump" in match.groupdict()
                    and "second_jump" in match.groupdict()
                ):
                    first_jump_hex = matched_groups.get("first_jump")
                    second_jump_hex = matched_groups.get("second_jump")
                    if first_jump_hex and len(first_jump_hex) == 4:
                        first_jump_bytes = bytes.fromhex(first_jump_hex)
                        offset1 = struct.unpack("<b", first_jump_bytes[1:])[0]
                        matched_groups["first_target"] = format_addr(
                            current_addr + 2 + offset1
                        )  # Target relative to end of first jump
                    if second_jump_hex and len(second_jump_hex) == 4:
                        second_jump_bytes = bytes.fromhex(second_jump_hex)
                        offset2 = struct.unpack("<b", second_jump_bytes[1:])[0]
                        matched_groups["second_target"] = format_addr(
                            current_addr + match_len + offset2
                        )  # Target relative to end of whole match

                chain = MatchChain(
                    base_address=base_ea,
                    segments=[
                        MatchSegment(
                            start=match_start_offset,  # Offset relative to mem.start
                            length=match_len,
                            description=pattern_meta.description or desc,
                            matched_bytes=matched_bytes,
                            segment_type=segment_type,
                            matched_groups=matched_groups,
                        )
                    ],
                )
                all_chains.add_chain(chain)

    all_chains.sort()
    print(f"Phase 1: Found {len(all_chains)} potential Stage1 matches.")
    return all_chains


# Function find_junk_instructions_after_stage1 exactly as provided in the original script
# (Adapting only to use MemHelper and offsets)
def find_junk_instructions_after_stage1(
    mem: MemHelper, stage1_chains: MatchChains
) -> MatchChains:
    """
    Finds and appends junk instructions immediately following Stage1 matches. (Original Logic)
    """
    print(
        f"\nPhase 2: Checking for junk instructions following {len(stage1_chains)} Stage1 matches"
    )
    updated_chains = (
        MatchChains()
    )  # Process chains and add potentially updated ones here

    for chain in stage1_chains:
        if not chain.segments:
            continue  # Should not happen if find_stage1 worked

        stage1_segment = chain.segments[0]
        # Start searching for junk immediately after the stage1 segment's offset
        current_offset = stage1_segment.start + stage1_segment.length
        # func_end is not directly available, use mem.length as the boundary
        max_offset = mem.length

        total_junk_len = 0
        # Original logic: Iterate while there's enough space for another junk instruction (> 6 bytes)
        # Let's adapt slightly: iterate while current_offset is within bounds
        while current_offset < max_offset:
            # Extract the buffer *starting from current_offset* within mem.mem_results
            post_stage1_buffer = mem.mem_results[current_offset:]
            if not post_stage1_buffer:
                break  # No more bytes

            # Original logic: Check if remaining buffer is > 6 bytes. Keep this constraint.
            if len(post_stage1_buffer) <= 6:
                # print(f"Debug Junk: Remaining buffer <= 6 bytes at offset {current_offset}. Stopping junk search for chain {format_addr(chain.overall_start())}")
                break

            junk_found_this_iteration = False
            for junk_pattern_meta in JUNK_PATTERNS:
                match = junk_pattern_meta.compile().match(post_stage1_buffer)
                if match:
                    junk_len = match.end()  # Length of the matched junk
                    junk_bytes = post_stage1_buffer[:junk_len]
                    # print(f"  Found junk: {junk_pattern_meta.description} ({junk_bytes.hex()}) at offset {current_offset} for chain {format_addr(chain.overall_start())}")

                    # Append junk segment to the *original* chain
                    chain.append_junk(
                        junk_start_offset=current_offset,  # Offset relative to mem.start
                        junk_len=junk_len,
                        junk_desc=junk_pattern_meta.description,
                        junk_bytes=junk_bytes,
                    )
                    current_offset += junk_len  # Move offset forward
                    total_junk_len += junk_len
                    junk_found_this_iteration = True
                    break  # Move to the next portion of the buffer (original logic)

            if not junk_found_this_iteration:
                # print(f"  No more junk found after offset {current_offset} for chain {format_addr(chain.overall_start())}")
                break  # No junk pattern matched at this position

        # Add the potentially updated chain (with junk appended) to the result
        updated_chains.add_chain(chain)

    updated_chains.sort()  # Re-sort based on start address
    print(f"Phase 2: Completed junk search.")
    return updated_chains


# Function find_big_instruction exactly as provided in the original script
def find_big_instruction(buffer_bytes, is_x64=False):
    """
    Find the 'big instruction' in a 6-byte buffer, checking specific positions from the end.
    According to the constraints, the buffer will always be exactly 6 bytes. (Original Logic)

    Args:
        buffer_bytes (bytes): The 6-byte buffer to analyze.
        is_x64 (bool): Whether to check for REX prefixes (x64 mode).

    Returns:
        dict: A dictionary containing information about the found instruction.
    """
    # Original assertion and helper functions
    assert len(buffer_bytes) == 6, "Buffer must be exactly 6 bytes"

    def is_rex_prefix(byte):
        return 0x40 <= byte <= 0x4F

    def is_valid_modrm(byte):
        # Original logic used 0x80-0xBF. Keep this.
        # Note: This is a simplification; not all ModR/M bytes in this range are valid
        # in all contexts, but it matches the original script's check.
        return 0x80 <= byte <= 0xBF

    # Ensure we have a 6-byte buffer (redundant due to assert, but safe)
    if len(buffer_bytes) != 6:
        return {
            "type": None,
            "name": "Invalid buffer size",
            "instruction": [],
            "position": -1,
            "junk_before": buffer_bytes,
            "junk_after": [],
        }

    # 1. First check for 3-byte instructions in x64 mode (highest priority) - Original Logic
    if is_x64:
        for pos in range(4):  # Start positions 0, 1, 2, 3
            if pos + 2 >= len(buffer_bytes):
                continue  # Ensure indices are valid

            rex = buffer_bytes[pos]
            opcode = buffer_bytes[pos + 1]
            modrm = buffer_bytes[pos + 2]

            if is_rex_prefix(rex):
                if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
                    junk_after = buffer_bytes[pos + 3 :]
                    expected_junk_bytes = max(0, 3 - pos)  # Original calculation
                    if len(junk_after) == expected_junk_bytes:
                        return {
                            "type": "3-byte",
                            "name": "REX + Two-byte Med instruction",
                            "instruction": [rex, opcode, modrm],
                            "position": pos,
                            "junk_before": buffer_bytes[:pos],
                            "junk_after": junk_after,
                        }
                elif opcode in BIG_OPCODE_SET and is_valid_modrm(modrm):
                    junk_after = buffer_bytes[pos + 3 :]
                    expected_junk_bytes = max(0, 3 - pos)  # Original calculation
                    if len(junk_after) == expected_junk_bytes:
                        return {
                            "type": "3-byte",
                            "name": "REX + Two-byte Big instruction",
                            "instruction": [rex, opcode, modrm],
                            "position": pos,
                            "junk_before": buffer_bytes[:pos],
                            "junk_after": junk_after,
                        }

    # 2. Next check for 2-byte instructions - Original Logic
    for pos in range(5):  # Start positions 0, 1, 2, 3, 4
        if pos + 1 >= len(buffer_bytes):
            continue  # Ensure indices are valid

        opcode = buffer_bytes[pos]
        modrm = buffer_bytes[pos + 1]

        if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
            junk_after = buffer_bytes[pos + 2 :]
            expected_junk_bytes = max(0, 4 - pos)  # Original calculation
            if len(junk_after) == expected_junk_bytes:
                return {
                    "type": "2-byte",
                    "name": "Two-byte Med instruction",
                    "instruction": [opcode, modrm],
                    "position": pos,
                    "junk_before": buffer_bytes[:pos],
                    "junk_after": junk_after,
                }
        elif opcode in BIG_OPCODE_SET and is_valid_modrm(modrm):
            junk_after = buffer_bytes[pos + 2 :]
            expected_junk_bytes = max(0, 4 - pos)  # Original calculation
            if len(junk_after) == expected_junk_bytes:
                return {
                    "type": "2-byte",
                    "name": "Two-byte Big instruction",
                    "instruction": [opcode, modrm],
                    "position": pos,
                    "junk_before": buffer_bytes[:pos],
                    "junk_after": junk_after,
                }

    # 3. Finally check for 1-byte instructions (lowest priority) - Original Logic
    pos = 5  # Only valid position for 1-byte instruction (last byte)
    if pos < len(buffer_bytes):  # Should always be true for 6-byte buffer
        byte = buffer_bytes[pos]
        if byte in SINGLE_BYTE_OPCODE_SET:
            return {
                "type": "1-byte",
                "name": "Single-byte big instruction",
                "instruction": [byte],
                "position": pos,
                "junk_before": buffer_bytes[:pos],
                "junk_after": [],
            }

    # No valid instruction found - Original Logic
    return {
        "type": None,
        "name": "No match found",
        "instruction": [],
        "position": -1,
        "junk_before": buffer_bytes,
        "junk_after": [],
    }


# Function filter_match_chains exactly as provided in the original script
def filter_match_chains(match_chains):
    """
    Filters out match chains that are false positives based on two criteria:
      - The total length of the anti-disassembly routine must be between 12 and 129 bytes.
      - The junk length must be nonzero. (Original Logic)
    """
    valid_chains = MatchChains()  # Use MatchChains collection
    for chain in match_chains:
        total_length = chain.overall_length()
        # Use the chain's junk_length property which calculates based on junk segments
        junk_length = chain.junk_length

        # Original filter conditions
        if junk_length == 0:
            # print(f"Debug filter_match_chains: Rejected {format_addr(chain.overall_start())} - junk_length is 0")
            continue
        if total_length < 12 or total_length > 129:
            # print(f"Debug filter_match_chains: Rejected {format_addr(chain.overall_start())} - length {total_length} out of range [12, 129]")
            continue

        valid_chains.add_chain(chain)  # Add the valid chain
    return valid_chains


# Function filter_antidisasm_patterns exactly as provided in the original script
# (Adapting only to use MemHelper, offsets, and MatchChain structure where necessary)
def filter_antidisasm_patterns(
    mem: MemHelper, chains: MatchChains, start_ea: int, min_size=12, max_size=129
) -> MatchChains:
    """
    Filter out false positive anti-disassembly patterns and handle overlaps.
    Integrates with existing big instruction detection code. (Original Logic)

    Args:
        mem: Memory object containing binary data for the full range
        chains: List of MatchChain objects (already passed Stage1 and Junk finding)
        start_ea: Base address of the MemHelper (mem.start)
        min_size: Minimum valid size (default: 12)
        max_size: Maximum valid size (default: 129)

    Returns:
        MatchChains object containing validated chains.
    """
    # Stage 1: Basic filtering (using the dedicated filter_match_chains function)
    print("Stage 3.1: Basic validation (Size and Junk Presence)")
    # The input 'chains' should already have junk appended if found
    filtered_chains_basic = filter_match_chains(chains)
    print(f"  After basic filtering: {len(filtered_chains_basic)} chains remain")

    # Stage 2: Validate big instructions
    print("Stage 3.2: Big instruction validation")
    validated_with_big_instr = MatchChains()

    # Need the is_x64 flag once
    _is_x64 = is_x64()

    for chain in filtered_chains_basic:
        # Check if we already have a big instruction segment (shouldn't happen yet)
        if any(
            seg.segment_type == SegmentType.BIG_INSTRUCTION for seg in chain.segments
        ):
            print(
                f"Warning: Chain {format_addr(chain.overall_start())} already has BigInstr before validation?"
            )
            validated_with_big_instr.add_chain(chain)
            continue

        # Find the big instruction using the original logic flow
        match_start_abs = chain.overall_start()  # Absolute EA of chain start
        # match_end_abs is end of stage1+junk
        match_end_abs = chain.overall_start() + chain.overall_length()
        # block_end is the end of the memory region being analyzed (mem.end)
        block_end_abs = mem.end

        # print(f"Analyzing match: {chain.description} @ {format_addr(match_start_abs)}")

        # Determine possible jump targets using JumpTargetAnalyzer with original logic
        # Pass absolute addresses and the mem object
        jump_analyzer = JumpTargetAnalyzer(
            match_bytes=chain.overall_matched_bytes(),  # Bytes of stage1 + junk
            match_start=match_start_abs,  # Absolute start EA of chain
            block_end=block_end_abs,  # Absolute end EA of analysis block
            start_ea=start_ea,  # Absolute start EA of MemHelper block
        ).process(
            mem=mem, chain=chain
        )  # Pass mem object and the chain

        big_instr_found_for_chain = False
        # Iterate through potential targets yielded by the analyzer's iterator (original logic)
        for target in jump_analyzer:  # Uses the custom __iter__
            # print(f"  Checking target: {format_addr(target)} for chain {format_addr(match_start_abs)}")
            # Original logic: Check for big instruction in the 6 bytes *before* target
            search_start_ea = target - 6
            if search_start_ea < start_ea:  # Check against MemHelper start
                # print(f"    Search start {format_addr(search_start_ea)} is before mem block start {format_addr(start_ea)}")
                continue

            # Extract the 6-byte buffer using MemHelper
            search_bytes = mem.get_bytes_at(search_start_ea, 6)
            if search_bytes is None:
                # print(f"    Failed to read 6 bytes before target {format_addr(target)}")
                continue  # Skip if we can't get exactly 6 bytes

            # print(f"    Searching for big instruction in buffer: {search_bytes.hex()} at {format_addr(search_start_ea)}")
            # Call the original find_big_instruction function
            result = find_big_instruction(search_bytes, is_x64=_is_x64)

            # Original check: if not result["type"]
            if not result or not result.get("type"):
                # print(f"    No big instruction found in buffer {search_bytes.hex()}")
                continue  # Continue to the next potential target

            # Found a valid big instruction
            # print(f"    Found Big Instr: {result['name']} at position {result['position']} in {search_bytes.hex()}")
            big_instr_found_for_chain = True

            # Original logic for checking superfluous bytes *after* the 6-byte buffer
            # This needs careful adaptation with MemHelper
            big_instr_segment_start_offset = (
                search_start_ea - start_ea
            )  # Offset relative to mem.start
            new_len = 6  # Start with the 6 bytes found
            new_bytes = search_bytes  # Start with the 6 bytes found

            # Check for additional SUPERFLULOUS_BYTE bytes immediately following the 6-byte buffer
            for i in itertools.count():
                extra_byte_ea = search_start_ea + 6 + i
                # Safely get the byte using MemHelper
                b = mem.get_byte_at(extra_byte_ea)
                if b is None or b != SUPERFLULOUS_BYTE:
                    break  # Stop if out of bounds or not the superfluous byte

                # print(f"    Found superfluous byte {hex(b)} at {format_addr(extra_byte_ea)}")
                new_bytes += bytes([b])
                new_len += 1

            # Add the Big Instruction segment (including any superfluous bytes)
            chain.add_segment(
                MatchSegment(
                    start=big_instr_segment_start_offset,  # Offset relative to mem.start
                    length=new_len,
                    description=result[
                        "name"
                    ],  # Use name from find_big_instruction result
                    matched_bytes=new_bytes,
                    segment_type=SegmentType.BIG_INSTRUCTION,
                    # Store instruction bytes for potential analysis/display
                    matched_groups={
                        "instruction": bytes(result["instruction"]).hex().upper()
                    },
                )
            )
            # print(f"    Added Big Instruction segment: offset={big_instr_segment_start_offset}, len={new_len}, bytes={new_bytes.hex()}")
            break  # Found big instruction for this chain, move to the next chain

        if big_instr_found_for_chain:
            validated_with_big_instr.add_chain(chain)
        # else:
        # print(f"  Rejected: {chain.description} @ {format_addr(chain.overall_start())} - no valid big instruction found for any target")

    print(
        f"  After big instruction validation: {len(validated_with_big_instr)} chains remain"
    )

    # Stage 3: Handle overlapping patterns - Original Logic
    print("Stage 3.3: Resolving overlaps")

    # Sort chains by start address (absolute EA)
    validated_with_big_instr.sort()  # Use MatchChain.__lt__
    final_chains = MatchChains()
    covered_ranges = []  # List of tuples: (absolute_start_ea, absolute_end_ea)

    for chain in validated_with_big_instr:
        chain_start = chain.overall_start()
        # Calculate chain end *including* the big instruction segment if present
        chain_end = chain.overall_end()  # Use the updated overall_end

        is_covered = False
        for start, end in covered_ranges:
            # Original overlap check: if this chain starts within an already covered range
            # This check might miss partial overlaps. A better check is:
            # if chain_start < end and chain_end > start:
            # Let's stick to the original check as implemented:
            if chain_start >= start and chain_start < end:
                # print(f"  Rejected overlap: {chain.description} @ {format_addr(chain_start)} - starts within existing pattern ({format_addr(start)} to {format_addr(end)})")
                is_covered = True
                break

        if not is_covered:
            final_chains.add_chain(chain)
            covered_ranges.append((chain_start, chain_end))
            # print(f"  Accepted: {chain.description} @ {format_addr(chain_start)} - valid pattern to {format_addr(chain_end)}")

    print(f"Filtering complete: {len(final_chains)} chains accepted")
    return final_chains


# --- Main Processing and Analysis Functions ---


def process_range(start_ea: int, end_ea: int) -> typing.List[PatchOperation]:
    """Processes a given memory range to find and prepare patches."""
    patch_operations = []
    mem = MemHelper(start_ea, end_ea)
    if not mem.mem_results:
        print("Memory reading failed. Aborting processing.")
        return patch_operations

    # Phase 1: Find initial Stage1 patterns
    stage1_chains = find_stage1(mem)
    if not stage1_chains:
        print("No Stage1 patterns found in the specified range.")
        return patch_operations

    # Phase 2: Find junk instructions following Stage1 (using original logic)
    chains_with_junk = find_junk_instructions_after_stage1(mem, stage1_chains)

    # Phase 3: Filter, validate big instructions, and resolve overlaps (using original logic)
    # Pass mem object and its start_ea
    final_chains = filter_antidisasm_patterns(mem, chains_with_junk, mem.start)

    print("\n=== Final Validated Anti-Disassembly Patterns ===")
    if not final_chains:
        print("No patterns survived the filtering process.")
    else:
        # Sort final chains for consistent output and patching order
        final_chains.sort()
        for chain in final_chains:
            print(chain)
            # Prepare NOP patch for the entire length of the validated chain
            patch_op = PatchOperation(
                address=chain.overall_start(),
                byte_values=b"\x90" * chain.overall_length(),
            )
            patch_operations.append(patch_op)

    return patch_operations


def decompile_function(func_ea: int):
    """Attempts to decompile a single function."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        # print(f"Warning: Cannot decompile, function not found at {format_addr(func_ea)}")
        return
    hf = ida_hexrays.hexrays_failure_t()
    try:
        ida_hexrays.decompile_func(func, hf, ida_hexrays.HX_WAIT)
        # if hf.code != ida_hexrays.DECOMP_OK:
        #      print(f"Warning: Decompilation failed for {format_addr(func_ea)}: {hf.errea} {hf.desc()}")
    except Exception as e:
        print(f"Warning: Exception during decompilation of {format_addr(func_ea)}: {e}")


def re_analyze_range(start_ea: int, end_ea: int):
    """Re-analyzes a specific address range after patching."""
    print(f"Re-analyzing range: {format_addr(start_ea)} to {format_addr(end_ea)}")
    if start_ea >= end_ea:
        print("  Skipping re-analysis: Invalid range.")
        return

    # Undefine existing items in the range
    print("  Undefining items...")
    # Use DELIT_SIMPLE as it's generally safer after patching potentially complex code
    ida_bytes.del_items(start_ea, ida_bytes.DELIT_SIMPLE, end_ea - start_ea)
    ida_auto.auto_wait()  # Allow IDA to process undefinition

    # Mark the range for reanalysis by creating instructions iteratively
    print("  Creating instructions...")
    curr = start_ea
    instructions_created = 0
    while curr < end_ea and curr != idaapi.BADADDR:
        # Store next potential head before creating instruction, in case create_insn fails badly
        next_head = ida_bytes.next_head(curr, end_ea)
        if next_head == idaapi.BADADDR or next_head <= curr:
            next_head = curr + 1  # Ensure progress if next_head fails

        # Create instruction
        instr_len = ida_ua.create_insn(curr)

        if instr_len > 0:
            instructions_created += 1
            curr += instr_len  # Advance by instruction length
        else:
            # Failed to create instruction, try advancing by 1 byte
            # print(f"Warning: Failed to create instruction at {format_addr(curr)}. Advancing 1 byte.")
            curr += 1

        # Safety break if stuck
        if curr >= next_head and instr_len <= 0:
            # print(f"Warning: Stuck during instruction creation at {format_addr(curr)}. Breaking re-analysis loop.")
            break

    print(f"  Created {instructions_created} instructions.")
    ida_auto.auto_wait()  # Allow IDA to process new items

    # Recreate functions in the analyzed range
    print("  Analyzing range for functions...")
    # Plan the range for function analysis
    success = ida_auto.plan_and_wait(start_ea, end_ea, True)
    if not success:
        print("  Warning: Failed to plan range for function analysis.")
    # Run the analysis queue
    ida_auto.auto_wait()

    # Decompile functions that *start* within the re-analyzed range
    print("  Attempting decompilation of functions starting in range...")
    func_ea = ida_funcs.get_next_func_addr(start_ea - 1)  # Find first func >= start_ea
    decompiled_count = 0
    while func_ea != idaapi.BADADDR and func_ea < end_ea:
        # Check if the function actually starts within the range
        func = ida_funcs.get_func(func_ea)
        if func and func.start_ea >= start_ea:
            # print(f"    Decompiling function at {format_addr(func_ea)}")
            decompile_function(func_ea)
            decompiled_count += 1
        # Move to the next function address regardless
        func_ea = ida_funcs.get_next_func_addr(func_ea)
    print(f"  Attempted decompilation for {decompiled_count} functions.")

    print(
        f"Re-analysis complete for range: {format_addr(start_ea)} to {format_addr(end_ea)}"
    )


# --- Main Execution ---


def run_patcher(start_address: typing.Optional[int] = None, patch: bool = False):
    """Main function to run the anti-disassembly removal process."""
    clear_output()
    print("=" * 60)
    print(" Anti-Disassembly Patcher Script (Original Logic) ".center(60, "="))
    print("=" * 60)
    print(f"Mode: {'Patching Enabled' if patch else 'Analysis Only'}")

    # 1. Determine processing range
    text_bounds = get_text_segment_bounds()
    if not text_bounds:
        return
    text_start, text_end = text_bounds

    proc_start_ea = text_start
    proc_end_ea = text_end

    if start_address is not None:
        if text_start <= start_address < text_end:
            proc_start_ea = start_address
            print(
                f"Processing from specified start address: {format_addr(proc_start_ea)}"
            )
        else:
            print(
                f"Warning: Specified start address {format_addr(start_address)} is outside code segment ({format_addr(text_start)}-{format_addr(text_end)}). Processing entire segment."
            )

    print(
        f"Processing range: {format_addr(proc_start_ea)} to {format_addr(proc_end_ea)}"
    )

    # 2. Process the range to find patterns and get patch operations
    patch_operations = process_range(proc_start_ea, proc_end_ea)

    # 3. Apply patches if requested
    if patch and patch_operations:
        print(f"\nApplying {len(patch_operations)} patch(es)...")
        num_patched_bytes = 0
        patched_ranges = []  # Store (start, end) of patched areas for reanalysis
        # Sort operations by address to patch sequentially
        patch_operations.sort(key=lambda op: op.address)
        for op in patch_operations:
            print(
                f"  Patching at {format_addr(op.address)} ({len(op.byte_values)} bytes)"
            )
            op.apply()
            num_patched_bytes += len(op.byte_values)
            patched_ranges.append((op.address, op.address + len(op.byte_values)))
        print(f"Patches applied ({num_patched_bytes} bytes modified).")

        # 4. Re-analyze the affected range(s) after patching
        print("\nTriggering re-analysis of patched range(s)...")
        if patched_ranges:
            # Merge overlapping/adjacent ranges for fewer re-analysis calls
            merged_ranges = []
            if patched_ranges:
                # Sort ranges by start address
                patched_ranges.sort(key=lambda x: x[0])
                current_start, current_end = patched_ranges[0]
                # Add padding to the first range
                current_start = max(proc_start_ea, current_start - 16)

                for next_start, next_end in patched_ranges[1:]:
                    # If next range overlaps or is adjacent (within 32 bytes padding), merge it
                    if next_start <= current_end + 32:
                        current_end = max(current_end, next_end)
                    else:
                        # Finish previous range (with padding) and start new one
                        merged_ranges.append(
                            (current_start, min(proc_end_ea, current_end + 16))
                        )
                        current_start = max(proc_start_ea, next_start - 16)
                        current_end = next_end
                # Add the last merged range (with padding)
                merged_ranges.append(
                    (current_start, min(proc_end_ea, current_end + 16))
                )

            print(f"  Re-analyzing {len(merged_ranges)} merged range(s):")
            for r_start, r_end in merged_ranges:
                print(f"    - {format_addr(r_start)} to {format_addr(r_end)}")
                re_analyze_range(r_start, r_end)
        else:
            print("No patches were applied, skipping re-analysis.")

        # 5. Optional: Jump to the start of the first patched range
        if patched_ranges:
            ida_kernwin.jumpto(min(r[0] for r in patched_ranges))
        else:
            ida_kernwin.jumpto(proc_start_ea)

    elif not patch_operations:
        print("\nNo anti-disassembly patterns found or validated.")
    else:
        print(
            f"\nAnalysis complete. {len(patch_operations)} potential patch(es) identified (run with patch=True to apply)."
        )

    print("=" * 60)
    print(" Script Finished ".center(60, "="))
    print("=" * 60)


if __name__ == "__main__":
    # --- Configuration ---
    APPLY_PATCHES = True  # Set to True to apply NOP patches
    START_FROM_ADDRESS = None  # Set to an address (int) or None for full segment scan
    # Example: START_FROM_ADDRESS = 0x140011000
    # Example: START_FROM_ADDRESS = idc.here() # Start from current cursor

    # --- Run ---
    run_patcher(start_address=START_FROM_ADDRESS, patch=APPLY_PATCHES)
