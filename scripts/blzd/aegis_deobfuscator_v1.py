import collections
import itertools
import re
import struct
import typing
from dataclasses import dataclass, field
from enum import Enum, auto

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_problems
import ida_ua
import idaapi
import idc

# fmt: off
CONDITIONAL_JUMPS = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
ALL_JUMPS = CONDITIONAL_JUMPS + [ida_allins.NN_jmp]
CONDITIONAL_JUMPS_MNEMONICS = [
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jcxz",
    "jecxz",
    "jrcxz",
    "je",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
]

# --- Reusable Padding Pattern ---
# First, define the raw padding pattern without capturing groups.
PADDING_PATTERN = rb"(?:\xC0[\xE0-\xFF]\x00|(?:\x86|\x8A)[\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF])"
# (We do not wrap this in a named group here so that we can reuse it inside other groups.)

class PatternCategory(Enum):
    MULTI_PART = auto()
    SINGLE_PART = auto()
    JUNK = auto()


@dataclass
class RegexPatternMetadata:
    category: PatternCategory
    pattern: bytes  # The regex pattern as a bytes literal
    description: typing.Optional[str] = None
    compiled: typing.Optional[typing.Pattern] = None

    def compile(self, flags=0):
        """Compile the regex if not already done, and return the compiled object."""
        if self.compiled is None:
            self.compiled = re.compile(self.pattern, flags)
        return self.compiled

    @property
    def group_names(self):
        """Return the dictionary mapping group names to their indices."""
        return self.compile().groupindex

@dataclass
class MultiPartPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = field(default=PatternCategory.MULTI_PART, init=False)

    def __post_init__(self):
        # Compile to ensure group names are available.
        _ = self.compile(re.DOTALL)
        required_groups = {"first_jump", "padding", "second_jump"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError(
                f"MultiPart pattern is missing required groups: {missing}"
            )

@dataclass
class SinglePartPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = field(default=PatternCategory.SINGLE_PART, init=False)

    def __post_init__(self):
        _ = self.compile(re.DOTALL)
        required_groups = {"prefix", "padding", "jump"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError(
                f"SinglePart pattern is missing required groups: {missing}"
            )

@dataclass
class JunkPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = field(default=PatternCategory.JUNK, init=False)

    def __post_init__(self):
        _ = self.compile(re.DOTALL)
        required_groups = {"junk"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError("Junk pattern must have a 'junk' group.")
    
# Multi-part jump patterns: pairs of conditional jumps with optional padding
MULTI_PART_PATTERNS = [
    MultiPartPatternMetadata(rb"(?P<first_jump>\x70.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x71.)", "JO ... JNO"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x71.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x70.)", "JNO ... JO"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x72.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x73.)", "JB ... JAE"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x73.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x72.)", "JAE ... JB"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x74.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x75.)", "JE ... JNE"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x75.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x74.)", "JNE ... JE"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x76.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x77.)", "JBE ... JA"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x77.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x76.)", "JA ... JBE"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x78.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x79.)", "JS ... JNS"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x79.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x78.)", "JNS ... JS"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x7A.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7B.)", "JP ... JNP"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x7B.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7A.)", "JNP ... JP"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x7C.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7D.)", "JL ... JGE"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x7D.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7C.)", "JGE ... JL"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x7E.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7F.)", "JLE ... JG"),
    MultiPartPatternMetadata(rb"(?P<first_jump>\x7F.)(?P<padding>" + PADDING_PATTERN + rb")*(?P<second_jump>\x7E.)", "JG ... JLE"),
]

# Single-part jump patterns: prefix instruction + optional padding + conditional jump
SINGLE_PART_PATTERNS = [
    SinglePartPatternMetadata(rb"(?P<prefix>\xF8)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "CLC ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xF9)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x76.)", "STC ... JBE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xF9)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x72.)", "STC ... JB"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xA8.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "TEST AL, imm8 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xA9....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "TEST EAX, imm32 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xF6..)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "TEST r/m8, imm8 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xF7.....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "TEST r/m32, imm32 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x84.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "TEST r/m8, r8 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x85.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "TEST r/m32, r32 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xA8.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "TEST AL, imm8 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xA9....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "TEST EAX, imm32 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xF6..)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "TEST r/m8, imm8 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\xF7.....)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "TEST r/m32, imm32 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x84.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "TEST r/m8, r8 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x85.)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "TEST r/m32, r32 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x80[\xE0-\xE7]\xFF)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "AND r/m8, 0xFF ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x24\xFF)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "AND AL, 0xFF ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x80[\xC8-\xCF]\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "OR r/m8, 0x00 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x0C\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "OR AL, 0x00 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x80[\xF0-\xF7]\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "XOR r/m8, 0x00 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x34\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x71.)", "XOR AL, 0x00 ... JNO"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x80[\xE0-\xE7]\xFF)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "AND r/m8, 0xFF ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x24\xFF)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "AND AL, 0xFF ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x80[\xC8-\xCF]\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "OR r/m8, 0x00 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x0C\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "OR AL, 0x00 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x80[\xF0-\xF7]\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "XOR r/m8, 0x00 ... JAE"),
    SinglePartPatternMetadata(rb"(?P<prefix>\x34\x00)(?P<padding>" + PADDING_PATTERN + rb")?(?P<jump>\x73.)", "XOR AL, 0x00 ... JAE"),
]


JUNK_PATTERNS = [
    JunkPatternMetadata(rb"(?P<junk>\x0F\x31)", "RDTSC"),
    JunkPatternMetadata(rb"(?P<junk>\x0F[\x80-\x8F]..[\x00\x01]\x00)", "TwoByte Conditional Jump"),
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


SUPERFLULOUS_BYTE = 0xF4
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


def format_addr(addr: int) -> str:
    """Return the address formatted as a string: 0x{address:02X}"""
    return f"0x{addr:02X}"


def clear_output():
    form = ida_kernwin.find_widget("Output window")
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


def is_x64():
    # Check if the current architecture is x64
    return ida_ida.inf_is_64bit()


class MemHelper:
    def __init__(self, start: int, end: int):
        self.mem_results = b""
        self.mem_offsets = []
        self.start = start
        self.end = end
        if not self.mem_results:
            self._get_memory(start, end)

    def _get_memory(self, start: int, end: int):
        result = idc.get_bytes(start, end - start)
        self.mem_results = result
        self.mem_offsets.append((start, end - start))


@dataclass(repr=False)
class PatchOperation:
    """Class to store patch operations that will be applied later."""

    address: int
    byte_values: bytes

    def apply(self):
        """Apply the patch operation."""
        ida_bytes.patch_bytes(self.address, self.byte_values)

    def __str__(self):
        """String representation with hex formatting."""
        return f"{self.__class__.__name__}(address=0x{self.address:X} , byte_values={self.byte_values.hex()})"

    __repr__ = __str__


@dataclass(repr=False)
class UnconditionalJumpOperation(PatchOperation):
    """Class to store unconditional jump patch operations."""

    byte_values: bytes = b"\xeb"

    def apply(self):
        """Apply the patch operation."""
        ida_bytes.patch_bytes(self.address, self.byte_values)

    def __str__(self):
        return super().__str__()


class SegmentType(Enum):
    STAGE1_SINGLE = auto()
    STAGE1_MULTIPLE = auto()
    JUNK = auto()
    BIG_INSTRUCTION = auto()


@dataclass
class MatchSegment:
    start: int
    length: int
    description: str
    matched_bytes: bytes
    segment_type: SegmentType
    matched_groups: typing.Dict[str, bytes] | None = None


class MatchChain:
    def __init__(self, base_address: int, segments: typing.List[MatchSegment] = None):
        self.base_address = base_address
        self.segments = segments or []

    def add_segment(self, segment: MatchSegment):
        self.segments.append(segment)

    def overall_start(self) -> int:
        return self.segments[0].start + self.base_address if self.segments else 0

    def overall_length(self) -> int:
        if not self.segments:
            return 0
        first = self.segments[0]
        last = self.segments[-1]
        return (last.start + last.length) - first.start

    def overall_matched_bytes(self) -> bytes:
        return b"".join(seg.matched_bytes for seg in self.segments)

    def append_junk(
        self, junk_start: int, junk_len: int, junk_desc: str, junk_bytes: bytes
    ):
        seg = MatchSegment(
            start=junk_start,
            length=junk_len,
            description=junk_desc,
            matched_bytes=junk_bytes,
            segment_type=SegmentType.JUNK,
        )
        self.add_segment(seg)

    @property
    def description(self) -> str:
        desc = []
        for idx, seg in enumerate(self.segments):
            if idx == 0:
                desc.append(f"{seg.description}")
            else:
                desc.append(f" -> {seg.description}")
        return "".join(desc)

    def update_description(self, new_desc: str):
        if self.segments:
            self.segments[0].description = new_desc

    # New properties for junk analysis
    @property
    def stage1_type(self) -> SegmentType:
        return self.segments[0].segment_type

    @property
    def junk_segments(self) -> list:
        """
        Returns a list of segments considered as junk based on their segment_type.
        """
        return [seg for seg in self.segments if seg.segment_type == SegmentType.JUNK]

    @property
    def junk_starts_at(self) -> typing.Optional[int]:
        """
        Returns the starting address of the junk portion.
        This is computed as base_address + the offset of the first junk segment.
        If no junk segments exist, returns None.
        """
        js = self.junk_segments
        if js:
            return self.base_address + js[0].start
        return None

    @property
    def junk_length(self) -> int:
        """
        Returns the total length of the junk portion.
        This is computed as the difference between the end (start + length) of the last junk segment
        and the start of the first junk segment.
        If there are no junk segments, returns 0.
        """
        js = self.junk_segments
        if not js:
            return 0
        first = js[0]
        last = js[-1]
        return (last.start + last.length) - first.start

    def __lt__(self, other):
        return self.overall_start() < other.overall_start()

    def __repr__(self):
        r = [
            f"{self.description.rjust(32, ' ')} @ 0x{self.overall_start():X} - "
            f"{self.overall_matched_bytes().hex()[:16]}"
            f"{'...' if self.overall_length() > 16 else ''}",
            "  |",
        ]
        for seg in self.segments:
            _grps = f"{' - ' + str(seg.matched_groups) if seg.matched_groups else ''}"
            r.append(
                f"  |_ {seg.description} @ 0x{self.base_address + seg.start:X} - {seg.matched_bytes.hex()}{_grps}"
            )
        return "\n".join(r)


class MatchChains:
    def __init__(self):
        self.chains = []

    def add_chain(self, chain: MatchChain):
        self.chains.append(chain)

    def __repr__(self):
        _the_repr = []
        for chain in self.chains:
            _the_repr.append(
                f"{chain.description.rjust(32, ' ')} @ 0x{chain.overall_start():X} - "
                f"{chain.overall_matched_bytes().hex()[:16]}"
                f"{'...' if chain.overall_length() > 16 else ''}"
            )
        return "\n".join(_the_repr)

    def __iter__(self):
        yield from self.chains

    def sort(self):
        self.chains.sort(key=lambda x: x.overall_start())


@dataclass
class JumpTargetAnalyzer:
    # Input parameters for processing jumps.
    match_bytes: bytes  # The bytes in which we're matching jump instructions.
    match_start: int  # The address where match_bytes starts.
    block_end: int  # End address of the allowed region.
    start_ea: int  # Base address of the memory block (used for bounds checking).

    # Internal structures.
    jump_targets: collections.Counter = field(
        init=False, default_factory=collections.Counter
    )
    jump_details: list = field(
        init=False, default_factory=list
    )  # List of (jump_ea, final_target, stage1_type)
    insertion_order: dict = field(
        init=False, default_factory=dict
    )  # final_target -> order index
    target_type: dict = field(
        init=False, default_factory=dict
    )  # final_target -> stage1_type

    def follow_jump_chain(self, mem, current_ea, match_end, visited=None):
        """
        Follow a chain of jumps starting from current_ea.
        Avoid loops or out-of-bounds jumps.
        """
        if visited is None:
            visited = set()
        # Avoid loops or jumps outside the memory block.
        if (
            current_ea in visited
            or current_ea < self.start_ea
            or current_ea >= self.start_ea + len(mem.mem_results)
        ):
            return None
        visited.add(current_ea)
        current_offset = current_ea - self.start_ea

        current_bytes = mem.mem_results[current_offset : self.block_end - self.start_ea]

        # Try matching each jump pattern.
        # we do not modify current_ea because we need to be *EXACT*
        # via addresses to check if the target is within the valid
        # conditional range and whether the big instruction
        # falls at the last 6 bytes of the buffer
        curr_addr = current_ea
        while True:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, curr_addr)
            if insn.itype == ida_allins.NN_nop:
                curr_addr += length
                continue
            # we only care about 2 byte jumps
            if insn.itype not in ALL_JUMPS or length != 2:
                break

            target = insn.Op1.addr

            # If the jump target is within the valid conditional range,
            # continue following the chain.

            if self.match_start <= target < match_end + 6:
                return self.follow_jump_chain(mem, target, match_end, visited)
            elif target == match_end + 6:
                return target
            # Otherwise, if the target is within the overall memory block, return it.
            return target if self.start_ea <= target < match_end + 6 else current_ea

        # If no jump pattern matches, end of the chain; return the current address.
        return current_ea

    def process(self, mem, chain):
        """
        Process each jump match in match_bytes.
        'chain' is expected to have attributes:
          - junk_length: int
          - stage1_type: SegmentType
        """
        match_end = chain.overall_start() + chain.overall_length()
        for jump_match in re.finditer(
            rb"[\xEB\x70-\x7F].", self.match_bytes, re.DOTALL
        ):
            jump_offset = jump_match.start()
            jump_ea = self.match_start + jump_offset
            final_target = self.follow_jump_chain(mem, jump_ea, match_end)
            if not final_target or final_target >= self.block_end:
                continue

            if not (match_end < final_target <= match_end + 6):
                # skip match if not within 6 bytes of match end
                continue

            assert self.match_start + chain.junk_length <= final_target < self.block_end
            self.jump_targets[final_target] += 1
            # Record the insertion order and the stage1_type on the first occurrence.
            if final_target not in self.insertion_order:
                self.insertion_order[final_target] = len(self.insertion_order)
                self.target_type[final_target] = chain.stage1_type
            self.jump_details.append((jump_ea, final_target, chain.stage1_type))

        return self

    def sorted_targets(self):
        """
        Return a sorted list of (final_target, count) tuples.

        Sorting behavior depends on the stage1_type:
         - For STAGE1_MULTIPLE: sort by count descending, then by final_target descending.
         - For STAGE1_SINGLE: sort by count descending, then by the order in which the target was first seen.
           (That is, when counts are equal, the first inserted target wins.)
         - For other types, default to (count, final_target) descending.
        """
        results = []
        for target, count in self.jump_targets.items():
            stype = self.target_type.get(target)
            order = self.insertion_order.get(target, 0)
            if stype == SegmentType.STAGE1_SINGLE:
                key_tuple = (
                    count,
                    -order,
                )  # higher count, then lower insertion order (i.e. first seen)
            else:
                key_tuple = (count, target)  # higher count, then higher address
            results.append((target, key_tuple))
        results.sort(key=lambda x: x[1], reverse=True)
        # Return a list of (final_target, count) tuples.
        return [(target, self.jump_targets[target]) for target, _ in results]

    def __iter__(self):
        """
        Iterate over the most likely targets.
        For each candidate, if a jump exists whose starting address equals candidate + 1,
        yield its final target instead.
        """
        for candidate, count in self.sorted_targets():
            final_candidate = candidate
            for jump_ea, target, stype in self.jump_details:
                if jump_ea == candidate + 1:
                    final_candidate = target
                    break
            yield final_candidate


def find_stage1(mem, ea, end_ea):
    print("Searching for stage1 patterns from 0x{:X} to 0x{:X}".format(ea, end_ea))

    # Combine all patterns, keeping your original format
    patterns = [
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
    for pattern_group, desc, segment_type in patterns:
        if not isinstance(pattern_group, list):
            pattern_group = [pattern_group]
        for pattern in pattern_group:
            for m in pattern.compile().finditer(mem.mem_results):
                match_len = m.end() - m.start()
                matched_bytes = mem.mem_results[m.start() : m.end()]
                matched_groups = {
                    k: f"{v.hex()}" for k, v in m.groupdict().items() if k != "padding"
                }
                if "jump" in matched_groups:
                    offset = struct.unpack("<b", matched_bytes[-1:])[0]
                    target = ea + m.start() + match_len + offset
                    matched_groups["target"] = format_addr(target)
                elif "first_jump" in matched_groups:
                    offset = struct.unpack("<b", matched_bytes[1:2])[0]
                    matched_groups["first_target"] = format_addr(
                        ea + m.start() + 2 + offset
                    )
                    offset = struct.unpack("<b", matched_bytes[-1:])[0]
                    target = ea + m.start() + match_len + offset
                    matched_groups["second_target"] = format_addr(target)
                all_chains.add_chain(
                    MatchChain(
                        base_address=ea,
                        segments=[
                            MatchSegment(
                                start=m.start(),
                                length=match_len,
                                description=desc,
                                matched_bytes=matched_bytes,
                                segment_type=segment_type,
                                matched_groups=matched_groups,
                            )
                        ],
                    )
                )
    all_chains.sort()
    return all_chains


# Function to find junk instructions after stage1 matches
def find_junk_instructions_after_stage1(mem, stage1_chains, start_ea, func_end):
    """
    - Register-based operations (0-57): ~58% chance.
    - RDTSC (58-60): ~3% chance.
    - PUSH imm32 (61-62): ~2% chance.
    - PUSH imm8 (63-65): ~3% chance.
    - Single-byte instructions (66-75): ~10% chance.
    - Conditional jumps with 8-bit offset (76-80): ~5% chance.
    - Conditional jumps with 32-bit offset (81-90): ~10% chance.
    - CALL instruction (91-99): ~9% chance.
    """
    print(
        f"\nPhase 2: Checking for junk instructions immediately following Stage1 matches"
    )

    for chain in stage1_chains:
        stage1_start = chain.overall_start()
        stage1_len = chain.overall_length()
        stage1_desc = chain.segments[0].description
        stage1_bytes = chain.overall_matched_bytes()

        # Calculate the position immediately after the Stage1 match in mem_results
        current_pos = stage1_start + stage1_len - start_ea
        if current_pos >= len(mem.mem_results):
            # skip if there's no room for junk
            continue

        # Extract the buffer after the Stage1 match
        post_stage1_buffer = mem.mem_results[current_pos:]
        total_junk_len = 0

        # Iterate while there's enough space for another junk instruction (> 6 bytes)
        while len(post_stage1_buffer) > 6:
            junk_found = False
            for junk_pattern in JUNK_PATTERNS:
                match = junk_pattern.compile().match(post_stage1_buffer)
                if match:
                    junk_len = match.end() - match.start()
                    junk_bytes = post_stage1_buffer[:junk_len]
                    chain.append_junk(
                        junk_start=current_pos + total_junk_len,
                        junk_len=junk_len,
                        junk_desc=junk_pattern.description,
                        junk_bytes=junk_bytes,
                    )
                    total_junk_len += junk_len
                    post_stage1_buffer = post_stage1_buffer[junk_len:]
                    junk_found = True
                    break  # Move to the next portion of the buffer

            if not junk_found:
                break
    stage1_chains.sort()
    return stage1_chains


def find_big_instruction(buffer_bytes, is_x64=False):
    """
    Find the 'big instruction' in a 6-byte buffer, checking specific positions from the end.
    According to the constraints, the buffer will always be exactly 6 bytes.

    Args:
        buffer_bytes (bytes): The 6-byte buffer to analyze.
        is_x64 (bool): Whether to check for REX prefixes (x64 mode).

    Returns:
        dict: A dictionary containing information about the found instruction.
    """
    assert len(buffer_bytes) == 6, "Buffer must be exactly 6 bytes"

    # Function to check if a byte is a valid REX prefix (0x40-0x4F)
    def is_rex_prefix(byte):
        return 0x40 <= byte <= 0x4F

    # Function to check if a byte is a valid ModR/M byte (0x80-0xBF)
    def is_valid_modrm(byte):
        return 0x80 <= byte <= 0xBF

    # Ensure we have a 6-byte buffer
    if len(buffer_bytes) != 6:
        return {
            "type": None,
            "name": "Invalid buffer size",
            "instruction": [],
            "position": -1,
            "junk_before": buffer_bytes,
            "junk_after": [],
        }

    # 1. First check for 3-byte instructions in x64 mode (highest priority)
    if is_x64:
        # Check all possible positions for 3-byte instructions (REX + opcode + ModR/M)
        for pos in range(4):  # Start positions 0, 1, 2, 3
            if pos + 2 >= len(buffer_bytes):
                continue

            rex = buffer_bytes[pos]
            opcode = buffer_bytes[pos + 1]
            modrm = buffer_bytes[pos + 2]

            if is_rex_prefix(rex):
                # Check if it forms a valid 3-byte instruction
                if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
                    # Get junk bytes at the end (based on position)
                    junk_after = buffer_bytes[pos + 3 :]

                    # Verify junk bytes constraint for 3-byte instructions
                    expected_junk_bytes = max(0, 3 - pos)
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
                    # Get junk bytes at the end (based on position)
                    junk_after = buffer_bytes[pos + 3 :]

                    # Verify junk bytes constraint for 3-byte instructions
                    expected_junk_bytes = max(0, 3 - pos)
                    if len(junk_after) == expected_junk_bytes:
                        return {
                            "type": "3-byte",
                            "name": "REX + Two-byte Big instruction",
                            "instruction": [rex, opcode, modrm],
                            "position": pos,
                            "junk_before": buffer_bytes[:pos],
                            "junk_after": junk_after,
                        }

    # 2. Next check for 2-byte instructions
    for pos in range(5):  # Start positions 0, 1, 2, 3, 4
        if pos + 1 >= len(buffer_bytes):
            continue

        opcode = buffer_bytes[pos]
        modrm = buffer_bytes[pos + 1]

        # Check if it forms a valid 2-byte instruction
        if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
            # Get junk bytes at the end (based on position)
            junk_after = buffer_bytes[pos + 2 :]

            # Verify junk bytes constraint for 2-byte instructions
            expected_junk_bytes = max(0, 4 - pos)
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
            # Get junk bytes at the end (based on position)
            junk_after = buffer_bytes[pos + 2 :]

            # Verify junk bytes constraint for 2-byte instructions
            expected_junk_bytes = max(0, 4 - pos)
            if len(junk_after) == expected_junk_bytes:
                return {
                    "type": "2-byte",
                    "name": "Two-byte Big instruction",
                    "instruction": [opcode, modrm],
                    "position": pos,
                    "junk_before": buffer_bytes[:pos],
                    "junk_after": junk_after,
                }

    # 3. Finally check for 1-byte instructions (lowest priority)
    pos = 5  # Only valid position for 1-byte instruction (last byte)
    if pos < len(buffer_bytes):
        byte = buffer_bytes[pos]
        if byte in SINGLE_BYTE_OPCODE_SET:
            return {
                "type": "1-byte",
                "name": "Single-byte big instruction",
                "instruction": [byte],
                "position": pos,
                "junk_before": buffer_bytes[:pos],
                "junk_after": [],  # No junk after 1-byte instruction at the end
            }

    # No valid instruction found
    return {
        "type": None,
        "name": "No match found",
        "instruction": [],
        "position": -1,
        "junk_before": buffer_bytes,
        "junk_after": [],
    }


def filter_match_chains(match_chains):
    """
    Filters out match chains that are false positives based on two criteria:
      - The total length of the anti-disassembly routine must be between 12 and 129 bytes.
      - The junk length must be nonzero.
    """
    valid_chains = []
    for chain in match_chains:
        total_length = chain.overall_length()
        junk_length = (
            chain.junk_length
        )  # assumes this property returns the total length of junk instructions
        if junk_length == 0:
            # Likely a false positive since no junk instructions were found.
            continue
        if total_length < 12 or total_length > 129:
            # Stub does not meet size constraints.
            continue
        valid_chains.append(chain)
    return valid_chains


def filter_antidisasm_patterns(mem, chains, start_ea, min_size=12, max_size=129):
    """
    Filter out false positive anti-disassembly patterns and handle overlaps.
    Integrates with existing big instruction detection code.

    Args:
        chains: List of MatchChain objects
        mem: Memory object containing binary data
        start_ea: Starting effective address
        min_size: Minimum valid size for an anti-disassembly routine (default: 12)
        max_size: Maximum valid size for an anti-disassembly routine (default: 129)

    Returns:
        List of validated MatchChain objects
    """
    # Stage 1: Basic filtering based on size and junk presence
    print("Stage 1: Basic validation")
    filtered_chains = []

    for chain in chains:

        # Apply basic filters
        length = chain.overall_length()
        if length < min_size or length > max_size:
            print(
                f"  Rejected: {chain.description} @ 0x{chain.overall_start():X} - length {length} outside valid range {min_size}-{max_size}"
            )
            continue

        if not chain.junk_segments or chain.junk_length == 0:
            print(
                f"  Rejected: {chain.description} @ 0x{chain.overall_start():X} - no junk instructions"
            )
            continue

        # If big instruction hasn't been detected yet, we'll validate it in Stage 2
        filtered_chains.append(chain)

    print(f"  After basic filtering: {len(filtered_chains)} chains remain")

    # Stage 2: Validate big instructions if not already done
    print("Stage 2: Big instruction validation")
    validated_with_big_instr = []

    for chain in filtered_chains:
        # Check if we already have a big instruction segment
        if any(
            seg.segment_type == SegmentType.BIG_INSTRUCTION for seg in chain.segments
        ):
            validated_with_big_instr.append(chain)
            continue

        # Find the big instruction
        match_start = chain.overall_start()
        chain_end = match_start + max_size

        print(f"Analyzing match: {chain.description} @ 0x{match_start:X}")

        # Determine possible jump targets - using your existing code
        jump_targets = JumpTargetAnalyzer(
            chain.overall_matched_bytes(), match_start, chain_end, start_ea
        ).process(mem=mem, chain=chain)

        big_instr_found = False

        for target in jump_targets:
            # The most_likely_target represents the most likely jump target within the
            # stub—likely the point where execution exits to the unobfuscated code.
            # however, if we do not find a match, then we want to continue searching
            # previous targets and use those in decending order until we find a match
            print(f"most_likely_target: 0x{target:X}, block_end: {chain_end:X}")
            # Check for big instruction in the 6 bytes before target
            # a big instruction (e.g., one with a 32-bit operand, up to 6 bytes)
            # just before the final jump target to confuse disassemblers.
            search_start = target - 6
            if search_start < start_ea:
                continue

            # Extract the 6-byte buffer
            buffer_offset = search_start - start_ea
            target_offset = target - start_ea

            if buffer_offset < 0 or target_offset > len(mem.mem_results):
                continue

            search_bytes = mem.mem_results[buffer_offset:target_offset]
            print(f"search_bytes: {search_bytes.hex()}")
            if len(search_bytes) != 6:
                continue  # Skip if we can't get exactly 6 bytes

            result = find_big_instruction(search_bytes, is_x64=is_x64())
            if not result["type"]:
                # if we do not find a match, then we want to find the previous targets and use those
                # in decending order until we find a match
                continue

            # Found a valid big instruction
            big_instr_found = True

            # check for multiple anti-disassembly bytes after search_start + 6
            # if found, then we want to add them to the new_bytes
            new_len = 6
            new_bytes = search_bytes

            # Check for additional anti-disassembly bytes
            for i in itertools.count():
                extra_offset = buffer_offset + 6 + i

                b = mem.mem_results[extra_offset]
                if b != SUPERFLULOUS_BYTE:
                    break

                new_bytes += bytes([b])
                new_len += 1

            chain.add_segment(
                MatchSegment(
                    start=buffer_offset,
                    length=new_len,
                    description=result["name"],
                    matched_bytes=new_bytes,
                    segment_type=SegmentType.BIG_INSTRUCTION,
                )
            )
            break

        if big_instr_found:
            validated_with_big_instr.append(chain)
        else:
            print(
                f"  Rejected: {chain.description} @ 0x{chain.overall_start():X} - no valid big instruction"
            )

    print(
        f"  After big instruction validation: {len(validated_with_big_instr)} chains remain"
    )

    # Stage 3: Handle overlapping patterns
    print("Stage 3: Resolving overlaps")

    # Sort chains by start address
    sorted_chains = sorted(validated_with_big_instr, key=lambda c: c.overall_start())
    final_chains = []
    covered_ranges = []

    for chain in sorted_chains:
        chain_start = chain.overall_start()

        # Calculate chain end including the big instruction
        big_instr_segments = [
            seg
            for seg in chain.segments
            if seg.segment_type == SegmentType.BIG_INSTRUCTION
        ]
        if big_instr_segments:
            # Use the end of the big instruction as the chain end
            big_instr = big_instr_segments[-1]
            offset_in_mem = big_instr.start
            chain_end = start_ea + offset_in_mem + big_instr.length
        else:
            # Fallback to overall length if no big instruction (shouldn't happen at this point)
            chain_end = chain_start + chain.overall_length()

        # Check if this chain overlaps with an already accepted chain
        is_covered = False
        for start, end in covered_ranges:
            # Check if this chain starts within a covered range
            if chain_start >= start and chain_start < end:
                print(
                    f"  Rejected overlap: {chain.description} @ 0x{chain_start:X} - starts within existing pattern ({start:X} to {end:X})"
                )
                is_covered = True
                break

        if not is_covered:
            final_chains.append(chain)
            covered_ranges.append((chain_start, chain_end))
            print(
                f"  Accepted: {chain.description} @ 0x{chain_start:X} - valid pattern to 0x{chain_end:X}"
            )

    print(f"Filtering complete: {len(final_chains)} of {len(chains)} chains accepted")
    return final_chains


def process(start_ea, end_ea, patch_operations):
    mem = MemHelper(start_ea, end_ea)
    chains = find_stage1(mem, start_ea, end_ea)
    if not chains:
        print("No stage1 matches found!")
        return

    chains = find_junk_instructions_after_stage1(mem, chains, start_ea, end_ea)
    chains = filter_match_chains(chains)
    chains = filter_antidisasm_patterns(mem, chains, start_ea)
    print("=== Final chains ===")
    chains.sort()
    for chain in chains:
        print(chain)
        patch_operations.append(
            PatchOperation(chain.overall_start(), b"\x90" * chain.overall_length())
        )
    return patch_operations


def decompile_function(func_start: int):
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)

    ida_auto.auto_wait()


# There's a bug in IDA's API.
# If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
# This resets each problem in the reanalyzed functions.
def reset_problems_in_function(func_start: int, func_end: int):
    current_address: int = func_start
    while current_address != func_end:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        current_address = current_address + 1


def re_analyze(func_start: int, func_end: int):
    size = func_end - func_start
    ida_bytes.del_items(func_start, 0, size)
    for i in range(size):
        idaapi.create_insn(func_start + i)
    ida_funcs.add_func(func_start, func_end)
    idaapi.auto_wait()
    decompile_function(func_start)
    print(f"Reanalyzed function @ 0x{func_start:X}")
    reset_problems_in_function(func_start, func_end)


def main(start_ea: int, end_ea: int, patch=False):
    print("Starting search...")
    patch_operations = []
    process(start_ea, end_ea, patch_operations)
    print("\nSearch completed.")
    if patch:
        print("Applying patches...")
        for patch in patch_operations:
            patch.apply()
        print("Patches applied.")


if __name__ == "__main__":
    clear_output()
    ea = idaapi.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        print("No function found at current address! Aborting")
        exit(1)
    start_ea = func.start_ea
    end_ea = func.end_ea
    try:
        main(start_ea, end_ea, patch=True)
    finally:
        idc.jumpto(start_ea)

    re_analyze(start_ea, end_ea)
