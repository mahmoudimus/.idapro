# -*- coding: utf-8 -*-

"""
IDA Python script to deflow anti-disassembly stubs by sequentially tracing
execution flow, forcing jumps to be unconditional (keeping original targets),
and patching intermediate non-jump instructions with INT3 (0xCC).

Assumptions:
- Relies on pattern matching functions (placeholders below) to identify
  initial "Stage1" stub entry points.
- Assumes these Stage1 patterns represent conditional jumps that are
  effectively always taken in the obfuscated code.
- Uses Capstone for dynamic disassembly during the trace.
"""
import collections
import functools
import itertools
import logging
import re
import struct
import typing
from dataclasses import dataclass, field
from enum import Enum, auto

import capstone
import ida_allins
import ida_auto
import ida_bytes
import ida_ida
import ida_kernwin
import ida_problems
import ida_ua
import idaapi
import idc

try:
    from mutilz.helpers.ida import clear_output, format_addr
    from mutilz.logconf import configure_logging
except ImportError:

    def format_addr(addr: int) -> str:
        """Return the address formatted as a string: 0x{address:02X}"""
        return f"0x{addr:02X}"

    def clear_output():
        try:
            form = ida_kernwin.find_widget("Output window")
            ida_kernwin.activate_widget(form, True)
            ida_kernwin.process_ui_action("msglist:Clear")
        except Exception as e:
            ida_kernwin.msg_clear()
        logger.info("Output window cleared.")

    def configure_logging(log, level=logging.INFO):
        logging.basicConfig(
            level=level,
            format="[%(levelname)s] @ %(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        log.setLevel(level)


logger = logging.getLogger("anti_disassembly_deflow")
# --- Globals & Configuration ---


# Constants
INT3_OPCODE = 0xCC
UNCONDITIONAL_JMP_SHORT_OPCODE = 0xEB
UNCONDITIONAL_JMP_NEAR_OPCODE = 0xE9
DEFAULT_CHUNK_SIZE = 0x400  # Configurable size for reading bytes
MAX_TRACE_DEPTH = 50  # Safety limit for trace recursion/iteration
MAX_INSN_BYTES = 15  # Max x86 instruction length

# --- Data Structures ---

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


class ThreadUtils:
    @staticmethod
    def is_mainthread():
        """
        Return a bool that indicates if this is the main application thread.
        """
        # isinstance(threading.current_thread(), threading._MainThread)
        return idaapi.is_main_thread()

    @staticmethod
    def mainthread(f):
        """
        A debug decorator to ensure that a function is always called from the main thread.
        """

        def wrapper(*args, **kwargs):
            assert ThreadUtils.is_mainthread()
            return f(*args, **kwargs)

        return wrapper

    @staticmethod
    def not_mainthread(f):
        """
        A debug decorator to ensure that a function is never called from the main thread.
        """

        def wrapper(*args, **kwargs):
            assert not ThreadUtils.is_mainthread()
            return f(*args, **kwargs)

        return wrapper


def execute_sync(function, sync_type):
    """
    Synchronize with the disassembler for safe database access.

    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = function(*args, **kwargs)
            return 1

        if ThreadUtils.is_mainthread():
            thunk()
        else:
            idaapi.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]

    return wrapper


execute_read = functools.partial(execute_sync, sync_type=idaapi.MFF_READ)
execute_write = functools.partial(execute_sync, sync_type=idaapi.MFF_WRITE)
execute_ui = functools.partial(execute_sync, sync_type=idaapi.MFF_FAST)
IS_X64 = execute_read(ida_ida.inf_is_64bit)()

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


class MemHelper:
    def __init__(self, start: int, end: int, mem_results: bytes = b""):
        self.mem_results = mem_results
        self.mem_offsets = []
        self.start = start
        self.end = end
        if not self.mem_results:
            self._get_memory(start, end)

    def _get_memory(self, start: int, end: int):
        result = idaapi.get_bytes(start, end - start)
        self.mem_results = result
        self.mem_offsets.append((start, end - start))


@dataclass(repr=False)
class DeferredPatchOp:
    """Class to store patch operations that will be applied later."""

    class Mode(Enum):
        PATCH = auto()  # Use ida_bytes.patch_bytes
        PUT = auto()  # Use ida_bytes.put_bytes

    address: int
    byte_values: bytes
    mode: Mode = Mode.PATCH  # Default to PATCH mode
    dry_run: bool = False  # When True, don't actually apply changes

    @classmethod
    def patch(cls, address: int, byte_values: bytes, dry_run: bool = False):
        return cls(address, byte_values, cls.Mode.PATCH, dry_run)

    @classmethod
    def put(cls, address: int, byte_values: bytes, dry_run: bool = False):
        return cls(address, byte_values, cls.Mode.PUT, dry_run)

    def apply(self):
        """Apply the patch operation using either patch_bytes or put_bytes based on mode."""
        if self.dry_run:
            # Log the operation but don't actually apply it
            logger.info(f"DRY RUN: Would apply {self}")
            return

        func = idaapi.put_bytes if self.mode == self.Mode.PUT else idaapi.patch_bytes
        func(self.address, self.byte_values)

    def __str__(self):
        """String representation with hex formatting."""
        dry_run_str = " (dry run)" if self.dry_run else ""
        return f"{self.__class__.__name__}(byte_values={self.byte_values.hex()}, mode={self.mode.name}{dry_run_str} @ address=0x{self.address:X})"

    __repr__ = __str__


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
    def stage1_segment(self) -> typing.Optional[MatchSegment]:
        if self.segments and self.segments[0].segment_type in (
            SegmentType.STAGE1_SINGLE,
            SegmentType.STAGE1_MULTIPLE,
        ):
            return self.segments[0]
        return None

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

    def __len__(self):
        return len(self.chains)

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

    @execute_read
    @staticmethod
    def decode_insn(ea: int, insn: ida_ua.insn_t):
        length = ida_ua.decode_insn(insn, ea)
        return insn, length

    def follow_jump_chain(self, mem, current_ea, match_end, visited=None, depth=0):
        """
        Follow a chain of jumps starting from current_ea.
        Avoid loops or out-of-bounds jumps.
        """
        indent = "  " * depth + "|_ "
        if visited is None:
            visited = set()
        # Avoid loops or jumps outside the memory block.
        if (
            current_ea in visited
            or current_ea < self.start_ea
            or current_ea >= self.start_ea + len(mem.mem_results)
        ):
            logger.debug(
                f"{indent}Jump chain stopped: Visited or out of bounds at 0x{current_ea:X}"
            )
            return None
        visited.add(current_ea)

        curr_addr = current_ea
        while True:
            # Calculate offset and get bytes for potential instruction
            current_offset = curr_addr - self.start_ea
            max_read_len = min(
                16, len(mem.mem_results) - current_offset
            )  # Read up to 16 bytes or end of buffer
            if max_read_len <= 0:
                logger.debug(
                    f"{indent}Jump chain stopped: Reached end of buffer at 0x{curr_addr:X}"
                )
                break  # Reached end of buffer

            instruction_bytes = mem.mem_results[
                current_offset : current_offset + max_read_len
            ]

            # Decode using Capstone
            try:
                # Use list comprehension and next to get the first instruction or None
                capstone_insn = next(
                    md.disasm(instruction_bytes, curr_addr, count=1), None
                )
            except capstone.CsError as e:
                logger.error(f"{indent}Capstone decoding error at 0x{curr_addr:X}: {e}")
                break  # Stop if decoding fails

            if capstone_insn is None:
                logger.debug(
                    f"{indent}Jump chain stopped: No instruction decoded at 0x{curr_addr:X}"
                )
                break  # Stop if no instruction could be decoded

            length = capstone_insn.size

            # Skip NOPs
            if capstone_insn.id == capstone.x86.X86_INS_NOP:
                logger.debug(f"{indent}Skipping NOP at 0x{curr_addr:X}")
                curr_addr += length
                continue

            # Check if it's a jump instruction and has the expected length (2 bytes)
            is_jump = capstone.CS_GRP_JUMP in capstone_insn.groups
            if not is_jump or length != 2:
                logger.debug(
                    f"{indent}Jump chain stopped: Not a 2-byte jump at 0x{curr_addr:X} (is_jump={is_jump}, len={length})"
                )
                break  # Not the type of jump we are tracing or not 2 bytes long

            # Ensure it's a conditional jump or JMP (based on original ALL_JUMPS logic)
            # The original code checked ida_allins constants; Capstone IDs are different.
            # We'll rely on the group check and the length check for simplicity here,
            # as the original code also used ALL_JUMPS which included NN_jmp.
            # Check if the operand is an immediate value (direct jump address)
            if (
                len(capstone_insn.operands) > 0
                and capstone_insn.operands[0].type == capstone.x86.X86_OP_IMM
            ):
                target = capstone_insn.operands[0].imm
                logger.debug(
                    f"{indent}Jump instruction at 0x{curr_addr:X} targets 0x{target:X}"
                )
            else:
                logger.debug(
                    f"{indent}Jump chain stopped: Jump at 0x{curr_addr:X} is not immediate"
                )
                # If not an immediate jump, we can't follow it with this logic
                break

            # If the jump target is within the valid conditional range,
            # continue following the chain.
            if self.match_start <= target < match_end + 6:
                # Note: Recursive call still uses current_ea logic as before,
                # target is where it *lands*, current_ea is the start of the block being analyzed.
                # The recursive nature handles the chain.
                logger.debug(
                    f"{indent}Following jump from 0x{curr_addr:X} to 0x{target:X}"
                )
                return self.follow_jump_chain(
                    mem, target, match_end, visited, depth + 1
                )
            elif target == match_end + 6:
                # Landed exactly at the potential big instruction start
                logger.debug(
                    f"{indent}Jump chain ends: Reached potential big instruction start 0x{target:X}"
                )
                return target
            # Otherwise, if the target is within the *overall* memory block, return it.
            # This means the jump goes outside the matched junk+stage1 but before the big instruction.
            elif self.start_ea <= target < match_end + 6:
                logger.debug(
                    f"{indent}Jump chain ends: Target 0x{target:X} is within bounds but outside conditional range."
                )
                return target
            else:
                # Jump goes out of bounds or to an unexpected location. Stop tracing.
                logger.debug(
                    f"{indent}Jump chain stopped: Target 0x{target:X} is out of bounds."
                )
                break  # Exit the while loop, will return current_ea below

        # If no jump pattern matches or loop broken, end of the chain; return the current address.
        logger.debug(f"{indent}Jump chain naturally ends at 0x{current_ea:X}")
        return current_ea

    def process(self, mem, chain):
        """
        Process each jump match in match_bytes.
        'chain' is expected to have attributes:
          - junk_length: int
          - stage1_type: SegmentType
        """
        match_end = chain.overall_start() + chain.overall_length()
        logger.debug(
            f"Processing jumps for chain @ 0x{chain.overall_start():X}, match_end=0x{match_end:X}"
        )
        for jump_match in re.finditer(
            rb"[\xEB\x70-\x7F].", self.match_bytes, re.DOTALL
        ):
            jump_offset = jump_match.start()
            jump_ea = self.match_start + jump_offset
            final_target = self.follow_jump_chain(mem, jump_ea, match_end)
            if not final_target:
                logger.debug(
                    f"  Skipping jump at 0x{jump_ea:X}: Invalid final target 0x{final_target if final_target else 0:X}"
                )
                continue

            # Adjusted condition: Target must be *after* the match end and within 6 bytes
            if abs(final_target - match_end) > 6:
                logger.debug(
                    f"  Skipping jump at 0x{jump_ea:X}: Final target 0x{final_target:X} not within [(0x{match_end - 6:X}, 0x{match_end:X}) or (0x{match_end:X}, 0x{match_end + 6:X}]"
                )
                continue

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


def find_stage1(mem, ea, end_ea) -> MatchChains:
    logger.info(
        "Searching for stage1 patterns from 0x{:X} to 0x{:X}".format(ea, end_ea)
    )
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


def find_junk_instructions_after_stage1(
    mem, stage1_chains, start_ea, func_end
) -> MatchChains:
    logger.info(
        f"\nPhase 2: Checking for junk instructions immediately following Stage1 matches"
    )
    for chain in stage1_chains:
        stage1_start = chain.overall_start()
        stage1_len = chain.overall_length()
        stage1_desc = chain.segments[0].description
        stage1_bytes = chain.overall_matched_bytes()
        current_pos = stage1_start + stage1_len - start_ea
        if current_pos >= len(mem.mem_results):
            continue
        post_stage1_buffer = mem.mem_results[current_pos:]
        total_junk_len = 0
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
                    break
            if not junk_found:
                break
    stage1_chains.sort()
    return stage1_chains


def find_big_instruction(buffer_bytes, is_x64=False):
    assert len(buffer_bytes) == 6, "Buffer must be exactly 6 bytes"

    def is_rex_prefix(byte):
        return 0x40 <= byte <= 0x4F

    def is_valid_modrm(byte):
        return 0x80 <= byte <= 0xBF

    if len(buffer_bytes) != 6:
        return {
            "type": None,
            "name": "Invalid buffer size",
            "instruction": [],
            "position": -1,
            "junk_before": buffer_bytes,
            "junk_after": [],
        }
    if is_x64:
        for pos in range(4):
            if pos + 2 >= len(buffer_bytes):
                continue
            rex = buffer_bytes[pos]
            opcode = buffer_bytes[pos + 1]
            modrm = buffer_bytes[pos + 2]
            if is_rex_prefix(rex):
                if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
                    junk_after = buffer_bytes[pos + 3 :]
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
                    junk_after = buffer_bytes[pos + 3 :]
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
    for pos in range(5):
        if pos + 1 >= len(buffer_bytes):
            continue
        opcode = buffer_bytes[pos]
        modrm = buffer_bytes[pos + 1]
        if opcode in MED_OPCODE_SET and is_valid_modrm(modrm):
            junk_after = buffer_bytes[pos + 2 :]
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
            junk_after = buffer_bytes[pos + 2 :]
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
    pos = 5
    if pos < len(buffer_bytes):
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
    return {
        "type": None,
        "name": "No match found",
        "instruction": [],
        "position": -1,
        "junk_before": buffer_bytes,
        "junk_after": [],
    }


def filter_match_chains(match_chains: MatchChains) -> list[MatchChains]:
    valid_chains = []
    for chain in match_chains:
        total_length = chain.overall_length()
        junk_length = chain.junk_length
        if junk_length == 0:
            continue
        if total_length < 12 or total_length > 129:
            continue
        valid_chains.append(chain)
    return valid_chains


def filter_antidisasm_patterns(
    mem, chains, start_ea, min_size=12, max_size=129
) -> list[MatchChains]:
    logger.info("Stage 1: Basic validation")
    filtered_chains = []
    for chain in chains:
        length = chain.overall_length()
        if length < min_size or length > max_size:
            logger.debug(
                f"  Rejected: {chain.description} @ 0x{chain.overall_start():X} - length {length} outside valid range {min_size}-{max_size}"
            )
            continue
        if not chain.junk_segments or chain.junk_length == 0:
            logger.debug(
                f"  Rejected: {chain.description} @ 0x{chain.overall_start():X} - no junk instructions"
            )
            continue
        filtered_chains.append(chain)
    logger.info(f"  After basic filtering: {len(filtered_chains)} chains remain")
    logger.info("Stage 2: Big instruction validation")
    validated_with_big_instr = []
    for chain in filtered_chains:
        if any(
            seg.segment_type == SegmentType.BIG_INSTRUCTION for seg in chain.segments
        ):
            validated_with_big_instr.append(chain)
            continue
        match_start = chain.overall_start()
        chain_end = match_start + chain.overall_length()
        logger.info(f"Analyzing match: {chain.description} @ 0x{match_start:X}")
        jump_targets = JumpTargetAnalyzer(
            chain.overall_matched_bytes(), match_start, chain_end, start_ea
        ).process(mem=mem, chain=chain)
        big_instr_found = False
        for target in jump_targets:
            logger.info(f"most_likely_target: 0x{target:X}, block_end: {chain_end:X}")
            search_start = target - 6
            if search_start < start_ea:
                continue
            buffer_offset = search_start - start_ea
            target_offset = target - start_ea
            target_offset_forward = target - start_ea + 6
            if buffer_offset < 0 or target_offset > len(mem.mem_results):
                continue
            if target_offset_forward > len(mem.mem_results):
                logger.info(
                    f"  Rejected: {chain.description} @ 0x{match_start:X} - target_offset_forward out of bounds: {target_offset_forward}"
                )
                continue
            search_bytes_backwards = mem.mem_results[buffer_offset:target_offset]
            search_bytes_forwards = mem.mem_results[target_offset:target_offset_forward]

            for start_offset, search_bytes in [
                (buffer_offset, search_bytes_backwards),
                (target_offset, search_bytes_forwards),
            ]:
                logger.info(f"search_bytes: {search_bytes.hex()}")
                # up to 6 bytes to search for a big instruction.
                if len(search_bytes) != 6:
                    logger.info(
                        f"  Rejected: {chain.description} @ 0x{match_start:X} - search_bytes too long: {len(search_bytes)} bytes"
                    )
                    continue
                result = find_big_instruction(search_bytes, is_x64=IS_X64)

                if not result["type"]:
                    continue
                big_instr_found = True

                new_len = (
                    len(result["junk_before"])
                    + len(result["instruction"])
                    + len(result["junk_after"])
                )
                new_bytes = (
                    result["junk_before"]
                    + bytes(result["instruction"])
                    + bytes(result["junk_after"])
                )
                for i in itertools.count():
                    extra_offset = start_offset + new_len + i
                    b = mem.mem_results[extra_offset]
                    if b != SUPERFLULOUS_BYTE:
                        break
                    new_bytes += bytes([b])
                    new_len += 1
                chain.add_segment(
                    MatchSegment(
                        start=start_offset,
                        length=new_len,
                        description=result["name"],
                        matched_bytes=new_bytes,
                        segment_type=SegmentType.BIG_INSTRUCTION,
                    )
                )
                break
            if big_instr_found:
                validated_with_big_instr.append(chain)
                break
            else:
                logger.info(
                    f"  Rejected: {chain.description} @ 0x{chain.overall_start():X} - no valid big instruction found for any jump target"
                )
    logger.info(
        f"  After big instruction validation: {len(validated_with_big_instr)} of {len(chains)} chains remain"
    )
    logger.info("Stage 3: Resolving overlaps")
    sorted_chains: list[MatchChains] = sorted(
        validated_with_big_instr, key=lambda c: c.overall_start()
    )
    final_chains: list[MatchChains] = []
    covered_ranges: list[tuple[int, int]] = []
    for chain in sorted_chains:
        chain_start = chain.overall_start()
        big_instr_segments = [
            seg
            for seg in chain.segments
            if seg.segment_type == SegmentType.BIG_INSTRUCTION
        ]
        if big_instr_segments:
            big_instr = big_instr_segments[-1]
            offset_in_mem = big_instr.start
            chain_end = start_ea + offset_in_mem + big_instr.length
        else:
            chain_end = chain_start + chain.overall_length()
        is_covered = False
        for start, end in covered_ranges:
            if chain_start >= start and chain_start < end:
                logger.info(
                    f"  Rejected overlap: {chain.description} @ 0x{chain_start:X} - starts within existing pattern ({start:X} to {end:X})"
                )
                is_covered = True
                break
        if not is_covered:
            final_chains.append(chain)
            covered_ranges.append((chain_start, chain_end))
            logger.info(
                f"  Accepted: {chain.description} @ 0x{chain_start:X} - valid pattern to 0x{chain_end:X}"
            )
    logger.info(
        f"Filtering complete: {len(final_chains)} of {len(chains)} chains accepted"
    )
    return final_chains


def process_chunk(
    chunk_base: int, chunk_bytes: bytes, chunk_end: int
) -> list[MatchChains]:
    """
    Processes a chunk of memory to find all relevant anti-disassembly patterns.
    This function orchestrates the calls to your pattern finding and filtering logic.
    Replace the dummy calls inside with your actual functions.
    """
    logger.info(
        f"Processing chunk 0x{chunk_base:X} - 0x{chunk_end:X} ({len(chunk_bytes)} bytes)"
    )
    mem = MemHelper(chunk_base, chunk_end, mem_results=chunk_bytes)

    # 1. Find initial Stage1 patterns
    chains: MatchChains = find_stage1(mem, chunk_base, chunk_end)
    if not chains:
        logger.info("No stage1 patterns found in chunk.")
        return []
    logger.info(f"Found {len(chains)} initial stage1 patterns.")

    # 2. Find associated junk (optional, depends if filters need it)
    chains: MatchChains = find_junk_instructions_after_stage1(
        mem, chains, chunk_base, chunk_end
    )

    # 3. Apply filters
    chains_list: list[MatchChains] = filter_match_chains(chains)
    chains_list: list[MatchChains] = filter_antidisasm_patterns(
        mem, chains_list, chunk_base
    )

    chains_list.sort()
    logger.info(f"Returning {len(chains_list)} filtered chains from chunk.")
    return chains_list


# --- Helper Functions ---


def get_jump_target(insn: capstone.CsInsn) -> typing.Optional[int]:
    """Extracts immediate jump target from a Capstone instruction."""
    if not insn.group(capstone.CS_GRP_JUMP):
        return None
    if len(insn.operands) > 0:
        op = insn.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            return op.imm
    return None


def create_unconditional_jump_patches(
    original_insn: capstone.CsInsn, target_ea: int, dry_run: bool = False
) -> list[DeferredPatchOp]:
    """
    Creates a list of DeferredPatchOp objects to make the original jump
    unconditional, pointing to target_ea. Fills remaining space with INT3.
    If conversion is impossible, patches the whole original instruction with INT3.
    """
    from_addr = original_insn.address
    available_len = original_insn.size
    patch_ops = []

    # Try JMP rel8 (requires 2 bytes)
    if available_len >= 2:
        offset8 = target_ea - (from_addr + 2)
        if -128 <= offset8 <= 127:
            jmp_bytes = bytes([UNCONDITIONAL_JMP_SHORT_OPCODE, offset8 & 0xFF])
            patch_ops.append(DeferredPatchOp.patch(from_addr, jmp_bytes, dry_run))
            # Fill remaining original bytes with INT3
            for i in range(2, available_len):
                patch_ops.append(
                    DeferredPatchOp.patch(from_addr + i, bytes([INT3_OPCODE]), dry_run)
                )
            logger.debug(
                f"  Created JMP SHORT patch ops for 0x{from_addr:X} -> 0x{target_ea:X}"
            )
            return patch_ops

    # # Try JMP rel32 (requires 5 bytes)
    # if available_len >= 5:
    #     offset32 = target_ea - (from_addr + 5)
    #     if -(2**31) <= offset32 < 2**31:
    #         jmp_bytes = bytes([UNCONDITIONAL_JMP_NEAR_OPCODE]) + struct.pack(
    #             "<i", offset32
    #         )
    #         patch_ops.append(DeferredPatchOp.patch(from_addr, jmp_bytes, dry_run))
    #         # Fill remaining original bytes with INT3
    #         for i in range(5, available_len):
    #             patch_ops.append(
    #                 DeferredPatchOp.patch(from_addr + i, bytes([INT3_OPCODE]), dry_run)
    #             )
    #         logger.debug(
    #             f"  Created JMP NEAR patch ops for 0x{from_addr:X} -> 0x{target_ea:X}"
    #         )
    #         return patch_ops

    logger.warning(
        f"Cannot create unconditional jump for 0x{from_addr:X} -> 0x{target_ea:X} with length {available_len}. Creating INT3 patches."
    )
    # Fallback: Patch original instruction with INT3
    for i in range(available_len):
        patch_ops.append(
            DeferredPatchOp.patch(from_addr + i, bytes([INT3_OPCODE]), dry_run)
        )
    return patch_ops


class NopDetector:

    _NOP_SEQUENCES = [
        b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 11 bytes
        b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 10 bytes
        b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 9 bytes
        b"\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 8 bytes
        b"\x0f\x1f\x80\x00\x00\x00\x00",  # 7 bytes
        b"\x66\x0f\x1f\x44\x00\x00",  # 6 bytes
        b"\x0f\x1f\x44\x00\x00",  # 5 bytes
        b"\x0f\x1f\x40\x00",  # 4 bytes
        b"\x0f\x1f\x00",  # 3 bytes
        b"\x66\x90",  # 2 bytes
        b"\x90",  # 1 byte
    ]
    _MAX_NOP_LEN = max(len(s) for s in _NOP_SEQUENCES)

    @functools.singledispatchmethod
    @classmethod
    def is_nop(cls, insn: capstone.CsInsn) -> bool:  # //NOSONAR
        """Checks if the instruction bytes match any known NOP sequence."""
        if insn.id == capstone.x86.X86_INS_NOP:
            return True
        for prefix in cls._NOP_SEQUENCES:
            if insn.bytes.startswith(prefix):
                return True
        return False

    @is_nop.register(ida_ua.insn_t)
    def _(cls, insn: ida_ua.insn_t) -> bool:  # //NOSONAR
        """Checks if the decoded instruction is a known NOP."""
        if not insn:
            return False
        if insn.itype == ida_ua.NN_nop:
            return True
        insn_bytes = ida_bytes.get_bytes(insn.ea, insn.size)
        if not insn_bytes:
            return False
        return any(
            insn_bytes == seq for seq in cls._NOP_SEQUENCES if len(seq) == insn.size
        )


class TraceUtils:
    """Contains static methods for tracing execution flow."""

    @staticmethod
    def trace_and_patch_jump_chain(
        md: capstone.Cs,  # Capstone instance
        mem_start_ea: int,  # Start address of the memory buffer
        mem_bytes: bytes,  # Bytes of the memory buffer
        start_trace_ea: int,  # Address to begin tracing from
        initial_processed_ea: int,  # Address after the initial segment (e.g., Stage1)
        patches_list: list[DeferredPatchOp],  # List to append patch ops to
        visited_set: set[
            int
        ],  # Set of already visited addresses in the *overall* trace
        dry_run: bool,
        current_depth: int = 0,
        max_depth: int = MAX_TRACE_DEPTH,
    ) -> int:
        """
        Traces execution flow starting from start_trace_ea.
        - Makes encountered jumps unconditional (keeping original target).
        - Patches non-jump instructions and gaps with INT3.
        - Modifies patches_list directly.
        - Returns the address *after* the last byte processed or patched by this trace segment.
        """
        current_ea = start_trace_ea
        last_processed_ea = initial_processed_ea  # Where the previous step left off

        while current_depth < max_depth:
            current_depth += 1
            logger.debug(f"  Trace step {current_depth}: current_ea = 0x{current_ea:X}")

            if current_ea in visited_set:
                logger.error(
                    f"  Cycle detected in trace at 0x{current_ea:X}. Stopping trace segment."
                )
                # Don't clear patches_list here, let the caller decide based on overall failure
                return last_processed_ea  # Return where we were before the cycle

            visited_set.add(current_ea)

            # Calculate offset within mem_bytes
            current_offset = current_ea - mem_start_ea
            if not (0 <= current_offset < len(mem_bytes)):
                logger.warning(
                    f"  Trace reached address 0x{current_ea:X} outside memory buffer [{mem_start_ea:X}-{mem_start_ea+len(mem_bytes):X}]. Stopping trace segment."
                )
                return last_processed_ea  # Return where we were

            # Read and disassemble instruction at current_ea
            try:
                # Read buffer starting from current offset
                read_len = min(MAX_INSN_BYTES, len(mem_bytes) - current_offset)
                if read_len <= 0:
                    logger.warning(
                        f"  Trace reached end of memory buffer at 0x{current_ea:X}. Stopping trace segment."
                    )
                    return last_processed_ea

                insn_buf = mem_bytes[current_offset : current_offset + read_len]
                insn = next(md.disasm(insn_buf, current_ea))
                logger.debug(
                    f"    Disassembled at 0x{insn.address:X}: {insn.mnemonic} {insn.op_str} (size={insn.size})"
                )

                target_ea = get_jump_target(insn)

                # --- Instruction Analysis ---
                # Check NOP (more robust check might be needed for all variants)

                if NopDetector.is_nop(insn):
                    logger.debug(
                        f"    NOP detected at 0x{insn.address:X}. Continuing trace."
                    )
                    last_processed_ea = insn.address + insn.size
                    current_ea = last_processed_ea  # Move to next instruction
                    continue  # Continue trace loop

                elif target_ea is not None:  # Jump with Immediate Target
                    logger.debug(
                        f"    Jump detected at 0x{insn.address:X} to 0x{target_ea:X}."
                    )
                    last_processed_ea = insn.address + insn.size
                    current_ea = target_ea  # Follow the jump target
                    if insn.mnemonic.lower() != "jmp" or insn.size == 2:
                        logger.debug(
                            f"    Planning unconditional patch and continuing trace."
                        )
                        jump_patch_ops = create_unconditional_jump_patches(
                            insn, target_ea, dry_run
                        )
                        patches_list.extend(jump_patch_ops)
                        # Fill gap between last processed instruction/segment and current one with INT3
                        logger.debug(
                            f"    Filling gap 0x{last_processed_ea:X} - 0x{target_ea-1:X} with INT3"
                        )
                        patches_list.append(
                            DeferredPatchOp(
                                last_processed_ea,
                                bytes([INT3_OPCODE] * (target_ea - last_processed_ea)),
                                dry_run,
                            )
                        )
                        # last_processed_ea = current_ea
                        # current_ea = target_ea
                    continue  # Continue trace loop

                else:  # Not a NOP, Not a Jump with Immediate Target (End of Trace Segment)
                    logger.debug(
                        f"    Trace segment ends: Non-NOP/Non-JCC instruction ('{insn.mnemonic} {insn.op_str}') or indirect jump at 0x{insn.address:X}."
                    )
                    last_processed_ea = insn.address + insn.size
                    return last_processed_ea  # Return address after this instruction

            except StopIteration:
                logger.error(
                    f"  Capstone failed to disassemble at 0x{current_ea:X}. Patching byte with INT3 and stopping trace segment."
                )
                patches_list.append(
                    DeferredPatchOp.patch(current_ea, bytes([INT3_OPCODE]), dry_run)
                )
                last_processed_ea = current_ea + 1
                return last_processed_ea
            except Exception as e:
                logger.error(
                    f"  Error during disassembly/trace at 0x{current_ea:X}: {e}. Stopping trace segment.",
                    exc_info=True,
                )
                # Don't fill gap here, just return where we were
                return last_processed_ea
        # --- End Trace Loop (Max Depth Reached) ---

        logger.error(
            f"  Trace starting 0x{start_trace_ea:X} exceeded max depth ({max_depth}). Stopping trace segment."
        )
        # Return the address we were trying to process when max depth was hit
        return current_ea


# --- Core Deflow Logic ---


def deflow_stubs_sequential_patch_in_place(
    start_ea=None, chunk_size=DEFAULT_CHUNK_SIZE, dry_run: bool = False
):
    """
    Identifies anti-disassembly stubs, traces the jump path dynamically using
    TraceUtils.trace_and_patch_jump_chain, making jumps unconditional and
    patching intermediate instructions with INT3 (0xCC).

    Args:
        start_ea (int, optional): Starting address. Defaults to idc.here().
        chunk_size (int, optional): Size of the chunk to analyze.
        dry_run (bool, optional): If True, logs planned patches but doesn't apply them.
    """
    if start_ea is None:
        start_ea = idc.here()
        if start_ea == idaapi.BADADDR:
            logger.error(
                "Invalid start address (BADADDR). Please place cursor or provide start_ea."
            )
            return

    run_mode = "DRY RUN" if dry_run else "Applying Patches"
    logger.info(
        f"Starting sequential in-place patch deflowing ({run_mode}) at 0x{start_ea:X} for {chunk_size} bytes."
    )

    # 1. Read chunk and identify potential entry points (Stage1 stubs)
    read_bytes = idaapi.get_bytes(start_ea, chunk_size)
    if not read_bytes:
        logger.error(f"Failed to read {chunk_size} bytes starting at 0x{start_ea:X}.")
        return
    chunk_end_ea = start_ea + len(read_bytes)
    logger.info(f"Read {len(read_bytes)} bytes (0x{start_ea:X} to 0x{chunk_end_ea:X}).")

    all_chains_obj: MatchChains = process_chunk(start_ea, read_bytes, chunk_end_ea)
    if not all_chains_obj:
        logger.info("No initial Stage1 stubs found by process_chunk.")
        return

    chains_by_start_addr = {c.overall_start(): c for c in all_chains_obj}
    logger.info(f"Found {len(chains_by_start_addr)} potential stub entry points.")

    # 2. Trace the flow for each entry point and collect patch operations
    all_patch_operations: list[DeferredPatchOp] = []
    processed_starts = set()

    for initial_chain_start_addr, initial_chain in chains_by_start_addr.items():
        if initial_chain_start_addr in processed_starts:
            continue

        logger.info(
            f"--- Tracing sequence starting from stub at 0x{initial_chain_start_addr:X} ---"
        )

        initial_stage1_seg = initial_chain.stage1_segment
        if not initial_stage1_seg:
            logger.warning(
                f"Initial chain at 0x{initial_chain_start_addr:X} has no stage1 segment. Skipping trace."
            )
            processed_starts.add(initial_chain_start_addr)
            continue

        initial_stage1_addr = initial_chain.base_address + initial_stage1_seg.start
        initial_stage1_len = initial_stage1_seg.length
        if initial_stage1_seg.segment_type == SegmentType.STAGE1_MULTIPLE:
            # print(f"Initial stage1 segment at 0x{initial_stage1_addr:X} is a multiple segment.")
            # print(f"  Matched bytes: {initial_stage1_seg.matched_bytes.hex()}")
            # print(f"  Matched groups: {initial_stage1_seg.matched_groups}")
            # always take the first jump in a STAGE1_MULTIPLE segment
            initial_stage1_len = 2
        initial_stage1_bytes = initial_stage1_seg.matched_bytes

        patches_for_this_trace: list[DeferredPatchOp] = []  # Collect ops for this trace
        stage1_jump_insn = None
        stage1_target_ea = None
        trace_succeeded = (
            True  # Flag to track if trace completed without critical errors
        )

        # Find the *first* jump with an immediate target within the Stage1 segment
        try:
            last_jump_found = None
            last_target_found = None
            for insn in md.disasm(initial_stage1_bytes, initial_stage1_addr):
                target = get_jump_target(insn)
                if target is not None:
                    last_jump_found = insn
                    last_target_found = target
                    logger.debug(
                        f"  Found potential Stage1 jump: {insn.mnemonic} at 0x{insn.address:X} -> 0x{target:X}"
                    )
                    break

            if last_jump_found and last_target_found is not None:
                stage1_jump_insn = last_jump_found
                stage1_target_ea = last_target_found
                logger.info(
                    f"  Identified Stage1 jump: {stage1_jump_insn.mnemonic} at 0x{stage1_jump_insn.address:X} targeting 0x{stage1_target_ea:X}"
                )
            else:
                logger.error(
                    f"Could not find a jump with immediate target within Stage1 segment at 0x{initial_stage1_addr:X}. Skipping trace."
                )
                trace_succeeded = False  # Mark trace as failed

        except Exception as e:
            logger.error(
                f"Error disassembling Stage1 segment at 0x{initial_stage1_addr:X}: {e}. Skipping trace."
            )
            trace_succeeded = False  # Mark trace as failed

        # If Stage1 jump identification failed, skip the rest
        if not trace_succeeded:
            processed_starts.add(initial_chain_start_addr)
            continue

        # # Plan the patch for the identified Stage1 jump
        # jump_patch_ops = create_unconditional_jump_patches(
        #     stage1_jump_insn, stage1_target_ea, dry_run
        # )
        # patches_for_this_trace.extend(jump_patch_ops)

        # # Initialize trace state
        # # Address *after* the entire Stage1 segment
        # initial_processed_ea = initial_stage1_addr + initial_stage1_len
        # # Prevent cycles involving the start or the jump itself
        # visited_in_trace = {initial_stage1_addr, stage1_jump_insn.address}
        visited_in_trace = set()
        # Call the static trace method
        try:
            final_processed_ea = TraceUtils.trace_and_patch_jump_chain(
                md=md,
                mem_start_ea=start_ea,
                mem_bytes=read_bytes,
                start_trace_ea=stage1_jump_insn.address,  # Start trace from target
                initial_processed_ea=stage1_jump_insn.address,  # Where Stage1 ended
                patches_list=patches_for_this_trace,  # Modify this list
                visited_set=visited_in_trace,  # Share visited set
                dry_run=dry_run,
            )
            logger.debug(
                f"  Trace segment finished, processed up to 0x{final_processed_ea:X}"
            )
            # Check if the trace itself reported a cycle or critical error (indicated by patches being cleared previously, though we removed that)
            # We rely on the logs for now. If trace_succeeded is still True, add patches.

        except Exception as e:
            logger.exception(
                f"  Unexpected error during TraceUtils call for 0x{initial_chain_start_addr:X}: {e}"
            )
            trace_succeeded = False  # Mark trace as failed

        # Add successfully generated patches for this trace to the main list
        # Only add if the trace didn't encounter critical errors (like cycles)
        if trace_succeeded:
            all_patch_operations.extend(patches_for_this_trace)
        else:
            logger.warning(
                f"  Discarding {len(patches_for_this_trace)} patches from failed trace for 0x{initial_chain_start_addr:X}."
            )

        processed_starts.add(
            initial_chain_start_addr
        )  # Mark initial start as processed

    # 3. Resolve conflicts and apply patches (This part remains the same)
    if not all_patch_operations:
        logger.info("No patch operations were generated.")
        return

    logger.info(f"Resolving {len(all_patch_operations)} planned patch operations.")
    final_patches = {}  # {address: byte_value} - Last write wins
    for op in all_patch_operations:
        for i, byte_val in enumerate(op.byte_values):
            final_patches[op.address + i] = byte_val

    logger.info(f"Applying {len(final_patches)} final byte patches.")
    applied_count = 0
    failed_count = 0
    # Create DeferredPatchOp list from the final resolved patches for application
    final_ops_to_apply = []
    sorted_addresses = sorted(final_patches.keys())
    addr_iter = iter(sorted_addresses)

    try:
        current_addr = next(addr_iter)
        while True:
            patch_start_addr = current_addr
            patch_bytes_list = [bytes([final_patches[current_addr]])]
            try:
                next_addr = next(addr_iter)
                while next_addr == current_addr + 1:
                    patch_bytes_list.append(bytes([final_patches[next_addr]]))
                    current_addr = next_addr
                    next_addr = next(addr_iter)
                current_addr = next_addr
            except StopIteration:
                pass
            # Create a single op for the contiguous block
            final_ops_to_apply.append(
                DeferredPatchOp.patch(
                    patch_start_addr, b"".join(patch_bytes_list), dry_run
                )
            )
            if current_addr == patch_start_addr:
                break
    except StopIteration:
        pass  # No patches

    # Apply the final, conflict-resolved, contiguous patches
    for op in final_ops_to_apply:
        if op.apply():
            applied_count += len(op.byte_values)
        elif not dry_run:  # Only count failures if not dry run
            failed_count += len(op.byte_values)

    result_str = (
        f"Applied {applied_count} bytes."
        if not dry_run
        else f"Previewed {applied_count} byte changes."
    )
    if failed_count > 0:
        result_str += f" Failed to apply {failed_count} bytes."
    logger.info(f"Sequential in-place patch deflowing finished. {result_str}")

    # 4. Reanalyze the patched area if not dry run
    if applied_count > 0 and not dry_run:
        logger.info(
            f"Requesting IDA reanalysis for range 0x{start_ea:X} - 0x{chunk_end_ea:X}..."
        )
        # ida_auto.auto_mark_range(section_start, section_end, ida_auto.AU_CODE)
        # attempt to re-analyze the reverted region
        ida_auto.plan_and_wait(start_ea, chunk_end_ea, True)
        # There's a bug in IDA's API.
        # If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
        # This resets each problem in the reanalyzed functions.
        current_address: int = start_ea
        while current_address != chunk_end_ea:
            ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
            current_address = current_address + 1

        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.refresh_idaview_anyway()
        logger.info("Reanalysis complete.")
    else:
        logger.info("No patches were applied, skipping reanalysis.")


# --- Example Usage ---

if __name__ == "__main__":
    # This block allows running the script directly from IDA's script execution
    clear_output()
    # --- Configuration ---
    DRY_RUN_MODE = True  # Set to True to preview patches without applying
    START_ADDRESS = None  # Set to specific address or None to use cursor
    CHUNK_SIZE_TO_ANALYZE = DEFAULT_CHUNK_SIZE  # Adjust as needed
    LOG_LEVEL = logging.DEBUG  # Change to logging.DEBUG for verbose logs
    # --- End Configuration ---

    # Configure logging level
    logger.setLevel(LOG_LEVEL)

    # Run the deflower
    try:
        deflow_stubs_sequential_patch_in_place(
            start_ea=START_ADDRESS,
            chunk_size=CHUNK_SIZE_TO_ANALYZE,
            dry_run=DRY_RUN_MODE,
        )
    except Exception as e:
        logger.exception(f"An unexpected error occurred during deflowing: {e}")

    pass  # End of example usage block
    pass  # End of example usage block
