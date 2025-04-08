import collections
import concurrent.futures
import functools
import itertools
import logging
import re
import struct
import threading
import traceback
import typing
from dataclasses import dataclass, field
from enum import Enum, auto

import capstone
import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_problems
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


try:
    from mutilz.helpers.ida import clear_output
    from mutilz.logconf import configure_logging
except ImportError:
    # Placeholder for mutilz functions if not available
    def clear_output():
        ida_kernwin.msg_clear()
        logger.info("Output window cleared.")

    def configure_logging(log, level=logging.INFO):
        logging.basicConfig(
            level=level,
            format="[%(levelname)s] @ %(asctime)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        log.setLevel(level)


logger = logging.getLogger("_rm_anti_dasm_threaded")


# --- Constants ---
MAX_BLOB_INDEX = 12
BLOB_NAME_PATTERN = "g_bufInitBlob{idx}"
# Use a shared dictionary in __main__ for script states
SHARED_STATE_DICT_NAME = "g_script_state_storage"
# Key specific to this script within the shared dictionary
CACHE_KEY_NAME = "blob_finder_next_index"
# Configuration options
USE_THREADS = False  # Set to False to disable threading
TOTAL_THREADS = 4  # Set the desired number of threads when threading is enabled


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


def format_addr(addr: int) -> str:
    """Return the address formatted as a string: 0x{address:02X}"""
    return f"0x{addr:02X}"


def clear_output():
    form = ida_kernwin.find_widget("Output window")
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


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


def decompile_function(func_start: int):
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.decompile_func(ida_funcs.get_func(func_start), hf)
    ida_auto.auto_wait()


def reset_problems_in_function(func_start: int, func_end: int):
    logger.info(
        f"Resetting disassembly problems in range 0x{func_start:X}-0x{func_end:X}"
    )
    problem_count = 0
    # Iterate through addresses in the function/range
    ea = func_start
    while ea < func_end:
        # Check for problems at the current address
        ptype = ida_problems.get_problem_type(ida_problems.PR_DISASM, ea)
        if ptype != ida_problems.PR_OK:
            ida_problems.forget_problem(ida_problems.PR_DISASM, ea)
            problem_count += 1
        # Move to the next potential instruction head or next byte if needed
        next_ea = idc.next_head(ea, func_end)
        if next_ea == idc.BADADDR or next_ea <= ea:
            ea += 1  # Increment by one if next_head fails or doesn't advance
        else:
            ea = next_ea
    logger.info(f"Cleared {problem_count} disassembly problems.")


def re_analyze(func_start: int, func_end: int):
    logger.info(f"Re-analyzing function range 0x{func_start:X}-0x{func_end:X}")
    size = func_end - func_start
    ida_bytes.del_items(func_start, 0, size)
    for i in range(size):
        idaapi.create_insn(func_start + i)
    ida_funcs.add_func(func_start, func_end)
    idaapi.auto_wait()
    decompile_function(func_start)
    logger.info(f"Reanalyzed function @ 0x{func_start:X}")
    reset_problems_in_function(func_start, func_end)


def process_chunk(chunk_base: int, chunk_bytes: bytes, chunk_end: int) -> list[MatchChains]:
    """
    Process a chunk of the memory region.
    Create a MemHelper for the chunk, and override its mem_results with the given chunk_bytes.
    Then run the stage1, junk analysis, and filtering functions on that memory region.
    """
    # Use the MemHelper class to create a memory object for this chunk.
    dummy_mem = MemHelper(chunk_base, chunk_end, mem_results=chunk_bytes)

    chains: MatchChains = find_stage1(dummy_mem, chunk_base, chunk_end)
    if not chains or not chains.chains:
        return []
    chains: MatchChains = find_junk_instructions_after_stage1(
        dummy_mem, chains, chunk_base, chunk_end
    )
    chains: list[MatchChains] = filter_match_chains(chains)
    chains: list[MatchChains] = filter_antidisasm_patterns(
        dummy_mem, chains, chunk_base
    )
    chains.sort()
    # Return the list of MatchChain objects from this chunk.
    return chains


# ---------------------------------------------------------------------------
# Object-Oriented Processor with Parallel Chunk Processing
# ---------------------------------------------------------------------------
class AntiDisasmProcessor:
    """
    Encapsulates anti-disassembly analysis and patching.
    If end_ea is None, the entire segment is processed.
    Uses configurable concurrent processing to analyze chunks in parallel,
    then applies patches serially.
    """

    def __init__(
        self,
        start_ea: int,
        end_ea: typing.Optional[int] = None,
        patch: bool = False,
        use_threads: bool = True,  # New parameter: whether to use threads
        num_threads: int = 4,  # New parameter: total number of threads
    ):
        self.start_ea = start_ea
        self.end_ea = end_ea if end_ea is not None else self._get_section_end(start_ea)
        self.patch = patch
        self.use_threads = use_threads
        self.num_threads = num_threads
        # Read the entire memory region once.
        self.mem = MemHelper(self.start_ea, self.end_ea)
        self.patch_operations = []

    def _get_section_end(self, start_ea: int) -> int:
        seg = idaapi.getseg(start_ea)
        if seg:
            return seg.end_ea
        else:
            raise ValueError(f"No segment found for address 0x{start_ea:X}")

    def parallel_process(self, chunk_size: int = 4096):
        """
        Splits the full memory buffer into chunks (with an overlap to account for stubs
        that may cross chunk boundaries), then processes each chunk.
        Returns a merged list of all MatchChain objects found.
        """
        full_bytes = self.mem.mem_results
        region_length = len(full_bytes)
        overlap = 129  # maximum anti-disassembly stub size
        chunks = []
        # Split into chunks with overlap (except for the last chunk)
        for offset in range(0, region_length, chunk_size):
            end_offset = min(region_length, offset + chunk_size)
            # If not the last chunk, extend by the overlap.
            if end_offset < region_length:
                end_offset = min(region_length, end_offset + overlap)
            chunk_base = self.start_ea + offset
            chunk_bytes = full_bytes[offset:end_offset]
            chunk_end = self.start_ea + end_offset
            chunks.append((chunk_base, chunk_bytes, chunk_end))

        all_chains = []
        if self.use_threads:
            # Execute in parallel using the configured number of threads
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.num_threads
            ) as executor:
                future_to_base = {
                    executor.submit(process_chunk, base, chunk, end_addr): base
                    for (base, chunk, end_addr) in chunks
                }
                for future in concurrent.futures.as_completed(future_to_base):
                    base_addr = future_to_base[future]
                    try:
                        chains = future.result()
                        all_chains.extend(chains)
                    except Exception as e:
                        logger.error(
                            f"Error processing chunk starting at 0x{base_addr:X}: {e}"
                        )
                        traceback.print_exc()
        else:
            # Execute sequentially (no threads)
            for base, chunk, end_addr in chunks:
                try:
                    chains = process_chunk(base, chunk, end_addr)
                    all_chains.extend(chains)
                except Exception as e:
                    logger.error(f"Error processing chunk starting at 0x{base:X}: {e}")
                    traceback.print_exc()

        all_chains.sort(key=lambda chain: chain.overall_start())
        return all_chains

    def process(self):
        """
        Runs the analysis using the (possibly parallel) chunk processing.
        Creates a list of patch operations from the merged results.
        """
        logger.info("Starting anti-disassembly analysis...")
        all_chains = self.parallel_process(chunk_size=4096)
        for chain in all_chains:
            self.patch_operations.append(
                PatchOperation(chain.overall_start(), b"\x90" * chain.overall_length())
            )
        logger.info(
            "Analysis completed. Found {} patch operations.".format(
                len(self.patch_operations)
            )
        )

    def apply_patches(self):
        if not self.patch_operations:
            self.process()
        logger.info("Applying patches serially...")
        for op in self.patch_operations:
            op.apply()
        logger.info("Patches applied.")

    def run(self):
        self.process()
        if self.patch:
            self.apply_patches()

    def reanalyze(self):
        size = self.end_ea - self.start_ea
        ida_bytes.del_items(self.start_ea, 0, size)
        for i in range(size):
            idaapi.create_insn(self.start_ea + i)
        ida_funcs.add_func(self.start_ea, self.end_ea)
        idaapi.auto_wait()
        decompile_function(self.start_ea)
        logger.info(f"Reanalyzed section @ 0x{self.start_ea:X}")
        reset_problems_in_function(self.start_ea, self.end_ea)


def _determine_alignment_exponent(address: int) -> int:
    """
    Determines the alignment exponent (log2) based on the address.
    Checks for 16, 8, 4, 2 byte alignment. Returns 0 if none match.
    """
    if (address % 16) == 0:
        return 4  # log2(16)
    elif (address % 8) == 0:
        return 3  # log2(8)
    elif (address % 4) == 0:
        return 2  # log2(4)
    elif (address % 2) == 0:
        return 1  # log2(2)
    else:
        return 0  # No specific alignment (or 1-byte aligned)


class SearchStrategy(Enum):
    BACKWARD_SCAN = auto()
    FORWARD_CHUNK = auto()


def _search_range(
    ea: int,
    check_instruction: typing.Callable[[ida_ua.insn_t], bool],
    max_range: int = 0x200,
    strategy: SearchStrategy = SearchStrategy.BACKWARD_SCAN,
) -> typing.Optional[int]:
    # (Implementation remains the same as previous correct version)
    if strategy == SearchStrategy.BACKWARD_SCAN:
        start_addr = max(ea - max_range, 0)
        current = ea
        while current >= start_addr:
            if not ida_bytes.is_loaded(current):
                current -= 1
                continue
            insn = ida_ua.insn_t()
            prev_head_ea = idc.prev_head(current)
            if prev_head_ea == idc.BADADDR or prev_head_ea < start_addr:
                break
            if not ida_bytes.is_loaded(prev_head_ea):
                current = prev_head_ea
                continue
            if ida_ua.decode_insn(insn, prev_head_ea) > 0:
                if check_instruction(insn):
                    return insn.ea
                current = prev_head_ea
            else:
                current -= 1

    elif strategy == SearchStrategy.FORWARD_CHUNK:
        current = ea
        end_addr = ea + max_range
        while current < end_addr:
            if not ida_bytes.is_loaded(current):
                current += 1
                continue
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, current)
            if insn_len > 0:
                if check_instruction(insn):
                    return current
                current += insn.size
            else:
                current += 1

    logger.debug(
        "No anchor found within range [0x%X - 0x%X] relative to 0x%X",
        max_range,
        max_range,
        ea,
    )
    return None


# --- Rest of the classes (GarbageBlobFinder, FunctionPaddingFinder) ---
# --- and execute() function remain the same as the previous correct version ---


class GarbageBlobFinder:
    # (Implementation remains the same as previous correct version)
    @staticmethod
    def _check(insn: ida_ua.insn_t) -> bool:
        mnem = insn.get_canon_mnem().lower()
        if mnem == "lea" and insn.ops[0].type == ida_ua.o_reg:
            dest_reg = idaapi.get_reg_name(insn.ops[0].reg, 8)
            if dest_reg and (dest_reg.lower() == "rdi" or dest_reg.lower() == "rdx"):
                if insn.ops[1].type == ida_ua.o_imm:
                    logger.debug("Found matching lea (rdi/rdx, imm) @ 0x%X", insn.ea)
                    return True
                elif insn.ops[1].type in [ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far]:
                    target_ea = idc.get_operand_value(insn.ea, 1)
                    if target_ea != idc.BADADDR:
                        logger.debug(
                            "Found matching lea (rdi/rdx, mem) @ 0x%X -> 0x%X",
                            insn.ea,
                            target_ea,
                        )
                        return True
        return False

    @classmethod
    def get_garbage_blobs(cls):
        text_seg = idaapi.get_segm_by_name(".text")
        if not text_seg:
            logger.error("Error: .text section not found.")
            return
        first_xref_to_text = None
        for xref in idautils.XrefsTo(text_seg.start_ea, 0):
            xref = typing.cast(ida_xref.xrefblk_t, xref)
            if not ida_bytes.is_loaded(xref.frm):
                continue
            seg_name = idc.get_segm_name(xref.frm)
            if seg_name == ".text":
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, xref.frm) > 0:
                    mnem = insn.get_canon_mnem().lower()
                    op1_type = insn.ops[0].type
                    op1_reg_name = ""
                    if op1_type == ida_ua.o_reg:
                        op1_reg_name = idaapi.get_reg_name(insn.ops[0].reg, 8)
                        if op1_reg_name:
                            op1_reg_name = op1_reg_name.lower()
                    op2_val = idc.get_operand_value(xref.frm, 1)
                    if (
                        mnem == "lea"
                        and op1_type == ida_ua.o_reg
                        and op1_reg_name == "rdi"
                        and op2_val == text_seg.start_ea
                    ):
                        logger.info(
                            f"Found potential blob 0 init: lea rdi, 0x{text_seg.start_ea:X} at 0x{xref.frm:X}"
                        )
                        first_xref_to_text = xref
                        yield xref
                        break
        if not first_xref_to_text:
            logger.warning("Could not find initial 'lea rdi, .text_start' instruction.")
            for xref in idautils.XrefsTo(text_seg.start_ea, 0):
                if not ida_bytes.is_loaded(xref.frm):
                    continue
                seg_name = idc.get_segm_name(xref.frm)
                if seg_name == ".text":
                    logger.warning(
                        f"Using fallback xref to .text start from 0x{xref.frm:X}"
                    )
                    first_xref_to_text = xref
                    yield xref
                    break
            if not first_xref_to_text:
                logger.error("No xref found to .text segment start from within .text.")
                return
        search_base_ea = first_xref_to_text.frm
        found_blob12 = False
        next_addr = idc.next_head(search_base_ea)
        if next_addr != idc.BADADDR and ida_bytes.is_loaded(next_addr):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, next_addr) > 0 and cls._check(insn):
                op_val = idc.get_operand_value(next_addr, 1)
                if op_val != idc.BADADDR and op_val > text_seg.start_ea:
                    try:
                        xref_to_blob12 = next(idautils.XrefsTo(op_val, 0))
                        logger.info(
                            f"Found potential blob 12 init (next insn): 0x{next_addr:X} -> 0x{op_val:X}"
                        )
                        yield xref_to_blob12
                        found_blob12 = True
                    except StopIteration:
                        logger.warning(
                            f"Instruction at 0x{next_addr:X} points to 0x{op_val:X}, but no xrefs found *to* it."
                        )
        if not found_blob12:
            prev_addr = idc.prev_head(search_base_ea)
            if prev_addr != idc.BADADDR and ida_bytes.is_loaded(prev_addr):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, prev_addr) > 0 and cls._check(insn):
                    op_val = idc.get_operand_value(prev_addr, 1)
                    if op_val != idc.BADADDR and op_val > text_seg.start_ea:
                        try:
                            xref_to_blob12 = next(idautils.XrefsTo(op_val, 0))
                            logger.info(
                                f"Found potential blob 12 init (prev insn): 0x{prev_addr:X} -> 0x{op_val:X}"
                            )
                            yield xref_to_blob12
                            found_blob12 = True
                        except StopIteration:
                            logger.warning(
                                f"Instruction at 0x{prev_addr:X} points to 0x{op_val:X}, but no xrefs found *to* it."
                            )
        if not found_blob12:
            search_strategies = [
                (SearchStrategy.BACKWARD_SCAN, search_base_ea),
                (SearchStrategy.FORWARD_CHUNK, idc.next_head(search_base_ea)),
            ]
            for strategy, start_ea in search_strategies:
                if start_ea == idc.BADADDR:
                    continue
                if not ida_bytes.is_loaded(start_ea):
                    logger.debug(
                        f"Skipping search from non-loaded address 0x{start_ea:X}"
                    )
                    continue
                logger.debug(
                    f"Searching for blob 12 init near 0x{start_ea:X} using {strategy.name}"
                )
                found_ea = _search_range(
                    start_ea, cls._check, max_range=0x50, strategy=strategy
                )
                if found_ea:
                    op_val = idc.get_operand_value(found_ea, 1)
                    if (
                        op_val != idc.BADADDR
                        and op_val != text_seg.start_ea
                        and op_val > text_seg.start_ea
                    ):
                        try:
                            xref_to_blob12 = next(idautils.XrefsTo(op_val, 0))
                            logger.info(
                                f"Found potential blob 12 init (nearby search): 0x{found_ea:X} -> 0x{op_val:X}"
                            )
                            yield xref_to_blob12
                            found_blob12 = True
                            break
                        except StopIteration:
                            logger.warning(
                                f"Instruction at 0x{found_ea:X} points to 0x{op_val:X}, but no xrefs found *to* it."
                            )
                if found_blob12:
                    break
        if not found_blob12:
            logger.warning(
                "Could not find a likely candidate for blob 12 initialization near blob 0."
            )

    @classmethod
    def get_tls_region(cls):
        blob_addresses = set()
        for xref in cls.get_garbage_blobs():
            if ida_bytes.is_loaded(xref.to):
                blob_addresses.add(xref.to)
            else:
                logger.warning(f"Xref target 0x{xref.to:X} is not loaded, skipping.")
        blobs = sorted(list(blob_addresses))
        logger.info(
            f"Identified potential blob start addresses: {[hex(b) for b in blobs]}"
        )
        return blobs


def execute():
    """
    Main execution function using shared state dictionary and finding lowest index.
    """

    # --- Find potential blob locations ---
    garbage_blobs = GarbageBlobFinder.get_tls_region()
    if not garbage_blobs:
        logger.error("Could not identify any garbage blob start addresses. Aborting.")
        return

    # --- Target the first identified blob ---
    start_ea = garbage_blobs[0]
    logger.info("Using garbage_blob0: 0x%X as base.", start_ea)
    if len(garbage_blobs) > 1:
        end_ea = garbage_blobs[1]
        logger.info("Identified garbage_blob12: 0x%X", end_ea)

    print("\nScript execution completed!")

    # Use the configuration variables defined at the top:
    processor = AntiDisasmProcessor(
        start_ea,
        end_ea,
        patch=True,
        use_threads=USE_THREADS,
        num_threads=TOTAL_THREADS,
    )
    try:
        processor.run()
    finally:
        idc.jumpto(start_ea)
    # Optionally, reanalyze after patching.


# --- Main Execution ---
if __name__ == "__main__":
    idaapi.auto_wait()
    clear_output()
    configure_logging(log=logger, level=logging.DEBUG)  # Use DEBUG for more cache info
    execute()
    idaapi.refresh_idaview_anyway()
