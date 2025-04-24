#!/usr/bin/env python3
# anti_deob.py
import argparse
import asyncio
import atexit
import contextlib
import json
import logging
import math
import multiprocessing
import os
import pathlib
import re
import stat
import struct
import sys
import threading
import time
import typing
import warnings
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache, partial, wraps
from multiprocessing import get_context, shared_memory

import capstone
import capstone.x86

# PyQt 5.15/6.2/6.3/6.4:
# https://riverbankcomputing.com/news/SIP_v6.7.12_Released
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message=(
        r"sipPyTypeDict\(\) is deprecated, the extension module should use "
        r"sipPyTypeDictRef\(\) instead"
    ),
)


def humanize_bytes(
    num_bytes: int, precision: int = 2, units: list[str] = ["B", "KB", "MB", "GB"]
) -> str:
    """
    Convert a byte count into a human-friendly string with units.

    Args:
        num_bytes (int): The number of bytes.
        precision (int): Number of decimal places for non-integer values.

    Returns:
        str: Human-readable string, e.g. '10 MB', '1.23 GB', '512 B'.

    Examples:
        >>> humanize_bytes(10 * 1024 * 1024)
        '10 MB'
        >>> humanize_bytes(1536)
        '1.5 KB'
        >>> humanize_bytes(0)
        '0 B'
        >>> humanize_bytes(123456789)
        '117.74 MB'
    """

    if num_bytes < 0:
        raise ValueError("num_bytes must be non-negative")
    if num_bytes == 0:
        return "0 B"
    idx = 0
    value = float(num_bytes)
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    if value.is_integer():
        return f"{int(value)} {units[idx]}"
    else:
        return f"{value:.{precision}f} {units[idx]}"


def is_ida():
    """
    Crude check to see if running inside IDA.

    Returns True if running inside IDA Pro, else False.
    """
    exec_name = pathlib.Path(sys.executable).name.lower()
    return exec_name.startswith(("ida", "idat", "idaw", "idag"))
    # we do not use this check because there's a possibility that
    # we're running inside a headless IDA mode and that uses an
    # `idapro` library which will make this succeed.
    #
    # Even though that is technically "running" in IDA, we can
    # still use the python interpreter that's executing the script.
    # The reason we want to know if we're in the IDA application is
    # because we want to find the python interpreter that IDA is using
    # to execute the script and to not start a new IDA instance.
    #
    # Maybe this function can be called `is_ida_application` or something.
    # try:
    #     import idaapi  # noqa

    #     return True
    # except ImportError:
    #     return False


# on windows, we need to set the encoding to utf-8 because it defaults to cp1252
# which does not support the emoji characters used in the logging
# or really any non-ascii characters
if not is_ida():
    # this works in non IDA and for python 3.7+
    sys.stdout.reconfigure(encoding="utf-8")
else:
    # IDA wraps sys.stdout and does not expose the `reconfigure` method
    # so we need to set the encoding manually
    sys.stdout.encoding = "utf-8"


def configure_logging(
    log,
    level=logging.INFO,
    handler_filters=None,
    fmt_str="[%(name)s:%(levelname)s:%(process)d:%(threadName)s] @ %(asctime)s %(message)s",
):
    log.propagate = False
    log.setLevel(level)
    formatter = logging.Formatter(fmt_str)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(level)

    # Add the custom filter if every_n is specified.
    if handler_filters is not None:
        for _filter in handler_filters:
            handler.addFilter(_filter)

    for handler in log.handlers[:]:
        log.removeHandler(handler)
        handler.close()

    if not log.handlers:
        log.addHandler(handler)


def get_logger(name=None):
    name = name or f"{"ida." if is_ida() else "worker."}{__name__}"
    return logging.getLogger(name)


logger = get_logger()
configure_logging(logger)

# ─── Helpers ───────────────────────────────────────────────────────────────


class reify:
    """Acts similar to a property, except the result will be
    set as an attribute on the instance instead of recomputed
    each access
    inspired by pyramids pyramid.decorators.reify decorator
    """

    def __init__(self, fn):
        self.fn = fn

    def __get__(self, instance, owner):
        if instance is None:
            return self

        fn = self.fn
        val = fn(instance)

        setattr(instance, fn.__name__, val)

        return val


class emit:
    def __init__(self, event):
        self.event = event

    def __call__(self, fn):
        @wraps(fn)
        def wrapper(inst, *args, **kwargs):
            result = fn(inst, *args, **kwargs)
            inst.emit(self.event)
            return result

        return wrapper


class EventEmitter:
    @reify
    def _listeners(self):
        return defaultdict(set)

    def on(self, event, handler=None):
        """
        Register an event handler for the given event.

        If handler is provided, it is registered directly.
        If handler is None, returns a decorator that can be used to register a function.

        The decorator can be wrapped with @wraps, but since it is not wrapping any
        specific function (just passing through), it is not strictly necessary.
        However, for consistency and to preserve metadata, we can use @wraps.

        >>> emitter = EventEmitter()
        >>> called = []
        >>> @emitter.on('foo')
        ... def handler():
        ...     called.append(1)
        >>> emitter.emit('foo')
        >>> called
        [1]
        """
        if handler:
            self._listeners[event].add(handler)
            return handler

        @wraps(self.on)
        def decorator(func):
            self.on(event, func)
            return func

        return decorator

    def once(self, event, handler):
        @wraps(handler)
        def once_handler(*args, **kwargs):
            self.remove(event, once_handler)
            return handler(*args, **kwargs)

        self.on(event, once_handler)

    def remove(self, event, handler):
        self._listeners.remove(handler)

    def emit(self, event, *args, **kwargs):
        for handler in self._listeners[event]:
            handler(*args, **kwargs)


@dataclass
class AsyncEventEmitter:
    def __post_init__(self):
        self._listeners = defaultdict(set)

    def on(self, event, handler=None):
        if handler:
            self._listeners[event].add(handler)
            return handler

        @wraps(self.on)
        def decorator(func):
            self.on(event, func)
            return func

        return decorator

    async def emit(self, event, *args):
        for h in self._listeners.get(event, []):
            res = h(*args)
            if asyncio.iscoroutine(res):
                await res


class MultiprocessingHelper:
    """
    Static helper class for multiprocessing context and Python interpreter discovery.

    Usage:
        interp = MultiprocessingHelper.get_python_interpreter()
        MultiprocessingHelper.set_multiprocessing_context()
    """

    @staticmethod
    @lru_cache(maxsize=1)
    def get_python_interpreter():
        """
        Gets the path to a suitable Python interpreter.
        Ensures we find a standalone Python executable.

        >>> import pathlib, sys, stat
        >>> interp: pathlib.Path = MultiprocessingHelper.get_python_interpreter()
        ...
        >>>
        """
        if (
            hasattr(sys, "_base_executable")
            and sys._base_executable
            and "python" in pathlib.Path(sys._base_executable).name.lower()
        ):
            logger.debug(f"Using _base_executable: {sys._base_executable}")
            return pathlib.Path(sys._base_executable)

        base_paths = [
            sys.prefix,
            sys.exec_prefix,
            sys.executable,
        ]
        exe_suffix = ".exe" if os.name == "nt" else ""
        python_name = f"python{exe_suffix}"

        def base_dirs():
            for dirname in map(pathlib.Path, base_paths):
                yield dirname
                yield dirname.parent
                yield dirname.parent.parent

        for dirname in base_dirs():
            for basename in ["", "bin", "python"]:
                interp_path = dirname / basename / python_name
                if not interp_path.exists():
                    continue

                if not (interp_path.is_file() or interp_path.is_symlink()):
                    continue

                st_mode = interp_path.stat().st_mode
                if not st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    continue

                logger.debug(f"Found Python interpreter at: {interp_path}")
                return interp_path

        logger.warning(
            "Could not determine Python interpreter path, falling back to 'python' in PATH."
        )
        return pathlib.Path("python")

    @staticmethod
    def set_multiprocessing_context():
        """
        Sets up the multiprocessing context to use 'spawn' and sets the Python executable.
        """
        # --- Multiprocessing Context Setup ---
        current_method = multiprocessing.get_start_method(allow_none=True)
        if current_method != "spawn":
            multiprocessing.set_start_method("spawn", force=True)
        multiprocessing.set_executable(
            str(MultiprocessingHelper.get_python_interpreter())
        )
        # multiprocessing.get_context() or multiprocessing.get_context("spawn")


MultiprocessingHelper.set_multiprocessing_context()

# ─── Core data structures ───────────────────────────────────────────────────


class SegmentType(Enum):
    STAGE1_MULTIPLE = auto()
    STAGE1_SINGLE = auto()
    JUNK = auto()
    BIG_INSTRUCTION = auto()


@dataclass
class MatchSegment:
    start: int
    length: int
    description: str
    matched_bytes: bytes
    segment_type: SegmentType
    matched_groups: dict = field(default_factory=dict)


@dataclass
class MatchChain:
    base_address: int
    segments: list = field(default_factory=list)

    def add_segment(self, seg: MatchSegment):
        self.segments.append(seg)

    def overall_start(self) -> int:
        return self.base_address + (self.segments[0].start if self.segments else 0)

    def overall_length(self) -> int:
        if not self.segments:
            return 0
        first = self.segments[0]
        last = self.segments[-1]
        return (last.start + last.length) - first.start

    def junk_segments(self):
        return [s for s in self.segments if s.segment_type == SegmentType.JUNK]

    def junk_length(self):
        js = self.junk_segments()
        if not js:
            return 0
        first = js[0]
        last = js[-1]
        return (last.start + last.length) - first.start

    def __repr__(self):
        return f"<Chain {self.segments[0].description if self.segments else ''} @0x{self.overall_start():X} len={self.overall_length()}>"


# TODO: inherit from list?
class MatchChains:
    def __init__(self):
        self.chains: list[MatchChain] = []

    def add_chain(self, chain: MatchChain):
        self.chains.append(chain)

    def __iter__(self):
        return iter(self.chains)

    def sort(self):
        self.chains.sort(key=lambda x: x.overall_start())

    def __len__(self):
        return len(self.chains)

    def __repr__(self):
        lines = []
        for c in self.chains:
            desc = c.segments[0].description
            off = c.overall_start()
            bhex = c.overall_matched_bytes().hex()[:16]
            tail = "…" if c.overall_length() > 16 else ""
            lines.append(f"{desc.rjust(32)} @0x{off:X} {bhex}{tail}")
        return "\n".join(lines)


# fmt: off
PADDING_PATTERN = rb"(?:\xC0[\xE0-\xFF]\x00|(?:\x86|\x8A)[\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF])"

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
# fmt: on


def _stage1_scan_one(job):
    """
    job = (pattern_bytes, description, segment_type, base_ea, buf)
    returns MatchChains
    """
    pat_bytes, desc, segtype, base_ea, buf = job
    prog = re.compile(pat_bytes, re.DOTALL)
    hits = MatchChains()

    for m in prog.finditer(buf):
        s = m.start()
        e = m.end()
        mb = buf[s:e]
        match_len = e - s

        groups = {
            k: v.hex()
            for k, v in m.groupdict().items()
            if (v is not None and k != "padding")
        }

        # compute jump targets
        if "jump" in groups:
            offset = struct.unpack("<b", mb[-1:])[0]
            tgt = base_ea + s + match_len + offset
            groups["target"] = hex(tgt)
        elif "first_jump" in groups:
            off1 = struct.unpack("<b", mb[1:2])[0]
            groups["first_target"] = hex(base_ea + s + 2 + off1)
            off2 = struct.unpack("<b", mb[-1:])[0]
            groups["second_target"] = hex(base_ea + s + match_len + off2)

        seg = MatchSegment(
            start=s,
            length=match_len,
            description=desc,
            matched_bytes=mb,
            segment_type=segtype,
            matched_groups=groups,
        )
        hits.add_chain(MatchChain(base_address=base_ea, segments=[seg]))

    return hits


def stage1_find_patterns(buf: bytes, base_ea: int):
    """
    Parallel regex-based Stage 1. Returns List[MatchChain].
    """
    jobs = [
        (
            rgx.pattern,
            rgx.description,
            (
                SegmentType.STAGE1_MULTIPLE
                if rgx.category == PatternCategory.MULTI_PART
                else SegmentType.STAGE1_SINGLE
            ),
            base_ea,
            buf,
        )
        for rgx in (MULTI_PART_PATTERNS + SINGLE_PART_PATTERNS)
    ]

    ctx = get_context("spawn")
    with ProcessPoolExecutor(mp_context=ctx) as exe:
        all_groups = exe.map(_stage1_scan_one, jobs)

    # flatten & sort
    out = [chain for group in all_groups for chain in group]
    out.sort(key=lambda c: c.overall_start())
    return out


# ─── Stage 2: peel off junk via Capstone ────────────────────────────────────


def peel_junk(buf: bytes, is_64: bool) -> int:
    md = capstone.Cs(
        capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
    )
    md.detail = True
    total = 0

    for insn in md.disasm(buf, 0):
        if total + insn.size > len(buf):
            break

        # RDTSC / RDTSCP
        if insn.id in (capstone.x86.X86_INS_RDTSC, capstone.x86.X86_INS_RDTSCP):
            total += insn.size

        # 2-byte conditional jump
        elif capstone.CS_GRP_JUMP in insn.groups and insn.size == 2:
            total += insn.size

        # CALL imm32
        elif (
            insn.id == capstone.x86.X86_INS_CALL
            and insn.operands
            and insn.operands[0].type == capstone.CS_OP_IMM
        ):
            total += insn.size

        # ADD/MOV/NEG/AND/OR/XOR imm
        elif insn.id in (
            capstone.x86.X86_INS_ADD,
            capstone.x86.X86_INS_MOV,
            capstone.x86.X86_INS_NEG,
            capstone.x86.X86_INS_AND,
            capstone.x86.X86_INS_OR,
            capstone.x86.X86_INS_XOR,
        ) and any(op.type == capstone.CS_OP_IMM for op in insn.operands):
            total += insn.size

        # PUSH/POP
        elif insn.id in (capstone.x86.X86_INS_PUSH, capstone.x86.X86_INS_POP):
            total += insn.size

        else:
            break

    return total


def find_junk_stage2_chain(chain: MatchChain, buf: bytes, base_ea: int, is_64: bool):
    off = chain.overall_start() - base_ea + chain.overall_length()
    sub = buf[off:]
    jl = peel_junk(sub, is_64)
    if jl > 0:
        chain.add_segment(
            MatchSegment(
                start=off,
                length=jl,
                description="Junk",
                matched_bytes=sub[:jl],
                segment_type=SegmentType.JUNK,
            )
        )
    return chain


def _stage2_worker(
    args: typing.Tuple[typing.List[MatchChain], bytes, int, bool],
) -> typing.List[MatchChain]:
    """
    args = (chains_chunk, buf, base_ea, is_64)
    Return updated chains with junk peeled.
    """
    chains_chunk, buf, base_ea, is_64 = args
    out: typing.List[MatchChain] = []
    for chain in chains_chunk:
        out.append(find_junk_stage2_chain(chain, buf, base_ea, is_64))
    return out


# ─── Stage 3: filter ────────────────────────────────────────────────────────


def stage3_filter(chains, min_length=12, max_length=129):
    return [
        c
        for c in chains
        if min_length <= c.overall_length() <= max_length and c.junk_length() > 0
    ]


# ─── Stage 4: jump-chain + big-instr + overlap ──────────────────────────────


def find_big_instruction(buf6: bytes, is_64: bool):
    md = capstone.Cs(
        capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
    )
    md.detail = True
    for pos in range(len(buf6)):
        insns = list(md.disasm(buf6[pos:], 0, count=1))
        if not insns:
            continue
        insn = insns[0]
        sz = insn.size
        if 2 <= sz <= 6:
            return {
                "type": f"{sz}-byte",
                "bytes": insn.bytes,
                "position": pos,
                "junk_before": buf6[:pos],
                "junk_after": buf6[pos + sz :],
            }
    return None


def follow_jump_chain(
    buf: bytes, base_ea: int, start_ea: int, block_end: int, is_64: bool
):
    md = capstone.Cs(
        capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
    )
    md.detail = True
    visited = set()
    ea = start_ea
    while ea not in visited and base_ea <= ea < block_end:
        visited.add(ea)
        off = ea - base_ea
        insns = list(md.disasm(buf[off:], ea, count=1))
        if not insns:
            break
        insn = insns[0]
        if insn.id == capstone.x86.X86_INS_NOP:
            ea += insn.size
            continue
        if capstone.CS_GRP_JUMP in insn.groups and insn.size in (2, 5, 6):
            tgt = insn.operands[0].imm
            if base_ea <= tgt < block_end + 6:
                ea = tgt
                continue
        break
    return ea


def _stage4_validate_chain(args):
    """
    args = (chain, buf, base, block_end, is_64)
    Returns either the updated chain or None.
    """
    chain, buf, base, block_end, is_64 = args

    # 1) follow jump chain
    exit_ea = follow_jump_chain(buf, base, chain.overall_start(), block_end, is_64)
    off = exit_ea - base - 6
    if off < 0:
        return None

    # 2) detect big instruction + junk after
    bi = find_big_instruction(buf[off : off + 6], is_64)
    if not bi:
        return None

    # 3) append that segment
    chain.add_segment(
        MatchSegment(
            start=off,
            length=6 + len(bi["junk_after"]),
            description=bi["type"],
            matched_bytes=buf[off : off + 6] + bi["junk_after"],
            segment_type=SegmentType.BIG_INSTRUCTION,
        )
    )
    return chain


def resolve_overlaps(chains):
    sorted_c = sorted(chains, key=lambda c: c.overall_start())
    final = []
    covered = []
    for c in sorted_c:
        st = c.overall_start()
        en = st + c.overall_length()
        if any(st >= a and st < b for a, b in covered):
            continue
        final.append(c)
        covered.append((st, en))
    return final


def log_execution_time(func, loglvl=logging.INFO):
    """
    Decorator to log the execution time of async stage methods.

    >>> import asyncio, logging
    >>> logging.basicConfig(level=logging.INFO)
    >>> class Dummy:
    ...     @log_execution_time
    ...     async def foo(self):
    ...         await asyncio.sleep(0.01)
    ...         return 42
    >>> d = Dummy()
    >>> asyncio.run(d.foo())
    42
    """

    @wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.log(loglvl, f"{func.__qualname__} executed in {elapsed:.4f} seconds")
        return result

    return wrapper


# ─── Async deobfuscator ───────────────────────────────────


@dataclass
class AsyncDeobfuscator(AsyncEventEmitter):
    shm_name: str
    data_size: int
    start_ea: int
    is_64bit: bool
    max_workers: int = None

    def __post_init__(self):
        super().__post_init__()
        self.pause_evt = asyncio.Event()
        self.stop_evt = asyncio.Event()
        self.max_workers = self.max_workers or max(1, multiprocessing.cpu_count())
        ctx = get_context("spawn")
        self.executor = ProcessPoolExecutor(
            max_workers=self.max_workers, mp_context=ctx
        )
        logger.info(f"executor pool created with {self.max_workers} workers")

    @contextlib.asynccontextmanager
    async def _get_buffer(self):
        """
        Async context manager to access the shared memory buffer.

        Usage:
            async with self._get_buffer() as buf:
                # use buf
        """
        shm = shared_memory.SharedMemory(name=self.shm_name)
        try:
            yield bytes(shm.buf[: self.data_size])
        finally:
            shm.close()

    @log_execution_time
    async def stage1(self):
        await self.emit("stage1_started")
        async with self._get_buffer() as buf:
            loop = asyncio.get_running_loop()
            chains = await loop.run_in_executor(
                self.executor, stage1_find_patterns, buf, self.start_ea
            )
        await self.emit("stage1_finished", chains)
        return chains

    @log_execution_time
    async def stage2(self, chains: typing.List[MatchChain]) -> typing.List[MatchChain]:
        await self.emit("stage2_started")

        # read the shared buffer once
        async with self._get_buffer() as buf:
            loop = asyncio.get_running_loop()

            # split chains into roughly equal chunks
            chunk_size = math.ceil(len(chains) / self.max_workers)
            jobs = [
                (chains[i : i + chunk_size], buf, self.start_ea, self.is_64bit)
                for i in range(0, len(chains), chunk_size)
            ]

            # schedule one big task per chunk
            tasks = [
                loop.run_in_executor(self.executor, _stage2_worker, job) for job in jobs
            ]

            # wait for them all, then flatten
            results = await asyncio.gather(*tasks)
        updated = [c for group in results for c in group]

        await self.emit("stage2_finished", updated)
        return updated

    @log_execution_time
    async def stage3(self, chains):
        await self.emit("stage3_started")
        filtered = stage3_filter(chains)
        await self.emit("stage3_finished", filtered)
        return filtered

    @log_execution_time
    async def stage4(self, chains):
        await self.emit("stage4_started")

        async with self._get_buffer() as buf:
            base = self.start_ea
            block_end = base + self.data_size
            loop = asyncio.get_running_loop()

            # build one job per chain
            jobs = [(c, buf, base, block_end, self.is_64bit) for c in chains]

            # schedule each on your ProcessPoolExecutor
            tasks = [
                loop.run_in_executor(self.executor, _stage4_validate_chain, job)
                for job in jobs
            ]

            # wait & filter out None
            results = await asyncio.gather(*tasks)
        valid = [c for c in results if c]

        # resolve overlaps & emit
        final = resolve_overlaps(valid)

        await self.emit("stage4_finished", final)
        return final

    @log_execution_time
    async def run(self):
        await self.emit("run_started")
        s1 = await self.stage1()
        s2 = await self.stage2(s1)
        s3 = await self.stage3(s2)
        final = await self.stage4(s3)
        return final

    async def shutdown(self):
        self.stop_evt.set()
        self.executor.shutdown(wait=True)
        await self.emit("stopped")


# ─── WorkerController: wrap AsyncDeobfuscator in its own event loop ───────
class WorkerController:
    def __init__(self, deob: AsyncDeobfuscator):
        self.deob = deob
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._result = None

    def _run_loop(self):
        # set and run the loop
        asyncio.set_event_loop(self.loop)
        self._result = self.loop.run_until_complete(self.deob.run())

    def start(self):
        """Launch the pipeline in its own thread."""
        self._thread.start()

    def pause(self):
        """Pause after finishing the current iteration."""
        logger.info("▶️  Pausing...")
        self.loop.call_soon_threadsafe(self.deob.pause_evt.set)

    def resume(self):
        """Resume if previously paused."""
        logger.info("▶️  Resuming...")
        self.loop.call_soon_threadsafe(self.deob.pause_evt.clear)

    def stop(self):
        """Stop the pipeline as soon as possible."""
        logger.info("🛑  Stopping...")
        self.loop.call_soon_threadsafe(self.deob.stop_evt.set)

    def join(self):
        """Block until the pipeline finishes, return the final chains."""
        self._thread.join()
        return self._result


# ─── Standalone worker entrypoint ───────────────────────────────────────────


def worker_main():
    p = argparse.ArgumentParser()
    p.add_argument("--shm_name", required=True)
    p.add_argument("--data_size", type=int, required=True)
    p.add_argument("--start_ea", type=lambda x: int(x, 0), required=True)
    p.add_argument("--is64", type=int, default=1)
    args = p.parse_args()

    deob = AsyncDeobfuscator(
        shm_name=args.shm_name,
        data_size=args.data_size,
        start_ea=args.start_ea,
        is_64bit=bool(args.is64),
    )

    # optional logging

    @deob.on("run_started")
    def on_run_started():
        logger.info("▶️  Pipeline starting")

    @deob.on("stage1_finished")
    def on_stage1_finished(ch):
        logger.info(f"✅ Stage1: {len(ch)} stubs")

    @deob.on("stage2_finished")
    def on_stage2_finished(ch):
        logger.info(f"✅ Stage2: {len(ch)} junk appended")

    @deob.on("stage3_finished")
    def on_stage3_finished(ch):
        logger.info(f"✅ Stage3: {len(ch)} remaining")

    @deob.on("stage4_finished")
    def on_stage4_finished(ch):
        logger.info(f"✅ Stage4: {len(ch)} final")

    @deob.on("stopped")
    def on_stopped():
        logger.info("🛑 Worker shutting down")

    # ——— start in background thread ———
    ctrl = WorkerController(deob)
    ctrl.start()

    # ——— command loop ———
    # This will block until IDA sends an "exit", "pause", or "resume" line.
    for line in sys.stdin:
        cmd = line.strip().lower()
        if cmd == "pause":
            ctrl.pause()
        elif cmd == "resume":
            ctrl.resume()
        elif cmd in ("stop", "exit", "shutdown"):
            ctrl.stop()
            break
        # you can also respond to "ping" if you want:
        elif cmd == "ping":
            logger.info("pong")

    # wait for the pipeline to complete
    results = ctrl.join()

    out = [
        {
            "offset": c.overall_start() - args.start_ea,
            "length": c.overall_length(),
            "description": c.segments[0].description,
        }
        for c in results
    ]

    logger.info("results_start")
    logger.info(json.dumps(out))
    logger.info("results_end")


# ─── IDA plugin entrypoint is no longer needed for console mode ─────────────
WORKER_SCRIPT_PATH = pathlib.Path(__file__)


if is_ida():
    import json
    import re

    from PyQt5 import QtCore
    from PyQt5.QtCore import QProcess, QProcessEnvironment

    import ida_bytes
    import ida_ida
    import ida_segment
    import idaapi

    is_x64 = ida_ida.inf_is_64bit()

    class PatchManager:
        """Manages deferred patch operations."""

        class Mode(Enum):
            PATCH = auto()  # Use ida_bytes.patch_bytes
            PUT = auto()  # Use ida_bytes.put_bytes

        def __init__(self, patch_mode: Mode = Mode.PATCH, dry_run: bool = False):
            self.dry_run = dry_run
            self.patch_mode = patch_mode
            self.pending_patches: list[DeferredPatchOp] = []
            logger.info(
                f"PatchManager initialized (dry_run={self.dry_run}, mode={self.patch_mode.name})"
            )

        def add_patch(self, address: int, byte_values: bytes):
            """Creates and queues a DeferredPatchOp."""
            op = DeferredPatchOp(address, byte_values, self.patch_mode)
            self.pending_patches.append(op)
            logger.debug(f"Queued patch operation: {op}")

        def apply_all(self, dry_run_override: bool | None = None) -> bool:
            """Applies all queued patch operations."""
            logger.info(f"Applying {len(self)} queued patches...")
            success_count = 0
            fail_count = 0

            if dry_run_override is None:
                # None is a sentinel value here that represents "use the default"
                dry_run_override = self.dry_run

            for op in self.pending_patches:
                if op.apply(dry_run_override):
                    success_count += 1
                else:
                    fail_count += 1

            logger.info(
                f"Patch application complete. Success: {success_count}, Failed: {fail_count}"
            )
            self.pending_patches.clear()  # Clear the list after applying
            return (
                fail_count == 0
            )  # Return True if all patches were applied successfully

        def __len__(self) -> int:
            return len(self.pending_patches)

    @dataclass(repr=False)
    class DeferredPatchOp:
        """Class to store patch operations that will be applied later."""

        address: int
        byte_values: bytes
        mode: PatchManager.Mode
        dry_run: bool = False

        @classmethod
        def patch(cls, address: int, byte_values: bytes, dry_run: bool = False):
            return cls(address, byte_values, PatchManager.Mode.PATCH, dry_run)

        @classmethod
        def put(cls, address: int, byte_values: bytes, dry_run: bool = False):
            return cls(address, byte_values, PatchManager.Mode.PUT, dry_run)

        def apply(self, dry_run_override: bool = False) -> bool:
            """Apply the patch operation using either patch_bytes or put_bytes based on mode."""
            is_dry_run = dry_run_override or self.dry_run
            logger.info(
                "[*] %sPatching decrypted chunk %s at 0x%X (size: %d)",
                "(Dry Run) " if is_dry_run else "",
                (
                    "revertably"
                    if self.mode == PatchManager.Mode.PATCH
                    else "destructively"
                ),
                self.address,
                len(self.byte_values),
            )
            success = True
            if is_dry_run:
                return success

            func = (
                idaapi.put_bytes
                if self.mode == PatchManager.Mode.PUT
                else idaapi.patch_bytes
            )
            try:
                func(self.address, self.byte_values)
            except Exception as e:
                logger.error(f"Failed to apply patch {self}: {e}")
                success = False
            return success

        def __str__(self):
            """String representation with hex formatting."""
            dry_run_str = " (dry run)" if self.dry_run else ""
            return f"{self.__class__.__name__}({len(self.byte_values)} bytes, mode={self.mode.name}{dry_run_str} @ address=0x{self.address:X})"

        __repr__ = __str__

    class WorkerLauncher(QtCore.QProcess):
        """
        Manages the external worker process using QProcess for command/status.
        Relies on shared memory for large data transfer.
        """

        ## Signals emitted by the broker

        #: For simple status updates like "ping", "results_ready"
        status_message = QtCore.pyqtSignal(str)

        #: For structured results (assuming list)
        processing_results = QtCore.pyqtSignal(list)

        #: For errors reported by the worker
        error_occurred_msg = QtCore.pyqtSignal(str)

        def __init__(self, parent=None):
            super(WorkerLauncher, self).__init__(parent)
            self.readyReadStandardOutput.connect(self._on_stdout)
            self.readyReadStandardError.connect(self._on_stderr)
            self.errorOccurred.connect(self._on_error)
            self.stateChanged.connect(self._on_state_changed)
            self.python_interpreter = MultiprocessingHelper.get_python_interpreter()

        def is_not_running(self):
            return self.state() == QtCore.QProcess.NotRunning

        def launch_worker(self, start_ea: int, shm_name: str, data_size: int):
            """
            Starts the worker script, passing shared memory details as arguments.

            :param worker_script_path: Path to the worker script.
            :param shm_name: Name of the shared memory segment.
            :param data_size: Size of the data in the shared memory segment.
            :raises FileNotFoundError: If the worker script does not exist.
            :raises RuntimeError: If the Python interpreter is not found or executable, or process fails to start.
            """
            env = QProcessEnvironment.systemEnvironment()
            env.insert("PYTHON_PATH", str(self.python_interpreter.parent))
            env.insert("PYTHON_BIN", str(self.python_interpreter.name))
            self.setProcessEnvironment(env)
            script = str(WORKER_SCRIPT_PATH)
            args = [
                "-u",
                script,
                "--shm_name",
                shm_name,
                "--data_size",
                str(data_size),
                "--start_ea",
                hex(start_ea),
                "--is64",
                "1" if is_x64 else "0",
            ]

            logger.info(f"Starting worker process: {self.python_interpreter} {args}")
            self.start(str(self.python_interpreter), args)

            return self.waitForStarted(5000)

        def stop_worker(self):
            """Attempts to terminate the worker process gracefully, then kills."""
            if self.is_not_running():
                logger.debug("Worker process was already stopped.")
                return

            logger.info("Attempting to terminate worker process...")
            # Send 'exit' command first to allow graceful cleanup in worker
            self.send_command("exit")
            # Give worker a moment to process 'exit' command
            if self.waitForFinished(1000):
                logger.info("Worker process exited gracefully after 'exit' command.")
                return  # Worker exited

            logger.warning(
                "Worker did not exit after 'exit' command, attempting terminate."
            )
            self.terminate()  # Send SIGTERM or similar
            if not self.waitForFinished(2000):  # Wait up to 2 seconds
                logger.warning("Worker did not terminate gracefully, killing process.")
                self.kill()  # Send SIGKILL or similar
                if not self.waitForFinished(1000):
                    logger.error("Worker process did not respond to kill.")
            logger.info("Worker process stopped.")

        def send_command(self, command: str):
            """
            Sends a command string to the worker process's stdin.
            Appends a newline to delimit commands.

            :param command: The command string to send (e.g., "process", "ping", "exit").
            """
            if self.state() == QtCore.QProcess.Running:
                data = (command + "\n").encode("utf-8")
                self.write(data)
                logger.debug(f"→ Sent command: {command}")
            else:
                logger.warning(
                    f"Attempted to send command '{command}' but worker is not running (State: {self.state()})."
                )

        def _on_stdout(self):
            """Reads data from worker's stdout, processes line by line or collects results."""
            # Convert QByteArray to Python bytes
            out = self.readAllStandardOutput().data().decode("utf-8")
            # we use print() here b/c we want the log without the logger prefix
            # from the parent process
            print(out.strip(), flush=True)
            m = re.search(r"results_start\n(.+?)\nresults_end", out, re.DOTALL)
            if not m:
                self.processing_results.emit([])
                return
            results = json.loads(m.group(1))
            results.append("results-ready")
            self.processing_results.emit(results)

        def _on_stderr(self):
            """Reads and logs data from the worker's standard error."""
            # Convert QByteArray to Python bytes before decoding
            data = self.readAllStandardError().data()
            if data:
                data = data.decode("utf-8", errors="replace").strip()
                # we use print() here b/c we want the log without the logger prefix
                # from the parent process
                print(data.strip(), file=sys.stderr, flush=True)

        def _on_error(self, error: QtCore.QProcess.ProcessError):
            """Logs process errors and emits a signal."""
            error_map = {
                QtCore.QProcess.FailedToStart: "FailedToStart",
                QtCore.QProcess.Crashed: "Crashed",
                QtCore.QProcess.Timedout: "Timedout",
                QtCore.QProcess.ReadError: "ReadError",
                QtCore.QProcess.WriteError: "WriteError",
                QtCore.QProcess.UnknownError: "UnknownError",
            }
            error_str = error_map.get(error, f"UnknownError({error})")
            msg = f"Worker process error: {error_str} - {self.errorString()}"
            # we use print() here b/c we want the log without the logger prefix
            # from the parent process
            print(msg.strip(), file=sys.stderr, flush=True)
            self.error_occurred_msg.emit(msg)

        def _on_state_changed(self, state: QtCore.QProcess.ProcessState):
            """Logs process state changes."""
            state_map = {
                QtCore.QProcess.NotRunning: "NotRunning",
                QtCore.QProcess.Starting: "Starting",
                QtCore.QProcess.Running: "Running",
            }
            state_str = state_map.get(state, f"UnknownState({state})")
            logger.info(f"Worker process state changed: {state_str}")

            if state == QtCore.QProcess.NotRunning:
                exit_code = self.exitCode()
                exit_status = self.exitStatus()
                exit_status_str = (
                    "NormalExit"
                    if exit_status == QtCore.QProcess.NormalExit
                    else "CrashExit"
                )
                msg = f"Worker process exited with code {exit_code} ({exit_status_str})"
                logger.info(msg)
                # emit an error if the exit was not normal and not intentional (e.g., via 'exit' command)
                if exit_status == QtCore.QProcess.CrashExit:
                    self.error_occurred_msg.emit(msg)

    class DataProcessorCore:

        # Store shared memory object as a class attribute
        _shared_memory = None

        def __init__(self):
            self.patch_manager = PatchManager(dry_run=True)
            self.proc = None
            atexit.register(self.terminate)

        def _handle_worker_status(self, status: str):
            logger.info(f"Worker status: {status}")

        def _handle_worker_results(self, results: list):
            logger.info(f"Worker results: {results}")

        def _handle_worker_error(self, error: str):
            """Handles error messages originating from the worker process."""
            logger.error(f"Worker reported an error: {error}")

            # Consider stopping the worker and cleaning up shared memory on error
            self.proc.stop_worker()
            self._cleanup_shared_memory()

        def terminate(self):
            """Terminate the plugin, stopping the broker and cleaning up shared memory."""
            logger.info("Terminating...")
            # Stop the broker process (sends 'exit' command)
            if self.proc and not self.proc.is_not_running():
                self.proc.stop_worker()
                self.proc = None  # Clear reference
            self._cleanup_shared_memory()
            logger.info("Terminated.")

        def pause(self):
            self.send_command("pause")

        def resume(self):
            self.send_command("resume")

        def stop(self):
            self.send_command("stop")

        @staticmethod
        def get_section_data(
            section_name: str,
            max_size: int = 120 * 1024 * 1024,
            min_size: int = 1024,
        ) -> tuple[int, bytes]:
            """Get the data of a section by name and return the start address and the bytes."""
            seg = ida_segment.get_segm_by_name(section_name)
            data_ea = seg.start_ea
            data_to_process_size = seg.end_ea - seg.start_ea
            # Cap size if needed, or handle very large sections
            if data_to_process_size > max_size:  # Limit to max_size (default is 120MB)
                data_to_process_size = max_size
                logger.warning(
                    f"Limiting section data size to {humanize_bytes(data_to_process_size)} from {section_name}."
                )
            elif data_to_process_size < min_size:  # Don't bother with tiny sections
                # TODO: do we even still need this?
                logger.error(
                    f"{section_name} section is too small ({humanize_bytes(data_to_process_size)}) for processing."
                )

                return

            logger.info(
                f"Reading {humanize_bytes(data_to_process_size)} from address {hex(data_ea)}"
            )
            # Read the bytes from IDA
            data_bytes = ida_bytes.get_bytes(data_ea, data_to_process_size)

            if not data_bytes or len(data_bytes) != data_to_process_size:
                logger.error(
                    f"Failed to read {humanize_bytes(data_to_process_size)} from {hex(data_ea)}. Read {len(data_bytes) if data_bytes else 0} bytes."
                )
                return

            return data_ea, data_bytes

        def run(self, start_ea: int, bytes_to_process: bytes, **kwargs):
            """Run the main plugin logic when hotkey is pressed."""
            plugin_arg: typing.Any = kwargs.pop("plugin_arg", None)
            if plugin_arg is not None:
                logger.info(f"Received plugin arg: {plugin_arg}")

            data_size = len(bytes_to_process)
            # 2) create shared memory & copy
            self._shared_memory = shared_memory.SharedMemory(
                create=True, size=data_size
            )
            self._shared_memory.buf[:data_size] = bytes_to_process

            # 3) launch worker
            self.proc = WorkerLauncher()
            self.proc.status_message.connect(self._handle_worker_status)
            self.proc.processing_results.connect(self._handle_worker_results)
            self.proc.error_occurred_msg.connect(self._handle_worker_error)
            if not self.proc.launch_worker(
                start_ea, self._shared_memory.name, data_size
            ):
                self.terminate()
                logger.error(f"Failed to start worker process: {self.errorString()}")
                return

        def _cleanup_shared_memory(self):
            """Helper function to close and unlink shared memory."""
            if not self._shared_memory:
                return

            try:
                logger.info(
                    f"Unlinking shared memory segment: {self._shared_memory.name}"
                )
                self._shared_memory.close()  # Close parent's view
                shared_memory.SharedMemory(
                    self._shared_memory.name
                ).unlink()  # Unlink the segment
                logger.info("Shared memory unlinked.")
            except FileNotFoundError:
                logger.warning(
                    f"Shared memory segment {self._shared_memory.name} already unlinked."
                )
            except Exception as e:
                logger.error(f"Error unlinking shared memory: {e}", exc_info=True)
            finally:
                self._shared_memory = None  # Clear reference

    class Taskr:
        """
        Singleton wrapper for the DataProcessor instance.

        Ensures only one DataProcessor is created and shared throughout the plugin's lifetime.

        Usage:
            >>> t1 = Taskr()
            >>> t2 = Taskr()
            >>> t1 is t2
            True
            >>> t1.get() is t2.get()
            True

        The .get() method returns the singleton DataProcessor instance.
        """

        _instance = None
        _processor = None

        def __new__(cls, *args, **kwargs):
            if cls._instance is None:
                # Not thread-safe, but sufficient for plugin/IDA context
                cls._instance = super().__new__(cls)
                logger.info("Initializing DataProcessor")
                cls._processor = DataProcessorCore()
            return cls._instance

        def get(self):
            """
            Returns the singleton DataProcessor instance.

            >>> t1 = Taskr()
            >>> t2 = Taskr()
            >>> t1.get() is t2.get()
            True
            """
            return self._processor

        def pause(self):
            self.get().pause()

        def resume(self):
            self.get().resume()

        def stop(self):
            self.get().stop()

    class DataProcessorPlugin(idaapi.plugin_t):
        """
        IDA Pro multiprocessing plugin with a worker
        using shared memory for large data and QProcess pipes for signaling.
        """

        flags = idaapi.PLUGIN_PROC
        comment = "Deobfuscation via Shared Memory, Multiprocessing and QProcess"
        help = "Press Alt-Shift-P to start data deobfuscation"
        wanted_name = "FastDeobfuscator"
        wanted_hotkey = "Alt-Shift-P"
        _core = None

        # --- Plugin Lifecycle ---
        def init(self):
            self._core = DataProcessorCore()
            return idaapi.PLUGIN_KEEP

        def term(self):
            """Terminate the plugin, stopping the broker and cleaning up shared memory."""
            logger.info("Terminating plugin.")
            self._core.terminate()
            logger.info("Plugin terminated.")

        def run(self, arg):
            data_ea, data_bytes = DataProcessorCore.get_section_data(".text")
            self._core.run(data_ea, data_bytes, plugin_arg=arg)

    def PLUGIN_ENTRY():
        return DataProcessorPlugin()


if __name__ == "__main__":
    if not is_ida():
        worker_main()
    else:
        print("Running Taskr().get().run(*Taskr().get().get_section_data('.text'))")
        Taskr().get().run(*Taskr().get().get_section_data(".text"))
