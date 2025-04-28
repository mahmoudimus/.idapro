#!/usr/bin/env python3
# anti_deob.py
import argparse
import asyncio
import atexit
import collections
import concurrent.futures
import contextlib
import dataclasses
import enum
import functools
import itertools
import logging
import math
import multiprocessing
import multiprocessing.connection
import multiprocessing.shared_memory
import os
import pathlib
import pickle
import re
import select
import stat
import struct
import sys
import threading
import time
import typing
import uuid
import warnings

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


def get_logger(name=None, configurer=None):
    if not configurer:
        configurer = configure_logging
    name = name or f"{"ida." if is_ida() else "worker."}{__name__}"
    logger = logging.getLogger(name)
    configurer(logger)
    return logger


logger = get_logger()

# maximum length of any stage-1 pattern (you said 129 bytes)
MAX_PATTERN_LEN = 129
MIN_PATTERN_LEN = 12

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
        @functools.wraps(fn)
        def wrapper(inst, *args, **kwargs):
            result = fn(inst, *args, **kwargs)
            inst.emit(self.event)
            return result

        return wrapper


class EventEmitter:
    @reify
    def _listeners(self):
        return collections.defaultdict(set)

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

        @functools.wraps(self.on)
        def decorator(func):
            self.on(event, func)
            return func

        return decorator

    def once(self, event, handler):
        @functools.wraps(handler)
        def once_handler(*args, **kwargs):
            self.remove(event, once_handler)
            return handler(*args, **kwargs)

        self.on(event, once_handler)

    def remove(self, event, handler):
        self._listeners.remove(handler)

    def emit(self, event, *args, **kwargs):
        for handler in self._listeners[event]:
            handler(*args, **kwargs)


@dataclasses.dataclass
class AsyncEventEmitter:
    def __post_init__(self):
        self._listeners = collections.defaultdict(set)

    def on(self, event, handler=None):
        if handler:
            self._listeners[event].add(handler)
            return handler

        @functools.wraps(self.on)
        def decorator(func):
            self.on(event, func)
            return func

        return decorator

    async def emit(self, event, *args):
        for h in self._listeners.get(event, []):
            res = h(*args)
            if asyncio.iscoroutine(res):
                await res


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

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.log(loglvl, f"{func.__qualname__} executed in {elapsed:.4f} seconds")
        return result

    return wrapper


class MultiprocessingHelper:
    """
    Static helper class for multiprocessing context and Python interpreter discovery.

    Usage:
        interp = MultiprocessingHelper.get_python_interpreter()
        MultiprocessingHelper.set_multiprocessing_context()
    """

    @staticmethod
    @functools.lru_cache(maxsize=1)
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
        # multiprocessing.multiprocessing.get_context() or multiprocessing.multiprocessing.get_context("spawn")


MultiprocessingHelper.set_multiprocessing_context()

# ─── Core data structures ───────────────────────────────────────────────────


class SegmentType(enum.Enum):
    STAGE1_MULTIPLE = enum.auto()
    STAGE1_SINGLE = enum.auto()
    JUNK = enum.auto()
    BIG_INSTRUCTION = enum.auto()


@dataclasses.dataclass
class MatchSegment:
    start: int
    length: int
    description: str
    matched_bytes: bytes
    segment_type: SegmentType
    matched_groups: dict = dataclasses.field(default_factory=dict)


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


# TODO: inherit from list?
class MatchChains:
    def __init__(self):
        self.chains: list[MatchChain] = []

    def add_chain(self, chain: MatchChain):
        self.chains.append(chain)

    def __iter__(self):
        yield from self.chains

    def sort(self):
        self.chains.sort(key=lambda x: x.overall_start())

    def __len__(self):
        return len(self.chains)

    def __repr__(self):
        lines = []
        for c in self.chains:
            desc = c.description
            off = c.overall_start()
            bhex = c.overall_matched_bytes().hex()[:16]
            tail = "…" if c.overall_length() > 16 else ""
            lines.append(f"{desc.rjust(32)} @ 0x{off:X} - {bhex}{tail}")
        return "\n".join(lines)


class PatternCategory(enum.Enum):
    MULTI_PART = enum.auto()
    SINGLE_PART = enum.auto()
    JUNK = enum.auto()


@dataclasses.dataclass
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


@dataclasses.dataclass
class MultiPartPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = dataclasses.field(
        default=PatternCategory.MULTI_PART, init=False
    )

    def __post_init__(self):
        # Compile to ensure group names are available.
        _ = self.compile(re.DOTALL)
        required_groups = {"first_jump", "padding", "second_jump"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError(f"MultiPart pattern is missing required groups: {missing}")


@dataclasses.dataclass
class SinglePartPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = dataclasses.field(
        default=PatternCategory.SINGLE_PART, init=False
    )

    def __post_init__(self):
        _ = self.compile(re.DOTALL)
        required_groups = {"prefix", "padding", "jump"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError(
                f"SinglePart pattern is missing required groups: {missing}"
            )


@dataclasses.dataclass
class JunkPatternMetadata(RegexPatternMetadata):
    category: PatternCategory = dataclasses.field(
        default=PatternCategory.JUNK, init=False
    )

    def __post_init__(self):
        _ = self.compile(re.DOTALL)
        required_groups = {"junk"}
        missing = required_groups - set(self.group_names)
        if missing:
            raise ValueError("Junk pattern must have a 'junk' group.")


# fmt: off
PADDING_PATTERN = rb"(?:\xC0[\xE0-\xFF]\x00|(?:\x86|\x8A)[\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF])"

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

# Helper sets for checking specific registers based on the regex patterns
# These patterns [\xC0-\xC3\xC5-\xC7] and [\xD8-\xDB\xDD-\xDF] and [\xE8-\xEB\xED-\xEF]
# correspond to ModR/M byte where MOD=11 (register) and R/M is 0-3 (EAX, ECX, EDX, EBX)
# or 5-7 (EBP, ESI, EDI). R/M=4 is ESP, which is skipped by these ranges.
# For 8-bit, these are AL, CL, DL, BL, BPL, SIL, DIL.
# Since REX prefixes are confirmed *not* to be used with these patterns,
# we only need to check for the 8-bit and 32-bit registers.
REG_32_SET = {
    capstone.x86.X86_REG_EAX,
    capstone.x86.X86_REG_ECX,
    capstone.x86.X86_REG_EDX,
    capstone.x86.X86_REG_EBX,
    capstone.x86.X86_REG_EBP,
    capstone.x86.X86_REG_ESI,
    capstone.x86.X86_REG_EDI,
}

REG_8_SET = {
    capstone.x86.X86_REG_AL,
    capstone.x86.X86_REG_CL,
    capstone.x86.X86_REG_DL,
    capstone.x86.X86_REG_BL,
    # AH (C4) is skipped by the regex range
    capstone.x86.X86_REG_CH,  # C5
    capstone.x86.X86_REG_DH,  # C6
    capstone.x86.X86_REG_BH,  # C7
    # Low bytes of SI, DI, BP, SP are only accessible with REX in 64-bit
    # but the regex implies non-REX. The original set included BPL, SIL, DIL
    # which correspond to ModR/M 101, 110, 111 when MOD != 11.
    # The regex range C0-C3, C5-C7 *specifically* uses MOD=11.
    # So, the correct registers are AL, CL, DL, BL, CH, DH, BH.
    # Let's redefine REG_8_SET based *only* on the registers implied by
    # the specific ModR/M bytes in the regexes when MOD=11.
}

# Helper to check if the first operand is a register from the allowed set
# based on the ModR/M ranges implied by the regexes.
# Assumes no REX prefixes are used with these specific junk patterns,
# so we only check against the 8-bit and 32-bit sets.
def is_allowed_reg(operands):
    if not operands or operands[0].type != capstone.CS_OP_REG:
        return False
    reg = operands[0].reg
    # Check if the register is one of the 8-bit or 32-bit registers
    # corresponding to the ModR/M R/M field 0-3, 5-7 when MOD=11,
    # which is the set derived from ModR/M=11 ranges
    return reg in REG_8_SET or reg in REG_32_SET

# Helper to check if there's an immediate operand
def has_imm_operand(operands):
    return any(op.type == capstone.CS_OP_IMM for op in operands)

# Function to check if a byte is a valid REX prefix (0x40-0x4F)
def is_rex_prefix(byte):
    return 0x40 <= byte <= 0x4F

# Function to check if a byte is a valid ModR/M byte (0x80-0xBF)
def is_valid_modrm(byte):
    return 0x80 <= byte <= 0xBF
# fmt: on


def _stage1_scan_one(job: tuple[RegexPatternMetadata, int, memoryview]) -> MatchChains:
    """
    job = (pattern_bytes, description, segment_type, base_ea, buf)
    returns MatchChains
    """
    rgx, base_ea, buf = job
    prog = rgx.compile()
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
            description=rgx.description,
            matched_bytes=mb.tobytes(),
            segment_type=(
                SegmentType.STAGE1_MULTIPLE
                if rgx.category == PatternCategory.MULTI_PART
                else SegmentType.STAGE1_SINGLE
            ),
            matched_groups=groups,
        )
        hits.add_chain(MatchChain(base_address=base_ea, segments=[seg]))

    return hits


def stage1_find_patterns(
    buf: memoryview, base_ea: int, mp: bool = False
) -> list[MatchChain]:
    """
    Parallel regex-based Stage 1. Returns List[MatchChain].
    """
    jobs = [
        (rgx, base_ea, buf)
        for rgx in itertools.chain(MULTI_PART_PATTERNS, SINGLE_PART_PATTERNS)
    ]

    if mp:
        ctx = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(mp_context=ctx) as exe:
            all_groups = exe.map(_stage1_scan_one, jobs)
    else:
        all_groups = list(map(_stage1_scan_one, jobs))

    # flatten
    out = [chain for group in all_groups for chain in group]
    # sort
    out.sort(key=lambda c: c.overall_start())
    return out


# ─── Stage 2: peel off junk via Capstone ────────────────────────────────────


@dataclasses.dataclass
class JunkInstruction:
    """Holds information about a single peeled junk instruction."""

    #: Offset relative to the start of the peeled buffer
    start_offset: int
    #: Length of the peeled junk instruction
    length: int
    #: Description of the peeled junk instruction
    description: str
    #: Bytes of the peeled junk instruction
    matched_bytes: bytes


class CapstoneDisasmContext:
    """
    Context manager and iterable for Capstone disassembly.

    Usage:
        with CapstoneDisasmContext(is_64, buf) as disasm_ctx:
            for insn in disasm_ctx:
                ...

    On error, iteration yields nothing.
    """

    _EMPTY_SET = set()

    def __init__(self, is_64: bool):
        self.is_64 = is_64

    @functools.cached_property
    def md(self):
        """
        Cached property for the Capstone disassembler instance.
        Returns None if initialization fails.
        """
        try:
            md = capstone.Cs(
                capstone.CS_ARCH_X86,
                capstone.CS_MODE_64 if self.is_64 else capstone.CS_MODE_32,
            )
            md.detail = True
            return md
        except Exception as e:
            logger.error(f"Failed to initialize Capstone: {e}")
            return None

    def __enter__(self):
        # No setup needed; iteration is handled in __iter__
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # The __exit__ method is not a generator and should not yield.
        # Instead, handle exceptions by logging them if present.
        PROPOGATE = False
        SUPPRESS = True

        match exc_type:
            case None:
                return PROPOGATE
            case capstone.CsError:
                logger.error(f"Capstone disassembly error: {exc_val}", exc_info=True)
                return SUPPRESS
            case _:
                logger.error(
                    f"Unexpected {exc_type.__name__} during Capstone disassembly: {exc_val}",
                    exc_info=True,
                )
                return SUPPRESS

    def disasm(self, buf: bytes, start_ea: int, **kwargs):
        """
        Disassemble the buffer and return an iterator of instructions.
        If initialization failed, returns an empty iterator.
        start_ea = 0 means is relative to the start of the input buffer 'buf'
        """
        if not self.md:
            yield from self._EMPTY_SET
            return

        for insn in self.md.disasm(buf, start_ea, **kwargs):
            yield insn


def peel_junk(buf: bytes, is_64: bool) -> typing.List[JunkInstruction]:
    """
    Disassembles the buffer using Capstone and returns a list of
    contiguous instructions that match the criteria derived from the
    original regex JUNK_PATTERNS, using a match statement.

    Stops at the first instruction that does not match any of the junk criteria.

    Args:
        buf: The byte buffer to disassemble and peel junk from.
        is_64: True if disassembling in 64-bit mode, False for 32-bit.
    Returns:
        A list of JunkInstruction objects for each matched junk instruction.
        Returns an empty list if no junk is found or on error.
    """
    peeled_instructions: typing.List[JunkInstruction] = []
    if not buf:
        return peeled_instructions

    current_offset = 0
    stop_disasm = False
    with CapstoneDisasmContext(is_64) as disasm_ctx:
        for insn in disasm_ctx.disasm(buf, 0):
            if stop_disasm:
                break
            logger.debug(
                f"Disassembled instruction: {insn.mnemonic} {insn.op_str} ({insn.size} bytes) at offset {current_offset} - bytes: {insn.bytes.hex()}"
            )
            # Safety check: Ensure the instruction doesn't go past the buffer end
            if current_offset + insn.size > len(buf):
                logger.warning(
                    f"Instruction {insn.mnemonic} at offset {current_offset} exceeds buffer bounds ({insn.size} bytes, buffer has {len(buf) - current_offset} remaining). Stopping."
                )
                break

            junk_description = "Unknown Junk"  # Default description

            # Check if the instruction's bytes match any junk regex pattern *exactly*
            for rgx in JUNK_PATTERNS:
                # Use match() to check from the beginning of the instruction bytes
                match = rgx.compile().match(insn.bytes)

                # Check if a match occurred AND it consumed the *entire* instruction
                if match:
                    if match.end() != insn.size:
                        logger.warning(
                            f"junk detected @ {insn.address} - {rgx.description} - matched {insn.bytes.hex()} and consumed {match.end()} bytes but expected {insn.size} bytes"
                        )
                    junk_description = rgx.description or "Junk"

                    # logger.debug(f"  Instruction bytes {instruction_bytes.hex()} matched regex: {junk_meta.pattern.decode('latin-1')}")
                    peeled_instructions.append(
                        JunkInstruction(
                            start_offset=current_offset,
                            length=insn.size,
                            description=junk_description,
                            matched_bytes=insn.bytes,
                        )
                    )
                    # found a junk instruction, break out of the loop
                    break
            else:
                # Stop at the first non-junk instruction
                # logger.debug(f"  Non-junk instruction: {insn.mnemonic} {insn.op_str} ({insn.size} bytes) at offset {current_offset}. Stopping.")
                stop_disasm = True
            current_offset += insn.size
            # logger.debug(f"  Found junk: {junk_description} - {insn.mnemonic} {insn.op_str} ({insn.size} bytes) at offset {current_offset - insn.size}")
    return peeled_instructions


def find_junk_stage2_chain(
    chain: MatchChain, buf: bytes, base_ea: int, is_64: bool
) -> MatchChain:
    """
    Finds a contiguous block of junk instructions immediately following the
    Stage 1 match in a single MatchChain using Capstone (peel_junk)
    and adds each individual junk instruction as a segment.

    Args:
        chain: The MatchChain object representing the stage 1 match.
        buf: The full byte buffer containing the function/memory region.
        base_ea: The base effective address of the buffer.
        is_64: True if disassembling in 64-bit mode, False for 32-bit.

    Returns:
        The updated MatchChain object with individual junk segments added.
    """
    # Calculate the offset in the buffer immediately after the Stage 1 match
    # chain.overall_start() is the absolute EA of the start of the chain (Stage 1)
    # base_ea is the base effective address of the buffer
    # The offset in the buffer is (chain_start_ea - buffer_base_ea) + chain_length
    stage1_end_ea = chain.overall_start() + chain.overall_length()
    buffer_offset_after_stage1 = stage1_end_ea - base_ea

    # Ensure the offset is within the buffer bounds
    if buffer_offset_after_stage1 >= len(buf):
        logger.debug(
            f"No bytes available after stage 1 match at EA 0x{stage1_end_ea:X} to search for junk."
        )
        return chain  # No buffer left to search

    # Get the sub-buffer starting after the Stage 1 match
    sub_buffer = buf[buffer_offset_after_stage1:]

    # Use peel_junk to find the individual contiguous junk segments
    # The 'start' in these segments is relative to the start of 'sub_buffer'
    js: list[JunkInstruction] = peel_junk(sub_buffer, is_64)

    if js:
        logger.debug(
            f"Found {len(js)} individual junk instructions after stage 1 match at EA 0x{stage1_end_ea:X}"
        )

        # Add each individual junk segment to the chain
        for relative_seg in js:
            # Calculate the absolute start EA of this junk segment
            absolute_start_ea = stage1_end_ea + relative_seg.start_offset

            # Calculate the start offset relative to the chain's base_address
            # This is what MatchSegment.start should store
            offset_relative_to_chain_base = absolute_start_ea - chain.base_address

            # Create a new MatchSegment for the chain
            chain_segment = MatchSegment(
                start=offset_relative_to_chain_base,
                length=relative_seg.length,
                description=relative_seg.description,
                matched_bytes=relative_seg.matched_bytes,
                segment_type=SegmentType.JUNK,
                # matched_groups=relative_seg.matched_groups # Copy if peel_junk provided them
            )
            chain.add_segment(chain_segment)

        # The junk_length and junk_segments properties on the chain will now be correct
        logger.debug(f"Total peeled junk length added: {chain.junk_length} bytes.")

    else:
        logger.debug(f"No junk found after stage 1 match at EA 0x{stage1_end_ea:X}")

    return chain


@dataclasses.dataclass
class BasicDecodedInstruction:
    """Holds standardized information about a decoded instruction."""

    address: int
    size: int
    is_jump: bool = False
    jump_target: typing.Optional[int] = None
    is_nop: bool = False


class InstructionDecoder(typing.Protocol):
    """Protocol defining the expected signature for decoder functions."""

    def __init__(self, is_x64: bool): ...

    def decode(
        self, ea: int, mem_bytes_at_ea: bytes
    ) -> typing.Optional[BasicDecodedInstruction]:
        """
        Decodes the instruction at virtual address 'ea' using the provided memory bytes.

        Args:
            ea: The virtual address of the instruction to decode.
            mem_bytes_at_ea: A bytes object containing memory starting from 'ea'.
                             The implementation should only consume the bytes
                             needed for the single instruction at 'ea'.

        Returns:
            An InstructionInfo object if decoding is successful, otherwise None.
        """
        ...


class CapstoneInstructionDecoder(InstructionDecoder):

    def __init__(self, is_x64: bool):
        self.is_x64 = is_x64
        self.md = capstone.Cs(
            capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_x64 else capstone.CS_MODE_32
        )
        self.md.detail = True

    def decode(
        self, ea: int, mem_bytes_at_ea: bytes
    ) -> typing.Optional[BasicDecodedInstruction]:
        """
        Decodes instruction at ea using IDA's disassembler.
        Ignores mem_bytes_at_ea, uses IDA's database.
        Conforms to DecoderProtocol.
        """
        # Decode using Capstone
        try:
            # Use list comprehension and next to get the first instruction or None
            insn = next(self.md.disasm(mem_bytes_at_ea, ea, count=1), None)
        except capstone.CsError as e:
            logger.error(f"Capstone decoding error at 0x{ea:X}: {e}")
            return None

        if insn is None:
            return None
        logger.debug(
            "Decoded instruction: %s %s (%X bytes) at offset %s - bytes: %s",
            insn.mnemonic,
            insn.op_str,
            insn.size,
            hex(ea),
            insn.bytes.hex(),
        )
        decoded = BasicDecodedInstruction(address=ea, size=insn.size)
        if insn.id == capstone.x86.X86_INS_NOP:
            decoded.is_nop = True
        # Check for 'xchg r8, r8' as a NOP pattern (0x90 is 'nop', i.e. 0x87 C9 is 'xchg cl, cl')
        elif insn.id in (
            capstone.x86.X86_INS_XCHG,
            # capstone.x86.X86_INS_MOV,
            # capstone.x86.X86_GRP_CMOV,
        ):
            op1, op2 = insn.operands
            if op1.type == op2.type and op1.size == op2.size and op1.reg == op2.reg:
                decoded.is_nop = True
        elif capstone.CS_GRP_JUMP in insn.groups:
            if (
                len(insn.operands) > 0
                and insn.operands[0].type == capstone.x86.X86_OP_IMM
            ):
                decoded.is_jump = True
                decoded.jump_target = insn.operands[0].imm
        return decoded


@dataclasses.dataclass
class JumpTargetAnalyzer:
    # Input parameters for processing jumps.
    match_bytes: bytes  # The bytes in which we're matching jump instructions.
    match_start: int  # The address where match_bytes starts.
    block_end: int  # End address of the allowed region.
    start_ea: int  # Base address of the memory block (used for bounds checking).

    # Internal structures.
    jump_targets: collections.Counter = dataclasses.field(
        init=False, default_factory=collections.Counter
    )
    jump_details: list = dataclasses.field(
        init=False, default_factory=list
    )  # List of (jump_ea, final_target, stage1_type)
    target_type: dict = dataclasses.field(
        init=False, default_factory=dict
    )  # final_target -> stage1_type

    def follow_jump_chain(
        self,
        mem: bytes,
        current_ea: int,
        match_end: int,
        decoder: InstructionDecoder,
        visited: set = None,
        depth: int = 0,
    ) -> typing.Optional[int]:
        """
        Follow a chain of 2-byte jumps starting from current_ea using the provided decoder.

        Args:
            mem: Memory object containing the relevant byte data. Its 'base' attribute
                 defines the absolute address corresponding to the start of its buffer.
            current_ea: The absolute starting virtual address for tracing.
            match_end: The absolute end address (exclusive) of the 'stage1' area.
            decoder: A function conforming to DecoderProtocol used for disassembly.
            visited: Set of visited addresses to prevent loops (internal use).
            depth: Recursion depth for logging (internal use).

        Returns:
            The absolute virtual address where the jump chain ends, or None.
        """
        indent = "  " * depth + "|_ "
        if visited is None:
            visited = set()

        # Get an efficient view of the memory buffer
        mem_view = mem
        mem_start_ea = self.start_ea  # Absolute start address of the buffer
        mem_len = len(mem_view)
        mem_end_ea = mem_start_ea + mem_len  # Absolute end address (exclusive)

        if current_ea in visited:
            logger.debug(
                "%sJump chain stopped: Already visited 0x%X", indent, current_ea
            )
            return None
        # Check if start address is within the bounds defined by the Memory object
        if not (mem_start_ea <= current_ea < mem_end_ea):
            logger.debug(
                "%sJump chain stopped: Start address 0x%X is outside Memory bounds [0x%X, 0x%X)",
                indent,
                current_ea,
                mem_start_ea,
                mem_end_ea,
            )
            return None

        visited.add(current_ea)

        trace_ea = current_ea
        while True:
            # Check if the current tracing address is still within the Memory bounds
            if not (mem_start_ea <= trace_ea < mem_end_ea):
                logger.debug(
                    "%sStopping trace: Address 0x%X is outside Memory bounds [0x%X, 0x%X). Returning last valid start: 0x%X",
                    indent,
                    trace_ea,
                    mem_start_ea,
                    mem_end_ea,
                    current_ea,
                )
                return current_ea  # Return the start address of the sequence that led out of bounds

            decoded_insn = None
            # Calculate offset relative to the start of the Memory object's buffer
            offset = trace_ea - mem_start_ea
            logger.debug("%soffset: %X", indent, offset)
            # We already know offset is >= 0 because trace_ea >= mem_start_ea
            # We need to ensure we have enough bytes left for *potential* instructions

            # Get bytes starting from the offset using the memoryview slice
            # Convert the slice to bytes for the decoder interface
            bytes_for_decoder = mem_view[offset:]
            if (
                not bytes_for_decoder
            ):  # Should not happen if bounds check is correct, but defensive check
                logger.warning(
                    "%sNo bytes available for decoding at offset %X (address 0x%X). Stopping trace.",
                    indent,
                    offset,
                    trace_ea,
                )
                return current_ea

            try:
                # Call the passed-in decoder function
                decoded_insn = decoder.decode(trace_ea, bytes_for_decoder)
            except Exception as e:
                logger.error(
                    "%sDecoder function raised exception at 0x%X: %s",
                    indent,
                    trace_ea,
                    e,
                )
                decoded_insn = None  # Treat as decode failure

            # If decoding failed or decoder returned None
            if not decoded_insn:
                logger.debug(
                    "%sFailed to decode instruction at 0x%X. Stopping trace. Returning start: 0x%X",
                    indent,
                    trace_ea,
                    current_ea,
                )
                return current_ea  # Return start of the sequence

            # --- Process the decoded instruction ---
            if decoded_insn.is_nop:
                logger.debug(
                    "%sNOP found at 0x%X (size %X). Skipping.",
                    indent,
                    trace_ea,
                    decoded_insn.size,
                )
                trace_ea += decoded_insn.size
                continue  # Continue the while loop to the next instruction

            if not decoded_insn.is_jump or decoded_insn.size != 2:
                logger.debug(
                    "%sChain stopped at 0x%X: Instruction is not a 2-byte jump. Returning start: 0x%X",
                    indent,
                    trace_ea,
                    current_ea,
                )
                return current_ea  # Return the start address of the sequence that ended

            # --- We have a 2-byte jump ---
            target = decoded_insn.jump_target  # This is an absolute address
            logger.debug(
                "%s  -> Found 2-byte jump at 0x%X targeting 0x%X",
                indent,
                trace_ea,
                target,
            )

            # --- Decide action based on the jump target (using absolute addresses) ---
            # 1. Target is within the 'followable' range [match_start, match_end + 6)
            if self.match_start <= target < match_end + 6:
                logger.debug(
                    "%sFollowing jump from 0x%X to 0x%X (recursive call)",
                    indent,
                    trace_ea,
                    target,
                )
                # Pass the same Memory object and decoder down recursively
                return self.follow_jump_chain(
                    mem, target, match_end, decoder, visited, depth + 1
                )

            # 2. Target lands exactly at the potential start of the next stage
            elif target == match_end + 6:
                logger.debug(
                    "%sJump chain ends: Reached potential next stage start 0x%X",
                    indent,
                    target,
                )
                return target  # Return the exact target address

            # 3. Target is within the overall Memory block, but *before* match_start.
            elif mem_start_ea <= target < self.match_start:
                logger.debug(
                    "%sJump chain ends: Target 0x%X is within Memory bounds [0x%X,0x%X) but outside followable range [0x%X, 0x%X). Returning target.",
                    indent,
                    target,
                    mem_start_ea,
                    mem_end_ea,
                    self.match_start,
                    match_end + 6,
                )
                return target  # Return the target address itself

            # 4. Target is out of the overall Memory bounds or otherwise unexpected.
            else:
                logger.debug(
                    "%sJump chain stopped: Target 0x%X is outside allowed ranges. Returning start address 0x%X",
                    indent,
                    target,
                    current_ea,
                )
                return current_ea  # Return the start address of the sequence containing the invalid jump

    def _decode_stream(self, decoder, start, match_bytes):
        offset = 0
        n = len(match_bytes)

        while offset < n:
            try:
                # hand the decoder only the bytes we haven’t consumed yet
                insn = decoder.decode(start + offset, match_bytes[offset:])
            except Exception as e:
                logger.error("Decode error @0x%X: %s", start + offset, e)
                return

            if not insn:
                return

            yield insn
            offset += insn.size

    def process(self, mem, chain, is_x64: bool):
        """
        Process each jump match in match_bytes.
        'chain' is expected to have attributes:
          - junk_length: int
          - stage1_type: SegmentType
        """
        decoder = CapstoneInstructionDecoder(is_x64)
        match_end = chain.overall_start() + chain.overall_length()
        logger.debug(
            "Processing jumps for chain @ 0x%X, match_end=0x%X",
            chain.overall_start(),
            match_end,
        )

        for insn in self._decode_stream(
            decoder, chain.overall_start(), self.match_bytes
        ):
            # 1) filter out non jumps or non 2-byte jumps
            if not insn.is_jump or insn.size != 2:
                continue

            final_target = self.follow_jump_chain(mem, insn.address, match_end, decoder)
            if not final_target:
                logger.debug("Bad target @0x%X", insn.address)
                continue

            if abs(final_target - match_end) > 6:
                logger.debug("Out of range @0x%X", insn.address)
                continue

            # 2) process the hit
            self.jump_targets[final_target] += 1
            if final_target not in self.target_type:
                self.target_type[final_target] = chain.stage1_type
            self.jump_details.append((insn.address, final_target, chain.stage1_type))
            logger.debug("Found jump @0x%X → 0x%X", insn.address, final_target)

        return self

    def __iter__(self):
        """
        Iterate over the most likely targets.
        For each candidate, if a jump exists whose starting address equals candidate + 1,
        yield its final target instead.

        Sorting is by count descending, then by final_target descending.
        """
        # Prepare a list of (final_target, count) tuples
        results = list(self.jump_targets.items())
        # Sort by count descending, then by final_target descending
        results.sort(key=lambda x: (x[1], x[0]), reverse=True)
        for candidate, count in results:
            final_candidate = candidate
            for jump_ea, target, stype in self.jump_details:
                if jump_ea == candidate + 1:
                    final_candidate = target
                    break
            yield final_candidate


def find_big_instruction(buffer_bytes: bytes, is_x64: bool = False) -> dict:
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


def _stage4_is_chain_valid(
    chain: MatchChain,
    mem: bytes,
    start_ea: int,
    is_x64: bool,
    max_size: int = MAX_PATTERN_LEN,
) -> MatchSegment | None:
    """
    Filter out false positive anti-disassembly patterns and handle overlaps.
    Integrates with existing big instruction detection code.

    Args:
        chains: List of MatchChain objects
        mem: Memory object containing binary data
        start_ea: Starting effective address
        max_size: Maximum valid size for an anti-disassembly routine (default: MAX_PATTERN_LEN)

    Returns:
        A single validated MatchChain object
    """

    # Check if we already have a big instruction segment
    for seg in chain.segments:
        if seg.segment_type == SegmentType.BIG_INSTRUCTION:
            return seg

    # Find the big instruction
    match_start = chain.overall_start()
    chain_end = match_start + max_size

    logger.debug(f"Analyzing match: {chain.description} @ 0x{match_start:X}")

    # Determine possible jump targets - using your existing code
    jump_targets = JumpTargetAnalyzer(
        chain.overall_matched_bytes(), match_start, chain_end, start_ea
    ).process(mem=mem, chain=chain, is_x64=is_x64)

    for target in jump_targets:
        # The most_likely_target represents the most likely jump target within the
        # stub—likely the point where execution exits to the unobfuscated code.
        # however, if we do not find a match, then we want to continue searching
        # previous targets and use those in decending order until we find a match
        logger.debug(f"most_likely_target: 0x{target:X}, block_end: 0x{chain_end:X}")
        # Check for big instruction in the 6 bytes before target
        # a big instruction (e.g., one with a 32-bit operand, up to 6 bytes)
        # just before the final jump target to confuse disassemblers.
        search_start = target - 6
        if search_start < start_ea:
            continue

        # Extract the 6-byte buffer
        buffer_offset = search_start - start_ea
        target_offset = target - start_ea
        target_offset_forward = target - start_ea + 6
        if buffer_offset < 0 or target_offset > len(mem):
            continue

        if target_offset_forward > len(mem):
            logger.debug(
                f"  Rejected: {chain.description} @ 0x{match_start:X} - target_offset_forward out of bounds: {target_offset_forward}"
            )
            continue
        search_bytes_backwards = mem[buffer_offset:target_offset]
        search_bytes_forwards = mem[target_offset:target_offset_forward]

        for start_offset, search_bytes in [
            (buffer_offset, search_bytes_backwards),
            (target_offset, search_bytes_forwards),
        ]:
            logger.debug(f"search_bytes: {search_bytes.hex()}")
            # up to 6 bytes to search for a big instruction.
            if len(search_bytes) != 6:
                logger.debug(
                    f"  Rejected: {chain.description} @ 0x{match_start:X} - search_bytes too long: {len(search_bytes)} bytes"
                )
                continue
            result = find_big_instruction(search_bytes, is_x64=is_x64)

            if not result["type"]:
                logger.debug("No valid instruction found.")
                # if we do not find a match, then we want to find the previous targets and use those
                # in decending order until we find a match
                continue

            # check for multiple anti-disassembly bytes after search_start + 6
            # if found, then we want to add them to the new_bytes
            new_len = (
                len(result["junk_before"])
                + len(result["instruction"])
                + len(result["junk_after"])
            )
            new_bytes = (
                bytes(result["junk_before"])
                + bytes(result["instruction"])
                + bytes(result["junk_after"])
            )

            # Check for additional anti-disassembly bytes
            max_extra = max_size - new_len
            mem_len = len(mem)
            for _ in range(max_extra):
                extra_offset = start_offset + new_len
                if extra_offset >= mem_len:
                    break
                if mem[extra_offset] != SUPERFLULOUS_BYTE:
                    break
                logger.info(
                    "* Found extra anti-disassembly byte @ 0x%X",
                    start_ea + start_offset + new_len,
                )
                new_bytes += bytes([mem[extra_offset]])
                new_len += 1

            return MatchSegment(
                start=start_offset,
                length=new_len,
                description=result["name"],
                matched_bytes=new_bytes,
                segment_type=SegmentType.BIG_INSTRUCTION,
            )


def resolve_overlaps(chains: list[MatchChain]) -> list[MatchChain]:
    """
    Fast, linear-time overlap resolution: keep only the first chain
    whose start is ≥ the furthest end so far.
    """
    logger.info(f"Resolving overlaps among {len(chains)} chains")

    # 1) Sort by start EA
    sorted_chains = sorted(chains, key=lambda c: c.overall_start())

    # 2) One‐pass acceptor
    final: list[MatchChain] = []
    max_end = -1  # highest end of any accepted chain so far

    for c in sorted_chains:
        s = c.overall_start()
        e = s + c.overall_length()
        if s >= max_end:
            final.append(c)
            max_end = e

    logger.info(
        f"Overlap resolution complete: {len(final)} of {len(chains)} chains accepted"
    )
    return final


# ─── Async deobfuscator ───────────────────────────────────


def make_chunks(buf_len: int, n_chunks: int, max_pat: int = MAX_PATTERN_LEN):
    """
    Yield exactly n_chunks tuples of
      (padded_start, padded_end, core_start, core_end).

    * core ranges partition [0, buf_len) evenly by floor division.
    * padded ranges extend each core by (max_pat-1) on both sides,
      clamped to [0, buf_len].
    """
    for i in range(n_chunks):
        # uniform core split
        core_start = (buf_len * i) // n_chunks
        core_end = (buf_len * (i + 1)) // n_chunks
        core_len = core_end - core_start

        # padding
        padded_start = max(0, core_start - (max_pat - 1))
        padded_end = min(buf_len, core_end + (max_pat - 1))
        padded_len = padded_end - padded_start

        logger.info(
            "Chunk %2d/%d: "
            "core=[%#x-%#x) (%d bytes), "
            "padded=[%#x-%#x) (%d bytes)",
            i,
            n_chunks,
            core_start,
            core_end,
            core_len,
            padded_start,
            padded_end,
            padded_len,
        )

        yield padded_start, padded_end, core_start, core_end


def process_chunk(args):
    """
    Entire 4-stage pipeline over one overlapping chunk.
    Returns only those chains whose start is in the chunk's core region.
    """
    shm_name, padded_start, padded_end, core_start, core_end, base_ea, is_64 = args

    core_valid = []

    # attach shared memory
    with shm_buffer(shm_name) as shm:
        # zero-copy view of the chunk
        full_buf_mv = memoryview(shm.buf)[padded_start:padded_end]
        try:
            # — Stage 1
            s1_chains = stage1_find_patterns(full_buf_mv, base_ea + padded_start)

            # — Stage 2 + 3
            s2_3 = []
            for chain in s1_chains:
                chain = find_junk_stage2_chain(chain, full_buf_mv, base_ea, is_64)
                if (
                    MIN_PATTERN_LEN <= chain.overall_length() <= MAX_PATTERN_LEN
                    and chain.junk_length > 0
                ):
                    s2_3.append(chain)

            # — Stage 4
            validated = []
            for chain in s2_3:
                seg = _stage4_is_chain_valid(chain, full_buf_mv, base_ea, is_64)
                if seg:
                    chain.add_segment(seg)  # attach the BIG_INSTRUCTION
                    validated.append(chain)

            # — Filter out duplicates from the overlap padding: only keep those
            #    whose start-offset falls in [core_start, core_end)
            for c in validated:
                rel_off = c.overall_start() - base_ea
                if core_start <= rel_off < core_end:
                    core_valid.append(c)

                # Sanity check
                start = c.overall_start()
                length = c.overall_length()
                end = start + length
                if length > MAX_PATTERN_LEN or end > base_ea + shm.size:
                    logger.warning(
                        "🚨 chain @ 0x%X length=%d end=0x%X (core=[%d, %d])",
                        start,
                        length,
                        end,
                        core_start + base_ea,
                        core_end + base_ea,
                    )
        finally:
            del full_buf_mv
    return core_valid


@contextlib.contextmanager
def shm_buffer(name: str, buf_len: int | None = None):
    """
    context manager to access the shared memory buffer.
    if buf_len is not provided, then the buffer will be the raw shm memory
    buffer else it will be a byte slice of the shm memory buffer.
    
    Usage:
        with shm_buffer(name=..) as buf:
            # use buf
    """
    shm = multiprocessing.shared_memory.SharedMemory(name=name)
    try:
        yield shm.buf[:buf_len] if buf_len else shm
    finally:
        shm.close()


@dataclasses.dataclass
class AsyncDeobfuscator(AsyncEventEmitter):
    shm_name: str
    data_size: int
    start_ea: int
    is_64bit: bool
    max_workers: int = None
    executor: concurrent.futures.Executor | None = None

    def __post_init__(self):
        super().__post_init__()
        self.pause_evt = asyncio.Event()
        self.stop_evt = asyncio.Event()
        self.max_workers = self.max_workers or max(1, multiprocessing.cpu_count())
        ctx = multiprocessing.get_context("spawn")
        self.executor = self.executor or concurrent.futures.ProcessPoolExecutor(
            max_workers=self.max_workers, mp_context=ctx
        )
        logger.info(f"executor pool created with {self.max_workers} workers")

    @log_execution_time
    async def run(self):
        await self.emit("run_started")

        # 1) define exactly max_workers chunks over the shared buffer
        buf_len = self.data_size
        chunks = list(make_chunks(buf_len, self.max_workers))
        logger.debug(
            "Splitting buffer of %d bytes into %d chunks:", buf_len, len(chunks)
        )
        for idx, (ps, pe, cs, ce) in enumerate(chunks):
            logger.debug(
                "  chunk %2d: core=[%d..%d) padded=[%d..%d)", idx, cs, ce, ps, pe
            )

        # 2) fire one full-pipeline task per chunk
        loop = asyncio.get_running_loop()
        jobs = [
            (
                self.shm_name,
                padded_start,
                padded_end,
                core_start,
                core_end,
                self.start_ea,
                self.is_64bit,
            )
            for padded_start, padded_end, core_start, core_end in chunks
        ]
        futures = [
            loop.run_in_executor(self.executor, process_chunk, job) for job in jobs
        ]

        # 3) wait, flatten, resolve overlaps globally
        per_chunk = await asyncio.gather(*futures)
        all_chains = [c for grp in per_chunk for c in grp]

        # now de-dupe any remaining overlaps
        final = resolve_overlaps(all_chains)

        # emit & return
        final.sort(key=lambda c: c.overall_start())
        await self.emit("run_finished", final)
        return final

    async def shutdown(self):
        self.stop_evt.set()
        self.executor.shutdown(wait=True)
        await self.emit("stopped")


# ─── Standalone worker entrypoint ───────────────────────────────────────────


class WorkerController:
    """Wrap AsyncDeobfuscator in its own event loop"""

    def __init__(self, deob: AsyncDeobfuscator):
        self.deob = deob
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._result = None
        self._started = False  # Track if start() has been called

    def _run_loop(self):
        # set and run the loop
        asyncio.set_event_loop(self.loop)
        try:
            self._result = self.loop.run_until_complete(self.deob.run())
        except Exception as e:
            logger.error(f"Exception in worker thread loop: {e}", exc_info=True)
            # Store exception or indicate error?
            self._result = None  # Or some error sentinel

    def start(self):
        """Launch the pipeline in its own thread."""
        if self._started:
            logger.warning("Start called on an already started worker controller.")
            return
        self._thread.start()
        self._started = True  # Mark as started

    def pause(self):
        """Pause after finishing the current iteration."""
        if not self._started:
            logger.warning("Pause called before worker controller was started.")
            return
        logger.info("▶️  Pausing...")
        self.loop.call_soon_threadsafe(self.deob.pause_evt.set)

    def resume(self):
        """Resume if previously paused."""
        if not self._started:
            logger.warning("Resume called before worker controller was started.")
            return
        logger.info("▶️  Resuming...")
        self.loop.call_soon_threadsafe(self.deob.pause_evt.clear)

    def stop(self):
        """Stop the pipeline as soon as possible."""
        if not self._started:
            logger.warning("Stop called before worker controller was started.")
            # Even if not started, set stop event for consistency if needed
            # self.loop.call_soon_threadsafe(self.deob.stop_evt.set) # Maybe not necessary if loop never runs
            return
        logger.info("🛑  Stopping...")
        # Use call_soon_threadsafe as the loop might be running
        self.loop.call_soon_threadsafe(self.deob.stop_evt.set)

    def join(self):
        """Block until the pipeline finishes, return the final chains."""
        if not self._started:
            logger.warning(
                "Join called before worker controller was started. Returning current result (None)."
            )
            return self._result  # Return None or whatever _result is initially

        # Check if the thread is actually alive before joining
        # is_alive() is True from the time start() returns until shortly after run() completes
        if self._thread.is_alive():
            self._thread.join()
        else:
            # Thread was started but might have finished already or crashed
            logger.info(
                "Worker thread was not alive when join was called (already finished or failed?)."
            )
        self._started = False
        return self._result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        PROPOGATE = False
        SUPPRESS = True
        if not exc_type:
            return SUPPRESS

        logger.error(
            "Worker thread raised an exception: %s %s %s", exc_type, exc_val, exc_tb
        )
        self.stop()
        return PROPOGATE


class ConnectionContext:
    """
    Context manager for a multiprocessing.connection.Connection.
    Ensures the connection is closed on exit.
    """

    def __init__(self, address: str, authkey: bytes | str, chunk_size: int = 1024):
        host, port_str = address.split(":")
        self.host = host
        self.port = int(port_str)

        if isinstance(authkey, str):
            authkey = bytes.fromhex(authkey)

        assert isinstance(authkey, bytes), f"Invalid authkey type: {type(authkey)}"
        self.authkey = authkey
        self._conn = None
        self.chunk_size = chunk_size

    @property
    def address(self) -> tuple[str, int]:
        return (self.host, self.port)

    @property
    def conn(self) -> multiprocessing.connection.Client:
        if self._conn is None:
            self._conn = multiprocessing.connection.Client(
                self.address, family="AF_INET", authkey=self.authkey  # Force TCP socket
            )
            logger.info(f"Connected to {self.address}")
        return self._conn

    def send_message(self, msg_type: str, data, **kwargs) -> bool:
        """
        Send a structured message through the connection.

        If data is a long list, split it into chunks, each carrying:
          - message_id: a unique UUID for this logical payload
          - chunk_index: 0-based index
          - total_chunks
        Otherwise send a single message with no chunk metadata.

        Args:
            msg_type: Type of message (status, result, error, etc.)
            data: The payload data
            **kwargs: Additional message attributes

        """
        try:
            if isinstance(data, list) and len(data) > self.chunk_size:
                message_id = uuid.uuid4().hex
                total_chunks = math.ceil(len(data) / self.chunk_size)

                for idx in range(total_chunks):
                    part = data[idx * self.chunk_size : (idx + 1) * self.chunk_size]
                    msg = {
                        "type": msg_type,
                        "data": part,
                        "timestamp": time.time(),
                        "message_id": message_id,
                        "chunk_index": idx,
                        "total_chunks": total_chunks,
                        **kwargs,
                    }
                    self.conn.send(msg)
                logger.debug(
                    f"→ Streamed {len(data)} items in {total_chunks} chunks under id {message_id}"
                )
                return True

            # small or non-list payload: single shot
            msg = {
                "type": msg_type,
                "data": data,
                "timestamp": time.time(),
                **kwargs,
            }
            self.conn.send(msg)
            logger.debug(f"→ Sent single message: {msg_type}")
            return True

        except Exception as e:
            logger.error(f"Failed to send message: {e}", exc_info=True)
            return False

    @property
    def closed(self):
        """True if the connection is closed"""
        return self.conn.closed

    @property
    def readable(self):
        """True if the connection is readable"""
        return self.conn.readable

    @property
    def writable(self):
        """True if the connection is writable"""
        return self.conn.writable

    def fileno(self):
        """File descriptor or handle of the connection"""
        return self.conn.fileno()

    def recv(self):
        """Receive a (picklable) object"""
        return self.conn.recv()

    def poll(self, timeout=0.0):
        """Whether there is any input available to be read"""
        return self.conn.poll(timeout)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        PROPOGATE = False
        SUPPRESS = True
        if exc_type:
            logger.error("Connection closed by parent")
            return PROPOGATE

        if self.conn is not None:
            try:
                logger.info("Closing worker-side connection.")
                self.conn.close()
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
        return SUPPRESS


def process(deob, address, authkey):
    """
    Main processing function that sets up event handlers and handles communication.

    Args:
        deob: The deobfuscator instance
        address: Address of the parent process
        authkey: Authentication key in hex format

    Returns:
        The results from the deobfuscator process
    """
    # Set up progress tracking
    progress_state = {
        "current": 0.0,
        "status": "initializing",
        "last_sent": 0.0,  # Track when we last sent a progress update
    }

    # Register event handlers with progress reporting
    @deob.on("run_started")
    def on_run_started():
        logger.info("▶️  Pipeline starting")
        progress_state["status"] = "running"
        progress_state["current"] = 0.0
        if "conn" in progress_state:
            progress_state["conn"].send_message(
                "progress",
                progress_state["current"],
                status="running",
                stage="starting",
            )

    @deob.on("stage1_finished")
    def on_stage1_finished(ch):
        logger.info(f"✅ Stage1: {len(ch)} stubs")
        progress_state["current"] = 0.25
        progress_state["status"] = "running"
        if "conn" in progress_state:
            progress_state["conn"].send_message(
                "progress",
                progress_state["current"],
                status="running",
                stage="stage1_complete",
                stubs_count=len(ch),
            )

    @deob.on("stage2_finished")
    def on_stage2_finished(ch):
        logger.info(f"✅ Stage2: {len(ch)} junk appended")
        progress_state["current"] = 0.50
        progress_state["status"] = "running"
        if "conn" in progress_state:
            progress_state["conn"].send_message(
                "progress",
                progress_state["current"],
                status="running",
                stage="stage2_complete",
                chunks_count=len(ch),
            )

    @deob.on("stage3_finished")
    def on_stage3_finished(ch):
        logger.info(f"✅ Stage3: {len(ch)} remaining")
        progress_state["current"] = 0.75
        progress_state["status"] = "running"
        if "conn" in progress_state:
            progress_state["conn"].send_message(
                "progress",
                progress_state["current"],
                status="running",
                stage="stage3_complete",
                chunks_count=len(ch),
            )

    @deob.on("stage4_finished")
    def on_stage4_finished(ch):
        logger.info(f"✅ Stage4: {len(ch)} final")
        progress_state["current"] = 0.95
        progress_state["status"] = "finalizing"
        if "conn" in progress_state:
            progress_state["conn"].send_message(
                "progress",
                progress_state["current"],
                status="finalizing",
                stage="stage4_complete",
                chunks_count=len(ch),
            )

    @deob.on("stopped")
    def on_stopped():
        logger.info("🛑 Worker shutting down")
        progress_state["status"] = "stopped"
        if "conn" in progress_state:
            progress_state["conn"].send_message("status", "stopped", status="stopped")

    with WorkerController(deob) as ctrl, ConnectionContext(address, authkey) as conn:
        # Store connection in progress_state for event handlers
        progress_state["conn"] = conn
        # Send initial ready message
        conn.send_message("status", "connected", status="ready")
        logger.info("Starting command loop (reading from connection)...")
        try:
            while True:
                try:
                    # Poll for commands with timeout
                    if not conn.closed and not conn.poll(timeout=0.5):
                        continue
                    # Connection has data
                    cmd = conn.recv()
                    logger.debug(f"← Received command: {cmd}")
                except EOFError:
                    logger.error("Connection closed by parent")
                    break

                # Process command
                if isinstance(cmd, dict):
                    cmd_type = cmd.get("command")
                    if cmd_type in ["stop", "exit", "shutdown"]:
                        logger.info("Received exit command")
                        break
                    elif cmd_type == "ping":
                        conn.send_message("status", "pong", status="running")
                    elif cmd_type == "pause":
                        ctrl.pause()
                        conn.send_message("status", "paused", status="paused")
                    elif cmd_type == "resume":
                        ctrl.resume()
                        conn.send_message("status", "resumed", status="running")
                    elif cmd_type == "start":
                        ctrl.start()
                        conn.send_message("status", "started", status="running")
                    elif cmd_type == "set_log_level":
                        level = cmd.get("level")
                        logger.setLevel(level)
                        ctrl.set_log_level(level)
                        logger.info(f"Worker log level set to {level}")
                        conn.send_message(
                            "status",
                            f"log_level_set:{level}",
                            status="running",
                        )
                    else:
                        logger.warning(f"Unknown command type: {cmd_type}")
                        conn.send_message(
                            "error",
                            f"Unknown command: {cmd_type}",
                            status="error",
                        )
                else:
                    logger.warning(f"Received unexpected command type: {type(cmd)}")
                    conn.send_message(
                        "error",
                        f"Expected dict command, got {type(cmd)}",
                        status="error",
                    )
            # Ensure pipeline stops if we exit the loop
            ctrl.stop()
        finally:
            # Remove connection from progress_state
            progress_state.pop("conn", None)

        # Wait for pipeline completion
        logger.info("Waiting for pipeline to finish...")
        return ctrl.join()


def worker_main():
    p = argparse.ArgumentParser()
    p.add_argument("--shm_name", required=True)
    p.add_argument("--data_size", type=int, required=True)
    p.add_argument("--start_ea", type=lambda x: int(x, 0), required=True)
    p.add_argument("--is64", type=int, default=1)
    p.add_argument("--address", required=True, help="Parent address (host:port)")
    p.add_argument("--authkey", required=True, help="Auth key in hex format")
    args = p.parse_args()

    try:
        deob = AsyncDeobfuscator(
            shm_name=args.shm_name,
            data_size=args.data_size,
            start_ea=args.start_ea,
            is_64bit=bool(args.is64),
        )

        # Run the deobfuscation process
        results = process(deob, args.address, args.authkey)
        logger.info("Pipeline finished.")

        if not results:
            logger.info("No results generated or retrieved from pipeline.")
            return

        # Format results
        asjson = [
            {
                "address": c.overall_start(),
                "length": c.overall_length(),
                "end": c.overall_start() + c.overall_length(),
            }
            for c in results
        ]

        logger.info(f"Processed {len(asjson)} results.")

        # Try to send results via connection
        with ConnectionContext(args.address, args.authkey) as conn:
            logger.info("Sending results via IPC connection in 5 seconds...")
            if not conn.send_message(
                "status", "sending_results", status="sending_results"
            ):
                logger.error("Failed to send status message")
            time.sleep(5)
            if not conn.send_message(
                "result", asjson, status="success", count=len(asjson)
            ):
                logger.error("Failed to send results message")
            if not conn.send_message(
                "status", "results_sent", status="results_sent", count=len(asjson)
            ):
                logger.error("Failed to send results_sent message")
            logger.info("Results sent via IPC connection.")

    except Exception as e:
        logger.error(f"Unhandled exception in worker_main: {e}", exc_info=True)
    finally:
        logger.info("Worker finished.")


# ─── IDA plugin entrypoint is no longer needed for console mode ─────────────


class PatchManager:
    """Manages deferred patch operations."""

    class Mode(enum.Enum):
        PATCH = enum.auto()  # Use ida_bytes.patch_bytes
        PUT = enum.auto()  # Use ida_bytes.put_bytes

    def __init__(
        self,
        patch_mode: Mode = Mode.PATCH,
        dry_run: bool = False,
        auto_clear: bool = True,
    ):
        self.dry_run = dry_run
        self.patch_mode = patch_mode
        self.pending_patches: list[DeferredPatchOp] = []
        self.auto_clear = auto_clear
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
        if self.auto_clear:
            self.pending_patches.clear()  # Clear the list after applying
        return fail_count == 0  # Return True if all patches were applied successfully

    def __len__(self) -> int:
        return len(self.pending_patches)


@dataclasses.dataclass(repr=False)
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
            ("revertably" if self.mode == PatchManager.Mode.PATCH else "destructively"),
            self.address,
            len(self.byte_values),
        )
        success = True
        if is_dry_run:
            return success

        try:
            func = (
                idaapi.put_bytes
                if self.mode == PatchManager.Mode.PUT
                else idaapi.patch_bytes
            )
            func(self.address, self.byte_values)
        except Exception as e:
            logger.error(f"Failed to apply patch {self}: {e}", exc_info=True)
            success = False
        return success

    def __str__(self):
        """String representation with hex formatting."""
        dry_run_str = " (dry run)" if self.dry_run else ""
        return f"{self.__class__.__name__}({len(self.byte_values)} bytes, mode={self.mode.name}{dry_run_str} @ address=0x{self.address:X})"

    __repr__ = __str__


WORKER_SCRIPT_PATH = pathlib.Path(__file__)

if is_ida():
    import json
    import re

    from PyQt5 import QtCore
    from PyQt5.QtCore import QProcessEnvironment

    import ida_bytes
    import ida_ida
    import ida_segment
    import idaapi

    is_x64 = ida_ida.inf_is_64bit()

    class TemporarilyDisableNotifier:
        """Context manager to temporarily disable a QSocketNotifier."""

        def __init__(self, notifier):
            self.notifier = notifier
            self.was_enabled = False

        def __enter__(self):
            # Save current enabled state
            self.was_enabled = self.notifier.isEnabled()
            # Disable the notifier
            self.notifier.setEnabled(False)
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            # Re-enable only if it was enabled before
            if self.was_enabled:
                self.notifier.setEnabled(True)

    class ConnectionReader(QtCore.QThread):
        message_received = QtCore.pyqtSignal(object)
        connection_closed = QtCore.pyqtSignal()

        def __init__(self, parent=None):
            super().__init__(parent)
            self.connection: multiprocessing.connection.Connection | None = None

        def set_connection(self, conn):
            self.connection = conn

        def run(self):
            if not self.connection:
                return

            try:
                # Keep calling recv() until the pipe/socket dies.
                while True:
                    msg = (
                        self.connection.recv()
                    )  # blocks until a *full* pickled object arrives
                    # emit every single message—status, result, results_sent, etc.
                    self.message_received.emit(msg)
            except (EOFError, OSError):
                # clean shutdown when the other side closes
                self.connection_closed.emit()
            except pickle.PickleError as e:
                logger.error(f"Pickle error: {e}")
            finally:
                try:
                    self.connection.close()
                except Exception:
                    pass

    class QtListener(QtCore.QObject):
        """Qt-friendly wrapper for multiprocessing.connection.Listener with non-blocking SOCKET connection handling"""

        # hardcode family to AF_INET since we're only socket listeners are supported.
        family = "AF_INET"

        # Signal emitted when a connection is accepted
        connection_accepted = QtCore.pyqtSignal(object)  # Passes the Connection object
        connection_error = QtCore.pyqtSignal(str)

        def __init__(self, address=None, backlog=1, authkey=None, parent=None):
            super().__init__(parent)

            # Create the standard listener
            self._listener = multiprocessing.connection.Listener(
                address, self.family, backlog, authkey
            )

            # Get the underlying socket from the SocketListener
            self._socket = self._listener._listener._socket
            # Create a socket notifier to monitor for incoming connections
            self._notifier = QtCore.QSocketNotifier(
                self._socket.fileno(), QtCore.QSocketNotifier.Read, self
            )
            self._notifier.activated.connect(self._on_connection_ready)
            self._notifier.setEnabled(True)

        def _on_connection_ready(self):
            """Called when the socket notifier detects the socket is readable"""
            with TemporarilyDisableNotifier(self._notifier):
                try:
                    # Verify socket is readable with select (non-blocking)
                    ready, _, _ = select.select([self._socket], [], [], 0)

                    if not ready:
                        return

                    # Socket is ready, so accept() won't block
                    conn = self.accept()
                    # Emit signal with the connection
                    self.connection_accepted.emit(conn)
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    self.connection_error.emit(str(e))

        def accept(self):
            """Original blocking accept method (avoid using in Qt apps)"""
            return self._listener.accept()

        def close(self):
            """Close the listener and clean up resources"""
            self._notifier.setEnabled(False)
            self._notifier.deleteLater()
            self._listener.close()

        @property
        def address(self):
            return self._listener.address

    class WorkerLauncher(QtCore.QProcess):
        """
        Manages the external worker process using QProcess for command/status.
        Relies on shared memory for large data transfer.
        Uses asynchronous bidirectional IPC for structured communication.
        """

        ## Signals emitted by the broker

        #: For structured results (assuming dict)
        processing_results = QtCore.pyqtSignal(dict)

        #: For errors reported by the worker
        error_occurred_msg = QtCore.pyqtSignal(str)

        #: When worker sends a message via IPC
        worker_message = QtCore.pyqtSignal(object)

        #: When worker connection is established
        worker_connected = QtCore.pyqtSignal()

        #: When worker connection is closed
        worker_disconnected = QtCore.pyqtSignal()

        def __init__(self, parent=None):
            super(WorkerLauncher, self).__init__(parent)
            self.readyReadStandardOutput.connect(self._on_stdout)
            self.readyReadStandardError.connect(self._on_stderr)
            self.errorOccurred.connect(self._on_error)
            self.stateChanged.connect(self._on_state_changed)
            self.python_interpreter = MultiprocessingHelper.get_python_interpreter()

            # --- Connection attributes ---
            self.listener = None
            self.connection = None
            self.authkey = None

            # Setup reader thread for non-blocking IPC reads
            self.reader_thread = ConnectionReader(self)
            self.reader_thread.message_received.connect(self._on_worker_message)
            self.reader_thread.connection_closed.connect(self._on_connection_closed)

            self.connection_attempts = 0
            self.max_connection_attempts = 10

            # per-stream accumulators: prefix → {"chunks": [...], "total": int}
            self._streams: dict[str, dict] = {}

        def is_not_running(self):
            return self.state() == QtCore.QProcess.NotRunning

        def _on_worker_message(self, message):
            """Process messages from the worker, including chunked streams."""
            msg_type = message.get("type")

            # 1) detect chunked stream
            msg_id = message.get("message_id")
            if msg_id:
                idx = message["chunk_index"]
                total = message["total_chunks"]

                stream = self._streams.setdefault(
                    msg_id, {"type": msg_type, "chunks": {}, "total": total}
                )
                stream["chunks"][idx] = message["data"]
                logger.info(
                    "Received chunk %d/%d for %r (id=%s)",
                    idx + 1,
                    total,
                    msg_type,
                    msg_id,
                )

                # once we have all chunks, reassemble and emit
                if len(stream["chunks"]) == total:
                    full = []
                    for i in range(total):
                        full.extend(stream["chunks"][i])
                    # cleanup
                    del self._streams[msg_id]
                    logger.info(
                        "%r streaming complete (id=%s, %d items)",
                        msg_type,
                        msg_id,
                        len(full),
                    )
                    # emit exactly once as a single result
                    self.processing_results.emit(
                        {
                            "type": "result",
                            "results": full,
                            "status": "success",
                        }
                    )
                return  # done

            # 2) non-chunked messages
            logger.debug("← Received message from worker: %r", message)
            # Emit the message for external handlers
            self.worker_message.emit(message)

            # Process specific message types if needed
            if isinstance(message, dict):
                msg_type = message.get("type")
                if msg_type == "error":
                    error_msg = message.get("error", "Unknown error")
                    self.error_occurred_msg.emit(error_msg)
                elif msg_type == "result":
                    # Format results in the expected structure
                    results = {
                        "results": message.get("data"),
                        "status": message.get("status", "success"),
                    }
                    logger.info("Emitted processing_results via IPC.")
                    self.processing_results.emit(results)
                # Worker message: {'type': 'status', 'data': 'connected', 'timestamp': 1745800440.6233163, 'status': 'ready'}
                elif msg_type == "status" and message.get("status") == "ready":
                    self.send_command({"command": "start"})

        def _on_connection_closed(self):
            """Handle connection closed by worker"""
            logger.info("Worker IPC connection closed.")

            if self.connection:
                try:
                    self.connection.close()
                except:
                    pass
                self.connection = None
            self.worker_disconnected.emit()

        def launch_worker(self, start_ea: int, shm_name: str, data_size: int):
            """Starts the worker script, passing connection details."""
            self._cleanup_resources()
            # Create a TCP socket listener
            self.authkey = os.urandom(32)  # Use a reasonably strong key
            logger.info(f"Generated Authkey: {self.authkey.hex()}")
            self.listener = QtListener(
                ("localhost", 0),  # Let OS assign port
                authkey=self.authkey,
                parent=self,
            )
            address = self.listener.address  # (host, port) tuple
            logger.info(f"Created listener on {address}")
            self.listener.connection_accepted.connect(self._on_connection_accepted)
            self.listener.connection_error.connect(self._on_connection_error)

            # --- Prepare QProcess ---
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
                "--address",
                f"{address[0]}:{address[1]}",
                "--authkey",
                self.authkey.hex(),
            ]

            logger.info(f"Starting worker process: {self.python_interpreter} {args}")
            self.start(str(self.python_interpreter), args)
            if not self.waitForStarted(5000):
                logger.error(f"Worker process failed to start: {self.errorString()}")
                self._cleanup_resources()
                return False

            # Begin checking for connections
            self.connection_attempts = 0
            # Begin connection attempts with backoff strategy
            logger.info("Worker process started. Beginning connection attempts...")
            return True  # Indicates process started, connection pending

        def _on_connection_accepted(self, conn):
            """Handle a new connection"""
            logger.info("Connection from worker accepted")
            # Set up communication
            # Give the new Connection to our reader thread
            #    (this atomically replaces its internal .connection)
            self.reader_thread.set_connection(conn)
            if not self.reader_thread.isRunning():
                self.reader_thread.start()
            self.connection = conn
            self.worker_connected.emit()

        def _on_connection_error(self, error_msg):
            """Handle connection errors"""
            logger.error(f"Connection error: {error_msg}")
            self.connection_attempts += 1

            if self.connection_attempts >= self.max_connection_attempts:
                self.error_occurred_msg.emit(
                    f"Failed to connect to worker after {self.max_connection_attempts} attempts"
                )
                self.stop_worker()

        def _cleanup_resources(self):
            """Clean up connection resources."""

            # Stop reader thread
            if self.reader_thread.isRunning():
                self.reader_thread.stop()

            # Close connection
            if self.connection:
                try:
                    self.connection.close()
                except:
                    pass
                self.connection = None

            # Close listener
            if self.listener:
                try:
                    self.listener.close()
                except:
                    pass
                self.listener = None

        def stop_worker(self):
            """Attempts to terminate the worker process gracefully, then kills."""
            if self.is_not_running() and not self.connection:
                logger.debug(
                    "Worker process was already stopped and connection closed."
                )
                return

            logger.info("Attempting to stop worker process...")

            # Try to send exit command if connected
            if self.connection:
                try:
                    logger.info("Sending exit command...")
                    self.send_command({"command": "exit"})
                    # Give a moment for clean shutdown
                    if self.waitForFinished(1000):
                        logger.info("Worker exited gracefully.")
                        self._cleanup_resources()
                        return
                except Exception as e:
                    logger.error(f"Error sending exit command: {e}")

            # Terminate if still running
            if not self.is_not_running():
                logger.warning("Worker did not exit gracefully, terminating...")
                self.terminate()
                if not self.waitForFinished(2000):
                    logger.warning("Worker did not terminate, killing...")
                    self.kill()
                    self.waitForFinished(1000)

            # Clean up resources
            self._cleanup_resources()
            logger.info("Worker process shutdown complete.")

        def send_command(self, command):
            """Sends a command object via the client connection."""
            if not self.connection:
                logger.warning(
                    f"Cannot send command '{command}', IPC connection not established or closed."
                )
                if self.state() != QtCore.QProcess.Running:
                    logger.warning("Worker process is not running.")
                return False

            logger.debug(f"→ Sending command: {command}")
            try:
                self.connection.send(command)
                logger.debug(f"→ Successfully sent command: {command}")
                return True
            except Exception as e:
                # Handle broken pipe errors, etc.
                logger.error(f"Failed to send command '{command}': {e}")
                self._on_connection_closed()
                return False

        def _on_stdout(self):
            """Reads and logs worker stdout."""
            out_bytes = self.readAllStandardOutput()
            if not out_bytes:
                return
            out = out_bytes.data().decode("utf-8", errors="replace")

            # Just log stdout, no special handling
            if out.strip():
                print(out.strip(), flush=True)

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

            if self.is_not_running():
                # Clean up resources if the process has stopped
                self._cleanup_resources()

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

        @staticmethod
        def from_range(start_ea: int, end_ea: int):
            """Get the data of a section by name and return the start address and the bytes."""
            data_bytes = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
            return start_ea, data_bytes

        def pause(self):
            self.proc.send_command({"command": "pause"})

        def resume(self):
            self.proc.send_command({"command": "resume"})

        def stop(self):
            self.proc.send_command({"command": "stop"})

        def start(self):
            self.proc.send_command({"command": "start"})

        def ping(self):
            self.proc.send_command({"command": "ping"})

        def set_log_level(self, level: int):
            """
            Dynamically request the worker process switch its logger level.
            Example:
                import logging
                Taskr().get().log_level(logging.DEBUG)
            """
            self.proc.send_command({"command": "set_log_level", "level": level})

        def terminate(self):
            """Terminate the plugin, stopping the broker and cleaning up shared memory."""
            logger.info("Terminating...")
            # Stop the broker process (sends 'exit' command)
            if self.proc and not self.proc.is_not_running():
                self.proc.stop_worker()
                self.proc = None  # Clear reference
            self._cleanup_shared_memory()
            logger.info("Terminated.")

        def _handle_worker_message(self, msg: typing.Any):
            logger.info(f"Worker message: {msg}")

        def _handle_worker_results(self, results: dict):
            logger.info(f"Worker results: {results}")
            if results["status"] == "success":
                for patch_instructions in results["results"]:
                    self.patch_manager.add_patch(
                        patch_instructions["address"],
                        patch_instructions["length"] * "\x90",
                    )
                self.patch_manager.apply_all()
            else:
                logger.error(f"Worker reported an error: {results['error']}")

        def _handle_worker_error(self, error: str):
            """Handles error messages originating from the worker process."""
            logger.error(f"Worker reported an error: {error}")

            # Consider stopping the worker and cleaning up shared memory on error
            self.proc.stop_worker()
            self._cleanup_shared_memory()

        def run(self, start_ea: int, bytes_to_process: bytes, **kwargs):
            """Run the main plugin logic when hotkey is pressed."""
            plugin_arg: typing.Any = kwargs.pop("plugin_arg", None)
            if plugin_arg is not None:
                logger.info(f"Received plugin arg: {plugin_arg}")

            data_size = len(bytes_to_process)
            # create shared memory & copy
            self._shared_memory = multiprocessing.shared_memory.SharedMemory(
                create=True, size=data_size
            )
            self._shared_memory.buf[:data_size] = bytes_to_process

            # launch worker
            self.proc = WorkerLauncher()
            self.proc.worker_message.connect(self._handle_worker_message)
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
                multiprocessing.shared_memory.SharedMemory(
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
