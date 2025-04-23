#!/usr/bin/env python3
# anti_deob.py

import argparse
import asyncio
import atexit
import contextlib
import json
import logging
import multiprocessing
import os
import pathlib
import stat
import sys
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


if not is_ida():
    sys.stdout.reconfigure(encoding="utf-8")
else:
    sys.stdout.encoding = "utf-8"


def configure_logging(
    log,
    level=logging.INFO,
    handler_filters=None,
    fmt_str="[%(levelname)s] @ %(asctime)s %(message)s",
):
    log.propagate = False
    log.setLevel(level)
    formatter = logging.Formatter(fmt_str)
    handler = logging.StreamHandler()
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
    name = name or f"{"ida_" if is_ida() else "worker_"}{__name__}"
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
        if handler is None:
            return partial(self.on, event)
        self._listeners[event].add(handler)

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


# ─── Stage 1: Capstone pattern matching ──────────────────────────────────────


def find_stage1_capstone(buf: bytes, base_ea: int, is_64: bool):
    md = capstone.Cs(
        capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
    )
    md.detail = True
    instrs = list(md.disasm(buf, base_ea))

    # Conditional jump ↔ inverse
    COND_JUMPS = {
        capstone.x86.X86_INS_JA: capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_JNO: capstone.x86.X86_INS_JA,
        capstone.x86.X86_INS_JAE: capstone.x86.X86_INS_JB,
        capstone.x86.X86_INS_JB: capstone.x86.X86_INS_JAE,
        capstone.x86.X86_INS_JBE: capstone.x86.X86_INS_JA,
        capstone.x86.X86_INS_JA: capstone.x86.X86_INS_JBE,
        capstone.x86.X86_INS_JE: capstone.x86.X86_INS_JNE,
        capstone.x86.X86_INS_JNE: capstone.x86.X86_INS_JE,
        capstone.x86.X86_INS_JG: capstone.x86.X86_INS_JLE,
        capstone.x86.X86_INS_JLE: capstone.x86.X86_INS_JG,
        capstone.x86.X86_INS_JGE: capstone.x86.X86_INS_JL,
        capstone.x86.X86_INS_JL: capstone.x86.X86_INS_JGE,
        capstone.x86.X86_INS_JS: capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_JNS: capstone.x86.X86_INS_JS,
        capstone.x86.X86_INS_JP: capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_JNP: capstone.x86.X86_INS_JP,
    }

    # Allowed padding
    PADDING_IDS = {
        capstone.x86.X86_INS_ROL,
        capstone.x86.X86_INS_ROR,
        capstone.x86.X86_INS_RCL,
        capstone.x86.X86_INS_RCR,
        capstone.x86.X86_INS_SHL,
        capstone.x86.X86_INS_SHR,
        capstone.x86.X86_INS_XCHG,
        capstone.x86.X86_INS_MOV,
    }

    # Single-part prefix→jump map
    PREFIX_TO_JUMP = {
        capstone.x86.X86_INS_CLC: capstone.x86.X86_INS_JAE,
        capstone.x86.X86_INS_STC: capstone.x86.X86_INS_JBE,
        capstone.x86.X86_INS_TEST: capstone.x86.X86_INS_JNO,
    }

    chains = []

    # Multi-part
    for i, insn1 in enumerate(instrs):
        inv = COND_JUMPS.get(insn1.id)
        if not inv:
            continue
        for insn2 in instrs[i + 1 :]:
            if insn2.id in PADDING_IDS:
                continue
            if insn2.id == inv and insn2.size == insn1.size:
                s = insn1.address
                e = insn2.address + insn2.size
                chains.append(
                    MatchChain(
                        base_address=base_ea,
                        segments=[
                            MatchSegment(
                                start=s - base_ea,
                                length=e - s,
                                description="Multi-part CJ",
                                matched_bytes=buf[s - base_ea : e - base_ea],
                                segment_type=SegmentType.STAGE1_MULTIPLE,
                                matched_groups={
                                    "first_jump": insn1.bytes.hex(),
                                    "second_jump": insn2.bytes.hex(),
                                },
                            )
                        ],
                    )
                )
            break

    # Single-part
    for i, insn1 in enumerate(instrs):
        want = PREFIX_TO_JUMP.get(insn1.id)
        if not want:
            continue
        for insn2 in instrs[i + 1 :]:
            if insn2.id in PADDING_IDS:
                continue
            if insn2.id == want:
                s = insn1.address
                e = insn2.address + insn2.size
                chains.append(
                    MatchChain(
                        base_address=base_ea,
                        segments=[
                            MatchSegment(
                                start=s - base_ea,
                                length=e - s,
                                description="Single-part CJ",
                                matched_bytes=buf[s - base_ea : e - base_ea],
                                segment_type=SegmentType.STAGE1_SINGLE,
                                matched_groups={
                                    "prefix": insn1.bytes.hex(),
                                    "jump": insn2.bytes.hex(),
                                },
                            )
                        ],
                    )
                )
            break

    chains.sort(key=lambda c: c.overall_start())
    return chains


# ─── Stage 2: peel off junk via Capstone ────────────────────────────────────


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
            and insn.operands[0].type == insn.OP_IMM
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
        ) and any(op.type == insn.OP_IMM for op in insn.operands):
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


# ─── Stage 3: filter ────────────────────────────────────────────────────────


def stage3_filter(chains):
    return [
        c for c in chains if 12 <= c.overall_length() <= 129 and c.junk_length() > 0
    ]


# ─── Stage 4: jump-chain + big-instr + overlap ──────────────────────────────


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


# ─── Async event emitter & deobfuscator ───────────────────────────────────


@dataclass
class AsyncEventEmitter:
    def __post_init__(self):
        self._listeners = {}

    def on(self, event, handler):
        self._listeners.setdefault(event, []).append(handler)

    async def emit(self, event, *args):
        for h in self._listeners.get(event, []):
            res = h(*args)
            if asyncio.iscoroutine(res):
                await res


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
        workers = self.max_workers or multiprocessing.cpu_count() or 1
        ctx = get_context("spawn")
        self.executor = ProcessPoolExecutor(max_workers=workers, mp_context=ctx)

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

    async def stage1(self):
        await self.emit("stage1_started")
        async with self._get_buffer() as buf:
            loop = asyncio.get_running_loop()
            chains = await loop.run_in_executor(
                self.executor, find_stage1_capstone, buf, self.start_ea, self.is_64bit
            )
        await self.emit("stage1_finished", chains)
        return chains

    async def stage2(self, chains):
        await self.emit("stage2_started")
        async with self._get_buffer() as buf:
            loop = asyncio.get_running_loop()
            tasks = [
                loop.run_in_executor(
                    self.executor,
                    find_junk_stage2_chain,
                    c,
                    buf,
                    self.start_ea,
                    self.is_64bit,
                )
                for c in chains
            ]
            updated = await asyncio.gather(*tasks)
        await self.emit("stage2_finished", updated)
        return updated

    async def stage3(self, chains):
        await self.emit("stage3_started")
        filtered = stage3_filter(chains)
        await self.emit("stage3_finished", filtered)
        return filtered

    async def stage4(self, chains):
        await self.emit("stage4_started")
        async with self._get_buffer() as buf:
            base = self.start_ea
            block_end = base + self.data_size
            loop = asyncio.get_running_loop()

            async def validate_one(chain):
                exit_ea = await loop.run_in_executor(
                    self.executor,
                    follow_jump_chain,
                    buf,
                    base,
                    chain.overall_start(),
                    block_end,
                    self.is_64bit,
                )
                off = exit_ea - base - 6
                if off < 0:
                    return None
                bi = find_big_instruction(buf[off : off + 6], self.is_64bit)
                if not bi:
                    return None
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

            tasks = [
                loop.run_in_executor(self.executor, validate_one, c) for c in chains
            ]
            results = await asyncio.gather(*tasks)
        results = [c for c in results if c]
        final = resolve_overlaps(results)
        await self.emit("stage4_finished", final)
        return final

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


# ─── Standalone worker entrypoint ───────────────────────────────────────────


def worker_main():
    p = argparse.ArgumentParser()
    p.add_argument("--shm_name", required=True)
    p.add_argument("--data_size", type=int, required=True)
    p.add_argument("--start_ea", type=lambda x: int(x, 0), required=True)
    p.add_argument("--is64", type=int, default=1)
    args = p.parse_args()
    sys.stdout.write("worker_main ran baby!!!\n")
    sys.stdout.flush()

    deob = AsyncDeobfuscator(
        shm_name=args.shm_name,
        data_size=args.data_size,
        start_ea=args.start_ea,
        is_64bit=bool(args.is64),
    )

    # optional logging
    deob.on("run_started", lambda: print("▶️  Pipeline starting"))
    deob.on("stage1_finished", lambda ch: print(f"✅ Stage1: {len(ch)} stubs"))
    deob.on("stage2_finished", lambda ch: print(f"✅ Stage2: junk appended"))
    deob.on("stage3_finished", lambda ch: print(f"✅ Stage3: {len(ch)} remain"))
    deob.on("stage4_finished", lambda ch: print(f"✅ Stage4: {len(ch)} final"))
    deob.on("stopped", lambda: print("🛑 Worker shutting down"))

    results = asyncio.run(deob.run())
    out = [
        {
            "offset": c.overall_start() - args.start_ea,
            "length": c.overall_length(),
            "description": c.segments[0].description,
        }
        for c in results
    ]

    sys.stdout.write("results_start\n")
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.write("results_end\n")
    sys.stdout.flush()


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
            if self.state() == QtCore.QProcess.NotRunning:
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
            logger.info(f"Worker stdout: {out}")
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
                logger.warning(f"Worker stderr: {data}")

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
            logger.error(msg)
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

        @staticmethod
        def get_section_data(
            section_name: str,
            max_size: int = 40 * 1024 * 1024,
            min_size: int = 1024,
        ) -> tuple[int, bytes]:
            """Get the data of a section by name and return the start address and the bytes."""
            seg = ida_segment.get_segm_by_name(section_name)
            data_ea = seg.start_ea
            data_to_process_size = seg.end_ea - seg.start_ea
            # Cap size if needed, or handle very large sections
            if data_to_process_size > max_size:  # Limit demo to ~40MB
                data_to_process_size = max_size
                logger.warning(
                    f"Limiting demo data size to {data_to_process_size} bytes from {section_name}."
                )
            elif data_to_process_size < min_size:  # Don't bother with tiny sections
                logger.error(
                    f"{section_name} section is too small ({data_to_process_size} bytes) for demo."
                )
                return

            logger.info(
                f"Reading {data_to_process_size} bytes from address {hex(data_ea)}"
            )
            # Read the bytes from IDA
            data_bytes = ida_bytes.get_bytes(data_ea, data_to_process_size)

            if not data_bytes or len(data_bytes) != data_to_process_size:
                logger.error(
                    f"Failed to read {data_to_process_size} bytes from {hex(data_ea)}. Read {len(data_bytes) if data_bytes else 0} bytes."
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
                self._cleanup_shared_memory()
                if self.proc.is_not_running():
                    self.proc.stop_worker()
                self.proc = None
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

    class DataProcessorPlugin(idaapi.plugin_t):
        """
        IDA Pro plugin example demonstrating multiprocessing with a worker
        using shared memory for large data and QProcess pipes for signaling.
        """

        flags = idaapi.PLUGIN_PROC
        comment = "External data processing via Shared Memory and QProcess"
        help = "Press Alt-Shift-P to start data processing example"
        wanted_name = "DataProcessingExample"
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
