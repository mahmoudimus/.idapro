"""
Optimized Capstone-based instruction pattern detection for x86 obfuscation patterns.
Uses IDA's fast signature search to locate candidates, then verifies with Capstone.
Includes junk instruction filtering to reduce false positives.
"""

from __future__ import annotations

import collections
import dataclasses
import datetime
import enum
import functools
import json
import logging
import re
import sys  # For sys.exc_info()
import time
import traceback  # For formatting traceback
import typing
import weakref
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from PyQt5.QtCore import (
    QModelIndex,
    QObject,
    QRegularExpression,
    QRunnable,
    QSortFilterProxyModel,
    Qt,
    QThreadPool,
    QTimer,
    pyqtSignal,
)
from PyQt5.QtGui import QStandardItem, QStandardItemModel

# Qt imports
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

import ida_bytes

# IDA imports
import ida_kernwin
import ida_nalt
import ida_range
import ida_segment
import idaapi

import capstone

# ----------------------------------------------------------------------
# Toggle Capstone verification on/off (handy for profiling)
# ----------------------------------------------------------------------
USE_CAPSTONE = True  # ← flip to True to restore Capstone analysis
MAX_PATTERN_LEN = 129

# --- Pattern Detection Core Classes (must be defined first) ---


class PatternCategory(Enum):
    MULTI_PART = auto()
    SINGLE_PART = auto()
    JUNK = auto()


@dataclass
class JunkPatternMetadata:
    """Metadata for junk instruction patterns."""

    pattern: bytes  # The regex pattern as a bytes literal
    description: str = ""
    compiled: Optional[re.Pattern[bytes]] = None

    def compile(self, flags=0):
        """Compile the regex if not already done, and return the compiled object."""
        if self.compiled is None:
            self.compiled = re.compile(self.pattern, flags)
        return self.compiled


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
    def __init__(
        self,
        base_address: int,
        segments: typing.Optional[typing.List[MatchSegment]] = None,
    ):
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


@dataclass
class PatternMatch:
    """Represents a successful pattern match with detailed information."""

    category: PatternCategory
    description: str
    start_offset: int
    end_offset: int
    instructions: List[capstone.CsInsn]
    pattern_name: str
    ida_address: int = 0  # IDA virtual address
    junk_count: int = 0  # Number of junk instructions following the pattern
    total_length: int = 0  # Total length including junk instructions

    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern match to dictionary for JSON serialization."""
        # Convert capstone instructions to serializable format
        serialized_instructions = []
        for insn in self.instructions:
            serialized_instructions.append(
                {
                    "address": insn.address,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex(),
                    "size": insn.size,
                }
            )

        return {
            "category": self.category.name,
            "description": self.description,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "instructions": serialized_instructions,
            "pattern_name": self.pattern_name,
            "ida_address": self.ida_address,
            "junk_count": self.junk_count,
            "total_length": self.total_length,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PatternMatch":
        """Create pattern match from dictionary (JSON deserialization)."""
        # Note: We can't reconstruct the full capstone objects, so we create mock objects
        # with the essential information for display purposes
        mock_instructions = []
        for insn_data in data["instructions"]:
            # Create a simple mock instruction object
            mock_insn = type(
                "MockInstruction",
                (),
                {
                    "address": insn_data["address"],
                    "mnemonic": insn_data["mnemonic"],
                    "op_str": insn_data["op_str"],
                    "bytes": bytes.fromhex(insn_data["bytes"]),
                    "size": insn_data["size"],
                },
            )()
            mock_instructions.append(mock_insn)

        return cls(
            category=PatternCategory[data["category"]],
            description=data["description"],
            start_offset=data["start_offset"],
            end_offset=data["end_offset"],
            instructions=mock_instructions,
            pattern_name=data["pattern_name"],
            ida_address=data["ida_address"],
            junk_count=data.get("junk_count", 0),
            total_length=data.get("total_length", 0),
        )


@dataclass
class PatternDetector:
    """Base class for instruction pattern detection using Capstone."""

    cs: Optional[capstone.Cs] = field(default=None, init=False)

    def __post_init__(self):
        """Initialize capstone with detailed instruction information."""
        if USE_CAPSTONE:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.cs.detail = True


# --- Utility Classes ---


class UserCanceledError(Exception):
    pass


class CustomFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setSortRole(Qt.DisplayRole)  # Default, can be overridden by header click
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._category_filter_text = "All Categories"  # For category filtering

    def set_category_filter(self, category_text: str):
        self._category_filter_text = category_text
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        if not model:  # Ensure model is valid
            return True

        # Category filter
        if self._category_filter_text != "All Categories":
            category_index = model.index(
                source_row, 1, source_parent
            )  # Assuming Category is column 1
            category_data = model.data(category_index, Qt.DisplayRole)
            if category_data != self._category_filter_text.replace(
                "-", " "
            ):  # Match display format
                return False

        # Regex filter (original logic, slightly adapted)
        regex = self.filterRegularExpression()
        if not regex.isValid():
            # logging.debug('Invalid regex: %s', regex.pattern()) # Avoid too much logging
            return True
        if regex.pattern() == "":
            return True

        # Apply regex to user-defined columns or all if not specified (currently columns 0,2,3 as per original logic)
        # For this specific table: Address (0), Description (2), Pattern Name (3)
        # Note: Original proxy filtered 0..2, which was File, Library Name. Adjusting to current context.
        for column in [0, 2, 3]:
            index = model.index(source_row, column, source_parent)
            data = model.data(index, Qt.DisplayRole)
            if data is not None:
                data_str = str(data)
                if regex.match(data_str).hasMatch():
                    return True
        return False  # If regex is set and no column matched

    def lessThan(self, left, right):
        # left/right are QModelIndex from the source model
        col = left.column()
        ldata = self.sourceModel().data(left, Qt.UserRole)
        rdata = self.sourceModel().data(right, Qt.UserRole)

        # Columns for numeric sort: Address (0), Junk Count (5), Total Length (6)
        if col in [0, 5, 6]:
            if ldata is None and rdata is None:
                return False
            if ldata is None:
                return True  # None is less than something
            if rdata is None:
                return False  # Something is not less than None
            try:
                lvalue = int(ldata)  # Assuming UserRole stores convertible to int
                rvalue = int(rdata)
                return lvalue < rvalue
            except (ValueError, TypeError):
                # Fallback to string comparison if UserRole data isn't purely numeric as expected
                pass

        # Fallback to default DisplayRole string comparison for other columns or if UserRole fails
        # This uses the sourceModel's data directly for the comparison.
        ldata_display = self.sourceModel().data(left, Qt.DisplayRole)
        rdata_display = self.sourceModel().data(right, Qt.DisplayRole)
        if ldata_display is None and rdata_display is None:
            return False
        if ldata_display is None:
            return True
        if rdata_display is None:
            return False
        return str(ldata_display) < str(rdata_display)


class WorkerSignals(QObject):
    auto_started = pyqtSignal()
    auto_finished = (
        pyqtSignal()
    )  # Renamed from your 'finished' to avoid conflict if we use QThread's finished later
    error = pyqtSignal(tuple)  # (type, value, traceback_str)
    result = pyqtSignal(object, object, bool)  # result_data, aux_data, success_flag
    progress = pyqtSignal(int)  # percentage


def _analyze_chain(
    chain: MatchChain,
    mem: bytes,
    start_ea: int,
    is_x64: bool,
    max_size: int = MAX_PATTERN_LEN,
) -> list[Range]:
    """
    Filter out false positive anti-disassembly patterns and analyze jump chains.

    Args:
        chain: The MatchChain object representing the pattern and surrounding bytes.
        mem: Memory bytes of the relevant segment.
        start_ea: The starting effective address of the 'mem' bytes.
        is_x64: Boolean indicating if the architecture is x64.
        max_size: Maximum valid size for an anti-disassembly routine.

    Returns:
        A list of Range objects representing resolved code blocks stemming from the chain.
    """

    match_start = chain.overall_start()
    chain_end = match_start + max_size
    ranges = []

    logging.info("Analyzing match: %s @ 0x%X", chain.description, match_start)

    jump_analyzer = JumpTargetAnalyzer(
        chain.overall_matched_bytes(), match_start, chain_end, start_ea
    )
    jump_targets_iter = jump_analyzer.process(mem=mem, chain=chain, is_x64=is_x64)

    for target in jump_targets_iter:
        if target is None:
            logging.debug(
                "JumpTargetAnalyzer yielded None for chain @ 0x%X, skipping this target.",
                match_start,
            )
            continue
        if target <= match_start:
            logging.debug(
                "Invalid jump target 0x%X (<= match_start 0x%X) for chain. Skipping.",
                target,
                match_start,
            )
            continue

        logging.info(
            "Most likely target: 0x%X, analysis boundary: 0x%X", target, chain_end
        )
        ranges.append(Range(match_start, target))
    return ranges


class AnalysisTask(QRunnable):
    """
    A QRunnable task to analyze a single pattern match (pm) in a separate thread.
    """

    def __init__(
        self,
        pattern_detection_widget,
        pm,
        mem_start_ea,
        mem_bytes,
        matcher_instance,
        is_x64,
    ):
        super().__init__()
        self.pattern_detection_widget = pattern_detection_widget
        self.pm = pm
        self.mem_start_ea = mem_start_ea
        self.mem_bytes = mem_bytes
        self.matcher_instance = matcher_instance
        self.is_x64 = is_x64
        self.result_ranges = []
        self.error = None
        # Store ida_address for reliable logging, as pm object might have thread affinity issues
        # or its attributes might be accessed from a different thread context.
        self.pm_ida_address = pm.ida_address

    def run(self):
        """
        Executes the analysis task.
        This method is called when the task is run by a thread in the QThreadPool.
        """
        try:
            # Access _convert_pm_to_mchain from the passed PatternDetectionWidget instance
            mchain = self.pattern_detection_widget._convert_pm_to_mchain(
                self.pm, self.mem_start_ea, self.mem_bytes, self.matcher_instance
            )
            if not mchain:
                # Logging is expected to be handled within _convert_pm_to_mchain
                return

            logging.debug(
                "Threaded: Calling _analyze_chain for MatchChain at 0x%X (pm: 0x%X)",
                mchain.overall_start(),
                self.pm_ida_address,  # Use stored pm_ida_address
            )
            # _analyze_chain is assumed to be a global function or correctly imported/defined
            # to be accessible here. It should also be thread-safe.
            pm_ranges = _analyze_chain(
                mchain, self.mem_bytes, self.mem_start_ea, self.is_x64
            )
            self.result_ranges = pm_ranges
            logging.debug(
                "Threaded: _analyze_chain for 0x%X (pm: 0x%X) returned %d ranges.",
                mchain.overall_start(),
                self.pm_ida_address,  # Use stored pm_ida_address
                len(self.result_ranges),
            )
        except Exception as e:
            self.error = e
            logging.error(
                "Threaded: Error in AnalysisTask for pm at 0x%X: %s",
                self.pm_ida_address,  # Use stored pm_ida_address
                e,
                exc_info=True,
            )


class CapstoneAnalysisRunnable(QRunnable):
    def __init__(self, data_chunk, matcher):
        super().__init__()
        self.data_chunk = data_chunk
        self.matcher = matcher
        self.signals = WorkerSignals()

    def run(self):
        self.signals.auto_started.emit()
        try:
            chunk_matches = []
            items_processed_in_this_chunk = 0
            total_in_chunk = len(self.data_chunk)

            for i, (candidate_ea, region_bytes, base_address) in enumerate(
                self.data_chunk
            ):
                if self.matcher is None:
                    logging.error("CapstoneAnalysisRunnable: Matcher is None")
                    # Decide: emit error or just skip? For now, let it go to general exception
                    raise ValueError("Matcher is None in CapstoneAnalysisRunnable")

                matches = self.matcher.analyze_candidate_region_bytes(
                    region_bytes, base_address, candidate_ea
                )
                chunk_matches.extend(matches)
                items_processed_in_this_chunk += 1

                self.signals.progress.emit(1)
            self.signals.result.emit(chunk_matches, items_processed_in_this_chunk, True)
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            self.signals.error.emit(
                (exc_type.__name__ if exc_type else "Exception", str(exc_value), tb_str)
            )
            self.signals.result.emit(
                [], 0, False
            )  # Emit a dummy result indicating failure for this chunk
        finally:
            self.signals.auto_finished.emit()


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
        logging.info(
            "PatchManager initialized (dry_run=%s, mode=%s)",
            self.dry_run,
            self.patch_mode.name,
        )

    def add_patch(self, address: int, byte_values: bytes):
        """Creates and queues a DeferredPatchOp."""
        op = DeferredPatchOp(address, byte_values, self.patch_mode)
        self.pending_patches.append(op)
        logging.debug("Queued patch operation: %s", op)

    def apply_all(self, dry_run_override: bool | None = None) -> bool:
        """Applies all queued patch operations."""
        logging.info("Applying %d queued patches...", len(self))
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

        logging.info(
            "Patch application complete. Success: %d, Failed: %d",
            success_count,
            fail_count,
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
        logging.info(
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
            logging.error(f"Failed to apply patch {self}: {e}", exc_info=True)
            success = False
        return success

    def __str__(self):
        """String representation with hex formatting."""
        dry_run_str = " (dry run)" if self.dry_run else ""
        return f"{self.__class__.__name__}({len(self.byte_values)} bytes, mode={self.mode.name}{dry_run_str} @ address=0x{self.address:X})"

    __repr__ = __str__


@dataclasses.dataclass
class CodeRegionSlicer:
    """Handles slicing of code regions around a candidate address."""

    region_size_before: int
    region_size_after: int
    max_total_region_size: int

    _EMPTY_ITERATOR: Iterator[Tuple[int, bytes, int]] = dataclasses.field(
        default_factory=lambda: iter([]), init=False, repr=False
    )

    def __call__(
        self,
        segment_start_ea: int,
        segment_bytes: bytes,
        candidates: list[int],
        progress_callback: Callable[[int], None] | None = None,
    ) -> Iterator[Tuple[int, bytes, int]]:
        """
        Slices a region of bytes around the candidate_ea within the segment_bytes.

        Args:
            candidate_ea: The effective address of the candidate.
            segment_start_ea: The starting EA of the segment_bytes.
            segment_bytes: The byte content of the entire segment.
            candidates: A list of candidate effective addresses.
            progress_callback: A function to call with the index of the current candidate. If None, no progress will be reported. If callback returns False, the loop will be terminated.

        Returns:
            An iterator that yields tuples of (region_bytes_slice, slice_base_ea) for each candidate.
        """
        if not segment_bytes:
            logging.warning("Segment bytes are empty, cannot slice.")
            yield from self._EMPTY_ITERATOR

        for idx, candidate_ea in enumerate(candidates):
            region_bytes_slice, slice_base_ea = self.get_slice(
                candidate_ea, segment_start_ea, segment_bytes
            )
            if region_bytes_slice and slice_base_ea is not None:
                yield candidate_ea, region_bytes_slice, slice_base_ea
            if progress_callback and progress_callback(idx) is False:
                break

    def get_slice(
        self,
        candidate_ea: int,
        segment_start_ea: int,
        segment_bytes: bytes,
    ) -> Tuple[Optional[bytes], Optional[int]]:
        """
        Slices a region of bytes around the candidate_ea within the segment_bytes.

        Args:
            candidate_ea: The effective address of the candidate.
            segment_start_ea: The starting EA of the segment_bytes.
            segment_bytes: The byte content of the entire segment.

        Returns:
            A tuple containing:
            - region_bytes_slice: The sliced bytes, or None if slicing fails.
            - slice_base_ea: The base EA of the slice, or None if slicing fails.
        """
        if not segment_bytes:
            logging.warning("Segment bytes are empty, cannot slice.")
            return None, None

        candidate_offset_in_segment = candidate_ea - segment_start_ea
        if not (0 <= candidate_offset_in_segment < len(segment_bytes)):
            logging.warning(
                "Candidate EA 0x%x is outside the segment bounds (0x%x - 0x%x).",
                candidate_ea,
                segment_start_ea,
                segment_start_ea + len(segment_bytes) - 1,
            )
            return None, None

        slice_start_offset = max(
            0, candidate_offset_in_segment - self.region_size_before
        )
        slice_end_offset = min(
            len(segment_bytes),
            candidate_offset_in_segment + self.region_size_after,
        )

        current_slice_len = slice_end_offset - slice_start_offset
        if current_slice_len <= 0:  # Ensure slice has positive length
            logging.warning(
                "Calculated slice for candidate 0x%x has zero or negative length (%d:%d).",
                candidate_ea,
                slice_start_offset,
                slice_end_offset,
            )
            return None, None

        if current_slice_len > self.max_total_region_size:
            excess = current_slice_len - self.max_total_region_size
            shrink_before = excess // 2
            shrink_after = excess - shrink_before

            temp_slice_start = slice_start_offset + shrink_before
            temp_slice_end = slice_end_offset - shrink_after

            # Adjust if candidate is pushed out of bounds by shrinking
            if candidate_offset_in_segment < temp_slice_start:
                # Candidate is before the adjusted start, anchor start to candidate
                temp_slice_start = candidate_offset_in_segment
                temp_slice_end = temp_slice_start + self.max_total_region_size
            elif candidate_offset_in_segment >= temp_slice_end:
                # Candidate is at or after the adjusted end, anchor end to candidate + 1
                temp_slice_end = (
                    candidate_offset_in_segment + 1
                )  # Slice end is exclusive
                temp_slice_start = temp_slice_end - self.max_total_region_size

            slice_start_offset = max(0, temp_slice_start)
            slice_end_offset = min(len(segment_bytes), temp_slice_end)

            # Final check for positive length after adjustments
            if slice_end_offset <= slice_start_offset:
                logging.warning(
                    "Adjusted slice for candidate 0x%x has zero or negative length (%d:%d) after max_total_region_size constraint.",
                    candidate_ea,
                    slice_start_offset,
                    slice_end_offset,
                )
                return None, None

        region_bytes_slice = segment_bytes[slice_start_offset:slice_end_offset]
        slice_base_ea = segment_start_ea + slice_start_offset

        if (
            not region_bytes_slice
        ):  # Should be caught by length checks, but as a safeguard
            logging.warning(
                "Empty byte slice for candidate at 0x%x (offset %d, slice %d:%d in segment) despite positive length assertion.",
                candidate_ea,
                candidate_offset_in_segment,
                slice_start_offset,
                slice_end_offset,
            )
            return None, None

        return region_bytes_slice, slice_base_ea


@dataclass
class CheckContinuePrompt:
    """Decorator that checks if user wants to continue after elapsed time.

    Args:
        metadata: Dictionary containing metadata to format into the prompt message
        cancel_func: Function to call if user cancels
        enable_prompt: Whether to enable the continue prompt
        start_time: Optional start time, will be initialized if None
        prompt_interval: Initial time before first prompt in seconds
        logger: Optional logger instance
    """

    metadata: dict | None = None
    cancel_func: Callable[[], None] | None = None
    enable_prompt: bool = True
    start_time: float = 0.0
    prompt_interval: int = 120
    logger: logging.Logger | None = None

    def __post_init__(self):
        current_time = time.time()
        self.start_time = current_time if self.start_time == 0.0 else self.start_time
        self.next_prompt_time = self.start_time + self.prompt_interval

    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time

    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.enable_prompt:
                return func(*args, **kwargs)

            if self.elapsed_time < self.next_prompt_time:
                return func(*args, **kwargs)

            minutes = int(self.elapsed_time / 60)
            seconds = int(self.elapsed_time % 60)
            time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

            # Format metadata into message
            message = f"{func.__name__} has been running for {time_str}.\n\n"
            if self.metadata:
                for key, value in self.metadata.items():
                    message += f"{key}: {value}\n"
            message += "\nContinue?"

            reply = QMessageBox.question(
                self,
                "Continue execution?",
                message,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )

            if reply == QMessageBox.No:
                if self.cancel_func:
                    return self.cancel_func()
                raise UserCanceledError("User canceled")

            self.next_prompt_time *= 2
            if self.logger is not None:
                self.logger.info(
                    "Next prompt will be at %d seconds (%.1f minutes)",
                    self.next_prompt_time,
                    self.next_prompt_time / 60.0,
                )
            return func(*args, **kwargs)

        return wrapper


class PatternDetectionWidget(QWidget):
    """Main dialog for pattern detection with progress tracking and results display."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Obfuscation Pattern Detection")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.matcher = None  # Will be set to FastPatternMatcher when needed
        self.all_patterns = []
        self.start_time = None
        self.next_prompt_time = 120
        self.enable_continue_prompt = False
        self.text_segment_bytes: Optional[bytes] = None
        self.text_segment_start_ea: int = 0

        # Initialize the code slicer
        self.code_slicer = CodeRegionSlicer(
            region_size_before=0,
            region_size_after=MAX_PATTERN_LEN,
            max_total_region_size=MAX_PATTERN_LEN,
        )

        # Thread pool for Capstone analysis
        self.thread_pool = QThreadPool.globalInstance()
        self.thread_pool.setMaxThreadCount(
            QThreadPool.globalInstance().maxThreadCount() // 2 or 1
        )  # Use half avail cores
        self.active_runnables = 0
        self.collected_matches_from_runnables = []
        self.total_items_for_analysis = (
            0  # Total candidate data points for analysis phase
        )
        self.items_processed_count = 0  # Count of items processed in analysis phase

        self.candidates = []
        self.current_candidate_idx = 0
        self.candidates_data = []  # For worker thread

        self.ui_update_timer = QTimer(self)  # Timer for updating elapsed time

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Control section
        control_group = QGroupBox("Detection Control")
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Detection")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)

        # Save/Load buttons
        self.save_btn = QPushButton("Save Results")
        self.load_btn = QPushButton("Load Results")
        self.export_csv_btn = QPushButton("Export CSV")
        self.clear_btn = QPushButton("Clear Results")
        self.save_btn.setEnabled(False)  # Enabled when patterns are found
        self.export_csv_btn.setEnabled(False)  # Enabled when patterns are found
        self.clear_btn.setEnabled(False)  # Enabled when patterns are found

        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.cancel_btn)
        control_layout.addWidget(QLabel("|"))  # Separator
        control_layout.addWidget(self.save_btn)
        control_layout.addWidget(self.load_btn)
        control_layout.addWidget(self.export_csv_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()
        control_group.setLayout(control_layout)
        # let the control row fill the full width
        control_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_label = QLabel("Ready to start detection...")
        self.time_label = QLabel("Elapsed: 0s")

        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.time_label)
        progress_group.setLayout(progress_layout)
        # let the progress row fill the full width
        progress_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Results section
        results_group = QGroupBox("Detection Results")
        results_layout = QVBoxLayout()

        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Search patterns...")
        filter_layout.addWidget(self.filter_input)

        self.category_filter = QComboBox()
        self.category_filter.addItems(
            ["All Categories", "Multi-Part", "Single-Part", "Junk"]
        )
        filter_layout.addWidget(self.category_filter)

        self.clear_filter_btn = QPushButton("Clear")
        filter_layout.addWidget(self.clear_filter_btn)

        results_layout.addLayout(filter_layout)

        # Results table -> TreeView
        self.results_tree_view = QTreeView()
        # make the tree view expand when its container resizes
        self.results_tree_view.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.results_tree_view.setAlternatingRowColors(True)
        self.results_tree_view.setSortingEnabled(True)
        self.results_tree_view.setRootIsDecorated(False)  # For a flat list look
        self.results_tree_view.setEditTriggers(QTreeView.NoEditTriggers)  # Read-only

        self.source_model = QStandardItemModel(0, 7)  # 0 rows, 7 columns
        self.source_model.setHorizontalHeaderLabels(
            [
                "Address",
                "Category",
                "Description",
                "Pattern Name",
                "Instructions",
                "Junk Count",
                "Total Length",
            ]
        )

        # Parent `self` for QObject management
        self.proxy_model = CustomFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.source_model)
        self.results_tree_view.setModel(self.proxy_model)

        header = self.results_tree_view.header()
        # allow the user to drag‐resize any column, and even reorder them
        header.setSectionsClickable(True)
        header.setSectionsMovable(True)
        # default to Interactive so users can drag edges
        header.setSectionResizeMode(QHeaderView.Interactive)
        # for col in range(7):
        #     header.setSectionResizeMode(col, QHeaderView.Stretch)
        # # ensure the very last section also expands into any leftover pixels
        last = header.model().columnCount() - 1
        header.setSectionResizeMode(last, QHeaderView.Stretch)
        # header.setStretchLastSection(True)

        results_layout.addWidget(self.results_tree_view)

        # Summary
        self.summary_label = QLabel("No patterns detected yet.")
        results_layout.addWidget(self.summary_label)

        results_group.setLayout(results_layout)
        # let the results section fill width & height
        results_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Layout assembly
        splitter = QSplitter(Qt.Vertical)

        top_widget = QWidget()
        top_layout = QVBoxLayout()
        top_layout.addWidget(control_group)
        top_layout.addWidget(progress_group)
        top_widget.setLayout(top_layout)
        # container for control+progress should also expand horizontally
        top_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        splitter.addWidget(top_widget)
        splitter.addWidget(results_group)
        splitter.setSizes([200, 400])  # Give more space to results
        # give the splitter all excess space (stretch=1)
        layout.addWidget(splitter, 1)

        # and make the splitter itself expand in both directions
        splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setLayout(layout)

    def _connect_signals(self):
        """Connect UI signals."""
        self.start_btn.clicked.connect(
            lambda: self.start_detection(ida_range.range_t(0x180001000, 0x18000191C))
        )
        self.cancel_btn.clicked.connect(self.cancel_detection)
        self.filter_input.textChanged.connect(self.apply_filters)
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        self.clear_filter_btn.clicked.connect(self.clear_filters)
        self.results_tree_view.doubleClicked.connect(self.goto_pattern_tree_item)

        # Connect Save/Load/Export/Clear buttons
        self.save_btn.clicked.connect(self.save_results)
        self.load_btn.clicked.connect(self.load_results)
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.clear_btn.clicked.connect(self.clear_results)

        self.ui_update_timer.timeout.connect(self._update_runtime_display)

    def _update_runtime_display(self):
        """Periodically updates the elapsed time label."""
        if self.start_time is not None and (
            self.cancel_btn.isEnabled() or not self.start_btn.isEnabled()
        ):  # Only update if running
            elapsed_time = time.time() - self.start_time
            minutes = int(elapsed_time / 60)
            seconds = int(elapsed_time % 60)
            time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
            self.time_label.setText(f"Elapsed: {time_str}")
        # else:
        # If start_time is None or detection not active, could clear or set to "Elapsed: 0s"
        # self.time_label.setText("Elapsed: 0s") # Or keep last value if preferred
        QApplication.processEvents()  # Ensure UI events are processed

    def start_detection(self, segm_range: ida_range.range_t | None = None):
        """Start pattern detection on main thread."""
        try:
            if not self.matcher:
                self.matcher = FastPatternMatcher()

            if segm_range is None:
                segm_range = ida_segment.get_segm_by_name(".text")
                if not segm_range:
                    self.handle_error("Could not find .text segment")
                    return

            self.text_segment_start_ea = segm_range.start_ea
            try:
                self.text_segment_bytes = ida_bytes.get_bytes(
                    self.text_segment_start_ea, segm_range.size()
                )
                if not self.text_segment_bytes:
                    self.handle_error("Failed to read bytes!")
                    return
                logging.info(
                    "Successfully read %d bytes from range (0x%x - 0x%x)",
                    len(self.text_segment_bytes),
                    segm_range.start_ea,
                    segm_range.end_ea,
                )
            except Exception as e:
                self.handle_error(f"Error reading .text segment: {e}")
                return

            self.start_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.progress_bar.setValue(0)
            self.all_patterns.clear()
            self.source_model.removeRows(0, self.source_model.rowCount())
            self.time_label.setText("Elapsed: 0s")  # Reset display at start
            self.ui_update_timer.start(
                1000
            )  # Start UI update timer (1 second interval)

            self.progress_label.setText("Searching for pattern candidates...")

            self.candidates = self.matcher.find_pattern_candidates(
                segm_range.start_ea, segm_range.end_ea
            )
            logging.info("Found %d potential pattern candidates", len(self.candidates))

            if not self.candidates:
                self.detection_finished([])
                return

            self.progress_bar.setValue(10)
            self.progress_label.setText("Preparing candidate data...")

            # Phase 2: Prepare all candidate data in a single step
            self.candidates_data = []
            total_candidates = len(self.candidates)

            @CheckContinuePrompt(
                metadata={"Total Candidates": total_candidates},
                cancel_func=self.cancel_detection,
                enable_prompt=self.enable_continue_prompt,
                logger=logging.getLogger(),
            )
            def progress_callback(idx: int):
                if self.cancel_btn.isEnabled() == False:  # Check if cancelled
                    logging.info("Data preparation cancelled.")
                    self.detection_finished([])  # Or handle cancellation more formally
                    return False

                # Update progress for data preparation (10% to 50% range)
                if total_candidates > 0 and (
                    idx % (total_candidates // 100 + 1) == 0
                    or idx == total_candidates - 1
                ):  # Update roughly 100 times or at the end
                    progress = int(10 + (idx / total_candidates) * 40)
                    self.progress_bar.setValue(progress)
                    self.progress_label.setText(
                        f"Preparing data for candidate {idx + 1}/{total_candidates}"
                    )

            for code_slice in self.code_slicer(
                self.text_segment_start_ea,
                self.text_segment_bytes,
                self.candidates,
                progress_callback,
            ):
                self.candidates_data.append(code_slice)

            # for idx, candidate_ea in enumerate(self.candidates):

            #     if self.code_slicer and self.text_segment_bytes is not None:
            #         region_bytes_slice, slice_base_ea = self.code_slicer.get_slice(
            #             candidate_ea,
            #             self.text_segment_start_ea,
            #             self.text_segment_bytes,
            #         )

            #         if region_bytes_slice and slice_base_ea is not None:
            #             self.candidates_data.append(
            #                 (candidate_ea, region_bytes_slice, slice_base_ea)
            #             )
            #         else:
            #             # Logging is handled within get_slice
            #             pass  # Continue to next candidate
            #     else:
            #         logging.error(
            #             "Code slicer or text_segment_bytes not initialized. Skipping candidate 0x%x",
            #             candidate_ea,
            #         )
            #         continue

            #     # Update progress for data preparation (10% to 50% range)
            #     if total_candidates > 0 and (
            #         idx % (total_candidates // 100 + 1) == 0
            #         or idx == total_candidates - 1
            #     ):  # Update roughly 100 times or at the end
            #         progress = int(10 + (idx / total_candidates) * 40)
            #         self.progress_bar.setValue(progress)
            #         self.progress_label.setText(
            #             f"Preparing data for candidate {idx + 1}/{total_candidates}"
            #         )

            #     # Check for user prompt to continue (if enabled and time elapsed)
            #     if self.start_time is not None and self.enable_continue_prompt:
            #         elapsed_time = time.time() - self.start_time
            #         if elapsed_time >= self.next_prompt_time:
            #             minutes = int(elapsed_time / 60)
            #             seconds = int(elapsed_time % 60)
            #             time_str = (
            #                 f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
            #             )
            #             reply = QMessageBox.question(
            #                 self,
            #                 "Continue Detection?",
            #                 f"Data preparation phase is processing {total_candidates} candidates.\nContinue?",
            #                 QMessageBox.Yes | QMessageBox.No,
            #                 QMessageBox.No,
            #             )
            #             if reply == QMessageBox.No:
            #                 self.cancel_detection()  # This will set cancel_btn state
            #                 return
            #             else:
            #                 self.next_prompt_time *= 2  # Postpone next prompt
            #                 logging.info(
            #                     "Next prompt will be at %d seconds (%.1f minutes)",
            #                     self.next_prompt_time,
            #                     self.next_prompt_time / 60.0,
            #                 )
            #                 # No timer to restart, loop continues

            if (
                not self.cancel_btn.isEnabled()
            ):  # Check if cancel was pressed during the loop
                logging.info("Detection cancelled during data preparation.")
                # self.detection_finished([]) # cancel_detection already handles this
                return

            if not self.candidates_data:
                logging.info("No valid candidate data prepared.")
                self.detection_finished([])
                return

            self.progress_bar.setValue(50)  # Mark data preparation as complete
            self.start_analysis_phase()  # Proceed to analysis

        except Exception as e:
            self.handle_error(str(e))

    def start_analysis_phase(self):
        """Start the Capstone analysis phase using a thread pool."""
        if not self.candidates_data:
            logging.info("No candidate data to analyze.")
            self.detection_finished([])
            return

        self.progress_label.setText(
            f"Starting Capstone analysis for {len(self.candidates_data)} data points..."
        )
        self.progress_bar.setValue(50)
        self.active_runnables = 0
        self.collected_matches_from_runnables = []
        self.total_items_for_analysis = len(self.candidates_data)
        self.items_processed_count = 0

        if self.matcher is None:
            self.handle_error("Matcher not initialized before analysis phase.")
            return

        # Determine number of chunks/runnables
        num_threads = self.thread_pool.maxThreadCount()
        chunk_size = (
            len(self.candidates_data) + num_threads - 1
        ) // num_threads  # Ceiling division
        chunk_size = max(1, chunk_size)  # Ensure chunk_size is at least 1

        for i in range(0, len(self.candidates_data), chunk_size):
            data_chunk = self.candidates_data[i : i + chunk_size]
            if not data_chunk:
                continue

            runnable = CapstoneAnalysisRunnable(data_chunk, self.matcher)
            # Connect to new signals
            runnable.signals.result.connect(self._handle_runnable_result)
            runnable.signals.error.connect(self._handle_runnable_error)
            runnable.signals.auto_finished.connect(self._handle_runnable_finished)
            runnable.signals.auto_started.connect(
                self._handle_runnable_started
            )  # Connect new signal
            runnable.signals.progress.connect(
                self._handle_runnable_progress
            )  # Connect new signal
            # We can connect auto_started and progress if needed for more detailed UI updates

            self.active_runnables += 1
            self.thread_pool.start(runnable)
            logging.info(
                "Started CapstoneAnalysisRunnable for %d items", len(data_chunk)
            )

        if (
            self.active_runnables == 0
        ):  # Should not happen if candidates_data is not empty
            logging.info("No runnables started, finishing detection.")
            self.detection_finished([])

    def _handle_runnable_started(self):
        """Slot to handle the auto_started signal from a CapstoneAnalysisRunnable."""
        logging.debug("A CapstoneAnalysisRunnable has started.")
        # You could update a status label here if desired, e.g.,
        # self.progress_label.setText("Analysis worker started...")
        # but be cautious about overwriting overall progress information.

    def _handle_runnable_progress(self, item_processed: int):
        """Slot to handle the progress signal from a CapstoneAnalysisRunnable."""
        logging.debug(f"Received chunk-local progress: {item_processed}%")
        # Update the label to show ongoing activity within a chunk.
        # This assumes self.items_processed_count is up-to-date from completed chunks.
        self.items_processed_count += item_processed
        if (
            self.total_items_for_analysis > 0
            and self.items_processed_count < self.total_items_for_analysis
        ):
            base_text = f"Analyzing... {self.items_processed_count}/{self.total_items_for_analysis} processed."
            # Calculate progress for the analysis phase (50% to 100% of total bar)
            # analysis_phase_percentage_float is 0-100 for the analysis work itself
            analysis_phase_percentage_float = (
                float(self.items_processed_count) / self.total_items_for_analysis
            ) * 100.0

            # This percentage maps to the 50-100 part of the progress bar
            # So, it contributes analysis_phase_percentage_float / 2.0 to the value above 50.
            progress_bar_increment = analysis_phase_percentage_float / 2.0
            new_progress_value = 50 + int(
                progress_bar_increment
            )  # int() here, after division by 2.0
            self.progress_bar.setValue(min(100, new_progress_value))
            self.progress_label.setText(
                f"{base_text} (Processed: {round(analysis_phase_percentage_float, 2)}%)"
            )
            # logging.debug(
            #     "_handle_runnable_result: Updated self.items_processed_count to %d. Progress bar set to %d%%. Label: %s",
            #     self.items_processed_count,
            #     new_progress_value,
            #     self.progress_label.text(),
            # )

    def _handle_runnable_result(
        self,
        found_matches: List[PatternMatch],
        items_processed_in_chunk: int,
        success: bool,
    ):
        """Slot to handle the result signal from a CapstoneAnalysisRunnable."""
        logging.debug(
            "_handle_runnable_result CALLED. Success: %s, Items in chunk: %d, Current total processed: %d / %d",
            success,
            items_processed_in_chunk,
            self.items_processed_count,
            self.total_items_for_analysis,
        )

        if success:
            self.collected_matches_from_runnables.extend(found_matches)
            if self.total_items_for_analysis < 0:
                # Fallback if total_items_for_analysis is 0, though should not happen if processing items.
                self.progress_bar.setValue(self.progress_bar.value() + 1)
        else:
            logging.warning(
                "A CapstoneAnalysisRunnable reported failure via result signal. Items reported by this chunk: %d",
                items_processed_in_chunk,
            )

    def _handle_runnable_finished(self):
        """Slot to handle the auto_finished signal from a CapstoneAnalysisRunnable."""
        self.active_runnables -= 1
        logging.debug(
            "_handle_runnable_finished: Active runnables now %d", self.active_runnables
        )
        if self.active_runnables == 0:
            self._check_all_runnables_finished()

    def _check_all_runnables_finished(self):
        """Called when all runnables have reported completion via auto_finished."""
        logging.info(
            "All CapstoneAnalysisRunnables finished. Total matches collected: %d",
            len(self.collected_matches_from_runnables),
        )

        # Remove duplicates from all collected matches
        unique_matches = []
        seen_addresses = set()
        for match in self.collected_matches_from_runnables:
            if match.ida_address not in seen_addresses:
                unique_matches.append(match)
                seen_addresses.add(match.ida_address)

        self.analysis_finished(unique_matches)  # Call the original analysis_finished

    def cancel_detection(self):
        """Cancel ongoing detection."""
        self.ui_update_timer.stop()  # Stop UI update timer
        self.thread_pool.clear()
        self.thread_pool.waitForDone(
            -1
        )  # Wait for active runnables to finish (or timeout)
        # Note: waitForDone does not interrupt running QRunnables.
        # True cancellation would require runnables to periodically check a flag.
        # For now, we let them finish their current small chunk.
        self.active_runnables = 0
        # When cancelling, ensure we call detection_finished with empty list or current if partial results are okay
        # For a clean cancel, pass empty.
        self.progress_label.setText("Detection cancelled.")
        self.progress_bar.setValue(
            0
        )  # Or 100 if treating cancel as "completion" of cancel op
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.update_buttons_state()  # Reflect that no patterns might be available if cleared
        # self.detection_finished([]) # This was the original line, let's ensure state is consistent

    def _prepare_analysis_dependencies(
        self,
    ) -> Optional[Tuple[capstone.Cs, bool, bytes, int, FastPatternMatcher]]:
        """Checks and prepares dependencies for the analysis phase, including the matcher itself."""
        if (
            self.matcher is None
            or self.matcher.detector is None
            or self.matcher.detector.cs is None
        ):
            logging.error(
                "Matcher or its Capstone instance not available. Cannot proceed with detailed analysis."
            )
            return None

        if self.text_segment_bytes is None:
            logging.error(
                ".text segment bytes not available. Cannot proceed with detailed analysis."
            )
            return None

        cs_instance = self.matcher.detector.cs
        is_x64 = cs_instance.mode == capstone.CS_MODE_64
        mem_bytes = self.text_segment_bytes
        mem_start_ea = self.text_segment_start_ea
        return (
            cs_instance,
            is_x64,
            mem_bytes,
            mem_start_ea,
            self.matcher,
        )  # Add matcher to returned tuple

    def _convert_pm_to_mchain(
        self,
        pm: PatternMatch,
        mem_start_ea: int,
        mem_bytes: bytes,
        matcher: FastPatternMatcher,
    ) -> Optional[MatchChain]:
        """Converts a PatternMatch object to a MatchChain for _analyze_chain."""
        if pm.category == PatternCategory.JUNK:
            logging.debug(
                "Skipping JUNK pattern at 0x%X for MatchChain conversion.",
                pm.ida_address,
            )
            return None

        current_segment_type: Optional[SegmentType] = None
        if pm.category == PatternCategory.MULTI_PART:
            current_segment_type = SegmentType.STAGE1_MULTIPLE
        elif pm.category == PatternCategory.SINGLE_PART:
            current_segment_type = SegmentType.STAGE1_SINGLE
        else:
            logging.warning(
                "Unknown pattern category %s for pm at 0x%X. Skipping MatchChain conversion.",
                pm.category,
                pm.ida_address,
            )
            return None

        if not pm.instructions:
            logging.warning(
                "PatternMatch at 0x%X has no instructions. Skipping MatchChain conversion.",
                pm.ida_address,
            )
            return None

        chain_instructions = pm.instructions
        chain_start_addr = chain_instructions[0].address
        chain_end_addr = chain_instructions[-1].address + chain_instructions[-1].size
        chain_len = chain_end_addr - chain_start_addr

        if chain_len <= 0:
            logging.warning(
                "PatternMatch at 0x%X has non-positive length (%d). Skipping MatchChain conversion.",
                pm.ida_address,
                chain_len,
            )
            return None

        chain_offset_in_mem = chain_start_addr - mem_start_ea
        if not (
            0 <= chain_offset_in_mem < len(mem_bytes)
            and 0 <= chain_offset_in_mem + chain_len <= len(mem_bytes)
        ):
            logging.error(
                "PatternMatch at 0x%X (len %d) is out of text segment bounds (offset %d, mem len %d). Skipping MatchChain conversion.",
                chain_start_addr,
                chain_len,
                chain_offset_in_mem,
                len(mem_bytes),
            )
            return None

        chain_actual_bytes = mem_bytes[
            chain_offset_in_mem : chain_offset_in_mem + chain_len
        ]

        seg_groups = {}
        if current_segment_type == SegmentType.STAGE1_SINGLE:
            jump_insn = None
            for insn in reversed(chain_instructions):  # Search from end
                if matcher._is_conditional_jump(
                    insn
                ):  # Use existing helper from FastPatternMatcher
                    jump_insn = insn
                    break
            if jump_insn:
                jump_offset_in_segment = jump_insn.address - chain_start_addr
                seg_groups = {
                    "jump_bytes": jump_insn.bytes,
                    "jump_offset_in_segment": jump_offset_in_segment,
                }
                logging.debug(
                    "For SINGLE_PART pm at 0x%X, found jump_insn: %s %s, bytes: %s, offset_in_segment: %d",
                    pm.ida_address,
                    jump_insn.mnemonic,
                    jump_insn.op_str,
                    jump_insn.bytes.hex(),
                    jump_offset_in_segment,
                )
            else:
                logging.warning(
                    "Could not find jump instruction in SINGLE_PART PatternMatch at 0x%X. Matched_groups will be empty for MatchChain.",
                    pm.ida_address,
                )

        current_segment = MatchSegment(
            start=0,  # Relative to MatchChain's base_address
            length=chain_len,
            description=pm.description,
            matched_bytes=chain_actual_bytes,
            segment_type=current_segment_type,
            matched_groups=seg_groups,
        )
        return MatchChain(base_address=chain_start_addr, segments=[current_segment])

    def _create_pm_from_resolved_range(
        self,
        resolved_range: Range,
        cs_instance: capstone.Cs,
        mem_start_ea: int,
        mem_bytes: bytes,
    ) -> Optional[PatternMatch]:
        """Creates a PatternMatch object from a resolved Range."""
        range_start_ea = resolved_range.start
        range_len = len(resolved_range)

        range_offset_in_mem = range_start_ea - mem_start_ea
        if not (
            0 <= range_offset_in_mem < len(mem_bytes)
            and 0 <= range_offset_in_mem + range_len <= len(mem_bytes)
        ):
            logging.error(
                "Resolved range 0x%X (len %d) is out of text segment bounds (offset %d, mem len %d). Skipping PatternMatch creation.",
                range_start_ea,
                range_len,
                range_offset_in_mem,
                len(mem_bytes),
            )
            return None

        range_bytes_data = mem_bytes[
            range_offset_in_mem : range_offset_in_mem + range_len
        ]
        range_instructions = (
            list(cs_instance.disasm(range_bytes_data, range_start_ea))
            if cs_instance
            else []
        )

        return PatternMatch(
            category=PatternCategory.SINGLE_PART,  # Generic category for resolved blocks
            description=f"Resolved Block: 0x{range_start_ea:X} - 0x{resolved_range.end:X}",
            start_offset=0,  # Relative to ida_address of this new PM
            end_offset=range_len,  # Relative to ida_address
            instructions=range_instructions,
            pattern_name="ResolvedBlock",
            ida_address=range_start_ea,
            junk_count=0,  # Junk count is not determined by this process
            total_length=range_len,
        )

    def analysis_finished(self, unique_matches: List[PatternMatch]):
        """Handle analysis completion by processing matches, resolving chains and overlaps."""
        logging.info(
            "Analysis finished. Received %d unique matches for further processing.",
            len(unique_matches),
        )

        analysis_deps = self._prepare_analysis_dependencies()
        if not analysis_deps:
            # Fallback to showing original matches if critical dependencies are missing
            self.all_patterns = unique_matches
            self._populate_model_from_patterns()
            self.detection_finished(self.all_patterns)  # Pass original patterns
            self.update_buttons_state()
            return

        cs_instance, is_x64, mem_bytes, mem_start_ea, matcher_instance = (
            analysis_deps  # Unpack matcher_instance
        )

        all_resolved_ranges: List[Range] = []
        logging.info("Starting chain analysis for non-junk patterns.")

        thread_pool = QThreadPool.globalInstance()
        active_tasks = []
        logging.info(
            "Submitting %d analysis tasks to the thread pool.", len(unique_matches)
        )

        for pm in unique_matches:
            task = AnalysisTask(
                self, pm, mem_start_ea, mem_bytes, matcher_instance, is_x64
            )
            active_tasks.append(task)
            thread_pool.start(task)

        logging.debug(
            "All %d tasks submitted. Waiting for completion...", len(active_tasks)
        )
        thread_pool.waitForDone()  # Blocks until all submitted tasks are finished

        logging.debug("All tasks completed. Collecting results...")

        for i, task in enumerate(active_tasks):
            if task.error:
                logging.warning(
                    "Task %d for pm at 0x%X (originally 0x%X) encountered an error: %s. Skipping its results.",
                    i + 1,  # 1-indexed task number
                    task.pm_ida_address,
                    task.pm.ida_address,  # In case pm_ida_address differs or for more info
                    task.error,
                )
            else:
                if task.result_ranges:  # Only extend if there are ranges
                    all_resolved_ranges.extend(task.result_ranges)
                    logging.debug(
                        "Task %d for pm at 0x%X (originally 0x%X) completed, contributing %d ranges.",
                        i + 1,
                        task.pm_ida_address,
                        task.pm.ida_address,
                        len(task.result_ranges),
                    )
                else:
                    logging.debug(
                        "Task %d for pm at 0x%X (originally 0x%X) completed with no ranges.",
                        i + 1,
                        task.pm_ida_address,
                        task.pm.ida_address,
                    )

        logging.info(
            "Chain analysis complete. Total resolved ranges before overlap removal: %d",
            len(all_resolved_ranges),
        )

        # resolve_overlaps is a global function
        final_interval_set = resolve_overlaps(all_resolved_ranges)
        logging.info(
            "Overlap resolution complete. Final intervals in set: %d",
            len(final_interval_set),
        )
        patch_manager = PatchManager()
        processed_patterns_for_display: List[PatternMatch] = []
        if final_interval_set:
            for resolved_range in final_interval_set:
                s, e = resolved_range.start, resolved_range.end
                patch_manager.add_patch(s, b"\x90" * (e - s))
                new_pm = self._create_pm_from_resolved_range(
                    resolved_range, cs_instance, mem_start_ea, mem_bytes
                )
                if new_pm:
                    processed_patterns_for_display.append(new_pm)
        logging.info(
            "Analysis completed. Found {} patch operations.".format(len(patch_manager))
        )
        patch_manager.apply_all()
        logging.info(
            "Converted %d final intervals to PatternMatch objects for display.",
            len(processed_patterns_for_display),
        )

        self.all_patterns = processed_patterns_for_display
        self._populate_model_from_patterns()
        self.detection_finished(self.all_patterns)
        self.update_buttons_state()

    def add_pattern_to_results(self, pattern: PatternMatch):
        """Add a newly found pattern to the results table."""
        if pattern not in self.all_patterns:
            self.all_patterns.append(pattern)
            self._populate_model_from_patterns()
            self.update_buttons_state()

    def detection_finished(self, patterns: List[PatternMatch]):
        """Handle detection completion."""
        self.ui_update_timer.stop()  # Stop UI update timer
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(100)

        if patterns:
            self.progress_label.setText(
                f"Detection complete! Found {len(patterns)} unique patterns."
            )
        else:
            self.progress_label.setText("Detection complete. No patterns found.")

        elapsed_time = time.time() - self.start_time if self.start_time else 0
        minutes = int(elapsed_time / 60)
        seconds = int(elapsed_time % 60)
        time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        self.time_label.setText(f"Completed in: {time_str}")

    def _populate_model_from_patterns(self):
        """Refresh the results tree view with current patterns based on filters."""
        # Clear existing model data before repopulating
        self.source_model.removeRows(0, self.source_model.rowCount())

        # The proxy model handles filtering, so we populate the source_model with all patterns
        # that match the current self.all_patterns (which might have been loaded or detected)
        # The actual filtering to display is done by CustomFilterProxyModel via invalidateFilter()

        # Get patterns that match the current UI filter settings for display
        # This step isn't strictly necessary here if proxy handles all, but good for summary.
        # For direct model population, we iterate self.all_patterns
        # The proxy model will decide what to show based on its internal filter state.

        for pattern in self.all_patterns:  # Iterate all patterns, proxy will filter
            addr_item = QStandardItem(
                f"0x{pattern.ida_address:08X}"
            )  # Changed to uppercase hex
            addr_item.setData(pattern.ida_address, Qt.UserRole)

            cat_text = pattern.category.name.replace("_", " ").title()
            cat_item = QStandardItem(cat_text)
            # No UserRole needed for category if sorting is by display text

            desc_item = QStandardItem(pattern.description)

            name_item = QStandardItem(pattern.pattern_name)

            insn_text = " ; ".join(
                [f"{insn.mnemonic} {insn.op_str}" for insn in pattern.instructions[:3]]
            )
            if len(pattern.instructions) > 3:
                insn_text += " ; ..."
            insn_item = QStandardItem(insn_text)

            junk_count_item = QStandardItem(str(pattern.junk_count))
            junk_count_item.setData(pattern.junk_count, Qt.UserRole)

            total_length_item = QStandardItem(
                str(pattern.total_length)
            )  # Store as string for display
            total_length_item.setData(
                pattern.total_length, Qt.UserRole
            )  # Store int for sorting

            row_items = [
                addr_item,
                cat_item,
                desc_item,
                name_item,
                insn_item,
                junk_count_item,
                total_length_item,
            ]
            self.source_model.appendRow(row_items)

        # Trigger proxy model to re-filter/re-sort if needed based on its current settings
        # This is usually handled by changes to filterRegularExpression or sortColumn.
        # If populating for the first time or after clearing, this ensures view is up-to-date.
        self.proxy_model.invalidate()  # Invalidate to ensure re-filtering and sorting
        self.update_summary()

    def get_filtered_patterns(self) -> List[PatternMatch]:
        """Get patterns currently visible in the proxy model (for summary/export)."""
        # This method now needs to iterate through the proxy model to see what's visible.
        # This is more complex than before. For summary, we might rely on proxy row count.
        # For export, we would iterate all_patterns and apply filters manually or export all.
        # For now, let's make this simpler and assume summary can use proxy_model.rowCount()

        # If an accurate list of *PatternMatch objects* that are visible is needed:
        visible_patterns = []
        if self.source_model and self.proxy_model:
            for proxy_row in range(self.proxy_model.rowCount()):
                source_index = self.proxy_model.mapToSource(
                    self.proxy_model.index(proxy_row, 0)
                )
                if source_index.isValid():
                    # Find the original PatternMatch object. This is tricky if not stored directly.
                    # We stored ida_address in UserRole of column 0. Let's use that to find it in self.all_patterns
                    ida_addr = self.source_model.data(
                        source_index.siblingAtColumn(0), Qt.UserRole
                    )
                    original_pattern = next(
                        (p for p in self.all_patterns if p.ida_address == ida_addr),
                        None,
                    )
                    if original_pattern:
                        visible_patterns.append(original_pattern)
        return visible_patterns

    def apply_filters(self):
        """Apply current filters to results tree view via the proxy model."""
        text_filter = self.filter_input.text()
        self.proxy_model.setFilterRegularExpression(QRegularExpression(text_filter))

        category_filter_text = self.category_filter.currentText()
        self.proxy_model.set_category_filter(category_filter_text)

        # No need to call _populate_model_from_patterns here, proxy handles it.
        self.update_summary()

    def clear_filters(self):
        """Clear all filters."""
        self.filter_input.clear()  # This will trigger textChanged, updating proxy regex
        self.category_filter.setCurrentIndex(
            0
        )  # This will trigger currentTextChanged, updating proxy category
        # self.proxy_model.setFilterRegularExpression(QRegularExpression(""))
        # self.proxy_model.set_category_filter("All Categories")
        # self.update_summary() # Will be called by apply_filters triggered by signals

    def update_summary(self):
        """Update the summary label based on visible items in the proxy model."""
        total_source_patterns = len(self.all_patterns)
        filtered_visible_count = self.proxy_model.rowCount()

        if total_source_patterns == 0:
            self.summary_label.setText("No patterns detected yet.")
        elif (
            filtered_visible_count == total_source_patterns
            and self.filter_input.text() == ""
            and self.category_filter.currentText() == "All Categories"
        ):
            if self.all_patterns:
                avg_junk = sum(p.junk_count for p in self.all_patterns) / len(
                    self.all_patterns
                )
                total_bytes = sum(p.total_length for p in self.all_patterns)
                self.summary_label.setText(
                    f"Found {total_source_patterns} patterns (avg {avg_junk:.1f} junk, {total_bytes} bytes)."
                )
            else:
                self.summary_label.setText(
                    f"Found {total_source_patterns} patterns total."
                )
        else:
            visible_patterns_for_stats = (
                self.get_filtered_patterns()
            )  # Get actual PatternMatch objects for stats
            if visible_patterns_for_stats:
                avg_junk = sum(p.junk_count for p in visible_patterns_for_stats) / len(
                    visible_patterns_for_stats
                )
                total_bytes = sum(p.total_length for p in visible_patterns_for_stats)
                self.summary_label.setText(
                    f"Showing {filtered_visible_count} of {total_source_patterns} patterns (avg {avg_junk:.1f} junk, {total_bytes} bytes)."
                )
            else:
                self.summary_label.setText(
                    f"Showing {filtered_visible_count} of {total_source_patterns} patterns (no matching for stats)."
                )

    def goto_pattern_tree_item(self, proxy_index: QModelIndex):
        """Navigate to the selected pattern in IDA from tree view item."""
        if not proxy_index.isValid():
            return
        source_index = self.proxy_model.mapToSource(proxy_index)
        # Address is in column 0, UserRole
        address = self.source_model.data(source_index.siblingAtColumn(0), Qt.UserRole)
        if isinstance(address, int):
            idaapi.jumpto(address)
        else:
            logging.warning("Could not get valid address from tree item: %s", address)

    def save_results(self):
        """Save pattern detection results (all patterns) to JSON file."""
        if not self.all_patterns:
            QMessageBox.information(self, "Save Results", "No patterns to save.")
            return

        # Get save filename
        default_filename = f"obfuscation_patterns_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Pattern Detection Results",
            default_filename,
            "JSON Files (*.json);;All Files (*)",
        )

        if not filename:
            return  # User cancelled

        try:
            # Create export data structure
            export_data = {
                "metadata": {
                    "version": "1.0",
                    "created": datetime.datetime.now().isoformat(),
                    "ida_database": (
                        ida_nalt.get_root_filename()
                        if "ida_nalt" in globals()
                        else "unknown"
                    ),
                    "total_patterns": len(self.all_patterns),
                    "categories": {
                        "multi_part": len(
                            [
                                p
                                for p in self.all_patterns
                                if p.category == PatternCategory.MULTI_PART
                            ]
                        ),
                        "single_part": len(
                            [
                                p
                                for p in self.all_patterns
                                if p.category == PatternCategory.SINGLE_PART
                            ]
                        ),
                        "junk": len(
                            [
                                p
                                for p in self.all_patterns
                                if p.category == PatternCategory.JUNK
                            ]
                        ),
                    },
                    "statistics": {
                        "avg_junk_count": sum(p.junk_count for p in self.all_patterns)
                        / len(self.all_patterns),
                        "total_obfuscation_bytes": sum(
                            p.total_length for p in self.all_patterns
                        ),
                        "min_junk_count": min(p.junk_count for p in self.all_patterns),
                        "max_junk_count": max(p.junk_count for p in self.all_patterns),
                    },
                },
                "patterns": [pattern.to_dict() for pattern in self.all_patterns],
            }

            # Write to file with pretty formatting
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            QMessageBox.information(
                self,
                "Save Complete",
                f"Successfully saved {len(self.all_patterns)} patterns to:\n{filename}",
            )

        except Exception as e:
            QMessageBox.critical(
                self, "Save Error", f"Failed to save results:\n{str(e)}"
            )

    def load_results(self):
        """Load pattern detection results from JSON file."""
        # Get load filename
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load Pattern Detection Results",
            "",
            "JSON Files (*.json);;All Files (*)",
        )

        if not filename:
            return  # User cancelled

        try:
            with open(filename, "r", encoding="utf-8") as f:
                import_data = json.load(f)

            # Validate file format
            if "patterns" not in import_data:
                QMessageBox.critical(
                    self,
                    "Load Error",
                    "Invalid file format: missing 'patterns' section.",
                )
                return

            # Load patterns
            loaded_patterns = []
            for pattern_data in import_data["patterns"]:
                try:
                    pattern = PatternMatch.from_dict(pattern_data)
                    loaded_patterns.append(pattern)
                except Exception as e:
                    logging.warning("Failed to load pattern: %s", e)
                    continue

            if not loaded_patterns:
                QMessageBox.warning(
                    self, "Load Warning", "No valid patterns found in file."
                )
                return

            # Ask user if they want to replace current results or append
            if self.all_patterns:
                reply = QMessageBox.question(
                    self,
                    "Load Results",
                    f"Found {len(loaded_patterns)} patterns in file.\n\n"
                    f"Current results: {len(self.all_patterns)} patterns\n\n"
                    "Replace current results or append to them?",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                    QMessageBox.Cancel,
                )

                if reply == QMessageBox.Cancel:
                    return
                elif reply == QMessageBox.Yes:
                    # Replace current results
                    self.all_patterns = loaded_patterns
                else:
                    # Append to current results
                    self.all_patterns.extend(loaded_patterns)
            else:
                # No current results, just load
                self.all_patterns = loaded_patterns

            # Update UI
            self._populate_model_from_patterns()
            self.update_buttons_state()

            # Show metadata if available
            metadata_info = ""
            if "metadata" in import_data:
                meta = import_data["metadata"]
                metadata_info = f"\n\nFile Info:\n"
                metadata_info += f"• Created: {meta.get('created', 'unknown')}\n"
                metadata_info += (
                    f"• IDA Database: {meta.get('ida_database', 'unknown')}\n"
                )
                metadata_info += (
                    f"• Original Count: {meta.get('total_patterns', 'unknown')}"
                )

                if "statistics" in meta:
                    stats = meta["statistics"]
                    metadata_info += (
                        f"\n• Avg Junk Count: {stats.get('avg_junk_count', 0):.1f}"
                    )
                    metadata_info += f"\n• Total Obfuscation: {stats.get('total_obfuscation_bytes', 0)} bytes"

            QMessageBox.information(
                self,
                "Load Complete",
                f"Successfully loaded {len(loaded_patterns)} patterns.\n"
                f"Current total: {len(self.all_patterns)} patterns.{metadata_info}",
            )

        except Exception as e:
            QMessageBox.critical(
                self, "Load Error", f"Failed to load results:\n{str(e)}"
            )

    def export_csv(self):
        """Export pattern detection results to CSV file."""
        if not self.all_patterns:
            QMessageBox.information(self, "Export CSV", "No patterns to export.")
            return

        # Get save filename
        default_filename = f"obfuscation_patterns_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Pattern Detection Results to CSV",
            default_filename,
            "CSV Files (*.csv);;All Files (*)",
        )

        if not filename:
            return  # User cancelled

        try:
            import csv

            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow(
                    [
                        "Address",
                        "Category",
                        "Description",
                        "Pattern Name",
                        "Junk Count",
                        "Total Length",
                        "Instructions",
                        "Instruction Bytes",
                    ]
                )

                # Write pattern data
                for pattern in self.all_patterns:
                    # Format instructions
                    insn_text = " ; ".join(
                        [
                            f"{insn.mnemonic} {insn.op_str}"
                            for insn in pattern.instructions
                        ]
                    )
                    insn_bytes = " ".join(
                        [
                            insn.bytes.hex().upper() if hasattr(insn, "bytes") else ""
                            for insn in pattern.instructions
                        ]
                    )

                    writer.writerow(
                        [
                            f"0x{pattern.ida_address:08X}",
                            pattern.category.name.replace("_", "-").title(),
                            pattern.description,
                            pattern.pattern_name,
                            pattern.junk_count,
                            pattern.total_length,
                            insn_text,
                            insn_bytes,
                        ]
                    )

            QMessageBox.information(
                self,
                "Export Complete",
                f"Successfully exported {len(self.all_patterns)} patterns to:\n{filename}",
            )

        except Exception as e:
            QMessageBox.critical(
                self, "Export Error", f"Failed to export results:\n{str(e)}"
            )

    def clear_results(self):
        """Clear all pattern detection results."""
        if not self.all_patterns:
            return

        reply = QMessageBox.question(
            self,
            "Clear Results",
            f"Clear all {len(self.all_patterns)} pattern detection results?\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.all_patterns.clear()
            self.source_model.removeRows(0, self.source_model.rowCount())
            self.update_buttons_state()
            self.update_summary()

    def update_buttons_state(self):
        """Update the enabled state of buttons based on current patterns."""
        has_patterns = len(self.all_patterns) > 0
        self.save_btn.setEnabled(has_patterns)
        self.export_csv_btn.setEnabled(has_patterns)
        self.clear_btn.setEnabled(has_patterns)

    def _handle_runnable_error(self, error_info: tuple):
        """Handle errors reported by runnables."""
        exc_type_name, exc_value_str, tb_str = error_info
        error_msg = f"Error in worker thread ({exc_type_name}): {exc_value_str}\nTraceback:\n{tb_str}"
        logging.error(error_msg)
        # Display a simplified message to the user, full details in log
        QMessageBox.critical(
            self,
            "Worker Error",
            f"An error occurred in an analysis worker ({exc_type_name}):\n{exc_value_str}.\nSee logs for full traceback.",
        )
        # Note: We don't stop other runnables here, they continue.
        # The overall process will complete, potentially with partial results.
        # The cancel_detection method can be used to stop everything if needed.

    def handle_error(self, error_msg: str):
        """Handle detection errors (typically for main thread errors or simple string errors)."""
        # This is the generic error handler. _handle_runnable_error is specific to worker tuple errors.
        # If a tuple comes here, it means it wasn't caught by _handle_runnable_error signal.
        if isinstance(error_msg, tuple) and len(error_msg) == 3:
            # It's likely our worker error tuple, format it nicely
            exc_type_name, exc_value_str, tb_str = error_msg
            full_error_msg = (
                f"Error ({exc_type_name}): {exc_value_str}\nTraceback:\n{tb_str}"
            )
            user_facing_msg = f"An error occurred ({exc_type_name}):\n{exc_value_str}."
        else:
            full_error_msg = error_msg
            user_facing_msg = error_msg

        logging.error("handle_error called: %s", full_error_msg)
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Error occurred during detection.")
        QMessageBox.critical(
            self, "Detection Error", f"An error occurred:\n{user_facing_msg}"
        )


# ----------------------------------------------------------------------
# Signature-pattern cache  (pattern-string → compiled_binpat_vec_t)
# ----------------------------------------------------------------------
_sig_cache: dict[bytes, ida_bytes.compiled_binpat_vec_t] = {}


def find_byte_sequence(
    start: int,
    end: int,
    sig: list[int] | bytes | str,
    direction: int = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
) -> Iterator[int]:
    """Cached pattern search: compiles each unique signature once."""
    if isinstance(sig, str):
        sigstr = sig
    elif isinstance(sig, list):
        sigstr = " ".join(f"{b:02x}" if b != -1 else "?" for b in sig)
    else:
        sigstr = sig.hex()

    key = sigstr.encode("utf-8")
    cpv = _sig_cache.get(key)
    if cpv is None:
        cpv = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(
            cpv,
            start,
            sigstr,
            16,
            ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B),
        )
        if err:
            return
        _sig_cache[key] = cpv

    ea = start
    while True:
        res, _ = ida_bytes.bin_search(ea, end, cpv, direction)
        if res == idaapi.BADADDR:
            break
        yield res
        ea = res + 1


# --- Pattern Detection Classes ---

JUNK_PATTERNS = [
    JunkPatternMetadata(rb"(?P<junk>\x0F\x31)", "RDTSC"),
    JunkPatternMetadata(
        rb"(?P<junk>\x0F[\x80-\x8F]..[\x00\x01]\x00)", "TwoByte Conditional Jump"
    ),
    JunkPatternMetadata(
        rb"(?P<junk>\xE8..[\x00\x01]\x00)\xC3?",
        "Invalid Call-0-Offset + RET (multi-byte NOP)",
    ),
    JunkPatternMetadata(rb"(?P<junk>\x81[\xC0-\xC3\xC5-\xC7]....)", "ADD reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x81[\xE8-\xEB\xED-\xEF]....)", "SUB reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\xC7[\xC0-\xC3\xC5-\xC7]....)", "MOV reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x80[\xC0-\xC3\xC5-\xC7].)", "ADD reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\x83[\xC0-\xC3\xC5-\xC7\xEC].)", "ADD reg32, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\xC6[\xC0-\xC3\xC5-\xC7].)", "MOV reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\xF6[\xD8-\xDB\xDD-\xDF])", "NEG reg8"),
    JunkPatternMetadata(rb"(?P<junk>\x80[\xE8-\xEB\xED-\xEF].)", "AND reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\x68....)", "PUSH imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x6A.)", "PUSH imm8"),
    JunkPatternMetadata(rb"(?P<junk>[\x70-\x7F].)", "Random 0x70-0x7F jump"),
    JunkPatternMetadata(rb"(?P<junk>[\x50-\x5F])", "Single-byte PUSH/POP"),
    JunkPatternMetadata(rb"(?P<junk>\x66\x90)", "Two-byte NOP"),
    JunkPatternMetadata(rb"(?P<junk>\x90\x90)", "Two-byte NOP"),
    JunkPatternMetadata(rb"(?P<junk>\x6B.)", "IMUL reg32, r/m32, imm8"),
    JunkPatternMetadata(
        rb"(?P<junk>[\xC0][\x18-\x1F\x58-\x5F\x98-\x9F\xD8-\xDF]....)",
        "RCR r/m8, imm8 (any mod)",
    ),
    JunkPatternMetadata(
        rb"(?P<junk>[\xC0][\x38-\x3F\x78-\x7F\xB8-\xBF\xF8-\xFF]....)",
        "SAR r/m8, imm8 (any mod)",
    ),
    JunkPatternMetadata(
        rb"(?P<junk>[\xC0][\x28-\x2F\x68-\x6F\xA8-\xAF\xE8-\xEF]....)",
        "SHR r/m8, imm8 (any mod)",
    ),
    JunkPatternMetadata(rb"(?P<junk>\x81[\x88-\x8B\x8D-\x8F]....)", "XOR reg32, imm32"),
    JunkPatternMetadata(rb"(?P<junk>\x83[\x80-\x83\x85-\x87].)", "ADD r/8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\x83[\xB0-\xB3\xB5-\xB7].)", "XOR reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\x83[\x88-\x8B\x8D-\x8F].)", "OR reg8, imm8"),
    JunkPatternMetadata(rb"(?P<junk>\xEB\xFF)", "Infinite-loop JMP"),
    JunkPatternMetadata(rb"(?P<junk>\xF6[\xB3\xB4\xB5\xB6\xB7])", "DIV reg8"),
    JunkPatternMetadata(
        rb"(?P<junk>\x80(?:"
        rb"[\x38-\x3B]"  # Mod=00, R/M=0–3
        rb"|[\x78-\x7B]"  # Mod=01, R/M=0–3
        rb"|[\xB8-\xBB]"  # Mod=10, R/M=0–3
        rb"|[\xF8-\xFB]"  # Mod=11, R/M=0–3
        rb"|[\x3D-\x3F]"  # Mod=00, R/M=5–7
        rb"|[\x7D-\x7F]"  # Mod=01, R/M=5–7
        rb"|[\xBD-\xBF]"  # Mod=10, R/M=5–7
        rb"|[\xFD-\xFF]"  # Mod=11, R/M=5–7
        rb")..)",
        "CMP r/m8, imm8 (80 /7 ib, any mod; r/m≠4)",
    ),
]


class JunkDetector:
    """Detects junk/obfuscation instructions after jump patterns."""

    def __init__(self):
        self.compiled_patterns = []
        for pattern_meta in JUNK_PATTERNS:
            try:
                compiled = pattern_meta.compile(re.DOTALL | re.VERBOSE)
                self.compiled_patterns.append((compiled, pattern_meta.description))
            except Exception as e:
                logging.warning(
                    "Failed to compile junk pattern %s: %s", pattern_meta.description, e
                )

    def count_junk_instructions(
        self, data: bytes, start_offset: int, max_search_length: int = 200
    ) -> Tuple[int, int]:
        """
        Count consecutive junk instructions starting from start_offset.

        Args:
            data: Raw byte data to search
            start_offset: Offset to start searching for junk
            max_search_length: Maximum bytes to search

        Returns:
            Tuple of (junk_count, total_junk_bytes)
        """
        if start_offset >= len(data):
            return 0, 0

        junk_count = 0
        current_offset = start_offset
        search_end = min(len(data), start_offset + max_search_length)
        total_junk_bytes = 0

        while current_offset < search_end:
            found_junk = False
            remaining_data = data[current_offset:search_end]

            # Try each junk pattern
            for compiled_pattern, description in self.compiled_patterns:
                match = compiled_pattern.match(remaining_data)
                if match:
                    junk_length = match.end()
                    junk_count += 1
                    current_offset += junk_length
                    total_junk_bytes += junk_length
                    found_junk = True
                    logging.debug(
                        "Found junk instruction: %s (length %d) at offset %d",
                        description,
                        junk_length,
                        current_offset - junk_length,
                    )
                    break

            if not found_junk:
                # Try to skip single bytes that might be part of multi-byte instructions
                # or unrecognized junk patterns, but limit consecutive skips
                if junk_count > 0:  # Only skip if we've found some junk already
                    current_offset += 1
                    total_junk_bytes += 1
                    # Don't increment junk_count for single-byte skips
                    if (
                        current_offset - start_offset > 50
                    ):  # Limit skipping to avoid false positives
                        break
                else:
                    break

        return junk_count, total_junk_bytes

    def has_sufficient_junk(
        self, data: bytes, start_offset: int, min_junk_count: int = 4
    ) -> Tuple[bool, int, int]:
        """
        Check if there are sufficient junk instructions after the pattern.

        Args:
            data: Raw byte data
            start_offset: Offset to start searching for junk
            min_junk_count: Minimum number of junk instructions required

        Returns:
            Tuple of (has_enough_junk, junk_count, total_junk_bytes)
        """
        junk_count, total_junk_bytes = self.count_junk_instructions(data, start_offset)
        has_enough = junk_count >= min_junk_count

        logging.debug(
            "Junk check at offset %d: found %d junk instructions (%d bytes), required %d",
            start_offset,
            junk_count,
            total_junk_bytes,
            min_junk_count,
        )

        return has_enough, junk_count, total_junk_bytes


class PaddingDetector:
    """Detects padding/junk instructions that don't affect program flow."""

    @staticmethod
    def is_padding_instruction(insn: capstone.CsInsn) -> bool:
        """
        Check if instruction is padding/junk.
        Original regex: rb"(?:\xc0[\xe0-\xff]\x00|(?:\x86|\x8a)[\xc0\xc9\xd2\xdb\xe4\xed\xf6\xff])"

        Detects:
        - SHL reg, 0 with various register encodings
        - XCHG or MOV with specific register combinations
        """
        if insn.mnemonic == "shl" and len(insn.operands) == 2:
            # SHL reg, 0
            if (
                insn.operands[1].type == capstone.x86.X86_OP_IMM
                and insn.operands[1].imm == 0
            ):
                return True

        if insn.mnemonic in ["xchg", "mov"]:
            # Check for register-to-register operations that don't change state
            if (
                len(insn.operands) == 2
                and insn.operands[0].type == capstone.x86.X86_OP_REG
                and insn.operands[1].type == capstone.x86.X86_OP_REG
            ):
                # Same register operations are junk
                if insn.operands[0].reg == insn.operands[1].reg:
                    return True

        return False


class FastPatternMatcher:
    """Optimized pattern matcher using IDA's signature search + Capstone verification."""

    # Signature patterns for fast initial search
    JUMP_PATTERNS = {
        # Multi-part conditional jump patterns (first jump opcodes)
        "jo_patterns": [0x70],  # JO
        "jno_patterns": [0x71],  # JNO
        "jb_patterns": [0x72],  # JB
        "jae_patterns": [0x73],  # JAE
        "je_patterns": [0x74],  # JE
        "jne_patterns": [0x75],  # JNE
        "jbe_patterns": [0x76],  # JBE
        "ja_patterns": [0x77],  # JA
        "js_patterns": [0x78],  # JS
        "jns_patterns": [0x79],  # JNS
        "jp_patterns": [0x7A],  # JP
        "jnp_patterns": [0x7B],  # JNP
        "jl_patterns": [0x7C],  # JL
        "jge_patterns": [0x7D],  # JGE
        "jle_patterns": [0x7E],  # JLE
        "jg_patterns": [0x7F],  # JG
    }

    PREFIX_PATTERNS = {
        # Single-part prefix patterns
        "or_al_0": [0x0C, 0x00],  # OR AL, 0x00
        "and_al_ff": [0x24, 0xFF],  # AND AL, 0xFF
        "xor_al_0": [0x34, 0x00],  # XOR AL, 0x00
        "test_al": [0xA8],  # TEST AL, imm8
        "test_eax": [0xA9],  # TEST EAX, imm32
        "clc": [0xF8],  # CLC
        "stc": [0xF9],  # STC
        "or_rm8": [0x80],  # OR r/m8, imm8 (with ModR/M 0xC8-0xCF)
        "and_rm8": [0x80],  # AND r/m8, imm8 (with ModR/M 0xE0-0xE7)
        "xor_rm8": [0x80],  # XOR r/m8, imm8 (with ModR/M 0xF0-0xF7)
        "test_rm8_r8": [0x84],  # TEST r/m8, r8
        "test_rm32_r32": [0x85],  # TEST r/m32, r32
        "test_rm8_imm": [0xF6],  # TEST r/m8, imm8
        "test_rm32_imm": [0xF7],  # TEST r/m32, imm32
        "cmp_esp": [0x81, 0xFC],  # CMP ESP, imm32
    }

    def __init__(self):
        self.detector = PatternDetector()
        self.multi_part_detector = MultiPartPatternDetector()
        self.single_part_detector = SinglePartPatternDetector()
        self.junk_detector = JunkDetector()  # Add junk detector

    def find_pattern_candidates(self, start_ea: int, end_ea: int) -> List[int]:
        """Find all potential pattern locations using fast signature search."""
        candidates = set()

        logging.info("Searching for conditional jump candidates...")

        # Search for conditional jumps (multi-part patterns)
        for pattern_name, opcodes in self.JUMP_PATTERNS.items():
            for opcode in opcodes:
                for ea in find_byte_sequence(start_ea, end_ea, [opcode]):
                    candidates.add(ea)

        logging.info("Searching for prefix instruction candidates...")

        # Search for prefix instructions (single-part patterns)
        for pattern_name, opcodes in self.PREFIX_PATTERNS.items():
            for ea in find_byte_sequence(start_ea, end_ea, opcodes):
                candidates.add(ea)

        return sorted(list(candidates))

    def analyze_candidate_region_bytes(
        self, region_bytes: bytes, base_address: int, candidate_ea: int
    ) -> List[PatternMatch]:
        """Analyze a byte region with Capstone - no IDA API calls."""
        matches = []

        if not region_bytes:
            return matches

        try:
            # Calculate offset of candidate within region
            candidate_offset = candidate_ea - base_address

            # Only analyze around the candidate, not the entire region
            analysis_start = max(0, candidate_offset - 50)
            analysis_end = min(len(region_bytes), candidate_offset + 50)
            analysis_bytes = region_bytes[analysis_start:analysis_end]

            # Try to find patterns in this small region
            matches = self._find_patterns_in_bytes(
                analysis_bytes, base_address + analysis_start
            )

        except Exception as e:
            logging.warning("Error analyzing candidate at 0x%x: %s", candidate_ea, e)

        return matches

    def _find_patterns_in_bytes(
        self, data: bytes, base_address: int
    ) -> List[PatternMatch]:
        """Find patterns in a small byte sequence with junk validation."""
        patterns = []

        try:
            if (
                not USE_CAPSTONE or self.detector.cs is None
            ):  # Added self.detector.cs is None check
                return patterns  # Capstone disabled or cs not initialized
            instructions = list(self.detector.cs.disasm(data, base_address))
            if len(instructions) < 2:
                return patterns

            # Look for multi-part patterns (complementary jumps)
            for i in range(len(instructions) - 1):
                first_insn = instructions[i]

                if self._is_conditional_jump(first_insn):
                    # Look for complementary jump within next few instructions
                    for j in range(i + 1, min(i + 6, len(instructions))):
                        second_insn = instructions[j]

                        if self._are_complementary_jumps(first_insn, second_insn):
                            # Found complementary jump pair - now check for junk
                            pattern_end_offset = (
                                second_insn.address + second_insn.size - base_address
                            )

                            # Check for sufficient junk instructions after the pattern
                            has_junk, junk_count, junk_bytes = (
                                self.junk_detector.has_sufficient_junk(
                                    data, pattern_end_offset, min_junk_count=4
                                )
                            )

                            if has_junk:
                                padding_insns = instructions[i + 1 : j]
                                all_insns = [first_insn] + padding_insns + [second_insn]

                                pattern = PatternMatch(
                                    category=PatternCategory.MULTI_PART,
                                    description=f"{first_insn.mnemonic.upper()} ... {second_insn.mnemonic.upper()}",
                                    start_offset=first_insn.address - base_address,
                                    end_offset=second_insn.address
                                    + second_insn.size
                                    - base_address,
                                    instructions=all_insns,
                                    pattern_name=f"multipart_{first_insn.mnemonic}_{second_insn.mnemonic}",
                                    ida_address=first_insn.address,
                                    junk_count=junk_count,
                                    total_length=(
                                        second_insn.address
                                        + second_insn.size
                                        - first_insn.address
                                    )
                                    + junk_bytes,
                                )
                                patterns.append(pattern)
                                logging.info(
                                    "Valid multi-part pattern found: %s with %d junk instructions (%d bytes) at 0x%x",
                                    pattern.description,
                                    junk_count,
                                    junk_bytes,
                                    pattern.ida_address,
                                )
                            else:
                                logging.debug(
                                    "Rejected multi-part pattern %s -> %s: insufficient junk (%d < 4) at 0x%x",
                                    first_insn.mnemonic,
                                    second_insn.mnemonic,
                                    junk_count,
                                    first_insn.address,
                                )
                            break

                # Look for single-part patterns (prefix + jump)
                if self._is_prefix_instruction(first_insn):
                    # Look for conditional jump within next few instructions
                    for j in range(i + 1, min(i + 4, len(instructions))):
                        jump_insn = instructions[j]

                        if self._is_conditional_jump(jump_insn):
                            # Found prefix + jump pair - now check for junk
                            pattern_end_offset = (
                                jump_insn.address + jump_insn.size - base_address
                            )

                            # Check for sufficient junk instructions after the pattern
                            has_junk, junk_count, junk_bytes = (
                                self.junk_detector.has_sufficient_junk(
                                    data, pattern_end_offset, min_junk_count=4
                                )
                            )

                            if has_junk:
                                padding_insns = instructions[i + 1 : j]
                                all_insns = [first_insn] + padding_insns + [jump_insn]

                                pattern = PatternMatch(
                                    category=PatternCategory.SINGLE_PART,
                                    description=f"{first_insn.mnemonic.upper()} {first_insn.op_str} ... {jump_insn.mnemonic.upper()}",
                                    start_offset=first_insn.address - base_address,
                                    end_offset=jump_insn.address
                                    + jump_insn.size
                                    - base_address,
                                    instructions=all_insns,
                                    pattern_name=f"singlepart_{first_insn.mnemonic}_{jump_insn.mnemonic}",
                                    ida_address=first_insn.address,
                                    junk_count=junk_count,
                                    total_length=(
                                        jump_insn.address
                                        + jump_insn.size
                                        - first_insn.address
                                    )
                                    + junk_bytes,
                                )
                                patterns.append(pattern)
                                logging.info(
                                    "Valid single-part pattern found: %s with %d junk instructions (%d bytes at 0x%x)",
                                    pattern.description,
                                    junk_count,
                                    junk_bytes,
                                    pattern.ida_address,
                                )
                            else:
                                logging.debug(
                                    "Rejected single-part pattern %s -> %s: insufficient junk (%d < 4) at 0x%x",
                                    first_insn.mnemonic,
                                    jump_insn.mnemonic,
                                    junk_count,
                                    first_insn.address,
                                )
                            break

        except Exception as e:
            logging.warning("Error in pattern analysis: %s", e)

        return patterns

    def _is_conditional_jump(self, insn: capstone.CsInsn) -> bool:
        """Check if instruction is a conditional jump."""
        return insn.id in [
            capstone.x86.X86_INS_JO,
            capstone.x86.X86_INS_JNO,
            capstone.x86.X86_INS_JB,
            capstone.x86.X86_INS_JAE,
            capstone.x86.X86_INS_JE,
            capstone.x86.X86_INS_JNE,
            capstone.x86.X86_INS_JBE,
            capstone.x86.X86_INS_JA,
            capstone.x86.X86_INS_JS,
            capstone.x86.X86_INS_JNS,
            capstone.x86.X86_INS_JP,
            capstone.x86.X86_INS_JNP,
            capstone.x86.X86_INS_JL,
            capstone.x86.X86_INS_JGE,
            capstone.x86.X86_INS_JLE,
            capstone.x86.X86_INS_JG,
        ]

    def _are_complementary_jumps(
        self, first: capstone.CsInsn, second: capstone.CsInsn
    ) -> bool:
        """Check if two jumps are complementary (opposite conditions)."""
        pairs = {
            capstone.x86.X86_INS_JO: capstone.x86.X86_INS_JNO,
            capstone.x86.X86_INS_JNO: capstone.x86.X86_INS_JO,
            capstone.x86.X86_INS_JB: capstone.x86.X86_INS_JAE,
            capstone.x86.X86_INS_JAE: capstone.x86.X86_INS_JB,
            capstone.x86.X86_INS_JE: capstone.x86.X86_INS_JNE,
            capstone.x86.X86_INS_JNE: capstone.x86.X86_INS_JE,
            capstone.x86.X86_INS_JBE: capstone.x86.X86_INS_JA,
            capstone.x86.X86_INS_JA: capstone.x86.X86_INS_JBE,
            capstone.x86.X86_INS_JS: capstone.x86.X86_INS_JNS,
            capstone.x86.X86_INS_JNS: capstone.x86.X86_INS_JS,
            capstone.x86.X86_INS_JP: capstone.x86.X86_INS_JNP,
            capstone.x86.X86_INS_JNP: capstone.x86.X86_INS_JP,
            capstone.x86.X86_INS_JL: capstone.x86.X86_INS_JGE,
            capstone.x86.X86_INS_JGE: capstone.x86.X86_INS_JL,
            capstone.x86.X86_INS_JLE: capstone.x86.X86_INS_JG,
            capstone.x86.X86_INS_JG: capstone.x86.X86_INS_JLE,
        }
        return pairs.get(first.id) == second.id

    def _is_prefix_instruction(self, insn: capstone.CsInsn) -> bool:
        """Check if instruction can be a prefix for single-part patterns."""
        # OR AL, 0x00 or AND AL, 0xFF or XOR AL, 0x00
        if insn.id in [
            capstone.x86.X86_INS_OR,
            capstone.x86.X86_INS_AND,
            capstone.x86.X86_INS_XOR,
        ]:
            if (
                len(insn.operands) == 2
                and insn.operands[0].type == capstone.x86.X86_OP_REG
                and insn.operands[0].reg == capstone.x86.X86_REG_AL
                and insn.operands[1].type == capstone.x86.X86_OP_IMM
            ):
                return insn.operands[1].imm == 0x00 or insn.operands[1].imm == 0xFF

        # TEST instructions
        if insn.id == capstone.x86.X86_INS_TEST:
            return True

        # CLC/STC
        if insn.id in [capstone.x86.X86_INS_CLC, capstone.x86.X86_INS_STC]:
            return True

        # CMP ESP, immediate
        if insn.id == capstone.x86.X86_INS_CMP:
            if (
                len(insn.operands) == 2
                and insn.operands[0].type == capstone.x86.X86_OP_REG
                and insn.operands[0].reg == capstone.x86.X86_REG_ESP
                and insn.operands[1].type == capstone.x86.X86_OP_IMM
            ):
                return True

        return False

    def find_all_patterns_optimized(self, segm_range=None) -> List[PatternMatch]:
        """Main optimized pattern finding function - simplified for Qt integration."""
        all_matches = []

        if segm_range is None:
            segm_range = ida_segment.get_segm_by_name(".text")
        if not segm_range:
            logging.error("Could not find .text segment")
            return all_matches

        logging.info(
            "Starting optimized pattern detection in .text segment (0x%x - 0x%x)",
            segm_range.start_ea,
            segm_range.end_ea,
        )

        # Phase 1: Fast candidate search
        candidates = self.find_pattern_candidates(
            segm_range.start_ea, segm_range.end_ea
        )
        logging.info("Found %d potential pattern candidates", len(candidates))

        if not candidates:
            return all_matches

        # Phase 2: Detailed analysis of candidates (no progress tracking here - handled by Qt)
        logging.info("Analyzing candidates with Capstone...")

        # for candidate_ea in candidates:
        #     matches = self.analyze_candidate_region(candidate_ea)
        #     all_matches.extend(matches)

        # Remove duplicates (same address)
        unique_matches = []
        seen_addresses = set()
        for match in all_matches:
            if match.ida_address not in seen_addresses:
                unique_matches.append(match)
                seen_addresses.add(match.ida_address)

        logging.info("Found %d unique patterns total", len(unique_matches))
        return unique_matches


# Keep the original detailed detector classes for reference
class MultiPartPatternDetector(PatternDetector):
    """Detects multi-part conditional jump patterns."""

    # Complementary jump pairs mapping
    COMPLEMENTARY_JUMPS = {
        capstone.x86.X86_INS_JO: capstone.x86.X86_INS_JNO,
        capstone.x86.X86_INS_JNO: capstone.x86.X86_INS_JO,
        capstone.x86.X86_INS_JB: capstone.x86.X86_INS_JAE,
        capstone.x86.X86_INS_JAE: capstone.x86.X86_INS_JB,
        capstone.x86.X86_INS_JE: capstone.x86.X86_INS_JNE,
        capstone.x86.X86_INS_JNE: capstone.x86.X86_INS_JE,
        capstone.x86.X86_INS_JBE: capstone.x86.X86_INS_JA,
        capstone.x86.X86_INS_JA: capstone.x86.X86_INS_JBE,
        capstone.x86.X86_INS_JS: capstone.x86.X86_INS_JNS,
        capstone.x86.X86_INS_JNS: capstone.x86.X86_INS_JS,
        capstone.x86.X86_INS_JP: capstone.x86.X86_INS_JNP,
        capstone.x86.X86_INS_JNP: capstone.x86.X86_INS_JP,
        capstone.x86.X86_INS_JL: capstone.x86.X86_INS_JGE,
        capstone.x86.X86_INS_JGE: capstone.x86.X86_INS_JL,
        capstone.x86.X86_INS_JLE: capstone.x86.X86_INS_JG,
        capstone.x86.X86_INS_JG: capstone.x86.X86_INS_JLE,
    }


class SinglePartPatternDetector(PatternDetector):
    """Detects single-part prefix + conditional jump patterns."""

    pass


@dataclasses.dataclass
class Range:
    """A range of addresses with a start (inclusive) and end (exclusive)."""

    start: int
    end: int

    def __post_init__(self):
        if self.start >= self.end:
            raise ValueError("start must be less than end")

    def __contains__(self, addr: int) -> bool:
        """Check if an address is within this range."""
        return self.start <= addr < self.end

    def __len__(self) -> int:
        """Return the size of the range in bytes."""
        return self.end - self.start

    def overlaps(self, other: "Range") -> bool:
        """Check if this range overlaps with another range."""
        return self.start < other.end and other.start < self.end

    def merge(self, other: "Range") -> "Range":
        return Range(min(self.start, other.start), max(self.end, other.end))


class IntervalSet:
    """
    Sorted, non-overlapping list of Range objects with O(log n) insertion.
    """

    __slots__ = ("_ranges",)

    def __init__(self) -> None:
        self._ranges: list[Range] = []

    def __iter__(self):
        return iter(self._ranges)

    def __len__(self):
        return len(self._ranges)

    # --- public ------------------------------------------------------------
    def add(self, new: Range) -> None:
        """
        Insert `new` and coalesce any overlaps / adjacencies in-place.
        """
        # Fast-path: first interval
        if not self._ranges:
            self._ranges.append(new)
            return

        # Binary-search insertion point by *start*
        idx = bisect_left(
            self._ranges, new.start, key=lambda r: r.start
        )  # Python 3.10+

        # Extend backward if necessary
        if idx > 0 and self._ranges[idx - 1].end >= new.start:
            idx -= 1

        # Merge forward while overlapping
        while idx < len(self._ranges) and new.overlaps(self._ranges[idx]):
            new = new.merge(self._ranges[idx])
            del self._ranges[idx]

        # Also coalesce "touching" intervals (…,end==new.start or vice-versa)
        if idx < len(self._ranges) and new.end == self._ranges[idx].start:
            new = new.merge(self._ranges[idx])
            del self._ranges[idx]
        if idx > 0 and self._ranges[idx - 1].end == new.start:
            new = new.merge(self._ranges[idx - 1])
            del self._ranges[idx - 1]
            idx -= 1

        self._ranges.insert(idx, new)

    # ­— optional helpers ---------------------------------------------------
    def covers(self, addr: int) -> bool:
        i = bisect_right(self._ranges, addr, key=lambda r: r.start) - 1
        return i >= 0 and addr < self._ranges[i].end

    def as_tuples(self):
        return [(r.start, r.end) for r in self._ranges]


@dataclasses.dataclass
class BasicDecodedInstruction:
    """Holds standardized information about a decoded instruction."""

    address: int
    size: int
    is_jump: bool = False
    jump_target: typing.Optional[int] = None
    is_nop: bool = False
    dead_opaque_predicate: bool = False


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
    # Maximum x86/x64 instruction length is 15 bytes
    MAX_INSNSZ = 16

    # Define register pairs for inc/pop patterns
    # Bidirectional mapping between 32-bit and 64-bit registers
    # Define base 32-bit to 64-bit register mapping
    REG_32_TO_64 = {
        capstone.x86.X86_REG_EAX: capstone.x86.X86_REG_RAX,
        capstone.x86.X86_REG_EBX: capstone.x86.X86_REG_RBX,
        capstone.x86.X86_REG_ECX: capstone.x86.X86_REG_RCX,
        capstone.x86.X86_REG_EDX: capstone.x86.X86_REG_RDX,
        # explicitly exclude esi, because it is not a valid register
        capstone.x86.X86_REG_EDI: capstone.x86.X86_REG_RDI,
        capstone.x86.X86_REG_EBP: capstone.x86.X86_REG_RBP,
        capstone.x86.X86_REG_ESP: capstone.x86.X86_REG_RSP,
    }
    # Derive 64-bit to 32-bit mapping by inverting the base mapping
    REG_64_TO_32 = {v: k for k, v in REG_32_TO_64.items()}

    def __init__(self, is_x64: bool):
        self.is_x64 = is_x64
        self.md = capstone.Cs(
            capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_x64 else capstone.CS_MODE_32
        )
        self.md.detail = True

        # state:
        self._buf: bytes = b""
        self._base_ea: int = 0
        self._offset: int = 0

    def load_buffer(self, mem_bytes: bytes, base_ea: int) -> None:
        """
        Load a fresh buffer and reset the internal offset to zero.
        You must call this before trying to disassemble.
        """
        self._buf = mem_bytes
        self._base_ea = base_ea
        self._offset = 0

    def get_next_insn(self) -> typing.Optional[capstone.CsInsn]:
        """
        Decode the next instruction at (base_ea + offset), advance offset.
        Returns None on decode error or end of buffer.
        """
        if self._offset >= len(self._buf):
            return None

        code = self._buf[self._offset : self._offset + self.MAX_INSNSZ]
        ea = self._base_ea + self._offset

        try:
            insn = next(self.md.disasm(code, ea, count=1), None)
        except capstone.CsError as e:
            logging.error("Capstone decoding error at 0x%X: %s", ea, e)
            return None

        if not insn:
            logging.debug("No instruction decoded at 0x%X", ea)
            return None

        # advance by the actual size decoded
        self._offset += insn.size

        logging.debug(
            "Decoded instruction: %s %s (%d bytes) at 0x%X – raw: %s",
            insn.mnemonic,
            insn.op_str,
            insn.size,
            ea,
            insn.bytes.hex(),
        )
        return insn

    def get_next_insns(self, count: int = 3) -> list[capstone.CsInsn]:
        """
        Decode up to `count` instructions, advancing offset each time.
        Returns fewer than `count` if you hit EOF or a decode failure.
        """
        insns: list[capstone.CsInsn] = []
        for _ in range(count):
            insn = self.get_next_insn()
            if not insn:
                break
            insns.append(insn)
        return insns

    def decode(
        self, ea: int, mem_bytes_at_ea: bytes
    ) -> typing.Optional[BasicDecodedInstruction]:
        """
        Decodes instruction at ea using IDA's disassembler.
        Ignores mem_bytes_at_ea, uses IDA's database.
        Conforms to DecoderProtocol.
        """
        self.load_buffer(mem_bytes_at_ea, ea)
        # Decode using Capstone
        insn = self.get_next_insn()
        if insn is None:
            return None

        decoded = BasicDecodedInstruction(address=ea, size=insn.size)
        if insn.id == capstone.x86.X86_INS_NOP:
            decoded.is_nop = True
        # Check for 'xchg r8, r8' as a NOP pattern (0x90 is 'nop', i.e. 0x87 C9 is 'xchg cl, cl')
        elif insn.id in (
            capstone.x86.X86_INS_XCHG,
            capstone.x86.X86_INS_MOV,
            capstone.x86.X86_GRP_CMOV,
        ):
            op1, op2 = insn.operands
            if op1.type == op2.type and op1.size == op2.size and op1.reg == op2.reg:
                decoded.is_nop = True
        # Handle 'inc eax' followed by 'pop rax' as a NOP pattern
        elif all(
            (
                insn.id == capstone.x86.X86_INS_INC,
                len(insn.operands) > 0,
                insn.operands[0].type == capstone.x86.X86_OP_REG,
            )
        ):
            next_insn = self.get_next_insn()
            if next_insn is not None and next_insn.id == capstone.x86.X86_INS_POP:
                logging.debug(f"Found inc/pop pattern at 0x{insn.address:X}")
                if insn.operands[0].reg in self.REG_32_TO_64 and (
                    next_insn.operands[0].reg == insn.operands[0].reg
                    or next_insn.operands[0].reg
                    == self.REG_32_TO_64[insn.operands[0].reg]
                ):
                    decoded.is_nop = True
                    decoded.size = insn.size + next_insn.size
                    return decoded
                elif insn.operands[0].reg in self.REG_64_TO_32 and (
                    next_insn.operands[0].reg == insn.operands[0].reg
                    or next_insn.operands[0].reg
                    == self.REG_64_TO_32[insn.operands[0].reg]
                ):
                    decoded.is_nop = True
                    decoded.size = insn.size + next_insn.size
                    return decoded
        elif insn.id == capstone.x86.X86_INS_PUSH and len(insn.operands) > 0:
            # we have encountered this dead code:
            # .text:0000000180188FB2 50                                                  push    rax
            # .text:0000000180188FB3 EB FF                                               jmp     short near ptr loc_180188FB3+1
            # .text:0000000180188FB5 C0 58 ? ?                                           rcr     byte ptr [rax-?], ?
            if insn.operands[0].reg == capstone.x86.X86_REG_RAX:
                logging.debug(f"Found push rax at 0x{insn.address:X}")
                next_insn = self.get_next_insn()
                if next_insn is not None and self._is_self_recursive_jump(next_insn):
                    next_next_insn = self.get_next_insn()
                    if next_next_insn is not None and next_next_insn.bytes.startswith(
                        b"\xc0\x58"
                    ):
                        decoded.dead_opaque_predicate = True
                        decoded.size = insn.size + next_insn.size + 2
                    return decoded
                else:
                    decoded.is_nop = True
                    return decoded
        # Handle LOOPNE instruction (opcode: E0) - loop while not equal/zero
        # When assembled as 'loopne near ptr $+5' it becomes: E0 03
        elif (
            capstone.CS_GRP_JUMP in insn.groups
            or insn.id == capstone.x86.X86_INS_LOOPNE
        ):
            if (
                len(insn.operands) > 0
                and insn.operands[0].type == capstone.x86.X86_OP_IMM
            ):
                decoded.is_jump = True
                decoded.jump_target = insn.operands[0].imm
        return decoded

    def _is_self_recursive_jump(self, insn: capstone.CsInsn) -> bool:
        """
        Heuristic detection of self-recursive jumps for Capstone.

        Args:
            insn: Capstone instruction object

        Returns:
            True if this appears to be a self-recursive jump
        """
        jump_source = insn.address
        # Pattern detection for common dead opaque predicates
        # EB FF - jump back 1 byte (into same instruction)
        if (
            insn.id == capstone.x86.X86_INS_JMP
            and len(insn.bytes) == 2
            and insn.bytes[0] == 0xEB
            and insn.bytes[1] == 0xFF
        ):
            logging.debug(f"Self-recursive jump detected: EB FF at 0x{jump_source:X}")
            return True

        return False


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
        visited: typing.Optional[set] = None,
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
            logging.debug(
                "%sJump chain stopped: Already visited 0x%X", indent, current_ea
            )
            return None
        # Check if start address is within the bounds defined by the Memory object
        if not (mem_start_ea <= current_ea < mem_end_ea):
            logging.debug(
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
                logging.debug(
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
            logging.debug("%soffset: %X", indent, offset)
            # We already know offset is >= 0 because trace_ea >= mem_start_ea
            # We need to ensure we have enough bytes left for *potential* instructions

            # Get bytes starting from the offset using the memoryview slice
            # Convert the slice to bytes for the decoder interface
            bytes_for_decoder = mem_view[offset:]
            if (
                not bytes_for_decoder
            ):  # Should not happen if bounds check is correct, but defensive check
                logging.warning(
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
                logging.error(
                    "%sDecoder function raised exception at 0x%X: %s",
                    indent,
                    trace_ea,
                    e,
                )
                decoded_insn = None  # Treat as decode failure

            # If decoding failed or decoder returned None
            if not decoded_insn:
                logging.debug(
                    "%sFailed to decode instruction at 0x%X. Stopping trace. Returning start: 0x%X",
                    indent,
                    trace_ea,
                    current_ea,
                )
                return current_ea  # Return start of the sequence

            # --- Process the decoded instruction ---
            if decoded_insn.is_nop:
                logging.debug(
                    "%sNOP found at 0x%X (size %X). Skipping.",
                    indent,
                    trace_ea,
                    decoded_insn.size,
                )
                trace_ea += decoded_insn.size
                continue  # Continue the while loop to the next instruction

            if decoded_insn.dead_opaque_predicate:
                logging.debug(
                    "%sDead opaque predicate found at 0x%X (size %X). Returning start: 0x%X.",
                    indent,
                    trace_ea,
                    decoded_insn.size,
                    current_ea,
                )
                return current_ea + decoded_insn.size

            if not decoded_insn.is_jump or decoded_insn.size != 2:
                logging.debug(
                    "%sChain stopped at 0x%X: Instruction is not a 2-byte jump. Returning start: 0x%X",
                    indent,
                    trace_ea,
                    current_ea,
                )
                return current_ea  # Return the start address of the sequence that ended

            # --- We have a 2-byte jump ---
            target = decoded_insn.jump_target
            if target is None:
                logging.debug(
                    "%sChain stopped at 0x%X: Instruction is a jump but has no target. Returning start: 0x%X",
                    indent,
                    trace_ea,
                    current_ea,
                )
                return current_ea

            logging.debug(
                "%s  -> Found 2-byte jump at 0x%X targeting 0x%X",
                indent,
                trace_ea,
                target,
            )

            # --- Decide action based on the jump target (using absolute addresses) ---
            # 1. Target is within the 'followable' range [match_start, match_end )
            if self.match_start <= target < match_end:
                logging.debug(
                    "%sFollowing jump from 0x%X to 0x%X (recursive call)",
                    indent,
                    trace_ea,
                    target,
                )
                # Pass the same Memory object and decoder down recursively
                return self.follow_jump_chain(
                    mem, target, match_end, decoder, visited, depth + 1
                )

            # 3. Target is within the overall Memory block, but *before* match_start.
            elif mem_start_ea <= target < self.match_start:
                logging.debug(
                    "%sJump chain ends: Target 0x%X is within Memory bounds [0x%X,0x%X) but outside followable range [0x%X, 0x%X). Returning target.",
                    indent,
                    target,
                    mem_start_ea,
                    mem_end_ea,
                    self.match_start,
                    match_end,
                )
                if depth == 0:  # this is a bs jump, ignore it.
                    return None
                return target  # Return the target address itself

            # 4. Target is out of the overall Memory bounds or otherwise unexpected.
            else:
                logging.debug(
                    "%sJump chain stopped: Target 0x%X is outside allowed ranges. Returning start address 0x%X",
                    indent,
                    target,
                    current_ea,
                )
                if depth == 0:  # this is a bs jump, ignore it.
                    return None
                return current_ea  # Return the start address of the sequence containing the invalid jump

    def _decode_stream(self, decoder, start, match_bytes):
        offset = 0
        n = len(match_bytes)

        while offset < n:
            try:
                # hand the decoder only the bytes we haven't consumed yet
                insn = decoder.decode(start + offset, match_bytes[offset:])
            except Exception as e:
                logging.error("Decode error @0x%X: %s", start + offset, e)
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
        match_end = chain.overall_start() + MAX_PATTERN_LEN
        logging.debug(
            "Processing jumps for chain @ 0x%X, match_end=0x%X",
            chain.overall_start(),
            match_end,
        )
        match chain.stage1_type:
            case SegmentType.STAGE1_SINGLE:
                if "jump_offset_in_segment" not in chain.segments[0].matched_groups:
                    logging.error(
                        "JumpTargetAnalyzer: 'jump_offset_in_segment' not found in matched_groups for STAGE1_SINGLE. Chain: %s",
                        chain,
                    )
                    return self  # or consider raising an error / returning empty to signify failure

                jump_offset_in_segment = chain.segments[0].matched_groups[
                    "jump_offset_in_segment"
                ]
                jump_ea = self.match_start + jump_offset_in_segment
                logging.debug(
                    "STAGE1_SINGLE: match_start=0x%X, jump_offset_in_segment=%d, calculated jump_ea=0x%X",
                    self.match_start,
                    jump_offset_in_segment,
                    jump_ea,
                )

            case SegmentType.STAGE1_MULTIPLE:
                # For multi-part, the first instruction in the chain *is* the jump.
                # The MatchChain's base_address (self.match_start here) is the jump_ea.
                jump_offset = 0
                jump_ea = self.match_start + jump_offset
                logging.debug(
                    "STAGE1_MULTIPLE: match_start=0x%X, jump_ea=0x%X",
                    self.match_start,
                    jump_ea,
                )
            case _:
                logging.error(
                    f"Invalid stage1_type: {chain.stage1_type} for chain: {chain}"
                )

        final_target = self.follow_jump_chain(mem, jump_ea, match_end, decoder)
        if not final_target:
            logging.debug(
                "  Skipping jump at 0x%X: Invalid final target 0x%X",
                jump_ea,
                final_target if final_target else 0,
            )
        else:
            self.jump_targets[final_target] += 1
            if final_target not in self.target_type:
                self.target_type[final_target] = chain.stage1_type
            self.jump_details.append((jump_ea, final_target, chain.stage1_type))
            logging.debug("Found jump @0x%X → 0x%X", jump_ea, final_target)
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


def resolve_overlaps(ranges: list[Range]) -> IntervalSet:
    """
    Fast, linear-time overlap resolution: keep only the first chain
    whose start is ≥ the furthest end so far.
    """
    logging.info(f"Resolving overlaps among {len(ranges)} ranges")
    intervals = IntervalSet()

    for r in ranges:
        intervals.add(r)

        # decide whether to keep the chain object itself
        last_end = intervals.as_tuples()[-1][1]  # rightmost byte so far
        target = r.end
        if target == last_end:  # this chain extended the interval set
            logging.info(f"  Accepted (or widened): {r.start:X}-{r.end:X}")
        else:
            logging.info(f"  Rejected overlap: {r.start:X}-{r.end:X}")

    return intervals


def find_obfuscation_patterns():
    logging.basicConfig(level=logging.INFO)
    PatternDetectionForm.show_pattern_detection_form(
        weakref.ref(find_obfuscation_patterns)
    )


class PatternDetectionForm(ida_kernwin.PluginForm):
    """
    Dockable container understood by IDA.
    We receive a weak-ref back to the plugin instance so we can
    tell it when the form is closed.
    """

    def __init__(self, plugin_ref, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._plugin_ref = plugin_ref  # weakref to pattern_detect_t

    # QWidget factory --------------------------------------------------
    def OnCreate(self, form):

        # Get the parent widget and ensure it fills space
        parent = self.FormToPyQtWidget(form)
        parent.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)  # type: ignore

        # Create layout for the parent
        parent_layout = QVBoxLayout(parent)
        parent_layout.setContentsMargins(0, 0, 0, 0)

        # Create and add our widget
        self.widget = PatternDetectionWidget(parent)
        parent_layout.addWidget(self.widget)
        return self.widget

    # tidy-up ----------------------------------------------------------
    def OnClose(self, form):
        plugin = self._plugin_ref()
        if plugin is not None:
            plugin._form = None  # allow GC to collect us

    @staticmethod
    def show_pattern_detection_form(plugin_ref):
        form = PatternDetectionForm(plugin_ref)
        # show the dockable widget
        # ida_kernwin.set_dock_pos(self.WINDOW_TITLE, "IDATopLevelDockArea", ida_kernwin.DP_RIGHT)
        form.Show(
            "Obfuscation Pattern Detection",
            ida_kernwin.PluginForm.WOPN_DP_RIGHT  # dock on the right; change to taste
            | ida_kernwin.PluginForm.WOPN_DP_SZHINT,
            # | ida_kernwin.PluginForm.WOPN_TAB,  # allow tab-docking
        )
        return form


# ---------------------------------------------------------------------
class pattern_detect_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "Pattern detector"
    wanted_hotkey = "Meta+P, H"

    def __init__(self):
        self._form: PatternDetectionForm | None = None

    # helper -----------------------------------------------------------
    def _ensure_form(self) -> PatternDetectionForm:
        if self._form is None:  # not created yet
            self._form = PatternDetectionForm.show_pattern_detection_form(
                weakref.ref(self)
            )
        return self._form

    # plugin entry-point ----------------------------------------------
    def run(self, arg):
        form = self._ensure_form()
        if form:
            ida_kernwin.activate_widget(form, True)  # just bring it to front


def PLUGIN_ENTRY():  # IDA looks for this symbol
    return pattern_detect_t()


if __name__ == "__main__":
    PatternDetectionForm.show_pattern_detection_form(weakref.ref(PatternDetectionForm))
