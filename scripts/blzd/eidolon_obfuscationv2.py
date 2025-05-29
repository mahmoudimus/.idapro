from __future__ import annotations

import datetime
import json
import weakref

"""
Optimized Capstone-based instruction pattern detection for x86 obfuscation patterns.
Uses IDA's fast signature search to locate candidates, then verifies with Capstone.
Includes junk instruction filtering to reduce false positives.
"""

import inspect
import logging
import re
import sys  # For sys.exc_info()
import time
import traceback  # For formatting traceback
import types
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Iterator, List, Optional, Tuple

from PyQt5.QtCore import (
    QModelIndex,
    QObject,
    QRegularExpression,
    QRunnable,
    QSize,
    QSortFilterProxyModel,
    Qt,
    QThread,
    QThreadPool,
    QTimer,
    pyqtSignal,
)
from PyQt5.QtGui import QFont, QStandardItem, QStandardItemModel

# Qt imports
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
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
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

import ida_bytes
import ida_ida

# IDA imports
import ida_kernwin
import ida_nalt
import ida_segment
import idaapi

import capstone

# ----------------------------------------------------------------------
# Toggle Capstone verification on/off (handy for profiling)
# ----------------------------------------------------------------------
USE_CAPSTONE = True  # ← flip to True to restore Capstone analysis


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


class PatternDetectionWidget(QWidget):
    """Main dialog for pattern detection with progress tracking and results display."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Obfuscation Pattern Detection")
        self.setMinimumHeight(600)
        self.setMinimumWidth(900)
        # self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.matcher = None  # Will be set to FastPatternMatcher when needed
        self.all_patterns = []
        self.start_time = None
        self.next_prompt_time = 120
        self.enable_continue_prompt = False
        self.text_segment_bytes: Optional[bytes] = None
        self.text_segment_start_ea: int = 0

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
        layout = QVBoxLayout()

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

        self.proxy_model = CustomFilterProxyModel(
            self
        )  # Parent `self` for QObject management
        self.proxy_model.setSourceModel(self.source_model)
        self.results_tree_view.setModel(self.proxy_model)

        header = self.results_tree_view.header()
        # allow the user to drag‐resize any column, and even reorder them
        header.setSectionsClickable(True)
        header.setSectionsMovable(True)

        # default to Interactive so users can drag edges
        header.setSectionResizeMode(QHeaderView.Interactive)

        # auto‐grab all free space in these two human‐readable columns:
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Description
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # Instructions

        # ensure the very last section also expands into any leftover pixels
        header.setStretchLastSection(True)

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
        self.start_btn.clicked.connect(self.start_detection)
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

    def start_detection(self):
        """Start pattern detection on main thread."""
        try:
            if not self.matcher:
                self.matcher = FastPatternMatcher()

            text_seg = ida_segment.get_segm_by_name(".text")
            if not text_seg:
                self.handle_error("Could not find .text segment")
                return

            self.text_segment_start_ea = text_seg.start_ea
            try:
                segment_size = text_seg.end_ea - text_seg.start_ea
                self.text_segment_bytes = ida_bytes.get_bytes(
                    self.text_segment_start_ea, segment_size
                )
                if not self.text_segment_bytes:
                    self.handle_error("Failed to read .text segment bytes.")
                    return
                logging.info(
                    "Successfully read %d bytes from .text segment (0x%x - 0x%x)",
                    len(self.text_segment_bytes),
                    text_seg.start_ea,
                    text_seg.end_ea,
                )
            except Exception as e:
                self.handle_error(f"Error reading .text segment: {e}")
                return

            self.start_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.progress_bar.setValue(0)
            self.all_patterns.clear()
            self.source_model.removeRows(0, self.source_model.rowCount())
            self.start_time = time.time()
            self.time_label.setText("Elapsed: 0s")  # Reset display at start
            self.ui_update_timer.start(
                1000
            )  # Start UI update timer (1 second interval)
            self.next_prompt_time = 120

            self.progress_label.setText("Searching for pattern candidates...")

            self.candidates = self.matcher.find_pattern_candidates(
                text_seg.start_ea, text_seg.end_ea
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

            for idx, candidate_ea in enumerate(self.candidates):
                if self.cancel_btn.isEnabled() == False:  # Check if cancelled
                    logging.info("Data preparation cancelled.")
                    self.detection_finished([])  # Or handle cancellation more formally
                    return

                # Slicing logic from old process_next_batch
                region_size_before = 50
                region_size_after = 50
                max_total_region_size = 100
                candidate_offset_in_segment = candidate_ea - self.text_segment_start_ea
                slice_start_offset = max(
                    0, candidate_offset_in_segment - region_size_before
                )
                slice_end_offset = min(
                    len(self.text_segment_bytes),
                    candidate_offset_in_segment + region_size_after,
                )
                current_slice_len = slice_end_offset - slice_start_offset
                if current_slice_len > max_total_region_size:
                    excess = current_slice_len - max_total_region_size
                    shrink_before = excess // 2
                    shrink_after = excess - shrink_before
                    temp_slice_start = slice_start_offset + shrink_before
                    temp_slice_end = slice_end_offset - shrink_after
                    if candidate_offset_in_segment < temp_slice_start:
                        temp_slice_start = candidate_offset_in_segment
                        temp_slice_end = temp_slice_start + max_total_region_size
                    elif candidate_offset_in_segment >= temp_slice_end:
                        temp_slice_end = candidate_offset_in_segment + 1
                        temp_slice_start = temp_slice_end - max_total_region_size
                    slice_start_offset = max(0, temp_slice_start)
                    slice_end_offset = min(len(self.text_segment_bytes), temp_slice_end)

                region_bytes_slice = self.text_segment_bytes[
                    slice_start_offset:slice_end_offset
                ]
                slice_base_ea = self.text_segment_start_ea + slice_start_offset

                if region_bytes_slice:
                    self.candidates_data.append(
                        (candidate_ea, region_bytes_slice, slice_base_ea)
                    )
                else:
                    logging.warning(
                        "Empty byte slice for candidate at 0x%x (offset %d, slice %d:%d in segment)",
                        candidate_ea,
                        candidate_offset_in_segment,
                        slice_start_offset,
                        slice_end_offset,
                    )

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

                # Check for user prompt to continue (if enabled and time elapsed)
                if self.start_time is not None and self.enable_continue_prompt:
                    elapsed_time = time.time() - self.start_time
                    if elapsed_time >= self.next_prompt_time:
                        minutes = int(elapsed_time / 60)
                        seconds = int(elapsed_time % 60)
                        time_str = (
                            f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
                        )
                        reply = QMessageBox.question(
                            self,
                            "Continue Detection?",
                            f"Data preparation has been running for {time_str}.\n\nThis phase processes {total_candidates} candidates.\nContinue?",
                            QMessageBox.Yes | QMessageBox.No,
                            QMessageBox.No,
                        )
                        if reply == QMessageBox.No:
                            self.cancel_detection()  # This will set cancel_btn state
                            return
                        else:
                            self.next_prompt_time *= 2  # Postpone next prompt
                            logging.info(
                                "Next prompt will be at %d seconds (%.1f minutes)",
                                self.next_prompt_time,
                                self.next_prompt_time / 60.0,
                            )
                            # No timer to restart, loop continues

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
                f"{base_text} (Processed: {analysis_phase_percentage_float}%)"
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
        self.detection_finished([])

    def analysis_finished(self, patterns: List[PatternMatch]):
        """Handle analysis completion from worker thread OR all runnables."""
        self.all_patterns = patterns
        self._populate_model_from_patterns()
        self.detection_finished(patterns)
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


# Legacy compatibility classes (simplified)
class ProgressDialog:
    """Legacy compatibility wrapper."""

    def __init__(self, message="Please wait...", hide_cancel=False):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def replace_message(self, new_message, hide_cancel=False):
        pass

    def user_canceled(self):
        return False


class ida_tguidm:
    """Legacy compatibility wrapper - now handled by Qt dialog."""

    def __init__(self, iterable, total=None, initial=0):
        self.iterable = iterable

    def __iter__(self):
        return iter(self.iterable)


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
    JunkPatternMetadata(rb"(?P<junk>[\x66\x90]\x90)", "Two-byte NOP"),
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
            region_matches = self._find_patterns_in_bytes(
                analysis_bytes, base_address + analysis_start
            )

            # Filter matches that are close to our candidate
            for match in region_matches:
                if abs(match.ida_address - candidate_ea) <= 20:  # Within 20 bytes
                    matches.append(match)

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
                                    "Valid multi-part pattern found: %s with %d junk instructions (%d bytes)",
                                    pattern.description,
                                    junk_count,
                                    junk_bytes,
                                )
                            else:
                                logging.debug(
                                    "Rejected multi-part pattern %s -> %s: insufficient junk (%d < 4)",
                                    first_insn.mnemonic,
                                    second_insn.mnemonic,
                                    junk_count,
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
                                    "Valid single-part pattern found: %s with %d junk instructions (%d bytes)",
                                    pattern.description,
                                    junk_count,
                                    junk_bytes,
                                )
                            else:
                                logging.debug(
                                    "Rejected single-part pattern %s -> %s: insufficient junk (%d < 4)",
                                    first_insn.mnemonic,
                                    jump_insn.mnemonic,
                                    junk_count,
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

    def find_all_patterns_optimized(self) -> List[PatternMatch]:
        """Main optimized pattern finding function - simplified for Qt integration."""
        all_matches = []

        # Get text segment
        text_seg = ida_segment.get_segm_by_name(".text")
        if not text_seg:
            logging.error("Could not find .text segment")
            return all_matches

        logging.info(
            "Starting optimized pattern detection in .text segment (0x%x - 0x%x)",
            text_seg.start_ea,
            text_seg.end_ea,
        )

        # Phase 1: Fast candidate search
        candidates = self.find_pattern_candidates(text_seg.start_ea, text_seg.end_ea)
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


# Legacy console function for backwards compatibility
def find_obfuscation_patterns_console():
    """Legacy console-based pattern detection."""
    logging.basicConfig(level=logging.INFO)

    matcher = FastPatternMatcher()
    matches = matcher.find_all_patterns_optimized()

    # Display results
    if matches:
        logging.info("\n=== Pattern Detection Results ===")
        for i, match in enumerate(matches):
            logging.info("%d. %s at 0x%x", i + 1, match.description, match.ida_address)
            for insn in match.instructions:
                logging.info("   %s %s", insn.mnemonic, insn.op_str)
            logging.info("")
    else:
        logging.info("No obfuscation patterns found.")

    return matches


# Main usage functions


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
        parent = self.FormToPyQtWidget(form)
        self.widget = PatternDetectionWidget(parent)  # <- your QWidget
        return self.widget

    # tidy-up ----------------------------------------------------------
    def OnClose(self, form):
        plugin = self._plugin_ref()
        if plugin is not None:
            plugin._form = None  # allow GC to collect us

    @staticmethod
    def show_pattern_detection_form(plugin_ref):
        form = PatternDetectionForm(plugin_ref)

        form.Show(
            "Obfuscation Pattern Detection",
            ida_kernwin.PluginForm.WOPN_DP_RIGHT  # dock on the right; change to taste
            | ida_kernwin.PluginForm.WOPN_PERSIST  # reopen with the database
            | ida_kernwin.PluginForm.WOPN_DP_SZHINT  # use the widget's size hint to determine the best geometry (Qt only)
            | ida_kernwin.PluginForm.WOPN_TAB,  # allow tab-docking
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


# Example usage
if __name__ == "__main__":
    # Show the modern Qt-based pattern detection dialog with junk filtering
    PatternDetectionForm.show_pattern_detection_form(weakref.ref(PatternDetectionForm))

    # Alternative: Use the legacy console-based detection
    # patterns = find_obfuscation_patterns_console()
    # print(f"Detection complete. Found {len(patterns)} patterns.")
