from __future__ import annotations

"""
Optimized Capstone-based instruction pattern detection for x86 obfuscation patterns.
Uses IDA's fast signature search to locate candidates, then verifies with Capstone.
"""

import inspect
import logging
import time
import types
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Iterator, List, Optional, Tuple

from PyQt5.QtCore import QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QFont

# Qt imports
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
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

# --- Pattern Detection Core Classes (must be defined first) ---


class PatternCategory(Enum):
    MULTI_PART = auto()
    SINGLE_PART = auto()
    JUNK = auto()


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


@dataclass
class PatternDetector:
    """Base class for instruction pattern detection using Capstone."""

    cs: capstone.Cs = field(
        default_factory=lambda: capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    )

    def __post_init__(self):
        """Initialize capstone with detailed instruction information."""
        self.cs.detail = True


# --- Utility Classes ---


class UserCanceledError(Exception):
    pass


class PatternDetectionWorker(QThread):
    """Worker thread for Capstone analysis only - IDA API calls must be on main thread."""

    analysis_completed = pyqtSignal(list)  # List of PatternMatch objects from analysis
    error_occurred = pyqtSignal(str)  # Error message

    def __init__(self, parent=None):
        super().__init__(parent)
        self.candidates_data = []  # List of (candidate_ea, region_bytes, base_address)
        self.matcher = None
        self._canceled = False

    def set_data(self, candidates_data, matcher):
        """Set the candidate data and matcher for analysis."""
        self.candidates_data = candidates_data
        self.matcher = matcher

    def cancel(self):
        self._canceled = True

    def run(self):
        """Analyze candidates using Capstone (no IDA API calls here)."""
        try:
            all_matches = []

            for candidate_ea, region_bytes, base_address in self.candidates_data:
                if self._canceled:
                    break

                # Pure Capstone analysis - no IDA API calls
                matches = self.matcher.analyze_candidate_region_bytes(
                    region_bytes, base_address, candidate_ea
                )
                all_matches.extend(matches)

            # Remove duplicates
            unique_matches = []
            seen_addresses = set()
            for match in all_matches:
                if match.ida_address not in seen_addresses:
                    unique_matches.append(match)
                    seen_addresses.add(match.ida_address)

            self.analysis_completed.emit(unique_matches)

        except Exception as e:
            self.error_occurred.emit(str(e))


class PatternDetectionDialog(QDialog):
    """Main dialog for pattern detection with progress tracking and results display."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Obfuscation Pattern Detection")
        self.setMinimumSize(900, 600)
        self.setWindowFlags(
            Qt.Window
            | Qt.WindowMinimizeButtonHint
            | Qt.WindowMaximizeButtonHint
            | Qt.WindowCloseButtonHint
        )

        self.worker = PatternDetectionWorker()
        self.matcher = None  # Will be set to FastPatternMatcher when needed
        self.all_patterns = []
        self.start_time = None
        self.next_prompt_time = 120

        # Timer-based processing for main thread
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.process_next_batch)
        self.candidates = []
        self.current_candidate_idx = 0
        self.candidates_data = []  # For worker thread

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout()

        # Control section
        control_group = QGroupBox("Detection Control")
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Detection")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)

        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.cancel_btn)
        control_layout.addStretch()
        control_group.setLayout(control_layout)

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

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(
            ["Address", "Category", "Description", "Pattern Name", "Instructions"]
        )

        # Make table sortable and resizable
        self.results_table.setSortingEnabled(True)
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(
            2, QHeaderView.Stretch
        )  # Description column stretches

        results_layout.addWidget(self.results_table)

        # Summary
        self.summary_label = QLabel("No patterns detected yet.")
        results_layout.addWidget(self.summary_label)

        results_group.setLayout(results_layout)

        # Layout assembly
        splitter = QSplitter(Qt.Vertical)

        top_widget = QWidget()
        top_layout = QVBoxLayout()
        top_layout.addWidget(control_group)
        top_layout.addWidget(progress_group)
        top_widget.setLayout(top_layout)

        splitter.addWidget(top_widget)
        splitter.addWidget(results_group)
        splitter.setSizes([200, 400])  # Give more space to results

        layout.addWidget(splitter)
        self.setLayout(layout)

    def connect_signals(self):
        """Connect UI signals."""
        self.start_btn.clicked.connect(self.start_detection)
        self.cancel_btn.clicked.connect(self.cancel_detection)
        self.filter_input.textChanged.connect(self.apply_filters)
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        self.clear_filter_btn.clicked.connect(self.clear_filters)
        self.results_table.cellDoubleClicked.connect(self.goto_pattern)

        # Worker signals
        self.worker.analysis_completed.connect(self.analysis_finished)
        self.worker.error_occurred.connect(self.handle_error)

    def start_detection(self):
        """Start pattern detection on main thread."""
        try:
            # Create matcher when needed to avoid forward reference issues
            if not self.matcher:
                self.matcher = FastPatternMatcher()

            # Get text segment (must be on main thread)
            text_seg = ida_segment.get_segm_by_name(".text")
            if not text_seg:
                self.handle_error("Could not find .text segment")
                return

            self.start_btn.setEnabled(False)
            self.cancel_btn.setEnabled(True)
            self.progress_bar.setValue(0)
            self.all_patterns.clear()
            self.results_table.setRowCount(0)
            self.start_time = time.time()
            self.next_prompt_time = 120

            self.progress_label.setText("Searching for pattern candidates...")

            # Phase 1: Fast candidate search (main thread)
            logging.info(
                "Starting optimized pattern detection in .text segment (0x%x - 0x%x)",
                text_seg.start_ea,
                text_seg.end_ea,
            )

            self.candidates = self.matcher.find_pattern_candidates(
                text_seg.start_ea, text_seg.end_ea
            )
            logging.info("Found %d potential pattern candidates", len(self.candidates))

            if not self.candidates:
                self.detection_finished([])
                return

            self.progress_bar.setValue(10)

            # Phase 2: Prepare data for analysis
            self.current_candidate_idx = 0
            self.candidates_data = []

            # Start timer-based processing for candidate preparation
            self.progress_label.setText("Preparing candidate data...")
            self.process_timer.start(10)  # Process every 10ms

        except Exception as e:
            self.handle_error(str(e))

    def process_next_batch(self):
        """Process a batch of candidates on main thread."""
        try:
            batch_size = 5  # Process 5 candidates per timer tick
            batch_end = min(
                self.current_candidate_idx + batch_size, len(self.candidates)
            )

            for i in range(self.current_candidate_idx, batch_end):
                candidate_ea = self.candidates[i]

                # Get bytes from IDA (must be on main thread)
                region_size = 100
                start_ea = max(candidate_ea - region_size, ida_ida.inf_get_min_ea())
                end_ea = min(candidate_ea + region_size, ida_ida.inf_get_max_ea())

                try:
                    region_bytes = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
                    if region_bytes:
                        self.candidates_data.append(
                            (candidate_ea, region_bytes, start_ea)
                        )
                except Exception as e:
                    logging.warning(
                        "Error getting bytes for candidate at 0x%x: %s", candidate_ea, e
                    )
                    continue

            self.current_candidate_idx = batch_end

            # Update progress
            progress = int(
                10 + (self.current_candidate_idx / len(self.candidates)) * 40
            )  # 10-50% for preparation
            self.progress_bar.setValue(progress)
            self.progress_label.setText(
                f"Preparing data for candidate {self.current_candidate_idx}/{len(self.candidates)}"
            )

            # Check for user cancellation and time prompts
            elapsed_time = time.time() - self.start_time
            if elapsed_time >= self.next_prompt_time:
                self.process_timer.stop()
                minutes = int(elapsed_time / 60)
                seconds = int(elapsed_time % 60)
                time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

                reply = QMessageBox.question(
                    self,
                    "Continue Detection?",
                    f"Pattern detection has been running for {time_str}.\n\nContinue?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if reply == QMessageBox.No:
                    self.cancel_detection()
                    return
                else:
                    self.next_prompt_time *= 2
                    logging.info(
                        "Next prompt will be at %d seconds (%.1f minutes)",
                        self.next_prompt_time,
                        self.next_prompt_time / 60.0,
                    )
                    self.process_timer.start(10)  # Resume processing

            # Check if we're done preparing data
            if self.current_candidate_idx >= len(self.candidates):
                self.process_timer.stop()
                self.start_analysis_phase()

        except Exception as e:
            self.process_timer.stop()
            self.handle_error(str(e))

    def start_analysis_phase(self):
        """Start the Capstone analysis phase in worker thread."""
        self.progress_label.setText("Starting Capstone analysis...")
        self.progress_bar.setValue(50)

        # Now we can safely use the worker thread for pure Capstone analysis
        self.worker.set_data(self.candidates_data, self.matcher)
        self.worker.start()

    def cancel_detection(self):
        """Cancel ongoing detection."""
        self.process_timer.stop()
        self.worker.cancel()
        self.worker.wait()
        self.detection_finished([])

    def analysis_finished(self, patterns: List[PatternMatch]):
        """Handle analysis completion from worker thread."""
        self.all_patterns = patterns
        self.refresh_results_table()
        self.detection_finished(patterns)

    def add_pattern_to_results(self, pattern: PatternMatch):
        """Add a newly found pattern to the results table."""
        if pattern not in self.all_patterns:
            self.all_patterns.append(pattern)
            self.refresh_results_table()

    def detection_finished(self, patterns: List[PatternMatch]):
        """Handle detection completion."""
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

    def refresh_results_table(self):
        """Refresh the results table with current patterns."""
        # Apply current filters
        filtered_patterns = self.get_filtered_patterns()

        self.results_table.setRowCount(len(filtered_patterns))

        for row, pattern in enumerate(filtered_patterns):
            # Address
            addr_item = QTableWidgetItem(f"0x{pattern.ida_address:08x}")
            addr_item.setData(Qt.UserRole, pattern.ida_address)  # Store for sorting
            self.results_table.setItem(row, 0, addr_item)

            # Category
            cat_item = QTableWidgetItem(pattern.category.name.replace("_", "-").title())
            self.results_table.setItem(row, 1, cat_item)

            # Description
            desc_item = QTableWidgetItem(pattern.description)
            self.results_table.setItem(row, 2, desc_item)

            # Pattern name
            name_item = QTableWidgetItem(pattern.pattern_name)
            self.results_table.setItem(row, 3, name_item)

            # Instructions (abbreviated)
            insn_text = " ; ".join(
                [f"{insn.mnemonic} {insn.op_str}" for insn in pattern.instructions[:3]]
            )
            if len(pattern.instructions) > 3:
                insn_text += " ; ..."
            insn_item = QTableWidgetItem(insn_text)
            self.results_table.setItem(row, 4, insn_item)

        self.update_summary()

    def get_filtered_patterns(self) -> List[PatternMatch]:
        """Get patterns that match current filters."""
        patterns = self.all_patterns

        # Text filter
        text_filter = self.filter_input.text().lower()
        if text_filter:
            patterns = [
                p
                for p in patterns
                if text_filter in p.description.lower()
                or text_filter in p.pattern_name.lower()
                or text_filter in f"{p.ida_address:08x}"
            ]

        # Category filter
        category_filter = self.category_filter.currentText()
        if category_filter != "All Categories":
            category_map = {
                "Multi-Part": PatternCategory.MULTI_PART,
                "Single-Part": PatternCategory.SINGLE_PART,
                "Junk": PatternCategory.JUNK,
            }
            if category_filter in category_map:
                patterns = [
                    p for p in patterns if p.category == category_map[category_filter]
                ]

        return patterns

    def apply_filters(self):
        """Apply current filters to results table."""
        self.refresh_results_table()

    def clear_filters(self):
        """Clear all filters."""
        self.filter_input.clear()
        self.category_filter.setCurrentText("All Categories")

    def update_summary(self):
        """Update the summary label."""
        total = len(self.all_patterns)
        filtered = self.results_table.rowCount()

        if total == 0:
            self.summary_label.setText("No patterns detected yet.")
        elif filtered == total:
            self.summary_label.setText(f"Found {total} patterns total.")
        else:
            self.summary_label.setText(f"Showing {filtered} of {total} patterns.")

    def goto_pattern(self, row: int, column: int):
        """Navigate to the selected pattern in IDA."""
        addr_item = self.results_table.item(row, 0)
        if addr_item:
            address = addr_item.data(Qt.UserRole)
            if isinstance(address, int):
                idaapi.jumpto(address)

    def handle_error(self, error_msg: str):
        """Handle detection errors."""
        self.process_timer.stop()
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Error occurred during detection.")
        QMessageBox.critical(
            self, "Detection Error", f"An error occurred:\n{error_msg}"
        )

    def handle_error(self, error_msg: str):
        """Handle detection errors."""
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_label.setText("Error occurred during detection.")
        QMessageBox.critical(
            self, "Detection Error", f"An error occurred:\n{error_msg}"
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


def find_byte_sequence(
    start: int,
    end: int,
    seq: list[int] | bytes,
    direction: int = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
) -> Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        start: min virtual address
        end: max virtual address
        seq: bytes to search e.g. b"\x01\x03"
    """
    patterns = ida_bytes.compiled_binpat_vec_t()

    if isinstance(seq, list):
        seqstr = " ".join([f"{b:02x}" if b != -1 else "?" for b in seq])
    else:
        seqstr = seq.hex()

    err = ida_bytes.parse_binpat_str(
        patterns,
        start,
        seqstr,
        16,
        ida_nalt.get_default_encoding_idx(  # use one byte-per-character encoding
            ida_nalt.BPU_1B
        ),
    )

    if err:
        return

    while True:
        ea = ida_bytes.bin_search(start, end, patterns, direction)
        ea = ea[0]
        if ea == idaapi.BADADDR:
            break
        start = ea + 1
        yield ea


# --- Pattern Detection Classes ---


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
        """Find patterns in a small byte sequence."""
        patterns = []

        try:
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
                            # Found complementary jump pair
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
                            )
                            patterns.append(pattern)
                            break

                # Look for single-part patterns (prefix + jump)
                if self._is_prefix_instruction(first_insn):
                    # Look for conditional jump within next few instructions
                    for j in range(i + 1, min(i + 4, len(instructions))):
                        jump_insn = instructions[j]

                        if self._is_conditional_jump(jump_insn):
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
                            )
                            patterns.append(pattern)
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

        for candidate_ea in candidates:
            matches = self.analyze_candidate_region(candidate_ea)
            all_matches.extend(matches)

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


# Main usage functions
def show_pattern_detection_dialog():
    """Show the pattern detection dialog."""
    dialog = PatternDetectionDialog()
    dialog.exec_()
    return dialog


def find_obfuscation_patterns():
    """Main function to find all obfuscation patterns - now with GUI."""
    logging.basicConfig(level=logging.INFO)

    # Show the modern Qt dialog instead of console output
    dialog = show_pattern_detection_dialog()
    return dialog.all_patterns


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


# Example usage
if __name__ == "__main__":
    # Show the modern Qt-based pattern detection dialog
    dialog = show_pattern_detection_dialog()
    print(f"Detection complete. Found {len(dialog.all_patterns)} patterns.")

    # Alternative: Use the legacy console-based detection
    # patterns = find_obfuscation_patterns_console()
    # print(f"Detection complete. Found {len(patterns)} patterns.")
