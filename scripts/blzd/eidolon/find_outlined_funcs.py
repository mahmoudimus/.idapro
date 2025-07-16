import abc
import dataclasses
import logging

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

import ida_allins
import ida_bytes
import ida_funcs
import ida_idp
import ida_kernwin
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

# Configure logging to display in the IDA output window
logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("OutlinedFuncDetector")


@dataclasses.dataclass
class CandidateFunction:
    """Holds the state for a function that might be outlined."""

    address: int
    name: str
    score: int
    confirmed: bool = False
    visited: bool = False


class Heuristic(abc.ABC):
    """Abstract base class for a heuristic used to score a function."""

    def __init__(self, weight: int):
        """
        Initializes the heuristic with a given weight.
        :param weight: The score to award if the heuristic passes.
        """
        self.weight = weight

    @abc.abstractmethod
    def __call__(self, func_ea: int) -> int:
        """
        Executes the heuristic against a function.
        :param func_ea: The starting address of the function.
        :return: The heuristic's weight if it passes, 0 otherwise.
        """
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(weight={self.weight})"


class IsLinearFlowHeuristic(Heuristic):
    """Heuristic: Checks if the function has a linear control flow (no branches)."""

    def __call__(self, func_ea: int) -> int:
        """
        A simple outlined function should not have complex branches.
        It returns the weight if the function has at most one successor per basic block.
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0
        try:
            flowchart = idaapi.FlowChart(func)
            for block in flowchart:
                if len(list(block.succs())) > 1:
                    return 0  # Found a conditional branch
        except Exception as e:
            log.warning(
                "Could not create flowchart for function at 0x%x: %s",
                func_ea,
                e,
            )
            return 0
        return self.weight


class NoCallsHeuristic(Heuristic):
    """Heuristic: Checks that the function is a leaf function (contains no calls)."""

    def __call__(self, func_ea: int) -> int:
        """
        Outlined functions are typically leaf functions.
        Returns the weight if no 'call' instructions are found.
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0
        for head in idautils.Heads(func.start_ea, func.end_ea):
            # In modern IDAPython, it's safer to decode the instruction
            # and pass the insn_t object to analysis functions.
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) > 0:
                if insn.itype == ida_allins.NN_null:
                    log.warning(
                        "Found null instruction at 0x%x in function at 0x%x",
                        head,
                        func_ea,
                    )
                    continue
                if ida_idp.is_call_insn(insn):
                    return 0
        return self.weight


class IsSmallHeuristic(Heuristic):
    """Heuristic: Checks if the function has a small number of effective instructions."""

    # --- NOP Sequences ---
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

    @staticmethod
    def _is_nop_instruction(insn: ida_ua.insn_t | None) -> bool:
        """Checks if the decoded instruction is a known NOP."""
        if not insn:
            return False
        # Check for the canonical NOP instruction type
        if insn.itype == ida_allins.NN_nop:
            return True
        # Check for multi-byte NOPs by comparing their byte sequences
        insn_bytes = ida_bytes.get_bytes(insn.ea, insn.size)
        if not insn_bytes:
            return False
        # Use a generator expression for efficiency
        return any(
            insn_bytes == seq
            for seq in IsSmallHeuristic._NOP_SEQUENCES
            if len(seq) == insn.size
        )

    def __init__(self, weight: int, max_effective_insns: int):
        super().__init__(weight)
        self.max_effective_insns = max_effective_insns

    def __call__(self, func_ea: int) -> int:
        """
        Returns the weight if the count of "work" instructions is within the threshold.
        "Work" instructions exclude NOPs, simple stack management, and returns.
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0

        effective_insn_count = 0
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) <= 0:
                log.warning(
                    "Could not decode instruction at 0x%x in function at 0x%x",
                    head,
                    func_ea,
                )
                return -1000
            if insn.itype == ida_allins.NN_null:
                log.warning(
                    "Found null instruction at 0x%x in function at 0x%x",
                    head,
                    func_ea,
                )
                return -1000
            # Exclude NOPs, stack management, and return instructions from the count.
            # This prevents flagging empty functions that only save/restore registers.
            if self._is_nop_instruction(insn) or ida_idp.is_ret_insn(head):
                continue

            # Use the modern API to get the instruction mnemonic
            mnem = idc.print_insn_mnem(head).lower()
            if mnem in ("push", "pop", "leave"):
                continue

            effective_insn_count += 1

        # A function must have at least one effective instruction to be considered.
        if 0 < effective_insn_count <= self.max_effective_insns:
            return self.weight
        return 0


class EndsWithRetHeuristic(Heuristic):
    """Heuristic: Checks that the function's last instruction is a return."""

    def __call__(self, func_ea: int) -> int:
        """
        Returns the weight if the function terminates with a 'ret' instruction.
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0
        last_head = idc.prev_head(func.end_ea)
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, last_head) <= 0:
            log.warning(
                "Could not decode instruction at 0x%x in function at 0x%x",
                last_head,
                func_ea,
            )
            return -1000
        if insn.itype == ida_allins.NN_null:
            log.warning(
                "Found null instruction at 0x%x in function at 0x%x",
                last_head,
                func_ea,
            )
            return -1000
        if last_head and ida_idp.is_ret_insn(last_head):
            return self.weight
        return 0


class IsNotJmpThunkHeuristic(Heuristic):
    """Heuristic: Penalizes functions that end in a JMP (likely a tail-call thunk)."""

    def __call__(self, func_ea: int) -> int:
        """
        Returns a large negative weight if the function's last instruction is a JMP,
        especially one to an external symbol.
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0

        last_head = idc.prev_head(func.end_ea)
        if not last_head:
            return 0

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, last_head) <= 0:
            log.warning(
                "Could not decode instruction at 0x%x in function at 0x%x",
                last_head,
                func_ea,
            )
            return -1000

        # Check if the last instruction is a jump.
        if insn.itype in (
            ida_allins.NN_jmp,
            ida_allins.NN_jmpfi,
            ida_allins.NN_jmpni,
            ida_allins.NN_jmpshort,
        ):
            # This is likely a tail-call thunk, not an outlined function.
            # We can be even more certain if it jumps to an external symbol.
            if insn.Op1.type == ida_ua.o_mem:
                op_addr = insn.Op1.addr
                seg: ida_segment.segment_t = ida_segment.getseg(op_addr)
                if seg and seg.type == ida_segment.SEG_XTRN:
                    # Definitely a thunk to an external function. Penalize heavily.
                    return self.weight

            # Penalize any JMP-terminated function, as it's not a simple snippet.
            return self.weight

        return 0


class SmallFrameHeuristic(Heuristic):
    """Heuristic: Checks that the function has a minimal stack frame."""

    def __init__(self, weight: int, max_frame_size: int):
        super().__init__(weight)
        self.max_frame_size = max_frame_size

    def __call__(self, func_ea: int) -> int:
        """
        Returns the weight if the function's stack frame size is within the threshold.
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0

        frame_tif = ida_typeinf.tinfo_t()
        # get_func_frame returns false if there is no frame.
        # In that case, the frame size is effectively 0, which passes the check.
        if not frame_tif.get_func_frame(func):
            return self.weight

        # tinfo_t.get_size() returns the size in bytes.
        # It returns BAD_SIZE (-1) on error.
        frame_size = frame_tif.get_size()
        if (
            frame_size
            in (
                0,
                None,
            )
            or frame_size > self.max_frame_size
        ):
            return 0

        return self.weight


class IsNotLibOrThunkHeuristic(Heuristic):
    """Heuristic: Penalizes functions that are already marked as library or thunk."""

    def __call__(self, func_ea: int) -> int:
        """
        Returns a large negative weight if the function is a library or thunk function,
        effectively disqualifying it. Otherwise, returns 0.
        """
        flags = idc.get_func_flags(func_ea)
        if flags & (idc.FUNC_LIB | idc.FUNC_THUNK):
            return self.weight  # This is a penalty, so weight should be negative
        return 0


class OutlinedFunctionDetector:
    """Detects outlined functions by scoring them and returning a list of candidates."""

    def __init__(self, heuristics: list[Heuristic], score_threshold: int):
        """
        Initializes the detector with a list of heuristics and a score threshold.

        :param heuristics: A list of callable Heuristic objects.
        :param score_threshold: The minimum score for a function to be considered outlined.
        """
        self.heuristics = heuristics
        self.score_threshold = score_threshold
        log.info(
            "Detector initialized with %d heuristics and score threshold of %d",
            len(heuristics),
            score_threshold,
        )

    def find_all(self) -> list[CandidateFunction]:
        """
        Finds all likely outlined functions and returns them as a list.
        :return: A list of CandidateFunction objects.
        """
        log.info("Starting scan for outlined functions...")
        candidates = []
        for func_ea in idautils.Functions():
            if idc.get_func_flags(func_ea) & idc.FUNC_OUTLINE:
                continue

            try:
                score = sum(h(func_ea) for h in self.heuristics)
            except Exception as e:
                log.error(
                    "Error %s in this function: %s - skipping!",
                    e,
                    hex(func_ea),
                    exc_info=True,
                )
                continue

            if score >= self.score_threshold:
                candidates.append(
                    CandidateFunction(
                        address=func_ea, name=idc.get_func_name(func_ea), score=score
                    )
                )
        log.info(
            "Scan complete. Found %d potential outlined functions.", len(candidates)
        )
        return candidates


# =============================================================================
# PyQt GUI Components
# =============================================================================
class OutlinedFunctionTableModel(QAbstractTableModel):
    """A Qt Table Model to manage the list of candidate functions."""

    _HEADERS = ["Confirmed", "Address", "Name", "Score"]
    _VISITED_COLOR = QColor(0xE0, 0xE0, 0xF8)  # A light lavender color

    def __init__(self, data: list[CandidateFunction]):
        super().__init__()
        self._data = data

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self._HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        row, col = index.row(), index.column()
        item = self._data[row]

        if role == Qt.DisplayRole:
            if col == 1:
                return f"0x{item.address:X}"
            if col == 2:
                return item.name
            if col == 3:
                return str(item.score)
        elif role == Qt.CheckStateRole and col == 0:
            return Qt.Checked if item.confirmed else Qt.Unchecked
        elif role == Qt.BackgroundRole and item.visited:
            return self._VISITED_COLOR
        return None

    def setData(self, index, value, role=Qt.EditRole):
        if not index.isValid():
            return False

        row, col = index.row(), index.column()
        item = self._data[row]

        if role == Qt.CheckStateRole and col == 0:
            item.confirmed = value == Qt.Checked
            self.dataChanged.emit(index, index, [role])
            return True
        return False

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        base_flags = super().flags(index)
        if index.column() == 0:
            return base_flags | Qt.ItemIsUserCheckable
        return base_flags

    def mark_as_visited(self, row: int):
        """Marks a row as visited and triggers a redraw."""
        if 0 <= row < len(self._data):
            self._data[row].visited = True
            # Emit dataChanged for the entire row to update its background
            start_index = self.index(row, 0)
            end_index = self.index(row, self.columnCount() - 1)
            self.dataChanged.emit(start_index, end_index, [Qt.BackgroundRole])

    def get_confirmed_functions(self) -> list[CandidateFunction]:
        """Returns a list of all functions the user has confirmed."""
        return [item for item in self._data if item.confirmed]


class OutlinedFunctionViewer(ida_kernwin.PluginForm):
    """A PyQt Widget to display and manage the list of candidate functions."""

    def __init__(self, candidates: list[CandidateFunction]):
        super().__init__()
        self.candidates = candidates
        self.model = OutlinedFunctionTableModel(self.candidates)

    def OnCreate(self, form):
        self.parent: QWidget = self.FormToPyQtWidget(form)
        self.parent.setWindowTitle("Outlined Function Candidates")
        self._setup_ui()

    def _setup_ui(self):
        # --- Table View ---
        self.table_view = QTableView()
        self.table_view.setModel(self.model)
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.setSortingEnabled(True)
        self.table_view.doubleClicked.connect(self.on_double_click)

        # Adjust column widths
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        # --- Controls ---
        self.rename_checkbox = QCheckBox("Rename confirmed functions to 'outline_...'")
        self.rename_checkbox.setChecked(True)
        self.apply_button = QPushButton("Apply Changes to Confirmed Functions")
        self.apply_button.clicked.connect(self.on_apply_changes)

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.rename_checkbox)
        controls_layout.addStretch()
        controls_layout.addWidget(self.apply_button)

        # --- Main Layout ---
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.table_view)
        main_layout.addLayout(controls_layout)
        self.parent.setLayout(main_layout)

    def on_double_click(self, index: QModelIndex):
        """Jump to the function in IDA when a row is double-clicked."""
        row = index.row()
        candidate = self.candidates[row]
        ida_kernwin.jumpto(candidate.address)
        self.model.mark_as_visited(row)

    def on_apply_changes(self):
        """Apply the FUNC_OUTLINE flag and rename functions for confirmed items."""
        confirmed_items = self.model.get_confirmed_functions()
        if not confirmed_items:
            QMessageBox.information(
                self.parent,
                "No Changes",
                "No functions were confirmed. Nothing to apply.",
            )
            return

        should_rename = self.rename_checkbox.isChecked()
        changed_count = 0

        for item in confirmed_items:
            flags = idc.get_func_flags(item.address)
            if not (flags & idc.FUNC_OUTLINE):
                idc.set_func_flags(item.address, flags | idc.FUNC_OUTLINE)
                changed_count += 1

            if should_rename and item.name.startswith("sub_"):
                new_name = f"outline_{item.name}"
                idc.set_name(item.address, new_name, idc.SN_NOWARN)

        QMessageBox.information(
            self.parent,
            "Success",
            f"Applied changes to {len(confirmed_items)} function(s).",
        )
        self.Close(0)

    def OnClose(self, form):
        pass


# =============================================================================
# Main Execution Logic
# =============================================================================
def main():

    heuristics = [
        # Disqualifying heuristics (large negative weight)
        IsNotLibOrThunkHeuristic(weight=-1000),
        IsNotJmpThunkHeuristic(weight=-1000),
        # Strong positive indicators
        IsLinearFlowHeuristic(weight=30),
        NoCallsHeuristic(weight=30),
        IsSmallHeuristic(weight=25, max_effective_insns=10),
        # Good supporting indicators
        EndsWithRetHeuristic(weight=20),
        SmallFrameHeuristic(weight=15, max_frame_size=32),
    ]

    # A function must score at least 90 to be considered outlined.
    # Max possible score is 30+30+25+20+15 = 120.
    # This threshold requires a function to pass most of the strong heuristics.
    score_threshold = 90

    detector = OutlinedFunctionDetector(heuristics, score_threshold)
    candidates = detector.find_all()

    if not candidates:
        ida_kernwin.info(
            "Scan complete. No new outlined function candidates were found."
        )
        return

    # Launch the GUI
    global outlined_function_viewer  # Keep a global reference to prevent garbage collection
    outlined_function_viewer = OutlinedFunctionViewer(candidates)
    outlined_function_viewer.Show("Outlined Function Candidates")


if __name__ == "__main__":
    main()
