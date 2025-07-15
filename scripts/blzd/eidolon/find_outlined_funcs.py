import abc
import logging

import ida_allins
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

# Configure logging to display in the IDA output window
logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("OutlinedFuncDetector")


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
    """
    Detects outlined functions by scoring them against a set of weighted heuristics.
    """

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

    def calculate_score(self, func_ea: int) -> int:
        """
        Calculates a score for a function based on the configured heuristics.

        :param func_ea: The starting address of the function.
        :return: The total score.
        """
        return sum(h(func_ea) for h in self.heuristics)

    def is_likely_outlined(self, func_ea: int) -> bool:
        """
        Checks if a function is likely an outlined function by comparing its score
        to the threshold.

        :param func_ea: The starting address of the function.
        :return: True if the function's score meets the threshold, False otherwise.
        """
        try:
            score = self.calculate_score(func_ea)
        except Exception as e:
            log.error(
                "Error in this function: %s - skipping!", hex(func_ea), exc_info=True
            )
            return False
        return score >= self.score_threshold

    def find_and_mark_all(self, set_ida_flag=True, rename_func=True):
        """
        Iterates through all functions, identifies outlined functions,
        and optionally marks and renames them.
        """
        log.info("Starting scan for outlined functions...")
        count = 0
        for func_ea in idautils.Functions():
            # Don't re-evaluate functions already marked as outlined.
            if idc.get_func_flags(func_ea) & idc.FUNC_OUTLINE:
                continue

            if self.is_likely_outlined(func_ea):
                count += 1
                func_name = idc.get_func_name(func_ea)
                log.info(
                    "Found likely outlined function: %s at 0x%x", func_name, func_ea
                )

                if set_ida_flag:
                    flags = idc.get_func_flags(func_ea)
                    idc.set_func_flags(func_ea, flags | idc.FUNC_OUTLINE)

                if rename_func and func_name.startswith("sub_"):
                    new_name = f"outline_{func_name}"
                    if not idc.set_name(func_ea, new_name, idc.SN_NOWARN):
                        log.warning("Failed to rename %s to %s", func_name, new_name)

        log.info("Scan complete. Found %d new outlined functions.", count)


def main():
    """
    Main entry point for the script. Configures and runs the detector.
    """
    # Define the set of heuristics and their weights.
    # These can be tuned for different obfuscation patterns.
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
    detector.find_and_mark_all(set_ida_flag=False, rename_func=False)


if __name__ == "__main__":
    main()
