import re
from collections import defaultdict

import networkx as nx

import ida_hexrays
import ida_lines
import idaapi
import idautils
import idc


# Alternative approach using direct microcode analysis
class MicrocodeAnalyzer:
    def __init__(self, func_ea):
        self.func_ea = func_ea
        self.mba = None
        self.dispatcher_patterns = []

    def analyze_microcode(self):
        """Analyze microcode to find control flow patterns"""
        hf = ida_hexrays.hexrays_failure_t()
        self.mba = ida_hexrays.gen_microcode(
            self.func_ea, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_GLBOPT1
        )

        if not self.mba:
            print("[-] Failed to generate microcode")
            return False

        # Analyze each block
        for blk_idx in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_idx)
            self._analyze_block(blk, blk_idx)

        return True

    def _analyze_block(self, blk, blk_idx):
        """Analyze a single microcode block"""
        # Look for dispatcher patterns
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_jcnd:
                # Conditional jump - might be part of switch
                pass
            elif insn.opcode == ida_hexrays.m_goto:
                # Unconditional jump
                pass
            elif insn.opcode == ida_hexrays.m_mov:
                # Assignment - check if it's to dispatcher variable
                pass

            insn = insn.next


# Usage
def main():
    # Get current function
    func_ea = idc.get_screen_ea()
    func = idaapi.get_func(func_ea)

    if not func:
        print("[-] No function at current address")
        return

    # Method 1: Using decompiler
    recovery = CFGRecovery(func.start_ea)
    recovery.run()

    # Method 2: Using microcode (optional)
    # analyzer = MicrocodeAnalyzer(func.start_ea)
    # analyzer.analyze_microcode()


if __name__ == "__main__":
    main()
