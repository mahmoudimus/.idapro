"""
Unflatten solver using IDA Pro's microcode API
Removes control flow flattening at the microcode level without patching the binary.

Run inside IDA Pro (9.0+) with latest Triton.
"""

from __future__ import annotations

import dataclasses
import enum
import functools
import logging
import struct
import time
import traceback
from collections import defaultdict, namedtuple
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import networkx as nx
import triton
from triton import ARCH, AST_NODE, CALLBACK, MODE, OPERAND, Instruction, TritonContext

import ida_allins
import ida_auto
import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_xref
import idaapi
import idautils
import idc

logging.basicConfig(level=logging.DEBUG)

# ──────────────────────────────────────────────────────────────────────
# USER SETTINGS
# ──────────────────────────────────────────────────────────────────────
FUNC = idaapi.get_func(idaapi.get_screen_ea())
FUNC_EA = FUNC.start_ea
FUNC_END = FUNC.end_ea
MAX_STEPS = 250000
DEBUG_MICROCODE = True

# Memory layout for emulation
STACK_TOP = 0x7FFF0000
STACK_SIZE = 0x10000
TEB_AREA = 0x100000
TEB_SIZE = 0x2000
DUMMY_ARG_REGION = 0x600000
DUMMY_ARG_SIZE = 0x1000

Edge = namedtuple("Edge", "src dst ip")


class MicrocodeUnflattener(ida_hexrays.microcode_filter_t):
    """
    A microcode filter that removes control flow flattening.
    This runs during decompilation and modifies the microcode.
    """

    def __init__(self):
        super().__init__()
        self.dispatcher_info = None
        self.state_transitions = {}
        self.entry_state = None
        self.resolved_targets = {}

    def set_analysis_results(
        self, dispatcher_info: Dict, transitions: nx.DiGraph, entry_state: int
    ):
        """Store the results from control flow analysis."""
        self.dispatcher_info = dispatcher_info
        self.state_transitions = transitions
        self.entry_state = entry_state

    def install(self):
        """Install this filter for the decompiler."""
        return ida_hexrays.install_microcode_filter(self, True)

    def remove(self):
        """Remove this filter."""
        return ida_hexrays.install_microcode_filter(self, False)

    def match(self, cdg: ida_hexrays.codegen_t) -> int:
        """Check if we should process this function."""
        # Only process our target function
        if cdg is None:
            return 0
        return 1 if cdg.insn.ea == FUNC_EA else 0

    def apply(self, cdg: ida_hexrays.codegen_t) -> int:
        """Apply the unflattening transformation to the microcode."""
        if not self.dispatcher_info:
            logging.warning("No dispatcher info available, skipping transformation")
            return 0

        try:
            logging.info(
                f"[+] Applying microcode transformation to function at 0x{cdg.insn.ea:X}"
            )

            # Get the microcode
            mba = cdg.mba
            if not mba:
                logging.error("No microcode available")
                return 0

            # Perform the transformation
            success = self._transform_microcode(mba)

            if success:
                # Mark that we modified the microcode
                mba.mark_chains_dirty()
                mba.verify(True)

            return 1 if success else 0

        except Exception as e:
            logging.error(f"Error in microcode transformation: {e}")
            traceback.print_exc()
            return 0

    def _transform_microcode(self, mba: ida_hexrays.mba_t) -> bool:
        """
        Transform the microcode to remove control flow flattening.
        """
        dispatcher_ea = self.dispatcher_info["dispatcher_ea"]
        state_var_info = self.dispatcher_info["state_var"]

        # First, resolve all jump chains
        self._resolve_jump_chains()

        # Find microcode blocks
        dispatcher_block = self._find_block_by_ea(mba, dispatcher_ea)
        if not dispatcher_block:
            logging.error(f"Could not find dispatcher block at 0x{dispatcher_ea:X}")
            return False

        # Process each block to redirect state transitions
        modified = False
        for blk in mba.blocks:
            if self._process_block(mba, blk):
                modified = True

        # Redirect entry point
        if self._redirect_entry(mba):
            modified = True

        # Remove unreachable blocks
        if modified:
            self._remove_unreachable_blocks(mba)

        return modified

    def _resolve_jump_chains(self):
        """Resolve all state transition chains."""
        G = self.state_transitions
        self.resolved_targets = {}

        for start_node in G.nodes():
            curr = start_node
            path = [curr]
            while G.out_degree(curr) > 0:
                succ = list(G.successors(curr))[0]
                if succ in path:  # Loop detected
                    break
                path.append(succ)
                curr = succ
            self.resolved_targets[start_node] = curr

    def _find_block_by_ea(
        self, mba: ida_hexrays.mba_t, ea: int
    ) -> Optional[ida_hexrays.mblock_t]:
        """Find a microcode block containing the given address."""
        blk = mba.blocks
        while blk:
            if blk.start <= ea < blk.end:
                return blk
            blk = blk.next
        return None

    def _process_block(self, mba: ida_hexrays.mba_t, blk: ida_hexrays.mblock_t) -> bool:
        """
        Process a single microcode block to redirect state transitions.
        Returns True if modifications were made.
        """
        modified = False
        state_var = self.dispatcher_info["state_var"]

        # Look for state variable assignments
        for ins in blk:
            if self._is_state_assignment(ins, state_var):
                # Get the assigned state value
                state_value = self._get_assigned_value(ins)
                if state_value is not None and state_value in self.resolved_targets:
                    # Find the final target state
                    final_state = self.resolved_targets[state_value]
                    target_ea = self.dispatcher_info["block_ea"].get(final_state)

                    if target_ea:
                        # Replace the state assignment with a direct goto
                        if self._replace_with_goto(mba, blk, ins, target_ea):
                            modified = True
                            break  # Block structure changed, stop processing

        return modified

    def _is_state_assignment(self, ins: ida_hexrays.minsn_t, state_var: Dict) -> bool:
        """Check if this instruction assigns to the state variable."""
        if ins.opcode != ida_hexrays.m_stx:
            return False

        # Check if destination matches our state variable
        if state_var["kind"] == "stk":
            # Stack variable - check if it's [base_reg + offset]
            if ins.l.t == ida_hexrays.mop_a:  # address operand
                # This is complex - we need to check if the address expression
                # matches our state variable location
                return self._matches_stack_var(ins.l, state_var)
        elif state_var["kind"] == "reg":
            # Register variable
            if ins.l.t == ida_hexrays.mop_r:  # register operand
                return ins.l.r == state_var["reg_id"]

        return False

    def _matches_stack_var(self, op: ida_hexrays.mop_t, state_var: Dict) -> bool:
        """Check if a memory operand matches our stack state variable."""
        # This is simplified - full implementation would parse the address expression
        # to check if it's [base_reg + offset] matching our state variable
        return True  # Placeholder

    def _get_assigned_value(self, ins: ida_hexrays.minsn_t) -> Optional[int]:
        """Extract the constant value being assigned."""
        if ins.r.t == ida_hexrays.mop_n:  # number/immediate
            return ins.r.value(ins.r.size)
        return None

    def _replace_with_goto(
        self,
        mba: ida_hexrays.mba_t,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        target_ea: int,
    ) -> bool:
        """Replace an instruction with a goto to the target address."""
        try:
            # Find or create the target block
            target_blk = None
            for b in mba.blocks:
                if b.start == target_ea:
                    target_blk = b
                    break

            if not target_blk:
                # Need to create a new block at the target
                target_blk = mba.insert_block(target_ea)

            # Create a goto instruction
            goto_ins = ida_hexrays.minsn_t(target_ea)
            goto_ins.opcode = ida_hexrays.m_goto
            goto_ins.l.make_blkref(target_blk.serial)

            # Replace the current instruction
            ins.swap(goto_ins)

            # Update block successors
            blk.succset.clear()
            blk.succset.add(target_blk.serial)

            # Mark the microcode as modified
            blk.mark_lists_dirty()
            blk.mba.mark_chains_dirty()

            logging.info(
                f"[+] Replaced state assignment at 0x{ins.ea:X} with goto to 0x{target_ea:X}"
            )
            return True

        except Exception as e:
            logging.error(f"Failed to replace with goto: {e}")
            return False

    def _redirect_entry(self, mba: ida_hexrays.mba_t) -> bool:
        """Redirect the function entry to skip the dispatcher."""
        if not self.entry_state:
            return False

        final_entry = self.resolved_targets.get(self.entry_state, self.entry_state)
        target_ea = self.dispatcher_info["block_ea"].get(final_entry)

        if not target_ea:
            return False

        # Find the entry block (usually block 0)
        if mba.blocks:
            entry_blk = mba.blocks[0]

            # Create a goto to the real entry point
            goto_ins = ida_hexrays.minsn_t(entry_blk.start)
            goto_ins.opcode = ida_hexrays.m_goto

            # Find the target block
            for blk in mba.blocks:
                if blk.start == target_ea:
                    goto_ins.l.make_blkref(blk.serial)

                    # Insert at the beginning of the entry block
                    entry_blk.insert_into_block(goto_ins, entry_blk.head)

                    logging.info(f"[+] Redirected entry point to 0x{target_ea:X}")
                    return True

        return False

    def _remove_unreachable_blocks(self, mba: ida_hexrays.mba_t):
        """Remove blocks that are no longer reachable."""
        # Build reachability graph
        reachable = set()
        to_visit = [0]  # Start from entry block

        while to_visit:
            blk_num = to_visit.pop()
            if blk_num in reachable:
                continue

            reachable.add(blk_num)
            blk = mba.blocks[blk_num]

            # Add successors
            for succ in blk.succset:
                if succ not in reachable:
                    to_visit.append(succ)

        # Remove unreachable blocks
        for i in range(len(mba.blocks)):
            if i not in reachable:
                logging.info(f"[+] Removing unreachable block {i}")
                # Note: Actually removing blocks is complex and may require
                # rebuilding the entire mba. For now, we just mark them.
                mba.blocks[i].flags |= ida_hexrays.MBL_DEAD


# Analysis functions (mostly reused from original with modifications)


class CTreeSwitchFinder(ida_hexrays.ctree_visitor_t):
    """A ctree visitor to find all switch statements in a function."""

    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.switches = []

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        if insn.op == ida_hexrays.cit_switch:
            self.switches.append(insn.cswitch)
        return 0


class StateStoreVisitor(ida_hexrays.ctree_visitor_t):
    """Find all assignments of constant values to the state variable."""

    def __init__(self, state_var_idx):
        super().__init__(ida_hexrays.CV_FAST)
        self.state_var_idx = state_var_idx
        self.found_stores = []

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        if insn.cexpr is not None and insn.cexpr.op == ida_hexrays.cot_asg:
            dest = insn.cexpr.x
            src = insn.cexpr.y
            if dest.op == ida_hexrays.cot_var and src.op == ida_hexrays.cot_num:
                if dest.v.getv() == self.state_var_idx:
                    addr = insn.ea
                    value = src.n.value(insn.cexpr.type)
                    self.found_stores.append((addr, value))
        return 0


def analyze_dispatcher(func_ea: int) -> Tuple[Dict, nx.DiGraph, int]:
    """
    Analyze the function to find the dispatcher and understand control flow.
    Returns: (dispatcher_info, state_graph, entry_state)
    """
    # Decompile to find switches
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        raise RuntimeError(f"Failed to decompile function at 0x{func_ea:X}")

    # Find switches
    finder = CTreeSwitchFinder()
    finder.apply_to(cfunc.body, None)

    if not finder.switches:
        raise RuntimeError("No switch statements found")

    # For simplicity, assume the main dispatcher is the largest switch
    main_switch = max(finder.switches, key=lambda s: len(s.cases))
    dispatcher_ea = main_switch.expr.ea

    # Get switch info
    switch_info = idaapi.get_switch_info(dispatcher_ea)
    if not switch_info:
        raise RuntimeError(f"Could not get switch info for 0x{dispatcher_ea:X}")

    # Get block mappings
    block_ea = get_switch_mapping(switch_info, dispatcher_ea)

    # Find state variable
    state_var = find_state_variable(cfunc, main_switch)

    # Run emulation to discover control flow
    G = emulate_control_flow(func_ea, dispatcher_ea, state_var, switch_info)

    # Find entry state
    entry_state = find_entry_state(G)

    dispatcher_info = {
        "dispatcher_ea": dispatcher_ea,
        "switch_info": switch_info,
        "state_var": state_var,
        "block_ea": block_ea,
    }

    return dispatcher_info, G, entry_state


def find_state_variable(cfunc: ida_hexrays.cfuncptr_t, switch_stmt) -> Dict:
    """Find information about the state variable."""
    switch_expr = switch_stmt.expr
    if switch_expr.op != idaapi.cot_var:
        raise RuntimeError("Switch expression is not a simple variable")

    lvar = switch_expr.v.getv()

    state_info = {}
    if lvar.is_stk_var():
        state_info["kind"] = "stk"
        state_info["offset"] = lvar.get_stkoff()
        state_info["base"] = "rbp"  # Assuming standard frame pointer
    elif lvar.is_reg_var():
        state_info["kind"] = "reg"
        state_info["reg_id"] = lvar.get_reg1()
        state_info["reg_name"] = idaapi.get_reg_name(lvar.get_reg1(), 8)
    else:
        raise RuntimeError("State variable is neither stack nor register")

    state_info["lvar_idx"] = lvar
    return state_info


def get_switch_mapping(si: idaapi.switch_info_t, dispatcher_ea: int) -> Dict[int, int]:
    """Get the mapping from switch cases to addresses."""
    cat = idaapi.calc_switch_cases(dispatcher_ea, si)
    cases, targets = cat.cases, cat.targets
    mapping = {}
    for i in range(targets.size()):
        tgt = targets[i]
        mapping.update({int(cv): tgt for cv in cases[i]})
    return mapping


def emulate_control_flow(
    func_ea: int, dispatcher_ea: int, state_var: Dict, switch_info: idaapi.switch_info_t
) -> nx.DiGraph:
    """
    Use Triton to emulate the function and discover the actual control flow.
    Returns a directed graph of state transitions.
    """
    # Initialize Triton
    tc = TritonContext()
    tc.setArchitecture(ARCH.X86_64)
    tc.setMode(MODE.ALIGNED_MEMORY, True)

    # Map memory segments
    map_all_segments(tc)

    # Set up stack
    tc.setConcreteMemoryAreaValue(STACK_TOP - STACK_SIZE, bytearray(STACK_SIZE))
    tc.setConcreteRegisterValue(tc.registers.rsp, STACK_TOP - 8)
    tc.setConcreteRegisterValue(tc.registers.rbp, STACK_TOP)

    # Set up dummy regions
    tc.setConcreteMemoryAreaValue(TEB_AREA, bytearray(TEB_SIZE))
    tc.setConcreteRegisterValue(tc.registers.gs, TEB_AREA)
    tc.setConcreteMemoryAreaValue(DUMMY_ARG_REGION, bytearray(DUMMY_ARG_SIZE))

    # Set entry point
    tc.setConcreteRegisterValue(tc.registers.rip, func_ea)
    tc.setConcreteRegisterValue(tc.registers.rcx, DUMMY_ARG_REGION)
    tc.setConcreteRegisterValue(tc.registers.rdx, 1)  # Default seed

    # Initialize state variable
    if state_var["kind"] == "stk":
        addr = tc.getConcreteRegisterValue(tc.registers.rbp) + state_var["offset"]
        tc.setConcreteMemoryValue(addr, 0)

    # Run emulation
    G = nx.DiGraph()
    G.add_node(0)  # Initial state

    prev_state = read_state(tc, state_var)
    steps = 0

    while steps < MAX_STEPS:
        ip = tc.getConcreteRegisterValue(tc.registers.rip)

        # Check if we're still in the function
        if not (func_ea <= ip < idaapi.get_func(func_ea).end_ea):
            break

        # Get instruction
        try:
            size = idaapi.get_item_size(ip)
            if not size:
                break
            opcode = ida_bytes.get_bytes(ip, size)
            if not opcode:
                break
        except:
            break

        # Create and process instruction
        instr = Instruction()
        instr.setAddress(ip)
        instr.setOpcode(opcode)

        # Skip calls
        if idc.print_insn_mnem(ip) == "call":
            tc.setConcreteRegisterValue(tc.registers.rip, ip + size)
            tc.setConcreteRegisterValue(tc.registers.rax, 0)
            steps += 1
            continue

        try:
            tc.processing(instr)
        except Exception as e:
            logging.debug(f"Emulation error at 0x{ip:X}: {e}")
            break

        # Check for state changes
        cur_state = read_state(tc, state_var)
        if cur_state != prev_state:
            G.add_node(cur_state)
            G.add_edge(prev_state, cur_state, ip=ip)
            prev_state = cur_state

            # Stop if we've found all states
            if G.number_of_nodes() >= switch_info.ncases:
                break

        steps += 1

    return G


def read_state(tc: TritonContext, state_var: Dict) -> int:
    """Read the current value of the state variable."""
    if state_var["kind"] == "reg":
        reg = getattr(tc.registers, state_var["reg_name"].lower())
        return tc.getConcreteRegisterValue(reg) & 0xFFFFFFFF
    elif state_var["kind"] == "stk":
        base = tc.getConcreteRegisterValue(tc.registers.rbp)
        addr = base + state_var["offset"]
        return int.from_bytes(tc.getConcreteMemoryAreaValue(addr, 4), "little")
    else:
        raise ValueError(f"Unknown state variable kind: {state_var['kind']}")


def find_entry_state(G: nx.DiGraph) -> int:
    """Find the entry state in the control flow graph."""
    # The entry state is typically the successor of state 0
    if G.has_node(0) and G.out_degree(0) > 0:
        return list(G.successors(0))[0]
    # Otherwise, find the node with no predecessors
    for node in G.nodes():
        if G.in_degree(node) == 0 and node != 0:
            return node
    return 1  # Default


def map_all_segments(tc: TritonContext):
    """Map all executable segments into Triton memory."""
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC):
            seg_bytes = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
            if seg_bytes:
                tc.setConcreteMemoryAreaValue(seg.start_ea, seg_bytes)


def main():
    """Main entry point for the unflattener."""
    print(f"[+] Analyzing function at 0x{FUNC_EA:X}")

    try:
        # Analyze the dispatcher and control flow
        dispatcher_info, state_graph, entry_state = analyze_dispatcher(FUNC_EA)

        print(f"[+] Found dispatcher at 0x{dispatcher_info['dispatcher_ea']:X}")
        print(f"[+] Discovered {state_graph.number_of_nodes()} states")
        print(f"[+] Entry state: {entry_state}")

        # Create and install the microcode filter
        unflattener = MicrocodeUnflattener()
        unflattener.set_analysis_results(dispatcher_info, state_graph, entry_state)

        if unflattener.install():
            print("[+] Microcode filter installed successfully")
            print("[+] Decompile the function to see the unflattened code")
            print("[+] The filter will remain active for this IDA session")

            # Optionally trigger decompilation
            if ida_kernwin.ask_yn(1, "Decompile the function now?") == 1:
                cfunc = ida_hexrays.decompile(FUNC_EA)
                if cfunc:
                    ida_hexrays.open_pseudocode(FUNC_EA, 0)
        else:
            print("[!] Failed to install microcode filter")

    except Exception as e:
        print(f"[!] Error: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
