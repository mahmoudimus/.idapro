import logging
import typing

import networkx as nx

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_pro
import idaapi
import idautils
import idc

# Attempt to import CFGRecovery from the sibling cfg_trace.py
# This might require IDA's Python environment to be configured correctly
# or for the scripts to be in a directory recognized as a package.
try:
    from .cfg_trace import CFGRecovery
except ImportError:
    # Fallback if relative import fails (e.g., script run in a way that doesn't define the package)
    # This assumes cfg_trace.py is in a path discoverable by Python's import system.
    # For a more robust solution, ensure your scripts directory is in PYTHONPATH
    # or handle this with a more explicit path manipulation if needed.
    try:
        import cfg_trace  # type: ignore

        CFGRecovery = cfg_trace.CFGRecovery  # type: ignore
    except ImportError:
        idaapi.msg(
            "ERROR: CFGRecovery class from cfg_trace.py could not be imported.\n"
        )
        idaapi.msg("Ensure cfg_trace.py is in the same directory or Python path.\n")
        CFGRecovery = None


class CFFUnflatten:
    """
    Orchestrates the unflattening of a control-flow flattened function
    using a recovered CFG.
    """

    def __init__(
        self,
        func_ea: int,
        cfg_graph: nx.DiGraph,
        dispatcher_var_idx: typing.Optional[int],
        case_block_info: dict,
        cff_entry_setup_points: dict[int, int],
    ):
        self.func_ea = func_ea
        self.func = idaapi.get_func(func_ea)
        self.cfg = cfg_graph
        self.dispatcher_var_idx = dispatcher_var_idx
        self.case_value_to_ea = {
            case_val: info["start_ea"] for case_val, info in case_block_info.items()
        }
        # Add obj_id to case_value_to_ea for easier lookup if needed
        self.case_value_to_obj_id = {
            case_val: info["case_item_obj_id"]
            for case_val, info in case_block_info.items()
        }
        self.cff_entry_setup_points = cff_entry_setup_points
        self.logger = logging.getLogger(self.__class__.__name__)
        self.switch_instruction_ea: typing.Optional[int] = None
        self.cfunc: typing.Optional[ida_hexrays.cfuncptr_t] = None

    def _get_cfunc(self) -> typing.Optional[ida_hexrays.cfuncptr_t]:
        """Gets or refreshes the decompiled function."""
        if not self.cfunc:
            try:
                self.cfunc = idaapi.decompile(self.func_ea)
            except ida_hexrays.DecompilationFailure:
                self.logger.error("Failed to decompile function 0x%X", self.func_ea)
                return None
        return self.cfunc

    def map_switch_and_case_eas(self) -> bool:
        """
        Identifies the main switch instruction EA and verifies case EAs.
        The case_value_to_ea map is already populated from CFGRecovery's output.
        This function primarily finds the switch instruction EA.
        """
        cfunc = self._get_cfunc()
        if not cfunc:
            return False

        found_switch = False
        for item in cfunc.treeitems:  # item is a citem_t
            if item.op == idaapi.cit_switch:
                found_switch = True
                self.switch_instruction_ea = item.ea
                self.logger.info(
                    "Identified dispatcher switch instruction at EA 0x%X", item.ea
                )

                # Verify EAs from CFGRecovery against live cfunc if necessary (optional)
                # switch_insn: ida_hexrays.cswitch_t = item.cinsn.cswitch
                # for case_idx in range(switch_insn.cases.size()):
                #     case_item: ida_hexrays.ccase_t = switch_insn.cases.at(case_idx)
                #     for val_idx in range(case_item.values.size()):
                #         case_val = case_item.values.at(val_idx)
                #         if case_val in self.case_value_to_ea:
                #             if self.case_value_to_ea[case_val] != case_item.ea:
                #                 self.logger.warning(
                #                     "EA mismatch for case 0x%X: CFG_EA=0x%X, CFunc_EA=0x%X",
                #                     case_val, self.case_value_to_ea[case_val], case_item.ea
                #                 )
                #         else:
                #             self.logger.warning("Case 0x%X from cfunc not in CFG EAs.", case_val)
                break  # Assuming one main dispatcher switch

        if not found_switch:
            self.logger.error(
                "Could not find the main switch statement in function 0x%X.",
                self.func_ea,
            )
            return False
        return True

    def find_terminating_jmp_in_block(
        self, block_start_ea: int, case_val: int
    ) -> typing.Optional[int]:
        """
        Finds the unconditional JMP instruction that likely terminates a case block
        and jumps back to the dispatcher loop.
        This JMP is the one we want to patch.

        Args:
            block_start_ea: The starting EA of the case block's code.
            case_val: The case value, for context in logging.

        Returns:
            The EA of the JMP instruction to patch, or None if not found.
        """
        cfunc = self._get_cfunc()
        if not cfunc or self.dispatcher_var_idx is None:
            return None

        # First, try to find the ccase_t item using its obj_id stored from CFGRecovery
        target_obj_id = self.case_value_to_obj_id.get(case_val)
        if target_obj_id is None:
            self.logger.warning(
                "No obj_id found for case 0x%X. Cannot find citem directly.", case_val
            )
            return None

        case_citem = None
        # Search for the specific ccase_t using its obj_id
        # cfunc.treeitems provides all citem_t in the function.
        # We need to find the citem_t whose obj_id matches.
        # This is inefficient. A better way is to traverse from the switch.
        for item in cfunc.treeitems:
            if item.op == idaapi.cit_switch:
                switch_insn: ida_hexrays.cswitch_t = item.cinsn.cswitch
                for i in range(switch_insn.cases.size()):
                    cc = switch_insn.cases.at(i)  # ccase_t
                    if cc.obj_id == target_obj_id:
                        case_citem = cc
                        break
                if case_citem:
                    break

        if not case_citem:
            self.logger.warning(
                "Could not locate citem for case 0x%X (obj_id %s) in cfunc.",
                case_val,
                target_obj_id,
            )
            # Fallback to basic block analysis if citem not found
            return self._find_jmp_by_bb_analysis(block_start_ea, case_val)

        # Traverse the statements within this case_citem (which is a cinsn_t, often a cblock)
        # Looking for a `goto` that leads back to the dispatcher, usually after dispatcher var assignment.
        # A ccase_t *is* a statement list. Iterate its contents if it's a block.

        # Simplified: Assume the last instruction in the basic block starting at block_start_ea
        # (or the block containing the dispatcher assignment) is the JMP.
        # The CFG trace already found dispatcher assignments.
        # The critical part is finding the JMP that *follows* such an assignment or terminates the semantic block.

        # Using a visitor to find the `goto` statement within the specific case block (citem)
        # This is complicated because the case_citem might not be simple.
        class GotoVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, logger):
                super().__init__(ida_hexrays.CV_FAST)
                self.goto_eas = []  # Store EAs of cgoto_t items
                self.logger = logger

            def visit_insn(self, insn: ida_hexrays.cinsn_t):
                if insn.op == idaapi.cit_goto:
                    self.logger.debug("GotoVisitor: Found cit_goto at EA 0x%X", insn.ea)
                    self.goto_eas.append(insn.ea)
                return 0  # Continue traversal

        visitor = GotoVisitor(self.logger)
        # case_citem itself is a cinsn_t. If it's a block, apply_to its cblock.
        # However, apply_to expects a citem_t as the root for traversal.
        # A ccase_t is a citem_t, so we can apply to it directly.
        visitor.apply_to(case_citem, None)  # type: ignore

        if visitor.goto_eas:
            # Heuristic: the JMP to patch is likely the one with the highest address
            # within this case block, as it's typically the last action.
            # Or, it's the one immediately after the dispatcher var assignment.
            # This needs careful handling.
            # For now, if there are gotos, assume the one at highest EA is the candidate.
            # This also assumes the goto is an unconditional jump back to dispatcher head.
            candidate_jmp_ea = max(
                visitor.goto_eas
            )  # JMPs are usually small, so EA itself is fine.
            self.logger.info(
                "Found candidate JMP (from cgoto_t) at 0x%X in case 0x%X (starts 0x%X)",
                candidate_jmp_ea,
                case_val,
                block_start_ea,
            )
            return candidate_jmp_ea
        else:
            self.logger.debug(
                "No explicit cgoto_t found in case 0x%X (0x%X). Trying BB analysis.",
                case_val,
                block_start_ea,
            )
            return self._find_jmp_by_bb_analysis(block_start_ea, case_val)

    def _find_jmp_by_bb_analysis(
        self, block_start_ea: int, case_val: int
    ) -> typing.Optional[int]:
        """Fallback to find JMP using basic block analysis."""
        func_graph = idaapi.FlowChart(idaapi.get_func(block_start_ea))
        for bb in func_graph:
            if (
                bb.start_ea == block_start_ea
            ):  # Found the starting basic block for this case
                # Check the last instruction of this BB
                # A BB's end_ea points *after* the last instruction.
                # prev_head gives the start of the last instruction.
                last_insn_ea = idc.prev_head(bb.end_ea, bb.start_ea)
                if last_insn_ea != idaapi.BADADDR:
                    mnem = idc.print_insn_mnem(last_insn_ea)
                    if mnem == "jmp":  # Unconditional jump
                        # Check if this jmp is to the dispatcher head (heuristic needed)
                        # For now, assume any JMP at end of case block is a candidate.
                        self.logger.info(
                            "Found candidate JMP (from BB analysis) at 0x%X in case 0x%X (BB 0x%X-0x%X)",
                            last_insn_ea,
                            case_val,
                            bb.start_ea,
                            bb.end_ea,
                        )
                        return last_insn_ea
                    elif mnem.startswith("ret"):
                        self.logger.info(
                            "Case 0x%X (0x%X) ends with RET at 0x%X. No JMP to patch for linking.",
                            case_val,
                            block_start_ea,
                            last_insn_ea,
                        )
                        return None  # This is a return block
                    else:
                        self.logger.warning(
                            "Case 0x%X (0x%X) BB 0x%X-0x%X ends with %s (0x%X), not JMP/RET.",
                            case_val,
                            block_start_ea,
                            bb.start_ea,
                            bb.end_ea,
                            mnem,
                            last_insn_ea,
                        )
                break  # Processed the first BB starting at block_start_ea

        self.logger.warning(
            "Could not find a clear terminating JMP for case 0x%X (starts 0x%X) via BB analysis.",
            case_val,
            block_start_ea,
        )
        return None

    def patch_jump(self, from_ea: int, to_ea: int, comment: str = "") -> bool:
        """
        Patches the instruction at from_ea to be an unconditional near jump to to_ea.
        Attempts to NOP out remaining bytes of the original instruction if the new JMP is shorter.
        """
        self.logger.info("Patching 0x%X to JMP to 0x%X. (%s)", from_ea, to_ea, comment)
        from_ea = ida_bytes.get_item_head(from_ea)
        original_size = ida_bytes.get_item_size(from_ea)

        # JMP rel32: Opcode E9, followed by 4-byte relative offset
        # Offset = target_ea - (current_ea_of_jmp_operand + 4)
        # current_ea_of_jmp_operand = from_ea + 1 (byte for E9)
        # Total size of JMP rel32 is 5 bytes.
        # Relative offset = to_ea - (from_ea + 5)
        offset = to_ea - (from_ea + 5)

        # Check if offset fits in 32 bits (signed)
        if not (-(1 << 31) <= offset < (1 << 31)):
            self.logger.error(
                "Offset 0x%X is too large for JMP rel32 from 0x%X to 0x%X. Patching failed.",
                offset,
                from_ea,
                to_ea,
            )
            return False

        if original_size < 5:
            self.logger.error(
                "Original instruction at 0x%X (size %d) is too small to fit a 5-byte JMP rel32. Patching aborted.",
                from_ea,
                original_size,
            )
            return False

        # Patch the JMP
        ida_bytes.patch_byte(from_ea, 0xE9)  # JMP opcode
        # IDA's patch_dword expects an unsigned value if it's for memory content
        ida_bytes.patch_dword(from_ea + 1, offset & 0xFFFFFFFF)

        # NOP out any remaining bytes of the original instruction
        bytes_to_nop = original_size - 5
        if bytes_to_nop > 0:
            for i in range(bytes_to_nop):
                ida_bytes.patch_byte(from_ea + 5 + i, 0x90)  # NOP
            self.logger.debug(
                "NOPed %d bytes after JMP at 0x%X", bytes_to_nop, from_ea + 5
            )

        idc.set_cmt(from_ea, f"Unflattened: JMP to 0x{to_ea:X}. {comment}", False)
        return True

    def unflatten(self) -> bool:
        """Main unflattening logic."""
        self.logger.info("Starting CFF unflattening for function 0x%X", self.func_ea)
        if not self.func:
            self.logger.error("Function at 0x%X not found.", self.func_ea)
            return False

        if not self._get_cfunc() or not self.map_switch_and_case_eas():
            self.logger.error(
                "Initial analysis (decompile, switch find) failed. Aborting."
            )
            return False

        if not self.cfg.nodes:
            self.logger.error("CFG is empty. Aborting.")
            return False

        # 1. Determine the actual entry point of the unflattened function
        start_nodes = [node for node, degree in self.cfg.in_degree() if degree == 0]
        if not start_nodes:
            # Fallback: If CFG has a 'start_node' attribute from CFGRecovery (not standard, but could be added)
            # Or, try the node with the smallest case value if all are integers.
            if self.cfg.nodes:
                # Heuristic: try smallest numeric case value or first node.
                potential_starts = sorted(
                    [n for n in self.cfg.nodes() if isinstance(n, int)], reverse=False
                )
                if potential_starts:
                    start_nodes = [potential_starts[0]]
                    self.logger.warning(
                        "No node with in-degree 0. Using smallest case value 0x%X as entry.",
                        start_nodes[0],
                    )
                else:  # No numeric nodes or no nodes
                    self.logger.error(
                        "No node with in-degree 0 and no suitable fallback start node in CFG. Aborting."
                    )
                    return False
            else:  # Should have been caught by self.cfg.nodes check earlier
                self.logger.error("CFG has no nodes. Cannot determine start node.")
                return False

        if len(start_nodes) > 1:
            self.logger.warning(
                "Multiple CFG start nodes found: %s. Using the first: 0x%X",
                [hex(n) if isinstance(n, int) else str(n) for n in start_nodes],
                start_nodes[0],
            )
        unflattened_entry_case_val = start_nodes[0]
        unflattened_entry_ea = self.case_value_to_ea.get(unflattened_entry_case_val)

        if unflattened_entry_ea is None:
            self.logger.error(
                "Could not find EA for unflattened entry case value 0x%X. Aborting.",
                unflattened_entry_case_val,
            )
            return False
        self.logger.info(
            "Determined unflattened entry point: case 0x%X at EA 0x%X",
            unflattened_entry_case_val,
            unflattened_entry_ea,
        )

        # function_start_ea = self.func.start_ea

        patch_point_for_entry: typing.Optional[int] = None

        # Try to use the CFF entry setup point identified by CFGRecovery first
        if unflattened_entry_case_val in self.cff_entry_setup_points:
            patch_point_for_entry = self.cff_entry_setup_points[
                unflattened_entry_case_val
            ]
            self.logger.info(
                "Using CFF entry setup point for case 0x%X found at EA 0x%X as the entry patch target.",
                unflattened_entry_case_val,
                patch_point_for_entry,
            )
        else:
            self.logger.warning(
                "CFF entry setup point for case 0x%X not found in cff_entry_setup_points. Falling back to heuristic.",
                unflattened_entry_case_val,
            )
            # Fallback heuristic: instruction immediately preceding the switch_instruction_ea
            if self.switch_instruction_ea:  # Make sure switch_instruction_ea was found
                heuristic_ea = ida_bytes.get_item_head(
                    idc.prev_head(self.switch_instruction_ea)
                )
                if heuristic_ea != idaapi.BADADDR and self.func.contains(heuristic_ea):
                    patch_point_for_entry = heuristic_ea
                    self.logger.info(
                        "Using fallback heuristic: instruction at 0x%X (before switch_instruction_ea 0x%X) as entry patch target.",
                        patch_point_for_entry,
                        self.switch_instruction_ea,
                    )
                else:
                    self.logger.error(
                        "Fallback heuristic for entry patch point failed: prev_head (0x%X) for switch_ea 0x%X is invalid or outside function.",
                        heuristic_ea,
                        self.switch_instruction_ea,
                    )
            else:
                # This case should have been caught earlier by the self.switch_instruction_ea check at the start of unflatten
                self.logger.error(
                    "Switch instruction EA not available for fallback heuristic."
                )

        if patch_point_for_entry is None:
            self.logger.error(
                "Could not determine a suitable patch point for redirecting to unflattened entry. Aborting entry patch."
            )
            return False

        self.logger.info(
            "Selected pre-dispatcher patch point at 0x%X. Will patch this to JMP to unflattened CFG entry 0x%X (case 0x%X)",
            patch_point_for_entry,
            unflattened_entry_ea,
            unflattened_entry_case_val,
        )

        # 2. Patch the function's original entry to the determined entry point
        if not self.patch_jump(
            patch_point_for_entry,
            unflattened_entry_ea,
            "Patched pre-dispatcher to CFG start",
        ):
            self.logger.error(
                "Failed to patch CFF entry point at 0x%X to JMP to 0x%X. Aborting.",
                patch_point_for_entry,
                unflattened_entry_ea,
            )
            return False

        # 3. For each block in the CFG, patch its exit JMP
        for case_val_src in self.cfg.nodes:
            block_start_ea = self.case_value_to_ea.get(case_val_src)
            if block_start_ea is None:
                self.logger.warning(
                    "Skipping case 0x%X: EA not found in case_value_to_ea map.",
                    case_val_src,
                )
                continue

            self.logger.debug(
                "Processing block for case 0x%X (starts at 0x%X)",
                case_val_src,
                block_start_ea,
            )

            successors = list(self.cfg.successors(case_val_src))
            if len(successors) == 1:  # Unconditional jump in CFG
                jmp_to_patch_ea = self.find_terminating_jmp_in_block(
                    block_start_ea, case_val_src
                )
                if jmp_to_patch_ea is None:
                    self.logger.warning(
                        "No JMP found to patch for case 0x%X (0x%X) which has one successor. Block might end differently (e.g. RET already, or analysis failed).",
                        case_val_src,
                        block_start_ea,
                    )
                    continue

                case_val_dst = successors[0]
                target_ea = self.case_value_to_ea.get(case_val_dst)
                if target_ea is None:
                    self.logger.error(
                        "EA for successor case 0x%X not found. Cannot patch JMP from 0x%X (case 0x%X)",
                        case_val_dst,
                        block_start_ea,
                        case_val_src,
                    )
                    continue

                patch_comment = f"Case 0x{case_val_src:X} -> 0x{case_val_dst:X}"
                if not self.patch_jump(jmp_to_patch_ea, target_ea, patch_comment):
                    self.logger.error(
                        "Failed to patch JMP at 0x%X (for case 0x%X) to 0x%X (case 0x%X)",
                        jmp_to_patch_ea,
                        case_val_src,
                        target_ea,
                        case_val_dst,
                    )

            elif len(successors) > 1:
                # Conditional branches. This script currently assumes cfg_trace provides unconditional links.
                # If cfg_trace were to provide conditions, re-writing them is much more complex.
                self.logger.warning(
                    "Case 0x%X (0x%X) has %d successors in CFG: %s. Re-writing conditional branches is not yet supported. This block will not be patched.",
                    case_val_src,
                    block_start_ea,
                    len(successors),
                    [hex(s) if isinstance(s, int) else str(s) for s in successors],
                )
            elif len(successors) == 0:
                # This block should end with a RET or be an exit block.
                # Verify find_terminating_jmp_in_block behavior for RET blocks.
                # If it correctly returns None for RETs, this is fine.
                self.logger.info(
                    "Case 0x%X (0x%X) is a terminal node in CFG. Expecting it to RET.",
                    case_val_src,
                    block_start_ea,
                )
                # Optionally, verify it does end in RET here.
                # self.find_terminating_jmp_in_block should have logged if it's a RET.

        # 4. NOP out the original dispatcher switch table jump
        if self.switch_instruction_ea:
            switch_jmp_size = ida_bytes.get_item_size(self.switch_instruction_ea)
            self.logger.info(
                "NOPing out original dispatcher switch JMP at 0x%X (size %d bytes)",
                self.switch_instruction_ea,
                switch_jmp_size,
            )
            for i in range(switch_jmp_size):
                ida_bytes.patch_byte(self.switch_instruction_ea + i, 0x90)  # NOP
            idc.set_cmt(
                self.switch_instruction_ea,
                "Unflattened: Original dispatcher NOPed",
                False,
            )
        else:
            self.logger.warning("Switch instruction EA not found, cannot NOP it out.")

        self.logger.info(
            "Unflattening patches applied for 0x%X. Requesting IDA reanalysis.",
            self.func_ea,
        )

        # Request IDA to reanalyze the function
        # A more robust way than del_func then plan_ea:
        ida_funcs.remove_func_tail(
            self.func, self.func_ea
        )  # Remove existing flow chart info
        ida_auto.plan_ea(
            self.func.start_ea
        )  # Plan for reanalysis starting from function entry

        # Force reanalysis of the function boundaries
        ida_auto.auto_wait()  # Allow IDA to process pending actions

        # Refresh Hex-Rays views if open
        vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vu and vu.cfunc and vu.cfunc.entry_ea == self.func_ea:
            vu.refresh_view(True)

        self.logger.info(
            "IDA reanalysis requested. Decompilation may need to be manually refreshed."
        )
        return True


def main_unflatten_ida_entry():
    """Entry point when script is run from IDA."""
    logging.basicConfig(
        level=logging.INFO,  # Adjust to DEBUG for more verbose output
        format="%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger(__name__ + ".main_unflatten_ida_entry")

    if CFGRecovery is None:
        logger.error("CFGRecovery class is not available. Cannot proceed.")
        return

    func_ea = idc.get_screen_ea()
    if func_ea == idaapi.BADADDR or not idaapi.get_func(func_ea):
        current_func_name = (
            idc.get_func_name(func_ea) if func_ea != idaapi.BADADDR else "BADADDR"
        )
        logger.error(
            "Please position the cursor within a valid target function. Current EA: 0x%X (%s)",
            func_ea,
            current_func_name,
        )
        idaapi.warning(
            "CFF Unflatten: No function at current address or invalid address."
        )
        return

    logger.info(
        "Starting CFF Unflattening process for function at 0x%X (%s)",
        func_ea,
        idc.get_func_name(func_ea),
    )

    # 1. Recover CFG using CFGRecovery
    cfg_tool = CFGRecovery(func_ea)
    if not cfg_tool.run():  # run() populates graph, dispatcher_var, blocks
        logger.error("CFG Recovery phase failed for function 0x%X.", func_ea)
        idaapi.warning(f"CFF Unflatten: CFG Recovery failed for 0x{func_ea:X}.")
        return

    if cfg_tool.dispatcher_var is None:
        logger.error(
            "CFG Recovery did not identify a dispatcher variable for function 0x%X.",
            func_ea,
        )
        idaapi.warning(
            f"CFF Unflatten: Could not find dispatcher variable for 0x{func_ea:X}."
        )
        return

    if not cfg_tool.graph or not cfg_tool.blocks:
        logger.error(
            "CFG Recovery resulted in an empty graph or no blocks for 0x%X.", func_ea
        )
        idaapi.warning(
            f"CFF Unflatten: CFG Recovery gave empty graph/blocks for 0x{func_ea:X}."
        )
        return

    logger.info(
        "CFG Recovery successful. Dispatcher var_idx: %s. Found %d nodes, %d edges. %d blocks.",
        cfg_tool.dispatcher_var,
        len(cfg_tool.graph.nodes),
        len(cfg_tool.graph.edges),
        len(cfg_tool.blocks),
    )

    # 2. Initialize and run the unflattening process
    unflattener = CFFUnflatten(
        func_ea,
        cfg_tool.graph,
        cfg_tool.dispatcher_var,
        cfg_tool.blocks,
        cfg_tool.cff_entry_setup_points,
    )

    if unflattener.unflatten():
        logger.info("CFF Unflattening process completed for 0x%X.", func_ea)
        idaapi.msg(
            f"CFF Unflattening for 0x{func_ea:X} done. Please check results and re-decompile if necessary."
        )
    else:
        logger.error("CFF Unflattening process failed for 0x%X.", func_ea)
        idaapi.warning(
            f"CFF Unflattening for 0x{func_ea:X} failed. Check logs for details."
        )


if __name__ == "__main__":
    # This allows the script to be run from IDA's script execution dialog
    # Ensure logging is set up if you run this block directly for testing outside IDA
    # (though it's designed for IDA's environment).
    main_unflatten_ida_entry()
