import logging
import re
import typing
from collections import defaultdict

import networkx as nx

import ida_hexrays
import ida_lines
import idaapi
import idautils
import idc


class CFGRecovery:
    # --- BEGIN NEW AssignmentVisitor CLASS ---
    class AssignmentVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, cfg_recovery_instance):
            super().__init__(ida_hexrays.CV_FAST | ida_hexrays.CV_PARENTS)
            self.cfg_recovery = cfg_recovery_instance
            self.assignments_to_dispatcher_found = 0
            self.total_cot_asg_found = 0
            self.logger = logging.getLogger(self.__class__.__name__)

        def visit_expr(self, expr):
            if expr.op == idaapi.cot_asg:
                self.total_cot_asg_found += 1

                lhs_details = "LHS: N/A"
                if expr.x:
                    lhs_op_name = expr.x.opname
                    lhs_var_idx_info = ""
                    if (
                        expr.x.op == idaapi.cot_var
                        and hasattr(expr.x, "v")
                        and expr.x.v
                    ):
                        lhs_var_idx_info = f", VarIdx: {expr.x.v.idx}"
                    lhs_details = f"LHS: op={lhs_op_name}{lhs_var_idx_info}, EA={hex(expr.x.ea if hasattr(expr.x, 'ea') else 0)}"

                rhs_details = "RHS: N/A"
                if expr.y:
                    rhs_op_name = expr.y.opname
                    rhs_val_info = ""
                    if (
                        expr.y.op == idaapi.cot_num
                        and hasattr(expr.y, "n")
                        and expr.y.n
                    ):
                        rhs_val_info = (
                            f", Val: {expr.y.n._value} (0x{expr.y.n._value:X})"
                        )
                    rhs_details = f"RHS: op={rhs_op_name}{rhs_val_info}, EA={hex(expr.y.ea if hasattr(expr.y, 'ea') else 0)}"

                # print(f"[VISITOR_COT_ASG_DETAILS #{self.total_cot_asg_found}] EA: {hex(expr.ea)}, {lhs_details}, {rhs_details}")

                lhs_is_dispatcher = False
                if (
                    expr.x
                    and expr.x.op == idaapi.cot_var
                    and hasattr(expr.x, "v")
                    and expr.x.v
                ):
                    if expr.x.v.idx == self.cfg_recovery.dispatcher_var:
                        lhs_is_dispatcher = True

                rhs_is_num = False
                if expr.y and expr.y.op == idaapi.cot_num:
                    rhs_is_num = True

                if lhs_is_dispatcher and rhs_is_num:
                    self.assignments_to_dispatcher_found += 1
                    target_case = expr.y.n._value

                    # print(
                    #     f">>> [VISITOR_DISPATCHER_ASSIGNMENT] EA: {hex(expr.ea)}, Var_idx: {expr.x.v.idx} = {hex(target_case)} (Value: {expr.y.n._value})"
                    # )
                    self.logger.debug(
                        ">>> [VISITOR_DISPATCHER_ASSIGNMENT] EA: %s, Var_idx: %s = %s (Value: %s)",
                        hex(expr.ea),
                        expr.x.v.idx,
                        hex(target_case),
                        expr.y.n._value,
                    )

                    # Diagnostic print for parent, using visitor's self.parents
                    if not self.parents.empty():
                        diag_parent_item = (
                            self.parents.back()
                        )  # self.parents is citem_vec_t
                        # print(
                        #     f"    Parent (from visitor.parents.back()): op={ida_hexrays.get_ctype_name(diag_parent_item.op)}, ea={hex(diag_parent_item.ea)}, obj_id={diag_parent_item.obj_id if hasattr(diag_parent_item, 'obj_id') else 'N/A'}"
                        # )
                        self.logger.debug(
                            "    Parent (from visitor.parents.back()): op=%s, ea=%s, obj_id=%s",
                            ida_hexrays.get_ctype_name(diag_parent_item.op),
                            hex(diag_parent_item.ea),
                            (
                                diag_parent_item.obj_id
                                if hasattr(diag_parent_item, "obj_id")
                                else "N/A"
                            ),
                        )
                    else:
                        # print(
                        #     f"    Parent: visitor.parents is empty (expr is likely top-level in visited ctree block or statement)."
                        # )
                        self.logger.debug(
                            "    Parent: visitor.parents is empty (expr is likely top-level in visited ctree block or statement)."
                        )

                    current_case = self.cfg_recovery._find_current_case_context(
                        expr, self.parents
                    )
                    if (
                        current_case is not None
                        and current_case in self.cfg_recovery.blocks
                    ):
                        self.cfg_recovery.blocks[current_case]["successors"].append(
                            target_case
                        )
                        self.cfg_recovery.edges.append(
                            (current_case, target_case, None)
                        )
                        # print(
                        #     f"    [+] SUCCESS: Found transition: case {hex(current_case)} -> case {hex(target_case)}"
                        # )
                        self.logger.info(
                            "    [+] SUCCESS: Found transition: case %s -> case %s",
                            hex(current_case),
                            hex(target_case),
                        )
                    else:
                        # print(
                        #     f"    [-] FAILURE: No context for dispatcher assignment to {hex(target_case)} at {hex(expr.ea)}. Dispatcher var idx: {self.cfg_recovery.dispatcher_var}"
                        # )
                        self.logger.warning(
                            "    [-] FAILURE: No context for dispatcher assignment to %s at %s. Dispatcher var idx: %s",
                            hex(target_case),
                            hex(expr.ea),
                            self.cfg_recovery.dispatcher_var,
                        )

                elif lhs_is_dispatcher and not rhs_is_num:
                    # print(
                    #     f"[VISITOR_WARN_DISPATCHER_ASSIGN_NON_NUM_RHS] EA: {hex(expr.ea)}, Dispatcher VarIdx: {expr.x.v.idx}, RHS_op: {expr.y.opname if expr.y else 'N/A'}"
                    # )
                    self.logger.warning(
                        "[VISITOR_WARN_DISPATCHER_ASSIGN_NON_NUM_RHS] EA: %s, Dispatcher VarIdx: %s, RHS_op: %s",
                        hex(expr.ea),
                        expr.x.v.idx,
                        expr.y.opname if expr.y else "N/A",
                    )

            return 0

    # --- END NEW AssignmentVisitor CLASS ---

    def __init__(self, func_ea):
        self.func_ea = func_ea
        self.func = idaapi.get_func(func_ea)
        self.blocks = {}  # case_value -> block_info
        self.edges = []  # (src_case, dst_case, condition)
        self.dispatcher_var = None
        self.graph = nx.DiGraph()
        self.logger = logging.getLogger(self.__class__.__name__)

    def find_dispatcher_variable(self, cfunc):
        """
        Find the state variable used in the dispatcher (n2 in this case):

        2025-06-01 11:31:18.257 Python>switches[0].cexpr.cinsn.cswitch.expr.op ==idaapi.cot_var
        2025-06-01 11:31:18.257 True
        2025-06-01 11:31:26.450 Python>switches[0].cexpr.cinsn.cswitch.expr.v
        2025-06-01 11:31:26.451 <ida_hexrays.var_ref_t; proxy of <Swig Object of type 'var_ref_t *' at 0x0000029C0A263ED0> >
        2025-06-01 11:31:31.067 Python>switches[0].cexpr.cinsn.cswitch.expr.v.idx

        """
        # Look for the main switch statement
        for item in cfunc.treeitems:
            if item.op == idaapi.cit_switch:
                # The switch expression should reference our dispatcher variable
                switch_insn = item.cinsn.cswitch
                if switch_insn.expr.op == idaapi.cot_var:
                    self.dispatcher_var = switch_insn.expr.v.idx
                    return True
        return False

    def extract_case_blocks(self, cfunc):
        """Extract all case blocks from the switch statement.
        Stores the obj_id of the ccase_t citem for context identification."""
        for item in cfunc.treeitems:  # item is a citem_t
            if item.op == idaapi.cit_switch:
                switch_insn: ida_hexrays.cswitch_t = item.cinsn.cswitch

                # Process each case
                for case_idx in range(switch_insn.cases.size()):
                    # switch_insn.cases is ccases_t (a POD vector of ccase_t*)
                    # .at(case_idx) gives ccase_t*
                    case_item: ida_hexrays.ccase_t = switch_insn.cases.at(case_idx)
                    # case_item is a ccase_t, which derives from cinsn_t.
                    # It represents the block of statements for the case.
                    # It has an 'obj_id' and an 'ea'.

                    # The values for this case (e.g., case 1: case 2: ...)
                    # case_item.values is a cvivavec_t
                    for val_idx in range(case_item.values.size()):
                        # For a simple `case N:`, values.size() is 1, values.at(0) is N (sval_t).
                        case_val = case_item.values.at(val_idx)

                        # Ensure we don't overwrite if multiple switch statements exist,
                        # or if a case value appears in different contexts.
                        # This basic model assumes one main dispatcher.
                        if case_val not in self.blocks:
                            self.blocks[case_val] = {
                                "case_item_obj_id": case_item.obj_id,  # Store obj_id of the ccase_t
                                "case_value": case_val,  # Store for completeness, key is case_val
                                "start_ea": case_item.ea,  # EA of the ccase_t itself
                                "successors": [],
                            }
                        # else:
                        #     print(f"[!] Warning: Case value {case_val} (0x{case_val:X}) already processed. Skipping duplicate.")
        if not self.blocks:
            # print("[-] No case blocks extracted. Main switch not found or empty.")
            self.logger.error(
                "[-] No case blocks extracted. Main switch not found or empty."
            )

    def analyze_block_transitions(self, cfunc):
        """Analyze how each block sets the dispatcher variable"""
        # We need to analyze the entire function body to find assignments
        self._analyze_item_recursive(cfunc.body, None)

    def _analyze_item_recursive(self, item, current_case):
        """Recursively analyze ctree items"""
        if item is None:
            return

        # Check if we're inside a case block
        if item.op == idaapi.cit_switch:
            switch_insn = item.cinsn.cswitch
            # Process each case's body
            for case_idx in range(switch_insn.cases.size()):
                case_list = switch_insn.cases[case_idx]
                # Get the case values
                case_values = []
                for val_idx in range(case_list.size()):
                    case_values.append(case_list[val_idx])

                # Analyze this case's body
                for case_val in case_values:
                    # Get the statement list for this case
                    self._analyze_case_body(item, case_val, case_idx)

        # Check for assignments to dispatcher variable
        elif item.op == idaapi.cot_asg:
            if (
                item.x.op == idaapi.cot_var
                and hasattr(item.x, "v")
                and item.x.v.idx == self.dispatcher_var
            ):
                # Found assignment to dispatcher variable
                if item.y.op == idaapi.cot_num:
                    target = item.y.n._value
                    if current_case is not None and current_case in self.blocks:
                        self.blocks[current_case]["successors"].append(target)
                        self.edges.append((current_case, target, None))

        # Handle expressions
        if hasattr(item, "x"):
            self._analyze_item_recursive(item.x, current_case)
        if hasattr(item, "y"):
            self._analyze_item_recursive(item.y, current_case)
        if hasattr(item, "z"):
            self._analyze_item_recursive(item.z, current_case)

        # Handle statements
        if hasattr(item, "cinsn"):
            insn = item.cinsn
            if insn:
                # Handle if statements
                if item.op == idaapi.cit_if:
                    cif = insn.cif
                    # Analyze condition
                    self._analyze_item_recursive(cif.expr, current_case)
                    # Analyze then branch
                    if cif.ithen:
                        self._analyze_if_branch(cif.ithen, current_case, True, cif.expr)
                    # Analyze else branch
                    if cif.ielse:
                        self._analyze_if_branch(
                            cif.ielse, current_case, False, cif.expr
                        )

                # Handle block statements
                elif item.op == idaapi.cit_block:
                    cblock = insn.cblock
                    # Analyze each statement in the block
                    for i in range(cblock.size()):
                        self._analyze_item_recursive(cblock[i], current_case)

        # Handle expression statements
        elif hasattr(item, "cexpr"):
            expr = item.cexpr
            if expr:
                # Recursively analyze the expression
                if hasattr(expr, "x"):
                    self._analyze_item_recursive(expr.x, current_case)
                if hasattr(expr, "y"):
                    self._analyze_item_recursive(expr.y, current_case)

    def _analyze_case_body(self, switch_item, case_val, case_idx):
        """Analyze a specific case body"""
        # In a switch statement, we need to look at the parent block
        # and find statements that follow this case
        parent = switch_item.parent
        if parent and parent.op == idaapi.cit_block:
            # Look through the parent block for our case
            found_our_case = False
            for i in range(parent.cinsn.cblock.size()):
                stmt = parent.cinsn.cblock[i]
                if stmt == switch_item:
                    found_our_case = True
                elif found_our_case:
                    # This might be part of our case body
                    self._analyze_item_for_case(stmt, case_val)

    def _analyze_item_for_case(self, item, case_val):
        """Analyze an item looking for dispatcher assignments for a specific case"""
        if item is None:
            return

        # Check for direct assignment
        if item.op == idaapi.cot_asg:
            if (
                hasattr(item, "x")
                and item.x.op == idaapi.cot_var
                and hasattr(item.x, "v")
                and item.x.v.idx == self.dispatcher_var
            ):
                if item.y.op == idaapi.cot_num:
                    target = item.y.n._value
                    if case_val in self.blocks:
                        self.blocks[case_val]["successors"].append(target)
                        self.edges.append((case_val, target, None))

        # Recursively check children
        if hasattr(item, "x"):
            self._analyze_item_for_case(item.x, case_val)
        if hasattr(item, "y"):
            self._analyze_item_for_case(item.y, case_val)

        # Handle statements
        if hasattr(item, "cinsn") and item.cinsn:
            if item.op == idaapi.cit_block:
                for i in range(item.cinsn.cblock.size()):
                    self._analyze_item_for_case(item.cinsn.cblock[i], case_val)
            elif item.op == idaapi.cit_if:
                self._analyze_item_for_case(item.cinsn.cif.ithen, case_val)
                if item.cinsn.cif.ielse:
                    self._analyze_item_for_case(item.cinsn.cif.ielse, case_val)

    def _analyze_if_branch(self, branch, current_case, is_then, condition):
        """Analyze an if branch for dispatcher assignments"""
        assignments = []

        def find_assignments(item):
            if item is None:
                return

            if item.op == idaapi.cot_asg:
                if (
                    hasattr(item, "x")
                    and item.x.op == idaapi.cot_var
                    and hasattr(item.x, "v")
                    and item.x.v.idx == self.dispatcher_var
                    and item.y.op == idaapi.cot_num
                ):
                    assignments.append(item.y.n._value)

            # Recursively check
            if hasattr(item, "x"):
                find_assignments(item.x)
            if hasattr(item, "y"):
                find_assignments(item.y)

            if hasattr(item, "cinsn") and item.cinsn:
                if item.op == idaapi.cit_block:
                    for i in range(item.cinsn.cblock.size()):
                        find_assignments(item.cinsn.cblock[i])

        find_assignments(branch)

        # Add edges with condition info
        for target in assignments:
            if current_case is not None and current_case in self.blocks:
                cond_str = "then" if is_then else "else"
                self.blocks[current_case]["successors"].append(target)
                self.edges.append((current_case, target, cond_str))

    def analyze_simple(self, cfunc):
        """Simpler analysis approach - look for pattern n2 = value, using a ctree visitor."""
        # print(
        #     f"[ANALYSIS_SIMPLE_VISITOR] Starting. Dispatcher var idx: {self.dispatcher_var}"
        # )
        self.logger.info(
            "[ANALYSIS_SIMPLE_VISITOR] Starting. Dispatcher var idx: %s",
            self.dispatcher_var,
        )

        visitor = CFGRecovery.AssignmentVisitor(self)
        visitor.apply_to(cfunc.body, None)  # type: ignore

        total_cot_asg_found = visitor.total_cot_asg_found
        assignments_to_dispatcher_found = visitor.assignments_to_dispatcher_found

        # print(
        #     f"[ANALYSIS_SIMPLE_VISITOR_SUMMARY] Total cot_asg items processed by visitor: {total_cot_asg_found}"
        # )
        self.logger.info(
            "[ANALYSIS_SIMPLE_VISITOR_SUMMARY] Total cot_asg items processed by visitor: %s",
            total_cot_asg_found,
        )
        # print(
        #     f"[ANALYSIS_SIMPLE_VISITOR_SUMMARY] Assignments to dispatcher variable (idx {self.dispatcher_var}) with numeric RHS found by visitor: {assignments_to_dispatcher_found}"
        # )
        self.logger.info(
            "[ANALYSIS_SIMPLE_VISITOR_SUMMARY] Assignments to dispatcher variable (idx %s) with numeric RHS found by visitor: %s",
            self.dispatcher_var,
            assignments_to_dispatcher_found,
        )

    def _find_current_case_context(self, item_to_check, item_parents_from_visitor):
        """
        Determine which case a citem_to_check belongs to by checking it and its parent chain.
        item_to_check: The citem (e.g., a cexpr_t for an assignment) whose context we need.
        item_parents_from_visitor: The citem_vec_t from the ctree_visitor_t, representing the
                                   parent chain of item_to_check (from furthest to closest parent).
                                   Note: This list does NOT include item_to_check itself.
        """
        if not item_to_check:
            # print(
            #     f"---> [_FIND_CONTEXT_CALLED] item_to_check is falsey (None or invalid proxy?). Value: {str(item_to_check)}. Returning None."
            # )
            self.logger.debug(
                "---> [_FIND_CONTEXT_CALLED] item_to_check is falsey (None or invalid proxy?). Value: %s. Returning None.",
                str(item_to_check),
            )
            return None

        # For logging the path taken during search
        path_for_logging = []
        # print(
        #     f"---> [_FIND_CONTEXT_DEBUG] item_to_check before op access: type={type(item_to_check)}, value={str(item_to_check)}"
        # )
        self.logger.debug(
            "---> [_FIND_CONTEXT_DEBUG] item_to_check before op access: type=%s, value=%s",
            type(item_to_check),
            str(item_to_check),
        )

        # --- BEGIN NEW DIAGNOSTICS & ERROR HANDLING ---
        try:
            # print(f"    DIR(item_to_check): {dir(item_to_check)}")  # Print attributes
            self.logger.debug(
                "    DIR(item_to_check): %s", dir(item_to_check)
            )  # Print attributes
            item_op = item_to_check.op
            # --- BEGIN NEW DIAGNOSTIC ---
            if item_op is None:
                # print(
                #     f"!!! DIAGNOSTIC: item_op is None immediately after item_to_check.op assignment."
                # )
                self.logger.warning(
                    "!!! DIAGNOSTIC: item_op is None immediately after item_to_check.op assignment."
                )
            # --- END NEW DIAGNOSTIC ---
            item_ea = item_to_check.ea

            item_obj_id_val = "N/A"  # Default
            if hasattr(item_to_check, "obj_id"):  # Check before direct access
                item_obj_id_val = item_to_check.obj_id
            item_obj_id_str = str(item_obj_id_val)

            current_item_desc = f"(Item: op={ida_hexrays.get_ctype_name(item_op)}, ea={hex(item_ea)}, obj_id={item_obj_id_str})"
        except AttributeError as e:
            # print(f"!!! ATTR_ERROR in _find_current_case_context: {e}")
            self.logger.error(
                "!!! ATTR_ERROR in _find_current_case_context: %s", e, exc_info=True
            )
            # print(
            #     f"    item_to_check at time of error: type={type(item_to_check)}, value={str(item_to_check)}"
            # )
            self.logger.error(
                "    item_to_check at time of error: type=%s, value=%s",
                type(item_to_check),
                str(item_to_check),
            )
            if hasattr(item_to_check, "this") and item_to_check.this is None:
                # print(
                #     "    item_to_check.this is None (underlying C++ object likely gone or invalid)"
                # )
                self.logger.error(
                    "    item_to_check.this is None (underlying C++ object likely gone or invalid)"
                )

            current_item_desc = "(Item: ERROR RETRIEVING DETAILS)"
        # --- END NEW DIAGNOSTICS & ERROR HANDLING ---
        path_for_logging.append(current_item_desc)

        # print(f"---> [_FIND_CONTEXT_CALLED] Checking context for: {current_item_desc}")

        # 1. Check the item_to_check itself
        if hasattr(item_to_check, "obj_id"):
            for case_val, block_info in self.blocks.items():
                if (
                    "case_item_obj_id" in block_info
                    and item_to_check.obj_id == block_info["case_item_obj_id"]
                ):
                    # print(f"---> [_FIND_CONTEXT_SUCCESS] Matched current item ({item_to_check.obj_id}) for case {hex(case_val)}. Path: {' -> '.join(path_for_logging)}")
                    return case_val

        # 2. Check its parents using the visitor's parent stack (iterating from closest to furthest)
        if item_parents_from_visitor:  # citem_vec_t is the type
            # The list is ordered from root down to immediate parent.
            # So, iterate in reverse to go from immediate parent upwards.
            for i in range(item_parents_from_visitor.size() - 1, -1, -1):
                parent_citem = typing.cast(
                    ida_hexrays.citem_t, item_parents_from_visitor.at(i)
                )

                # --- BEGIN ADDED NULL CHECK FOR PARENT_CITEM ---
                if not parent_citem:
                    # print(f"    [!] Warning: Parent citem at index {i} in visitor parent stack is None or invalid. Skipping.")
                    self.logger.warning(
                        "    [!] Warning: Parent citem at index %s in visitor parent stack is None or invalid. Skipping.",
                        i,
                    )
                    continue
                # --- END ADDED NULL CHECK FOR PARENT_CITEM ---

                # --- BEGIN MODIFIED PARENT LOGGING ---
                parent_op_str = "N/A"
                parent_ea_str = hex(parent_citem.ea)
                parent_obj_id_str = (
                    str(parent_citem.obj_id)
                    if hasattr(parent_citem, "obj_id")
                    else "N/A"
                )

                if parent_citem.is_expr():  # Check if it's an expression
                    # If it's an expression, get the opcode from the cexpr_t object
                    parent_op_str = ida_hexrays.get_ctype_name(parent_citem.cexpr.op)
                else:
                    # If it's not an expression, it's likely an instruction (or empty/other).
                    # The citem_t.op itself holds the relevant opcode (e.g., cit_block, cit_if).
                    parent_op_str = ida_hexrays.get_ctype_name(parent_citem.op)

                parent_desc = f"(Parent: op={parent_op_str}, ea={parent_ea_str}, obj_id={parent_obj_id_str})"
                # --- END MODIFIED PARENT LOGGING ---
                path_for_logging.append(parent_desc)

                if hasattr(parent_citem, "obj_id"):
                    for case_val, block_info in self.blocks.items():
                        if (
                            "case_item_obj_id" in block_info
                            and parent_citem.obj_id == block_info["case_item_obj_id"]
                        ):
                            # print(f"---> [_FIND_CONTEXT_SUCCESS] Matched parent ({parent_citem.obj_id}) for case {hex(case_val)}. Path: {' -> '.join(path_for_logging)}")
                            return case_val

        # print(f"---> [_FIND_CONTEXT_FAILURE] No context found. Path: {' -> '.join(path_for_logging)}")
        return None

    def build_graph(self):
        """Build NetworkX graph from extracted information"""
        # Add nodes
        for case_val, block_info in self.blocks.items():
            self.graph.add_node(case_val, **block_info)

        # Add edges
        for src, dst, condition in self.edges:
            if src in self.graph and dst in self.graph:
                if condition:
                    self.graph.add_edge(src, dst, condition=condition)
                else:
                    self.graph.add_edge(src, dst)

    def generate_dot(self):
        """Generate DOT format for visualization"""
        dot_lines = ["digraph CFG {"]
        dot_lines.append("    rankdir=TB;")
        dot_lines.append("    node [shape=box];")

        # Add nodes
        for node in self.graph.nodes():
            label = f"Case 0x{node:X}" if isinstance(node, int) else f"Case {node}"
            dot_lines.append(f'    "{node}" [label="{label}"];')

        # Add edges
        for src, dst, data in self.graph.edges(data=True):
            if "condition" in data:
                label = data["condition"]
                dot_lines.append(f'    "{src}" -> "{dst}" [label="{label}"];')
            else:
                dot_lines.append(f'    "{src}" -> "{dst}";')

        dot_lines.append("}")
        return "\n".join(dot_lines)

    def run(self):
        """Main function to run the CFG recovery"""
        # print(f"[*] Starting CFG recovery for function at 0x{self.func_ea:X}")
        self.logger.info("[*] Starting CFG recovery for function at 0x%X", self.func_ea)

        # Get decompiled function
        cfunc = idaapi.decompile(self.func_ea)
        if not cfunc:
            # print("[-] Failed to decompile function")
            self.logger.error("[-] Failed to decompile function")
            return False

        # Find dispatcher variable
        if not self.find_dispatcher_variable(cfunc):
            # print("[-] Failed to find dispatcher variable")
            self.logger.error("[-] Failed to find dispatcher variable")
            return False

        # print(f"[+] Found dispatcher variable at index: {self.dispatcher_var}")
        self.logger.info(
            "[+] Found dispatcher variable at index: %s", self.dispatcher_var
        )

        # Extract case blocks
        self.extract_case_blocks(cfunc)
        # print(f"[+] Extracted {len(self.blocks)} case blocks")
        self.logger.info("[+] Extracted %s case blocks", len(self.blocks))

        # Use simple analysis approach
        self.analyze_simple(cfunc)
        # print(f"[+] Found {len(self.edges)} control flow edges")
        self.logger.info("[+] Found %s control flow edges", len(self.edges))

        # Build graph
        self.build_graph()

        # Generate outputs
        dot_output = self.generate_dot()
        output_file = f"cfg_0x{self.func_ea:X}.dot"
        with open(output_file, "w") as f:
            f.write(dot_output)
        # print(f"[+] Saved DOT file to {output_file}")
        self.logger.info("[+] Saved DOT file to %s", output_file)
        # print(f"[+] Visualize with: dot -Tpng {output_file} -o cfg.png")
        self.logger.info("[+] Visualize with: dot -Tpng %s -o cfg.png", output_file)

        return True


# Usage
def main():
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Get a logger instance for this module if you plan to use it elsewhere in main,
    # otherwise, the root logger configured by basicConfig will handle logs from CFGRecovery.
    # For simplicity, the logger instance in CFGRecovery methods will use __name__ (i.e., the script's name as a module)

    # Get current function
    func_ea = idc.get_screen_ea()
    func = idaapi.get_func(func_ea)

    if not func:
        # print("[-] No function at current address")
        # It's better to log this with a logger available in main or use logging directly.
        logging.error(
            "[-] No function at current address"
        )  # Using logging directly as logger instance might not be set up here yet if main is very simple.
        return

    # Run CFG recovery
    recovery = CFGRecovery(func.start_ea)
    recovery.run()


if __name__ == "__main__":
    main()
