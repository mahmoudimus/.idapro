import traceback

import ida_hexrays
import idaapi


class RefFinder(idaapi.ctree_visitor_t):
    def __init__(self):
        super().__init__(idaapi.CV_FAST)
        self.funcs = set()
        self.globals = set()

    def visit_expr(self, expr):
        # function call: expr.op == cot_call, target in expr.x
        if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj:
            self.funcs.add(expr.x.obj_ea)
        # any object reference that's not a local (locals are cot_var)
        elif expr.op == idaapi.cot_obj:
            self.globals.add(expr.obj_ea)
        return 0


def get_pseudocode_refs(func_ea):
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays not available")

    f = idaapi.get_func(func_ea)
    cfunc = ida_hexrays.decompile(f)
    finder = RefFinder()
    finder.apply_to(
        cfunc.body, None
    )  # walks the entire CTree  [oai_citation:2‡Gist](https://gist.github.com/NyaMisty/7f149e6340430a56f5c5b77418a8c454?utm_source=chatgpt.com)

    print(f"Calls in pseudocode of {hex(func_ea)}:")
    for ea in sorted(finder.funcs):
        print(f"  {hex(ea)}: {idaapi.get_func_name(ea)}")

    print(f"\nGlobal vars in pseudocode of {hex(func_ea)}:")
    for ea in sorted(finder.globals):
        print(f"  {hex(ea)}: {idaapi.get_name(ea) or '<unnamed>'}")


def dump_pseudocode_locals(func_ea):
    """
    func_ea       address of the function to retitle
    loc_mapping   dict mapping (spoff, width) → desired name
    """
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler not available")

    f = idaapi.get_func(func_ea)
    cfunc = ida_hexrays.decompile(f)
    if not cfunc:
        print("Decompile failed for", hex(func_ea))
        return

    # open or switch to the decompiler view
    vu = idaapi.open_pseudocode(func_ea, 0)

    for lvar in vu.cfunc.lvars:
        print("local variable names:", lvar.name)

    calls = set()
    globals = set()

    # 2) walk every micro-basic block
    for (
        blk
    ) in (
        cfunc.mba
    ):  # mba_t array on cfunc_t  [oai_citation:0‡Elastic](https://www.elastic.co/security-labs/introduction-to-hexrays-decompilation-internals?utm_source=chatgpt.com)
        insn = (
            blk.head
        )  # first minsn_t in the block  [oai_citation:1‡Elastic](https://www.elastic.co/jp/security-labs/introduction-to-hexrays-decompilation-internals?utm_source=chatgpt.com)
        while insn:
            # look for direct calls
            if insn.opcode == ida_hexrays.m_call:
                # for an m_call, x.value is the EA of the target
                calls.add(insn.x.value)

            # look for memory refs (globals/statics)
            # this covers loads/stores from absolute addresses
            elif insn.opcode in (ida_hexrays.m_load, ida_hexrays.m_store):
                # x.value is the address being accessed
                globals.add(insn.x.value)

            insn = insn.next  # move to the next micro-instruction

    # 3) print out what we found
    print(f"Calls in {hex(func_ea)}:")
    for ea in sorted(calls):
        print(f"  {hex(ea)}: {idc.get_func_name(ea)}")
    print(f"\nGlobal/data refs in {hex(func_ea)}:")
    for ea in sorted(globals):
        print(f"  {hex(ea)}: {idc.get_name(ea) or '<unnamed>'}")
    # # rename_lvar(v, name, is_user_name=True)  [oai_citation:2‡python.docs.hex-rays.com](https://python.docs.hex-rays.com/classida__hexrays_1_1vdui__t.html?utm_source=chatgpt.com)
    # if vu.rename_lvar(lvar, newname, True):
    #     print(f"  renamed sp+{loc.stkoff:#x} → {newname}")
    vu.refresh_view(True)


try:
    print(dump_pseudocode_locals(idaapi.get_screen_ea()))
except Exception as e:
    print("Exception caught", e)
    traceback.print_exc()


get_pseudocode_refs(idaapi.get_screen_ea())
vu = idaapi.open_pseudocode(idaapi.get_screen_ea(), 0)
vu.refresh_view(True)
