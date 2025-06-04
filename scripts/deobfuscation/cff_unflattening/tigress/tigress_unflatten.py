import ida_auto
import ida_bytes
import ida_gdl
import ida_hexrays
import ida_lines
import ida_nalt
import ida_pro
import idaapi
import idautils
import idc

# def unflatten_dispatcher(si, root_block, state_var_inst, to_patch_list):
#     """This recursive Function calls itself until all nested Blocks are found.
#     Could run into the recursion Limit if big Functions are used

#     Args:
#         si (switch_info_t): Dispatcher Switch
#         root_block (BasicBlock): Root BasicBlock
#         state_var_inst (str): state variable instruction string in ida
#         to_patch_list (list): list of byte Patches
#     """
#     for bb in root_block.succs():
#         # breakpoint()

#         bb_last_inst = idc.prev_head(bb.end_ea)
#         if prep_patch(bb, bb_last_inst, state_var_inst, si, to_patch_list):
#             continue
#         else:
#             if idc.get_name(bb.start_ea) != idc.print_operand(bb_last_inst, 0):
#                 unflatten_dispatcher(si, bb, state_var_inst, to_patch_list)


# def prep_patch(bb, bb_last_inst, state_var_inst, si, to_patch_list, skip_jmp=False):
#     """checks if the Block is patchable and appends the patch to the list

#     Args:
#         bb (BasicBlock): BasicBlock to be examined
#         bb_last_inst (int): address of last instruction in Block
#         state_var_inst (str): state variable instruction string in ida
#         si (switch_info_t): Dispatcher Switch
#         to_patch_list (list): list of byte Patches
#         skip_jmp (bool, optional): If True skips the jmp instruction Check. Defaults to False.

#     Returns:
#         bool: returns True if not a Branch Block
#     """
#     if (
#         idc.print_insn_mnem(bb_last_inst) == "jmp"
#         or skip_jmp
#         or idc.print_insn_mnem(bb_last_inst) == "nop"
#     ):
#         state_var_ea = idc.prev_head(bb_last_inst)

#         if idc.print_operand(state_var_ea, 0) == state_var_inst:
#             print(format_bb(bb))

#             state_var = to_int(idc.print_operand(state_var_ea, 1))
#             print(f"state Variable: {state_var}")

#             real_succs_func_addr = int(
#                 get_jumptable_function_address_by_case(si, state_var), 16
#             )
#             real_succs_func_name = idc.get_name(real_succs_func_addr)

#             success, data = idautils.Assemble(
#                 state_var_ea, f"jmp {real_succs_func_addr}"
#             )
#             ida_bytes.del_items(bb_last_inst)

#             if success:
#                 to_patch_list.append([state_var_ea, data])
#                 print(
#                     f"Basic Block addr {hex(bb_last_inst)}, Succesor Function addr: {real_succs_func_name}"
#                 )

#         return True


# def patch_binary(to_patch_list):
#     """apply binary patches from list

#     Args:
#         to_patch_list (list): list of byte Patches
#     """
#     for patch in to_patch_list:
#         idaapi.patch_bytes(patch[0], patch[1])


# def to_int(hex_str) -> int:
#     """converts ida hex strings to int

#     Args:
#         hex_str (str): ida hex string

#     Returns:
#         int: converted integer Object
#     """
#     if hex_str[-1] == "h":
#         return int(hex_str[:-1], 16)
#     else:
#         return int(hex_str)


# def get_dispatcher_block(ea) -> idaapi.BasicBlock:
#     """Searches for the Dispatcher Block and returns it

#     Args:
#         ea (str): Address of function

#     Returns:
#         idaapi.BasicBlock: Dispatcher Block
#     """
#     dispatcher_block = [0, 0]
#     function = idaapi.get_func(ea)
#     flowchart = idaapi.FlowChart(function)
#     print(
#         "Function starting at 0x%x consists of %d basic blocks"
#         % (function.start_ea, flowchart.size)
#     )

#     for bb in flowchart:
#         bb_succs_list = list(bb.succs())  # maybe sum less memory
#         if len(bb_succs_list) > dispatcher_block[1]:
#             dispatcher_block[0] = bb
#             dispatcher_block[1] = len(bb_succs_list)

#     print(
#         "DispatcherBlock starting at 0x%x has %d succesor basic blocks"
#         % (dispatcher_block[0].start_ea, dispatcher_block[1])
#     )

#     return dispatcher_block[0]


# def find_jumps(si: ida_nalt.switch_info_t) -> list:
#     """unused function

#     Args:
#         si (ida_nalt.switch_info_t): switch dispatcher

#     Returns:
#         list: jumptable cases
#     """
#     jtable = []
#     e_size = si.get_jtable_element_size()
#     for num in range(0, si.get_jtable_size()):
#         print(si.elbase)
#         jtable.append(
#             hex(
#                 int.from_bytes(
#                     ida_bytes.get_bytes(si.jumps + (num * e_size), e_size), "little"
#                 )
#                 + si.elbase
#                 - 0x100000000
#             )
#         )

#     return jtable


# def get_jumptable_function_address_by_case(si: ida_nalt.switch_info_t, case_num) -> str:
#     """returns case succesor Block address

#     Args:
#         si (ida_nalt.switch_info_t): Dispatcher Switch
#         case_num (int): number of switch Case

#     Returns:
#         str: address of case
#     """
#     e_size = si.get_jtable_element_size()
#     func_ea = hex(
#         int.from_bytes(
#             ida_bytes.get_bytes(si.jumps + (case_num * e_size), e_size), "little"
#         )
#         + si.elbase
#         - 0x100000000
#     )
#     return func_ea


# def get_jumptable(func: idaapi.func_t):
#     """iterates over function and returns first Jump Table

#     Args:
#         func (idaapi.func_t): flattend function

#     Returns:
#         switch_info_t: returns switch
#     """
#     si = ida_nalt.switch_info_t()
#     for head_ea in idautils.Heads(func.start_ea, func.end_ea):
#         if ida_nalt.get_switch_info(si, head_ea) is not None:  # jump table
#             return si


# def format_bb(bb):
#     """formats Basic Block properties

#     Args:
#         bb (BasicBlock): BasicBlock
#     """
#     bbtype = {
#         0: "fcb_normal",
#         1: "fcb_indjump",
#         2: "fcb_ret",
#         3: "fcb_cndret",
#         4: "fcb_noret",
#         5: "fcb_enoret",
#         6: "fcb_extern",
#         7: "fcb_error",
#     }
#     return "ID: %d, Start: 0x%x, End: 0x%x Size: %d, " "Type: %s" % (
#         bb.id,
#         bb.start_ea,
#         bb.end_ea,
#         (bb.end_ea - bb.start_ea),
#         bbtype[bb.type],
#     )


def unflatten_dispatcher(si, root_block, state_var_inst, to_patch_list):
    """This recursive Function calls itself until all nested Blocks are found.
    Could run into the recursion Limit if big Functions are used

    Args:
        si (switch_info_t): Dispatcher Switch
        root_block (BasicBlock): Root BasicBlock
        state_var_inst (str): state variable instruction string in ida
        to_patch_list (list): list of byte Patches
    """
    for bb in root_block.succs():
        # breakpoint()

        bb_last_inst = idc.prev_head(bb.end_ea)
        if prep_patch(bb, bb_last_inst, state_var_inst, si, to_patch_list):
            continue
        else:
            if idc.get_name(bb.start_ea) != idc.print_operand(bb_last_inst, 0):
                unflatten_dispatcher(si, bb, state_var_inst, to_patch_list)


def prep_patch(bb, bb_last_inst, state_var_inst, si, to_patch_list, skip_jmp=False):
    """checks if the Block is patchable and appends the patch to the list

    Args:
        bb (BasicBlock): BasicBlock to be examined
        bb_last_inst (int): address of last instruction in Block
        state_var_inst (str): state variable instruction string in ida
        si (switch_info_t): Dispatcher Switch
        to_patch_list (list): list of byte Patches
        skip_jmp (bool, optional): If True skips the jmp instruction Check. Defaults to False.

    Returns:
        bool: returns True if not a Branch Block
    """
    if (
        idc.print_insn_mnem(bb_last_inst) == "jmp"
        or skip_jmp
        or idc.print_insn_mnem(bb_last_inst) == "nop"
    ):
        state_var_ea = idc.prev_head(bb_last_inst)

        if idc.print_operand(state_var_ea, 0) == state_var_inst:
            print(format_bb(bb))

            state_var = to_int(idc.print_operand(state_var_ea, 1))
            print(f"state Variable: {state_var}")

            real_succs_func_addr = int(
                get_jumptable_function_address_by_case(si, state_var), 16
            )
            real_succs_func_name = idc.get_name(real_succs_func_addr)

            success, data = idautils.Assemble(
                state_var_ea, f"jmp {real_succs_func_addr}"
            )
            ida_bytes.del_items(bb_last_inst)

            if success:
                to_patch_list.append([state_var_ea, data])
                print(
                    f"Basic Block addr {hex(bb_last_inst)}, Succesor Function addr: {real_succs_func_name}"
                )

        return True


def patch_binary(to_patch_list):
    """apply binary patches from list

    Args:
        to_patch_list (list): list of byte Patches
    """
    for patch in to_patch_list:
        idaapi.patch_bytes(patch[0], patch[1])


def to_int(hex_str) -> int:
    """converts ida hex strings to int

    Args:
        hex_str (str): ida hex string

    Returns:
        int: converted integer Object
    """
    if hex_str[-1] == "h":
        return int(hex_str[:-1], 16)
    else:
        return int(hex_str)


def get_dispatcher_block(ea) -> idaapi.BasicBlock:
    """Searches for the Dispatcher Block and returns it

    Args:
        ea (str): Address of function

    Returns:
        idaapi.BasicBlock: Dispatcher Block
    """
    dispatcher_block = [0, 0]
    function = idaapi.get_func(ea)
    flowchart = idaapi.FlowChart(function)
    print(
        "Function starting at 0x%x consists of %d basic blocks"
        % (function.start_ea, flowchart.size)
    )

    for bb in flowchart:
        bb_succs_list = list(bb.succs())  # maybe sum less memory
        if len(bb_succs_list) > dispatcher_block[1]:
            dispatcher_block[0] = bb
            dispatcher_block[1] = len(bb_succs_list)

    print(
        "DispatcherBlock starting at 0x%x has %d succesor basic blocks"
        % (dispatcher_block[0].start_ea, dispatcher_block[1])
    )

    return dispatcher_block[0]


def find_jumps(si: ida_nalt.switch_info_t) -> list:
    """unused function

    Args:
        si (ida_nalt.switch_info_t): switch dispatcher

    Returns:
        list: jumptable cases
    """
    jtable = []
    e_size = si.get_jtable_element_size()
    for num in range(0, si.get_jtable_size()):
        print(si.elbase)
        jtable.append(
            hex(
                int.from_bytes(
                    ida_bytes.get_bytes(si.jumps + (num * e_size), e_size), "little"
                )
                + si.elbase
                - 0x100000000
            )
        )

    return jtable


def get_jumptable_function_address_by_case(si: ida_nalt.switch_info_t, case_num) -> str:
    """returns case succesor Block address

    Args:
        si (ida_nalt.switch_info_t): Dispatcher Switch
        case_num (int): number of switch Case

    Returns:
        str: address of case
    """
    e_size = si.get_jtable_element_size()
    func_ea = hex(
        int.from_bytes(
            ida_bytes.get_bytes(si.jumps + (case_num * e_size), e_size), "little"
        )
        + si.elbase
        - 0x100000000
    )
    return func_ea


def get_jumptable(func: idaapi.func_t):
    """iterates over function and returns first Jump Table

    Args:
        func (idaapi.func_t): flattend function

    Returns:
        switch_info_t: returns switch
    """
    si = ida_nalt.switch_info_t()
    for head_ea in idautils.Heads(func.start_ea, func.end_ea):
        if ida_nalt.get_switch_info(si, head_ea) is not None:  # jump table
            return si


def format_bb(bb):
    """formats Basic Block properties

    Args:
        bb (BasicBlock): BasicBlock
    """
    bbtype = {
        0: "fcb_normal",
        1: "fcb_indjump",
        2: "fcb_ret",
        3: "fcb_cndret",
        4: "fcb_noret",
        5: "fcb_enoret",
        6: "fcb_extern",
        7: "fcb_error",
    }
    return "ID: %d, Start: 0x%x, End: 0x%x Size: %d, " "Type: %s" % (
        bb.id,
        bb.start_ea,
        bb.end_ea,
        (bb.end_ea - bb.start_ea),
        bbtype[bb.type],
    )


def get_pseudocode(func) -> str:

    cfunc = ida_hexrays.decompile(func)
    if cfunc is None:
        print("Failed to decompile!")  # add to log
        return False

    sv = cfunc.get_pseudocode()

    decompiled_func_string = ""
    for sline in sv:
        decompiled_func_string += f"{ida_lines.tag_remove(sline.line)}\n"

    return decompiled_func_string


def find_function_address_by_name(func_name) -> int:
    for func in idautils.Functions():
        print(func)
        if idc.get_func_name(func) == func_name:
            return func


def notflatten_evaluate(func_name):
    ea = find_function_address_by_name(func_name)  # function address
    func = idaapi.get_func(ea)
    filename = f"{func_name}"

    ida_gdl.gen_flow_graph(
        filename, func_name, func, func.start_ea, func.end_ea, ida_gdl.CHART_GEN_DOT
    )

    # generate pseudocode
    pseudocode = get_pseudocode(func)
    with open(f"{filename}.c", "w", encoding="utf-8") as f:
        f.write(pseudocode)


def unflatten_evaluate(func_name):
    ea = find_function_address_by_name(func_name)  # function address
    func = idaapi.get_func(ea)
    si = get_jumptable(func)
    dispatcher_block = get_dispatcher_block(ea)
    state_var_inst = idc.print_operand(
        dispatcher_block.start_ea, 1
    )  # state Variable name in IDA
    to_patch_list = []
    filename = f"{func_name}"

    # prep unfallten Graph
    try:
        unflatten_dispatcher(si, dispatcher_block, state_var_inst, to_patch_list)
    except Exception as e:
        print(f"Error: {e}")
        return

    # prep patch entry Block
    flowchart = idaapi.FlowChart(func)
    bb = flowchart[0]
    prep_patch(bb, bb.end_ea, state_var_inst, si, to_patch_list, skip_jmp=True)

    # patch dispatcher Block not working right know
    dispatcher_block_last_inst = idc.prev_head(dispatcher_block.end_ea)

    #   ida_bytes.del_items(dispatcher_block_last_inst)

    # workaround
    success, nop = idautils.Assemble(dispatcher_block_last_inst, f"nop")
    if success:
        to_patch_list.append([dispatcher_block_last_inst, nop])
        ida_bytes.del_items(dispatcher_block_last_inst)

    # apply patches
    patch_binary(to_patch_list)
    # generate graph
    ida_auto.auto_wait()
    ida_gdl.gen_flow_graph(
        filename, func_name, func, func.start_ea, func.end_ea, ida_gdl.CHART_GEN_DOT
    )

    # generate pseudocode
    pseudocode = get_pseudocode(func)
    with open(f"{filename}.c", "w", encoding="utf-8") as f:
        f.write(pseudocode)


def main():
    ida_auto.auto_wait()
    # Init Variables
    ea = find_function_address_by_name("str_flip")  # put function name here
    func = idaapi.get_func(ea)
    si = get_jumptable(func)
    dispatcher_block = get_dispatcher_block(ea)
    state_var_inst = idc.print_operand(
        dispatcher_block.start_ea, 1
    )  # state Variable name in IDA
    to_patch_list = []
    print(f"state variable Instruction: {state_var_inst}")

    # prep unfallten Graph
    unflatten_dispatcher(si, dispatcher_block, state_var_inst, to_patch_list)

    # prep patch entry Block
    flowchart = idaapi.FlowChart(func)
    bb = flowchart[0]
    prep_patch(bb, bb.end_ea, state_var_inst, si, to_patch_list, skip_jmp=True)

    # patch dispatcher Block not working right know
    dispatcher_block_last_inst = idc.prev_head(dispatcher_block.end_ea)

    #   ida_bytes.del_items(dispatcher_block_last_inst)

    # workaround
    success, nop = idautils.Assemble(dispatcher_block_last_inst, f"nop")
    if success:
        to_patch_list.append([dispatcher_block_last_inst, nop])
        ida_bytes.del_items(dispatcher_block_last_inst)

    # apply patches
    patch_binary(to_patch_list)


if __name__ == "__main__":
    main()
