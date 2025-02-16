
import idaapi
import idautils

from miasm.analysis.binary import Container
from miasm.expression.expression import *
from miasm.analysis.machine import Machine
from unittest import mock


def compare_args(args, scn_args, conn):
    for ind, val in args.items():
        possible_vals = (
            conn.modules.idc.get_operand_value(scn_args[ind], 0),
            conn.modules.idc.get_operand_value(scn_args[ind], 1),
        )
        if val not in possible_vals:
            return False
    return True


def patch_xref(instr_offset, patch_offset, mdis, mn, exectbl):
    inst = mdis.dis_instr(instr_offset)
    new_loc_key = mdis.loc_db.add_location(offset=patch_offset - instr_offset)
    inst.args[0] = ExprLoc(new_loc_key, 32)
    patch = list(filter(lambda x: len(x) == inst.l, mn.asm(inst, mdis.loc_db)))
    assert len(patch) > 0, "Couldn't assemble instruction of the same size."
    exectbl.img_rva[exectbl.virt2rva(instr_offset)] = patch[0]


def patch_xrefs(find_addr, patch_addr, args):
    """
    Patches xrefs with certain arguments
    :param find_addr: address of function whose xrefs are to be replaced
    :param patch_addr: the new target of the xref call
    :param args: dictionary mapping number of argument to its required value
    :param ip: optional, IP of the computer running rpyc server in IDA
    :param port: optional, port of the computer running rpyc server in IDA
    :param conn: optional, already estabilished connection to running rpyc server in IDA
    :return: None
    """

    file_name = idaapi.get_input_file_path()
    cont = Container.from_stream(open(file_name, "rb"))
    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream)
    exectbl = cont.executable

    for r in idautils.XrefsTo(find_addr):
        scn_args = idaapi.get_arg_addrs(r.frm)
        if scn_args is None and args:
            print("Couldn't find args of %x" % r.frm)
            continue
        if compare_args(args, scn_args):
            patch_xref(r.frm, patch_addr, mdis, machine.mn, exectbl)

    with open(file_name + ".dump", "wb") as fl:
        fl.write(bytes(exectbl))

