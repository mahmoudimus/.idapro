import struct
import typing

import idaapi
import ida_idaapi
import ida_ida
import ida_bytes
import ida_kernwin as kw

from collections import namedtuple
import miasm.expression.expression as m2_expr
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.analysis.depgraph import DependencyGraph
from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.core.bin_stream import bin_stream
from miasm.ir.ir import IRBlock, IRCFG
from miasm.core.asmblock import AsmCFG, AsmBlock, disasmEngine
from miasm.arch.x86.arch import conditional_branch
from miasm.analysis.machine import Machine
from miasm.expression.expression import Expr, LocKey, ExprId, ExprInt, ExprLoc
from miasm.arch.x86.regs import (
    all_regs_ids,
    EAX,
    RAX,
    ECX,
    RCX,
    EDX,
    RDX,
    EBX,
    RBX,
    ESI,
    RSI,
    EDI,
    RDI,
    ESP,
    RSP,
    EBP,
    RBP,
)

if 760 < idaapi.IDA_SDK_VERSION < 900:
    get_inf_structure = ida_idaapi.get_inf_structure
else:

    class _InfBridge:
        @property
        def procname(self):
            return ida_ida.inf_get_procname()

        is_64bit = staticmethod(ida_ida.inf_is_64bit)
        is_32bit = staticmethod(ida_ida.inf_is_32bit_exactly)
        is_be = staticmethod(ida_ida.inf_is_be)

    get_inf_structure = _InfBridge


__ver_minor__ = 1
__ver_major__ = 0

pack = struct.pack

LOG_LEVEL = 2
REGISTER_DEFAULT_VALUE = 0xFFFFFFFF

def log(msg, code="+"):
    levels = {
        "@": -1,  # Important messages
        "~": -2,  # Critical errors
        "+": 0,  # Normal messages
        "!": 1,  # Warnings errors
        "?": 2,  # Info messages
    }

    msg_level = levels.get(code, None)

    if msg_level is None:
        raise Exception(f"Unknown msg code {msg_level}")

    if msg_level > LOG_LEVEL:
        return

    print(f"[{code}] {msg}")


def get_target_arch():
    info = get_inf_structure()

    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
        bits = 16

    return bits


def get_target_path():
    return idaapi.get_input_file_path()


def get_stream():
    return bin_stream_ida()


def get_vars(cond: Expr, vars=[]):
    if cond.is_id():
        vars.append(cond)

    return cond


def is_static_expr(cond):
    cvars = []

    cond.visit(lambda cond: get_vars(cond, cvars))

    if not cvars:
        return True

    return False


def simple_unwrap_expr(expr: Expr, loc_db: LocationDB):
    ra = -1
    if expr.is_int():
        ra = int(typing.cast(ExprInt, expr))
    elif expr.is_loc():
        ra = loc_db.get_location_offset(typing.cast(ExprLoc, expr).loc_key)
        if ra is None:
            ra = -1

    return ra


def get_ax():
    return RAX if get_target_arch() == 64 else EAX


def get_bx():
    return RBX if get_target_arch() == 64 else EBX


def get_cx():
    return RCX if get_target_arch() == 64 else ECX


def get_dx():
    return RDX if get_target_arch() == 64 else EDX


def get_si():
    return RSI if get_target_arch() == 64 else ESI


def get_di():
    return RDI if get_target_arch() == 64 else EDI


def get_sp():
    return RSP if get_target_arch() == 64 else ESP


def get_bp():
    return RBP if get_target_arch() == 64 else EBP


def get_sym_ptr(v):
    return ExprInt(v, get_target_arch())


IRLoop = namedtuple("IRLoop", "head tail body")


# Define the exception handling function
def handle_priv_insn_exception(jit, exception_value):
    from miasm.jitter.csts import EXCEPT_PRIV_INSN

    if exception_value == EXCEPT_PRIV_INSN:
        # Implement logic to handle the privileged instruction exception
        print("Handling privileged instruction exception")

        # Example logic for FRSTOR
        if jit.cpu.instr.mnemonic == "frstor":
            print("Handling FRSTOR instruction")
            # Perform the necessary FPU state restore operations here
            # For instance, read the FPU state from memory and restore it
            # This is a placeholder for the actual FRSTOR operation
            eip = jit.cpu.eip  # Get current instruction pointer
            # Example: Restore FPU state (this will depend on your specific needs)
            # jit.cpu.fpu.regs = read_fpu_state_from_memory(jit.cpu.mem, addr)
            # Set eip to the next instruction to continue execution
            jit.cpu.eip = eip + jit.cpu.instr.jitstep_length
            return True

        # Add handling for other instructions as necessary
        if jit.cpu.instr.mnemonic == "xgetbv":
            print("Handling XGETBV instruction")
            # Example logic for XGETBV
            eip = jit.cpu.eip
            jit.cpu.regs.eax = 0  # Example value
            jit.cpu.regs.ecx = 0  # Example value
            jit.cpu.regs.edx = 0  # Example value
            jit.cpu.eip = eip + jit.cpu.instr.jitstep_length
            return True

    return False


def float64_to_float80(value):
    # Pack the 64-bit float into binary format
    packed_value = struct.pack("d", value)
    # Unpack it as an integer to get the raw bits
    int_value = struct.unpack("Q", packed_value)[0]

    # Extract sign, exponent, and mantissa
    sign = (int_value >> 63) & 0x1
    exponent = (int_value >> 52) & 0x7FF
    mantissa = int_value & 0xFFFFFFFFFFFFF

    # Bias the exponent by 1023 (for 64-bit) and adjust for 16383 (for 80-bit)
    if exponent == 0:  # Zero or subnormal number
        exponent80 = 0
        mantissa80 = mantissa << 11
    elif exponent == 0x7FF:  # Infinity or NaN
        exponent80 = 0x7FFF
        mantissa80 = (mantissa << 11) | 0x7FFFFFFFFFFFFF
    else:  # Normalized number
        exponent80 = exponent + (0x3FFF - 0x3FF)
        mantissa80 = mantissa << 11

    # Construct the 80-bit extended precision float
    float80 = (sign << 79) | (exponent80 << 64) | mantissa80

    # Pack the value as an 80-bit extended precision float
    float80_packed = struct.pack("QH", float80 & 0xFFFFFFFFFFFFFFFF, float80 >> 64)

    return float80_packed


# from miasm.expression.simplifications import expr_simp
# from miasm.arch.x86.arch import mn_x86, repeat_mn, replace_regs
# from miasm.expression.expression_helper import expr_cmps, expr_cmpu
# import miasm.arch.x86.regs as regs
# from miasm.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock

def insert_mneumonic_patches():
    import miasm.arch.x86.sem
    import miasm.arch.x86.regs
    import miasm.expression.expression as m2_expr

    from miasm.jitter.csts import EXCEPT_PRIV_INSN

    exception_flags = m2_expr.ExprId("exception_flags", 32)

    # Implement the XGETBV instruction
    def XGETBV(ir, instr):
        print("XGETBV: i def got here")
        e = [m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32))]
        return e, []

    miasm.arch.x86.sem.mnemo_func["xgetbv"] = XGETBV

    # Implement the FRSTOR instruction
    def FRSTOR(ir, instr1, *args):
        e = [m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32))]
        return e, []

    # Patch Miasm to include the FRSTOR instruction
    miasm.arch.x86.sem.mnemo_func["frstor"] = FRSTOR

    def fstp(ir, instr, dst):
        e = []

        float_st0 = miasm.arch.x86.regs.float_st0
        float_tword80 = ExprId("float_st0", 80)
        if isinstance(dst, m2_expr.ExprMem) and dst.size > 64:
            # Evaluate the expression to get the actual float value from float_st0
            # value64_expr = ir.eval_expr(float_st0)
            # value64 = ir.jitter.vm.get_mem_value(value64_expr, 64, sign_flag=False)
            # value64_float = struct.unpack('d', struct.pack('Q', value64))[0]

            # # Convert the 64-bit value to 80 bits
            # value80 = float64_to_float80(value64_float)

            # # Store the 80-bit value in the destination memory location
            # mem_addr = ir.eval_expr(dst.arg)
            # e.append(m2_expr.ExprAssign(m2_expr.ExprMem(mem_addr, 80), m2_expr.ExprInt(int.from_bytes(value80, 'little'), 80)))
            src = float_tword80
            src = m2_expr.ExprOp("fpconvert_fp80", src)
            e.append(m2_expr.ExprAssign(dst, src))

        elif isinstance(dst, m2_expr.ExprMem):
            src = float_st0
            if dst.size == 32:
                src = m2_expr.ExprOp("fpconvert_fp32", src)
            e.append(m2_expr.ExprAssign(dst, src))
        else:
            src = float_st0
            if miasm.arch.x86.sem.float_list.index(dst) > 1:
                # a = st0 -> st0 is dropped
                # a = st1 -> st0 = st0, useless
                e.append(m2_expr.ExprAssign(miasm.arch.x86.sem.float_prev(dst), src))

        e += miasm.arch.x86.sem.set_float_cs_eip(instr)
        e += miasm.arch.x86.sem.float_pop(dst)
        return e, []

    def retf(ir, instr, src=None):
        print("retf: i def got here")

        e = []
        meip = ir.IRDst  # Assuming IRDst corresponds to RIP for 64-bit mode
        size, admode = instr.v_opmode(), instr.v_admode()

        if src is None:
            src = m2_expr.ExprInt(0, instr.mode)
        myesp = ir.IRDst[:size]

        src = src.zeroExtend(size)

        result = myesp
        if ir.do_stk_segm:
            result = ir.gen_segm_expr(miasm.arch.x86.regs.SS, result)

        # Ensure size consistency for RIP
        e.append(
            m2_expr.ExprAssign(meip, ir.ExprMem(result, size=size).zeroExtend(meip.size))
        )
        e.append(
            m2_expr.ExprAssign(
                ir.IRDst, ir.ExprMem(result, size=size).zeroExtend(ir.IRDst.size)
            )
        )

        result = myesp + m2_expr.ExprInt(size // 8, size)
        if ir.do_stk_segm:
            result = ir.gen_segm_expr(miasm.arch.x86.regs.SS, result)

        e.append(m2_expr.ExprAssign(miasm.arch.x86.regs.CS, ir.ExprMem(result, size=16)))

        value = myesp + (m2_expr.ExprInt((2 * size) // 8, size) + src)
        e.append(m2_expr.ExprAssign(myesp, value))
        return e, []

    # Patch Miasm to include the fstp instruction
    miasm.arch.x86.sem.fstp = fstp
    miasm.arch.x86.sem.mnemo_func["fstp"] = fstp

    # Patch the retf instruction
    # miasm.arch.x86.sem.retf = retf
    # miasm.arch.x86.sem.mnemo_func["retf"] = retf

    # Implement and register the exception callback
    # def handle_priv_insn_exception(cpu, exception_value):
    #     if exception_value == EXCEPT_PRIV_INSN:
    #         # Implement logic to handle the XGETBV instruction
    #         pass

    # cpu.exception_callbacks[EXCEPT_PRIV_INSN] = handle_priv_insn_exception
    print('[*] Miasm patched.')


insert_mneumonic_patches()


class IDALifter:

    def __init__(self, arch: int, stream: bin_stream, dontdis_retcall=True, blockwatchdog=100, dis_nulstart_block=True, followcall=False):
        self._root_ir: IRBlock
        self._arch = arch
        self._machine: Machine = Machine(f"x86_{self._arch}")
        self._locdb : LocationDB = LocationDB()
        self._bs: bin_stream = stream
        self._mdis: disasmEngine = self._machine.dis_engine(
            stream, loc_db=self._locdb
        )  # pyright: ignore[reportOptionalCall]

        self._mdis.dontdis_retcall = dontdis_retcall
        self._mdis.blocs_wd = blockwatchdog
        self._mdis.dont_dis_nulstart_bloc = not dis_nulstart_block
        self._mdis.follow_call = followcall
        

    def _new_flow(self, start_ea):
        """
        Transform code from IDA to asm and ir cfg
        :param start_ea: Address of a function
        :return: None
        """
        self._ir_arch = self._machine.ira(
            self._mdis.loc_db
        )  # pyright: ignore[reportOptionalCall]

        self._asm_cfg: AsmCFG = self._mdis.dis_multiblock(start_ea)
        # self._asm_cfg: AsmCFG = AsmCFG(self._mdis.loc_db)
        # self._asm_cfg.add_block(self._mdis.dis_block(start_ea))

        self._ir_cfg: IRCFG = self._ir_arch.new_ircfg_from_asmcfg(self._asm_cfg)

        self._root_ir = typing.cast(IRBlock, self._ir_cfg.get_block(
            start_ea
        ))

        _root = getattr(self._root_ir, 'loc_key', None)
        if not _root:
            print("Could not establish loc_key @ ", start_ea)
            return 
        self._root = _root

        self._loops = []

        for back_edge, body in self._ir_cfg.compute_natural_loops(self._root):
            tail, head = back_edge

            l = IRLoop(head=tail, tail=head, body=body)

            self._loops.append(l)

    @property
    def ip(self):
        """
        Get instruction pointer symbol
        :return:
        """
        if self._arch == 32:
            return ExprId("EIP", 32)
        elif self._arch == 64:
            return ExprId("RIP", 64)
        elif self._arch == 16:
            return ExprId("IP", 16)

        raise Exception(f"Unknown bitness {self._arch}")

    def _is_loop_head(self, loc: LocKey):
        for l in self._loops:
            if l.head == loc:
                return True, l

        return False, None

    def _is_loop_tail(self, loc: LocKey):
        for l in self._loops:
            if l.tail == loc:
                return True, l

        return False, None

    def _get_loop(self, loc: LocKey):
        status, loop = self._is_loop_head(loc)
        if status:
            return loop

        status, loop = self._is_loop_body(loc)
        if status:
            return loop

        status, loop = self._is_loop_tail(loc)
        if status:
            return loop

        return None

    def _is_loop_body(self, loc: LocKey):
        for l in self._loops:
            if loc in l.body:
                return True, l

        return False, None

    def update(self, ea):
        self._new_flow(ea)


class IDAFlowRecovery(IDALifter):
    def __init__(
        self,
        ea: int,
        stream: bin_stream,
        arch: int,
        ids_check=True,
        mem_check=True,
        verbose_log=False,
        ctx=None,
    ):
        self._ea = ea

        super().__init__(arch, stream)

        self.update(ea)

        self._ids_check = ids_check
        self._mem_check = mem_check
        self._verbose_log = verbose_log

        self._flow_patches_map = {}
        self._branch_conditions = []

        self._mark_branch_conditions(ctx=ctx)

    @property
    def flow_fixes(self):
        return self._flow_patches_map

    def _mark_branch_conditions(self, ctx=None):
        """
        For any cjmp in CFG tries to find all solutions for []IP symbol
        :return:
        """
        ir_loc: LocKey
        ir_block: IRBlock

        for ir_loc, ir_block in self._ir_cfg.blocks.items():
            # check for detect current location that is head or tail of natural loop

            loc_addr = self._ir_cfg.loc_db.get_location_offset(ir_loc)

            is_head, _ = self._is_loop_head(ir_loc)
            is_tail, _ = self._is_loop_tail(ir_loc)
            if not ir_block.dst.is_cond() or is_head or is_tail:
                continue

            dg = DependencyGraph(self._ir_cfg)

            dst_solutions = set()

            solutions_log = []

            for sol in dg.get(
                ir_loc, [self.ip], ir_block.assignblks[-1].instr.offset, set()
            ):
                try:
                    solutions = sol.emul(self._ir_arch, ctx=ctx)
                except NotImplementedError as ex:
                    log(f"Unsupported expression in location - {ir_loc}", code="!")

                    solutions_log.append((ir_loc, ir_block, None))

                    dst_solutions = set()
                    break

                ip_expr = solutions.get(self.ip)

                solutions_log.append((ir_loc, ir_block, ip_expr))

                if (
                    not ip_expr.is_int()
                    and not ip_expr.is_loc()
                    and not is_static_expr(ip_expr)
                ):
                    dst_solutions = set()

                    known_dst = self._flow_patches_map.get(loc_addr, None)
                    if known_dst:
                        del self._flow_patches_map[loc_addr]

                    break

                if not ip_expr.is_int() and not ip_expr.is_loc():
                    log(f"Static ip expressions unsupported now [{ip_expr}]")

                    # invlidate dst_solutions
                    dst_solutions = set()

                    known_dst = self._flow_patches_map.get(loc_addr, None)
                    if known_dst:
                        del self._flow_patches_map[loc_addr]

                    break

                dst_solutions.update([ip_expr])

            if self._verbose_log:
                vl_pad = 24
                for ir_loc, ir_block, ip_expr in solutions_log:
                    print(f"{'-' * vl_pad}")
                    print(f"{ir_loc} - {hex(loc_addr)if loc_addr else 'None'}")
                    for assign_block in ir_block.assignblks:
                        for dst, src in assign_block.iteritems():
                            print(f"{dst} = {src}")
                    print(f"{'-' * vl_pad}")
                    print(f"Solution: {ip_expr}")

            if len(dst_solutions) != 1:
                continue

            static_dst = dst_solutions.pop()
            static_addr = simple_unwrap_expr(static_dst, self._ir_cfg.loc_db)

            if static_addr == -1:
                log(
                    f"Oops ... {static_dst}. Fail resolve dst by a simple approach",
                    code="!",
                )
                continue

            known_dst = self._flow_patches_map.get(loc_addr, None)
            if known_dst is None:
                self._flow_patches_map[loc_addr] = static_addr
            elif self._flow_patches_map[loc_addr] != static_addr:
                # We found in another path different static solution, not opaque jmp
                del self._flow_patches_map[loc_addr]

        if self._verbose_log:
            for l, d in self._flow_patches_map.items():
                print(f"{hex(l)} -> {hex(d)}")

    def apply(self):
        """
        Apply patches to found opaque branch
        :return: None
        """

        for src, dst in self._flow_patches_map.items():
            ir_block: IRBlock = self._ir_cfg.get_block(src)

            asm_instr = ir_block.assignblks[ir_block.dst_linenb].instr

            if asm_instr.name not in conditional_branch:
                log(f"Unsupported asm pattern at {hex(src)}", code="!")
                continue

            patch_addr = asm_instr.offset

            opcode1 = ida_bytes.get_byte(patch_addr)

            # Fast and Furious
            if opcode1 == 0x0F:
                ida_bytes.patch_bytes(
                    patch_addr,
                    b"\xe9" + pack("<I", (dst - (patch_addr + 5)) & (2**32 - 1)),
                )
            elif ((opcode1 & 0xE0) == 0xE0) or ((opcode1 & 0x70) == 0x70):
                ida_bytes.patch_byte(patch_addr, 0xEB)
                ida_bytes.patch_byte(patch_addr + 1, (dst - (patch_addr + 2)) & 0xFF)
            else:
                log(f"Unknown first part of opcode at {hex(patch_addr)}", code="!")
                continue

            log(f"Apply patch JCC -> JMP at {hex(patch_addr)}")


class StartDialog(kw.Form):
    def __init__(self, version=f"{__ver_major__}{__ver_minor__}", registers={}):
        kw.Form.__init__(
            self,
            f"""Miasm CFG deobfuscator for IDA. v{version}
                        {{FormChangeCb}}
                        <#Entry  : {{iAddr}}> 
                        <#(E/R)AX:{{iAX}}>
                        <#(E/R)DX:{{iDX}}>
                        <#(E/R)CX:{{iCX}}>
                        <#(E/R)BX:{{iBX}}>
                        <#(E/R)SI:{{iSI}}> 
                        <#(E/R)DI:{{iDI}}>
                        <#(E/R)SP:{{iSP}}>
                        <#(E/R)BP:{{iBP}}>
                        <#Disable patch:{{rMode}}>
                        <#Verbose logging:{{rModeLogging}}>{{cModeGroup1}}>
                        """,
            {
                "iAddr": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR, value=kw.get_screen_ea()
                ),
                "cModeGroup1": idaapi.Form.ChkGroupControl(
                    (
                        "rMode",
                        "rModeLogging",
                    )
                ),
                "FormChangeCb": idaapi.Form.FormChangeCb(self.OnFormChange),
                "iAX": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("ax", REGISTER_DEFAULT_VALUE),
                ),
                "iDX": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("dx", REGISTER_DEFAULT_VALUE),
                ),
                "iCX": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("cx", REGISTER_DEFAULT_VALUE),
                ),
                "iBX": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("bx", REGISTER_DEFAULT_VALUE),
                ),
                "iSI": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("si", REGISTER_DEFAULT_VALUE),
                ),
                "iDI": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("di", REGISTER_DEFAULT_VALUE),
                ),
                "iSP": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("sp", REGISTER_DEFAULT_VALUE),
                ),
                "iBP": kw.Form.NumericInput(
                    tp=idaapi.Form.FT_ADDR,
                    value=registers.get("bp", REGISTER_DEFAULT_VALUE),
                ),
            },
        )

    def OnFormChange(self, fid):
        if fid == self.rMode.id:
            self.rMode.checked = not self.rMode.checked
        elif fid == self.rMode.id:
            self.rModeLogging.checked = not self.rModeLogging.checked
        return 1


def main(registers):
    sd = StartDialog(registers=registers)
    sd.Compile()
    ok = sd.Execute()

    if not ok:
        return

    if not sd.iAddr.value:
        log("Start address must be set", code="~")
        return

    concrete_context = {}

    if sd.iAX.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_ax()] = get_sym_ptr(sd.iAX.value)

    if sd.iDX.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_dx()] = get_sym_ptr(sd.iDX.value)

    if sd.iCX.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_cx()] = get_sym_ptr(sd.iCX.value)

    if sd.iBX.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_bx()] = get_sym_ptr(sd.iBX.value)

    if sd.iSI.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_si()] = get_sym_ptr(sd.iSI.value)

    if sd.iDI.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_di()] = get_sym_ptr(sd.iDI.value)

    if sd.iSP.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_sp()] = get_sym_ptr(sd.iSP.value)

    if sd.iBP.value != REGISTER_DEFAULT_VALUE:
        concrete_context[get_bp()] = get_sym_ptr(sd.iBP.value)

    ifr = IDAFlowRecovery(
        sd.iAddr.value,
        get_stream(),
        get_target_arch(),
        verbose_log=sd.rModeLogging.checked,
        ctx=concrete_context,
    )
    if not sd.rMode.checked:
        ifr.apply()


if __name__ == "__main__":
    start = "rdi=0x7ffe0384,rsi=0x1,rsp=0xb67beff298,rbx=0x7ffe0385,rdx=0x1,rcx=0x7ff6d2f50000,rax=0x7ff6d2f53660,r9=0x7ff6d2f53660,r10=0x99012e4578d92870,r11=0xb67beff338,r12=0x7ff8607abf90,r13=0x1,r14=0x7ff6d2f50000,r15=0x7ff6d2f53660,rip=0x7ff6d2f53660,mr=0x7ff8608cf000:503c7d60f87f0000,mw=0xb67beff298:aabf7a60f87f0000"
    registers = {}
    for item in start.split(","):
        key, value = item.split("=")
        if key.startswith("r"):
            registers[key[1:]] = int(value, base=16)
    print(registers)
    main(registers)
