import idaapi, idautils, idc, ida_funcs, ida_auto
import sys
import os

import angr
from keystone import *
from capstone import *
from idc import *
from ida_ua import *
from ida_bytes import *
from ida_allins import *
import logging
from enum import Enum
import shutil
import re
import six
import struct

####################################################################
# Constants.
####################################################################

"""
TODO:
-fix the plugin "reload" need
-move keypatcher to different class
-check if patching the binary ida is working on is enough, or does angr need to reload it every time.
-implement deflow algorithm https://ferib.dev/blog.php?l=post/Reversing_Common_Obfuscation_Techniques' (????)
heuristics:
    -think about checkign the damage an opaque predicate does to a binary as an heursitic.
    -think about state explosion heuristic.
    -think about doing dual jp-mov-jnp fixes ahead.
-fix non full scan
-add patterns for found opaques
-

-PROBLEMS:
1111111111111111111111111 ON RET_ADDR_CHECK
.text:000000014209C761                 jo      short loc_14209C76A
.text:000000014209C763                 mov     bl, bl
.text:000000014209C765                 jmp     short loc_14209C78E ; Keypatch modified this from:
.text:000000014209C765 ; END OF FUNCTION CHUNK FOR retAddrCheck ;   jno short loc_14209C78E
.text:000000014209C765 ; ---------------------------------------------------------------------------
.text:000000014209C767                 db 81h
.text:000000014209C768                 db 0C2h, 18h
.text:000000014209C76A ; ---------------------------------------------------------------------------
.text:000000014209C76A ; START OF FUNCTION CHUNK FOR retAddrCheck
.text:000000014209C76A
.text:000000014209C76A loc_14209C76A:                          ; CODE XREF: retAddrCheck+281↑j
.text:000000014209C76A                 nop
.text:000000014209C76B                 jo      short loc_14209C78E


22222222222222222222222222 ON EXEC MAYBE
0x1406272f3
0x1406272f6
1 jb 5
2 jnb 8
3 db db
4 db db
5 jb 8 
6 db db
7 db db

"""


T_VER = 21
DEBUG = True
DEBUG_VERBOSE = False
CONDITIONAL_JMP_SIZE_IN_BYTES = 2
DEPTH = 150
ACTIVE_THERSHOLD_FOR_LAST_PREDICATE_MODE = 700
TOPAQUE_ANGR_ADDITION = "_Topaqueminator_ver_" + str(T_VER) + "_patched"
APPLY_PATCHES_ON_INPUT_FILE = False
CONTINUOS_ANALYZING = False
TESTS_MODE = False


SINGLE_BLOCK_MODE = False
WHOLE_FUNCTION_MODE = True
FIX_DEFLOW_MODE = False


patch_info = []
last_found_opaque_predicate = None
addresses_avoided_set = set()
addresses_find_set = set()
opaque_jumpedto_addresses_set = set()
unfixable_deflow_addresses = set()
is_last_predicate_mode = False


##################py compitability funcs################################################################
def to_string(s):
    # python3 bytes
    if six.PY3 and isinstance(s, bytes):
        return s.decode("latin-1")
    # python2 unicode
    elif six.PY2 and isinstance(s, six.text_type):
        return s.encode("utf-8")
    return str(s)


def to_hexstr(buf, sep=" "):
    # for python3 bytes
    if six.PY3 and isinstance(buf, bytes):
        return sep.join("{0:02x}".format(c) for c in buf).upper()
    return sep.join("{0:02x}".format(ord(c)) for c in buf).upper()


def convert_hexstr(code):
    # normalize code
    code = code.lower()
    code = code.replace(" ", "")  # remove space
    code = code.replace("h", "")  # remove trailing 'h' in 90h
    code = code.replace("0x", "")  # remove 0x
    code = code.replace("\\x", "")  # remove \x
    code = code.replace(",", "")  # remove ,
    code = code.replace(";", "")  # remove ;
    code = code.replace('"', "")  # remove "
    code = code.replace("'", "")  # remove '
    code = code.replace("+", "")  # remove +

    # single-digit hexcode?
    if len(code) == 1 and (
        (code >= "0" and code <= "9") or (code >= "a" and code <= "f")
    ):
        # stick 0 in front (so 'a' --> '0a')
        code = "0" + code

    # odd-length is invalid
    if len(code) % 2 != 0:
        return None

    try:
        hex_data = code.decode("hex")
        # we want a list of int
        return [ord(i) for i in hex_data]
    except:
        # invalid hex
        return None


#######################################################################################################


################################ IDA 6/7 Compatibility function #########################################
def get_dtype(ea, op_idx):
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    dtype = insn.ops[op_idx].dtype
    dtyp_size = idaapi.get_dtype_size(dtype)
    return dtype, dtyp_size


def set_comment(ea, comment):
    idc.set_cmt(ea, comment, 0)


def get_comment(ea):
    return idc.get_cmt(ea, 0)


def read_range_selection():
    return idaapi.read_range_selection(None)


#########################################################################################################


class Keypatch_Asm:
    # supported architectures
    arch_lists = {
        "X86 16-bit": (KS_ARCH_X86, KS_MODE_16),  # X86 16-bit
        "X86 32-bit": (KS_ARCH_X86, KS_MODE_32),  # X86 32-bit
        "X86 64-bit": (KS_ARCH_X86, KS_MODE_64),  # X86 64-bit
        "ARM": (KS_ARCH_ARM, KS_MODE_ARM),  # ARM
        "ARM Thumb": (KS_ARCH_ARM, KS_MODE_THUMB),  # ARM Thumb
        "ARM64 (ARMV8)": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),  # ARM64
        "Hexagon": (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),  # Hexagon
        "Mips32": (KS_ARCH_MIPS, KS_MODE_MIPS32),  # Mips32
        "Mips64": (KS_ARCH_MIPS, KS_MODE_MIPS64),  # Mips64
        "PowerPC 32": (KS_ARCH_PPC, KS_MODE_PPC32),  # PPC32
        "PowerPC 64": (KS_ARCH_PPC, KS_MODE_PPC64),  # PPC64
        "Sparc 32": (KS_ARCH_SPARC, KS_MODE_SPARC32),  # Sparc32
        "Sparc 64": (KS_ARCH_SPARC, KS_MODE_SPARC64),  # Sparc64
        "SystemZ": (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN),  # SystemZ
    }

    endian_lists = {
        "Little Endian": KS_MODE_LITTLE_ENDIAN,  # little endian
        "Big Endian": KS_MODE_BIG_ENDIAN,  # big endian
    }

    syntax_lists = {
        "Intel": KS_OPT_SYNTAX_INTEL,
        "Nasm": KS_OPT_SYNTAX_NASM,
        "AT&T": KS_OPT_SYNTAX_ATT,
    }

    def __init__(self, arch=None, mode=None):
        # update current arch and mode
        self.update_hardware_mode()

        # override arch & mode if provided
        if arch is not None:
            self.arch = arch
        if mode is not None:
            self.mode = mode

        # IDA uses Intel syntax by default
        self.syntax = KS_OPT_SYNTAX_INTEL

    # return Keystone arch & mode (with endianess included)
    @staticmethod
    def get_hardware_mode():
        (arch, mode) = (None, None)

        # heuristically detect hardware setup
        info = idaapi.get_inf_structure()

        try:
            cpuname = info.procname.lower()
        except:
            cpuname = info.procName.lower()

        
        is_be = ida_ida.cvar.inf.is_be()

        if cpuname == "metapc":
            arch = KS_ARCH_X86
            if info.is_64bit():
                mode = KS_MODE_64
            elif info.is_32bit():
                mode = KS_MODE_32
            else:
                mode = KS_MODE_16
        elif cpuname.startswith("arm"):
            # ARM or ARM64
            if info.is_64bit():
                arch = KS_ARCH_ARM64
                if is_be:
                    mode = KS_MODE_BIG_ENDIAN
                else:
                    mode = KS_MODE_LITTLE_ENDIAN
            else:
                arch = KS_ARCH_ARM
                # either big-endian or little-endian
                if is_be:
                    mode = KS_MODE_ARM | KS_MODE_BIG_ENDIAN
                else:
                    mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("sparc"):
            arch = KS_ARCH_SPARC
            if info.is_64bit():
                mode = KS_MODE_SPARC64
            else:
                mode = KS_MODE_SPARC32
            if is_be:
                mode |= KS_MODE_BIG_ENDIAN
            else:
                mode |= KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("ppc"):
            arch = KS_ARCH_PPC
            if info.is_64bit():
                mode = KS_MODE_PPC64
            else:
                mode = KS_MODE_PPC32
            if cpuname == "ppc":
                # do not support Little Endian mode for PPC
                mode += KS_MODE_BIG_ENDIAN
        elif cpuname.startswith("mips"):
            arch = KS_ARCH_MIPS
            if info.is_64bit():
                mode = KS_MODE_MIPS64
            else:
                mode = KS_MODE_MIPS32
            if is_be:
                mode |= KS_MODE_BIG_ENDIAN
            else:
                mode |= KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("systemz") or cpuname.startswith("s390x"):
            arch = KS_ARCH_SYSTEMZ
            mode = KS_MODE_BIG_ENDIAN

        return (arch, mode)

    def update_hardware_mode(self):
        (self.arch, self.mode) = self.get_hardware_mode()

    # normalize assembly code
    # remove comment at the end of assembly code
    @staticmethod
    def asm_normalize(text):
        text = " ".join(text.split())
        if text.rfind(";") != -1:
            return text[: text.rfind(";")].strip()

        return text.strip()

    @staticmethod
    # check if input address is valid
    # return
    #       -1  invalid address at target binary
    #        0  type mismatch of input address
    #        1  valid address at target binary
    def check_address(address):
        try:
            if idc.is_mapped(address):
                return 1
            else:
                return -1
        except:
            # invalid type
            return 0

    ### resolve IDA names from input asm code
    # todo: a better syntax parser for all archs
    def ida_resolve(self, assembly, address=idc.BADADDR):
        def _resolve(_op, ignore_kw=True):
            names = re.findall(r"[\$a-z0-9_:\.]+", _op, re.I)

            # try to resolve all names
            for name in names:
                # ignore known keywords
                if ignore_kw and name in (
                    "byte",
                    "near",
                    "short",
                    "word",
                    "dword",
                    "ptr",
                    "offset",
                ):
                    continue

                sym = name

                # split segment reg
                parts = name.partition(":")
                if parts[2] != "":
                    sym = parts[2]

                (typ, value) = idaapi.get_name_value(address, sym)

                # skip if name doesn't exist or segment / segment registers
                if typ in (idaapi.NT_SEG, idaapi.NT_NONE):
                    continue

                _op = _op.replace(sym, "0x{0:X}".format(value))

            return _op

        if self.check_address(address) == 0:
            print("Keypatch: WARNING: invalid input address {0}".format(address))
            return assembly

        # for now, we only support IDA name resolve for X86, ARM, ARM64, MIPS, PPC, SPARC
        if not (
            self.arch
            in (
                KS_ARCH_X86,
                KS_ARCH_ARM,
                KS_ARCH_ARM64,
                KS_ARCH_MIPS,
                KS_ARCH_PPC,
                KS_ARCH_SPARC,
            )
        ):
            return assembly

        _asm = assembly.partition(" ")
        mnem = _asm[0]
        opers = _asm[2].split(",")

        for idx, op in enumerate(opers):
            _op = list(op.partition("["))
            ignore_kw = True
            if _op[1] == "":
                _op[2] = _op[0]
                _op[0] = ""
            else:
                _op[0] = _resolve(_op[0], ignore_kw=True)
                ignore_kw = False

            _op[2] = _resolve(_op[2], ignore_kw=ignore_kw)

            opers[idx] = "".join(_op)

        asm = "{0} {1}".format(mnem, ",".join(opers))
        return asm

    # return bytes of instruction or data
    # return None on failure
    def ida_get_item(self, address, hex_output=False):
        if self.check_address(address) != 1:
            # not a valid address
            return (None, 0)

        # return None if address is in the middle of instruction / data
        if address != idc.get_item_head(address):
            return (None, 0)

        size = idc.get_item_size(address)
        item = idc.get_bytes(address, size)

        if item is None:
            return (None, 0)

        if hex_output:
            item = to_hexstr(item)

        return (item, size)

    @staticmethod
    def get_op_dtype_name(ea, op_idx):
        dtyp_lists = {
            idaapi.dt_byte: "byte",  #  8 bit
            idaapi.dt_word: "word",  #  16 bit
            idaapi.dt_dword: "dword",  #  32 bit
            idaapi.dt_float: "dword",  #  4 byte
            idaapi.dt_double: "dword",  #  8 byte
            # idaapi.dt_tbyte = 5        #  variable size (ph.tbyte_size)
            # idaapi.dt_packreal = 6         #  packed real format for mc68040
            idaapi.dt_qword: "qword",  #  64 bit
            idaapi.dt_byte16: "xmmword",  #  128 bit
            # idaapi.dt_code = 9         #  ptr to code (not used?)
            # idaapi.dt_void = 10        #  none
            # idaapi.dt_fword = 11       #  48 bit
            # idaapi.dt_bitfild = 12     #  bit field (mc680x0)
            # idaapi.dt_string = 13      #  pointer to asciiz string
            # idaapi.dt_unicode = 14     #  pointer to unicode string
            # idaapi.dt_3byte = 15       #  3-byte data
            # idaapi.dt_ldbl = 16        #  long double (which may be different from tbyte)
            idaapi.dt_byte32: "ymmword",  # 256 bit
        }
        dtype, dtyp_size = get_dtype(ea, op_idx)
        if dtype == idaapi.dt_tbyte and dtyp_size == 10:
            return "xword"

        dtyp_name = dtyp_lists.get(dtype, None)

        return dtyp_name

    # return asm instructions from start to end
    def ida_get_disasm_range(self, start, end):
        codes = []
        while start < end:
            asm = self.asm_normalize(idc.GetDisasm(start))
            if asm == None:
                asm = ""
            codes.append(asm)
            start = start + idc.get_item_size(start)

        return codes

    # get disasm from IDA
    # return '' on invalid address
    def ida_get_disasm(self, address, fixup=False):

        def GetMnem(asm):
            sp = asm.find(" ")
            if sp == -1:
                return asm
            return asm[:sp]

        if self.check_address(address) != 1:
            # not a valid address
            return ""

        # return if address is in the middle of instruction / data
        if address != idc.get_item_head(address):
            return ""

        asm = self.asm_normalize(idc.GetDisasm(address))
        # for now, only support IDA syntax fixup for Intel CPU
        if not fixup or self.arch != KS_ARCH_X86:
            return asm

        # KS_ARCH_X86 mode
        # rebuild disasm code from IDA
        i = 0
        mnem = GetMnem(asm)
        if mnem == "" or mnem in ("rep", "repne", "repe"):
            return asm

        opers = []
        while idc.get_operand_type(address, i) > 0 and i < 6:
            t = idc.get_operand_type(address, i)
            o = idc.print_operand(address, i)

            if t in (idc.o_mem, idc.o_displ):
                parts = list(o.partition(":"))
                if parts[2] == "":
                    parts[2] = parts[0]
                    parts[0] = ""

                if "[" not in parts[2]:
                    parts[2] = "[{0}]".format(parts[2])

                o = "".join(parts)

                if "ptr " not in o:
                    dtyp_name = self.get_op_dtype_name(address, i)
                    if dtyp_name != None:
                        o = "{0} ptr {1}".format(dtyp_name, o)

            opers.append(o)
            i += 1

        asm = mnem
        for o in opers:
            if o != "":
                asm = "{0} {1},".format(asm, o)

        asm = asm.strip(",")
        return asm

    # assemble code with Keystone
    # return (encoding, count), or (None, 0) on failure
    def assemble(self, assembly, address, arch=None, mode=None, syntax=None):

        # return assembly with arithmetic equation evaluated
        def eval_operand(assembly, start, stop, prefix=""):
            imm = assembly[start + 1 : stop]
            try:
                eval_imm = eval(imm)
                if eval_imm > 0x80000000:
                    eval_imm = 0xFFFFFFFF - eval_imm
                    eval_imm += 1
                    eval_imm = -eval_imm
                return assembly.replace(prefix + imm, prefix + hex(eval_imm))
            except:
                return assembly

        # IDA uses different syntax from Keystone
        # sometimes, we can convert code to be consumable by Keystone
        def fix_ida_syntax(assembly):

            # return True if this insn needs to be fixed
            def check_arm_arm64_insn(arch, mnem):
                if arch == KS_ARCH_ARM:
                    if mnem.startswith("ldr") or mnem.startswith("str"):
                        return True
                    return False
                elif arch == KS_ARCH_ARM64:
                    if mnem.startswith("ldr") or mnem.startswith("str"):
                        return True
                    return mnem in ("stp")
                return False

            # return True if this insn needs to be fixed
            def check_ppc_insn(mnem):
                return mnem in ("stw")

            # replace the right most string occurred
            def rreplace(s, old, new):
                li = s.rsplit(old, 1)
                return new.join(li)

            # convert some ARM pre-UAL assembly to UAL, so Keystone can handle it
            # example: streqb --> strbeq
            def fix_arm_ual(mnem, assembly):
                # TODO: this is not an exhaustive list yet
                if len(mnem) != 6:
                    return assembly

                if mnem[-1] in ("s", "b", "h", "d"):
                    # print(">> 222", mnem[3:5])
                    if mnem[3:5] in (
                        "cc",
                        "eq",
                        "ne",
                        "hs",
                        "lo",
                        "mi",
                        "pl",
                        "vs",
                        "vc",
                        "hi",
                        "ls",
                        "ge",
                        "lt",
                        "gt",
                        "le",
                        "al",
                    ):
                        return assembly.replace(
                            mnem, mnem[:3] + mnem[-1] + mnem[3:5], 1
                        )

                return assembly

            if self.arch != KS_ARCH_X86:
                assembly = assembly.lower()
            else:
                # Keystone does not support immediate 0bh, but only 0Bh
                assembly = assembly.upper()

            # however, 0X must be converted to 0x
            # Keystone should fix this limitation in the future
            assembly = assembly.replace("0X", " 0x")

            _asm = assembly.partition(" ")
            mnem = _asm[0]
            if mnem == "":
                return assembly

            # for PPC, Keystone does not accept registers with 'r' prefix,
            # but only the number behind. lets try to fix that here by
            # removing the prefix 'r'.
            if self.arch == KS_ARCH_PPC:
                for n in range(32):
                    r = " r%u," % n
                    if r in assembly:
                        assembly = assembly.replace(r, " %u," % n)
                for n in range(32):
                    r = "(r%u)" % n
                    if r in assembly:
                        assembly = assembly.replace(r, "(%u)" % n)
                for n in range(32):
                    r = ", r%u" % n
                    if assembly.endswith(r):
                        assembly = rreplace(assembly, r, ", %u" % n)

            if self.arch == KS_ARCH_X86:
                if mnem == "RETN":
                    # replace retn with ret
                    return assembly.replace("RETN", "RET", 1)
                if "OFFSET " in assembly:
                    return assembly.replace("OFFSET ", " ")
                if mnem in ("CALL", "JMP") or mnem.startswith("LOOP"):
                    # remove 'NEAR PTR'
                    if " NEAR PTR " in assembly:
                        return assembly.replace(" NEAR PTR ", " ")
                elif mnem[0] == "J":
                    # JMP instruction
                    if " SHORT " in assembly:
                        # remove ' short '
                        return assembly.replace(" SHORT ", " ")
            elif self.arch in (KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_PPC):
                # *** ARM
                # LDR     R1, [SP+rtld_fini],#4
                # STR     R2, [SP,#-4+rtld_fini]!
                # STR     R0, [SP,#fini]!
                # STR     R12, [SP,#4+var_8]!

                # *** ARM64
                # STP     X29, X30, [SP,#-0x10+var_150]!
                # STR     W0, [X29,#0x150+var_8]
                # LDR     X0, [X0,#(qword_4D6678 - 0x4D6660)]
                # TODO:
                # ADRP    X19, #interactive@PAGE

                # *** PPC
                # stw     r5, 0x120+var_108(r1)

                if self.arch == KS_ARCH_ARM and mode == KS_MODE_THUMB:
                    assembly = assembly.replace("movt.w", "movt")

                if self.arch == KS_ARCH_ARM:
                    # print(">> before UAL fix: ", assembly)
                    assembly = fix_arm_ual(mnem, assembly)
                    # print(">> after UAL fix: ", assembly)

                if check_arm_arm64_insn(self.arch, mnem) or (
                    ("[" in assembly) and ("]" in assembly)
                ):
                    bang = assembly.find("#")
                    bracket = assembly.find("]")
                    if bang != -1 and bracket != -1 and bang < bracket:
                        return eval_operand(assembly, bang, bracket, "#")
                    elif "+0x0]" in assembly:
                        return assembly.replace("+0x0]", "]")
                elif check_ppc_insn(mnem):
                    start = assembly.find(", ")
                    stop = assembly.find("(")
                    if start != -1 and stop != -1 and start < stop:
                        return eval_operand(assembly, start, stop)
            return assembly

        def is_thumb(address):
            return idc.get_sreg(address, "T") == 1

        if self.check_address(address) == 0:
            return (None, 0)

        # use default syntax, arch and mode if not provided
        if syntax is None:
            syntax = self.syntax
        if arch is None:
            arch = self.arch
        if mode is None:
            mode = self.mode

        if arch == KS_ARCH_ARM and is_thumb(address):
            mode = KS_MODE_THUMB

        try:
            ks = Ks(arch, mode)
            if arch == KS_ARCH_X86:
                ks.syntax = syntax
            encoding, count = ks.asm(fix_ida_syntax(assembly), address)
        except KsError as e:
            # keep the below code for debugging
            # print("Keypatch Error: {0}".format(e))
            # print("Original asm: {0}".format(assembly))
            # print("Fixed up asm: {0}".format(fix_ida_syntax(assembly)))
            encoding, count = None, 0

        return (encoding, count)

    # patch at address, return the number of written bytes & original data
    # this process can fail in some cases
    @staticmethod
    def patch_raw(address, patch_data, size):
        ea = address
        orig_data = ""

        while ea < (address + size):

            if not idc.has_value(idc.get_full_flags(ea)):
                print("Keypatch: FAILED to read data at 0x{0:X}".format(ea))
                break

            orig_byte = idc.get_wide_byte(ea)
            orig_data += chr(orig_byte)
            patch_byte = ord(patch_data[ea - address])

            if patch_byte != orig_byte:
                # patch one byte
                if idaapi.patch_byte(ea, patch_byte) != 1:
                    print(
                        "Keypatch: FAILED to patch byte at 0x{0:X} [0x{1:X}]".format(
                            ea, patch_byte
                        )
                    )
                    break
            ea += 1
        return (ea - address, orig_data)

    # patch at address, return the number of written bytes & original data
    # on patch failure, we revert to the original code, then return (None, None)
    def patch(self, address, patch_data, size):
        # save original function end to fix IDA re-analyze issue after patching
        orig_func_end = idc.get_func_attr(address, idc.FUNCATTR_END)

        (patched_len, orig_data) = self.patch_raw(address, patch_data, size)

        if size != patched_len:
            # patch failure
            if patched_len > 0:
                # revert the changes
                (rlen, _) = self.patch_raw(address, orig_data, patched_len)
                if rlen == patched_len:
                    print(
                        "Keypatch: successfully reverted changes of {0:d} byte(s) at 0x{1:X} [{2}]".format(
                            patched_len, address, to_hexstr(orig_data)
                        )
                    )
                else:
                    print(
                        "Keypatch: FAILED to revert changes of {0:d} byte(s) at 0x{1:X} [{2}]".format(
                            patched_len, address, to_hexstr(orig_data)
                        )
                    )

            return (None, None)

        # ask IDA to re-analyze the patched area
        if orig_func_end == idc.BADADDR:
            # only analyze patched bytes, otherwise it would take a lot of time to re-analyze the whole binary
            idaapi.plan_and_wait(address, address + patched_len + 1)
        else:
            idaapi.plan_and_wait(address, orig_func_end)

            # try to fix IDA function re-analyze issue after patching
            idc.set_func_end(address, orig_func_end)

        return (patched_len, orig_data)

    # return number of bytes patched
    # return
    #    0  Invalid assembly
    #   -1  PatchByte failure
    #   -2  Can't read original data
    #   -3  Invalid address
    def patch_code(
        self,
        address,
        assembly,
        syntax,
        padding,
        save_origcode,
        orig_asm=None,
        patch_data=None,
        patch_comment=None,
        undo=False,
    ):
        global patch_info

        if self.check_address(address) != 1:
            # not a valid address
            return -3

        orig_comment = get_comment(address)
        if orig_comment is None:
            orig_comment = ""

        nop_comment = ""
        padding_len = 0
        if not undo:
            # we are patching via Patcher
            (orig_encoding, orig_len) = self.ida_get_item(address)
            if (orig_encoding, orig_len) == (None, 0):
                return -2

            (encoding, count) = self.assemble(assembly, address, syntax=syntax)
            if encoding is None:
                return 0

            patch_len = len(encoding)
            patch_data = "".join(chr(c) for c in encoding)

            if patch_data == orig_encoding:
                # print("Keypatch: no need to patch, same encoding data [{0}] at 0x{1:X}".format(to_hexstr(orig_encoding), address))
                return orig_len

            # for now, only support NOP padding on Intel CPU
            if padding and self.arch == KS_ARCH_X86:
                if patch_len < orig_len:
                    padding_len = orig_len - patch_len
                    patch_len = orig_len
                    patch_data = patch_data.ljust(patch_len, "\x90")
                elif patch_len > orig_len:
                    patch_end = address + patch_len - 1
                    ins_end = idc.get_item_end(patch_end)
                    padding_len = ins_end - patch_end - 1

                    if padding_len > 0:
                        patch_len = ins_end - address
                        patch_data = patch_data.ljust(patch_len, "\x90")

                if padding_len > 0:
                    nop_comment = (
                        "\nKeypatch padded NOP to next boundary: {0} bytes".format(
                            padding_len
                        )
                    )

            orig_asm = self.ida_get_disasm_range(address, address + patch_len)
        else:
            # we are reverting the change via "Undo" menu
            patch_len = len(patch_data) if patch_data else 0

        (plen, p_orig_data) = self.patch(address, patch_data, patch_len)
        if plen is None:
            # failed to patch
            return -1

        if not undo:  # we are patching
            new_patch_comment = None
            if save_origcode is True:
                # append original instruction to comments
                fmted_asm = "\n  ".join(orig_asm if orig_asm else "")
                new_patch_comment = ""
                if orig_comment != "":
                    new_patch_comment = "\n"
                new_patch_comment += f"Keypatch modified this from:\n  {fmted_asm}{nop_comment}"
                
                new_comment = "{0}{1}".format(orig_comment, new_patch_comment)
                set_comment(address, new_comment)

            if padding_len == 0:
                print(
                    "Keypatch: successfully patched {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}]".format(
                        plen, address, to_hexstr(p_orig_data), to_hexstr(patch_data)
                    )
                )
            else:
                print(
                    "Keypatch: successfully patched {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}], with {4} byte(s) NOP padded".format(
                        plen,
                        address,
                        to_hexstr(p_orig_data),
                        to_hexstr(patch_data),
                        padding_len,
                    )
                )
            # save this patching for future "undo"
            patch_info.append((address, assembly, p_orig_data, new_patch_comment))
        else:  # we are reverting
            if patch_comment:
                # clean previous IDA comment by replacing it with ''
                new_comment = orig_comment.replace(patch_comment, "")
                set_comment(address, new_comment)

            print(
                "Keypatch: successfully reverted {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}]".format(
                    plen, address, to_hexstr(p_orig_data), to_hexstr(patch_data)
                )
            )

        return plen

    # fill a range of code [addr_begin, addr_end].
    # return the length of patched area
    # on failure, return 0 = wrong input, -1 = failed to patch
    def fill_code(
        self,
        addr_begin,
        addr_end,
        assembly,
        syntax,
        padding,
        save_origcode,
        orig_asm=None,
    ):
        # treat input as assembly code first
        (encoding, _) = self.assemble(assembly, addr_begin, syntax=syntax)

        if encoding is None:
            # input might be a hexcode string. try to convert it to raw bytes
            encoding = convert_hexstr(assembly)

        if encoding is None:
            # invalid input: this is neither assembly nor hexcode string
            return 0

        # save original assembly code before overwritting them
        orig_asm = self.ida_get_disasm_range(addr_begin, addr_end)

        # save original comment at addr_begin
        # TODO: save comments in this range, but how to interleave them?
        orig_comment = get_comment(addr_begin)
        if orig_comment is None:
            orig_comment = ""

        patch_data = ""
        assembly_new = []
        size = addr_end - addr_begin
        # calculate filling data
        encode_chr = "".join(chr(c) for c in encoding)
        while True:
            if len(patch_data) + len(encode_chr) <= size:
                patch_data = patch_data + encode_chr
                assembly_new += [assembly.strip()]
            else:
                break

        # for now, only support NOP padding on Intel CPU
        if padding and self.arch == KS_ARCH_X86:
            for i in range(size - len(patch_data)):
                assembly_new += ["nop"]
            patch_data = patch_data.ljust(size, "\x90")

        (plen, p_orig_data) = self.patch(addr_begin, patch_data, len(patch_data))
        if plen is None:
            # failed to patch
            return -1

        new_patch_comment = ""
        # append original instruction to comments
        if save_origcode is True:
            if orig_comment == "":
                new_patch_comment = "Keypatch filled range [0x{0:X}:0x{1:X}] ({2} bytes), replaced:\n  {3}".format(
                    addr_begin,
                    addr_end - 1,
                    addr_end - addr_begin,
                    "\n  ".join(orig_asm),
                )
            else:
                new_patch_comment = "\nKeypatch filled range [0x{0:X}:0x{1:X}] ({2} bytes), replaced:\n  {3}".format(
                    addr_begin,
                    addr_end - 1,
                    addr_end - addr_begin,
                    "\n  ".join(orig_asm),
                )

            new_comment = "{0}{1}".format(orig_comment, new_patch_comment)
            set_comment(addr_begin, new_comment)

        print(
            'Keypatch: successfully filled range [0x{0:X}:0x{1:X}] ({2} bytes) with "{3}", replaced "{4}"'.format(
                addr_begin,
                addr_end - 1,
                addr_end - addr_begin,
                assembly,
                "; ".join(orig_asm),
            )
        )

        # save this modification for future "undo"
        patch_info.append(
            (addr_begin, "\n  ".join(assembly_new), p_orig_data, new_patch_comment)
        )

        return plen

    ### Form helper functions
    @staticmethod
    def dict_to_ordered_list(dictionary):
        l = sorted(list(dictionary.items()), key=lambda t: t[0], reverse=False)
        keys = [i[0] for i in l]
        values = [i[1] for i in l]

        return (keys, values)

    def get_value_by_idx(self, dictionary, idx, default=None):
        (keys, values) = self.dict_to_ordered_list(dictionary)

        try:
            val = values[idx]
        except IndexError:
            val = default

        return val

    def find_idx_by_value(self, dictionary, value, default=None):
        (keys, values) = self.dict_to_ordered_list(dictionary)

        try:
            idx = values.index(value)
        except:
            idx = default

        return idx

    def get_arch_by_idx(self, idx):
        return self.get_value_by_idx(self.arch_lists, idx)

    def find_arch_idx(self, arch, mode):
        return self.find_idx_by_value(self.arch_lists, (arch, mode))

    def get_syntax_by_idx(self, idx):
        return self.get_value_by_idx(self.syntax_lists, idx, self.syntax)

    def find_syntax_idx(self, syntax):
        return self.find_idx_by_value(self.syntax_lists, syntax)

    ### /Form helper functions


class OpaqueAnalyzeRetValues(Enum):
    NOT_OPAQUE = 1
    ALWAYS_JMP = 2
    NEVER_JMP = 3
    CHANGE_MODE = 4
    ERROR = 5


class OpaqueIdaPatcherRetValues(Enum):
    SKIP_BLOCK = 1
    RETURN_TO_MAINLOOP = 2
    PROCEED = 3


class FunctionOpaqueIdentifier:

    def __init__(self):
        if not DEBUG_VERBOSE:
            logger = logging.getLogger("angr")
            logger.propagate = False
            logger = logging.getLogger("claripy")
            logger.propagate = False
            logger = logging.getLogger("cle")
            logger.propagate = False
            logger = logging.getLogger("pyvex")
            logger.propagate = False

        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

        self.current_func_name = idaapi.get_func_name(idaapi.get_screen_ea())
        self.current_func = ida_funcs.get_func(idaapi.get_screen_ea())
        self.ida_inputfile_path = idaapi.get_input_file_path()
        self.inputfile_path = (
            idaapi.get_input_file_path().replace(".exe", "")
            + TOPAQUE_ANGR_ADDITION
            + ".exe"
        )

        logging.debug("Reapplying IDA patches on the operating on exe..")
        if os.path.isfile(self.inputfile_path):
            try:
                os.remove(self.inputfile_path)
            except:
                self.inputfile_path = (
                    idaapi.get_input_file_path().replace(".exe", "")
                    + TOPAQUE_ANGR_ADDITION
                    + "_f.exe"
                )
        shutil.copy(self.ida_inputfile_path, self.inputfile_path)
        self.apply_patch_bytes(self.current_func.start_ea, self.current_func.end_ea)
        if not TESTS_MODE and not FIX_DEFLOW_MODE:
            logging.debug("Loading angr...")
            self.angr_prj = angr.Project(
                self.inputfile_path, load_options={"auto_load_libs": False}
            )
        else:
            logging.debug("WE ARE IN TESTS MODE. ANGR IS NOT LOADED.")
        self.kp_asm = Keypatch_Asm()
        print("Down the rabbit hole..")
        print(
            "[Topaqueminator] Identifying opaque predicates on function:",
            self.current_func_name,
        )

        self.run()

    def check_if_jmp_x86_64(self, inst_ea):
        inst = idautils.DecodeInstruction(inst_ea)
        if not inst:
            return False
        inst_str = inst.get_canon_mnem()
        if "jmp" in inst_str:
            return True
        return False

    def check_conditional_x86_64(self, inst_ea):
        inst = idautils.DecodeInstruction(inst_ea)
        if not inst:
            return False
        inst_str = inst.get_canon_mnem()
        if "j" in inst_str and "jmp" not in inst_str:
            return True
        return False

    def convert_bytes_to_asm_instructions(self, bytes):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        asm_str = ""
        for inst in md.disasm(bytes, self.current_func.start_ea):
            print(
                str(hex(inst.address)) + " " + inst.mnemonic + " " + inst.op_str + ";"
            )
            asm_str += (
                str(hex(inst.address))
                + " "
                + inst.mnemonic
                + " "
                + inst.op_str
                + ";"
                + "\n"
            )
        return asm_str

    def get_the_location_of_the_jump(self, jmp_inst_ea):
        if self.check_if_jmp_x86_64(jmp_inst_ea) or self.check_conditional_x86_64(
            jmp_inst_ea
        ):
            return idc.get_operand_value(jmp_inst_ea, 0)
        return None

    def fix_function_end(self, new_end_ea):
        logging.debug("Patching function end: {}".format(hex(new_end_ea)))
        # self.current_func.end_ea = new_end_ea
        func_ea = idc.next_head(idc.prev_head(new_end_ea))
        res = ida_funcs.set_func_end(func_ea, new_end_ea)
        logging.debug("set end result: {}".format(res))
        self.referesh_screen_and_reanalyze()

    def test_if_instruction_broken(self, inst_addr):
        if "j" in idc.print_insn_mnem(inst_addr):
            if (
                idc.generate_disasm_line(inst_addr, 0)[-2:-1] == "+"
                and idc.generate_disasm_line(inst_addr, 0)[-1:].isdigit()
            ):
                logging.debug("Broken Instruction: {}".format(hex(inst_addr)))
                return True
        return False

    def test_if_instruction_jmp_qword_broken(self, inst_addr):
        if "j" in idc.print_insn_mnem(inst_addr):
            if "+" in idc.generate_disasm_line(
                inst_addr, 0
            ) and "qword" in idc.generate_disasm_line(inst_addr, 0):
                logging.debug("Broken qword instruction: {}".format(hex(inst_addr)))
                return True
        return False

    def fix_jmp_qword(self, inst_addr):
        code_addr = self.get_the_location_of_the_jump(inst_addr)
        ret = idc.create_insn(code_addr)
        self.referesh_screen_and_reanalyze()
        return ret

    def fix_jmp_inst_on_opaque_predicate(self, opaque_addr):
        if self.test_if_instruction_broken(
            opaque_addr
        ) or self.test_if_instruction_jmp_qword_broken(opaque_addr):
            logging.debug("Fixing broken instruction...")
            code_addr = self.get_the_location_of_the_jump(opaque_addr)
            if not code_addr:
                return False
            fix_addr = code_addr - int(idc.generate_disasm_line(opaque_addr, 0)[-1:])
            ret_val_del = idc.del_items(fix_addr, 1)
            self.referesh_screen_and_reanalyze()
            ret_val_create = idc.create_insn(code_addr)
            self.referesh_screen_and_reanalyze()
            if ret_val_create == 0 or ret_val_del == False:
                return False
            return True
        return False

    def referesh_screen_and_reanalyze(self):
        ida_auto.auto_wait()
        idaapi.reanalyze_function(self.current_func)
        ida_auto.auto_wait()

    def tompaque_patch_code(self, instruction_string, address):
        cmt = (
            "Topaque Patched from: {}".format(idc.generate_disasm_line(address, 0))
            + "\n"
            + "\tTopaque Patched to: "
            + instruction_string
        )
        self.kp_asm.patch_code(
            address, instruction_string, KS_ARCH_X86, 1, 0, patch_comment=cmt
        )
        idc.set_cmt(address, cmt, False)
        self.referesh_screen_and_reanalyze()
        if APPLY_PATCHES_ON_INPUT_FILE:
            self.apply_patch_bytes(self.current_func.start_ea, self.current_func.end_ea)
        self.referesh_screen_and_reanalyze()

    def fix_opaque_predicate(self, opaque_addr, opaque_type_num, different_addr=None):
        if opaque_type_num == OpaqueAnalyzeRetValues.ALWAYS_JMP:
            if different_addr is not None:
                jmp_location_str = different_addr
            else:
                jumploc = self.get_the_location_of_the_jump(opaque_addr)
                if not jumploc:
                    print("unknown jump location!")
                    return
                jmp_location_str = hex(jumploc)
            raw_assembly = "jmp " + jmp_location_str
            self.tompaque_patch_code(raw_assembly, opaque_addr)
            self.referesh_screen_and_reanalyze()
        elif opaque_type_num == OpaqueAnalyzeRetValues.NEVER_JMP:
            raw_assembly = "nop"
            self.tompaque_patch_code(raw_assembly, opaque_addr)
            self.referesh_screen_and_reanalyze()

    def fix_undef_code_places(self, predicate_ea):
        idc.create_insn(predicate_ea)
        self.referesh_screen_and_reanalyze()

    def fix_using_single_block_analysis(self):
        # single block anaylsis.
        while SINGLE_BLOCK_MODE and self.patch_opaque_predicates_loop(
            SINGLE_BLOCK_MODE
        ):
            if not CONTINUOS_ANALYZING:
                break
        return

    def fix_using_whole_function_analysis(self):
        # next iteration start each time from start (whol func analysis)
        while self.patch_opaque_predicates_loop(False):
            if not CONTINUOS_ANALYZING:
                break

    def deflow_main_loop(self):
        pass

    def fix_using_deflow(self):
        f = FixCode(self.current_func.start_ea)
        f.process()

    def unravel_jmp_chains(self, opaque_addr):
        if self.check_conditional_x86_64(opaque_addr) or self.check_if_jmp_x86_64(
            opaque_addr
        ):
            next_jmp_loc = self.get_the_location_of_the_jump(opaque_addr)
            inst = idautils.DecodeInstruction(opaque_addr)
            if not inst:
                return False, None
            init_inst_string = inst.get_canon_mnem()
            inst = idautils.DecodeInstruction(next_jmp_loc)
            if not inst:
                return False, None
            jmp_inst_string = inst.get_canon_mnem()            
            counter = 0
            while self.check_conditional_x86_64(next_jmp_loc) and (
                init_inst_string == jmp_inst_string
            ):
                counter += 1
                next_jmp_loc = self.get_the_location_of_the_jump(next_jmp_loc)
                logging.debug(f"{next_jmp_loc}")
                if next_jmp_loc is None:
                    logging.debug("unravel_jmp_chains next_jmp_loc is None ")
                inst = idautils.DecodeInstruction(next_jmp_loc)
                if not inst:
                    logging.debug(f"cannot decode instruction at {next_jmp_loc}")
                    continue
                jmp_inst_string = inst.get_canon_mnem()
            return (counter > 0), next_jmp_loc
        return False, None

    def ida_pre_explore_patch(self, block, is_single_block_mode):
        global last_found_opaque_predicate
        global is_last_predicate_mode
        logging.debug(
            "INSIDE ida_pre_explore_patch(self, block, is_single_block_mode):"
        )
        opaque_addr = idc.prev_head(block.end_ea)
        # fix idas stupid shit, than continue with trying to analyze opaque.
        is_unraveled, final_jmp_loc = self.unravel_jmp_chains(opaque_addr)

        if is_unraveled and final_jmp_loc is not None:
            inst = idautils.DecodeInstruction(opaque_addr)
            if not inst:
                return False, None
            inst_cmd_str = inst.get_canon_mnem()
            self.tompaque_patch_code(
                inst_cmd_str + " {}".format(hex(final_jmp_loc)), opaque_addr
            )
            return OpaqueIdaPatcherRetValues.RETURN_TO_MAINLOOP

        if is_single_block_mode:
            # handle the case of single jump blocks. they are NOT opaque.
            if "j" in idc.print_insn_mnem(block.start_ea):
                logging.debug(
                    "single block start from JMP instruction is NOT opaque. block_start_ea: {} ".format(
                        hex(block.start_ea)
                    )
                )
                return OpaqueIdaPatcherRetValues.SKIP_BLOCK

        if is_last_predicate_mode:
            if last_found_opaque_predicate == None:
                logging.debug("we are in last found mode, but last_found_opaq is None.")
                raise Exception("Error: we are in last found mode, but last_found_opaq is None.")

            if block.start_ea < self.get_the_location_of_the_jump(
                last_found_opaque_predicate
            ):
                logging.debug(
                    "block.start_ea < self.get_the_location_of_the_jump(last_found_opaque_predicate), skipping block"
                )
                return OpaqueIdaPatcherRetValues.SKIP_BLOCK

        if self.check_conditional_x86_64(opaque_addr) or self.check_if_jmp_x86_64(
            opaque_addr
        ):
            jump_to_operand_location_value = self.get_the_location_of_the_jump(
                opaque_addr
            )
            if self.test_if_instruction_broken(
                opaque_addr
            ) or self.test_if_instruction_jmp_qword_broken(opaque_addr):
                if (
                    idaapi.get_func(jump_to_operand_location_value) is None
                ):  # was jump + 0x15
                    logging.debug(
                        "Chunk does not belone to any function, create and set func end"
                    )
                    # func_ea = block.end_ea
                    if self.fix_jmp_inst_on_opaque_predicate(opaque_addr) == False:
                        logging.debug("UNABLE TO FIX BROKEN INSTRUCTION, PROCEEDING..")
                        return OpaqueIdaPatcherRetValues.PROCEED
                    # idc.set_func_end(func_ea, jump_to_operand_location_value + 0x10)
                    self.referesh_screen_and_reanalyze()
                    return OpaqueIdaPatcherRetValues.RETURN_TO_MAINLOOP
                if jump_to_operand_location_value < opaque_addr:
                    # broken instuction + opaque address
                    # TODO: if we are at the beginning, return false and let the user decide.
                    raise ValueError(
                        "SELF DECRYPTING CODE FOUND. PLEASE HANDLY MANUALLY."
                    )
                    # self.tompaque_patch_code("nop", opaque_addr)
                    # return OpaqueIdaPatcherRetValues.RETURN_TO_MAINLOOP
            if jump_to_operand_location_value < opaque_addr:
                # we are in a loop, analyze the next instruction. no point in analyzing this one.
                return OpaqueIdaPatcherRetValues.SKIP_BLOCK
            else:
                # cond jmp is 2 bytes
                if (
                    idc.next_head(opaque_addr)
                    - (opaque_addr + CONDITIONAL_JMP_SIZE_IN_BYTES)
                    == 1
                ):
                    # is conditional, instruction not broken, next head is 1 bytes fucking close.
                    # they are doing that stupid shit again. ja jb [x] jb [x
                    logging.debug(
                        "is conditional, instruction not broken, next head is 1 bytes fucking close."
                    )
                    logging.debug(
                        "they are doing that stupid shit again. ja jb [x] jb [x"
                    )
                    if self.check_if_jmp_x86_64(opaque_addr):
                        return OpaqueIdaPatcherRetValues.PROCEED
                    if final_jmp_loc is not None:
                        self.handle_found_opaque_predicate(
                            OpaqueAnalyzeRetValues.ALWAYS_JMP, opaque_addr, block
                        )
                    last_found_opaque_predicate = opaque_addr
                    return OpaqueIdaPatcherRetValues.RETURN_TO_MAINLOOP

        return OpaqueIdaPatcherRetValues.PROCEED

    def handle_found_opaque_predicate(
        self, analyze_res, opaque_addr, block, different_addr=None
    ):
        global is_last_predicate_mode
        if (analyze_res == OpaqueAnalyzeRetValues.ALWAYS_JMP) or (
            analyze_res == OpaqueAnalyzeRetValues.NEVER_JMP
        ):
            # Opaque was found, restart the function analysis.
            # TODO: currently, angr is working on the binary, meaning if IDA patched the bytes it does not mean angr seen it.
            # think of something clever to solve that.
            print("######## - OPAQUE FOUND - ########")
            print("Opaque conditional jump address is: ", hex(opaque_addr))
            if analyze_res == OpaqueAnalyzeRetValues.ALWAYS_JMP:
                self.fix_jmp_inst_on_opaque_predicate(opaque_addr)
                if (
                    sum(1 for _ in (idautils.CodeRefsTo(idc.next_head(opaque_addr), 1)))
                    == 1
                ):
                    logging.debug("No xrefs, patching opaque func chunk end")
                    # if there are no xrefs to the next line, fix the function chunk end.
                    self.fix_function_end(block.end_ea)
                logging.debug("Opaque type is ALWAYS JMP")
            elif analyze_res == OpaqueAnalyzeRetValues.NEVER_JMP:
                logging.debug("Opaque type is NEVER JMP")
            else:
                logging.error(
                    "PROBABLY SHOULDNT BE HERE \nError was returned, probably trying to go to a chunk that is not a part of fuction.\n"
                )
                raise Exception("ERROR")
            print("Starting to patch the opaque")
            self.fix_opaque_predicate(opaque_addr, analyze_res, different_addr)
            print("Tomerminatored the opaque.")
            return True
        if analyze_res == OpaqueAnalyzeRetValues.CHANGE_MODE:
            logging.debug("Changing mode.. to many active shitty states.")
            is_last_predicate_mode = True
        if analyze_res == OpaqueAnalyzeRetValues.NOT_OPAQUE:
            if self.fix_jmp_inst_on_opaque_predicate(opaque_addr):
                return True

        return False

    def patch_opaque_predicates_loop(self, is_single_block_mode):
        global is_last_predicate_mode
        self.referesh_screen_and_reanalyze()
        fc = idaapi.FlowChart(self.current_func)
        counter = 0

        # MAIN LOOP
        for block in fc:
            print(
                "======================================================================"
            )

            self.referesh_screen_and_reanalyze()
            opaque_addr = idc.prev_head(block.end_ea)
            patch_retval = self.ida_pre_explore_patch(block, is_single_block_mode)

            if patch_retval == OpaqueIdaPatcherRetValues.SKIP_BLOCK:
                continue
            if patch_retval == OpaqueIdaPatcherRetValues.RETURN_TO_MAINLOOP:
                return True
            if patch_retval == OpaqueIdaPatcherRetValues.PROCEED:
                pass

            if self.check_conditional_x86_64(opaque_addr):
                print(
                    "Found conditional jump address in: ",
                    hex(opaque_addr),
                    ".\n Starting to explore.",
                )
                analyze_res = self.explore_for_opaques(
                    opaque_addr, is_single_block_mode, block.start_ea
                )
                if self.handle_found_opaque_predicate(analyze_res, opaque_addr, block):
                    return True
            else:
                print("conditional jump not found.")

            print("Iteration Done.")
            counter += 1
            if counter == DEPTH:
                logging.debug("MAX ITERATIONS, STOPPING.")
                break

        return False

    def convert_asm_string_to_bytes(self, asm_str) -> bytes:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        all_shell_code = b""
        for inst in asm_str:
            encoding, count = ks.asm(inst)
            if not encoding:
                continue
            opcodes = b""
            for i in encoding:
                opcodes += bytes([i])
            all_shell_code += opcodes
        return all_shell_code

    def pre_explore_get_ea_of_execution_start(
        self, is_single_block_mode, block_start_ea
    ):
        global last_found_opaque_predicate
        global is_last_predicate_mode
        start_ea = 0x0
        if (last_found_opaque_predicate is not None) and is_last_predicate_mode:
            start_ea = self.get_the_location_of_the_jump(last_found_opaque_predicate)
            logging.debug("Start from last found predicate, not function start.")
        else:
            start_ea = self.current_func.start_ea

        if is_single_block_mode:
            start_ea = block_start_ea

        if (not is_last_predicate_mode) and (not is_single_block_mode):
            start_ea = self.current_func.start_ea

        return start_ea

    def apply_pre_explore_heursitcs(self, predicate_ea):
        global addresses_avoided_set
        global addresses_find_set
        predicate_jmp_address_operand = self.get_the_location_of_the_jump(predicate_ea)

        # Append invariants
        addresses_avoided_set.add(predicate_jmp_address_operand)
        addresses_find_set.add(idaapi.next_head(predicate_ea, predicate_ea + 0xF))
        addresses_find_set.add(idc.next_addr(predicate_ea))

        logging.debug(
            "PRE EXPLORE: Avoid set is: [{}]".format(
                ", ".join(hex(x) for x in addresses_avoided_set)
            )
        )
        logging.debug(
            "PRE EXPLORE: Find set is: [{}]".format(
                ", ".join(hex(x) for x in addresses_find_set)
            )
        )

    def evaluate_explore_results(self, simMgr):
        logging.debug("SimMgr: {}".format(simMgr))
        total_stashes_len = 0

        for stash in simMgr.stashes:
            total_stashes_len += len(stash)

        if len(simMgr.unconstrained) == total_stashes_len:
            raise ValueError("All states ended unconstrained.")
            return OpaqueAnalyzeRetValues.NOT_OPAQUE

        if len(simMgr.found) == 0:
            logging.debug("len(simMgr.found) == 0 and len(simMgr.unconstrained) == 0")
            return OpaqueAnalyzeRetValues.ALWAYS_JMP
        else:
            if total_stashes_len - len(simMgr.found) == 0:
                logging.debug(
                    "len(simMgr.found) != 0 or len(simMgr.unconstrained) != 0, total_stashes_len = len(found)"
                )
                return OpaqueAnalyzeRetValues.NEVER_JMP
            if total_stashes_len - len(simMgr.avoid) == 0:
                logging.debug("total_stashes_len = len(avoid)")
                return OpaqueAnalyzeRetValues.ALWAYS_JMP

        return OpaqueAnalyzeRetValues.NOT_OPAQUE

    def patch_bytes_on_position(self, ea, fpos, org_val, patch_val):
        if fpos != -1:
            self.inputfile_obj.seek(fpos)
            self.inputfile_obj.write(struct.pack("B", patch_val))
        return 0

    def apply_patch_bytes(self, start_ea, end_ea):
        self.inputfile_obj = open(self.inputfile_path, "rb+")
        idaapi.visit_patched_bytes(start_ea, end_ea, self.patch_bytes_on_position)
        self.inputfile_obj.close()

    def apply_post_explore_heuristics(self, ret_code, predicate_ea, simMgr):
        global last_found_opaque_predicate
        global addresses_avoided_set
        global addresses_find_set
        global opaque_jumpedto_addresses_set
        ret_code = ret_code
        predicate_jmp_address_operand = self.get_the_location_of_the_jump(predicate_ea)

        # restore invaraints.
        # TODO: think of heuristic.
        addresses_avoided_set.remove(predicate_jmp_address_operand)
        addresses_find_set.clear()
        if ret_code != OpaqueAnalyzeRetValues.NOT_OPAQUE:
            last_found_opaque_predicate = predicate_ea
            opaque_jumpedto_addresses_set.add(predicate_jmp_address_operand)

        if len(simMgr.active) > ACTIVE_THERSHOLD_FOR_LAST_PREDICATE_MODE:
            ret_code = OpaqueAnalyzeRetValues.CHANGE_MODE

        logging.debug(
            "POST EXPLORE: Avoid set is: [{}]".format(
                ", ".join(hex(x) for x in addresses_avoided_set)
            )
        )
        logging.debug(
            "POST EXPLORE: Find set is: [{}]".format(
                ", ".join(hex(x) for x in addresses_find_set)
            )
        )
        return ret_code

    @staticmethod
    def avoid_function(state):
        return state.addr >= min(addresses_avoided_set)

    @staticmethod
    def find_function(state):
        return (state.addr >= min(addresses_find_set)) and (
            state.addr <= max(addresses_find_set)
        )

    def explore_for_opaques(self, predicate_ea, is_single_block_mode, block_start_ea):
        start_ea = 0x0
        ret_code = OpaqueAnalyzeRetValues.NOT_OPAQUE

        start_ea = self.pre_explore_get_ea_of_execution_start(
            is_single_block_mode, block_start_ea
        )

        # ignore func call
        s = self.angr_prj.factory.blank_state(addr=start_ea)
        s.options.add(angr.options.CALLLESS)
        # s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        # s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        # s.options.add(angr.options.SYMBOLIC)
        # s.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        # s.options.add(angr.options.ABSTRACT_MEMORY)

        simMgr = self.angr_prj.factory.simgr(s)

        self.apply_pre_explore_heursitcs(predicate_ea)

        simMgr.explore(
            find=FunctionOpaqueIdentifier.find_function,
            avoid=FunctionOpaqueIdentifier.avoid_function,
        )

        ret_code = self.evaluate_explore_results(simMgr)

        ret_code = self.apply_post_explore_heuristics(ret_code, predicate_ea, simMgr)

        return ret_code

    def patch_opaque_predicates(self):

        if FIX_DEFLOW_MODE:
            logging.debug("Deflow fix running.")
            self.fix_using_deflow()
        elif SINGLE_BLOCK_MODE:
            logging.debug("Single block level opaque removal fix running.")
            self.fix_using_single_block_analysis()
        elif WHOLE_FUNCTION_MODE:
            logging.debug("Whole function level opaque removal fix running.")
            self.fix_using_whole_function_analysis()

    def run(self):
        self.patch_opaque_predicates()


jumps = [
    NN_jmp,
    NN_jmpfi,
    NN_jmpni,
    NN_jmpshort,
    NN_ja,
    NN_jae,
    NN_jb,
    NN_jbe,
    NN_jc,
    NN_jcxz,
    NN_jecxz,
    NN_jrcxz,
    NN_je,
    NN_jg,
    NN_jge,
    NN_jl,
    NN_jle,
    NN_jna,
    NN_jnae,
    NN_jnb,
    NN_jnbe,
    NN_jnc,
    NN_jne,
    NN_jng,
    NN_jnge,
    NN_jnl,
    NN_jnle,
    NN_jno,
    NN_jnp,
    NN_jns,
    NN_jnz,
    NN_jo,
    NN_jp,
    NN_jpe,
    NN_jpo,
    NN_js,
    NN_jz,
]


class FixCode:
    unexplored: set[int] = set()
    explored: set[int] = set()

    def __init__(self, ea) -> None:
        self.unexplored.add(ea)

    @staticmethod
    def is_valid_jump(cmd):
        jump_to = cmd.Op1.addr
        item_start = get_item_head(jump_to)
        # print(f"{cmd.ea:x} - is_valid_jump: {jump_to:x} =? {get_item_head(jump_to):x}")
        return item_start == jump_to

    # makes code if needed on ea and returns next instr addr
    @staticmethod
    def make_code(ea) -> int:
        # skip if already code
        if is_code(get_flags(ea)) and get_item_head(ea) == ea:
            return get_item_head(ea)

        cmd = insn_t()
        auto_wait()
        if create_insn(ea, cmd) <= 0:
            # try to undef and retry
            del_items(ea, 0, 10)
            cmd = insn_t()
            if create_insn(ea, cmd) <= 0:
                print(f"create_insn(ea, cmd) failed {ea:x}, dont know what to do")
                return BADADDR
            auto_wait()

        return get_item_head(ea)

    @staticmethod
    def append_cmt(ea, cmt):
        e_cmt = get_cmt(ea, False) or ""
        set_cmt(ea, e_cmt + " " + cmt, 0)

    @staticmethod
    def fill_nop(cmd):
        # 2 bytes jump
        FixCode.append_cmt(cmd.ea, f"Patched jmp, original: {GetDisasm(cmd.ea)}")
        patch_byte(cmd.ea, 0xEB)
        for ea in range(get_item_end(cmd.ea), cmd.Op1.addr):
            patch_byte(ea, 0x90)
        # if cmd.itype in NN_call:

    # fix 'chunk' from ea and below, until ret or no code
    def fix_chunk(self, ea):
        start_chunk_ea = ea
        cmd = insn_t()
        print(f"fix_chunk starting ea: {ea:x}")
        FixCode.append_cmt(ea, f"chunk {ea:x} starts here")
        while True:
            ea = get_item_head(ea)
            new_ea = self.make_code(ea)
            if new_ea == BADADDR:
                break
            ea = new_ea
            size = decode_insn(cmd, ea)
            print(f"working on {ea:x}, size: {size} {GetDisasm(ea)}")
            if cmd.itype in jumps:

                # check if jump+X - not valid, obfuscation
                rc = self.is_valid_jump(cmd)
                if rc:
                    if cmd.Op1.addr not in self.explored:
                        FixCode.append_cmt(cmd.ea, "original good jump ")
                        self.explored.add(cmd.Op1.addr)
                        if cmd.itype == NN_jmp:
                            print(f"straight JMP to {cmd.Op1.addr:x} continue there")
                            FixCode.append_cmt(cmd.ea, "JMP, taking it to process")
                            ea = cmd.Op1.addr
                            continue

                        # seems to be valid conditional jump, add addr to process this branch
                        self.unexplored.add(cmd.Op1.addr)
                        print(f"valid jump at {cmd.ea:x}, adding {cmd.Op1.addr:x}")
                        FixCode.append_cmt(
                            cmd.ea,
                            f"good conditional jump, queue as chunk {cmd.Op1.addr:x}",
                        )
                    else:
                        print(f"already processed, valid jump at {cmd.ea:x}")
                else:
                    if size > 2:
                        print(
                            f"WARNING, size {size} > 2, obfuscations jumps are 2 byte long"
                        )
                        return

                    print(f"obfuscation jump at {cmd.ea:x} to {cmd.Op1.addr:x}, nop it")
                    if cmd.ea > cmd.Op1.addr:
                        print(
                            f"negative jump at {cmd.ea:x} to {cmd.Op1.addr:x}, stop chunk here, idk what to do"
                        )
                        return
                    # fill with nops
                    self.fill_nop(cmd)
                    # self.make_code(cmd.Op1.addr)
                    ea = cmd.Op1.addr
                    del_items(ea, 0, 10)
                    auto_wait()
                    continue

            if cmd.itype == NN_retn:
                print(f"reached return. done  {cmd.ea:x} ")
                break

            # advance to next instr
            ea = get_item_end(ea)
        print(f"fix_chunk ends: {start_chunk_ea:x}")
        FixCode.append_cmt(ea, f"chunk {start_chunk_ea:x} ends here")

    def process(self):
        loops = 0
        while len(self.unexplored) > 0:
            ea = self.unexplored.pop()
            self.fix_chunk(ea)
            loops += 1
            _addr = [f"{x:x} " for x in self.unexplored]
            _done = [f"{x:x} " for x in self.explored]
            print(f"addresses to process: {len(self.unexplored)} - {_addr}")
            print(f"addresses done: {len(self.explored)} - {_done}")
            # if loops > 50:
            #     break


def run_main_class():
    analyze = FunctionOpaqueIdentifier()

if __name__ == "__main__":
    run_main_class()

# """------------------------------"""


# class Topaqueminator(idaapi.plugin_t):
#     flags = idaapi.PLUGIN_UNL
#     wanted_name = "Topaqueminator"
#     wanted_hotkey = "Ctrl-Alt-T"
#     comment = "Topaqueminator Comment"
#     help = "TBD"

#     def init(self):
#         print("--------------------------------------")
#         print("Topaqueminator Starting. VER:", T_VER)
#         print("--------------------------------------")
#         return idaapi.PLUGIN_OK

#     def run(self, ctx):
#         run_main_class()

#     def term(self):
#         print("Made by Tomerminator, use as you wish.")
#         print("Topaqueminator finished.")


# """------------------------------"""


# def PLUGIN_ENTRY():
#     try:
#         return Topaqueminator()
#     except Exception as err:
#         import traceback

#         print(f"Error: {err}\n{traceback.format_exc()}")
#         raise


# """------------------------------"""
