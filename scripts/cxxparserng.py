import sys

analysismodules = [mod for mod in sys.modules if mod.startswith("rangers_analysis")]
for mod in analysismodules:
    del sys.modules[mod]

from rangers_analysis.config import autoconfigure_rangers_analysis

autoconfigure_rangers_analysis()

import cProfile
import csv
import os
import re
from ctypes import POINTER, c_uint

from clang.cindex import (
    BaseEnumeration,
    Cursor,
    CursorKind,
    Index,
    TranslationUnit,
    TypeKind,
    _CXString,
    conf,
    register_function,
)
from rangers_analysis.config import rangers_analysis_config
from rangers_analysis.lib.analysis_exceptions import AnalysisException
from rangers_analysis.lib.funcs import ensure_function, require_thunk
from rangers_analysis.lib.naming import (
    get_alias_ea,
    get_aliases,
    get_all_aliases,
    nlist_names,
    remove_alias,
    set_generated_func_name,
    set_generated_name,
)

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment
import idaapi
from ida_bytes import *
from ida_netnode import netnode
from ida_typeinf import *
from idc import *

if not conf.loaded:
    conf.set_library_file(os.path.join(os.path.dirname(__file__), "libclang.dll"))

API_LOCATION = os.environ[rangers_analysis_config["sdk_env_var"]]
UCSL_LOCATION = os.environ["UCSL_LOCATION"]

known_mangled_names = []

# class _CXStringForSet(_CXString):
#     def __del__(self):
#         pass

# class _CXStringSet(Structure):
#     _fields_ = [("strings", POINTER(_CXStringForSet)), ("count", c_uint)]

#     def __del__(self):
#         conf.lib.clang_disposeStringSet(byref(self))

#     def __len__(self):
#         return self.count

#     def __getitem__(self, idx):
#         if idx < 0 or idx >= self.count:
#             raise IndexError()

#         return self.strings[idx]

#     @staticmethod
#     def from_result(res, fn=None, args=None):
#         if not res:
#             return []

#         string_set = res.contents
#         assert isinstance(string_set, _CXStringSet)
#         return [_CXStringForSet.from_result(s) for s in string_set]

# register_function(conf.lib, ('clang_Cursor_getCXXManglings', [Cursor], POINTER(_CXStringSet), _CXStringSet.from_result), False)

# @property
# def cxx_manglings(self):
#     return conf.lib.clang_Cursor_getCXXManglings(self)

# Cursor.cxx_manglings = cxx_manglings

register_function(
    conf.lib,
    (
        "clang_Cursor_getMicrosoftVFTableMangling",
        [Cursor, POINTER(Cursor), c_uint],
        _CXString,
        _CXString.from_result,
    ),
    False,
)
register_function(conf.lib, ("clang_Cursor_getODRHash", [Cursor], c_uint), False)


def get_mangled_vtable_name(self, base_path=[]):
    base_path_size = len(base_path)
    base_path_arr = (Cursor * base_path_size)(*base_path)
    return conf.lib.clang_Cursor_getMicrosoftVFTableMangling(
        self, base_path_arr, base_path_size
    )


Cursor.get_mangled_vtable_name = get_mangled_vtable_name


def get_odr_hash(self):
    return conf.lib.clang_Cursor_getODRHash(self)


Cursor.get_odr_hash = get_odr_hash

try:
    CursorKind.CONCEPT
except:
    CursorKind.CONCEPT = CursorKind(604)


def parse_usr(usr):
    initial_usr = usr
    substitutions = []

    # print(f'parsing usr {usr}')

    def expect(m):
        if m:
            return m
        else:
            raise Exception(f"parse error: {usr} in USR {initial_usr}")

    def parse_re(regexp):
        nonlocal usr

        m = re.match(regexp, usr)

        if m:
            usr = usr[len(m.group(0)) :]
            return m.group(0)
        else:
            return None

    def parse_ident():
        return parse_re(r"[a-zA-Z0-9_]+")

    def parse_template_argument_():
        if parse_re(f"V"):
            t = parse_type()
            val = parse_re("[0-9]+")
            if not val:
                # hack due to USR ambiguity in e.g. c:@N@std@S@_Iter_traits_pointer>#V$@N@std@E@_Itraits_pointer_strategy0<
                val = re.search(r"[0-9]+$", t).group(0)
            return val
        if pack_header := parse_re(r"p[0-9]+"):
            pack_size = int(pack_header[1:])
            pack_args = []

            for _ in range(0, pack_size):
                pack_args.append(parse_template_argument_())

            return ", ".join(pack_args)

        return parse_type()

    def parse_template_argument():
        expect(parse_re(r"#"))
        return parse_template_argument_()

    def parse_template_parameter_list():
        header = parse_re(r">[0-9]+")
        if header:
            size = int(header[1:])
            args = []

            for _ in range(0, size):
                args.append(parse_template_argument())

            expect(parse_re(r"<"))

            return f'<{", ".join(args)}>'

    def parse_template_argument_list():
        if parse_re(r">"):
            args = []

            while not parse_re(r"<"):
                args.append(parse_template_argument())

            return f'<{", ".join(args)}>'

    def parse_array():
        if parse_re(r"n"):
            size = expect(parse_re(r"[0-9]+"))
            t = expect(parse_type())

            return f"{t}[{size}]"

    def parse_builtin_type():
        if parse_re(r"v"):
            return "void"
        if parse_re(r"b"):
            return "bool"
        if parse_re(r"c"):
            return "unsigned char"
        if parse_re(r"u"):
            return "char8_t"
        if parse_re(r"q"):
            return "char16_t"
        if parse_re(r"w"):
            return "char32_t"
        if parse_re(r"s"):
            return "unsigned short"
        if parse_re(r"i"):
            return "unsigned int"
        if parse_re(r"l"):
            return "unsigned long"
        if parse_re(r"k"):
            return "unsigned long long"
        if parse_re(r"j"):
            return "unsigned __int128"
        if parse_re(r"C"):
            return "char"
        if parse_re(r"r"):
            return "signed char"
        if parse_re(r"W"):
            return "wchar_t"
        if parse_re(r"S"):
            return "short"
        if parse_re(r"I"):
            return "int"
        if parse_re(r"L"):
            return "long"
        if parse_re(r"K"):
            return "long long"
        if parse_re(r"J"):
            return "__int128"
        if parse_re(r"h"):
            return "__fp16"
        if parse_re(r"f"):
            return "float"
        if parse_re(r"d"):
            return "double"
        if parse_re(r"D"):
            return "long double"
        if parse_re(r"Q"):
            return "__float128"
        if parse_re(r"n"):
            return "nullptr"

    def parse_non_builtin_type():
        nonlocal usr

        if parse_re(r"@N@|@S@|@E@|@U@|@SA@|@EA@|@UA@"):
            name = expect(parse_ident())
            args = parse_template_argument_list()
            qualifier = f'{name}{args if args else ""}'

            rest = parse_type()

            return f"{qualifier}::{rest}" if rest else qualifier
        # Add qualifiers for namespaces and structs
        if parse_re(r"@ST"):
            name = expect(parse_ident())
            args = expect(parse_template_parameter_list())
            qualifier = f"{name}{args}"

            expect(parse_re(r"@"))

            rest = parse_type()

            return f"{qualifier}::{rest}" if rest else qualifier
        if parse_re(r"\$"):
            return parse_type()
        if parse_re(r"@T@"):
            return parse_ident()
        if parse_re(r"@"):
            name = expect(parse_ident())
            rest = parse_type()
            return f"{name}::{rest}" if rest else name
        if parse_re(r"\*"):
            return f"{parse_type()}*"
        if parse_re(f"&&"):
            return f"{parse_type()}&&"
        if parse_re(f"&"):
            return f"{parse_type()}&"
        if parse_re(r"%"):
            class_type = expect(parse_type())
            func_type = expect(parse_type())
            first_space_index = func_type.index(" ")
            return f"{func_type[:first_space_index]} ({class_type}::*){func_type[first_space_index + 1:]}"
        if parse_re(r"F"):
            return_type = expect(parse_type())
            args = []

            expect(parse_re("\("))
            while not parse_re("\)"):
                expect(parse_re("#"))
                args.append(expect(parse_type()))

            return f'{return_type} ({", ".join(args)})'
        if parse_re(r"{"):
            return expect(parse_array())

    def parse_type():
        if mods := parse_re(r"[1-7]"):
            modflags = int(mods)
            m = ""
            if modflags & 1:
                m += "const "
            if modflags & 2:
                m += "volatile "
            if modflags & 4:
                m += "restrict "
            return f"{m}{parse_type()}"
        if substExpr := parse_re(r"S[0-9]+_"):
            substIdx = int(substExpr[1:-1])
            return substitutions[substIdx]
        if res := parse_builtin_type():
            return res
        if res := parse_non_builtin_type():
            substitutions.append(res)
            return res

    def parse_decl():
        typ = parse_type()
        args = parse_template_argument_list()

        return f'{typ}{args if args else ""}'

    expect(parse_re(r"c:"))
    parse_re(r"[^@]*")
    return parse_decl()


decl_name_cache = dict()


def get_decl_name(decl):
    usr = decl.get_usr()

    if usr in decl_name_cache:
        return decl_name_cache[usr]

    parsed = parse_usr(usr)

    decl_name_cache[usr] = parsed

    return parsed


class CallingConv(BaseEnumeration):
    _kinds = []
    _name_map = None
    pass


CallingConv.Default = CallingConv(0)
CallingConv.C = CallingConv(1)
CallingConv.X86StdCall = CallingConv(2)
CallingConv.X86FastCall = CallingConv(3)

CallingConv.X86ThisCall = CallingConv(4)
CallingConv.X86Pascal = CallingConv(5)
CallingConv.AAPCS = CallingConv(6)
CallingConv.AAPCS_VFP = CallingConv(7)

CallingConv.X86RegCall = CallingConv(8)
CallingConv.IntelOclBicc = CallingConv(9)
CallingConv.Win64 = CallingConv(10)
CallingConv.X86_64Win64 = CallingConv.Win64

CallingConv.X86_64SysV = CallingConv(11)
CallingConv.X86VectorCall = CallingConv(12)
CallingConv.Swift = CallingConv(13)
CallingConv.PreserveMost = CallingConv(14)

CallingConv.PreserveAll = CallingConv(15)
CallingConv.AArch64VectorCall = CallingConv(16)
CallingConv.Invalid = CallingConv(100)
CallingConv.Unexposed = CallingConv(200)
cursor_handlers = {}
type_handlers = {}
idati = idaapi.get_idati()

if idaapi.BADADDR == 2**64 - 1:
    FF_POINTER = FF_QWORD
    POINTER_SIZE = 8

else:
    FF_POINTER = FF_DWORD
    POINTER_SIZE = 4

simple_types = {
    TypeKind.BOOL: BTF_BOOL,
    TypeKind.FLOAT: BTF_FLOAT,
    TypeKind.DOUBLE: BTF_DOUBLE,
    TypeKind.LONGDOUBLE: BTF_LDOUBLE,
    TypeKind.CHAR_S: BTF_CHAR,
    TypeKind.CHAR_U: BTF_UCHAR,
    TypeKind.SCHAR: BTF_CHAR,
    TypeKind.UCHAR: BTF_UCHAR,
    TypeKind.WCHAR: BT_INT16,
    TypeKind.CHAR16: BT_INT16,
    TypeKind.CHAR32: BT_INT32,
    TypeKind.SHORT: BTF_INT16,
    TypeKind.USHORT: BTF_UINT16,
    TypeKind.INT: BTF_INT32,
    TypeKind.LONG: BTF_INT32,
    TypeKind.LONGLONG: BTF_INT64,
    TypeKind.UINT: BTF_UINT32,
    TypeKind.ULONG: BTF_UINT32,
    TypeKind.ULONGLONG: BTF_UINT64,
    TypeKind.INT128: BTF_INT128,
    TypeKind.UINT128: BTF_UINT128,
    TypeKind.VOID: BTF_VOID,
    TypeKind.INVALID: BTF_VOID,
}


def get_stock_type_id(type):
    match type.kind:
        case TypeKind.POINTER:
            pointee = type.get_pointee()

            match pointee.kind:
                case TypeKind.SCHAR:
                    return STI_PCCHAR if pointee.is_const_qualified() else STI_PCHAR
                case TypeKind.UCHAR:
                    return STI_PCUCHAR if pointee.is_const_qualified() else STI_PUCHAR
                case TypeKind.INT:
                    return None if pointee.is_const_qualified() else STI_PINT
                case TypeKind.UINT:
                    return None if pointee.is_const_qualified() else STI_PUINT
                case TypeKind.VOID | TypeKind.INVALID:
                    return STI_PCVOID if pointee.is_const_qualified() else STI_PVOID
                case TypeKind.POINTER:
                    if pointee.is_const_qualified():
                        return None

                    pointee2 = pointee.get_pointee()

                    match pointee2.kind:
                        case TypeKind.VOID | TypeKind.INVALID:
                            return None if pointee2.is_const_qualified() else STI_PPVOID

        case TypeKind.NULLPTR:
            return STI_PVOID

        case TypeKind.VARIABLEARRAY | TypeKind.INCOMPLETEARRAY:
            element = type.get_array_element_type()

            match element.kind:
                case TypeKind.SCHAR:
                    return STI_ACCHAR if element.is_const_qualified() else STI_ACHAR
                case TypeKind.UCHAR:
                    return STI_ACUCHAR if element.is_const_qualified() else STI_AUCHAR

        case TypeKind.ELABORATED | TypeKind.TYPEDEF:
            match type.spelling:
                case "size_t":
                    return STI_SIZE_T
                case "ssize_t":
                    return STI_SSIZE_T


def handle_stock_type(type):
    stock_type_id = get_stock_type_id(type)

    if stock_type_id != None:
        return tinfo_t.get_stock(stock_type_id)


class KnownMangledName:
    def __init__(self, name, tif):
        self.name = name
        self.tif = tif


def discover_sdk_name(mangled_name, type, apply_type=False):
    known_mangled_names.append(KnownMangledName(mangled_name, type))
    if apply_type:
        apply_type_to_name(mangled_name, type)


def apply_type_to_name(mangled_name, type):
    if address := get_alias_ea(mangled_name):
        idaapi.apply_tinfo(
            address, type, idaapi.TINFO_DELAYFUNC | idaapi.TINFO_DEFINITE
        )

        thunk_name = "j_" + mangled_name
        if get_alias_ea(thunk_name) != None:
            apply_type_to_name(thunk_name, type)


callingconv_map = {
    CallingConv.C: idaapi.CM_CC_CDECL,
    CallingConv.X86FastCall: idaapi.CM_CC_FASTCALL,
    CallingConv.X86ThisCall: idaapi.CM_CC_THISCALL,
    CallingConv.X86StdCall: idaapi.CM_CC_STDCALL,
    CallingConv.X86Pascal: idaapi.CM_CC_PASCAL,
}

visited = dict()
vtable_infos = dict()
saved = set()


def get_existing_tif(decl_name):
    existing_tif = idaapi.tinfo_t()
    return existing_tif if existing_tif.get_named_type(idati, decl_name) else None


tif_ordinal_odr_hash_netnode = "$ tif ordinal odr hashes"
netnode(tif_ordinal_odr_hash_netnode).create(tif_ordinal_odr_hash_netnode)


def get_tif_odr(tif):
    return netnode(tif_ordinal_odr_hash_netnode).altval(tif.get_ordinal())


def set_tif_odr(tif, odr):
    netnode(tif_ordinal_odr_hash_netnode).altset(tif.get_ordinal(), odr)


def invalidate_odr_hash_by_ordinal(tif_ordinal):
    netnode(tif_ordinal_odr_hash_netnode).altdel(tif_ordinal)


def is_same_odr_hash(decl, tif):
    new_odr = decl.get_odr_hash()
    existing_odr = get_tif_odr(tif)
    return existing_odr != 0 and existing_odr == new_odr


def set_tif_for_odr_hash(decl, tif):
    set_tif_odr(tif, decl.get_odr_hash())


class VTableInfo:
    def __init__(self, base_path, members, offset, unshifted_class_tif):
        self.base_path = base_path
        self.members = [*members]
        self.offset = offset
        self.unshifted_class_tif = unshifted_class_tif


def save_tinfo(tif, decl_name):
    gc_marker = type_attr_t()
    gc_marker.key = "imported"
    gc_marker.value = b""
    tif.set_attr(gc_marker)

    # oldtif = tinfo_t()
    # if oldtif.get_named_type(idati, decl_name):
    #     print('for ', tif, ' comparison is ', tif.equals_to(oldtif))

    tif.set_named_type(idati, decl_name, idaapi.NTF_REPLACE)
    saved.add(decl_name)


def garbage_collect():
    next_name = first_named_type(idati, NTF_TYPE)

    while next_name != None:
        cur_name = next_name
        next_name = next_named_type(idati, cur_name, NTF_TYPE)

        tif = tinfo_t()
        tif.get_named_type(idati, cur_name)

        if tif.get_attr("imported") != None and not cur_name in saved:
            del_named_type(idati, cur_name, NTF_TYPE)


def CursorHandler(kind):
    def decorator(f):
        cursor_handlers[kind] = f
        return f

    return decorator


def TypeHandler(kind):
    def decorator(f):
        type_handlers[kind] = f
        return f

    return decorator


def resolve_function(
    type, flags=0, class_tif=None, decl=None, this_shift=0, this_parent_tif=None
):
    decl = decl or type.get_declaration()
    tif = idaapi.tinfo_t()
    data = idaapi.func_type_data_t()
    data.flags = flags
    data.stkargs = 0
    data.spoiled.clear()
    data.clear()

    # ida only supports cdecl + ellipsis when varargs exists
    if type.is_function_variadic():
        data.cc = idaapi.CM_CC_ELLIPSIS
    else:
        # you can use one of these
        # data.cc = idaapi.CM_CC_THISCALL
        data.cc = idaapi.CM_CC_FASTCALL

    if class_tif:
        thistype = idaapi.tinfo_t()

        this_type_ptd = ptr_type_data_t()
        this_type_ptd.obj_type = class_tif

        if this_shift != 0:
            this_type_ptd.parent = this_parent_tif
            this_type_ptd.delta = this_shift
            this_type_ptd.taptr_bits = TAPTR_SHIFTED

        thistype.create_ptr(this_type_ptd)
        funcarg = idaapi.funcarg_t()
        funcarg.name = "this"
        funcarg.type = thistype
        funcarg.flags = FAI_HIDDEN
        data.push_back(funcarg)

    if decl.kind == CursorKind.CONSTRUCTOR:
        data.rettype = thistype
    else:
        return_type = type.get_result()
        return_tif = get_ida_type(return_type)

        if return_type.get_canonical().kind in (
            TypeKind.RECORD,
            TypeKind.CONSTANTARRAY,
            TypeKind.INCOMPLETEARRAY,
            TypeKind.VARIABLEARRAY,
            TypeKind.DEPENDENTSIZEDARRAY,
        ):
            real_return_tif = idaapi.tinfo_t()
            real_return_tif.create_ptr(return_tif)

            data.rettype = real_return_tif

            funcarg = idaapi.funcarg_t()
            funcarg.name = "retstr"
            funcarg.type = real_return_tif
            funcarg.flags = FAI_STRUCT | FAI_RETPTR

            data.push_back(funcarg)
        else:
            data.rettype = return_tif

    if decl.kind != CursorKind.NO_DECL_FOUND:
        for argument in decl.get_arguments():
            funcarg = idaapi.funcarg_t()
            funcarg.name = argument.spelling
            funcarg.type = get_ida_type(argument.type)
            data.push_back(funcarg)
    else:
        for argument in type.argument_types():
            funcarg = idaapi.funcarg_t()
            funcarg.type = get_ida_type(argument)
            data.push_back(funcarg)

    if decl.kind == CursorKind.DESTRUCTOR:
        flags_tif = idaapi.tinfo_t()
        flags_tif.create_simple_type(BTF_UINT32)

        funcarg = idaapi.funcarg_t()
        funcarg.name = "flags"
        funcarg.type = flags_tif
        data.push_back(funcarg)

    tif.create_func(data)
    tif.get_func_details(data)  # TODO: what?
    return tif


def _create_forward_declaration(decl):
    declname = get_decl_name(decl)
    tif = idaapi.tinfo_t()

    if not tif.get_named_type(idati, declname):
        tif.create_forward_decl(idati, BTF_STRUCT, declname)

    visited[decl.hash] = tif
    return tif


def get_ida_type(type):
    decl = type.get_declaration()

    # print(f'GET: {type.kind}, spelling: {type.spelling}, declkind: {decl.kind}')

    # If we don't have a declaration, we don't have a hash and can't cache the result.
    if decl.kind == CursorKind.NO_DECL_FOUND:
        found = get_stock_or_build_ida_type(type)
    else:
        # print(f'Type has declaration. kind: {decl.kind}, hash: {decl.hash}, displayname: {decl.displayname}, usr: {decl.get_usr()}, typename: {get_decl_name(decl)}, file: {decl.location.file}')
        found = visited.get(decl.hash) or define_ida_type(decl)

    if type.is_const_qualified():
        found = found.copy()
        found.set_const()

    return found


def define_ida_type(decl):
    tif = get_stock_or_build_ida_type(decl.type)
    visited[decl.hash] = tif
    return tif


def get_stock_or_build_ida_type(type):
    stock_type = handle_stock_type(type)

    return stock_type if stock_type != None else build_ida_type(type)


def build_ida_type(type):
    tif = type_handlers[type.kind](type)
    return tif


@TypeHandler(TypeKind.UNEXPOSED)
@TypeHandler(TypeKind.AUTO)
def handle_unexposed(type):
    can = type.get_canonical()
    if can != type:
        return get_ida_type(can)
    else:
        tif = idaapi.tinfo_t()
        tif.create_simple_type(BTF_VOID)
        return tif


@TypeHandler(TypeKind.ELABORATED)
def handle_elaborated(type):
    return get_ida_type(type.get_named_type())


@TypeHandler(TypeKind.VARIABLEARRAY)
@TypeHandler(TypeKind.CONSTANTARRAY)
@TypeHandler(TypeKind.VECTOR)
@TypeHandler(TypeKind.INCOMPLETEARRAY)
def handle_array(type):
    count = (
        0
        if type.kind in (TypeKind.VARIABLEARRAY, TypeKind.INCOMPLETEARRAY)
        else type.element_count
    )
    tif = idaapi.tinfo_t()
    tif.create_array(get_ida_type(type.element_type), count)
    return tif


@TypeHandler(TypeKind.BOOL)
@TypeHandler(TypeKind.FLOAT)
@TypeHandler(TypeKind.DOUBLE)
@TypeHandler(TypeKind.LONGDOUBLE)
@TypeHandler(TypeKind.CHAR_S)
@TypeHandler(TypeKind.CHAR_U)
@TypeHandler(TypeKind.SCHAR)
@TypeHandler(TypeKind.UCHAR)
@TypeHandler(TypeKind.WCHAR)
@TypeHandler(TypeKind.CHAR16)
@TypeHandler(TypeKind.CHAR32)
@TypeHandler(TypeKind.SHORT)
@TypeHandler(TypeKind.USHORT)
@TypeHandler(TypeKind.INT)
@TypeHandler(TypeKind.LONG)
@TypeHandler(TypeKind.LONGLONG)
@TypeHandler(TypeKind.UINT)
@TypeHandler(TypeKind.ULONG)
@TypeHandler(TypeKind.ULONGLONG)
@TypeHandler(TypeKind.INT128)
@TypeHandler(TypeKind.UINT128)
@TypeHandler(TypeKind.VOID)
@TypeHandler(TypeKind.INVALID)
def handle_simple_type(type):
    tif = idaapi.tinfo_t()
    tif.create_simple_type(simple_types[type.kind])
    return tif


@TypeHandler(TypeKind.FUNCTIONPROTO)
def handle_function_proto(type):
    return resolve_function(type)


@TypeHandler(TypeKind.POINTER)
@TypeHandler(TypeKind.LVALUEREFERENCE)
@TypeHandler(TypeKind.RVALUEREFERENCE)
def handle_pointer(type):
    pointee = type.get_pointee()
    pointee_type = get_ida_type(pointee)

    tif = idaapi.tinfo_t()
    tif.create_ptr(pointee_type)
    return tif


def is_multi_inherited_class(decl):
    base_decls = [
        member
        for member in decl.get_children()
        if member.kind == CursorKind.CXX_BASE_SPECIFIER
    ]
    if len(base_decls) == 0:
        return False
    if len(base_decls) > 1:
        return True
    return is_multi_inherited_class(base_decls[0])


@TypeHandler(TypeKind.MEMBERPOINTER)
def handle_member_pointer(type):
    class_type = type.get_class_type()
    ptr_tif = handle_pointer(type)

    if not is_multi_inherited_class(class_type.get_canonical().get_declaration()):
        return ptr_tif

    udt = idaapi.udt_type_data_t()

    ptr_member_udt = idaapi.udt_member_t()
    ptr_member_udt.name = "ptr"
    ptr_member_udt.offset = 0
    ptr_member_udt.type = ptr_tif
    udt.push_back(ptr_member_udt)

    adjustor_tif = idaapi.tinfo_t()
    adjustor_tif.create_simple_type(BTF_INT32)

    adjustor_member_udt = idaapi.udt_member_t()
    adjustor_member_udt.name = "adjustor"
    adjustor_member_udt.offset = 0
    adjustor_member_udt.type = adjustor_tif
    udt.push_back(adjustor_member_udt)

    udt.sda = 4
    udt.taudt_bits |= TAUDT_CPPOBJ

    tif = idaapi.tinfo_t()
    tif.create_udt(udt, BTF_STRUCT)
    return tif


@TypeHandler(TypeKind.TYPEDEF)
def handle_typedef(type):
    decl = type.get_declaration()
    decl_name = get_decl_name(decl)

    existing_tif = get_existing_tif(decl_name)
    canonical_type = type.get_canonical()
    canonical_decl = canonical_type.get_declaration()
    if (
        existing_tif
        and canonical_type.kind in (TypeKind.RECORD, TypeKind.ENUM)
        and canonical_decl.kind != CursorKind.NO_DECL_FOUND
    ):
        existing_canonical_tif = get_existing_tif(get_decl_name(canonical_decl))
        if existing_canonical_tif and is_same_odr_hash(
            canonical_decl, existing_canonical_tif
        ):
            if canonical_type.kind == TypeKind.RECORD:
                get_ida_type(canonical_type)
            return existing_tif

    origin_tif = get_ida_type(decl.underlying_typedef_type)
    existing_type_name = origin_tif.get_type_name()

    if existing_type_name == None:
        save_tinfo(origin_tif, decl_name)
        return origin_tif
    elif existing_type_name == decl_name:
        return origin_tif
    else:
        tif = idaapi.tinfo_t()
        tif.create_typedef(idati, existing_type_name)
        save_tinfo(tif, decl_name)
        return tif


def is_stock_function(ea):
    return (
        ida_name.get_name(ea).startswith("nullsub_")
        or ida_name.get_name(ea) == "pure_virtual_function"
        or ida_bytes.get_bytes(ea, 3) == b"\xb0\x01\xc3"
        or ida_bytes.get_bytes(ea, 3) == b"\x32\xc0\xc3"
    )


class VFunc:
    def __init__(self, class_tif):
        self.class_tif = class_tif
        self.parent_tif = None
        self.offset = 0

    def set_override(self, base_tif, offset):
        if offset != 0:
            self.parent_tif = self.class_tif
            self.class_tif = base_tif
            self.offset = offset

    def overrides(self, that):
        return (self.is_dtor() and that.is_dtor()) or (
            self.get_name() == that.get_name()
            and [t.get_canonical() for t in self.get_arguments()]
            == [t.get_canonical() for t in that.get_arguments()]
            and self.is_const_method() == that.is_const_method()
        )


class DeclVFunc(VFunc):
    def __init__(self, decl, class_tif):
        super().__init__(class_tif)
        self.decl = decl

    def is_dtor(self):
        return self.decl.kind == CursorKind.DESTRUCTOR

    def is_const_method(self):
        return self.decl.is_const_method()

    def get_name(self):
        return self.decl.spelling

    def get_mangled_name(self):
        return self.decl.mangled_name

    def get_arguments(self):
        return self.decl.type.argument_types()

    def get_tif(self):
        return resolve_function(
            self.decl.type, 0, self.class_tif, self.decl, self.offset, self.parent_tif
        )


class DefaultDtorVFunc(VFunc):
    def __init__(self, class_decl, class_tif):
        super().__init__(class_tif)
        self.class_decl = class_decl

    def is_dtor(self):
        return True

    def is_const_method(self):
        return False

    def get_name(self):
        return f"~{self.class_decl.spelling}"

    def get_mangled_name(self):
        mangled_vtable_name = self.class_decl.get_mangled_vtable_name([])
        mangled_class_name = mangled_vtable_name[4:-4]
        return f"??_D{mangled_class_name}@QEAAXXZ"

    def get_tif(self):
        data = idaapi.func_type_data_t()
        data.stkargs = 0
        data.cc = idaapi.CM_CC_FASTCALL

        ret_type = idaapi.tinfo_t()
        ret_type.create_simple_type(BTF_VOID)
        data.rettype = ret_type

        this_type = idaapi.tinfo_t()
        this_type.create_ptr(self.class_tif)

        this_funcarg = idaapi.funcarg_t()
        this_funcarg.name = "this"
        this_funcarg.type = this_type
        this_funcarg.flags = FAI_HIDDEN
        data.push_back(this_funcarg)

        flags_tif = idaapi.tinfo_t()
        flags_tif.create_simple_type(BTF_UINT32)

        flags_funcarg = idaapi.funcarg_t()
        flags_funcarg.name = "flags"
        flags_funcarg.type = flags_tif
        data.push_back(flags_funcarg)

        tif = idaapi.tinfo_t()
        tif.create_func(data)
        tif.get_func_details(data)  # TODO: what?

        return tif


def handle_union(type, type_updated, forward_tif):
    decl = type.get_declaration()
    decl_name = get_decl_name(decl)

    udt = idaapi.udt_type_data_t()
    udt.is_union = True
    udt.taudt_bits |= TAUDT_CPPOBJ

    for member in type.get_fields():
        member_udt = idaapi.udt_member_t()
        member_udt.name = member.spelling
        member_udt.offset = member.get_field_offsetof()
        member_udt.type = get_ida_type(member.type)
        udt.push_back(member_udt)

    if type_updated:
        tif = idaapi.tinfo_t()
        tif.create_udt(udt, BTF_UNION)
        if not decl.is_anonymous():
            save_tinfo(tif, decl_name)

        return tif
    else:
        return forward_tif


@TypeHandler(TypeKind.RECORD)
def handle_record(type):
    decl = type.get_declaration()
    type_updated = True
    forward_tif = None

    if not decl.is_anonymous():
        decl_name = get_decl_name(decl)
        existing_tif = get_existing_tif(decl_name)
        if existing_tif and is_same_odr_hash(decl, existing_tif):
            visited[decl.hash] = existing_tif
            forward_tif = existing_tif
            type_updated = False
        else:
            forward_tif = _create_forward_declaration(decl)
            set_tif_for_odr_hash(decl, forward_tif)

    if decl.kind == CursorKind.UNION_DECL:
        return handle_union(type, type_updated, forward_tif)

    process_cursor(decl)

    align = type.get_align()
    udt = idaapi.udt_type_data_t()
    if align > 1:
        udt.sda = calc_min_align(align)

    vtbl_infos = []
    is_root = False

    def create_vfunc(member):
        nonlocal is_root

        f = DeclVFunc(member, forward_tif)

        if len(vtbl_infos) == 0:
            is_root = True
            vtbl_infos.append(VTableInfo([], [], 0, forward_tif))

        for vtbl_info in vtbl_infos:
            for i, vtbl_member in enumerate(vtbl_info.members):
                if f.overrides(vtbl_member):
                    f.set_override(vtbl_info.unshifted_class_tif, vtbl_info.offset)
                    vtbl_info.members[i] = f
                    return

        vtbl_infos[0].members.append(f)

    def create_bases():
        delayed_base_udts = []
        offset = 0

        for member in decl.get_children():
            if member.kind == CursorKind.CXX_BASE_SPECIFIER:
                member_type = get_ida_type(member.type)
                member_decl = member.type.get_canonical().get_declaration()
                base_vtbl_infos = vtable_infos[member_decl.hash]

                member_udt = idaapi.udt_member_t()
                member_udt.name = member.spelling
                member_udt.type = member_type
                member_udt.set_baseclass()

                if len(base_vtbl_infos) == 0:
                    delayed_base_udts.append(member_udt)
                else:
                    for vtbl_info in base_vtbl_infos:
                        total_offset = vtbl_info.offset + offset
                        vtbl_infos.append(
                            VTableInfo(
                                (
                                    vtbl_info.base_path
                                    if offset == 0
                                    else [member_decl, *vtbl_info.base_path]
                                ),
                                vtbl_info.members,
                                total_offset,
                                (
                                    forward_tif
                                    if total_offset == 0
                                    else vtbl_info.unshifted_class_tif
                                ),
                            )
                        )

                    offset += member_type.get_size()

                    udt.push_back(member_udt)

        for base_udt in delayed_base_udts:
            udt.push_back(base_udt)

    def create_fields():
        for member in type.get_fields():
            member_udt = idaapi.udt_member_t()
            member_udt.name = (
                "____anonymous____" if member.spelling == "" else member.spelling
            )
            member_udt.offset = member.get_field_offsetof()
            member_udt.type = get_ida_type(member.type)
            udt.push_back(member_udt)

    def create_vtable_type(vtbl_info):
        vtbl_udt = idaapi.udt_type_data_t()
        vtbl_udt.taudt_bits |= TAUDT_VFTABLE

        for member in vtbl_info.members:
            method_ptr_tif = idaapi.tinfo_t()
            method_ptr_tif.create_ptr(member.get_tif())

            member_udt = idaapi.udt_member_t()
            member_udt.name = member.get_name()
            member_udt.type = method_ptr_tif

            vtbl_udt.push_back(member_udt)

        vtbl_tif = idaapi.tinfo_t()
        vtbl_tif.create_udt(vtbl_udt, BTF_STRUCT)
        vtbl_name = (
            f"{decl_name}_vtbl"
            if vtbl_info.offset == 0
            else f"{decl_name}_{vtbl_info.offset:04x}_vtbl"
        )
        save_tinfo(vtbl_tif, vtbl_name)

        return vtbl_tif

    def create_vtables():
        for member in decl.get_children():
            if (
                member.kind in (CursorKind.CXX_METHOD, CursorKind.DESTRUCTOR)
                and member.is_virtual_method()
            ):
                create_vfunc(member)

        # Create a default destructor if none was specified, we have vtables, and our primary base has a destructor.
        if len(vtbl_infos) > 0 and not any(
            map(
                lambda member: member.kind == CursorKind.DESTRUCTOR
                and member.is_virtual_method(),
                decl.get_children(),
            )
        ):
            for i, member in enumerate(vtbl_infos[0].members):
                if member.is_dtor():
                    vtbl_infos[0].members[i] = DefaultDtorVFunc(decl, forward_tif)
                    break

        for vtbl_info in vtbl_infos:
            if type_updated:
                vtbl_tif = create_vtable_type(vtbl_info)
            else:
                vtbl_tif = get_existing_tif(
                    f"{decl_name}_vtbl"
                    if vtbl_info.offset == 0
                    else f"{decl_name}_{vtbl_info.offset:04x}_vtbl"
                )

            mangled_vtable_name = decl.get_mangled_vtable_name(vtbl_info.base_path)
            print(f"Trying to set vtable name {mangled_vtable_name}")
            discover_sdk_name(mangled_vtable_name, vtbl_tif, type_updated)

            if vtbl_ea := get_alias_ea(mangled_vtable_name):
                for i, member in enumerate(vtbl_info.members):
                    vfunc_ea = ida_bytes.get_qword(vtbl_ea + 8 * i)

                    if not is_stock_function(vfunc_ea):
                        mangled_member_name = member.get_mangled_name()

                        try:
                            set_generated_func_name(
                                ensure_function(vfunc_ea),
                                mangled_member_name,
                                certain=True,
                                steal=True,
                            )
                        except AnalysisException:
                            set_generated_name(
                                vfunc_ea, mangled_member_name, certain=True, steal=True
                            )

                        discover_sdk_name(mangled_member_name, member.get_tif(), True)

            if is_root:
                vtbl_ptr_tif = idaapi.tinfo_t()
                vtbl_ptr_tif.create_ptr(vtbl_tif)

                vtbl_member_udt = idaapi.udt_member_t()
                vtbl_member_udt.name = "__vftable"
                vtbl_member_udt.set_vftable()
                vtbl_member_udt.type = vtbl_ptr_tif

                udt.insert(udt.begin(), vtbl_member_udt)

    def create_nonvirtual_methods():
        for member in decl.get_children():
            if (
                member.kind
                in (
                    CursorKind.CXX_METHOD,
                    CursorKind.CONSTRUCTOR,
                    CursorKind.DESTRUCTOR,
                )
                and not member.is_virtual_method()
            ):
                discover_sdk_name(
                    member.mangled_name,
                    resolve_function(
                        member.type,
                        0,
                        None if member.is_static_method() else forward_tif,
                        member,
                    ),
                    type_updated,
                )

    # if not type.is_pod():
    udt.taudt_bits |= TAUDT_CPPOBJ

    create_bases()
    create_fields()

    if not decl.is_anonymous():
        vtable_infos[decl.hash] = vtbl_infos

        create_vtables()

    if type_updated:
        tif = idaapi.tinfo_t()
        tif.create_udt(udt, BTF_STRUCT)
        if not decl.is_anonymous():
            save_tinfo(tif, decl_name)
    else:
        tif = forward_tif

    create_nonvirtual_methods()

    return tif


@TypeHandler(TypeKind.ENUM)
def handle_enum(type):
    decl = type.get_declaration()
    decl_name = get_decl_name(decl)
    is_scoped = decl.is_scoped_enum()

    existing_tif = get_existing_tif(decl_name)
    if existing_tif and is_same_odr_hash(decl, existing_tif):
        return existing_tif

    etd = enum_type_data_t(BTE_ALWAYS | (BTE_SIZE_MASK & (1 << type.get_size() - 1)))

    for member in decl.get_children():
        if member.kind == CursorKind.ENUM_CONSTANT_DECL:
            emt = enum_member_t()
            emt.name = (
                f"{decl_name}::{member.spelling}" if is_scoped else member.spelling
            )
            emt.value = member.enum_value

            etd.push_back(emt)

    tif = idaapi.tinfo_t()
    tif.create_enum(etd)
    save_tinfo(tif, decl_name)

    set_tif_for_odr_hash(decl, tif)

    return tif


@CursorHandler(CursorKind.TYPEDEF_DECL)
@CursorHandler(CursorKind.TYPE_ALIAS_DECL)
def handle_typedef_cursor(item):
    define_ida_type(item)


@CursorHandler(CursorKind.CLASS_DECL)
# @CursorHandler(CursorKind.CLASS_TEMPLATE)
@CursorHandler(CursorKind.STRUCT_DECL)
@CursorHandler(CursorKind.UNION_DECL)
@CursorHandler(CursorKind.ENUM_DECL)
def handle_struct(item):
    if item.is_definition():
        define_ida_type(item)
    elif definition := item.get_definition():
        _create_forward_declaration(definition)


@CursorHandler(CursorKind.FUNCTION_DECL)
@CursorHandler(CursorKind.VAR_DECL)
def typedefs(item):
    type = get_ida_type(item.type)

    discover_sdk_name(item.mangled_name, type, True)


@CursorHandler(CursorKind.NAMESPACE)
@CursorHandler(CursorKind.LINKAGE_SPEC)
@CursorHandler(CursorKind.UNEXPOSED_DECL)
def linkage(item):
    process_cursor(item)


def clear_ctx():
    visited.clear()
    vtable_infos.clear()
    saved.clear()


def parse_file(path, args=[]):
    index = Index.create()
    tx = index.parse(
        path,
        args,
        None,
        TranslationUnit.PARSE_SKIP_FUNCTION_BODIES | TranslationUnit.PARSE_INCOMPLETE,
    )

    if len(tx.diagnostics) != 0:
        for diagnostic in tx.diagnostics:
            print(f"diag: {diagnostic}")
    else:
        clear_ctx()
        known_mangled_names.clear()
        process_cursor(tx.cursor)
        # garbage_collect()
        clear_ctx()


def process_cursor(cursor):
    for item in cursor.get_children():
        if item.kind in cursor_handlers:
            # print(item.kind, item.spelling, item.mangled_name, item.hash, item.displayname, item.canonical.mangled_name, item.get_usr())
            cursor_handlers[item.kind](item)
        else:
            # print('unhandled', item.location.file.name, item.location.line, item.kind, item.spelling, item.mangled_name, item.hash, item.displayname, item.canonical.mangled_name, item.get_usr())
            continue


def run_sync():
    parse_file(
        os.path.join(API_LOCATION, "type-export-entry.cpp"),
        ["--std=c++20", f"-I{UCSL_LOCATION}/universal-cslib/src"],
    )


class ChooseSDKName(ida_kernwin.Choose):
    def __init__(self, names):
        self.names = names
        super().__init__(
            "Known names in SDK",
            [
                ["Short Name", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Full Name", 100 | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            ida_kernwin.Choose.CH_MODAL,
        )

    def OnGetSize(self):
        return len(self.names)

    def OnGetLine(self, n):
        name = self.names[n].name

        short_demangled_name = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
        full_name = ida_name.demangle_name(name, 0) or name

        if not short_demangled_name or not full_name:
            return [name, name]

        return [short_demangled_name, full_name]


def apply_sdk_name(ea):
    names = [
        *known_mangled_names
    ]  # intentional copy to remain consistent even if the known mangled names somehow change
    choice = ida_kernwin.choose_choose(ChooseSDKName(names))

    if choice != -1:
        known = names[choice]

        func = ida_funcs.get_func(ea)

        if func:
            try:
                thunk = require_thunk(func)
                set_generated_func_name(thunk, known.name, certain=True)
            except AnalysisException:
                set_generated_name(ea, known.name, certain=True)
        else:
            set_generated_name(ea, known.name, certain=True)

        apply_type_to_name(known.name, known.tif)


class ChooseAlias(ida_kernwin.Choose):
    def __init__(self, aliases, ea):
        self.aliases = aliases
        self.ea = ea
        super().__init__(
            "Aliases",
            [
                ["Short Name", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Full Name", 100 | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            ida_kernwin.Choose.CH_MODAL
            | ida_kernwin.Choose.CH_NOBTNS
            | ida_kernwin.Choose.CH_CAN_DEL,
        )

    def OnGetSize(self):
        return len(self.aliases)

    def OnGetLine(self, n):
        alias = self.aliases[n]

        short_demangled_name = ida_name.demangle_name(alias, ida_name.MNG_SHORT_FORM)
        full_name = ida_name.demangle_name(alias, 0) or alias

        if not short_demangled_name or not full_name:
            return [alias, alias]

        return [short_demangled_name, full_name]

    def OnDeleteLine(self, sel):
        alias = self.aliases[sel]
        remove_alias(self.ea, alias)
        self.aliases.remove(alias)
        return True, None


def view_aliases(ea):
    aliases = [alias for alias, idx in [*get_aliases(ea)]]
    ida_kernwin.choose_choose(ChooseAlias(aliases, ea))


class ChooseAliasList(ida_kernwin.Choose):
    def __init__(self, aliases):
        self.aliases = aliases
        super().__init__(
            "Alias list",
            [
                ["Address", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Short Name", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Full Name", 100 | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            ida_kernwin.Choose.CH_MULTI
            | ida_kernwin.Choose.CH_NOBTNS
            | ida_kernwin.Choose.CH_CAN_DEL,
        )

    def OnGetSize(self):
        return len(self.aliases)

    def OnGetLine(self, n):
        ea, alias = self.aliases[n]

        short_demangled_name = ida_name.demangle_name(alias, ida_name.MNG_SHORT_FORM)
        full_name = ida_name.demangle_name(alias, 0) or alias

        if not short_demangled_name or not full_name:
            return [f"{ea:x}", alias, alias]

        return [f"{ea:x}", short_demangled_name, full_name]

    def OnDeleteLine(self, msel):
        alias_sel = [self.aliases[sel] for sel in msel]
        for a in alias_sel:
            ea, alias = a
            remove_alias(ea, alias)
            self.aliases.remove(a)
        return [ida_kernwin.Choose.ALL_CHANGED]


def open_alias_list():
    aliases = [*get_all_aliases()]
    ida_kernwin.choose_choose(ChooseAliasList(aliases))


def generate_thunks():
    image_base = ida_nalt.get_imagebase()

    f = open(os.path.join(API_LOCATION, "src", "thunks.asm"), "w")
    f.write(
        f"""
.data
    moduleOffset dq 0

.code

PUBLIC {rangers_analysis_config['sdk_prefix']}_GetAddress
{rangers_analysis_config['sdk_prefix']}_GetAddress:
    mov rax, qword ptr [rcx+2]
    ret

"""
    )
    for main_name, ea in nlist_names():
        for name, idx in get_aliases(ea):
            demangled = ida_name.demangle_name(name, 0)
            if (
                len(name) > 200
                or name.startswith("j_")
                or name.startswith("??_7")
                or name.startswith("??_R")
                or name.startswith("??__E")
                or name.startswith("??__F")
                or not demangled
            ):
                continue
            # func = ida_funcs.get_func(ea)
            # if not func or func.flags & ida_funcs.FUNC_THUNK or func.start_ea != ea:
            #     continue

            f.write(
                f"""
PUBLIC {name}
{name}:
    mov rax, 0{ea:x}h
    jmp rax
"""
            )

    f.write("end\n")
    f.close()


def generate_address_list():
    with open(os.path.join(API_LOCATION, "addresses.csv"), "w", newline="") as f:
        csvw = csv.writer(f)

        for main_name, ea in nlist_names():
            for name, idx in get_aliases(ea):
                demangled = ida_name.demangle_name(name, 0)
                if name not in ("atexit", "singletonList") and not demangled:
                    continue

                csvw.writerow([f"{ea:x}", name, int(has_user_name(get_flags(ea)))])


def import_address_list():
    with open(os.path.join(API_LOCATION, "addresses.csv"), "r", newline="") as f:
        for row in csv.reader(f):
            set_generated_name(int(row[0], 16), row[1], certain=int(row[2]) == 1)


def get_right_click_target_ea(ctx):
    print(f"{ctx.cur_value:x}, {ctx.cur_extracted_ea:x}, {ctx.cur_ea:x}")
    if ida_segment.getseg(ctx.cur_value):
        return ctx.cur_value
    elif ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
        if not ctx.cur_value == BADADDR:
            vdui = ida_hexrays.get_widget_vdui(ctx.widget)
            treeitem = vdui.cfunc.treeitems.at(ctx.cur_value)
            if treeitem.is_expr() and treeitem.cexpr.obj_ea != BADADDR:
                return treeitem.cexpr.obj_ea
        elif (
            ctx.cur_ea != BADADDR
            and ida_funcs.get_func(ctx.cur_ea)
            and ida_funcs.get_func(ctx.cur_ea).start_ea == ctx.cur_ea
        ):
            return ctx.cur_ea

    print("invalid target")


def get_typeinf_targets(ctx):
    for i in ctx.chooser_selection:
        yield int(ida_kernwin.get_chooser_data(ctx.widget_title, i)[0])


class CPPParserActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, cpp_parser):
        super().__init__()
        self.cpp_parser = cpp_parser


class ApplySDKNameActionHandler(CPPParserActionHandler):
    def activate(self, ctx):
        if target := get_right_click_target_ea(ctx):
            apply_sdk_name(target)

        ida_kernwin.update_action_state(
            "cppparser:apply-sdk-name", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class ViewAliasesActionHandler(CPPParserActionHandler):
    def activate(self, ctx):
        if target := get_right_click_target_ea(ctx):
            view_aliases(target)

        ida_kernwin.update_action_state(
            "cppparser:view-aliases", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class ClearCacheActionHandler(CPPParserActionHandler):
    def activate(self, ctx):
        for i in get_typeinf_targets(ctx):
            invalidate_odr_hash_by_ordinal(i)

        ida_kernwin.update_action_state(
            "cppparser:clear-cache", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class ClearCacheActionHandler(CPPParserActionHandler):
    def activate(self, ctx):
        for i in get_typeinf_targets(ctx):
            invalidate_odr_hash_by_ordinal(i)

        ida_kernwin.update_action_state(
            "cppparser:clear-whole-cache", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class SyncHandler(CPPParserActionHandler):
    def activate(self, ctx):
        run_sync()
        ida_kernwin.update_action_state("cppparser:sync", ida_kernwin.AST_ENABLE_ALWAYS)
        return 0


class GenerateThunksHandler(CPPParserActionHandler):
    def activate(self, ctx):
        generate_thunks()
        generate_address_list()
        ida_kernwin.update_action_state(
            "cppparser:generate-thunks", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class ImportAddressesHandler(CPPParserActionHandler):
    def activate(self, ctx):
        import_address_list()
        ida_kernwin.update_action_state(
            "cppparser:import-addresses", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class AliasListActionHandler(CPPParserActionHandler):
    def activate(self, ctx):
        open_alias_list()
        ida_kernwin.update_action_state(
            "cppparser:alias-list", ida_kernwin.AST_ENABLE_ALWAYS
        )
        return 0


class CPPParserUIHooks(ida_kernwin.UI_Hooks):
    def populating_widget_popup(self, widget, popup_handle, ctx):
        if ctx.widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle, "cppparser:apply-sdk-name"
            )
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle, "cppparser:view-aliases"
            )
        if ctx.widget_type == ida_kernwin.BWN_LOCTYPS:
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle, "cppparser:clear-cache"
            )


class CPPParser:
    def __init__(self):
        sync_action = ida_kernwin.action_desc_t(
            "cppparser:sync", "Load SDK types", SyncHandler(self)
        )
        ida_kernwin.register_action(sync_action)
        ida_kernwin.update_action_state("cppparser:sync", ida_kernwin.AST_ENABLE_ALWAYS)

        generate_thunks_action = ida_kernwin.action_desc_t(
            "cppparser:generate-thunks", "Generate thunks", GenerateThunksHandler(self)
        )
        ida_kernwin.register_action(generate_thunks_action)
        ida_kernwin.update_action_state(
            "cppparser:generate-thunks", ida_kernwin.AST_ENABLE_ALWAYS
        )

        generate_thunks_action = ida_kernwin.action_desc_t(
            "cppparser:import-addresses",
            "Import addresses from CSV",
            ImportAddressesHandler(self),
        )
        ida_kernwin.register_action(generate_thunks_action)
        ida_kernwin.update_action_state(
            "cppparser:import-addresses", ida_kernwin.AST_ENABLE_ALWAYS
        )

        view_aliases_action = ida_kernwin.action_desc_t(
            "cppparser:alias-list", "Alias list", AliasListActionHandler(self)
        )
        ida_kernwin.register_action(view_aliases_action)
        ida_kernwin.update_action_state(
            "cppparser:alias-list", ida_kernwin.AST_ENABLE_ALWAYS
        )

        apply_sdk_name_action = ida_kernwin.action_desc_t(
            "cppparser:apply-sdk-name",
            "Apply SDK name...",
            ApplySDKNameActionHandler(self),
        )
        ida_kernwin.register_action(apply_sdk_name_action)
        ida_kernwin.update_action_state(
            "cppparser:apply-sdk-name", ida_kernwin.AST_ENABLE_ALWAYS
        )

        view_aliases_action = ida_kernwin.action_desc_t(
            "cppparser:view-aliases", "SDK aliases...", ViewAliasesActionHandler(self)
        )
        ida_kernwin.register_action(view_aliases_action)
        ida_kernwin.update_action_state(
            "cppparser:view-aliases", ida_kernwin.AST_ENABLE_ALWAYS
        )

        view_aliases_action = ida_kernwin.action_desc_t(
            "cppparser:clear-cache",
            "Clear SDK type cache",
            ClearCacheActionHandler(self),
        )
        ida_kernwin.register_action(view_aliases_action)
        ida_kernwin.update_action_state(
            "cppparser:clear-cache", ida_kernwin.AST_ENABLE_ALWAYS
        )

        ida_kernwin.create_toolbar("cppparser", "CPP Parser")

        ida_kernwin.attach_action_to_toolbar("cppparser", "cppparser:sync")
        ida_kernwin.attach_action_to_toolbar("cppparser", "cppparser:generate-thunks")
        ida_kernwin.attach_action_to_toolbar("cppparser", "cppparser:import-addresses")
        ida_kernwin.attach_action_to_toolbar("cppparser", "cppparser:alias-list")

        self.ui_hooks = CPPParserUIHooks()
        self.ui_hooks.hook()
        # global apply_sdk_name_hk
        # apply_sdk_name_hk = ida_kernwin.add_hotkey('Shift+N', apply_sdk_name)

    def dispose(self):
        self.ui_hooks.unhook()
        # ida_kernwin.del_hotkey(apply_sdk_name_hk)

        ida_kernwin.detach_action_from_toolbar("cppparser", "cppparser:alias-list")
        ida_kernwin.detach_action_from_toolbar(
            "cppparser", "cppparser:import-addresses"
        )
        ida_kernwin.detach_action_from_toolbar("cppparser", "cppparser:generate-thunks")
        ida_kernwin.detach_action_from_toolbar("cppparser", "cppparser:sync")

        ida_kernwin.delete_toolbar("cppparser")

        ida_kernwin.unregister_action("cppparser:clear-cache")
        ida_kernwin.unregister_action("cppparser:view-aliases")
        ida_kernwin.unregister_action("cppparser:apply-sdk-name")
        ida_kernwin.unregister_action("cppparser:alias-list")
        ida_kernwin.unregister_action("cppparser:import-addresses")
        ida_kernwin.unregister_action("cppparser:generate-thunks")
        ida_kernwin.unregister_action("cppparser:sync")


try:
    cppparser
    try:
        cppparser.dispose()
        del cppparser
        print("cpp parser unregistered")
    except Exception as err:
        print(str(err))
except:
    cppparser = CPPParser()
    print("cpp parser installed")
