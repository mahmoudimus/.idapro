r"""
execfile('<path>/cxxparser.py')
parse_file('<path>/a.cpp',[r'-I<path>\LuaJIT-2.0.5\src', '-D__NT__', '-D__X64__', '-D__EA64__'])
parse_file('<path>/malloc.c',['-target=x86_64-linux-gnu'])
Originally from: https://gist.github.com/Jinmo/5f131a8bf3335f747e0ae7d6d6b881a4
Modified by Mahmoud Abdelkader @ https://gist.github.com/mahmoudimus/d16aa9ed85053fc4b7e46a2d37203b21
"""

import re
import sys
from functools import reduce

from clang.cindex import (
    BaseEnumeration,
    CursorKind,
    Index,
    TranslationUnit,
    TypeKind,
    conf,
)

# only import idapro if we're not running in ida
if not any(sys.executable.endswith(x) for x in ["ida.exe", "ida64.exe"]):
    import idapro

import idaapi


class _ParserConfig:
    RAISE_ON_UNKNOWN_TYPE = False


class CallingConv(BaseEnumeration):
    """Describes the calling convention of a function."""

    Default = 0
    C = 1
    X86StdCall = 2
    X86FastCall = 3
    X86ThisCall = 4
    X86Pascal = 5
    AAPCS = 6
    AAPCS_VFP = 7
    X86RegCall = 8
    IntelOclBicc = 9
    Win64 = 10
    X86_64Win64 = Win64
    X86_64SysV = 11
    X86VectorCall = 12
    Swift = 13
    PreserveMost = 14
    PreserveAll = 15
    AArch64VectorCall = 16
    Invalid = 100
    Unexposed = 200

    _kinds = []
    _name_map = None


handlers = {}


idati = idaapi.get_idati()
# idati = idaapi.til_t()


if idaapi.BADADDR == 2**64 - 1:
    FF_POINTER = idaapi.FF_QWORD
    POINTER_SIZE = 8

else:
    FF_POINTER = idaapi.FF_DWORD
    POINTER_SIZE = 4


def preprocess(dict):
    result = {}
    for key, (ida_type, _string) in dict.items():
        if _string is None:
            _sv = _string
        elif _string != "void":
            tinfo = idaapi.tinfo_t(_string)
            _sv = tinfo.get_decltype()
        else:
            _sv = b"\x01"
        result[key] = (ida_type & 0xFFFFFFFF, _sv)
    return result


def _size_to_flags(size):
    return {
        1: idaapi.FF_BYTE,
        2: idaapi.FF_WORD,
        4: idaapi.FF_DWORD,
        8: idaapi.FF_QWORD,
    }[size]


builtin_types = preprocess(
    {
        TypeKind.RECORD: (idaapi.FF_STRUCT, None),
        TypeKind.ENUM: (idaapi.FF_DWORD, "int"),
        TypeKind.BOOL: (_size_to_flags(idati.cc.size_b), "bool"),
        TypeKind.DOUBLE: (idaapi.FF_DOUBLE, "double"),
        TypeKind.LONGDOUBLE: (idaapi.FF_DOUBLE, "double"),
        TypeKind.FLOAT: (idaapi.FF_FLOAT, "float"),
        TypeKind.WCHAR: (idaapi.FF_WORD, "unsigned short"),
        TypeKind.CHAR16: (idaapi.FF_WORD, "unsigned short"),
        TypeKind.CHAR32: (idaapi.FF_DWORD, "unsigned int"),
        TypeKind.SHORT: (_size_to_flags(idati.cc.size_s), "short"),
        TypeKind.USHORT: (_size_to_flags(idati.cc.size_s), "unsigned short"),
        TypeKind.INT: (_size_to_flags(idati.cc.size_i), "int"),
        TypeKind.LONG: (_size_to_flags(idati.cc.size_l), "long"),
        TypeKind.LONGLONG: (_size_to_flags(idati.cc.size_ll), "long long"),
        TypeKind.UINT: (_size_to_flags(idati.cc.size_i), "unsigned int"),
        TypeKind.ULONG: (_size_to_flags(idati.cc.size_l), "unsigned long"),
        TypeKind.ULONGLONG: (_size_to_flags(idati.cc.size_ll), "unsigned long long"),
        TypeKind.CHAR_S: (idaapi.FF_BYTE, "signed char"),
        TypeKind.CHAR_U: (idaapi.FF_BYTE, "unsigned char"),
        TypeKind.SCHAR: (idaapi.FF_BYTE, "signed char"),
        TypeKind.UCHAR: (idaapi.FF_BYTE, "unsigned char"),
        TypeKind.INT128: (idaapi.FF_OWORD, "__int128"),
        TypeKind.UINT128: (idaapi.FF_OWORD, "unsigned __int128"),
        TypeKind.VOID: (idaapi.FF_0VOID, "void"),
        TypeKind.POINTER: (idaapi.FF_0OFF | FF_POINTER, None),
        TypeKind.LVALUEREFERENCE: (idaapi.FF_0OFF | FF_POINTER, None),
    }
)

callingconv_map = {
    CallingConv.C: idaapi.CM_CC_CDECL,
    CallingConv.X86FastCall: idaapi.CM_CC_FASTCALL,
    CallingConv.X86ThisCall: idaapi.CM_CC_THISCALL,
    CallingConv.X86StdCall: idaapi.CM_CC_STDCALL,
    CallingConv.X86Pascal: idaapi.CM_CC_PASCAL,
}

visited = dict()
virtuals_mapping = dict()


def handle(kind):
    def decorator(f):
        handlers[kind] = f
        return f

    return decorator


@handle(CursorKind.ENUM_DECL)
def handle_enum(item, context):
    members = []
    for member in item.get_children():
        members.append((member.spelling, member.enum_value))
    enum_id = idaapi.add_enum(idaapi.BADADDR, item.spelling, 0)
    for name, value in members:
        idaapi.add_enum_member(enum_id, name, value, -1)


class Struct:
    def __init__(self, name, is_union, flags=0):
        self.is_union = is_union

        self.ti = idaapi.tinfo_t()
        self.udt = idaapi.udt_type_data_t()
        self.udt.taudt_bits = flags

        self.name = name
        self.save(True)

    def add_member(self, name, offset, flag, size, tif):
        member = idaapi.udt_member_t()
        member.offset = offset
        member.name = name
        member.size = size
        member.type = tif

        if name.endswith("_vftable"):
            member.set_vftable()

        self.udt.push_back(member)

    def set_align(self, align):
        self.udt.effalign = align

    def save(self, replace=True):
        name = self.name

        while True:
            self.ti.create_udt(
                self.udt, idaapi.BTF_STRUCT if not self.is_union else idaapi.BTF_UNION
            )

            res = self.ti.set_named_type(
                idati, name, idaapi.NTF_REPLACE if replace else 0
            )
            if res == idaapi.TERR_OK:
                break
            elif res == idaapi.TERR_SAVE:  # name conflict
                assert replace == False, "?!"
                name = "_" + name
            elif res == idaapi.TERR_WRONGNAME:
                raise Exception("not allowed name: %r" % name)

        self.name = name
        return self.ti


def is_primitive(kind):
    if kind not in builtin_types:
        return False
    return builtin_types[kind][1]


def resolve_pointer(type, context):
    tif = idaapi.tinfo_t()
    pointee = type.get_pointee()
    _register_type(pointee, context)
    pointee_type = idaapi.tinfo_t()

    if pointee.kind in (TypeKind.UNEXPOSED,):
        pointee = pointee.get_canonical()
    if pointee.kind in (
        TypeKind.TYPEDEF,
        TypeKind.POINTER,
        TypeKind.LVALUEREFERENCE,
        TypeKind.ELABORATED,
    ):
        pointee_type = _register_type(pointee, context)
    elif pointee.kind == TypeKind.INVALID:
        pointee_type.deserialize(idati, builtin_types[TypeKind.VOID][1], b"")
    elif pointee.kind == TypeKind.FUNCTIONPROTO or is_primitive(pointee.kind):
        pointee_type = _register_type(pointee, context)
    else:
        name = pointee.spelling

        if not context.resolve(
            name, lambda name: pointee_type.get_named_type(idati, name)
        ):
            pointee_type.create_forward_decl(idati, idaapi.BTF_STRUCT, name)
    if pointee_type is None:
        pointee_type = idaapi.tinfo_t()
        assert pointee_type.create_forward_decl(
            idati, idaapi.BTF_STRUCT, pointee.spelling
        )
    tif.create_ptr(pointee_type)
    return tif


def _make_vtable(name, virtuals, context):
    # Creates a special struct(record) for vtable
    class FakeType(object):
        def __init__(self, kind, spelling, size=POINTER_SIZE, pointee=None):
            self.kind = kind
            self.spelling = spelling
            self.size = size
            self.pointee = pointee

        def get_size(self):
            return self.size

        def get_canonical(self):
            return self

        def get_pointee(self):
            return self.pointee

    vtable_name = "%s_vftable" % (name)

    struct = Struct(vtable_name, False, idaapi.TAUDT_VFTABLE)

    for i, func in enumerate(virtuals):
        size = POINTER_SIZE
        flag = FF_POINTER | idaapi.FF_0OFF
        member_name = "%s" % (func.spelling)

        tif = resolve_function(func.type, context, class_=name)
        tif.create_ptr(tif)

        struct.add_member(member_name, i * POINTER_SIZE, flag, size, tif)

    visited[vtable_name] = {"bases": [], "is_typedef": False, "resolved": None}

    struct.save()

    return FakeType(
        TypeKind.POINTER,
        vtable_name + " *",
        pointee=FakeType(TypeKind.RECORD, vtable_name),
    )


def resolve_function(type, context, flags=0, class_=None):
    func = idaapi.tinfo_t()
    data = idaapi.func_type_data_t()
    data.flags = flags
    data.rettype = _register_type(type.get_result(), context)
    data.stkargs = 0
    data.spoiled.clear()
    data.clear()
    cc = CallingConv.from_id(conf.lib.clang_getFunctionTypeCallingConv(type))
    # ida only supports cdecl + ellipsis when varargs exists
    if type.is_function_variadic():
        data.cc = idaapi.CM_CC_ELLIPSIS
    elif class_:
        # you can use one of these
        data.cc = idaapi.CM_CC_THISCALL
        # data.cc = idaapi.CM_CC_FASTCALL
    else:
        data.cc = callingconv_map.get(cc, idaapi.CM_CC_CDECL)
    if class_:
        funcarg = idaapi.funcarg_t()
        class_type_ = _create_forward_declaration(class_)
        class_type_.create_ptr(class_type_)
        funcarg.type = class_type_
        data.push_back(funcarg)
    for argument in type.argument_types():
        funcarg = idaapi.funcarg_t()
        funcarg.type = _register_type(argument, context)
        data.push_back(funcarg)
    func.create_func(data)
    func.get_func_details(data)
    return func


def _create_forward_declaration(typename):
    tif = idaapi.tinfo_t()
    if tif.get_named_type(idati, typename):
        return tif
    tif.create_forward_decl(idati, idaapi.BTF_STRUCT, typename)
    return tif


def _register_type(type, context, bases=[], virtuals=[]):
    global debug

    typename = context.name(type.spelling)
    found = visited.get(typename)
    if found:
        return found["resolved"]

    result = {
        "bases": bases,
        "is_typedef": type.kind == TypeKind.TYPEDEF,
        "resolved": None,
    }

    if type.kind == TypeKind.UNEXPOSED:
        type = type.get_canonical()

    if type.kind not in (TypeKind.TYPEDEF, TypeKind.ELABORATED):
        visited[typename] = result

    if type.kind == TypeKind.ELABORATED:
        result["resolved"] = tif = idaapi.tinfo_t()
        tif.create_typedef(idati, typename, idaapi.BTF_STRUCT)
        visited[typename] = result
        return tif

    if type.kind == TypeKind.VARIABLEARRAY:
        tif = idaapi.tinfo_t()
        tif.create_ptr(_register_type(type.element_type, context))
        result["resolved"] = tif
        return tif

    if type.kind in (TypeKind.CONSTANTARRAY, TypeKind.VECTOR, TypeKind.INCOMPLETEARRAY):
        count = type.element_count if type.kind != TypeKind.INCOMPLETEARRAY else 1
        tif = idaapi.tinfo_t()
        debug = type
        tif.create_array(_register_type(type.element_type, context), count)
        result["resolved"] = tif
        return tif

    if is_primitive(type.kind):
        tif = idaapi.tinfo_t()
        assert tif.deserialize(idati, builtin_types[type.kind][1], b"")
        result["resolved"] = tif
        return tif

    if type.kind == TypeKind.FUNCTIONPROTO:
        result["resolved"] = tif = resolve_function(type, context)
        return tif

    if type.kind in (TypeKind.POINTER, TypeKind.LVALUEREFERENCE):
        result["resolved"] = tif = resolve_pointer(type, context)
        return tif

    if type.kind == TypeKind.TYPEDEF:
        canonical = type.get_canonical()
        original = canonical.spelling
        # if original == typename:
        #     del visited[typename]
        tif = _register_type(canonical, context)
        if original != typename and tif:
            tif.set_named_type(idati, typename, idaapi.NTF_TYPE)
            result["resolved"] = tif
            visited[typename] = result

            origkey = typename.split("<")[0]
            target = canonical.spelling.split("<")[0]
            if target in virtuals_mapping:
                virtuals_mapping[origkey] = virtuals_mapping[target]

            return tif
        else:
            debug = type
            return tif
    if type.kind == TypeKind.RECORD:
        align = type.get_align()
        item = type
        unique_sizes = set(x.get_field_offsetof() for x in type.get_fields())
        if len(unique_sizes) == 1 and list(unique_sizes)[0] == -2:
            is_union = False
            should_guess = True
        else:
            is_union = len(unique_sizes) == 1 and len(list(type.get_fields())) != 1
            should_guess = False
        if item.get_size() == -2:
            # forward declaration
            tif = _create_forward_declaration(typename)
            del visited[typename]
            result["resolved"] = tif
            return tif
        members = []
        offset = 0
        # populate_bases(members, base)
        delta = 0
        has_virtuals = False
        for i, base in enumerate(bases):
            base_type = base.type
            base_size = base.type.get_size()
            base_align = base.type.get_align()
            if virtuals_mapping[context.name(base_type.spelling.split("<")[0])]:
                has_virtuals = True
        has_virtuals = has_virtuals or len(virtuals)
        for i, base in enumerate(bases):
            base_type = base.type
            base_size = base.type.get_size()
            base_align = base.type.get_align()
            base_virtuals = virtuals_mapping[
                context.name(base_type.spelling.split("<")[0])
            ]
            vtable_delta = (
                POINTER_SIZE if has_virtuals and not base_virtuals and i == 0 else 0
            )
            for member in base_type.get_fields():
                # If has virtuals and not first, we should substract vtable pointer size
                members.append(
                    (
                        vtable_delta * 8
                        + offset
                        + member.get_field_offsetof()
                        - delta * 8,
                        member.type,
                        "base%d_%s" % (i, member.spelling),
                    )
                )
                print(delta, offset // 8, member.get_field_offsetof() // 8)
            if i:
                members.insert(
                    0,
                    (
                        offset,
                        _make_vtable(
                            context.name(base.spelling), base_virtuals, context
                        ),
                        "base%d__vftable" % i,
                    ),
                )
            _register_type(base_type, context)
            offset += (base_size + base_align - 1) // base_align * base_align * 8
            if not i:
                virtuals = base_virtuals + virtuals

        __visited = set()
        virtuals = [
            x
            for x in virtuals
            if (x.spelling, x.type.spelling) not in __visited
            and (__visited.add((x.spelling, x.type.spelling)) or True)
        ]

        if virtuals:
            members.insert(
                0, (0, _make_vtable(typename, virtuals, context), "__vftable")
            )

        virtuals_mapping[typename] = virtuals

        for member in item.get_fields():
            if member.is_bitfield():
                continue
            if member.kind == CursorKind.FIELD_DECL:
                members.append(
                    (member.get_field_offsetof(), member.type, member.spelling)
                )
            else:
                continue

        struc = Struct(typename, is_union, idaapi.TAUDT_CPPOBJ if virtuals else 0)
        struc.set_align(align.bit_length() - 1)

        for offset, type, name_ in members:
            size = type.get_size()
            if not name_:
                name_ = "__offset%x" % (offset >> 3)
            if size < 0:
                if type.kind == TypeKind.INCOMPLETEARRAY:
                    # later fixed to array
                    size = type.element_type.get_size()
                else:
                    print(type)
                    if _ParserConfig.RAISE_ON_UNKNOWN_TYPE:
                        raise Exception("Unknown type: %s" % type)
                    continue
            flag = 0
            canonical = type.get_canonical()
            tif = None
            if canonical.kind == TypeKind.RECORD:
                tif = _register_type(canonical, context)
            elif canonical.kind in (TypeKind.POINTER, TypeKind.LVALUEREFERENCE):
                tif = resolve_pointer(canonical, context)
            else:
                if canonical.kind in builtin_types:
                    flag |= builtin_types[canonical.kind][0]
                tif = _register_type(canonical, context)

            if offset % 8:
                continue

            res = struc.add_member(name_, offset >> 3, flag, size, tif)

        tif = result["resolved"] = struc.save()
        return tif


@handle(CursorKind.CLASS_DECL)
@handle(CursorKind.CLASS_TEMPLATE)
@handle(CursorKind.STRUCT_DECL)
@handle(CursorKind.UNION_DECL)
def handle_struct(item, context):
    # Is there any way to check if it's forward declaration or not?
    if len(list(item.get_children())) == 0 and item.type.get_size() > 1:
        # forward class/struct declaration
        return
    bases = []
    virtuals = []
    virtuals_mapping[context.name(item.spelling)] = virtuals
    for member in item.get_children():
        if member.kind == CursorKind.CXX_BASE_SPECIFIER:
            bases.append(member)
        elif member.kind in (
            CursorKind.CXX_METHOD,
            CursorKind.DESTRUCTOR,
            CursorKind.CONSTRUCTOR,
        ):
            if member.is_virtual_method():
                virtuals.append(member)
    _register_type(item.type, context, bases, virtuals)


@handle(CursorKind.TYPEDEF_DECL)
@handle(CursorKind.TYPE_ALIAS_DECL)
@handle(CursorKind.FUNCTION_DECL)
@handle(CursorKind.VAR_DECL)
def typedefs(item, context):
    type = _register_type(item.type, context)
    if item.kind in (CursorKind.FUNCTION_DECL, CursorKind.VAR_DECL):
        address = idaapi.get_name_ea_simple(item.spelling)
        if address != idaapi.BADADDR:
            res = idaapi.apply_tinfo(
                address, type, idaapi.TINFO_DELAYFUNC | idaapi.TINFO_DEFINITE
            )


@handle(CursorKind.NAMESPACE)
def namespace(item, context):
    process_cursor(item, context.nest_namespace(item.spelling))


@handle(CursorKind.LINKAGE_SPEC)
@handle(CursorKind.UNEXPOSED_DECL)
def linkage(item, context):
    process_cursor(item, context)


def parse_file(path, args=[]):
    parse_file_with_settings(path, _ParserConfig, args)


def parse_file_with_settings(path, opts, args=[]):
    index = Index.create()
    tx = index.parse(path, args)
    if idaapi.BADADDR == 2**64 - 1:
        args.insert(0, "-m64")
    else:
        args.insert(0, "-m32")

    process_cursor(tx.cursor)


def parse_ast(path, args=[]):
    index = Index.create()
    tx = TranslationUnit.from_ast_file(path, index)
    if idaapi.BADADDR == 2**64 - 1:
        args.insert(0, "-m64")
    else:
        args.insert(0, "-m32")

    process_cursor(tx.cursor)


class Context(object):
    def __init__(self, namespaces=[]):
        self.namespaces = namespaces

    def nest_namespace(self, namespace):
        return Context(namespaces=self.namespaces + [namespace])

    def name(self, name):
        return Context._generate_name(name, self.namespaces)

    @staticmethod
    def _generate_name(name, namespaces):
        name = re.sub("^(const |volatile |struct |union |class )+", "", name)
        name = re.sub(r"[^a-zA-Z0-9:<>=]", "_", name)
        if not namespaces:
            return name
        prefix = "::".join(namespaces) + "::"
        if name.startswith(prefix):
            return name
        return "%s%s" % (prefix, name)

    def resolve(self, name, predicate):
        return reduce(
            lambda acc, item: acc or predicate(Context._generate_name(name, item)),
            (self.namespaces[:-i] for i in range(len(self.namespaces) + 1)),
            False,
        )


def process_cursor(cursor, context=None):
    if context is None:
        context = Context()
    for item in cursor.get_children():
        print(item.location.file.name, item.location.line, item.kind, item.spelling)
        if item.kind in handlers:
            handlers[item.kind](item, context)
        else:
            continue
