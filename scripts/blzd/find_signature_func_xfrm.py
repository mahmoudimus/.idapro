import base64
import re

import ida_bytes
import ida_nalt
import ida_typeinf
import idaapi
import idc

CONSTANTS = [
    0x12910FDC6A1EEB2B,
    0x5173E4B8939061E5,
    0xBF13E7AC,
]

PATTERNS = [
    "44 ?? ?? ?? ?? ?? ?? 48 B8 2B EB 1E 6A DC 0F 91 12 48 89 85 ?? ?? ?? ?? 4C ??",
    "48 ?? ?? ?? ?? 48 B8 E5 61 90 93 B8 E4 73 51 48 ?? ??",
    "B8 AC E7 13 BF 4C ?? ?? ?? ?? 48 ?? ?? ?? ??",
]

ENCODED_MANGLED_NAME = base64.b64decode(
    b"P0V4ZWN1dGVOdGhUaW1lSW1wbF8xNUBAWUFfTlha"
).decode("utf-8")


def get_max_address():
    max_address = 0
    segment = idc.get_first_seg()

    while segment != idc.BADADDR:
        max_address = max(max_address, idc.get_segm_end(segment))
        segment = idc.get_next_seg(segment)

    return max_address


# def find_cmp(function, current_decrypt_addr):
#     while current_decrypt_addr > function.start_ea:
#         current_decrypt_addr = idc.prev_head(current_decrypt_addr)
#         if idc.print_insn_mnem(current_decrypt_addr) == "cmp":
#             return current_decrypt_addr
#     return idc.BADADDR


def set_type(ea, type_str):
    _type = idc.parse_decl(type_str, idc.PT_SILENT)
    return idc.apply_type(ea, _type, ida_typeinf.TINFO_DEFINITE)


def parse_mangled_method_name(mangled_name):
    demangled_name = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DN))
    if not demangled_name:
        return None, None
    return re.match(r"(?:(.*)::)?(.*?)\(.*\)", demangled_name).groups()


def get_func_details(func_ea):
    tinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tinfo, func_ea)
    if not tinfo.is_func():
        return None
    func_details = ida_typeinf.func_type_data_t()
    tinfo.get_func_details(func_details)
    return func_details


def apply_signature(ea, sig):
    name = idc.get_func_name(ea)
    ret, args = sig
    print("apply 0x%x %s", ea, name)
    decl = "{} {}({})".format(ret, name, args)
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    # idc.set_name(ea, name)
    idc.apply_type(ea, prototype_details)


def parse_pattern(pattern_str, image_base):
    pattern = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(pattern, image_base, pattern_str, 16)

    if err:
        print(f"[Error] Failed to parse pattern: {err}")
        return None

    return pattern


def find_signature(start_addr, compiled_pattern, max_address):
    if compiled_pattern is None:
        return idc.BADADDR

    return ida_bytes.bin_search(
        start_addr, max_address, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD
    )


def main():

    compiled_patterns = [
        parse_pattern(pattern, idaapi.get_imagebase()) for pattern in PATTERNS
    ]
    image_base = idaapi.get_imagebase()
    max_address = get_max_address()

    for compiled_pattern in compiled_patterns:
        ea, _ = find_signature(0, compiled_pattern, max_address)
        print(f"Found signature at 0x{ea:X}")
        while ea != idc.BADADDR:
            try:
                function = idaapi.get_func(ea)
                sig_found_addr = ea

            except Exception as e:
                print(f"[Error] Failed to process instruction at 0x{ea:X} ->", e)

            ea, _ = find_signature(
                idc.next_head(sig_found_addr), compiled_pattern, max_address
            )


if __name__ == "__main__":
    main()
