import ctypes
import os

import ida_bytes
import ida_name
import ida_segment
import idaapi
import idautils
import idc


def get_required_address(name, description):
    addr = idc.get_name_ea_simple(name)
    if addr == idaapi.BADADDR:
        print(f"Error: Could not find address for {description} ({name})")
        return None
    return addr


def function_range(start, end, advance):
    current = start
    while current < end:
        yield current
        current = advance(current)


class TLS_DATA_UNENCRYPTED(ctypes.Structure):
    _pack_ = 2
    _fields_ = [
        ("Identifier", ctypes.c_ubyte * 14),
        ("TlsStart", ctypes.c_uint64),
        ("TlsEnd", ctypes.c_uint64),
    ]

    def __repr__(self):
        return "\n".join(
            [
                f"Identifier:  {bytes(self.Identifier).hex()}",
                "TlsStart:    0x{:016X}".format(self.TlsStart),
                "TlsEnd:      0x{:016X}".format(self.TlsEnd),
            ]
        )


def find_next_extern_after_messagebox():
    # Look for the externs segment
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = ida_segment.get_segm_name(seg)

        if seg.type != ida_segment.SEG_XTRN:
            continue

        # Check if this is an externs segment
        print(f"Found externs segment: {seg_name} at {hex(seg_ea)}")
        imports = []
        found_messagebox = False

        for address in function_range(seg.start_ea, seg.end_ea, idc.next_head):
            # Get all imports
            name = idaapi.get_ea_name(address, idaapi.GN_DEMANGLED)
            # Skip if not a real name
            if not name:
                continue

            imports.append((address, name))
        # Sort imports by address
        imports.sort(key=lambda x: x[0])

        # Find MessageBoxW and then the next import
        for i, (address, name) in enumerate(imports):
            if "MessageBoxW" in name and not found_messagebox:
                found_messagebox = True
                if len(imports) < i + 1:
                    continue
                next_ea, next_name = imports[i + 1]
                return next_ea, next_name

    print("Either MessageBoxW not found or no extern after it")
    return None, None


def find_tls_data_offset():
    g_tlsData_address = get_required_address("g_tlsData", "TLS Data")
    if g_tlsData_address:
        return g_tlsData_address
    print("TLS Data address not found, searching for signature")
    next_extern_ea, next_extern_name = find_next_extern_after_messagebox()
    if next_extern_ea:
        ida_name.set_name(next_extern_ea, "g_tlsData", ida_name.SN_FORCE)
        print(
            f"Found extern after MessageBoxW: {next_extern_name} at {hex(next_extern_ea)}"
        )
        return next_extern_ea
    print("TLS Data signature not found")
    return None


g_tlsData = bytes(
    [
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x2E,
        0x1E,
        0xD7,
        0x4D,
        0x92,
        0x27,
        0x03,
        0x26,
        0xDB,
        0x65,
        0x98,
        0x1C,
        0x19,
        0xAC,
        0x00,
        0x10,
        0x00,
        0x40,
        0x01,
        0x00,
        0x00,
        0x00,
        0x2C,
        0xD3,
        0x0B,
        0x40,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
)


def get_tls_data(start_offset=0x37):
    tls_data = find_tls_data_offset()
    tls_data_size = idc.get_item_size(tls_data)
    print(hex(tls_data), tls_data_size)
    g_tlsData = ida_bytes.get_bytes(tls_data, tls_data_size)
    print([hex(i) for i in g_tlsData])
    first_non_zero_index = next(
        (i for i, byte in enumerate(g_tlsData) if byte != 0), None
    )
    tls_data_slice = g_tlsData[
        first_non_zero_index : first_non_zero_index
        + ctypes.sizeof(TLS_DATA_UNENCRYPTED)
    ]
    print(tls_data_slice.hex("-"))
    tls_data = TLS_DATA_UNENCRYPTED.from_buffer_copy(tls_data_slice)
    print(tls_data)
    return tls_data


print(get_tls_data())
