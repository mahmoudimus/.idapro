import idautils
import idc


def rename_to_auto_generated(prefix):
    for func_ea in idautils.Functions():
        # Get the raw function name
        name = idc.get_func_name(func_ea)
        # Attempt to demangle the name; if demangling fails, fallback to the raw name.
        demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DEMNAMES))
        if demangled is None:
            demangled = name

        # Check if the (demangled) name starts with the target prefix.
        if demangled.startswith(prefix):
            # Generate the auto-generated name using the function's start address (in hex)
            new_name = "sub_%X" % func_ea
            if idc.set_name(func_ea, new_name, idc.SN_NOWARN):
                print("Renamed %s (demangled: %s) to %s" % (name, demangled, new_name))
            else:
                print("Failed to rename %s (demangled: %s)" % (name, demangled))


# rename_to_auto_generated("xxxJxOxHxNxxxWxIxCxKxxx")
rename_to_auto_generated("patch_")
