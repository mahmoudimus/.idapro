import idaapi
import idc

# Get the current base address
base_address = idaapi.get_imagebase()

# Print the base address
print("Base Address: 0x{:X}".format(base_address))
