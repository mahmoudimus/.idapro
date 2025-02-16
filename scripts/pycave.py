#!/usr/bin/python3

""" pycave.py: Dirty code to find code caves in Portable Executable files"""

__author__ = 'axcheron'
__license__ = 'Apache 2'
__version__ = '0.1'

import argparse
import pefile
import sys


def pycave(file_name, cave_size, base, codecave_opcode):

    image_base = int(base, 16)
    min_cave = cave_size
    fname = file_name
    pe = None

    try:
        pe = pefile.PE(fname)
    except IOError as e:
        print(e)
        sys.exit(0)
    except pefile.PEFormatError as e:
        print("[-] %s" % e.args[0])
        sys.exit(0)

    print("[+] Minimum code cave size: %d" % min_cave)
    print("[+] Image Base:  0x%08X" % image_base)
    print("[+] Loading \"%s\"..." % fname)

    # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    if is_aslr:
        print("\n[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.")

    fd = open(fname, "rb")
    found = False
    print("\n[+] Looking for code caves...")
    for section in pe.sections:
        if section.SizeOfRawData != 0:
            pos = 0
            count = 0
            fd.seek(section.PointerToRawData, 0)
            data = fd.read(section.SizeOfRawData)

            for byte in data:
                pos += 1
                if byte == codecave_opcode: # 0x00 or byte == "\x00":
                    count += 1
                else:
                    if count >= min_cave:
                        found = True
                        raw_addr = section.PointerToRawData + pos - count - 1
                        vir_addr = image_base + section.VirtualAddress + pos - count - 1

                        print("[+] Code cave found in %s \tSize: %d bytes \tRA: 0x%08X \tVA: 0x%08X"
                              % (section.Name.decode(), count, raw_addr, vir_addr))
                    count = 0

    pe.close()
    fd.close()
    if not found:
        print(f"\n[-] Did not find any code caves with opcodes: 0x{codecave_opcode:02X} !")


def bytestr_to_bytearr(data):
    return list(bytearray.fromhex(data.replace("\\x", " ")))


if __name__ == "__main__":
    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description="Find code caves in PE files")

    # Add arguments
    parser.add_argument(dest="file_name", action="store",
                        help="PE file", type=str)

    parser.add_argument("-s", "--size", dest="size", action="store", default=300,
                        help="Min. cave size", type=int)

    parser.add_argument("-b", "--base", dest="base", action="store", default="0x00400000",
                        help="Image base", type=str)
    parser.add_argument('-c', '--cave-opcodes', type=str, dest="cave_opcodes", action="store", default="\\x00\\x90\\xCC", help="OpCode considered as valid code caves (Example: NULL(0x00), NOP(0x90)).")

    args = parser.parse_args()
    try:
        cave_opcodes = bytestr_to_bytearr(args.cave_opcodes)
    except:
        raise Exception("Malformed byte string. A byte string must be defined with the following format: \"\\x01\\x02\\x03...\\x0a\".")
    for codecave_oc in cave_opcodes:
        pycave(args.file_name, args.size, args.base, codecave_opcode=codecave_oc)
