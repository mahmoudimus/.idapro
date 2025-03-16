import logging

import capstone
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_search
import ida_ida
import ida_segment
import ida_ua
import idaapi
import idc

# Configure logging
logger = logging.getLogger("aegis_undoer")
logger.setLevel(logging.DEBUG)


# Format address for display
def format_addr(addr):
    return f"0x{addr:X}"


class AegisUndoer:
    def __init__(self):
        self.is_x64 = ida_ida.inf_is_64bit()

        # Create Capstone disassembler
        self.md = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_64 if self.is_x64 else capstone.CS_MODE_32,
        )
        self.md.detail = True

        # Known block size from the provided information
        self.BLOCK_SIZE = 54

        # Jump opcodes for detection
        self.JUMP_OPCODES = list(range(0x70, 0x80)) + [0xEB, 0xE9]

        # Statistics
        self.blocks_found = 0
        self.blocks_patched = 0

        # Set to track analyzed functions to avoid duplicates
        self.analyzed_functions = set()

    def evaluate_jump(self, ea):
        """Analyze a jump instruction and return its destination and size"""
        inst_byte = ida_bytes.get_byte(ea)

        # Short conditional jumps (0x70-0x7F) or short JMP (0xEB)
        if (inst_byte >= 0x70 and inst_byte <= 0x7F) or inst_byte == 0xEB:
            offset = ida_bytes.get_byte(ea + 1)
            # Handle signed byte offset
            if offset > 127:
                offset = offset - 256
            jmp_size = 2
            jmp_dest = ea + jmp_size + offset
            return (jmp_dest, jmp_size, True)

        # Near JMP (0xE9)
        elif inst_byte == 0xE9:
            offset = ida_bytes.get_dword(ea + 1)
            # Handle signed dword offset
            if offset > 0x7FFFFFFF:
                offset = offset - 0x100000000
            jmp_size = 5
            jmp_dest = ea + jmp_size + offset
            return (jmp_dest, jmp_size, True)

        # Near conditional jumps (0x0F 0x80-0x8F)
        elif inst_byte == 0x0F:
            second_byte = ida_bytes.get_byte(ea + 1)
            if second_byte >= 0x80 and second_byte <= 0x8F:
                offset = ida_bytes.get_dword(ea + 2)
                # Handle signed dword offset
                if offset > 0x7FFFFFFF:
                    offset = offset - 0x100000000
                jmp_size = 6
                jmp_dest = ea + jmp_size + offset
                return (jmp_dest, jmp_size, True)

        # Not a jump instruction
        return (0, 0, False)

    def scan_for_circular_jumps(self, start_ea=None, end_ea=None):
        """
        Scan for 54-byte blocks containing circular jumps

        Args:
            start_ea: Optional starting address to scan (beginning of function)
            end_ea: Optional ending address to scan (end of function)
        """
        if start_ea is not None and end_ea is not None:
            print(
                f"[*] Scanning for 54-byte anti-disassembly blocks in function {format_addr(start_ea)}..."
            )
            scan_ranges = [(start_ea, end_ea)]
        else:
            print(
                "[*] Scanning for 54-byte anti-disassembly blocks across all executable segments..."
            )
            # Search each executable segment
            scan_ranges = []
            for seg_idx in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(seg_idx)
                if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                    continue
                scan_ranges.append((seg.start_ea, seg.end_ea))

        blocks_found = []

        # Scan each range
        for range_start, range_end in scan_ranges:
            # Scan the range
            ea = range_start
            while ea < range_end - self.BLOCK_SIZE:
                # Check if this address contains a jump instruction
                jmp_dest, jmp_size, is_jump = self.evaluate_jump(ea)

                if is_jump:
                    # Check if jump target is within the expected 54-byte block
                    if ea <= jmp_dest < ea + self.BLOCK_SIZE:
                        # Verify this is likely an anti-disassembly block by checking:
                        # 1. Multiple jumps in the block
                        # 2. At least one backward jump
                        jumps_found = 0
                        has_backward_jump = False

                        for offset in range(self.BLOCK_SIZE):
                            check_ea = ea + offset
                            check_dest, _, check_is_jump = self.evaluate_jump(check_ea)

                            if check_is_jump:
                                jumps_found += 1
                                if check_dest < check_ea:
                                    has_backward_jump = True

                        # If we have multiple jumps and at least one backward jump, likely anti-disassembly
                        if jumps_found >= 2 and has_backward_jump:
                            blocks_found.append(ea)
                            print(
                                f"[+] Found potential anti-disassembly block at {format_addr(ea)}"
                            )

                ea += 1

                # Show progress periodically for larger scans
                if ea % 100000 == 0 and start_ea is None:
                    print(f"[*] Scanning: {format_addr(ea)}")

        # Update total blocks found count
        self.blocks_found += len(blocks_found)
        if start_ea is not None:
            print(
                f"[*] Found {len(blocks_found)} potential anti-disassembly blocks in function {format_addr(start_ea)}"
            )
        else:
            print(f"[*] Found {self.blocks_found} potential anti-disassembly blocks")

        return blocks_found

    def scan_for_collision_jumps(self, start_ea=None, end_ea=None):
        """
        Scan for 54-byte blocks containing opaque predicates (collision jumps)

        Args:
            start_ea: Optional starting address to scan (beginning of function)
            end_ea: Optional ending address to scan (end of function)
        """
        if start_ea is not None and end_ea is not None:
            print(
                f"[*] Scanning for opaque predicates in function {format_addr(start_ea)}..."
            )
            scan_ranges = [(start_ea, end_ea)]
        else:
            print(
                "[*] Scanning for opaque predicates in 54-byte blocks across all executable segments..."
            )
            # Search each executable segment
            scan_ranges = []
            for seg_idx in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(seg_idx)
                if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                    continue
                scan_ranges.append((seg.start_ea, seg.end_ea))

        blocks_found = []

        # Scan each range
        for range_start, range_end in scan_ranges:
            # Scan the range
            ea = range_start
            while ea < range_end - self.BLOCK_SIZE:
                # Verify this is a 54-byte block by checking for collision jumps
                collision_found = False

                for offset in range(
                    self.BLOCK_SIZE - 2
                ):  # -2 because jump needs at least 2 bytes
                    check_ea = ea + offset
                    jmp_dest, _, is_jump = self.evaluate_jump(check_ea)

                    if is_jump and ea <= jmp_dest < ea + self.BLOCK_SIZE:
                        # Check if jump destination is not at an instruction boundary
                        dest_head = idc.get_item_head(jmp_dest)
                        if dest_head != jmp_dest:
                            collision_found = True
                            break

                if collision_found:
                    blocks_found.append(ea)
                    print(f"[+] Found potential opaque predicate at {format_addr(ea)}")

                ea += 1

                # Show progress periodically for larger scans
                if ea % 100000 == 0 and start_ea is None:
                    print(f"[*] Scanning: {format_addr(ea)}")

        # Add to total blocks found
        blocks_count = len(blocks_found)
        self.blocks_found += blocks_count

        if start_ea is not None:
            print(
                f"[*] Found {blocks_count} blocks with opaque predicates in function {format_addr(start_ea)}"
            )
        else:
            print(f"[*] Found {blocks_count} blocks with opaque predicates")

        return blocks_found

    def patch_block(self, block_ea):
        """Patch a 54-byte anti-disassembly block by NOPing it out"""
        print(f"[*] Patching anti-disassembly block at {format_addr(block_ea)}")

        # NOP out the entire 54-byte block
        for offset in range(self.BLOCK_SIZE):
            ida_bytes.patch_byte(block_ea + offset, 0x90)

        # Re-analyze the patched area
        ida_bytes.del_items(block_ea, 0, self.BLOCK_SIZE)
        ida_bytes.create_insn(block_ea)

        # Mark the patched area with a comment
        idc.set_cmt(block_ea, f"[PATCHED] Aegis Anti-Disassembly Block (54 bytes)", 0)

        self.blocks_patched += 1
        print(
            f"[+] Successfully patched anti-disassembly block at {format_addr(block_ea)}"
        )

    def analyze_function(self, func_ea):
        """Analyze a specific function for anti-disassembly blocks"""
        if func_ea in self.analyzed_functions:
            print(f"[*] Function {format_addr(func_ea)} already analyzed, skipping")
            return []

        # Get function boundaries
        func = ida_funcs.get_func(func_ea)
        if not func:
            print(f"[!] No function at {format_addr(func_ea)}")
            return []

        print(
            f"[*] Analyzing function {format_addr(func_ea)} (size: {func.end_ea - func.start_ea} bytes)"
        )
        self.analyzed_functions.add(func_ea)

        # Find anti-disassembly blocks in this function
        circular_blocks = self.scan_for_circular_jumps(func.start_ea, func.end_ea)
        collision_blocks = self.scan_for_collision_jumps(func.start_ea, func.end_ea)

        # Combine and deduplicate blocks
        all_blocks = sorted(set(circular_blocks + collision_blocks))

        if not all_blocks:
            print(
                f"[*] No anti-disassembly blocks found in function {format_addr(func_ea)}"
            )
            return []

        print(
            f"[*] Found {len(all_blocks)} anti-disassembly blocks in function {format_addr(func_ea)}"
        )

        # Patch each block
        for block_ea in all_blocks:
            try:
                self.patch_block(block_ea)
            except Exception as e:
                print(f"[!] Error patching at {format_addr(block_ea)}: {str(e)}")

        # Refresh after patching
        ida_kernwin.refresh_idaview_anyway()

        return all_blocks

    def run(self, func_ea=None):
        """
        Main function to find and patch all 54-byte anti-disassembly blocks

        Args:
            func_ea: Optional function address to focus analysis on
        """
        print("=" * 60)
        print("Aegis 54-Byte Anti-Disassembly Block Undoer")
        print("=" * 60)
        print(f"Architecture: {'x64' if self.is_x64 else 'x86'}")

        if func_ea is not None:
            # Analyze a specific function
            self.analyze_function(func_ea)
        else:
            # Find all anti-disassembly blocks across the entire binary
            circular_blocks = self.scan_for_circular_jumps()
            collision_blocks = self.scan_for_collision_jumps()

            # Combine and deduplicate blocks
            all_blocks = sorted(set(circular_blocks + collision_blocks))

            if not all_blocks:
                print("[!] No anti-disassembly blocks found")
                return

            print("\n[*] Starting to patch anti-disassembly blocks...")

            # Patch each block
            for block_ea in all_blocks:
                try:
                    self.patch_block(block_ea)
                except Exception as e:
                    print(f"[!] Error patching at {format_addr(block_ea)}: {str(e)}")

        print("\n" + "=" * 60)
        print(
            f"[*] Patching complete: {self.blocks_patched}/{self.blocks_found} anti-disassembly blocks removed"
        )
        print("=" * 60)

        # Refresh the view
        ida_kernwin.refresh_idaview_anyway()


# # Simple dialog to get function address
# class FunctionAddressDialog(ida_kernwin.Form):
#     def __init__(self):
#         ida_kernwin.Form.__init__(
#             self,
#             """STARTITEM 0
# Aegis Anti-Disassembly Undoer

# <##Use current function:{current_function}>
# <##Enter specific function address:{func_addr}>
# <##Scan entire binary:{scan_entire_binary}>
# """,
#             {
#                 "current_function": ida_kernwin.Form.RadGroupControl(
#                     ("current_function"), value=True
#                 ),
#                 "func_addr": ida_kernwin.Form.NumericInput(
#                     tp=ida_kernwin.Form.FT_ADDR, value=0
#                 ),
#                 "scan_entire_binary": ida_kernwin.Form.RadGroupControl(
#                     ("scan_entire_binary"), value=False
#                 ),
#             },
#         )


# # Main entry point
# def main():
#     # Show dialog to get function address
#     dlg = FunctionAddressDialog()
#     dlg.Compile()
#     if dlg.Execute() != 1:
#         print("Cancelled by user")
#         return

#     undoer = AegisUndoer()

#     if dlg.current_function.selected:
#         # Get current function
#         func_ea = idc.get_func_attr(idc.get_screen_ea(), idc.FUNCATTR_START)
#         if func_ea == idc.BADADDR:
#             print("[!] No function at current address")
#             return
#         undoer.run(func_ea)
#     elif dlg.func_addr.value != 0:
#         # Use specified function address
#         undoer.run(dlg.func_addr.value)
#     else:
#         # Scan entire binary
#         undoer.run()


def main():
    
if __name__ == "__main__":
    main()
