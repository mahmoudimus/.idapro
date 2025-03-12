import struct

import capstone
import keystone
import unicorn
from unicorn import UC_HOOK_CODE, UC_PROT_ALL
from unicorn.x86_const import *

# Memory configurations
BASE_ADDRESS = 0x140000000
STACK_ADDRESS = 0x200000000
STACK_SIZE = 0x10000
HEAP_ADDRESS = 0x300000000
HEAP_SIZE = 0x10000


class OpaquePredicateDetector:
    def __init__(self, binary_code, start_address):
        self.binary_code = binary_code
        self.start_address = start_address
        self.base_address = BASE_ADDRESS

        # Initialize disassembler
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.cs.detail = True

        # Initialize emulator
        self.emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

        # Initialize assembler (for testing alternative paths)
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

        # Track execution paths
        self.path_history = {}
        self.jump_targets = set()
        self.executed_addresses = set()
        self.branch_decisions = {}

        # Misaligned entry points and overlapping instructions
        self.misaligned_entries = set()
        self.instruction_boundaries = {}

    def setup_memory(self):
        # Map memory for code
        self.emu.mem_map(self.base_address, 0x100000, UC_PROT_ALL)
        self.emu.mem_write(self.base_address, self.binary_code)

        # Map stack and initialize stack pointer
        self.emu.mem_map(STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL)
        self.emu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 0x1000)
        self.emu.reg_write(UC_X86_REG_RBP, STACK_ADDRESS + STACK_SIZE - 0x1000)

        # Map heap for dynamic allocations
        self.emu.mem_map(HEAP_ADDRESS, HEAP_SIZE, UC_PROT_ALL)

        # Initialize registers with random but valid values
        self.initialize_registers()

    def initialize_registers(self):
        # Set reasonable initial values for general purpose registers
        for reg in [
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RSI,
            UC_X86_REG_RDI,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
        ]:
            self.emu.reg_write(reg, HEAP_ADDRESS + 0x1000)  # Point to valid memory

        # Initialize EFLAGS to a neutral state
        self.emu.reg_write(
            UC_X86_REG_EFLAGS, 0x202
        )  # IF=1 (interrupts enabled), bit 1 is always 1

    def code_hook(self, uc, address, size, user_data):
        """Hook for tracing code execution"""
        self.executed_addresses.add(address)

        # Get the current instruction
        code = uc.mem_read(address, size)
        instruction = next(self.cs.disasm(code, address))

        # Record instruction boundaries
        for i in range(size):
            self.instruction_boundaries[address + i] = (address, address + size)

        # Check if this is a conditional jump
        if self.is_conditional_jump(instruction):
            # Record the branch decision
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            target = self.get_jump_target(instruction)

            # Record the jump decision and target
            taken = self.will_jump_be_taken(instruction, eflags)
            self.branch_decisions[address] = {
                "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                "eflags": eflags,
                "target": target,
                "taken": taken,
            }

            if taken:
                self.jump_targets.add(target)

                # Check if this is a misaligned entry point
                if (
                    target in self.instruction_boundaries
                    and self.instruction_boundaries[target][0] != target
                ):
                    self.misaligned_entries.add(target)
                    print(f"Misaligned entry detected at 0x{target:x}")

    def is_conditional_jump(self, instruction):
        """Check if the instruction is a conditional jump"""
        conditional_jumps = {
            "je",
            "jne",
            "jz",
            "jnz",
            "js",
            "jns",
            "jc",
            "jnc",
            "jo",
            "jno",
            "jp",
            "jnp",
            "jpe",
            "jpo",
            "jl",
            "jle",
            "jg",
            "jge",
            "jb",
            "jbe",
            "ja",
            "jae",
            "jcxz",
            "jecxz",
            "jrcxz",
        }
        return instruction.mnemonic in conditional_jumps

    def get_jump_target(self, instruction):
        """Extract the target address of a jump instruction"""
        if instruction.operands[0].type == capstone.x86.X86_OP_IMM:
            return instruction.operands[0].value.imm
        return None

    def will_jump_be_taken(self, instruction, eflags):
        """Determine if a conditional jump will be taken based on EFLAGS"""
        mnemonic = instruction.mnemonic

        cf = (eflags >> 0) & 1  # Carry Flag
        pf = (eflags >> 2) & 1  # Parity Flag
        zf = (eflags >> 6) & 1  # Zero Flag
        sf = (eflags >> 7) & 1  # Sign Flag
        of = (eflags >> 11) & 1  # Overflow Flag

        # Logic for each conditional jump
        if mnemonic == "je" or mnemonic == "jz":
            return zf == 1
        elif mnemonic == "jne" or mnemonic == "jnz":
            return zf == 0
        elif mnemonic == "js":
            return sf == 1
        elif mnemonic == "jns":
            return sf == 0
        elif mnemonic == "jc" or mnemonic == "jb" or mnemonic == "jnae":
            return cf == 1
        elif mnemonic == "jnc" or mnemonic == "jae" or mnemonic == "jnb":
            return cf == 0
        elif mnemonic == "jo":
            return of == 1
        elif mnemonic == "jno":
            return of == 0
        elif mnemonic == "jp" or mnemonic == "jpe":
            return pf == 1
        elif mnemonic == "jnp" or mnemonic == "jpo":
            return pf == 0
        elif mnemonic == "jl" or mnemonic == "jnge":
            return sf != of
        elif mnemonic == "jge" or mnemonic == "jnl":
            return sf == of
        elif mnemonic == "jle" or mnemonic == "jng":
            return zf == 1 or sf != of
        elif mnemonic == "jg" or mnemonic == "jnle":
            return zf == 0 and sf == of
        elif mnemonic == "jbe" or mnemonic == "jna":
            return cf == 1 or zf == 1
        elif mnemonic == "ja" or mnemonic == "jnbe":
            return cf == 0 and zf == 0
        return False

    def analyze_branch(self, address):
        """Analyze a conditional branch by executing both paths"""
        # Extract the conditional jump
        code_at_address = self.binary_code[address - self.base_address :]
        instruction = next(self.cs.disasm(code_at_address, address))

        if not self.is_conditional_jump(instruction):
            return None

        target = self.get_jump_target(instruction)
        if not target:
            return None

        # Track the execution paths for both taken and not-taken cases
        taken_path = self.execute_path(address, force_jump=True)
        not_taken_path = self.execute_path(address, force_jump=False)

        # Compare the execution paths
        if taken_path and not_taken_path:
            # If both paths eventually reach the same destination, this may be an opaque predicate
            is_converging = self.paths_converge(taken_path, not_taken_path)

            # Check for invalid instructions or other anomalies along one path
            invalid_taken = self.check_path_validity(taken_path)
            invalid_not_taken = self.check_path_validity(not_taken_path)

            # If one path is valid and the other is not, it's likely an opaque predicate
            if (invalid_taken and not invalid_not_taken) or (
                not invalid_taken and invalid_not_taken
            ):
                return {
                    "address": address,
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                    "target": target,
                    "opaque_predicate": True,
                    "valid_path": "taken" if not invalid_taken else "not_taken",
                    "reason": "One path contains invalid/unreachable code",
                }

            # Analyze misaligned entry points
            if target in self.misaligned_entries:
                # Analyze the code at the misaligned entry to determine if it's valid
                misaligned_validity = self.analyze_misaligned_entry(target)
                if not misaligned_validity:
                    return {
                        "address": address,
                        "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                        "target": target,
                        "opaque_predicate": True,
                        "valid_path": "not_taken",
                        "reason": "Jump to misaligned entry leading to invalid instructions",
                    }

            # If paths converge but one has significantly more instructions, might be junk code
            if is_converging and (
                len(taken_path) > len(not_taken_path) * 2
                or len(not_taken_path) > len(taken_path) * 2
            ):
                return {
                    "address": address,
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                    "target": target,
                    "opaque_predicate": True,
                    "valid_path": "shorter",
                    "reason": "Paths converge but one contains likely junk code",
                }

        return None

    def analyze_misaligned_entry(self, address):
        """Analyze a misaligned entry point to determine if it's valid code"""
        try:
            # Try to execute from the misaligned entry point
            misaligned_emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
            misaligned_emu.mem_map(self.base_address, 0x100000, UC_PROT_ALL)
            misaligned_emu.mem_write(self.base_address, self.binary_code)

            # Just try to execute a few instructions to see if they're valid
            misaligned_emu.emu_start(address, address + 0x20, timeout=1000, count=5)
            return True
        except unicorn.UcError:
            # If execution fails, the misaligned entry likely leads to invalid instructions
            return False

    def paths_converge(self, path1, path2):
        """Check if two execution paths eventually converge to the same point"""
        # Get the last few addresses from each path
        tail_length = min(10, len(path1), len(path2))
        if tail_length == 0:
            return False

        tail1 = set(path1[-tail_length:])
        tail2 = set(path2[-tail_length:])

        # If there's significant overlap in the tails, paths likely converge
        overlap = tail1.intersection(tail2)
        return len(overlap) >= tail_length // 2

    def check_path_validity(self, path):
        """Check if a path contains invalid instructions or other anomalies"""
        if not path:
            return True  # Empty path is considered invalid

        # Check for known invalid instruction patterns
        for addr in path:
            try:
                code = self.emu.mem_read(
                    addr, 15
                )  # Read enough bytes for a full instruction
                instruction = next(self.cs.disasm(code, addr))

                # Check for instructions that would likely cause exceptions
                if instruction.mnemonic in ["int", "into", "ud2"]:
                    return True

                # Check for jumps to invalid addresses
                if instruction.mnemonic.startswith("j") and self.get_jump_target(
                    instruction
                ):
                    target = self.get_jump_target(instruction)
                    if target < self.base_address or target > self.base_address + len(
                        self.binary_code
                    ):
                        return True
            except:
                return True  # If disassembly fails, consider the path invalid

        return False

    def execute_path(self, start_address, force_jump=None):
        """Execute a path starting from an address, optionally forcing a jump decision"""
        # Create a new emulator instance for this path
        emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        emu.mem_map(self.base_address, 0x100000, UC_PROT_ALL)
        emu.mem_write(self.base_address, self.binary_code)
        emu.mem_map(STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL)
        emu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 0x1000)
        emu.reg_write(UC_X86_REG_RBP, STACK_ADDRESS + STACK_SIZE - 0x1000)
        emu.mem_map(HEAP_ADDRESS, HEAP_SIZE, UC_PROT_ALL)

        # Initialize registers
        for reg in [
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RSI,
            UC_X86_REG_RDI,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
        ]:
            emu.reg_write(reg, HEAP_ADDRESS + 0x1000)

        # Set EFLAGS based on force_jump parameter if at a conditional jump
        if force_jump is not None:
            code = emu.mem_read(start_address, 15)
            instruction = next(self.cs.disasm(code, start_address))

            if self.is_conditional_jump(instruction):
                # Modify EFLAGS to force the desired branch behavior
                eflags = 0x202  # Default flags

                # Adjust specific flags based on the jump condition
                mnemonic = instruction.mnemonic

                if mnemonic in ["je", "jz"]:
                    eflags |= (1 << 6) if force_jump else 0  # ZF=1 or ZF=0
                elif mnemonic in ["jne", "jnz"]:
                    eflags |= 0 if force_jump else (1 << 6)  # ZF=0 or ZF=1
                elif mnemonic == "jnp" or mnemonic == "jpo":
                    eflags |= 0 if force_jump else (1 << 2)  # PF=0 or PF=1
                elif mnemonic == "jp" or mnemonic == "jpe":
                    eflags |= (1 << 2) if force_jump else 0  # PF=1 or PF=0

                # Set other flags as needed for other jumps
                emu.reg_write(UC_X86_REG_EFLAGS, eflags)

        # Track execution path
        path = []

        def hook_code(uc, address, size, user_data):
            path.append(address)

            # Limit execution to prevent infinite loops
            if len(path) > 1000:
                emu.emu_stop()

        emu.hook_add(UC_HOOK_CODE, hook_code)

        try:
            # Execute a short sequence from the start address
            emu.emu_start(
                start_address, start_address + 0x1000, timeout=1000, count=100
            )
        except unicorn.UcError as e:
            # Just return whatever path was executed before the error
            pass

        return path

    def detect_opaque_predicates(self):
        """Main function to detect opaque predicates in the code"""
        # Set up memory and hooks
        self.setup_memory()
        self.emu.hook_add(UC_HOOK_CODE, self.code_hook)

        # First pass: execute the code to collect information
        try:
            self.emu.emu_start(
                self.start_address,
                self.start_address + 0x1000,
                timeout=1000,
                count=1000,
            )
        except unicorn.UcError as e:
            print(f"Emulation error: {e}")

        # Second pass: analyze conditional branches
        opaque_predicates = []
        for address in self.branch_decisions:
            result = self.analyze_branch(address)
            if result and result["opaque_predicate"]:
                opaque_predicates.append(result)

        return opaque_predicates

    def disassemble_range(self, start, size):
        """Disassemble a range of code"""
        code = self.binary_code[
            start - self.base_address : start - self.base_address + size
        ]
        for insn in self.cs.disasm(code, start):
            print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")


def detect_opaque_predicates_in_file(binary_file, start_address):
    with open(binary_file, "rb") as f:
        binary_code = f.read()

    detector = OpaquePredicateDetector(binary_code, start_address)
    results = detector.detect_opaque_predicates()

    for result in results:
        print(f"Opaque predicate at 0x{result['address']:x}: {result['instruction']}")
        print(f"  Target: 0x{result['target']:x}")
        print(f"  Valid path: {result['valid_path']}")
        print(f"  Reason: {result['reason']}")
        print()


def analyze_specific_address(binary_file, address):
    with open(binary_file, "rb") as f:
        binary_code = f.read()

    detector = OpaquePredicateDetector(binary_code, address)
    detector.setup_memory()

    # Disassemble around the address
    print(f"Disassembly around 0x{address:x}:")
    detector.disassemble_range(address, 50)
    print()

    # Analyze the branch specifically
    if detector.is_conditional_jump(
        next(detector.cs.disasm(detector.emu.mem_read(address, 15), address))
    ):
        result = detector.analyze_branch(address)
        if result:
            print(f"Analysis of branch at 0x{address:x}:")
            for key, value in result.items():
                print(f"  {key}: {value}")
        else:
            print(
                f"Branch at 0x{address:x} appears to be a legitimate conditional jump."
            )
    else:
        print(f"Address 0x{address:x} is not a conditional jump.")


# Example usage: analyze the specific edge case
if __name__ == "__main__":
    # Replace with your binary file
    binary_file = "sample_binary.bin"

    # Analyze the specific edge case
    analyze_specific_address(binary_file, 0x140004979)
