class DeFlow:
    """
    Class for detecting and removing control flow obfuscation from binaries.

    This class can work with either a direct function address in IDA or a provided byte buffer.
    It detects and patches opaque predicates and other control flow obfuscation techniques.
    """

    def __init__(self):
        self._already_discovered = set()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    @staticmethod
    def is_in_range(addr, base_address, buffer_end_ea):
        """
        Helper to see if 'addr' is located within our buffer range.
        """
        return base_address <= addr < buffer_end_ea

    def deflow_functions(self, functions=None):
        """
        Main entry point for deobfuscating functions.

        Args:
            functions: Optional iterable of function entry points (start addresses) in the .text section.
            text_seg_buffer: Whether to use the entire .text segment as buffer.

        Returns:
            None
        """

        # Get the start of the .text segment and its size in IDA.
        text_seg = ida_segment.get_segm_by_name(".text")
        if not text_seg:
            print("[-] Could not find .text segment.")
            return

        if not functions:
            functions = idautils.Functions(text_seg.start_ea, text_seg.end_ea)

        logger.debug(
            "Processing %d functions in text segment range: base_address=0x%x, end_address=0x%x, size=%d",
            len(functions),
            text_seg.start_ea,
            text_seg.end_ea,
            text_seg.end_ea - text_seg.start_ea,
        )

        # Reset discovered addresses for a new deflow run
        self._already_discovered = set()

        for func_addr in functions:
            logger.debug("Processing function at address: 0x%x", func_addr)

            func = ida_funcs.get_func(func_addr)
            logger.debug(
                "Function 0x%x: start_ea=0x%x, end_ea=0x%x, size=%d",
                func_addr,
                func.start_ea,
                func.end_ea,
                func.end_ea - func.start_ea,
            )
            patch_operations = self.deflow(
                text_seg.start_ea, text_seg.end_ea, func_addr, func.end_ea
            )
            for operation in patch_operations:
                operation.apply()

    def deflow(
        self,
        segment_start_ea,
        segment_end_ea,
        chunk_start_ea,
        chunk_end_ea,
        apply_patches=False,
    ):
        patch_operations = []
        chunks = self.deflow_chunk(
            segment_start_ea,
            segment_end_ea,
            chunk_start_ea,
            chunk_end_ea,
            patch_operations,
        )
        logger.debug(
            "Initial chunks from deflow_chunk for function 0x%x: %s",
            chunk_start_ea,
            ", ".join([format_addr(c) for c in chunks]),
        )
        while True:
            if not chunks:
                break
            new_chunks = []
            for c in chunks:
                logger.debug("Processing chunk at 0x%x", c)
                new_chunks.extend(
                    self.deflow_chunk(
                        segment_start_ea,
                        segment_end_ea,
                        c,
                        chunk_end_ea,
                        patch_operations,
                    )
                )
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "New chunks after iteration: %s",
                    ", ".join([format_addr(c) for c in new_chunks]),
                )
            chunks = new_chunks

        if apply_patches:
            logger.debug(
                f"Applying {len(patch_operations)} patch operations for chunk 0x{chunk_start_ea:x}"
            )
            for operation in patch_operations:
                operation.apply()
        return patch_operations

    def deflow_chunk(
        self,
        buffer_start_ea,
        buffer_end_ea,
        address,
        ending_address,
        patch_operations,
        provided_buffer=None,
    ):
        """
        Analyze and deobfuscate a chunk of code.

        Args:
            buffer_start_ea: Start address of the buffer being analyzed
            buffer_end_ea: End address of the buffer being analyzed
            address: Address of the chunk to analyze
            ending_address: End address of the function containing the chunk
            patch_operations: List to store patch operations
            provided_buffer: Optional byte buffer to use instead of reading from IDA

        Returns:
            List of new chunks to analyze
        """
        logger.debug("Starting deflow_chunk analysis for address: 0x%x", address)
        new_chunks = []

        is_negative = address < 0
        address = abs(address)

        # Check if we have already discovered this address
        if address in self._already_discovered:
            logger.debug("Address 0x%x already discovered, skipping.", address)
            return new_chunks

        self._already_discovered.add(address)

        # We'll keep track of potential obfuscated branches
        last_branch = 0  # Indicates our last conditional jump address
        last_branch_size = 0  # Size of the last conditional jump instruction
        last_target = 0  # Target location of the last conditional jump

        # Calculate the offset in 'buffer' corresponding to 'address'.
        if not self.is_in_range(address, buffer_start_ea, buffer_end_ea):
            logger.debug(
                "Address %s out of range [%s - %s]",
                format_addr(address),
                format_addr(buffer_start_ea),
                format_addr(buffer_end_ea),
            )
            return new_chunks

        # Use provided buffer or get bytes from IDA
        if provided_buffer is None:
            # Disassemble from 'address' until we run out of bytes
            buffer_size = ending_address - address
            if buffer_size < 0:
                buffer_size = 0x8000  # just take 512kb from the buffer size

            buffer = ida_bytes.get_bytes(address, buffer_size)
        else:
            buffer = provided_buffer

        insn = None
        for insn in self.md.disasm(buffer, address):
            logger.debug(
                "Disassembled instruction at 0x%x: %s %s",
                insn.address,
                insn.mnemonic,
                insn.op_str,
            )
            insn = typing.cast(capstone.CsInsn, insn)

            # We'll track potential jump targets
            target = 0
            is_jmp = True

            # 1) Check for invalid / return instructions
            if (
                insn.id == 0
                or insn.mnemonic in ["ret", "retn"]
                or insn.mnemonic.startswith("ret")
                or insn.mnemonic == "int"
            ):
                logger.debug(
                    "Encountered return or invalid instruction at 0x%x", insn.address
                )
                if last_target == 0:
                    return new_chunks  # Only accept when no lastTarget
                # If there is a last_target, continue analysis.

            # 2) Check for conditional jump instructions
            elif insn.mnemonic in CONDITIONAL_JUMPS_MNEMONICS:
                # if(lastTarget == 0)
                if last_target == 0:
                    target = self.calc_target_jump(insn)
                    logger.debug(
                        "Conditional jump at 0x%x with target 0x%x",
                        insn.address,
                        target,
                    )

                    # Check if in range
                    if not self.is_in_range(target, buffer_start_ea, buffer_end_ea):
                        logger.debug("Target 0x%x out of range", target)
                        is_jmp = False
                    else:
                        # Check if instruction is bigger than 2,
                        # if so it won't be obfuscated but we do want to analyze the target location
                        if insn.size > 2:
                            logger.debug(
                                "Instruction size > 2 at 0x%x; adding target 0x%x and stopping jump analysis",
                                insn.address,
                                target,
                            )
                            is_jmp = False
                            new_chunks.append(target)
                else:
                    # Do not accept any conditional jumps if we already have a last_target
                    # (might be looking at junk code)
                    logger.debug(
                        "Skipping conditional jump at 0x%x due to existing last_target 0x%x",
                        insn.address,
                        last_target,
                    )
                    is_jmp = False
            # 3) Check for unconditional jumps or calls
            elif insn.mnemonic in ["jmp", "call"] and last_target == 0:
                target = self.calc_target_jump(insn)
                real_head = idc.get_item_head(target)
                logger.debug(
                    "Unconditional %s at 0x%x with target 0x%x",
                    insn.mnemonic,
                    insn.address,
                    target,
                )
                if not self.is_in_range(target, buffer_start_ea, buffer_end_ea):
                    logger.debug("New address 0x%x out of range", target)
                    is_jmp = False
                else:
                    if insn.mnemonic == "call":
                        # address + insn.size => next instruction's address
                        next_insn_addr = idc.next_addr(insn.address)
                        if next_insn_addr != (address + insn.size):
                            logger.warning(
                                "Call instruction: next instruction address 0x%x is not the expected 0x%x. Reverting",
                                next_insn_addr,
                                address + insn.size,
                            )
                            next_insn_addr = address + insn.size
                        logger.debug(
                            "Call instruction: adding next instruction address 0x%x",
                            next_insn_addr,
                        )
                        new_chunks.append(next_insn_addr)
                    # Add instruction target for further analysis
                    new_chunks.append(target)
                    return new_chunks
            else:
                # it's not a jump, so we can't handle it
                is_jmp = False

            # Call the extracted function to handle branch instructions
            result, last_branch, last_branch_size, last_target = (
                self.handle_branch_instruction(
                    insn,
                    insn.address,  # In Capstone, insn.address is the runtime address
                    last_branch,
                    last_branch_size,
                    last_target,
                    buffer_start_ea,
                    is_jmp,
                    target,
                    is_negative,
                    new_chunks,
                    patch_operations,
                )
            )

            if result is not None:
                return result

        else:
            if insn:
                logger.debug(
                    "last instruction disassembled: %s @ 0x%x and last_target: 0x%x",
                    insn.mnemonic,
                    insn.address,
                    last_target,
                )
                target_head = idc.prev_head(last_target)
                if last_target != 0 and target_head != last_target:
                    # create an artifical collision by using the previous head of the last target
                    A = idc.get_item_size(target_head)
                    B = last_target - target_head
                    location = target_head + B + 1  # go past last_target by just 1 byte
                    logger.debug(
                        "idc.prev_head(0x%x) = 0x%x, location: 0x%x, last_branch: 0x%x, last_branch_size: %d, last_target: 0x%x, is_jmp: %s, target: 0x%x, is_negative: %s",
                        last_target,
                        target_head,
                        location,
                        last_branch,
                        last_branch_size,
                        last_target,
                        is_jmp,
                        target,
                        is_negative,
                    )
                    result, last_branch, last_branch_size, last_target = (
                        self.handle_branch_instruction(
                            insn,
                            location,
                            last_branch,
                            last_branch_size,
                            last_target,
                            buffer_start_ea,
                            is_jmp,
                            target,
                            is_negative,
                            new_chunks,
                            patch_operations,
                        )
                    )

        return new_chunks

    def handle_branch_instruction(
        self,
        insn,
        location,
        last_branch,
        last_branch_size,
        last_target,
        buffer_start_ea,
        is_jmp,
        target,
        is_negative,
        new_chunks,
        patch_operations,
    ):
        """
        Handle branch instruction analysis for opaque predicate detection and removal.

        Args:
            insn: Current instruction being analyzed
            location: Address of the current instruction
            last_branch: Address of the last branch instruction
            last_branch_size: Size of the last branch instruction
            last_target: Target address of the last branch
            buffer_start_ea: Start address of the buffer being analyzed
            is_jmp: Whether the current instruction is a jump
            target: Target address of the current jump instruction
            is_negative: Whether the jump is negative
            new_chunks: List of new code chunks to analyze
            patch_operations: List to store patch operations

        Returns:
            Tuple of (result, last_branch, last_branch_size, last_target)
        """
        # Steps (bytes) left to reach lastTarget from current address
        steps_left = last_target - location  # Only valid if we have a last_target

        # Setup a new target if current instruction is a conditional jump
        # while there is no last_target
        if last_target == 0 and is_jmp:
            last_branch = location
            last_branch_size = insn.size
            last_target = target
            logger.debug(
                "Setting branch info: last_branch=0x%x, last_branch_size=%d, last_target=0x%x",
                last_branch,
                last_branch_size,
                last_target,
            )
            return None, last_branch, last_branch_size, last_target
        elif steps_left == 0 and last_target != 0:
            logger.debug(
                "Exact collision at 0x%x; adding 0x%x and 0x%x",
                location,
                last_branch + last_branch_size,
                last_target,
            )
            new_chunks.append(last_branch + last_branch_size)
            new_chunks.append(last_target)
            return new_chunks, last_branch, last_branch_size, last_target
        elif steps_left < 0 and last_target != 0:
            # stepsLeft != 0 => collision within the instruction => obfuscated
            count = last_target - last_branch
            logger.debug(
                "Obfuscated branch detected at 0x%x; count: %d", last_branch, count
            )
            if count > 0:
                # making sure we are a positive jump
                buffer_offset = last_branch - buffer_start_ea  # index in local buffer

                # NOP slide everything except our own instruction
                patch_byte = b"\x90" if is_negative else b"\xcc"
                patch_bytes: bytes = patch_byte * (count - last_branch_size)
                patch_operations.append(
                    PatchOperation(
                        buffer_start_ea + buffer_offset + last_branch_size, patch_bytes
                    )
                )
                logger.debug(
                    "Patching bytes at 0x%x with %s",
                    buffer_start_ea + buffer_offset,
                    patch_bytes.hex(),
                )

                if not is_negative:
                    # Force unconditional jump
                    patch_operations.append(
                        UnconditionalJumpOperation(buffer_start_ea + buffer_offset)
                    )
                    logger.debug(
                        "Forced unconditional jump at 0x%x",
                        buffer_start_ea + buffer_offset,
                    )

                # add next instruction for analysis and exit current analysis
                new_chunks.append(last_target)
                logger.debug("Added new chunk target 0x%x", last_target)
                return new_chunks, last_branch, last_branch_size, last_target
            else:
                # we are a negative jump, set 63rd bit to indicate negative jump
                last_target = -last_target
                logger.debug(
                    "Negative jump encountered. Adjusted last_target: 0x%x", last_target
                )
                # add target to analyzer and exit current analysis
                new_chunks.append(last_target)
                return new_chunks, last_branch, last_branch_size, last_target

        return None, last_branch, last_branch_size, last_target

    def calc_target_jump(self, insn: capstone.CsInsn):
        """
        Helper to extract jump or call target from an instruction.

        Args:
            insn: Capstone instruction object

        Returns:
            Target address of the jump or call instruction
        """
        operand = idc.get_operand_value(insn.address, 0)
        op = insn.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            target = op.imm
            logger.debug(
                "@ insn.address: %s with jump target: %s",
                format_addr(insn.address),
                format_addr(target),
            )
        else:
            logger.debug("Operand not immediate at %s", format_addr(insn.address))
        return operand

    @staticmethod
    def disassemble(ea):
        """
        Get the disassembly text associated with an address.

        Args:
            ea: Effective address to disassemble

        Returns:
            String containing the disassembly text
        """
        return idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE)


def deflow(chains: MatchChains):
    deflow = DeFlow()
    patch_operations = []
    BUFFER_SIZE = 129  # Max size of anti-disassembly block
    for chain in chains:
        match_start = chain.overall_start()
        match_len = chain.overall_length()
        match_end = match_start + match_len
        block_end = match_start + BUFFER_SIZE
        patch_operations.extend(
            deflow.deflow(match_start, block_end, match_start, match_end)
        )
    print(f"operations: {patch_operations}")
    return patch_operations
