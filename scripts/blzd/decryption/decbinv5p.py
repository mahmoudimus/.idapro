import abc
import functools
import json
import logging
import pathlib
import sys
import typing
import warnings
from dataclasses import dataclass, field
from enum import Enum, auto

from mutilz.helpers.ida import clear_output, find_byte_sequence
from mutilz.logconf import configure_logging

import ida_auto
import ida_bytes
import ida_kernwin
import ida_problems
import ida_range
import ida_segment
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

import unicorn

logger = logging.getLogger("decrypt_binary_v4")

PAGE_SIZE = 0x1000  # 4 KB pages


class UnicornEmulator:
    def __init__(
        self,
        debug=True,
        stack_base=None,
        stack_size=8 * 1024 * 1024,
        flags: int = unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN,
    ):
        self.mu = unicorn.Uc(unicorn.UC_ARCH_X86, flags)
        self.stack_base = stack_base or 0x004000000  # Higher stack base address
        self.stack_size = stack_size or 8 * 1024 * 1024  # 8MB stack size
        self._init()
        self._install_debug_hook(debug)

    def _install_debug_hook(self, debug):
        if debug:
            # Install a hook to print debug information on every executed instruction.
            self.mu.hook_add(unicorn.UC_HOOK_CODE, self._hook_code)

    def _init(self):
        self.mu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self._hook_exception)
        self._map_low_memory()
        self._map_segments()
        self._init_registers()

    def _map_low_memory(self):
        # Map low memory to cover gs:[rax] accesses (e.g., from 0x0 to 0x1000)
        self.mu.mem_map(0x0, 0x1000, unicorn.UC_PROT_ALL)
        seg_bytes = idc.get_bytes(0x0, 0x100)
        if seg_bytes:
            self.mu.mem_write(0x0, seg_bytes)

    def _map_segments(self):
        # Map our code and stack into Unicorn's memory.
        code_segment = ida_segment.get_segm_by_name(".text")  # Get code segment
        self.mu.mem_map(
            code_segment.start_ea,
            code_segment.end_ea - code_segment.start_ea,
            unicorn.UC_PROT_ALL,
        )
        self._map_combined_segments(".data", unicorn.UC_PROT_ALL)
        self.mu.mem_map(
            self.stack_base, self.stack_size, unicorn.UC_PROT_ALL
        )  # Map stack

        code_bytes = idc.get_bytes(
            code_segment.start_ea, code_segment.end_ea - code_segment.start_ea
        )
        self.mu.mem_write(code_segment.start_ea, code_bytes)

    def _init_registers(self):
        # Initialize registers—all set to 0.
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RIP, self.stack_base)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, 0)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RBX, 0)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, 0)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, 0)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RSI, 0)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, 0)
        self.mu.reg_write(
            unicorn.x86_const.UC_X86_REG_RSP, self.stack_base + self.stack_size - 0x1000
        )

    def _dump_registers(self, uc=None):
        """Dump all x86_64 registers in a formatted output."""
        if not uc:
            uc = self.mu
        registers = {
            "RAX": unicorn.x86_const.UC_X86_REG_RAX,
            "RBX": unicorn.x86_const.UC_X86_REG_RBX,
            "RCX": unicorn.x86_const.UC_X86_REG_RCX,
            "RDX": unicorn.x86_const.UC_X86_REG_RDX,
            "RSI": unicorn.x86_const.UC_X86_REG_RSI,
            "RDI": unicorn.x86_const.UC_X86_REG_RDI,
            "RBP": unicorn.x86_const.UC_X86_REG_RBP,
            "RSP": unicorn.x86_const.UC_X86_REG_RSP,
            "RIP": unicorn.x86_const.UC_X86_REG_RIP,
            "R8": unicorn.x86_const.UC_X86_REG_R8,
            "R9": unicorn.x86_const.UC_X86_REG_R9,
            "R10": unicorn.x86_const.UC_X86_REG_R10,
            "R11": unicorn.x86_const.UC_X86_REG_R11,
            "R12": unicorn.x86_const.UC_X86_REG_R12,
            "R13": unicorn.x86_const.UC_X86_REG_R13,
            "R14": unicorn.x86_const.UC_X86_REG_R14,
            "R15": unicorn.x86_const.UC_X86_REG_R15,
            "EFLAGS": unicorn.x86_const.UC_X86_REG_EFLAGS,
        }

        logger.debug("\n--- Register Dump (x86_64) ---")
        for reg_name, reg_id in registers.items():
            value = uc.reg_read(reg_id)
            padded_reg_name = reg_name.rjust(3)
            logger.debug(f"{padded_reg_name}: 0x{value:016X}")
        logger.debug("-----------------------------\n")

    def _hook_exception(self, uc, access, address, size, value, user_data):
        """Robust exception hook: attempt to map missing memory so that emulation can continue.
        If the access error is due to unmapped memory, map a page at the aligned address and resume.
        Otherwise, if mapping fails, stop execution."""
        logger.info(
            f"Exception: access={access} at address: 0x{address:016X}, size={size}, value={value}"
        )
        self._dump_registers(uc)

        PAGE_SIZE = 0x1000
        aligned_addr = address & ~(PAGE_SIZE - 1)

        try:
            # Try to map a new page at the missing address with all permissions
            uc.mem_map(aligned_addr, PAGE_SIZE, unicorn.UC_PROT_ALL)
            logger.info(
                f"Mapped missing memory at 0x{aligned_addr:016X} (size: 0x{PAGE_SIZE:X}). Resuming emulation."
            )
            return True  # Resume emulation
        except unicorn.UcError as e:
            logger.error(f"Failed to handle exception at 0x{address:016X}", e)
            return False

    def _hook_code(self, mu, address, size, user_data):
        """
        This hook is called on every instruction executed.
        It prints the current instruction address, the disassembled line (from IDA),
        and some register values.
        """
        self._dump_registers()
        disasm_line = idc.generate_disasm_line(address, 0)
        logger.info("Executing 0x%X: %s", address, disasm_line)

    def _map_combined_segments(
        self, seg_name, prot, PAGE_SIZE=0x1000, copy_content=True
    ):
        segs = []
        for seg_ea in idautils.Segments():
            if idc.get_segm_name(seg_ea) == seg_name:
                seg_start = seg_ea
                seg_end = idc.get_segm_end(seg_ea)
                segs.append((seg_start, seg_end))

        if not segs:
            logger.info("No segments found for", seg_name)
            return

        # Compute the union of all segments.
        min_start = min(seg[0] for seg in segs)
        max_end = max(seg[1] for seg in segs)

        # Align the union to page boundaries.
        aligned_start = min_start & ~(PAGE_SIZE - 1)
        aligned_end = (max_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        size = aligned_end - aligned_start

        logger.info(
            f"Mapping combined segment {seg_name}: {hex(aligned_start)} - {hex(aligned_end)} (size: 0x{size:X})"
        )

        # Map the combined region.
        self.mu.mem_map(aligned_start, size, prot)

        if copy_content:
            # Optionally, write data from each segment into the mapped region.
            for seg_start, seg_end in segs:
                seg_size = seg_end - seg_start
                seg_bytes = idc.get_bytes(seg_start, seg_size)
                if seg_bytes:
                    self.mu.mem_write(seg_start, seg_bytes)
        return aligned_start, size

    def emulate(self, start_ea, end_ea) -> unicorn.Uc:
        code_size = end_ea - start_ea
        try:
            self.mu.emu_start(start_ea, start_ea + code_size)
        except unicorn.UcError as e:
            print("Emulation error: %s" % e)

        return self.mu


class SearchDirection(Enum):
    """
    Enum defining different strategies for searching anchor instructions.

    BACKWARD_SCAN: Scan byte-by-byte backwards from ea (memory efficient)
    FORWARD_CHUNK: Read chunk of memory and scan forward (potentially faster)
    """

    BACKWARD = auto()  # Original strategy: scan backwards byte by byte
    FORWARD = auto()  # New strategy: read chunk and scan forward


# def _search_range(
#     ea: int,
#     check_instruction: typing.Callable[[ida_ua.insn_t], bool],
#     max_range: int = 0x200,
#     strategy: SearchStrategy = SearchStrategy.BACKWARD_SCAN,
# ) -> typing.Optional[int]:
#     """
#     Searches for an instruction that matches the `check_instruction` function
#     using the specified search strategy.

#     Args:
#         ea (int): Starting effective address to search from
#         max_range (int): Maximum number of bytes to search (default: 0x200)
#         strategy (AnchorSearchStrategy): Search strategy to use (default: BACKWARD_SCAN)

#     Returns:
#         Optional[int]: The anchor address if found, None otherwise
#     """

#     if strategy == SearchStrategy.BACKWARD_SCAN:
#         # Original strategy: scan backwards byte by byte
#         start_addr = max(ea - max_range, 0)
#         current = ea
#         while current >= start_addr:
#             insn = ida_ua.insn_t()
#             if ida_ua.decode_insn(insn, current) > 0:
#                 if check_instruction(insn):
#                     return current
#                 current -= 1
#             else:
#                 current -= 1

#     elif strategy == SearchStrategy.FORWARD_CHUNK:
#         # Scan forward through the chunk
#         current = ea
#         while current < ea + max_range:
#             insn = ida_ua.insn_t()
#             if ida_ua.decode_insn(insn, current) > 0:
#                 if check_instruction(insn):
#                     return current
#                 current += insn.size
#             else:
#                 current += 1

#     logger.debug("No anchor found within %d bytes before 0x%X", max_range, ea)
#     return None


class Searcher:
    """
    Encapsulates searching logic within a specified range and direction.
    """

    def __init__(
        self,
        start_ea: int,
        direction: SearchDirection,
        processor: "KeyLengthProcessor",
        max_distance: int = 0x1000,
    ):
        self.start_ea = start_ea
        self.direction = direction
        self.processor = processor
        self.condition: typing.Callable[[ida_ua.insn_t], bool] = processor.anchor
        self.max_distance = max_distance
        self.processor.reset()

    def search(self) -> typing.Optional[int]:
        """
        Searches for an instruction that matches the `check_instruction` function
        using the specified search strategy.

        Args:
            ea (int): Starting effective address to search from
            max_range (int): Maximum number of bytes to search (default: 0x200)
            strategy (AnchorSearchStrategy): Search strategy to use (default: BACKWARD_SCAN)

        Returns:
            Optional[int]: The anchor address if found, None otherwise
        """

        if self.direction == SearchDirection.BACKWARD:
            # Original strategy: scan backwards byte by byte
            start_addr = max(self.start_ea - self.max_distance, 0)
            current = self.start_ea
            while current >= start_addr:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, current) > 0:
                    if self.condition(insn):
                        logger.debug("Found anchor at 0x%X", current)
                        return current
                    current -= 1
                else:
                    current -= 1

        elif self.direction == SearchDirection.FORWARD:
            # Scan forward through the chunk
            current = self.start_ea
            while current < self.start_ea + self.max_distance:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, current) > 0:
                    if self.condition(insn):
                        logger.debug("Found anchor at 0x%X", current)
                        return current
                    current += insn.size
                else:
                    current += 1

        logger.debug(
            "No anchor found within %d bytes before 0x%X",
            self.max_distance,
            self.start_ea,
        )
        return None

    # def search(self) -> typing.Optional[int]:
    #     """
    #     Performs the search based on the initialized parameters.

    #     Returns:
    #         Optional[int]: The address of the found instruction, or None if not found.
    #     """
    #     current = self.start_ea
    #     insn = ida_ua.insn_t()
    #     searched_distance = 0
    #     if self.direction == SearchDirection.BACKWARD:
    #         end_ea = max(self.start_ea - self.max_distance, 0)
    #         while current >= end_ea:
    #             insn_len = ida_ua.decode_prev_insn(insn, current)
    #             if insn_len == idaapi.BADADDR or insn_len == 0:
    #                 # Could not decode previous instruction, move back one byte
    #                 current -= 1
    #                 searched_distance += 1
    #                 continue

    #             if self.condition(insn):
    #                 return insn.ea  # Found the instruction

    #             current = insn.ea  # Move to the start of the decoded instruction
    #             searched_distance = self.start_ea - current
    #             if searched_distance >= self.max_distance:
    #                 break  # Stop if we've exceeded max distance

    #         # Final check for the very first byte if needed
    #         if current < end_ea:
    #             insn_len = ida_ua.decode_insn(insn, end_ea)
    #             if insn_len > 0 and self.condition(insn):
    #                 return insn.ea

    #     elif self.direction == SearchDirection.FORWARD:
    #         end_ea = self.start_ea + self.max_distance
    #         while current < end_ea:
    #             insn_len = ida_ua.decode_insn(insn, current)
    #             if insn_len <= 0:
    #                 # Could not decode, advance by one byte
    #                 current += 1
    #                 searched_distance += 1
    #                 continue

    #             if self.condition(insn):
    #                 return current  # Found the instruction

    #             current += insn_len
    #             searched_distance = current - self.start_ea
    #             if searched_distance >= self.max_distance:
    #                 break  # Stop if we've exceeded max distance

    #     logger.debug(
    #         "Search did not find matching instruction within %d bytes %s from 0x%X",
    #         self.max_distance,
    #         "before" if self.direction == SearchDirection.BACKWARD else "after",
    #         self.start_ea,
    #     )
    #     return None


# 69 45 00 82 81 46 61 DF 52 10 F4 0C D7 A9 5F 26 6F 3C 1D 15 6E E4 93 0D 77 AB 20 A6 99
# -> Encrypted_Function_Pad

# ? ? 2B EB 1E 6A DC 0F 91 12  -> ExecuteNthTime #15
# -> polynomials
# -> EncDataTransform_Start function addr
# -> imageExeRange
# -> tlsMirrorBase
# -> tlsCryptoReady
# -> EncryptedDataTransform function addr
# -> encDataRandomTable
# -> uberHash
# -> uberHashChangeReported
# -> tlsCodeHashInvalid
# -> tlsCrash function addr

BytesData = typing.Union[list[int], bytes, bytearray]


class ByteBuffer(abc.ABC):
    """Abstract base class for byte access."""

    @abc.abstractmethod
    def get_byte(self, ea: int) -> int:
        """
        Gets a single byte at the specified effective address.
        Raises IndexError if the byte cannot be read.
        """
        pass

    @abc.abstractmethod
    def get_bytes(self, ea: int, size: int) -> bytes | None:
        """
        Gets a sequence of bytes. Returns None on failure.
        """
        pass

    @abc.abstractmethod
    def is_valid_address(self, ea: int) -> bool:
        """Checks if the address is potentially readable."""
        pass


class IDBBackedBuffer(ByteBuffer):
    """Directly accesses IDA database for bytes."""

    def get_byte(self, ea: int) -> int:
        """Gets a single byte directly from the IDB."""
        # Check if address exists in the database segmentation
        if not ida_bytes.is_loaded(ea):
            raise IndexError(f"Address 0x{ea:X} is not loaded in IDB.")

        b = ida_bytes.get_byte(ea)
        # ida_bytes.get_byte returns -1 on error (e.g., outside defined range)
        if b == -1:
            # Verify if the address is *truly* invalid or just happens to contain 0xFF
            # A simple check is to try and read 1 byte using get_bytes
            if ida_bytes.get_bytes(ea, 1) is None:
                raise IndexError(f"Failed to read byte at address 0x{ea:X} from IDB.")
            else:
                # If get_bytes works, the byte must be 0xFF
                return 0xFF
        return b

    def get_bytes(self, ea: int, size: int) -> bytes | None:
        """Gets bytes directly from the IDB. Returns None on failure."""
        return ida_bytes.get_bytes(ea, size)

    def is_valid_address(self, ea: int) -> bool:
        """Checks if the address is loaded in the IDB."""
        return ida_bytes.is_loaded(ea)


class MemBackedBuffer(ByteBuffer):
    """Buffers reads from the IDB for potentially faster sequential access."""

    DEFAULT_BUFFER_SIZE = 96 * 1024  # 96KB default buffer

    def __init__(
        self, buffer_size: int = DEFAULT_BUFFER_SIZE, preload_ea: int | None = None
    ):
        if buffer_size <= 0:
            raise ValueError("Buffer size must be positive.")
        self.buffer_size = buffer_size
        self.buffer = bytearray()
        self.buffer_start_ea = idaapi.BADADDR
        self.buffer_end_ea = idaapi.BADADDR  # Exclusive end address

        # Basic stats
        self._cache_hits = 0
        self._cache_misses = 0
        self._bytes_read_from_idb = 0

        if preload_ea is not None:
            try:
                self._slide_window(preload_ea)
            except IndexError:
                logger.warning(f"Preload failed for address 0x{preload_ea:X}")

    def _is_address_in_buffer(self, ea: int) -> bool:
        """Checks if the address is within the current buffer's range."""
        return self.buffer_start_ea <= ea < self.buffer_end_ea

    def _slide_window(self, target_ea: int) -> None:
        """Loads a chunk of memory centered around target_ea into the buffer."""
        self._cache_misses += 1
        # Calculate the ideal start address to center the buffer
        # Ensure start_ea is not negative
        new_start = max(0, target_ea - self.buffer_size // 2)

        # Ensure read doesn't go past max_ea, adjust size if necessary
        max_ea = idaapi.inf_get_max_ea()
        read_size = min(self.buffer_size, max_ea - new_start)
        if read_size <= 0:
            logger.warning(
                f"Cannot read at or beyond max EA (0x{max_ea:X}). Requested start 0x{new_start:X}"
            )
            self._invalidate_buffer()
            raise IndexError(f"Cannot read memory at 0x{new_start:X} (beyond max EA)")

        logger.debug(
            f"Sliding window to cover 0x{target_ea:X}. Reading {read_size} bytes from 0x{new_start:X}"
        )

        actual_bytes = ida_bytes.get_bytes(new_start, read_size)

        if actual_bytes:
            self.buffer = bytearray(actual_bytes)
            self.buffer_start_ea = new_start
            self.buffer_end_ea = new_start + len(actual_bytes)
            self._bytes_read_from_idb += len(actual_bytes)
            logger.debug(
                f"Loaded {len(actual_bytes)} bytes into buffer. Range: [0x{self.buffer_start_ea:X} - 0x{self.buffer_end_ea:X})"
            )
        else:
            # Failed to read bytes - maybe invalid address or gap in memory?
            logger.warning(
                f"Failed to read {read_size} bytes starting at 0x{new_start:X}"
            )
            self._invalidate_buffer()
            # Raise error to signal failure to the caller
            raise IndexError(f"Failed to read memory for buffer at 0x{new_start:X}")

    def _invalidate_buffer(self):
        """Clears the buffer and resets its state."""
        self.buffer = bytearray()
        self.buffer_start_ea = idaapi.BADADDR
        self.buffer_end_ea = idaapi.BADADDR

    def get_byte(self, ea: int) -> int:
        """Gets a single byte, loading from IDB if not buffered."""
        if self._is_address_in_buffer(ea):
            self._cache_hits += 1
        else:
            # This call raises IndexError on failure
            self._slide_window(ea)
            # Check again after sliding - must be in buffer now if _slide_window succeeded
            if not self._is_address_in_buffer(ea):
                # This should not happen if _slide_window doesn't error, but as a safeguard:
                raise IndexError(f"Address 0x{ea:X} could not be loaded into buffer.")

        offset = ea - self.buffer_start_ea
        return self.buffer[offset]

    def get_bytes(self, ea: int, size: int) -> bytes | None:
        """Gets bytes, loading from IDB if needed. Returns None on failure."""
        if size <= 0:
            return b""

        end_ea = ea + size  # Exclusive end
        # Check if the *entire* range is currently buffered
        if self._is_address_in_buffer(ea) and self._is_address_in_buffer(end_ea - 1):
            self._cache_hits += 1
            start_offset = ea - self.buffer_start_ea
            end_offset = end_ea - self.buffer_start_ea
            return bytes(self.buffer[start_offset:end_offset])  # Return copy
        else:
            # Range is not fully buffered. Can we serve it by sliding?
            if size > self.buffer_size:
                # Request is larger than the buffer capacity, fallback to direct read
                logger.warning(
                    f"Requested size {size} exceeds buffer size {self.buffer_size}. Falling back to direct IDB read for 0x{ea:X}."
                )
                self._cache_misses += 1  # Treat as miss
                direct_bytes = ida_bytes.get_bytes(ea, size)
                if direct_bytes:
                    self._bytes_read_from_idb += len(direct_bytes)
                return direct_bytes
            else:
                # Try sliding the window to cover the start address
                try:
                    self._slide_window(ea)  # Will increment miss counter
                    # Check again if the range is now fully covered
                    if self._is_address_in_buffer(ea) and self._is_address_in_buffer(
                        end_ea - 1
                    ):
                        # Success after sliding
                        start_offset = ea - self.buffer_start_ea
                        end_offset = end_ea - self.buffer_start_ea
                        return bytes(
                            self.buffer[start_offset:end_offset]
                        )  # Return copy
                    else:
                        # Still not covered after sliding (e.g., requested range crosses boundary IDA failed to read)
                        logger.warning(
                            f"Range 0x{ea:X}-0x{end_ea:X} still not in buffer after slide. Falling back to direct IDB read."
                        )
                        # Fallback to direct read
                        direct_bytes = ida_bytes.get_bytes(ea, size)
                        if direct_bytes:
                            self._bytes_read_from_idb += len(direct_bytes)
                        return direct_bytes
                except IndexError as e:
                    # _slide_window failed
                    logger.error(
                        f"Failed to load buffer for range 0x{ea:X}-0x{end_ea:X}: {e}"
                    )
                    return None

    def is_valid_address(self, ea: int) -> bool:
        """Checks if the address is within the buffer or potentially loadable."""
        if self._is_address_in_buffer(ea):
            return True
        # Check IDA's idea of validity if not in buffer
        return ida_bytes.is_loaded(ea)

    def get_stats(self) -> dict:
        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "bytes_read_from_idb": self._bytes_read_from_idb,
            "current_buffer_range": (
                f"[0x{self.buffer_start_ea:X} - 0x{self.buffer_end_ea:X})"
                if self.buffer_start_ea != idaapi.BADADDR
                else "Empty"
            ),
        }


text_segment = ida_segment.get_segm_by_name(".text")
text_buffer = MemBackedBuffer(
    buffer_size=text_segment.size(), preload_ea=text_segment.start_ea
)


@dataclass(repr=False)
class BytePattern:
    """
    Encapsulates a parsed byte pattern and its associated mask.
    Supports wildcards:
      - For string input:
          "??" indicates a full byte wildcard.
          "1?" or "?F" indicates a nibble wildcard (which enables nibble-level matching).
          Spaces are ignored.
      - For bytes-like input, the value -1 represents any byte.
        However, if the user passes in a bytes object that looks textual
        (i.e. contains spaces or "?" characters), then it is decoded and processed
        as a string pattern.
    The conversion is done once and cached.
    """

    original: typing.Union[str, BytesData]
    pattern: bytes = field(init=False)
    mask: bytes = field(init=False)
    nibble_mode: bool = field(init=False, default=False)

    def __repr__(self):
        return (
            f"BytePattern(original='{self.original}', "
            f"pattern={self.pattern.hex().upper()}, "
            f"mask={self.mask.hex().upper()}, "
            f"nibble_mode={self.nibble_mode})"
        )

    def __post_init__(self) -> None:
        # If the input is a string, parse directly as string.
        if isinstance(self.original, str):
            self._parse_str_pattern(self.original)
        # For bytes, check if it decodes as text and appears to be a pattern.
        elif isinstance(self.original, bytes):
            try:
                decoded = self.original.decode("ascii")
                # If decoded string contains spaces or '?' then treat it as a string pattern.
                if "?" in decoded or " " in decoded:
                    warnings.warn(
                        "Bytes input appears to be a textual representation; decoding and processing as string pattern."
                    )
                    self._parse_str_pattern(decoded)
                else:
                    self._parse_bytes_pattern(self.original)
            except Exception:
                # If decoding fails, fall back to bytes parsing.
                self._parse_bytes_pattern(self.original)
        else:
            self._parse_bytes_pattern(self.original)

        # logger.debug("Parsed %r", self)

    def _parse_str_pattern(self, s: str) -> None:
        """
        Parse a hex string pattern with wildcards.
        Acceptable wildcards:
          - "??": full byte wildcard.
          - A hex pair with one unknown nibble (e.g., "1?" or "?F") for nibble-level wildcard.
        Spaces in the input are ignored.
        """
        # Remove spaces and ensure even number of characters.
        clean_seq = "".join(["??" if p == "?" else p for p in s.split(" ") if p])
        if len(clean_seq) % 2 != 0:
            raise ValueError(
                f"Hex pattern ({s}) when spaces are removed ({clean_seq}) length must be even (each byte consists of two hex digits)."
            )

        pattern_bytes = bytearray()
        mask_bytes = bytearray()
        self.nibble_mode = False

        for i in range(0, len(clean_seq), 2):
            high_char = clean_seq[i]
            low_char = clean_seq[i + 1]
            if high_char == "?" and low_char == "?":
                # Full byte wildcard.
                pattern_bytes.append(0x00)  # Dummy value; not used.
                mask_bytes.append(0x00)
            elif high_char == "?" or low_char == "?":
                # Nibble wildcard detected.
                self.nibble_mode = True
                if high_char == "?" and low_char != "?":
                    try:
                        low_nibble = int(low_char, 16)
                    except ValueError:
                        raise ValueError(f"Invalid hex digit: {low_char}")
                    pattern_bytes.append(low_nibble)
                    mask_bytes.append(0x0F)  # Only the low nibble is significant.
                elif low_char == "?" and high_char != "?":
                    try:
                        high_nibble = int(high_char, 16)
                    except ValueError:
                        raise ValueError(f"Invalid hex digit: {high_char}")
                    pattern_bytes.append(high_nibble << 4)
                    mask_bytes.append(0xF0)  # Only the high nibble is significant.
                else:
                    raise ValueError("Invalid pattern with nibble wildcard.")
            else:
                try:
                    byte_val = int(high_char + low_char, 16)
                except ValueError:
                    raise ValueError(f"Invalid hex digits: {high_char}{low_char}")
                pattern_bytes.append(byte_val)
                mask_bytes.append(0xFF)

        self.pattern = bytes(pattern_bytes)
        self.mask = bytes(mask_bytes)

    def _parse_bytes_pattern(self, data: BytesData) -> None:
        """
        Parse a bytes-like or list-based pattern.
        Acceptable wildcard:
          - -1 represents any byte.
        """
        if not (
            isinstance(data, (bytes, bytearray))
            or (
                isinstance(data, list)
                and all(isinstance(b, int) and -1 <= b < 256 for b in data)
            )
        ):
            raise TypeError(
                "byte pattern must be a list of ints (-1 or 0-255), bytes, or bytearray"
            )

        if isinstance(data, (bytes, bytearray)):
            byte_list = list(data)
        else:
            byte_list = data

        pattern_bytes = bytearray()
        mask_bytes = bytearray()
        for b in byte_list:
            if b == -1:
                pattern_bytes.append(0x00)  # Dummy value.
                mask_bytes.append(0x00)
            else:
                pattern_bytes.append(b)
                mask_bytes.append(0xFF)
        self.pattern = bytes(pattern_bytes)
        self.mask = bytes(mask_bytes)
        self.nibble_mode = (
            False  # For pure bytes input we don't expect partial wildcards.
        )


# class ByteSequenceFinder:
#     """
#     Encapsulates the logic for searching a byte sequence in IDA's address space.
#     The pattern is parsed and cached in a BytePattern instance.

#     >>> finder = ByteSequenceFinder("1? ?? 34", start=0x1000, end=0x2000)
#     >>> for ea in finder.find_iter():
#     >>>     logger.info("Match found at 0x%X", ea)
#     """

#     def __init__(
#         self,
#         # TODO: this should be updated to use a ByteMemSearcher as well as an IDBSearcher
#         start: int | ida_range.range_t,
#         pattern: typing.Union[str, BytesData] | BytePattern | None = None,
#         end: int | None = idaapi.BADADDR,
#         max_distance: typing.Union[int, None] = None,
#         direction: int = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
#     ) -> None:

#         if isinstance(start, ida_range.range_t):
#             start, end = start.start_ea, start.end_ea

#         # IDA has a bug where basically BIN_SEARCH_BACKWARD does not work. we have to manually handle it
#         # so we have to check for it and adjust the max_distance accordingly
#         if (direction & ida_bytes.BIN_SEARCH_BACKWARD) == ida_bytes.BIN_SEARCH_BACKWARD:
#             _direction = "backward"
#             # if we did not set an end address
#             #  and if max_distance is set, end address is start - max_distance
#             #  otherwise we use the imagebase
#             if not end or end == idaapi.BADADDR:
#                 end = (
#                     idaapi.get_imagebase() if not max_distance else start - max_distance
#                 )
#             # now IDA's bug is that it will not search backwards if the end address is before the start address
#             # so we have to swap them if that's the case
#             if end < start:
#                 start, end = end, start
#             _range = f"0x{start:X} - 0x{end:X}"
#             # also, if max_distance is set, we have to set it to None since there's a bug in IDA
#             # where it will set the end address to the start address + max_distance, which is not
#             # what we want
#             if max_distance:
#                 max_distance = None
#         else:
#             direction |= ida_bytes.BIN_SEARCH_FORWARD
#             _direction = "forward"
#             if not end and max_distance:
#                 end = start + max_distance
#             _range = f"0x{start:X} - 0x{end:X}"

#         # must set this after the above!
#         self.direction = direction
#         self.start = start
#         self.end = end
#         self.max_distance = max_distance
#         self.byte_pattern = pattern
#         logger.debug(
#             "ByteSequenceFinder searching %s within range: %s %s",
#             _direction,
#             _range,
#             f"for pattern: {self.byte_pattern.original}" if self.byte_pattern else "",
#         )

#     def with_pattern(
#         self, pattern: typing.Union[str, BytesData] | BytePattern
#     ) -> "ByteSequenceFinder":
#         if isinstance(pattern, BytePattern):
#             self._pattern = pattern
#         else:
#             self._pattern = BytePattern(pattern)
#         return self

#     @property
#     def byte_pattern(self) -> BytePattern:
#         return self._pattern

#     @byte_pattern.setter
#     def byte_pattern(self, pattern: typing.Union[str, BytesData] | BytePattern | None):
#         if pattern:
#             self.with_pattern(pattern)
#         else:
#             self._pattern = None

#     def _matches_at(self, addr: int) -> bool:
#         """
#         Check whether the byte pattern matches at a given address using a nibble-level comparison.
#         """
#         pat_len = len(self.byte_pattern.pattern)
#         for i in range(pat_len):
#             actual_byte = ida_bytes.get_byte(addr + i)
#             if (actual_byte & self.byte_pattern.mask[i]) != (
#                 self.byte_pattern.pattern[i] & self.byte_pattern.mask[i]
#             ):
#                 return False
#         return True

#     def _find_next_manual(self, current: int) -> int:
#         """
#         Perform a nibble-level search by manually iterating the address range.
#         """
#         pat_len = len(self.byte_pattern.pattern)
#         addr = current
#         while addr <= self.end - pat_len:
#             if self._matches_at(addr):
#                 return addr
#             addr += 1
#         return idaapi.BADADDR

#     def _find_next_optimized(self, current: int) -> int:
#         """
#         Perform an optimized search using IDA's ida_bytes.find_bytes function.
#         This is used when the pattern does not require nibble-level matching.
#         """
#         ea = ida_bytes.find_bytes(
#             bs=self.byte_pattern.pattern,
#             range_start=current,
#             range_size=self.max_distance,
#             range_end=self.end,
#             mask=self.byte_pattern.mask,
#             flags=self.direction,
#         )
#         return ea

#     def find_iter(self) -> typing.Iterator[int]:
#         """
#         Yield all effective addresses where the byte sequence is found.
#         """
#         current = self.start
#         while True:
#             if self.byte_pattern.nibble_mode:
#                 ea = self._find_next_manual(current)
#             else:
#                 ea = self._find_next_optimized(current)
#             if ea == idaapi.BADADDR:
#                 break
#             yield ea
#             current = ea + 1


#     __iter__ = find_iter


# --- Updated ByteSequenceFinder ---
class ByteSequenceFinder:
    """
    Encapsulates the logic for searching a byte sequence in IDA's address space.
    Uses a ByteBuffer for potentially optimized byte access during manual search.
    """

    def __init__(
        self,
        start: int | ida_range.range_t,
        pattern: typing.Union[str, BytesData] | BytePattern | None = None,
        end: int | None = idaapi.BADADDR,
        max_distance: typing.Union[int, None] = None,
        direction: int = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
        byte_buffer: ByteBuffer | None = None,  # Accept a buffer instance
    ) -> None:

        if isinstance(start, ida_range.range_t):
            _start, _end = start.start_ea, start.end_ea
        else:
            _start = start
            _end = end

        # --- Determine effective search range and direction string ---
        is_backward = (
            direction & ida_bytes.BIN_SEARCH_BACKWARD
        ) == ida_bytes.BIN_SEARCH_BACKWARD
        _direction_str = "backward" if is_backward else "forward"

        if is_backward:
            # Logic to determine the actual range [effective_start, effective_end) for backward search
            self.manual_search_start = (
                _start  # Where the user wants to start searching *from*
            )
            if max_distance is not None:
                effective_start = max(idaapi.inf_get_min_ea(), _start - max_distance)
            elif _end is not None and _end != idaapi.BADADDR and _end < _start:
                effective_start = _end  # User specified a lower bound
            else:
                effective_start = idaapi.inf_get_min_ea()  # Default to min EA

            effective_end = (
                _start + 1
            )  # Search up to and including the original start address
            self.search_limit = effective_start  # The lowest address to check

            # For ida_bytes.find_bytes (if used backward), IDA expects range_start < range_end
            self.ida_find_range_start = effective_start
            self.ida_find_range_end = effective_end

        else:  # Forward search
            direction |= ida_bytes.BIN_SEARCH_FORWARD
            effective_start = _start
            self.manual_search_start = (
                _start  # Where the user wants to start searching *from*
            )
            if max_distance is not None:
                effective_end = _start + max_distance
            elif _end is not None and _end != idaapi.BADADDR:
                effective_end = _end
            else:
                effective_end = idaapi.inf_get_max_ea()  # Default to max EA

            self.search_limit = effective_end  # The address limit (exclusive)
            self.ida_find_range_start = effective_start
            self.ida_find_range_end = effective_end

        _range_str = f"0x{effective_start:X} - 0x{effective_end:X}"  # Logical range

        # --- Initialize buffer ---
        if byte_buffer is None:
            # Default to MemBackedBuffer, preload near the start of the search activity
            preload_addr = self.manual_search_start
            # Adjust preload hint for backward search to be near the end of the range
            if is_backward:
                # Preload somewhere within the range [search_limit, manual_search_start]
                preload_addr = max(
                    self.search_limit,
                    self.manual_search_start - MemBackedBuffer.DEFAULT_BUFFER_SIZE // 4,
                )

            logger.debug(
                f"Initializing default MemBackedBuffer, preloading near 0x{preload_addr:X}"
            )
            self.buffer = MemBackedBuffer(preload_ea=preload_addr)
            self._owns_buffer = True  # Flag to indicate we should report stats
        else:
            logger.debug(f"Using provided {type(byte_buffer).__name__}.")
            self.buffer = byte_buffer
            self._owns_buffer = False

        # --- Set other members ---
        self.direction = direction
        # Note: self.start/end/max_distance might be less relevant now range is calculated above
        # Keep them for reference or potential other uses if needed.
        self.orig_start = _start
        self.orig_end = _end
        self.orig_max_distance = max_distance

        self.byte_pattern = pattern  # Property setter handles parsing

        logger.debug(
            f"ByteSequenceFinder searching %s within logical range: %s %s",
            _direction_str,
            _range_str,
            f"for pattern: {self.byte_pattern.original}" if self.byte_pattern else "",
        )
        # Log buffer type only if it's the default one we created
        if self._owns_buffer and isinstance(self.buffer, MemBackedBuffer):
            logger.debug(f"MemBackedBuffer stats: {self.buffer.get_stats()}")

    def __del__(self):
        # Print stats when the finder is destroyed if we created the buffer
        if (
            self._owns_buffer
            and isinstance(self.buffer, MemBackedBuffer)
            and hasattr(self, "buffer")
        ):
            logger.debug(
                f"Final MemBackedBuffer stats for finder starting at 0x{self.orig_start:X}: {self.buffer.get_stats()}"
            )

    def with_pattern(
        self, pattern: typing.Union[str, BytesData] | BytePattern
    ) -> "ByteSequenceFinder":
        """Sets or updates the search pattern."""
        if isinstance(pattern, BytePattern):
            self._pattern = pattern
        else:
            self._pattern = BytePattern(pattern)
        return self

    @property
    def byte_pattern(self) -> BytePattern:
        """Gets the current BytePattern."""
        if not hasattr(self, "_pattern"):
            self._pattern = None
        return self._pattern

    @byte_pattern.setter
    def byte_pattern(self, pattern: typing.Union[str, BytesData] | BytePattern | None):
        """Sets the search pattern."""
        if pattern:
            self.with_pattern(pattern)
        else:
            self._pattern = None

    def _matches_at(self, addr: int) -> bool:
        """
        Check if the byte pattern matches at a given address using the buffer.
        Prefers reading the whole chunk needed for the match at once.
        """
        if not self.byte_pattern:
            return False  # Should not happen if called from find_iter

        pat_len = len(self.byte_pattern.pattern)
        if pat_len == 0:
            return True  # Empty pattern matches anywhere? Or False? Let's say False.

        try:
            # Optimization: read the whole chunk needed using the buffer
            chunk = self.buffer.get_bytes(addr, pat_len)
            if (
                chunk is None or len(chunk) != pat_len
            ):  # Buffer couldn't provide the full bytes
                # logger.debug(f"Buffer failed to provide {pat_len} bytes at 0x{addr:X} for matching.")
                return False  # Cannot match if we can't get the bytes

            # Compare using the retrieved chunk
            pattern_p = self.byte_pattern.pattern
            pattern_m = self.byte_pattern.mask
            for i in range(pat_len):
                # Byte-wise comparison using the mask
                if (chunk[i] & pattern_m[i]) != (pattern_p[i] & pattern_m[i]):
                    return False  # Mismatch found
            # If loop completes, all bytes match
            return True

        except IndexError:
            # This implies addr or addr+pat_len is outside readable/buffered range
            # logger.debug(f"IndexError during match check at 0x{addr:X} (length {pat_len})")
            return False  # Cannot match if bytes are out of bounds

    def _find_next_manual_forward(self, current: int) -> int:
        """Perform a manual byte-by-byte search FORWARD using the buffer."""
        pat_len = len(self.byte_pattern.pattern)
        if pat_len == 0:
            return idaapi.BADADDR

        addr = current
        # Search up to the limit, ensuring the pattern *starts* before the limit
        # The last possible start address is self.search_limit - pat_len
        while addr <= self.search_limit - pat_len:
            if self._matches_at(addr):
                return addr
            addr += 1
        return idaapi.BADADDR

    def _find_next_manual_backward(self, current: int) -> int:
        """Perform a manual byte-by-byte search BACKWARD using the buffer."""
        pat_len = len(self.byte_pattern.pattern)
        if pat_len == 0:
            return idaapi.BADADDR

        # `current` is the address to start searching *from* (inclusive).
        # Search down to `self.search_limit` (inclusive).
        addr = current
        while addr >= self.search_limit:
            # Check if the pattern starting at 'addr' fits within memory bounds conceptually
            # (The buffer access in _matches_at handles actual read boundaries)
            if self._matches_at(addr):
                return addr
            addr -= 1
        return idaapi.BADADDR

    def _find_next_optimized(self, current: int) -> int:
        """Perform optimized search using ida_bytes.find_bytes."""
        # Optimized search uses IDA's backend, doesn't directly benefit from our Python buffer
        # `current` acts as the resume hint for forward search, but its effect on
        # backward search in ida_bytes is less clear/reliable for iteration.

        is_backward = self.direction & ida_bytes.BIN_SEARCH_BACKWARD

        if is_backward:
            # WARNING: Iterating backward with ida_bytes.find_bytes might not work as expected.
            # It typically finds the *last* occurrence in the *entire* range on the first call.
            # Subsequent calls are not guaranteed to find the next one down.
            # We'll only call it once reliably for backward search in find_iter.
            if current != self.manual_search_start:
                logger.warning(
                    "Iterative optimized backward search requested but likely unreliable. Stopping."
                )
                return idaapi.BADADDR
            # For the first call, use the full calculated range
            start_range = self.ida_find_range_start
            end_range = self.ida_find_range_end
        else:  # Forward
            # Start searching from 'current' within the overall range
            start_range = current
            end_range = self.ida_find_range_end

        # Ensure start_range is not beyond end_range
        if start_range >= end_range:
            return idaapi.BADADDR  # Invalid range

        ea = ida_bytes.find_bytes(
            bs=self.byte_pattern.pattern,
            range_start=start_range,
            range_end=end_range,
            mask=self.byte_pattern.mask,
            flags=self.direction,
        )

        return ea

    def find_iter(self) -> typing.Iterator[int]:
        """Yield all effective addresses where the byte sequence is found."""
        if not self.byte_pattern:
            logger.error("No byte pattern set for search.")
            return

        is_backward = self.direction & ida_bytes.BIN_SEARCH_BACKWARD
        # Use manual search if nibble mode is enabled
        use_manual_search = self.byte_pattern.nibble_mode

        # Start searching from the logical start point for the direction
        current = self.manual_search_start

        logger.debug(
            f"Starting find_iter: manual_start=0x{self.manual_search_start:X}, limit=0x{self.search_limit:X}, backward={is_backward}, manual={use_manual_search}"
        )

        while True:
            ea = idaapi.BADADDR
            if use_manual_search:
                if is_backward:
                    # Check if current is still within valid search range before calling
                    if current < self.search_limit:
                        break
                    ea = self._find_next_manual_backward(current)
                else:
                    # Check if current is still within valid search range before calling
                    if current >= self.search_limit:
                        break
                    ea = self._find_next_manual_forward(current)
            else:  # Optimized search
                if is_backward:
                    # Only perform optimized backward search *once*
                    if current == self.manual_search_start:
                        ea = self._find_next_optimized(current)
                        # Prevent further optimized backward loops
                        current = (
                            self.search_limit - 1
                        )  # Effectively stops next iteration check
                    else:
                        ea = idaapi.BADADDR  # Stop iteration
                else:  # Forward optimized search
                    # Check if current is still within valid search range
                    if current >= self.search_limit:
                        break
                    ea = self._find_next_optimized(current)

            if ea == idaapi.BADADDR:
                logger.debug("Search ended by find function returning BADADDR.")
                break  # No match found or end of search range reached by find function

            # --- Validate the found address against the search limits ---
            # This is an extra safeguard, the find functions should respect limits.
            if is_backward:
                if ea < self.search_limit:
                    logger.debug(
                        f"Backward search found 0x{ea:X} below limit 0x{self.search_limit:X}. Stopping."
                    )
                    break
                # Ensure it's not above the initial starting point (shouldn't happen)
                if ea > self.manual_search_start:
                    logger.warning(
                        f"Backward search found 0x{ea:X} > start 0x{self.manual_search_start:X}. Stopping."
                    )
                    break
            else:  # Forward
                if ea >= self.search_limit:
                    logger.debug(
                        f"Forward search found 0x{ea:X} at/beyond limit 0x{self.search_limit:X}. Stopping."
                    )
                    break

            logger.debug(f"Match found at 0x{ea:X}")
            yield ea

            # --- Update current position for the next iteration ---
            if is_backward:
                # Move to the byte *before* the current find to continue searching downward
                current = ea - 1
                # Check if we have gone past the limit
                if current < self.search_limit:
                    logger.debug(
                        "Reached search limit during backward iteration update."
                    )
                    break
            else:
                # Move to the byte *after* the start of the current find
                # If using manual search, advance by 1.
                # If using optimized search, it should find the *next* occurrence >= current+1.
                current = ea + 1  # Advance by at least 1 byte

                # Check if we have gone past the limit
                if current >= self.search_limit:
                    logger.debug(
                        "Reached search limit during forward iteration update."
                    )
                    break

    __iter__ = find_iter


class KeyLengthProcessor:
    def __init__(self):
        self._instructions = 0

    def signatures(self) -> list[bytes]:
        """List of byte signatures (IDA format with wildcards) to search for."""
        return [
            # look for:
            # btr [rcx], eax
            # jnb short xx
            BytePattern("48 ? 44 24 20 0F B3 ? 73 ?"),
            BytePattern("48 ? 44 24 20 0F B3 ? 89 ? ? ? 00 00 73 ?"),
        ]

    def is_valid(self, x: int) -> bool:
        """Checks if the final emulated value (from RCX after div) is valid."""
        return isinstance(x, int) and 0x100 <= x < 0x200

    def find(self, finder):
        """Finds potential locations using signatures."""
        for signature in self.signatures():
            yield from finder(signature)

    def reset(self):
        self._instructions = 0

    def anchor(self, insn: ida_ua.insn_t, max_lookahead: int = 20) -> bool:
        """
        Checks if the given instruction 'insn' is the start of the target sequence.
        It verifies this by looking ahead for specific subsequent instructions.
        """
        # 1. Check if the current instruction is the 'mov [mem/displ], imm' candidate
        mnem = insn.get_canon_mnem().lower()
        if not (
            mnem == "mov"
            and insn.ops[0].type in (ida_ua.o_mem, ida_ua.o_displ)
            and insn.ops[1].type == ida_ua.o_imm
        ):
            return False  # Not the potential start instruction type

        logger.debug(
            "Potential anchor 'mov [mem], imm' found at 0x%X. Looking ahead...", insn.ea
        )

        # 2. Look ahead to verify the sequence
        found_xor_edx = False
        found_add_rax_count = 0
        found_div_ecx = False

        current_ea = insn.ea
        steps = 0
        sequence_ok = True  # Flag to track if sequence structure seems correct

        while steps < max_lookahead:
            next_insn = ida_ua.insn_t()
            # Use next_head to move forward, ensuring we handle instruction sizes correctly
            next_ea = idc.next_head(current_ea)
            if next_ea == idc.BADADDR or ida_ua.decode_insn(next_insn, next_ea) <= 0:
                logger.debug(
                    "Lookahead stopped at 0x%X due to decode error or end.", next_ea
                )
                sequence_ok = False
                break  # Stop if decoding fails or end of segment

            current_ea = next_ea
            steps += 1
            next_mnem = next_insn.get_canon_mnem().lower()
            logger.debug(
                "  [Lookahead %d] 0x%X: %s",
                steps,
                current_ea,
                idc.generate_disasm_line(current_ea, 0),
            )

            # Check for 'xor edx, edx' - must appear before adds and div
            if not found_xor_edx:
                if (
                    next_mnem == "xor"
                    and next_insn.ops[0].type == ida_ua.o_reg
                    and next_insn.ops[1].type == ida_ua.o_reg
                ):
                    reg1_name = idaapi.get_reg_name(next_insn.ops[0].reg, 4)
                    reg2_name = idaapi.get_reg_name(next_insn.ops[1].reg, 4)
                    if reg1_name.lower() == "edx" and reg2_name.lower() == "edx":
                        logger.debug("    Found 'xor edx, edx'")
                        found_xor_edx = True
                        continue  # Move to next instruction
                # If we see add/div before xor edx,edx, the sequence is wrong
                elif next_mnem == "add" or next_mnem == "div":
                    logger.debug(
                        "    Sequence mismatch: Found %s before 'xor edx, edx'",
                        next_mnem,
                    )
                    sequence_ok = False
                    break

            # Check for 'add rax, imm' - must appear after xor edx, edx but before div ecx
            elif not found_div_ecx:
                if (
                    next_mnem == "add"
                    and next_insn.ops[0].type == ida_ua.o_reg
                    and next_insn.ops[1].type == ida_ua.o_imm
                ):
                    reg_name = idaapi.get_reg_name(
                        next_insn.ops[0].reg, 8
                    )  # Check RAX (64-bit)
                    if reg_name.lower() == "rax":
                        logger.debug(
                            "    Found 'add rax, imm' (%d)", found_add_rax_count + 1
                        )
                        found_add_rax_count += 1
                        continue  # Move to next instruction
                # If we see div before enough adds, sequence is wrong (allow intermediate instructions)
                elif next_mnem == "div":
                    # Check if it's the specific 'div ecx'
                    ops = [op for op in next_insn.ops if op.type != ida_ua.o_void]
                    op = ops[1] if len(ops) > 1 else ops[0]  # Divisor operand
                    if op.type == ida_ua.o_reg:
                        reg_name = idaapi.get_reg_name(op.reg, 4)  # Check ECX (32-bit)
                        if reg_name.lower() == "ecx":
                            logger.debug("    Found 'div ecx'")
                            found_div_ecx = True
                            # We found the final part, break lookahead
                            break
                        else:
                            logger.debug(
                                "    Sequence mismatch: Found 'div %s', expected 'div ecx'",
                                reg_name,
                            )
                            sequence_ok = False
                            break
                    else:
                        logger.debug(
                            "    Sequence mismatch: Found 'div' with non-register operand"
                        )
                        sequence_ok = False
                        break

            # If we have already found div ecx, we can stop the lookahead.
            if found_div_ecx:
                break

        # 3. Check if all required instructions were found in the correct order
        #    (Implicitly handled by the state checks during lookahead)
        if sequence_ok and found_xor_edx and found_add_rax_count >= 2 and found_div_ecx:
            logger.info(
                ">>> Valid anchor sequence confirmed starting at 0x%X <<<", insn.ea
            )
            return True  # This 'mov' instruction is the correct anchor

        logger.debug(
            "Anchor candidate at 0x%X rejected. Sequence requirements not met (xor:%s, add>=2:%s, div:%s)",
            insn.ea,
            found_xor_edx,
            found_add_rax_count >= 2,
            found_div_ecx,
        )
        return False  # The sequence after this 'mov' did not match

    def traverse(self, ea: int, max_distance: int = 0x100):
        """Creates Searcher instances to find the anchor."""

        # Search backwards from the location found by the initial signature scan ('ea')
        finder = ByteSequenceFinder(
            ea,
            pattern="48 C7 44 24 ? ? ? ? ? 33 D2 48 8B 44 24 ? FF C6 48",
            max_distance=max_distance,
            direction=ida_bytes.BIN_SEARCH_BACKWARD,
            byte_buffer=text_buffer,
        )

        def search():
            for anchor_ea in finder.find_iter():
                if abs(anchor_ea - ea) > max_distance:
                    continue
                logger.debug("Found possible anchor at 0x%X", anchor_ea)
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, anchor_ea) > 0 and self.anchor(
                    insn, max_lookahead=20
                ):
                    return anchor_ea

        return [search]

    def emulate(
        self, sig_start_ea: int, found_ea: int, debug: bool = False, max_steps: int = 30
    ):
        """Emulates from the found anchor ('start_ea') to 'div ecx'."""
        # This part remains the same: find the 'div ecx' instruction *after* the anchor
        # to determine the emulation end point.
        if found_ea is None:
            # This condition should ideally not be hit if anchor finding is robust
            logger.error(
                "Emulation called with found_ea=None. Anchor not found from 0x%X",
                sig_start_ea,
            )
            return None

        logger.info("Starting emulation analysis from anchor at 0x%X", found_ea)

        # Now traverse downward from the anchor to find the "div ecx" instruction.
        end_ea = None
        current = found_ea
        steps = 0
        while (
            current != idc.BADADDR and steps <= max_steps
        ):  # Added steps <= max_steps check here
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, current)
            if insn_len <= 0:
                logger.warning(
                    "Failed to decode instruction at 0x%X during emulation scan.",
                    current,
                )
                # Attempt to skip potentially bad bytes, could be risky
                next_head = idc.next_head(current)
                if (
                    next_head == idc.BADADDR or next_head <= current
                ):  # Prevent infinite loop
                    logger.error(
                        "Cannot advance past undecodable byte at 0x%X.", current
                    )
                    break
                current = next_head
                continue

            steps += 1
            logger.debug(
                "decoded %s at 0x%X", idc.generate_disasm_line(current, 0), current
            )
            mnem = insn.get_canon_mnem().lower()

            if mnem == "div":
                ops = [op for op in insn.ops if op.type != ida_ua.o_void]
                op = ops[1] if len(ops) > 1 else ops[0]  # Divisor operand

                if op.type == ida_ua.o_reg:
                    reg_name = idaapi.get_reg_name(op.reg, 4)  # 4 bytes for ECX
                    if reg_name and reg_name.lower() == "ecx":
                        # Valid 'div ecx' instruction found. End emulation *after* this instruction.
                        end_ea = current + insn.size
                        logger.info(
                            "Found 'div ecx' target for emulation end at 0x%X", current
                        )
                        break  # Stop search

            # Move to the next instruction's address
            current += insn_len
            # Check if we exceeded max_steps after processing the instruction
            if steps > max_steps:
                logger.warning(
                    "Max steps (%d) reached during emulation scan before finding 'div ecx'. Stopping scan.",
                    max_steps,
                )
                break

        if end_ea is None:
            logger.error(
                "Failed to find 'div ecx' instruction within %d steps downward from anchor 0x%X.",
                max_steps,
                found_ea,
            )
            return None

        logger.info("Emulating code from 0x%X to 0x%X", found_ea, end_ea)
        mu = emulate_range_with_unicorn(found_ea, end_ea, debug)
        if mu is None:
            logger.error(
                "Unicorn emulation failed for range 0x%X - 0x%X", found_ea, end_ea
            )
            return None

        # The value we need is in RCX *before* the division, which Unicorn captures.
        x = mu.reg_read(unicorn.x86_const.UC_X86_REG_RCX)
        logger.info("Final RCX value after emulation: 0x%X (%d)", x, x)

        if self.is_valid(x):
            logger.info("RCX value 0x%X is valid.", x)
            return x
        else:
            logger.warning("RCX value 0x%X is invalid.", x)
            return None


class NumLengthProcessor:

    def signatures(self):
        return [BytePattern("33 D2 48 8B 5C 24")]

    def is_valid(self, x):
        return isinstance(x, int) and 0x1E <= x < 0x100

    def find(self, finder):
        for signature in self.signatures():
            yield from finder(signature)

    def traverse(self, ea: int, max_distance: int = 0x50):
        """Creates Searcher instances to find the anchor."""

        # Search forward from the location found by the initial signature scan ('ea')
        finder = ByteSequenceFinder(
            ea,
            pattern="F7 F1 48 C7",
            max_distance=max_distance,
            byte_buffer=text_buffer,
        )

        def search():
            for anchor_ea in finder.find_iter():
                if abs(anchor_ea - ea) > max_distance:
                    continue
                logger.debug("Found possible anchor at 0x%X", anchor_ea)
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, anchor_ea) > 0:
                    return anchor_ea

        return [search]

    def emulate(
        self, sig_start_ea: int, found_ea: int, debug: bool = False, max_steps: int = 30
    ):
        """Emulates from the found anchor ('start_ea') to 'div ecx'."""
        # This part remains the same: find the 'div ecx' instruction *after* the anchor
        # to determine the emulation end point.
        if sig_start_ea is None:
            # This condition should ideally not be hit if anchor finding is robust
            logger.error(
                "Emulation called with start_ea=None. Anchor not found @ 0x%X", found_ea
            )
            return None

        logger.info("Starting emulation analysis from anchor at 0x%X", sig_start_ea)
        end_ea = sig_start_ea + max_steps
        logger.info("Emulating code from 0x%X to 0x%X", sig_start_ea, end_ea)
        mu = emulate_range_with_unicorn(sig_start_ea, end_ea, debug)
        if mu is None:
            logger.error(
                "Unicorn emulation failed for range 0x%X - 0x%X", sig_start_ea, end_ea
            )
            return None

        x = mu.reg_read(unicorn.x86_const.UC_X86_REG_RCX)
        logger.info("Final RCX value after emulation: 0x%X (%d)", x, x)

        if self.is_valid(x):
            logger.info("RCX value 0x%X is valid.", x)
            return x
        else:
            logger.warning("RCX value 0x%X is invalid.", x)
            return None


class KeyOffsetProcessor:

    def signatures(self):
        return [
            BytePattern(
                "48 C7 ?? 24 ?? ?? ?? ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? F4 FF 48 8B ?? 24 ?? ?? ?? ?? 49 8D"
            ),
            BytePattern(
                "48 C7 ?? 24 ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? F4 FF 48 8B ?? 24 ?? 49 8D"
            ),
        ]

    def is_valid(self, x):
        return isinstance(x, int) and idaapi.get_segm_name(idaapi.getseg(x)) == ".rdata"

    def find(self, finder):
        for signature in self.signatures():
            yield from finder(signature)

    def traverse(self, ea: int, max_distance: int = 0x30):
        """Creates Searcher instances to find the anchor."""

        finder = ByteSequenceFinder(
            ea, pattern="49 8D ??", max_distance=max_distance, byte_buffer=text_buffer
        )

        def search():
            for anchor_ea in finder.find_iter():
                if abs(anchor_ea - ea) > max_distance:
                    continue
                logger.debug("Found possible anchor at 0x%X", anchor_ea)
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, anchor_ea) < 0:
                    continue
                mnem = insn.get_canon_mnem().lower()
                if mnem != "lea" or insn.ops[0].type != ida_ua.o_reg:
                    continue
                dest_reg = idaapi.get_reg_name(insn.ops[0].reg, 8)
                if dest_reg.lower() == "rdi":
                    logger.debug("Found lea rdi @ 0x%X", insn.ea)
                    return anchor_ea

        return [search]

    def emulate(
        self, sig_start_ea: int, found_ea: int, debug: bool = False, max_steps: int = 30
    ):
        if found_ea is None:
            logger.info(
                "No 'lea rdi' instruction found starting from 0x%X", sig_start_ea
            )
            return None

        logger.debug("Found target 'lea rdi' at 0x%X", found_ea)
        logger.debug("0x%X: %s", found_ea, idc.generate_disasm_line(found_ea, 1))
        rva = idc.get_operand_value(found_ea, 1)
        addr = idaapi.get_imagebase() + rva
        if idaapi.get_segm_name(idaapi.getseg(addr)) == ".rdata":
            return addr

        logger.debug(
            "Emulating from:\n\t0x%X: %s\n\t0x%X: %s",
            sig_start_ea,
            idc.generate_disasm_line(sig_start_ea, 1),
            idc.next_head(found_ea),
            idc.generate_disasm_line(idc.next_head(found_ea), 1),
        )
        mu = emulate_range_with_unicorn(sig_start_ea, idc.next_head(found_ea))
        x = mu.reg_read(unicorn.x86_const.UC_X86_REG_RDI)
        logger.info("Final RDI: 0x%X (%d)", x, x)
        return x


def emulate_range_with_unicorn(start_ea, end_ea, debug=False):
    """
    Emulate the code between start_ea and end_ea using Unicorn.
    All registers are initialized to zero.
    A hook is installed to print each instruction as it executes.
    Returns the final value in EAX.
    """
    code_size = end_ea - start_ea
    code = ida_bytes.get_bytes(start_ea, code_size)
    if code is None:
        logger.error(
            "Could not retrieve code bytes from 0x%X to 0x%X", start_ea, end_ea
        )
        return None

    logger.info(
        "Emulating code from 0x%X to 0x%X (size=0x%X)", start_ea, end_ea, code_size
    )
    emulator = UnicornEmulator(debug=True)
    return emulator.emulate(start_ea, end_ea)


def decode_anchor(ea: int) -> typing.Optional[int]:

    def check_instruction(insn: ida_ua.insn_t) -> bool:
        """Helper function to validate if instruction is our target anchor"""
        mnem = insn.get_canon_mnem().lower()
        if (
            mnem == "mov"
            and insn.ops[0].type in (ida_ua.o_mem, ida_ua.o_displ)
            and insn.ops[1].type == ida_ua.o_imm
        ):
            logger.debug("Found mov constant, mem @ 0x%X", insn.ea)
            return True
        return False

    return _search_range(ea, check_instruction)


def find_anchor_and_emulate(ea: int):
    # First, locate the anchor instruction using your preferred method.
    # Here we assume that the anchor has been located (e.g. by a previous decoding loop)
    # and is stored in the variable "anchor". If not found, we print an error and return.
    anchor = decode_anchor(ea)  # Assume decode_anchor() implements your upward search
    if anchor is None:
        logger.info("No anchor (xor reg, reg) found upward from 0x%X" % ea)
        return None

    # Now traverse downward from the anchor to find the "div ecx" instruction.
    end = None
    current = anchor
    while current != idc.BADADDR:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current) <= 0:
            current = idc.next_head(current)
            continue  # Skip if the instruction cannot be decoded
        logger.debug(
            "decoded %s at 0x%X", idc.generate_disasm_line(current, 0), current
        )
        mnem = insn.get_canon_mnem().lower()
        if mnem != "div":
            current = idc.next_head(current)
            continue  # Not a 'div' instruction, skip to next

        # Use a list comprehension to filter out unused operands.
        ops = [op for op in insn.ops if op.type != ida_ua.o_void]
        # For a DIV instruction, the explicit divisor is typically in operand index 1,
        # but if there's only one operand, fall back to operand index 0.
        op = ops[1] if len(ops) > 1 else ops[0]

        if op.type != ida_ua.o_reg:
            current = idc.next_head(current)
            continue  # Operand is not a register

        logger.debug("register: %s", op.reg)
        reg_name = idaapi.get_reg_name(op.reg, 4)  # 4 bytes for a 32-bit register
        logger.debug("reg_name: %s", reg_name)
        if reg_name.lower() != "ecx":
            current = idc.next_head(current)
            continue  # Register is not ECX

        # Valid 'div ecx' instruction found.
        end = (
            current + insn.size
        )  # Use insn.size (or idc.get_item_size(current) if needed)
        logger.debug(
            "Found 'div ecx' at 0x%X: %s",
            current,
            idc.generate_disasm_line(current, 0),
        )
        break

    if end is None:
        logger.info("No 'div ecx' instruction found downward from anchor.")
        return None

    mu = emulate_range_with_unicorn(anchor, end)
    x = mu.reg_read(unicorn.x86_const.UC_X86_REG_RCX)
    logger.info("Final RCX: 0x%X (%d)", x, x)
    return x


def process_signatures(segment, signatures, validators, param_name):
    """
    Iterates through the provided signatures to find and validate a parameter.
    Returns a tuple (value, ea) if a valid parameter is found, or (None, None) otherwise.
    """
    for signature in signatures:
        for ea in find_byte_sequence(segment.start_ea, segment.end_ea, signature):
            logger.debug(f"Found at 0x{ea:X}")
            value = find_anchor_and_emulate(ea)
            logger.debug(f"{param_name} value: %s", hex(value))
            if all(validation(value) for validation in validators):
                logger.info("Valid %s: %s", param_name, hex(value))
                return value, ea
    return None, None


def process_key_offset_signature(segment, signatures, validators):
    """
    Iterates through the provided signatures to find and validate a key offset.
    Returns a tuple (value, ea) if a valid key offset is found, or (None, None) otherwise.
    """
    for signature in signatures:
        for ea in find_byte_sequence(segment.start_ea, segment.end_ea, signature):
            logger.debug(f"Found at 0x{ea:X}")
            value = emulate_until_lea_rdi(ea)
            logger.debug(f"key offset value: %s", hex(value))
            if all(validation(value) for validation in validators):
                logger.info("Key address: 0x%s", hex(value))
                return value, ea
    return None, None


def emulate_until_lea_rdi(start_ea: int):
    """
    Emulates code starting at start_ea until a 'lea rdi' instruction is encountered.
    It then executes that 'lea rdi' instruction and returns the value of RDI after execution.

    The emulation is done in two phases:
      1. From start_ea up to (but not including) the target instruction.
      2. Then emulates the target instruction alone.

    Returns:
        The value in RDI after executing the 'lea rdi' instruction, or None on error.
    """

    # --- Phase 1: Locate the target instruction ---
    def _predicate(insn: ida_ua.insn_t) -> bool:
        """Helper function to validate if instruction is our target anchor"""
        mnem = insn.get_canon_mnem().lower()
        if mnem == "lea" and insn.ops[0].type == ida_ua.o_reg:
            dest_reg = idaapi.get_reg_name(insn.ops[0].reg, 8)
            if dest_reg.lower() == "rdi":
                logger.debug("Found lea rdi @ 0x%X", insn.ea)
                return True
        return False

    target_ea = _search_range(
        start_ea, _predicate, strategy=SearchStrategy.FORWARD_CHUNK
    )

    if target_ea is None:
        logger.info("No 'lea rdi' instruction found starting from 0x%X", start_ea)
        return None

    logger.debug("Found target 'lea rdi' at 0x%X", target_ea)
    logger.debug("0x%X: %s", target_ea, idc.generate_disasm_line(target_ea, 1))
    rva = idc.get_operand_value(target_ea, 1)
    addr = idaapi.get_imagebase() + rva
    if idaapi.get_segm_name(idaapi.getseg(addr)) == ".rdata":
        return addr

    logger.debug(
        "Emulating from:\n\t0x%X: %s\n\t0x%X: %s",
        start_ea,
        idc.generate_disasm_line(start_ea, 1),
        idc.next_head(target_ea),
        idc.generate_disasm_line(idc.next_head(target_ea), 1),
    )
    mu = emulate_range_with_unicorn(start_ea, idc.next_head(target_ea))
    x = mu.reg_read(unicorn.x86_const.UC_X86_REG_RDI)
    logger.info("Final RDI: 0x%X (%d)", x, x)
    return x


def set_type(ea, type_str, name):
    # Parse the declaration into a tinfo_t structure.
    tinfo = idc.parse_decl(type_str, idc.PT_SILENT)
    if not tinfo:
        logger.error("Error parsing type declaration")
        return False
    # Apply the type to the address.
    if idc.apply_type(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
        # Explicitly set the name.
        if idc.set_name(ea, name, idc.SN_NOWARN):
            logger.info("Type and name applied successfully.")
        else:
            logger.info("Type applied but failed to rename.")
        return True
    else:
        logger.error("Failed to apply type.")
        return False


def apply_signature(ea, sig):
    name = idc.get_func_name(ea)
    ret, args = sig
    logger.info(f"apply 0x{ea:x} {name}")
    decl = "{} {}({})".format(ret, name, args)
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    # idc.set_name(ea, name)
    idc.apply_type(ea, prototype_details)


def find_crypto_key():
    segment = ida_segment.get_segm_by_name(".text")

    # def _process_signatures(sig):
    #     """
    #     Iterates through the provided signatures to find and validate a parameter.
    #     Returns a tuple (value, ea) if a valid parameter is found, or (None, None) otherwise.
    #     """
    #     for ea in find_byte_sequence(segment.start_ea, segment.end_ea, sig):
    #         if not ea:
    #             continue
    #         yield ea
    for processor in [KeyLengthProcessor(), NumLengthProcessor(), KeyOffsetProcessor()]:
        for ea in processor.find(
            ByteSequenceFinder(segment, byte_buffer=text_buffer).with_pattern
        ):
            logger.debug(f"Found at 0x{ea:X}")
            for traverser in processor.traverse(ea):
                if found := traverser():
                    max_steps = abs(found - ea)
                    result = processor.emulate(ea, found, max_steps=max_steps)
                    logger.info("Valid %s: %s", processor, hex(result))

    return None, None, None


# def find_crypto_key():
#     segment = ida_segment.get_segm_by_name(".text")
#     # Process key length signatures.
#     per_key_length, _ = process_signatures(
#         segment, KEY_LENGTH_SIGNATURES, KEY_LENGTH_VALIDATION, "key length"
#     )
#     # Optionally use key_length and key_ea as needed.

#     # Process number of keys signatures.
#     num_keys, num_ea = process_signatures(
#         segment, NUM_KEYS_SIGNATURES, NUM_KEYS_VALIDATION, "num keys"
#     )
#     if not per_key_length or not num_keys:
#         logger.error("Failed to find key length or number of keys!")
#         return None, None, None

#     # Optionally use num_keys and num_ea as needed.
#     key_addr, _ = process_key_offset_signature(
#         segment, KEY_OFFSET_SIGNATURES, KEY_OFFSET_VALIDATION
#     )
#     type_str = f"unsigned __int8 g_bufCryptoKey[0x{num_keys:X}][0x{per_key_length:X}];"
#     logger.info(type_str)
#     if not key_addr:
#         logger.error("Failed to find key offset!")
#         return None, None, None

#     logger.info("g_bufCryptoKey address: 0x%X", key_addr)
#     result = set_type(key_addr, type_str, "g_bufCryptoKey")
#     if result:
#         logger.info("Type %s applied successfully.", type_str)
#     else:
#         logger.error("Failed to apply type: %s", type_str)
#     return key_addr, num_keys, per_key_length


def get_garbage_blobs():
    """
    Yields pairs of (garbage_blog_ea, aligned)
    """

    def _check(insn: ida_ua.insn_t) -> bool:
        """Finds the lea rdi, xxxxx or lea rdx, xxxxx before or after"""
        mnem = insn.get_canon_mnem().lower()
        if mnem == "lea" and insn.ops[0].type == ida_ua.o_reg:
            dest_reg = idaapi.get_reg_name(insn.ops[0].reg, 8)
            if dest_reg.lower() == "rdi" or dest_reg.lower() == "rdx":
                logger.debug("Found lea rdi @ 0x%X", insn.ea)
                return True
        return False

    text_seg = idaapi.get_segm_by_name(".text")
    if not text_seg:
        logger.error("Error: .text section not found.")
        return
    for xref in idautils.XrefsTo(text_seg.start_ea):
        ea = xref.frm
        if idc.get_segm_name(ea) != ".text":
            continue

        if idaapi.print_insn_mnem(ea) == "lea":
            yield xref

    if not xref:
        raise StopIteration
    ea = xref.frm
    prev_addr = idc.prev_head(ea)
    next_addr = idc.next_head(ea)

    if idaapi.print_insn_mnem(prev_addr) == "lea":
        gb12 = idc.get_operand_value(prev_addr, 1)
        if gb12 >= ea:
            yield next(idautils.XrefsTo(gb12))

    elif idaapi.print_insn_mnem(next_addr) == "lea":
        gb12 = idc.get_operand_value(next_addr, 1)
        if gb12 >= ea:
            yield next(idautils.XrefsTo(gb12))
    else:
        for strategy in SearchStrategy:
            found = _search_range(prev_addr, _check, max_range=0x30, strategy=strategy)

            if found:
                gb12 = idc.get_operand_value(found, 1)
                if gb12 >= ea:
                    yield next(idautils.XrefsTo(gb12))
                    break


def get_tls_region():
    blobs = []
    for xref in get_garbage_blobs():
        # the garbage blobs have minimum length of 0x1000 to
        # maximum 0x2000 (hardcoded!)
        # so we align the garbage blog ea to the nearest multiple of 0x1000
        # aligned = get_aligned_offset(xref.to)
        blobs.append(xref.to)
    blobs.sort()
    return blobs


def validate_decrypted_data(data: bytes) -> bool:
    """
    Validates the decrypted data by checking if the first qword is zero.
    """
    return data.find(b"\xb9\xf1\xd8\x27\x98") != -1  # adler32 constant


def fnv1a_hash(data: bytes) -> int:
    # FNV-1a 64-bit parameters
    hash_val = 0xCBF29CE484222325  # 14695981039346656037
    prime = 0x100000001B3  # 1099511628211
    mask = 0xFFFFFFFFFFFFFFFF  # 64-bit mask

    for b in data:
        hash_val ^= b
        hash_val = (hash_val * prime) & mask
    return hash_val


def nonstd_rc4(input_buf: bytes | bytearray, key: bytes | bytearray) -> bytearray:
    """
    Performs the core RC4-variant encryption/decryption logic.

    Args:
        input_buf: The data to process (plaintext or ciphertext).
        key: The key to use

    Returns:
        A bytearray containing the processed data (ciphertext or plaintext).
    """
    key_size = len(key)
    if key_size == 0:
        # Handle zero-length key case if necessary, maybe return input unmodified?
        # C++ might crash or have UB, Python needs explicit handling.
        # Let's mimic potential C++ behavior of modulo by zero error indirectly
        # by raising an error, or return input as is. For now, raise error.
        raise ValueError("Key size cannot be zero")

    # KSA (Key Scheduling Algorithm) - Standard RC4 part
    state = bytearray(range(256))
    j = 0
    for k in range(256):
        j = (j + state[k] + key[k % key_size]) & 0xFF
        state[k], state[j] = state[j], state[k]  # Swap

    # PRGA (Pseudo-Random Generation Algorithm) & XOR - Non-standard part
    x = 0
    y = 0
    output_buf = bytearray(len(input_buf))
    for m in range(len(input_buf)):
        x = (x + 1) & 0xFF
        y = (y + state[x]) & 0xFF
        state[x], state[y] = state[y], state[x]  # Swap
        # Keystream byte is state[y] AFTER the swap (Non-standard RC4)
        keystream_byte = state[y]
        output_buf[m] = input_buf[m] ^ keystream_byte

    return output_buf


def rc4_serial_decrypt(
    ciphertext: bytes | bytearray, key: bytes | bytearray, serial_iv: int
) -> tuple[bytearray, int]:
    """
    Decrypts data encrypted with a "serial" rc4 function that depends on a continguous
    hash as an initialization vector.

    Args:
        ciphertext: The encrypted data buffer.
        key: The original encryption key (pKey in C++).
        serial_iv: The value of the s_IV *before* it was updated
                      with the plaintext hash during the corresponding
                      encryption call for this block.

    Returns:
        A tuple containing:
        - decrypted_plaintext (bytearray): The decrypted data.
        - next_iv (int): The FNV-1a hash of the decrypted plaintext,
                           which should be used as the serial_iv for the
                           *next* sequential block, if any.
    """
    n_key_size = len(key)
    if n_key_size == 0:
        raise ValueError("Original key size cannot be zero")

    # 1. Recreate the seededKey using the original key and the serial_iv
    _seeded_key = bytearray(n_key_size)
    # Use 'little' endian consistent with potential C++ struct/union access
    # Assuming little-endian based on common architectures.
    s_iv_bytes = serial_iv.to_bytes(
        8, byteorder=sys.byteorder
    )  # Use system byte order or specify 'little'/'big' if known

    for i in range(n_key_size):
        _seeded_key[i] = s_iv_bytes[i % 8] ^ key[i]

    # 2. Decrypt using the core nonstd rc4 logic and the seeded key
    decrypted_plaintext = nonstd_rc4(ciphertext, _seeded_key)

    # 3. Calculate the FNV-1a hash of the decrypted plaintext
    next_iv = fnv1a_hash(decrypted_plaintext)

    return decrypted_plaintext, next_iv


class RC4PEDecryptor:
    def __init__(
        self,
        crypto_matrix,
        sections_to_decrypt,
        tls_region=None,
        multipage_relocs=None,
        dryrun=False,
        patch_mode="patch",
        max_pages=None,
        page_size=PAGE_SIZE,
    ):
        """
        Initialize the RC4 PE decryptor

        Args:
            crypto_matrix: n-by-m matrix of crypto keys
            sections_to_decrypt: List of section names to decrypt
            tls_region: Dictionary with 'start' and 'end' addresses for TLS region to skip
            multipage_relocs: List of dictionaries with 'rva' and 'size' keys
            dryrun: If True, perform decryption without patching IDA database
            patch_mode: "patch" (allows undo) or "put" (destructive)
            max_pages: Maximum number of pages to decrypt (None = all pages)
        """
        self.crypto_matrix = crypto_matrix
        self.num_keys = len(crypto_matrix)
        self.per_key_size = len(crypto_matrix[0])
        self.sections_to_decrypt = sections_to_decrypt
        self.dryrun = dryrun
        self.patch_mode = patch_mode.lower()
        self.max_pages = max_pages
        self.page_size = page_size

        if self.patch_mode not in ["patch", "put"]:
            logger.warning("Invalid patch_mode. Using 'patch' mode by default.")
            self.patch_mode = "patch"

        # Default values for optional parameters
        self.tls_region = tls_region or {"start": 0, "end": 0}
        self.multipage_relocs = multipage_relocs or []

        # Store decryption results when in dryrun mode
        self.decryption_results = {}

        # Running hash for serial encryption
        self.reset_state()

    def reset_state(self):
        """Reset the decryption state (page_hash) for a new section"""
        self.page_hash = 0

    def get_pe_sections(self):
        """Get PE section information from IDA"""
        sections = []
        for seg_idx in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(seg_idx)
            if not seg:
                continue

            name = idaapi.get_segm_name(seg)
            sections.append(
                {
                    "name": name,
                    "start": seg.start_ea,
                    "size": seg.end_ea - seg.start_ea,
                    "vaddr": seg.start_ea
                    - idaapi.get_imagebase(),  # Relative virtual address
                }
            )
        return sections

    def hexdump(self, data, addr, bytes_per_line=16, joined=True):
        """Create a hexdump of data for display"""
        result = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i : i + bytes_per_line]
            hex_values = " ".join(f"{b:02X}" for b in chunk)
            ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            result.append(
                f"{addr+i:08X}: {hex_values.ljust(bytes_per_line*3)} {ascii_values}"
            )
        return "\n".join(result) if joined else result

    def apply_patch(self, addr, data):
        """Apply the patch using the selected method"""
        if self.patch_mode == "patch":
            return ida_bytes.patch_bytes(addr, data)
        else:  # "put" mode
            return ida_bytes.put_bytes(addr, data)

    def adjust_decryption_for_multipage_relocs(
        self, decrypt_addr, decrypt_size, start_rva
    ):
        """Adjust decryption range for multipage relocations"""
        end_rva = decrypt_size + start_rva

        for reloc in self.multipage_relocs:
            if reloc["rva"] < start_rva and reloc["rva"] + reloc["size"] > start_rva:
                overlap = reloc["rva"] + reloc["size"] - start_rva
                decrypt_addr += overlap
                decrypt_size -= overlap

            if reloc["rva"] < end_rva and reloc["rva"] + reloc["size"] > end_rva:
                decrypt_size -= end_rva - reloc["rva"]

        return decrypt_addr, decrypt_size

    def decrypt_page(self, binary, crypt_key):
        """
        Decrypt a page of data using a serial hash-based RC4 algorithm

        Args:
            binary: the page data to decrypt
            crypt_key: a bytearray of the key to decrypt this page with

        Returns:
            True if successful
        """
        try:
            decrypted_data, self.page_hash = rc4_serial_decrypt(
                binary,
                crypt_key,
                self.page_hash,
            )
        except Exception as e:
            logger.error("Error decrypting page: %s", e)
            return False, None

        return True, decrypted_data

    def decrypt(self):
        """Decrypt all target sections in the PE file"""
        # Get all PE sections
        pe_sections = self.get_pe_sections()
        logger.debug(f"[+] Found {len(pe_sections)} sections in the PE file")

        if self.dryrun:
            logger.info("[!] Running in DRYRUN mode - no bytes will be patched")
        else:
            logger.info(
                f"[!] Patching mode: {self.patch_mode.upper()} ({'allows undo' if self.patch_mode == 'patch' else 'destructive'})"
            )

        # Track the total number of pages processed
        total_pages_processed = 0

        # Process each section
        for section in pe_sections:
            # Check if this section should be decrypted
            if section["name"].lower() not in [
                s.lower() for s in self.sections_to_decrypt
            ]:
                logger.info(f"[+] Skipping section: {section['name']}")
                continue

            # Reset the page hash for each new section
            self.reset_state()

            section_start = section["start"]
            section_size = section["size"]
            section_va = section["vaddr"]

            # Initialize storage for this section's decryption results
            self.decryption_results[section["name"]] = []

            # Count pages decrypted in this section
            section_pages_processed = 0

            # Decrypt the section in chunks
            for offset in range(0, section_size, self.page_size):
                # Check if we've reached the maximum number of pages
                if self.max_pages is not None and (
                    total_pages_processed >= self.max_pages
                ):
                    logger.info(
                        f"[!] Reached maximum number of pages ({self.max_pages}), stopping decryption"
                    )
                    break

                # Skip TLS region during decryption
                tls_start = self.tls_region.get("start", 0)
                tls_end = self.tls_region.get("end", 0)
                decrypt_addr = section_start + offset

                if tls_start == 0 or (tls_start <= decrypt_addr < tls_end):
                    continue

                memory_offset = section_va + offset
                key_index = (memory_offset // self.page_size) % self.num_keys
                logger.debug(
                    "[+] Using key index: %d (num_keys: %d, key_index %% num_keys: %d) for memory offset 0x%X",
                    key_index,
                    self.num_keys,
                    key_index % self.num_keys,
                    memory_offset,
                )

                chunk_size = min(section_size - offset, self.page_size)

                # Adjust decryption range for multipage relocations
                original_addr = decrypt_addr
                original_size = chunk_size

                if self.multipage_relocs:
                    decrypt_addr, decrypt_size = (
                        self.adjust_decryption_for_multipage_relocs(
                            decrypt_addr, chunk_size, memory_offset
                        )
                    )
                    if decrypt_addr != original_addr or (decrypt_size != original_size):
                        print(
                            f"[DEBUG] Adjusted for relocations: {original_addr:X}->{decrypt_addr:X}, {original_size}->{decrypt_size}"
                        )

                    if decrypt_size <= 0:
                        continue
                else:
                    decrypt_size = chunk_size

                try:
                    # Read the encrypted data from IDA database
                    encrypted_data = idc.get_bytes(decrypt_addr, decrypt_size)
                    # Decrypt the chunk
                    success, decrypted_data = self.decrypt_page(
                        binary=encrypted_data,
                        crypt_key=self.crypto_matrix[key_index],
                    )
                    if not success:
                        logger.error(
                            "[!] Failed to decrypt chunk at 0x%X",
                            decrypt_addr,
                        )
                        continue

                    # In dryrun mode, store the results for inspection
                    chunk_info = {
                        "address": decrypt_addr,
                        "size": decrypt_size,
                        "encrypted": bytes(encrypted_data),
                        "decrypted": bytes(decrypted_data),
                        "hexdump": self.hexdump(
                            decrypted_data[: min(32, decrypt_size)],
                            decrypt_addr,
                        ),
                    }
                    self.decryption_results[section["name"]].append(chunk_info)

                    if self.dryrun:
                        # Print sample of decrypted data
                        logger.info(
                            "[*] Decrypted chunk at 0x%X (size: %d) with key index %d",
                            decrypt_addr,
                            decrypt_size,
                            key_index,
                        )
                        results = self.hexdump(
                            (
                                decrypted_data[:32]
                                if decrypt_size > 32
                                else decrypted_data
                            ),
                            decrypt_addr,
                            joined=False,
                        )
                        for r in results:
                            logger.info(r)

                        if decrypt_size > 32:
                            logger.info("... (truncated) ...")
                    else:
                        # Write back the decrypted data to IDA database
                        self.apply_patch(decrypt_addr, bytes(decrypted_data))
                        logger.info(
                            "[*] Patched decrypted chunk at 0x%X (size: %d)",
                            decrypt_addr,
                            decrypt_size,
                        )

                    # Increment page counters
                    section_pages_processed += 1
                    total_pages_processed += 1

                except Exception as e:
                    logger.error(
                        "[!] Error decrypting chunk at 0x%X: %s",
                        decrypt_addr,
                        e,
                    )

            logger.info(
                f"[+] {'Analyzed' if self.dryrun else 'Decrypted'} {section_pages_processed} pages in '{section['name']}' section using RC4",
            )

            # If we've reached the maximum, exit the loop early
            if self.max_pages is not None and total_pages_processed >= self.max_pages:
                break

        logger.info("[+] Total pages processed: %d", total_pages_processed)
        return self.decryption_results


def extract_2d_array(address, num_keys, per_key_length):
    # Get the raw bytes from the specified address
    raw_bytes = ida_bytes.get_bytes(address, num_keys * per_key_length)

    # Convert the raw bytes into a 2D array
    array_2d = []
    for i in range(num_keys):
        # Calculate the starting position for each key
        start_pos = i * per_key_length
        # Extract the bytes for the current key
        key_bytes = raw_bytes[start_pos : start_pos + per_key_length]
        # Add the key bytes to the 2D array
        array_2d.append(key_bytes)

    return array_2d, raw_bytes


def decrypt_pe_file(
    key_addr,
    num_keys,
    per_key_length,
    tls_offsets,
    dryrun=False,
    patch_mode="patch",
    max_pages=None,
):
    """Helper function to set up and run the decryptor

    Args:
        dryrun: If True, perform decryption without patching IDA database
        patch_mode: "patch" (allows undo) or "put" (destructive)
    """

    g_bufCryptoKey, raw_bytes = extract_2d_array(key_addr, num_keys, per_key_length)
    # Define sections to decrypt - replace with actual section names
    sections_to_decrypt = [".text"]  # Example section names

    # Define TLS region to skip (if any)
    tls_region = {
        "start": tls_offsets[0],  # Replace with actual TLS start address if needed
        "end": tls_offsets[1],  # Replace with actual TLS end address if needed
    }

    # Define multipage relocs (if any)
    multipage_relocs = []  # List of dicts with 'rva' and 'size' keys

    # Create and run the decryptor
    decryptor = RC4PEDecryptor(
        g_bufCryptoKey,
        sections_to_decrypt=sections_to_decrypt,
        tls_region=tls_region,
        multipage_relocs=multipage_relocs,
        dryrun=dryrun,
        patch_mode=patch_mode,
        max_pages=max_pages,
    )

    results = decryptor.decrypt()
    return results


class DecryptException(Exception):
    pass


# There's a bug in IDA's API.
# If you undefine and redefine a function's data, the operands are marked as a disassembly problem.
# This resets each problem in the reanalyzed functions.
def reset_problems_in_function(func_start: int, func_end: int):
    current_address: int = func_start
    while current_address != func_end:
        ida_problems.forget_problem(ida_problems.PR_DISASM, current_address)
        current_address = current_address + 1


def re_analyze(decryption_results: dict):
    text_section = decryption_results[".text"]
    section_start = text_section[0]["address"]
    section_end = text_section[-1]["address"] + text_section[-1]["size"]
    ida_bytes.del_items(
        section_start,
        ida_bytes.DELIT_SIMPLE | ida_bytes.DELIT_EXPAND,
        section_end - section_start,
    )

    # ida_auto.auto_mark_range(section_start, section_end, ida_auto.AU_CODE)

    # attempt to re-analyze the reverted region
    ida_auto.plan_and_wait(section_start, section_end, True)
    reset_problems_in_function(section_start, section_end)
    # ida_auto.plan_range(section_start, section_end)
    # ida_auto.auto_wait()
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
    ida_kernwin.refresh_idaview_anyway()


def execute(decrypt=False, dry_run=False, reanalyze=False):
    print(find_crypto_key())
    return
    key_addr, num_keys, per_key_length = find_crypto_key()
    if not key_addr:
        logger.error("[!] No key extracted")
        return -1
    tls_data = get_tls_region()
    if not tls_data:
        logger.error("[!] tls data offset not found")
        return -1

    decryption_results = None
    if decrypt:
        decryption_results = decrypt_pe_file(
            key_addr,
            num_keys,
            per_key_length,
            tls_data,
            dry_run,
            patch_mode="put",
            max_pages=None,
        )
        if decryption_results:
            logger.info("[+] Decryption succeeded!")
            dump_key(
                key_addr=key_addr,
                num_keys=num_keys,
                per_key_length=per_key_length,
                output_file=pathlib.Path("g_bufCryptKey.json"),
            )
            if reanalyze:
                re_analyze(decryption_results)

        else:
            logger.error("[!] Decryption did not succeed.")


def dump_key(
    key_addr: int = None,
    num_keys: int = None,
    per_key_length: int = None,
    output_file: pathlib.Path = None,
):
    if key_addr is None:
        key_addr, num_keys, per_key_length = find_crypto_key()
        if key_addr is None:
            logger.error("[!] No key extracted")
            return -1
    if output_file is None:
        input_path = pathlib.Path(idc.get_input_file_path())
        output_file = input_path.with_name("g_bufCryptKey.json")

    if output_file.exists():
        logger.warning(f"Key file already exists: {output_file}, skipping")
        return

    logger.info(f"Dumping key to {output_file}")

    # Get the complete binary blob of keys.
    g_bufCryptoKey, raw_bytes = extract_2d_array(key_addr, num_keys, per_key_length)

    # Construct JSON data according to the schema.
    json_data = {
        "g_bufCryptoKey": [list(key) for key in g_bufCryptoKey],
        "key_length": per_key_length,
        "num_keys": num_keys,
        "key_addr": f"0x{key_addr:X}",
    }

    # Write the JSON to the file.
    with output_file.open("w+") as f:
        json.dump(json_data, f, indent=4)


def cli(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Decrypt a binary file.")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the binary")
    parser.add_argument("--dry-run", action="store_true", help="Dry run the decryption")
    args = parser.parse_args()
    execute(decrypt=args.decrypt, dry_run=args.dry_run)


if __name__ == "__main__":
    clear_output()
    configure_logging(log=logger, level=logging.DEBUG)
    execute(decrypt=True, dry_run=False, reanalyze=True)
