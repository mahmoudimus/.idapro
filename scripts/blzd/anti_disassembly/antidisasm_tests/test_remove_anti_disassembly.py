import logging
import os
import pathlib
import unittest

import idapro

# Import the plugin's execute_action and supporting classes
from plugins.mutilz.actions.remove_anti_disassembly import (
    Memory,
    PatchManager,
    configure_logging,
    execute_action,
    logger,
)

configure_logging(log=logger, level=logging.DEBUG)
logger.debug("Starting test")


class TestRemoveAntiDisassembly(unittest.TestCase):
    """
    Test the remove_anti_disassembly plugin's execute_action function
    by loading a raw binary dump and asserting that patch operations
    are discovered and queued.
    """

    def setUp(self):
        # Determine paths and load raw binary data
        script_dir = pathlib.Path(__file__).parent
        bin_file = script_dir.parent / "tmp" / "anti_disasm_test_11.1.0.60228.bin"
        with open(bin_file, "rb") as f:
            self.data = f.read()

        # Define the EA range corresponding to the dump
        self.start_ea = 0x141887CBD
        self.end_ea = 0x1418881EA

        # Monkey-patch Memory.from_ida_range to load from our raw buffer
        Memory.from_ida_range = classmethod(
            lambda cls, start, end: cls.from_buffer(self.data, base=start)
        )

    def test_execute_action_queues_patches(self):
        # Create a dry-run patch manager
        patch_manager = PatchManager(dry_run=True, auto_clear=False)
        # Run the plugin logic on our dump
        execute_action(self.start_ea, self.end_ea, patch_manager, force_analyze=False)
        # Verify that at least one patch was queued
        self.assertGreater(
            len(patch_manager.pending_patches),
            0,
            "No patch operations were queued",
        )

        # Ensure each queued patch lies within the specified EA range
        for patch in patch_manager.pending_patches:
            self.assertGreaterEqual(
                patch.address,
                self.start_ea,
                f"Patch at 0x{patch.address:X} is below start EA",
            )
            self.assertLess(
                patch.address + len(patch.byte_values),
                self.end_ea,
                f"Patch at 0x{patch.address:X} extends beyond end EA",
            )


if __name__ == "__main__":
    unittest.main()
