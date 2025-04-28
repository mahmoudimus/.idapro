import concurrent.futures
import functools
import json
import logging
import multiprocessing
import os
import pathlib
import unittest
from contextlib import asynccontextmanager

import idapro  # type: ignore

from scripts.blzd import mp9

AsyncDeobfuscator = mp9.AsyncDeobfuscator
configure_logging = mp9.configure_logging

logfmt = "%(levelname)s %(name)s: %(message)s"
debug_configure_logging = functools.partial(
    configure_logging, level=logging.DEBUG, fmt_str=logfmt
)
logger = logging.getLogger(__name__)
configure_logging(logger, level=logging.INFO, fmt_str=logfmt)
configure_logging(mp9.logger, level=logging.DEBUG, fmt_str=logfmt)
mp9.configure_logging = debug_configure_logging

# Load raw binary data once
script_dir = pathlib.Path(__file__).parent
bin_file = script_dir.parent / "tmp" / "11.1.0.60228.json"
try:
    with bin_file.open("r") as f:
        ROUTINE_DATA = json.load(f)
except FileNotFoundError:
    logger.error("Routine data file not found: %s", bin_file)
    ROUTINE_DATA = {}
except json.JSONDecodeError:
    logger.error("Error decoding JSON from file: %s", bin_file)
    ROUTINE_DATA = {}


def load_and_generate_tests(cls):
    """Dynamically add test methods to the class for each routine address."""

    # Check for environment variable to filter tests
    filter_addr_str = os.environ.get("TEST_ROUTINE_ADDR")
    if filter_addr_str:
        logger.info("Filtering tests to run only for address: %s", filter_addr_str)
        try:
            # Ensure the provided address is treated as a decimal string key
            int(filter_addr_str)
        except ValueError:
            logger.error(
                "Invalid TEST_ROUTINE_ADDR value: '%s'. Must be a decimal integer string.",
                filter_addr_str,
            )
            filter_addr_str = None  # Disable filtering if invalid

    # Store routine data on the class for access in setUp
    cls.json_data = ROUTINE_DATA

    # Find original test methods (those starting with 'test_')
    original_test_methods = {
        name: getattr(cls, name)
        for name in dir(cls)
        if name.startswith("test_") and callable(getattr(cls, name))
    }

    # Remove original test methods to avoid running them directly
    for name in original_test_methods:
        delattr(cls, name)

    # Create new test methods for each routine address
    for addr_str in ROUTINE_DATA:
        # Apply filtering if the environment variable is set
        if filter_addr_str and addr_str != filter_addr_str:
            continue

        addr_hex = hex(int(addr_str))
        for original_name, original_method in original_test_methods.items():
            # Create a new function that calls the original test method
            # We use a closure to capture the original_method
            def make_test_runner(method_to_run):
                async def test_runner(self):
                    await method_to_run(self)

                return test_runner

            new_test_method = make_test_runner(original_method)
            new_test_name = f"{original_name}_{addr_hex}"
            # Copy necessary attributes from the original method
            new_test_method.__name__ = new_test_name
            new_test_method.__doc__ = original_method.__doc__
            setattr(cls, new_test_name, new_test_method)

    return cls


@load_and_generate_tests
class TestAsyncDeobfuscator(unittest.IsolatedAsyncioTestCase):
    """
    Test the AsyncDeobfuscator stages and ensure final chains match
    the patch addresses discovered by execute_action.
    """

    # Class attribute to store loaded JSON data
    json_data = None

    def setUp(self):
        # Extract routine address from the test method name (e.g., test_stage1_non_empty_0x141887cbd)
        test_id_parts = self.id().split(".")[-1].split("_")
        addr_str = str(
            int(test_id_parts[-1], 16)
        )  # Get the last part (address) and convert to decimal string key

        if addr_str not in self.json_data:
            self.fail(f"Address {addr_str} not found in JSON data.")

        # Define EA range based on the parsed address
        routine = self.json_data[addr_str]
        self.start_ea = routine["addr"]
        self.size = routine["size"]
        self.end_ea = self.start_ea + self.size
        self.data = bytes.fromhex(routine["data"])
        logger.debug(
            "Setting up test for routine 0x%X, data length: %d",
            self.start_ea,
            len(self.data),
        )

        # Provide buffer to AsyncDeobfuscator via a fake shared memory context
        # @asynccontextmanager
        # async def fake_get_buffer(inst):
        #     yield self.data
        # AsyncDeobfuscator._get_buffer = fake_get_buffer  # override
        self._shared_memory = multiprocessing.shared_memory.SharedMemory(
            create=True, size=len(self.data)
        )
        self._shared_memory.buf[: len(self.data)] = self.data
        # Instantiate deobfuscator
        self.deob = AsyncDeobfuscator(
            shm_name=self._shared_memory.name,
            data_size=len(self.data),
            start_ea=self.start_ea,
            is_64bit=True,
            max_workers=1,
            executor=concurrent.futures.ThreadPoolExecutor(max_workers=1),
        )
        self.deob.data = self.data

    def tearDown(self):
        self._shared_memory.close()

        # now tear down the shared memory itself (only the creator should do this)
        try:
            multiprocessing.shared_memory.SharedMemory(
                name=self._shared_memory.name
            ).unlink()
        except FileNotFoundError:
            pass

    async def test_run_matches_expected_addresses(self):
        final = await self.deob.run()
        actual_addresses = sorted(c.overall_start() for c in final)
        logger.info(
            "Actual start addresses for 0x%X: %s",
            self.start_ea,
            [hex(a) for a in actual_addresses],
        )


if __name__ == "__main__":
    unittest.main()
