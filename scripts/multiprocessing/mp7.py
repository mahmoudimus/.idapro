import argparse
import atexit
import concurrent.futures
import json
import logging
import multiprocessing
import multiprocessing.shared_memory as sm
import os
import pathlib
import stat
import sys
import typing
import weakref
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache

logging.basicConfig(level=logging.DEBUG, format="[Plugin:%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class MultiprocessingHelper:
    """
    Static helper class for multiprocessing context and Python interpreter discovery.

    Usage:
        interp = MultiprocessingHelper.get_python_interpreter()
        MultiprocessingHelper.set_multiprocessing_context()
    """

    @staticmethod
    @lru_cache(maxsize=1)
    def get_python_interpreter():
        """
        Gets the path to a suitable Python interpreter.
        Ensures we find a standalone Python executable.

        >>> import pathlib, sys, stat
        >>> interp: pathlib.Path = MultiprocessingHelper.get_python_interpreter()
        ...
        >>>
        """
        if (
            hasattr(sys, "_base_executable")
            and sys._base_executable
            and "python" in pathlib.Path(sys._base_executable).name.lower()
        ):
            logger.debug(f"Using _base_executable: {sys._base_executable}")
            return pathlib.Path(sys._base_executable)

        base_paths = [
            sys.prefix,
            sys.exec_prefix,
            sys.executable,
        ]
        exe_suffix = ".exe" if os.name == "nt" else ""
        python_name = f"python{exe_suffix}"

        def base_dirs():
            for dirname in map(pathlib.Path, base_paths):
                yield dirname
                yield dirname.parent
                yield dirname.parent.parent

        for dirname in base_dirs():
            for basename in ["", "bin", "python"]:
                interp_path = dirname / basename / python_name
                if not interp_path.exists():
                    continue

                if not interp_path.is_file() or not interp_path.is_symlink():
                    continue

                if not interp_path.stat().st_mode & (
                    stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                ):
                    continue

                logger.debug(f"Found Python interpreter at: {interp_path}")
                return interp_path

        logger.warning(
            "Could not determine Python interpreter path, falling back to 'python' in PATH."
        )
        return pathlib.Path("python")

    @staticmethod
    def set_multiprocessing_context():
        """
        Sets up the multiprocessing context to use 'spawn' and sets the Python executable.
        """
        # --- Multiprocessing Context Setup ---
        current_method = multiprocessing.get_start_method(allow_none=True)
        if current_method != "spawn":
            multiprocessing.set_start_method("spawn", force=True)
        multiprocessing.set_executable(
            str(MultiprocessingHelper.get_python_interpreter())
        )
        # multiprocessing.get_context() or multiprocessing.get_context("spawn")


MultiprocessingHelper.set_multiprocessing_context()


def is_ida():
    """
    Crude check to see if running inside IDA.

    Returns True if running inside IDA Pro, else False.
    """
    exec_name = pathlib.Path(sys.executable).name.lower()
    return exec_name.startswith(("ida", "idat", "idaw", "idag"))


class TrackedMemoryView:
    """
    A wrapper for memoryview that tracks active references and exposes the slice protocol.
    When all references are gone, the parent context manager can safely clean up.
    """

    def __init__(self, parent, memview):
        # Store a weak reference to the parent
        self._parent_ref = weakref.ref(parent)
        self._memview = memview
        # Immediately increment the refcount on the parent via the weak reference
        parent_obj = self._parent_ref()
        if parent_obj:
            parent_obj._incref()
        else:
            # This case should ideally not happen right after creation,
            # but defensive programming is good.
            logging.warning(
                "Parent object disappeared immediately after creating TrackedMemoryView."
            )

    def __getitem__(self, item):
        if isinstance(item, slice):
            start, stop, step = item.indices(len(self))
            return TrackedMemoryView(self._parent_ref(), self._memview[start:stop:step])
        else:
            return self._memview[item]

    def __len__(self):
        return len(self._memview)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def tobytes(self):
        return self._memview.tobytes()

    def close(self):
        if self._memview is None:
            return

        parent_obj = self._parent_ref()
        if parent_obj:
            parent_obj._decref()
        else:
            logging.warning(
                "Attempted to _decref on a parent that has already disappeared."
            )

        try:
            self._memview.release()
        except BufferError:
            # If release fails with BufferError, it might already be released.
            # Still set to None to make close idempotent.
            pass
        except Exception as e:
            # Log other unexpected errors during release
            logging.error(f"Error during memoryview release: {e}", exc_info=True)
        finally:
            # Set self._memview to None to make close idempotent
            self._memview = None

    def __del__(self):
        self.close()

    def __repr__(self):
        # Access refcount via the weak reference if the parent still exists
        parent_obj = self._parent_ref()
        refcount_info = (
            f"refs={parent_obj._refcount}" if parent_obj else "parent=<gone>"
        )
        memview_len = len(self) if self._memview is not None else "closed"
        return f"<TrackedMemoryView len={memview_len} {refcount_info}>"


class SharedMemoryChunk:
    """
    Context manager for accessing a chunk of shared memory.
    Proxies the .buf property to a TrackedMemoryView of the specified region.
    Ensures the memoryview is deleted and the shared memory is closed on exit.
    Tracks the number of active TrackedMemoryView references.
    """

    def __init__(self, shm_name: str):
        self.shm_name = shm_name
        self._shm = None
        self._refcount = 0

    def __enter__(self):
        self._shm = sm.SharedMemory(name=self.shm_name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Only close shared memory when all TrackedMemoryView references are gone
        if self._shm is not None and self._refcount == 0:
            self._shm.close()
            self._shm = None

    def _incref(self):
        self._refcount += 1

    def _decref(self):
        self._refcount -= 1

    @property
    def buf(self):
        """
        Returns the raw memoryview of the shared memory buffer.
        The user is responsible for wrapping slices in TrackedMemoryView
        if reference counting is needed for those slices.
        """
        # return self._shm.buf
        return TrackedMemoryView(self, memoryview(self._shm.buf))


if is_ida():
    from PyQt5 import QtCore
    from PyQt5.QtCore import QProcessEnvironment

    import ida_bytes
    import ida_segment
    import idaapi

    WORKER_SCRIPT_PATH = pathlib.Path(__file__)

    class DataProcessingBroker(QtCore.QProcess):
        """
        Manages the external worker process using QProcess for command/status.
        Relies on shared memory for large data transfer.
        """

        ## Signals emitted by the broker

        #: For simple status updates like "ping", "results_ready"
        status_message = QtCore.pyqtSignal(str)

        #: For structured results (assuming list)
        processing_results = QtCore.pyqtSignal(list)

        #: For errors reported by the worker
        error_occurred_msg = QtCore.pyqtSignal(str)

        def __init__(self, parent=None):
            super(DataProcessingBroker, self).__init__(parent)
            self.readyReadStandardOutput.connect(self._on_stdout)
            self.readyReadStandardError.connect(self._on_stderr)
            self.errorOccurred.connect(self._on_error)
            self.stateChanged.connect(self._on_state_changed)

            # Buffer to reconstruct multi-line data like JSON from stdout
            self._stdout_buffer = b""
            self._collecting_results = False
            self._results_buffer = b""

        def start_worker(
            self, worker_script_path: pathlib.Path, shm_name: str, data_size: int
        ):
            """
            Starts the worker script, passing shared memory details as arguments.

            :param worker_script_path: Path to the worker script.
            :param shm_name: Name of the shared memory segment.
            :param data_size: Size of the data in the shared memory segment.
            :raises FileNotFoundError: If the worker script does not exist.
            :raises RuntimeError: If the Python interpreter is not found or executable, or process fails to start.
            """
            if not worker_script_path.exists():
                raise FileNotFoundError(
                    f"Worker script not found: {worker_script_path}"
                )
            python_interpreter = MultiprocessingHelper.get_python_interpreter()
            env = QProcessEnvironment.systemEnvironment()
            env.insert("PYTHON_PATH", str(python_interpreter.parent))
            env.insert("PYTHON_BIN", str(python_interpreter.name))
            self.setProcessEnvironment(env)
            # Construct the command with shared memory arguments
            args = [
                str(worker_script_path),
                "--shm_name",
                shm_name,
                "--data_size",
                str(data_size),
            ]

            logger.info(f"Starting worker process: {python_interpreter} {args}")
            self.start(str(python_interpreter), args)

            if not self.waitForStarted(5000):
                logger.error(f"Failed to start worker process: {self.errorString()}")
                raise RuntimeError(
                    f"Failed to start worker process: {self.errorString()}"
                )

        def send_command(self, command: str):
            """
            Sends a command string to the worker process's stdin.
            Appends a newline to delimit commands.

            :param command: The command string to send (e.g., "process", "ping", "exit").
            """
            if self.state() == QtCore.QProcess.Running:
                data = (command + "\n").encode("utf-8")
                self.write(data)
                logger.debug(f"→ Sent command: {command}")
            else:
                logger.warning(
                    f"Attempted to send command '{command}' but worker is not running (State: {self.state()})."
                )

        def _on_stdout(self):
            """Reads data from worker's stdout, processes line by line or collects results."""
            # Convert QByteArray to Python bytes
            data = self.readAllStandardOutput().data()
            self._stdout_buffer += data

            while True:
                # Find the first newline character in bytes
                try:
                    newline_index = self._stdout_buffer.index(b"\n")
                except ValueError:
                    # No newline found, wait for more data
                    break

                # Extract the line (including the newline)
                line_data = self._stdout_buffer[: newline_index + 1]
                # Keep the rest in the buffer
                self._stdout_buffer = self._stdout_buffer[newline_index + 1 :]

                # Decode and strip whitespace (including the newline)
                try:
                    # Now decode the extracted bytes line
                    line = line_data.decode("utf-8").strip()
                except UnicodeDecodeError as e:
                    logger.warning(
                        f"Failed to decode stdout line: {e} - Data: {line_data!r}"
                    )
                    continue  # Skip this line if it can't be decoded

                if not line:  # Ignore empty lines
                    continue

                # --- Process the line ---
                # Handle special markers for results data
                if line == "results_start":
                    logger.debug(
                        "Received 'results_start' marker. Starting results collection."
                    )
                    self._collecting_results = True
                    self._results_buffer = b""  # Clear buffer for new results
                    continue  # Process next line

                elif line == "results_end":
                    logger.debug(
                        "Received 'results_end' marker. Results collection complete."
                    )
                    self._collecting_results = False
                    try:
                        # Attempt to parse the collected JSON data
                        results_data = json.loads(self._results_buffer.decode("utf-8"))
                        logger.info(
                            f"Successfully parsed results: {len(results_data)} items."
                        )
                        # Emit the structured results
                        self.processing_results.emit(results_data)
                    except json.JSONDecodeError as e:
                        logger.error(
                            f"Failed to decode results JSON: {e}", exc_info=True
                        )
                        self.error_occurred_msg.emit(f"JSON decode error: {e}")
                    except Exception as e:
                        logger.error(
                            f"Error processing collected results: {e}", exc_info=True
                        )
                        self.error_occurred_msg.emit(f"Results processing error: {e}")

                    self._results_buffer = b""  # Clear buffer after processing/attempt
                    continue  # Process next line

                elif self._collecting_results:
                    # If we are currently collecting results, append the raw line data (before strip)
                    # This is crucial for multi-line JSON strings if they occur, though less common.
                    # We append the line_data including the newline, as json.loads expects valid JSON.
                    logger.debug(f"Collecting result line: {line_data!r}")
                    # Append the raw bytes line data
                    self._results_buffer += line_data
                    continue  # Process next line

                # If not collecting results, treat as a status message
                logger.debug(f"← Received status: {line}")
                self.status_message.emit(line)  # Emit simple status lines

        def _on_stderr(self):
            """Reads and logs data from the worker's standard error."""
            # Convert QByteArray to Python bytes before decoding
            data = self.readAllStandardError().data()
            if data:
                data = data.decode("utf-8", errors="replace").strip()
                logger.warning(f"Worker stderr: {data}")

        def _on_error(self, error: QtCore.QProcess.ProcessError):
            """Logs process errors and emits a signal."""
            error_map = {
                QtCore.QProcess.FailedToStart: "FailedToStart",
                QtCore.QProcess.Crashed: "Crashed",
                QtCore.QProcess.Timedout: "Timedout",
                QtCore.QProcess.ReadError: "ReadError",
                QtCore.QProcess.WriteError: "WriteError",
                QtCore.QProcess.UnknownError: "UnknownError",
            }
            error_str = error_map.get(error, f"UnknownError({error})")
            msg = f"Worker process error: {error_str} - {self.errorString()}"
            logger.error(msg)
            self.error_occurred_msg.emit(msg)

        def _on_state_changed(self, state: QtCore.QProcess.ProcessState):
            """Logs process state changes."""
            state_map = {
                QtCore.QProcess.NotRunning: "NotRunning",
                QtCore.QProcess.Starting: "Starting",
                QtCore.QProcess.Running: "Running",
            }
            state_str = state_map.get(state, f"UnknownState({state})")
            logger.info(f"Worker process state changed: {state_str}")

            if state == QtCore.QProcess.NotRunning:
                exit_code = self.exitCode()
                exit_status = self.exitStatus()
                exit_status_str = (
                    "NormalExit"
                    if exit_status == QtCore.QProcess.NormalExit
                    else "CrashExit"
                )
                msg = f"Worker process exited with code {exit_code} ({exit_status_str})"
                logger.info(msg)
                # emit an error if the exit was not normal and not intentional (e.g., via 'exit' command)
                if exit_status == QtCore.QProcess.CrashExit:
                    self.error_occurred_msg.emit(msg)

        def stop_worker(self):
            """Attempts to terminate the worker process gracefully, then kills."""
            if self.state() != QtCore.QProcess.NotRunning:
                logger.info("Attempting to terminate worker process...")
                # Send 'exit' command first to allow graceful cleanup in worker
                self.send_command("exit")
                # Give worker a moment to process 'exit' command
                if self.waitForFinished(1000):
                    logger.info(
                        "Worker process exited gracefully after 'exit' command."
                    )
                    return  # Worker exited

                logger.warning(
                    "Worker did not exit after 'exit' command, attempting terminate."
                )
                self.terminate()  # Send SIGTERM or similar
                if not self.waitForFinished(2000):  # Wait up to 2 seconds
                    logger.warning(
                        "Worker did not terminate gracefully, killing process."
                    )
                    self.kill()  # Send SIGKILL or similar
                    if not self.waitForFinished(1000):
                        logger.error("Worker process did not respond to kill.")
                logger.info("Worker process stopped.")
            else:
                logger.debug("Worker process was already stopped.")

    class TaskProcessor:
        """
        IDA Pro plugin example demonstrating multiprocessing with a worker
        using shared memory for large data and QProcess pipes for signaling.
        """

        # Store shared memory object and broker process as class attributes
        _shared_memory = None
        _broker = None

        # --- Plugin Lifecycle ---
        def __init__(self):
            # --- Set up Timers (optional, but useful for demo/ping) ---
            # Keep ping timer if desired for status check, otherwise remove.
            # The main work completion is signaled by processing_results or status_message.
            self.ping_timer = QtCore.QTimer()

        @staticmethod
        def get_section_data(
            section_name: str,
            max_size: int = 40 * 1024 * 1024,
            min_size: int = 1024,
        ) -> bytes:
            """Get the data of a section by name."""
            seg = ida_segment.get_segm_by_name(section_name)
            data_ea = seg.start_ea
            data_to_process_size = seg.end_ea - seg.start_ea
            # Cap size if needed, or handle very large sections
            if data_to_process_size > max_size:  # Limit demo to ~40MB
                data_to_process_size = max_size
                logger.warning(
                    f"Limiting demo data size to {data_to_process_size} bytes from {section_name}."
                )
            elif data_to_process_size < min_size:  # Don't bother with tiny sections
                logger.error(
                    f"{section_name} section is too small ({data_to_process_size} bytes) for demo."
                )
                return

            logger.info(
                f"Reading {data_to_process_size} bytes from address {hex(data_ea)}"
            )
            # Read the bytes from IDA
            data_bytes = ida_bytes.get_bytes(data_ea, data_to_process_size)

            if not data_bytes or len(data_bytes) != data_to_process_size:
                logger.error(
                    f"Failed to read {data_to_process_size} bytes from {hex(data_ea)}. Read {len(data_bytes) if data_bytes else 0} bytes."
                )
                return

            return data_bytes

        def terminate(self):
            """Terminate the plugin, stopping the broker and cleaning up shared memory."""
            logger.info("Terminating plugin.")

            # Stop timers if they exist
            if self.ping_timer and self.ping_timer.isActive():
                self.ping_timer.stop()
                logger.debug("Ping timer stopped.")

            # Stop the broker process (sends 'exit' command)
            if self._broker and self._broker.state() != QtCore.QProcess.NotRunning:
                self._broker.stop_worker()
                self._broker = None  # Clear reference

            # Clean up shared memory (unlink)
            if self._shared_memory:
                try:
                    logger.info(
                        f"Unlinking shared memory segment: {self._shared_memory.name}"
                    )
                    self._shared_memory.close()  # Close parent's view
                    sm.SharedMemory(
                        self._shared_memory.name
                    ).unlink()  # Unlink the segment
                    logger.info("Shared memory unlinked.")
                except FileNotFoundError:
                    logger.warning(
                        f"Shared memory segment {self._shared_memory.name} already unlinked."
                    )
                except Exception as e:
                    logger.error(f"Error unlinking shared memory: {e}", exc_info=True)
                finally:
                    self._shared_memory = None  # Clear reference

            logger.info("Plugin terminated.")

        def run(self, bytes_to_process: bytes, **kwargs):
            """Run the main plugin logic when hotkey is pressed."""
            plugin_arg: typing.Any = kwargs.pop("plugin_arg", None)
            if plugin_arg is not None:
                logger.info(f"Received plugin arg: {plugin_arg}")

            logger.info("Plugin hotkey pressed. Starting data processing example.")

            # Prevent starting multiple brokers
            if self._broker and self._broker.state() != QtCore.QProcess.NotRunning:
                logger.warning("Broker process is already running.")
                return

            data_to_process_size = len(bytes_to_process)  # Use actual read size

            if data_to_process_size == 0:
                logger.error("No data to process.")
                return

            # Create a shared memory segment
            try:
                # Size should be at least the data size. Can add buffer for results if needed later.
                # Let's make it exactly the data size for simplicity, results come via stdout.
                self._shared_memory = sm.SharedMemory(
                    create=True, size=data_to_process_size
                )
                logger.info(
                    f"Created shared memory segment: name='{self._shared_memory.name}', size={self._shared_memory.size}"
                )

                # Copy data into shared memory
                logger.info("Copying data into shared memory...")
                self._shared_memory.buf[:data_to_process_size] = bytes_to_process
                logger.info("Data copied to shared memory.")

            except Exception as e:
                logger.error(
                    f"Failed to create or write to shared memory: {e}", exc_info=True
                )
                # Clean up if creation failed partway
                if self._shared_memory:
                    try:
                        self._shared_memory.close()
                        # Attempt unlink if create=True succeeded but writing failed
                        sm.SharedMemory(self._shared_memory.name).unlink()
                    except Exception:
                        pass  # Ignore cleanup errors if original error is more important
                    finally:
                        self._shared_memory = None
                return  # Stop here if shared memory failed

            # --- 2. Launch Broker Process ---
            try:

                self._broker = DataProcessingBroker()
                # Connect signals from the broker to our handler slots
                self._broker.status_message.connect(self._handle_worker_status)
                self._broker.processing_results.connect(self._handle_worker_results)
                self._broker.error_occurred_msg.connect(self._handle_worker_error)

                # Start the worker, passing shared memory details
                self._broker.start_worker(
                    WORKER_SCRIPT_PATH,
                    self._shared_memory.name,  # Pass the name
                    data_to_process_size,  # Pass the actual size
                )

                # Wait briefly to ensure the worker starts and attaches
                # A more robust approach might wait for a specific "ready" signal from the worker
                if not self._broker.waitForStarted(2000):
                    logger.error("Worker failed to start after creating shared memory.")
                    raise RuntimeError("Worker failed to start.")

            except (FileNotFoundError, RuntimeError) as e:
                logger.error(f"Failed to start broker process: {e}")
                # Clean up shared memory if broker failed to start after creation
                self._cleanup_shared_memory()  # Use helper for cleanup
                # Clean up broker object reference
                if self._broker:
                    # Ensure QProcess is stopped if start failed
                    if self._broker.state() != QtCore.QProcess.NotRunning:
                        self._broker.stop_worker()
                    self._broker = None
                return  # Do not proceed

            logger.info("Worker process started.")

            # --- 3. Send "process" command to worker ---
            # This triggers the worker to read from shared memory and start processing pool
            self._broker.send_command("process")
            logger.info("Sent 'process' command to worker.")

            # Use lambda to pass the message to send
            self.ping_timer.timeout.connect(lambda: self._broker.send_command("ping"))
            self.ping_timer.start(5000)  # Ping less often, maybe every 5s
            logger.info("Ping timer started (sending 'ping' every 5s).")

        # --- Signal Handlers (Slots) ---
        def _handle_worker_status(self, message: str):
            """Handles simple status messages from the worker via stdout."""
            logger.info(f"Status from worker: {message}")
            if message == "pong":
                logger.info("✅ Ping/pong via QProcess pipes successful.")
            elif message.startswith("unknown_command:"):
                logger.warning(f"Worker reported unknown command: {message}")

            # Other status messages can be handled here

        def _handle_worker_results(self, results: list):
            """Handles structured results received from the worker."""
            logger.info(
                f"Received processing results from worker ({len(results)} items)."
            )
            # --- Process Results and Patch IDA ---
            # Example: Assume results is a list of dicts like {'offset': ..., 'sum': ..., ...}
            # You would iterate through results and use ida_bytes.patch_bytes
            bytes_patched_count = 0
            for item in results:
                if "error" in item:
                    logger.error(
                        f"Error in chunk result: {item['error']} at offset {item.get('offset', 'N/A')}"
                    )
                    continue

                offset = item.get("offset")
                # Dummy patching logic: Patch the first byte of each chunk to 0xCC (int3)
                # based on the original data_ea
                if offset is not None and hasattr(
                    self, "data_ea"
                ):  # Check if data_ea was set (not dummy data)
                    patch_ea = self.data_ea + offset
                    patch_byte = b"\xcc"  # Example: INT 3 instruction
                    if (
                        ida_bytes.patch_bytes(patch_ea, patch_byte) == 1
                    ):  # patch_bytes returns 1 on success
                        bytes_patched_count += 1
                        logger.debug(f"Patched byte at {hex(patch_ea)}")
                    else:
                        logger.warning(f"Failed to patch byte at {hex(patch_ea)}")
                else:
                    logger.debug(
                        f"Skipping patch for result at offset {offset} (dummy data or data_ea not set)."
                    )

            logger.info(
                f"Finished processing results. Patched {bytes_patched_count} locations (if using non-dummy data)."
            )
            # Worker is running, we can keep it running for more tasks
            # TODO: maybe explore an option to clean up and shut down broker
            # after processing is done. I'm not sure this is actually needed.
            # self._broker.stop_worker()
            # self._cleanup_shared_memory() # Clean up shared memory

        def _handle_worker_error(self, message: str):
            """Handles error messages originating from the worker process."""
            logger.error(f"Worker reported an error: {message}")

            # Consider stopping the worker and cleaning up shared memory on error
            self._broker.stop_worker()
            self._cleanup_shared_memory()

        def _cleanup_shared_memory(self):
            """Helper function to close and unlink shared memory."""
            if self._shared_memory:
                try:
                    logger.info(
                        f"Unlinking shared memory segment: {self._shared_memory.name}"
                    )
                    self._shared_memory.close()  # Close parent's view
                    sm.SharedMemory(
                        self._shared_memory.name
                    ).unlink()  # Unlink the segment
                    logger.info("Shared memory unlinked.")
                except FileNotFoundError:
                    logger.warning(
                        f"Shared memory segment {self._shared_memory.name} already unlinked."
                    )
                except Exception as e:
                    logger.error(f"Error unlinking shared memory: {e}", exc_info=True)
                finally:
                    self._shared_memory = None  # Clear reference

    class DataProcessingPlugin(idaapi.plugin_t):
        """
        IDA Pro plugin example demonstrating multiprocessing with a worker
        using shared memory for large data and QProcess pipes for signaling.
        """

        flags = idaapi.PLUGIN_PROC
        comment = "External data processing via Shared Memory and QProcess"
        help = "Press Alt-Shift-P to start data processing example"
        wanted_name = "DataProcessingExample"
        wanted_hotkey = "Alt-Shift-P"
        _core = None

        # --- Plugin Lifecycle ---
        def init(self):
            self._core = TaskProcessor()
            return idaapi.PLUGIN_KEEP

        def term(self):
            """Terminate the plugin, stopping the broker and cleaning up shared memory."""
            logger.info("Terminating plugin.")
            self._core.terminate()
            logger.info("Plugin terminated.")

        def run(self, arg):
            data_bytes = TaskProcessor.get_section_data(".text")
            self._core.run(data_bytes, plugin_arg=arg)

    # --- IDA Plugin Entry Point ---
    def PLUGIN_ENTRY():
        """IDA's entry point for the plugin."""
        return DataProcessingPlugin()


if not is_ida():

    # --- Processing Logic (Placeholder) ---
    # This function runs in a process pool worker.
    # It receives shared memory details and an offset/size within the data to process.
    # It should *not* rely on global variables set in the main worker process.
    def process_chunk(shm_name, data_size, offset, chunk_size):
        """
        Processes a chunk of shared memory data using explicit context managers.
        This runs in a separate process pool worker.

        Returns a dict with the result or error.
        """
        try:
            # Create the SharedMemoryChunk context. This attaches to the shared memory.
            # The 'with' statement ensures shm_chunk_parent.__exit__ is called.
            with SharedMemoryChunk(shm_name) as shm_chunk:
                # Get the raw memoryview and create a TrackedMemoryView around the slice.
                # Use a 'with' statement to ensure its __exit__ (and thus release()) is called
                # immediately after the block finishes.
                with shm_chunk.buf[offset : offset + chunk_size] as chunk_view:
                    # Perform processing using the sliced view
                    # For demonstration, just return the sum of byte values in the chunk
                    result = sum(chunk_view)
                    logger.debug(f"Processed chunk at offset {offset}: sum = {result}")

                # Exiting the inner 'with chunk_view' block calls chunk_view.__exit__
                # which calls chunk_view.close() -> chunk_view._memview.release()
                # and decrements shm_chunk's refcount.

            # Exiting the outer 'with shm_chunk' block calls shm_chunk.__exit__.
            # shm_chunk.__exit__ checks if its refcount is 0 (which it should be
            # if all TrackedMemoryViews derived from it have been closed) and,
            # if so, closes the underlying sm.SharedMemory.

            return {"offset": offset, "sum": result, "chunk_size": chunk_size}

        except Exception as e:
            logger.error(
                f"Error processing chunk at offset {offset}: {e}", exc_info=True
            )
            # Return an error indicator or re-raise
            return {"offset": offset, "error": str(e), "chunk_size": chunk_size}

    def work(args):
        logger.info(
            f"Worker started. Attaching to shared memory '{args.shm_name}' size {args.data_size} bytes."
        )
        # --- Main loop: Read commands from stdin ---
        try:
            while True:
                # Read a command line from standard input (sent by the IDA plugin)
                line = sys.stdin.readline()

                # If readline returns empty string, it means EOF (parent closed pipe)
                if not line:
                    logger.info("EOF received on stdin, exiting.")
                    break

                # Process the command
                command = line.strip()
                logger.info(f"Received command: {command}")
                if command == "ping":
                    # Simple ping/pong response
                    response = "pong\n"
                    sys.stdout.write(response)
                    sys.stdout.flush()
                    logger.debug("Sent: pong")

                elif command == "process":
                    logger.info("Starting data processing...")
                    results = []
                    chunk_size = 1024 * 1024  # 1 MB
                    offsets = range(0, args.data_size, chunk_size)
                    executor = None  # Initialize executor variable

                    try:
                        # Create the executor instance
                        ctx = multiprocessing.get_context("spawn")
                        executor = ProcessPoolExecutor(mp_context=ctx)

                        # Submit tasks to the pool
                        future_to_chunk = {
                            executor.submit(
                                process_chunk,
                                args.shm_name,
                                args.data_size,
                                offset,
                                min(chunk_size, args.data_size - offset),
                            ): offset
                            for offset in offsets
                        }

                        # Collect results as they complete
                        for future in concurrent.futures.as_completed(future_to_chunk):
                            offset = future_to_chunk[future]
                            try:
                                chunk_result = future.result()
                                results.append(chunk_result)
                            except Exception as exc:
                                logger.error(
                                    f"Chunk at offset {offset} generated an exception: {exc}",
                                    exc_info=True,
                                )
                                results.append(
                                    {"offset": offset, "error": f"Exception: {exc}"}
                                )

                    except Exception as e:
                        # Log errors related to executor creation or task submission/retrieval
                        logger.error(
                            f"Error during ProcessPoolExecutor processing: {e}",
                            exc_info=True,
                        )
                        # Still attempt to send an error signal back if possible
                        if not sys.stdout.closed:
                            try:
                                sys.stdout.write("error\n")
                                sys.stdout.write(f"executor_error: {e}\n")
                                sys.stdout.flush()
                            except IOError as ioe:
                                logger.error(
                                    f"IOError writing executor error to stdout: {ioe}"
                                )
                        # No 'continue' here, proceed to finally block for potential shutdown

                    finally:
                        # Explicitly shut down the executor and wait for workers
                        if executor:
                            logger.debug("Shutting down ProcessPoolExecutor...")
                            # wait=True is default but explicit here for clarity
                            executor.shutdown(wait=True)
                            logger.debug("ProcessPoolExecutor shut down.")

                    # --- Now proceed after executor shutdown ---

                    # Check if results were collected (might be empty if error occurred before loop)
                    if results:
                        logger.info(
                            f"Processing finished. Collected {len(results)} chunk results."
                        )
                        # --- Send Results back to Parent ---
                        try:
                            results_json = json.dumps(results)
                            sys.stdout.write("results_start\n")
                            sys.stdout.write(results_json + "\n")
                            sys.stdout.write("results_end\n")
                            sys.stdout.write(
                                "results_ready\n"
                            )  # Signal completion *after* results
                            sys.stdout.flush()
                            logger.info("Sent results and 'results_ready' signal.")
                        except Exception as e:
                            logger.error(f"Error sending results: {e}", exc_info=True)
                            # Attempt to send error signal if sending results failed
                            if not sys.stdout.closed:
                                try:
                                    sys.stdout.write("error\n")
                                    sys.stdout.write(f"send_results_error: {e}\n")
                                    sys.stdout.flush()
                                except IOError as ioe:
                                    logger.error(
                                        f"IOError writing send_results_error to stdout: {ioe}"
                                    )
                    elif not sys.stdout.closed:
                        # If no results and no prior error message sent, indicate a general processing issue maybe
                        # Or just log it internally. Let's log it.
                        logger.warning(
                            "Processing finished but no results were collected (possibly due to earlier errors)."
                        )
                        # Optionally send a different signal? For now, just don't send results_ready.

                elif command == "exit":
                    logger.info("Received 'exit' command, exiting.")
                    break  # Exit the loop

                else:
                    # Handle unknown commands
                    logger.warning(f"Received unknown command: {command}")
                    sys.stdout.write(f"unknown_command: {command}\n")
                    sys.stdout.flush()

        except Exception as e:
            # Catch any unexpected errors in the main loop
            logger.error(f"Unexpected worker error: {e}", exc_info=True)
            # Signal error back to parent
            # Check if stdout is writable before writing
            if not sys.stdout.closed:
                try:
                    sys.stdout.write("error\n")
                    sys.stdout.write(f"unexpected_error: {e}\n")
                    sys.stdout.flush()
                except IOError as ioe:
                    logger.error(f"IOError writing final error to stdout: {ioe}")

        finally:
            logger.info("Worker shutting down.")


class Taskr:
    """
    Singleton wrapper for the TaskProcessor instance.

    Ensures only one TaskProcessor is created and shared throughout the plugin's lifetime.

    Usage:
        >>> t1 = Taskr()
        >>> t2 = Taskr()
        >>> t1 is t2
        True
        >>> t1.get() is t2.get()
        True

    The .get() method returns the singleton TaskProcessor instance.
    """

    _instance = None
    _task_processor = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            # Not thread-safe, but sufficient for plugin/IDA context
            cls._instance = super().__new__(cls)
            logger.info("Initializing TaskProcessor")
            cls._task_processor = TaskProcessor()
        return cls._instance

    def get(self):
        """
        Returns the singleton TaskProcessor instance.

        >>> t1 = Taskr()
        >>> t2 = Taskr()
        >>> t1.get() is t2.get()
        True
        """
        return self._task_processor


def main():
    if is_ida():
        Taskr().get().run(Taskr().get().get_section_data(".text"))
        atexit.register(Taskr().get().terminate)
    else:
        parser = argparse.ArgumentParser(description="Worker process for IDA plugin.")
        parser.add_argument(
            "--shm_name", required=True, help="Shared memory segment name"
        )
        parser.add_argument(
            "--data_size",
            type=int,
            required=True,
            help="Size of the data in shared memory",
        )
        args = parser.parse_args()
        work(args)


if __name__ == "__main__":
    main()
