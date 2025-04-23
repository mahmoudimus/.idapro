import concurrent.futures
import logging
import math
import multiprocessing
import os
import pathlib
import sys
import threading
import time
import traceback
from multiprocessing.connection import Client, Listener
from threading import Thread

# --- IDA & Qt Imports ---
try:
    from PySide6.QtCore import (
        QObject,
        QProcess,
        QProcessEnvironment,
        QTimer,
        Signal,
        Slot,
    )

    import ida_idaapi
    import ida_kernwin
    import ida_pro

    # QApplication is no longer needed directly in the main logic
except ImportError:
    # Define placeholders if not in IDA, for the external process part
    # Although the external process won't use these directly
    ida_idaapi = None
    ida_kernwin = None
    ida_pro = None
    # Qt imports might fail outside IDA, handle gracefully if needed
    # Or assume they exist if PySide6 is installed where the external runs
    from PySide6.QtCore import (
        QObject,
        QProcess,
        QProcessEnvironment,
        QTimer,
        Signal,
        Slot,
    )

# Configure logging (used by both IDA plugin and external process)
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- Global State ---
ida_task_manager_client = None
plugin_instance = None  # Optional reference to the plugin instance


# --- Utility Functions ---
def get_python_interpreter():
    """Gets the path to the Python interpreter, preferring sys.executable."""
    # In standard Python, sys.executable is the interpreter.
    # In IDA's embedded Python, sys.executable points to IDA itself.
    # We need the actual Python interpreter linked with IDA.
    # sys._base_executable might exist and point to the python exe in some embedded scenarios.
    if (
        hasattr(sys, "_base_executable")
        and sys._base_executable
        and "python" in sys._base_executable.lower()
    ):
        return pathlib.Path(sys._base_executable)

    # Fallback: Check common relative paths from sys.prefix (installation dir)
    prefix_path = pathlib.Path(sys.prefix)
    common_paths = [
        prefix_path / "bin" / "python",  # Common on Linux/macOS venv
        prefix_path / "python",  # Sometimes direct in prefix
        prefix_path / "python.exe",  # Common on Windows
        prefix_path / "bin" / "python.exe",  # Windows venv
        pathlib.Path(sys.executable).parent
        / "python",  # If IDA is in same dir as python
        pathlib.Path(sys.executable).parent / "python.exe",
    ]
    for path in common_paths:
        if path.exists() and os.access(path, os.X_OK):
            return path

    # Last resort: Assume 'python' is in PATH (might fail in isolated envs)
    logging.warning(
        "Could not reliably determine Python interpreter path; falling back to 'python'."
    )
    return pathlib.Path("python")


PYTHON_INTERPRETER = get_python_interpreter()
logging.info(f"Using Python interpreter: {PYTHON_INTERPRETER}")


def is_ida():
    """Crude check to see if running inside IDA."""
    if not ida_pro:
        return False  # Check if IDA modules were imported
    # Use a more reliable check if possible, e.g., checking idaapi functions
    try:
        # ida_kernwin.get_kernel_version() # Example: Check if an IDA API call works
        # Check executable name as fallback
        exec_name = pathlib.Path(sys.executable).name.lower()
        is_ida_env = exec_name.startswith(("ida", "idat", "idaw", "idag"))
        # print(f"is_ida() check: executable='{exec_name}', result={is_ida_env}") # Less noisy
        return is_ida_env
    except Exception:
        return False


# Define ida_log based on environment
if is_ida():

    def ida_log(level, msg):
        prefix = f"[{level.upper()}] [mp5 Plugin] "
        ida_kernwin.msg(f"{prefix}{msg}\n")

    logging.info("IDA environment detected. Registering IDA logger.")
else:
    # Define a placeholder if not in IDA, using standard logging
    def ida_log(level, msg):
        log_func = getattr(logging, level.lower(), logging.info)
        log_func(f"[mp5 External] {msg}")


# --- Multiprocessing Context Setup ---
try:
    # Only configure multiprocessing if not the external process already
    # (Avoids issues if external process imports this script somehow differently)
    if is_ida():
        multiprocessing.set_start_method("spawn", force=True)
        multiprocessing.set_executable(str(PYTHON_INTERPRETER))
        MPCTX = multiprocessing.get_context("spawn")
        logging.info("Successfully set multiprocessing start method to 'spawn'.")
    else:
        MPCTX = multiprocessing.get_context()  # Use default for external
except (ValueError, RuntimeError) as e:
    logging.warning(
        f"Could not force 'spawn' start method or set executable: {e}. Using default."
    )
    MPCTX = multiprocessing.get_context()


# --- Connection Server Class ---
class ConnectionServer(QObject):
    """Listens for a single connection and emits it. Interruptible via close()."""

    new_connection = Signal(object)  # Emits the connection object
    connection_error = Signal(str)

    def __init__(self, address=None, authkey=b"secret", parent=None):
        super().__init__(parent)
        self._authkey = authkey
        self._address_info = address or ("localhost", 0)
        self.listener = None
        self.thread = None
        self._stop_requested = False  # Flag to indicate intentional stop

    def start(self):
        """Starts the listener in a background thread."""
        if self.thread and self.thread.is_alive():
            ida_log("warning", "Server thread already running.")
            return
        try:
            self._stop_requested = False  # Reset flag on start
            self.listener = Listener(self._address_info, authkey=self._authkey)
            ida_log("info", f"Connection server listening on {self.address}")
            self.thread = Thread(target=self._run, daemon=True)
            self.thread.start()
        except Exception as e:
            ida_log("error", f"Failed to start listener: {e}")
            self.connection_error.emit(str(e))
            if self.listener:
                try:
                    self.listener.close()
                except OSError:
                    pass  # Ignore errors during cleanup
            self.listener = None

    @property
    def address(self):
        """Returns the address the listener is bound to."""
        return self.listener.address if self.listener else None

    @Slot()
    def _request_stop(self):
        """Slot to indicate that a stop has been requested externally."""
        ida_log("debug", "ConnectionServer stop requested via slot.")
        self._stop_requested = True

    def _run(self):
        """Accepts one connection, blocks until connection or listener closed."""
        ida_log("info", "Server thread started, blocking on accept()...")
        conn = None
        try:
            if not self.listener:
                ida_log("error", "Listener not initialized before starting run loop.")
                return

            # Blocking call - will be interrupted by self.listener.close() from another thread
            conn = self.listener.accept()
            ida_log("info", f"Connection accepted from {self.listener.last_accepted}")
            # Check if stop was requested *during* a potential accept race condition
            if not self._stop_requested:
                self.new_connection.emit(conn)
            else:
                ida_log(
                    "info",
                    "Stop was requested just as connection arrived, ignoring connection.",
                )
                try:
                    conn.close()  # Close the connection we just accepted but won't use
                except Exception:
                    pass

        except OSError as e:
            # This exception is expected when self.listener.close() is called externally
            if self._stop_requested:
                ida_log(
                    "info",
                    f"Server accept loop terminated as requested (accept OSError: {e}).",
                )
            else:
                ida_log("error", f"Server accept loop OSError: {e}")
                self.connection_error.emit(f"Accept OSError: {e}")
        except Exception as e:
            ida_log("error", f"Unexpected error in server thread: {e}")
            if not self._stop_requested:
                self.connection_error.emit(str(e))
        finally:
            ida_log("info", "Server thread finished.")

    def close(self):
        """Stops the listener and joins the thread."""
        ida_log("info", "Closing connection server...")
        # self._request_stop() should have been called via signal *before* this
        listener_to_close = self.listener
        self.listener = None
        if listener_to_close:
            try:
                listener_to_close.close()
                ida_log("info", "Listener closed.")
            except OSError as e:
                ida_log("warning", f"Error closing listener: {e}")
        if self.thread and self.thread.is_alive():
            ida_log("info", "Joining server thread...")
            self.thread.join(timeout=2.0)
            if self.thread.is_alive():
                ida_log("warning", "Server thread did not exit cleanly.")
        self.thread = None


# --- Task Manager Client Class ---
class TaskManagerClient(QProcess):
    """Manages the external Python process from within IDA."""

    stop_server_signal = Signal()
    log_message = Signal(str)
    process_error = Signal(str)
    process_finished = Signal(int, QProcess.ExitStatus)

    def __init__(self, python_exe, script_path, parent=None):
        super().__init__(parent)
        self._python_exe = str(python_exe)
        self._script_path = str(script_path)
        self._conn = None
        # Make server a child of this QObject for lifetime management
        self._server = ConnectionServer(authkey=b"secret_ida_key", parent=self)

        # --- Timer for connection polling ---
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(200)
        self._poll_timer.timeout.connect(self._poll_connection)

        # Setup process environment
        env = QProcessEnvironment.systemEnvironment()
        for v in ("PYTHONHOME", "PYTHONPATH"):  # Avoid conflicts
            if env.contains(v):
                ida_log("info", f"Removing conflicting environment variable: {v}")
                env.remove(v)
        self.setProcessEnvironment(env)

        # Configure process settings
        self.setProcessChannelMode(QProcess.MergedChannels)  # Combine stdout/stderr

        # Connect signals
        self._server.new_connection.connect(self._on_conn)
        self._server.connection_error.connect(self._on_server_error)
        # Connect stop signal to server's stop slot
        self.stop_server_signal.connect(self._server._request_stop)
        self.readyReadStandardOutput.connect(self._echo_output)
        self.errorOccurred.connect(self._on_process_error)
        # Connect QProcess.finished to our own cleanup AND the signal emission
        self.finished.connect(self._on_process_finished)

    def launch_process(self):
        """Starts the connection server and launches the external process."""
        if self.state() != QProcess.NotRunning:
            ida_log("warning", "Process is already running.")
            return
        self._server.start()
        if not self._server.address:
            ida_log(
                "error", "Failed to start connection server. Cannot launch process."
            )
            self.process_error.emit("Failed to start IPC server.")
            return
        host, port = self._server.address
        self.setProgram(self._python_exe)
        self.setArguments(
            [
                "-u",
                self._script_path,
                "--host",
                host,
                "--port",
                str(port),
                "--authkey",
                "secret_ida_key",
            ]
        )
        ida_log(
            "info",
            f"Launching external process: {self._python_exe} -u {self._script_path} with args...",
        )
        self.start()  # QProcess.start()

        # --- Add state logging ---
        ida_log("debug", f"QProcess state immediately after start(): {self.state()}")
        # Use QTimer.singleShot to check state again shortly after event loop gets a chance
        QTimer.singleShot(
            500, lambda: ida_log("debug", f"QProcess state after 500ms: {self.state()}")
        )
        # --- End state logging ---

    @Slot(object)
    def _on_conn(self, conn):
        """Handles the incoming connection and starts polling."""
        if self._conn:
            ida_log(
                "warning",
                "New connection received, stopping polling and closing previous connection.",
            )
            self._poll_timer.stop()
            try:
                self._conn.close()
            except Exception:
                pass
        ida_log("info", "Connection received from external process.")
        self._conn = conn
        try:
            if getattr(self._conn, "closed", True):
                raise ValueError("Connection object appears closed immediately.")
            if not hasattr(self._conn, "poll") or not hasattr(self._conn, "recv"):
                raise ValueError("Connection object lacks poll/recv methods.")
            ida_log("debug", "_on_conn: Starting polling timer.")
            self._poll_timer.start()
        except Exception as e:
            ida_log(
                "error", f"Failed to start polling timer or connection invalid: {e}"
            )
            ida_log("error", traceback.format_exc())
            if self._conn:
                try:
                    self._conn.close()
                except:
                    pass
            self._conn = None

    @Slot()
    def _poll_connection(self):
        """Periodically checks the connection for incoming data."""
        if not self._conn or getattr(self._conn, "closed", True):
            self._poll_timer.stop()
            return
        try:
            while self._conn.poll():
                ida_log("debug", "_poll_connection: poll() is True, calling recv()...")
                msg = self._conn.recv()
                ida_log("debug", f"_poll_connection: Received message: {msg}")
                verb, arg = msg
                if verb == "LOG":
                    self.log_message.emit(f"[External] {arg}")
                elif verb == "TASK_RESULT":
                    self.log_message.emit(f"[Result] {arg}")
                elif verb == "TASK_ERROR":
                    self.log_message.emit(f"[Error] {arg}")
                else:
                    ida_log(
                        "warning", f"Received unknown message via poll: {verb} {arg}"
                    )
                if not self._conn or getattr(self._conn, "closed", True):
                    break
        except (EOFError, OSError, ConnectionResetError, BrokenPipeError) as e:
            ida_log("warning", f"_poll_connection: Connection error/closed: {e}")
            self.log_message.emit(f"Connection error/closed: {e}")
            self._poll_timer.stop()
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
            self._conn = None
        except Exception as e:
            ida_log(
                "error", f"_poll_connection: Unexpected error processing message: {e}"
            )
            ida_log("error", traceback.format_exc())
            self._poll_timer.stop()
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
            self._conn = None

    @Slot()
    def _echo_output(self):
        """Reads and logs stdout/stderr from the external process."""
        ida_log("debug", "_echo_output slot triggered.")
        try:
            output_bytes = self.readAllStandardOutput()
            if output_bytes:
                text = output_bytes.data().decode(errors="ignore").strip()
                if text:
                    self.log_message.emit(f"[Proc Output] {text}")
        except Exception as e:
            ida_log("error", f"Error reading process output: {e}")

    @Slot(str)
    def _on_server_error(self, error_msg):
        ida_log("error", f"Connection server error: {error_msg}")
        self.process_error.emit(f"Server Error: {error_msg}")

    @Slot("QProcess::ProcessError")
    def _on_process_error(self, error):
        error_string = self.errorString()
        # --- Make log more prominent ---
        ida_log("error", f"!!!! QProcess Error Occurred: {error} - {error_string} !!!!")
        # --- End log ---
        self.process_error.emit(f"Process Error {error}: {error_string}")
        # Cleanup might be premature if it's just FailedToStart, but okay for now
        self.cleanup()

    @Slot(int, QProcess.ExitStatus)
    def _on_process_finished(self, exit_code, exit_status):
        status_text = (
            "crashed" if exit_status == QProcess.CrashExit else "finished normally"
        )
        ida_log("info", f"External process {status_text} with exit code {exit_code}.")
        self.process_finished.emit(exit_code, exit_status)  # Emit signal *first*
        self.cleanup()  # Ensure cleanup happens

    def request_shutdown(self):
        if self._conn:
            ida_log("info", "Sending SHUTDOWN command to external process.")
            try:
                self._conn.send(("SHUTDOWN", None))
            except OSError as e:
                ida_log("warning", f"Failed to send SHUTDOWN command: {e}")
        else:
            ida_log("warning", "Cannot send SHUTDOWN: No active connection.")
            self.terminate_process()

    def terminate_process(self):
        if self.state() != QProcess.NotRunning:
            ida_log("warning", "Terminating external process forcefully...")
            self.terminate()
            if not self.waitForFinished(3000):
                ida_log("warning", "Process did not terminate after 3s, killing...")
                self.kill()
                self.waitForFinished(1000)

    def cleanup(self):
        # Make sure cleanup is idempotent
        if hasattr(self, "_cleaned_up") and self._cleaned_up:
            return
        ida_log("info", "TaskManagerClient cleanup initiated.")
        self._cleaned_up = True

        process_was_running = self.state() == QProcess.Running
        connection_existed = self._conn is not None

        # 1. Stop Timers
        ida_log("debug", "Stopping polling timer...")
        self._poll_timer.stop()

        # 2. Request process shutdown (if applicable)
        if process_was_running and connection_existed:
            self.request_shutdown()
            # Short delay to allow shutdown message to be potentially processed
            # Note: In a plugin context, QTimer.singleShot(100, self._continue_cleanup) might be better
            # than time.sleep(), but keep it simple for now.
            time.sleep(0.1)

        # 3. Signal the ConnectionServer to stop accepting
        # This needs to happen *before* closing the server object itself.
        ida_log("debug", "Emitting stop_server_signal...")
        self.stop_server_signal.emit()  # Asks server thread to stop accepting

        # 4. Stop and cleanup the connection server
        # The server object is a child QObject, might be deleted automatically,
        # but explicit close is safer for the thread.
        self._server.close()

        # 5. Close the active connection object (if IDA still holds it)
        if self._conn:
            conn_to_close = self._conn
            self._conn = None
            try:
                ida_log("debug", "Closing IDA-side connection object...")
                conn_to_close.close()
            except OSError as e:
                ida_log("warning", f"Error closing client connection: {e}")

        # 6. Ensure the external process is terminated
        current_state = self.state()
        ida_log(
            "debug", f"Process state before final termination check: {current_state}"
        )
        if current_state != QProcess.NotRunning:
            ida_log("info", "Process still running, attempting termination...")
            self.terminate_process()
        else:
            ida_log("info", "Process already finished.")

        ida_log("info", "TaskManagerClient cleanup finished.")
        # Note: We don't set the global ida_task_manager_client to None here.
        # That should happen where it's managed (plugin term, or before creating new one).


# --- Global Cleanup Function ---
def cleanup_ida_client():
    """Function to be called on IDA exit or script unload."""
    global ida_task_manager_client
    if ida_task_manager_client:
        ida_log("info", "Cleaning up Task Manager Client...")
        try:
            # Call the instance's cleanup method
            ida_task_manager_client.cleanup()
            # Optional: Delete the QObject explicitly if needed, though parentage might handle it.
            # ida_task_manager_client.deleteLater()
        except Exception as e:
            ida_log("error", f"Exception during TaskManagerClient cleanup: {e}")
            ida_log("error", traceback.format_exc())
        finally:
            # Clear the global reference *after* attempting cleanup
            ida_task_manager_client = None
            ida_log("info", "Global client reference cleared.")
    else:
        ida_log("info", "No active Task Manager Client to clean up.")


# --- Action Handler ---
class LaunchTaskManagerAction(ida_kernwin.action_handler_t):
    def __init__(self, plugin_ref):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin_ref

    def activate(self, ctx):
        # Restore original logic, keep the prominent log
        ida_log("info", "!!!! LaunchTaskManagerAction.activate() CALLED !!!!")

        global ida_task_manager_client
        if ida_task_manager_client:
            ida_log("warning", "Task Manager Client already running...")
            ida_kernwin.warning("Task Manager is already running.")
            return 1

        try:
            script_path = pathlib.Path(__file__).resolve()
            ida_task_manager_client = TaskManagerClient(
                PYTHON_INTERPRETER, script_path, parent=None
            )

            ida_task_manager_client.log_message.connect(self.plugin.log_client_message)
            ida_task_manager_client.process_error.connect(self.plugin.log_client_error)
            ida_task_manager_client.finished.connect(self.plugin.handle_client_finish)

            ida_task_manager_client.launch_process()
            ida_log("info", "Task Manager Client launched via plugin action.")

        except Exception as e:
            ida_log("error", f"Failed to create or launch TaskManagerClient: {e}")
            ida_log("error", traceback.format_exc())
            if ida_task_manager_client:
                cleanup_ida_client()
            else:
                ida_task_manager_client = None
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# --- Plugin Class ---
class MyTaskManagerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Manages an external Python process for tasks"
    help = "Launches and manages an external task processor"
    wanted_name = "My Task Manager"
    wanted_hotkey = ""

    ACTION_NAME = "my_task_manager:launch"
    ACTION_LABEL = "Launch Task Manager"
    MENU_PATH = f"Edit/Plugins/{wanted_name}/{ACTION_LABEL}"

    def __init__(self):
        self.action_handler_instance = None

    def init(self):
        global plugin_instance
        plugin_instance = self
        ida_log("info", f"{self.wanted_name} plugin initialized.")

        self.action_handler_instance = LaunchTaskManagerAction(self)
        if not self.action_handler_instance:
            ida_log("error", "Failed to create LaunchTaskManagerAction instance.")
            return ida_idaapi.PLUGIN_SKIP

        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_NAME,
            self.ACTION_LABEL,
            self.action_handler_instance,
            self.wanted_hotkey,
            "Launches the external task manager process",
            -1,
        )

        if not ida_kernwin.register_action(action_desc):
            ida_log("error", f"Failed to register action {self.ACTION_NAME}")
            self.action_handler_instance = None
            return ida_idaapi.PLUGIN_SKIP

        # Attach to the NEW menu path
        if not ida_kernwin.attach_action_to_menu(
            self.MENU_PATH, self.ACTION_NAME, ida_kernwin.SETMENU_APP
        ):
            ida_log(
                "warning",
                f"Failed to attach action {self.ACTION_NAME} to the NEW menu path '{self.MENU_PATH}'",
            )
            # If attachment fails now, it's more likely a problem
            # return ida_idaapi.PLUGIN_SKIP # Consider failing init if menu is critical
            pass

        ida_log(
            "info",
            f"Action '{self.ACTION_NAME}' registered and attempted attachment to menu '{self.MENU_PATH}'.",
        )
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Called when the plugin is invoked directly from the menu ('My Task Manager').
        We want the user to use the sub-menu action instead.
        """
        ida_log("info", f"{self.wanted_name} run() called (arg={arg}).")
        if arg == 0:
            ida_log("debug", "Plugin run() called non-interactively.")
        else:
            # Guide user to the new sub-menu item
            ida_log("info", "Plugin run() called interactively.")
            ida_kernwin.info(
                f"Please use the '{self.ACTION_LABEL}' sub-menu under '{self.wanted_name}' in the Plugins menu."
            )
        return None

    def term(self):
        ida_log("info", f"{self.wanted_name} plugin terminating.")
        cleanup_ida_client()

        try:
            # Detach from the NEW menu path
            ida_kernwin.detach_action_from_menu(self.MENU_PATH, self.ACTION_NAME)
            ida_kernwin.unregister_action(self.ACTION_NAME)
            ida_log("info", f"Action '{self.ACTION_NAME}' unregistered.")
        except Exception as e:
            ida_log("error", f"Exception during action unregistration: {e}")

        ida_log("info", f"{self.wanted_name} plugin terminated.")
        global plugin_instance
        plugin_instance = None
        self.action_handler_instance = None

    @Slot(str)
    def log_client_message(self, message):
        ida_log("info", f"[Client] {message}")

    @Slot(str)
    def log_client_error(self, message):
        ida_log("error", f"[Client Error] {message}")

    @Slot(int, QProcess.ExitStatus)
    def handle_client_finish(self, exit_code, exit_status):
        status = "crashed" if exit_status == QProcess.CrashExit else "finished"
        ida_log("info", f"Client process {status} (Code: {exit_code}).")


# ————————————————————————————————————————————————————————————————————————————————
# External Process Functions (Worker Side)
# ————————————————————————————————————————————————————————————————————————————————


def compute_sqrt(n):
    """Compute the square root of the given number."""
    pid = os.getpid()
    result = math.sqrt(n) + 1
    return n, result


def run_computation_tasks(conn, shutdown_event):
    """Manages the ProcessPoolExecutor and computation tasks."""
    parent_pid = os.getpid()
    ida_log("info", f"PARENT (PID: {parent_pid}): Starting computation task runner.")
    numbers = [4, 16, 25, 36, 49, 64, 81, 100] * 5
    mp_context = MPCTX if "MPCTX" in globals() else multiprocessing.get_context()
    ida_log("info", f"Using multiprocessing context: {mp_context.get_start_method()}")
    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=4, mp_context=mp_context
        ) as executor:
            ida_log(
                "info",
                f"ProcessPoolExecutor started with {executor._max_workers} workers.",
            )
            futures = {executor.submit(compute_sqrt, n): n for n in numbers}
            while futures and not shutdown_event.is_set():
                done, not_done = concurrent.futures.wait(
                    futures.keys(),
                    timeout=0.5,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if shutdown_event.is_set():
                    ida_log("info", "Shutdown detected during computation.")
                    ida_log("info", f"Cancelling {len(not_done)} pending tasks...")
                    for future in not_done:
                        future.cancel()
                    concurrent.futures.wait(not_done, timeout=1.0)
                    break
                for future in done:
                    n_original = futures.pop(future)
                    try:
                        n, result = future.result()
                        log_msg = (
                            f"PARENT (PID: {parent_pid}): Result for {n} is {result}"
                        )
                        conn.send(("TASK_RESULT", log_msg))
                    except concurrent.futures.CancelledError:
                        log_msg = f"PARENT (PID: {parent_pid}): Task for {n_original} was cancelled."
                        conn.send(("TASK_ERROR", log_msg))
                    except Exception as e:
                        log_msg = f"PARENT (PID: {parent_pid}): Computation for {n_original} raised: {e}"
                        conn.send(("TASK_ERROR", log_msg))
            ida_log("info", "Computation loop finished.")
            ida_log("info", "Shutting down ProcessPoolExecutor...")
            executor.shutdown(wait=True, cancel_futures=True)
            ida_log("info", "ProcessPoolExecutor shut down.")
    except Exception as e:
        ida_log("error", f"Error during computation task management: {e}")
        try:
            conn.send(("TASK_ERROR", f"Critical error in task runner: {e}"))
        except OSError:
            ida_log("warning", "Connection already closed when sending critical error.")


def command_listener(conn, shutdown_event):
    """Listens for commands from the IDA process."""
    ida_log("info", "Command listener started.")
    try:
        while not shutdown_event.is_set():
            try:
                if conn.poll(0.5):
                    msg = conn.recv()
                    verb, arg = msg
                    ida_log("info", f"Received command: {verb}")
                    if verb == "SHUTDOWN":
                        ida_log("info", "SHUTDOWN command received.")
                        shutdown_event.set()
                        break
                    else:
                        ida_log("warning", f"Ignoring unknown command: {verb}")
            except (EOFError, OSError, ConnectionResetError, BrokenPipeError) as e:
                ida_log(
                    "warning",
                    f"Connection error in command listener (likely closed by host): {e}. Assuming shutdown.",
                )
                shutdown_event.set()
                break
    except Exception as e:
        ida_log("error", f"Unexpected error in command listener: {e}")
        shutdown_event.set()
    finally:
        ida_log("info", "Command listener finished.")


def external_process_main(host, port, authkey):
    """Main function for the external process."""
    conn = None
    shutdown_event = threading.Event()
    listener_thread = None
    try:
        # --- Log connection attempt ---
        ida_log(
            "info",
            f"External attempting to connect to {host}:{port} with key {authkey[:5]}...",  # Log only first 5 chars of key
        )
        # --- End log ---

        # --- Wrap Client connection in try/except ---
        try:
            conn = Client(
                (host, port), authkey=authkey.encode()
            )  # Ensure authkey is bytes
            ida_log("info", "External successfully connected back to IDA process.")
        except Exception as connect_err:
            ida_log("error", f"External FAILED TO CONNECT: {connect_err}")
            ida_log("error", traceback.format_exc())
            return  # Exit if connection fails
        # --- End wrap ---

        conn.send(("LOG", f"Hello from external process (PID: {os.getpid()})"))
        listener_thread = Thread(
            target=command_listener, args=(conn, shutdown_event), daemon=True
        )
        listener_thread.start()
        run_computation_tasks(conn, shutdown_event)
        ida_log("info", "Computation tasks finished or interrupted.")
    except Exception as e:
        ida_log("error", f"An error occurred in the external process main loop: {e}")
        ida_log("error", traceback.format_exc())
    finally:
        ida_log("info", "External process shutting down.")
        shutdown_event.set()
        if listener_thread and listener_thread.is_alive():
            ida_log("info", "Waiting for command listener thread to exit...")
            listener_thread.join(timeout=1.5)
            if listener_thread.is_alive():
                ida_log("warning", "Command listener did not exit cleanly.")
        if conn:
            try:
                conn.close()
                ida_log("info", "Connection closed.")
            except OSError as e:
                ida_log("warning", f"Error closing connection: {e}")
        ida_log("info", f"External process (PID: {os.getpid()}) finished.")


# --- Script Entry Point Logic ---
if not is_ida():
    # Running as the external process launched by IDA
    import argparse

    parser = argparse.ArgumentParser(
        description="External computation process for IDA."
    )
    parser.add_argument(
        "--host", required=True, help="Host address of the IDA listener."
    )
    parser.add_argument(
        "--port", required=True, type=int, help="Port number of the IDA listener."
    )
    parser.add_argument(
        "--authkey", required=True, help="Authentication key for the connection."
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level.",
    )
    args = parser.parse_args()

    # --- Configure logging for the external process with flushing ---
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    log_format = "%(asctime)s - %(levelname)s - [External %(process)d] - %(message)s"
    stderr_handler = logging.StreamHandler(sys.stderr)

    class FlushFilter(logging.Filter):
        def filter(self, record):
            for handler in logging.getLogger().handlers:
                handler.flush()
            return True

    stderr_handler.setFormatter(logging.Formatter(log_format))
    stderr_handler.setLevel(log_level)
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    root_logger.addHandler(stderr_handler)
    root_logger.setLevel(log_level)
    root_logger.addFilter(FlushFilter())
    # --- End of logging configuration ---

    external_process_main(args.host, args.port, args.authkey)


# --- Plugin Registration ---
# This function is the entry point IDA looks for when loading plugins.
def PLUGIN_ENTRY():
    # Ensure IDA modules are available before creating the plugin
    if not is_ida():
        print("[mp5] ERROR: Cannot load as plugin outside IDA environment.")
        return None
    return MyTaskManagerPlugin()
