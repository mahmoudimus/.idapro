"""
IDA Pro plugin to launch a Python worker pool and offload tasks.
"""

import json
import os
import pathlib
import queue
import subprocess
import sys
import threading
import time

# Use PyQt5 for IDA's main GUI thread
from PyQt5 import QtCore, QtWidgets  # <-- Changed from PySide6
from PyQt5.QtCore import (  # <-- Import pyqtSignal for signal definition
    pyqtSignal,
    pyqtSlot,
)

from idaapi import *
from idc import *

# Configuration
WORKER_COUNT = 4  # Number of worker processes
TASK_QUEUE_TIMEOUT = 0.1  # Timeout for getting tasks from the queue
EVENT_LOOP_INTERVAL = 0.01  # seconds
WORKER_SCRIPT_PATH = pathlib.Path(get_user_idadir()) / "scripts" / "worker_script.py"


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
    print(
        "Could not reliably determine Python interpreter path; falling back to 'python'."
    )
    return pathlib.Path("python")


class Worker(QtCore.QObject):
    """
    Worker thread for processing tasks.
    NOTE: This Worker class runs in the *worker process*, not the IDA GUI thread.
    It doesn't strictly need Qt signals if using other IPC, but we keep them for
    concept matching with the IDA side's result processing via signals.
    However, the communication *to* this worker thread (via Queue)
    and *from* it (via result_queue, which will be handled by the parent process)
    is the primary mechanism here. The signals here are less critical unless
    you were running the worker in a QThread *within* the worker process,
    which we are not. Let's simplify this Worker class for the external process.
    """

    # We don't need Qt signals in the worker *process*
    pass  # The actual worker logic will be in worker_script.py


class WorkerPoolProcess(QtCore.QProcess):
    """
    Process that hosts the worker pool.
    """

    # Signals must be defined using pyqtSignal in PyQt5
    finished = pyqtSignal(int, QtCore.QProcess.ExitStatus)  # <-- Use pyqtSignal
    readyReadStandardOutput = pyqtSignal()  # <-- Use pyqtSignal
    readyReadStandardError = pyqtSignal()  # <-- Use pyqtSignal

    def __init__(self, task_queue, result_queue):
        super().__init__()
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.python_executable = get_python_interpreter()
        # Use a more reliable path for the worker script
        self.script_dir = WORKER_SCRIPT_PATH.parent
        self.script_path = WORKER_SCRIPT_PATH

        # Connect signals using the new syntax if necessary, though PyQt5 handles this
        # automatically when inheriting from QProcess. The definitions above are key.
        self.readyReadStandardOutput.connect(self.read_output)
        self.readyReadStandardError.connect(self.read_error)
        self.finished.connect(self.process_finished)

        # Ensure the worker script exists before trying to run it
        self._create_worker_script()

    def start_pool(self, worker_count):
        if not self.script_path.exists():
            print(f"Error: Worker script not found at {self.script_path}")
            self._create_worker_script()  # Attempt to create it again
            if not self.script_path.exists():
                print("FATAL: Could not create worker script. Cannot start pool.")
                return

        args = [self.python_executable, self.script_path, str(worker_count)]
        print(
            f"Starting worker pool process: {self.python_executable} {' '.join(args)}"
        )
        try:
            self.start(self.python_executable, args)
            if not self.waitForStarted(
                5000
            ):  # Wait up to 5 seconds for process to start
                print(f"Error starting worker pool process: {self.errorString()}")
        except Exception as e:
            print(f"Exception during process start: {e}")

    def read_output(self):
        data = self.readAllStandardOutput().data().decode().strip()
        if data:  # Only process if there's actual data
            # Attempt to parse JSON results from worker
            for line in data.splitlines():
                try:
                    result_data = json.loads(line)
                    # Assuming worker sends {"task_id": id, "result": res}
                    task_id = result_data.get("task_id")
                    result = result_data.get("result")
                    if task_id is not None:
                        # Put result back into the main process's result queue
                        self.result_queue.put((task_id, result))
                except json.JSONDecodeError:
                    # If it's not JSON, treat as a log message from the worker
                    print(f"Worker Pool Log: {line}")
                    if hasattr(self, "log_callback") and callable(self.log_callback):
                        self.log_callback(f"Worker Pool Log: {line}")

    def read_error(self):
        data = self.readAllStandardError().data().decode().strip()
        if data:
            print(f"Worker Pool Error: {data}")
            if hasattr(self, "log_callback") and callable(self.log_callback):
                self.log_callback(f"Worker Pool Error: {data}")

    def process_finished(self, exit_code, exit_status):
        print(
            f"Worker pool process finished with code {exit_code} and status {exit_status}"
        )
        if hasattr(self, "process_finished_callback") and callable(
            self.process_finished_callback
        ):
            self.process_finished_callback()

    def _create_worker_script(self):
        """Helper to create the worker script file."""
        worker_script_content = """
import sys
import os
import json
import queue
import threading
import time

# Disable PySide6/PyQt if they somehow sneak into the worker environment path
# This is a defensive measure
try:
    if 'PySide6' in sys.modules:
        print("Warning: PySide6 found in worker process, attempting to remove.")
        # This is tricky and might not fully work if imports happened early
        sys.modules = {name: module for name, module in sys.modules.items() if 'PySide6' not in name}
    if 'PyQt5' in sys.modules:
        print("Warning: PyQt5 found in worker process, attempting to remove.")
        sys.modules = {name: module for name, module in sys.modules.items() if 'PyQt5' not in name}
except Exception as e:
    print(f"Error trying to clean up Qt modules in worker: {e}")


def worker(task_queue, result_queue):
    # Simple execution environment
    local_vars = {}
    global_vars = {} # Use a dedicated dict for task globals

    while True:
        try:
            # Use a small timeout to allow checking for poison pills more frequently
            task = task_queue.get(timeout=0.1)
            if task is None:
                # print("Worker received poison pill, exiting.") # Optional: log worker exit
                break  # Poison pill

            task_id, code, globals_data_str = task

            try:
                # Restore globals/locals - Deserialize with care!
                if globals_data_str:
                    temp_globals = json.loads(globals_data_str)
                    # Merge restored globals, prioritizing task-specific ones
                    global_vars.update(temp_globals)

                # Execute the code in the isolated environment
                # Pass global_vars as both globals and locals for simplicity in exec
                exec(code, global_vars, global_vars)

                # Get result assuming it's put into a 'result' variable in the executed code
                result = global_vars.get('result', None)

                # Serialize result and potentially modified globals to send back
                # Filter out non-serializable objects added by exec if necessary
                serializable_result = None
                try:
                     serializable_result = json.dumps(result)
                except TypeError:
                     serializable_result = f"Result not JSON serializable: {type(result)}"

                # Send result back as JSON
                result_queue.put(json.dumps({"task_id": task_id, "result": serializable_result}))

                # Optional: Send back updated serializable globals
                # serializable_globals = {k: v for k, v in global_vars.items() if isinstance(v, (int, float, str, bool, list, dict, tuple, type(None)))}
                # result_queue.put(json.dumps({"task_id": task_id, "globals": serializable_globals}))


            except Exception as e:
                # Send error back as JSON
                error_msg = f"Execution Error: {type(e).__name__}: {str(e)}"
                result_queue.put(json.dumps({"task_id": task_id, "error": error_msg}))

            # Mark task as done - important for JoinableQueue if used, but not needed for simple Queue
            # task_queue.task_done()

        except queue.Empty:
            # No task, just pass and loop
            pass
        except Exception as e:
             # Catch unexpected errors in the worker loop itself
             print(f"Unexpected Worker Error: {type(e).__name__}: {str(e)}", file=sys.stderr)
             # sys.stderr.flush() # Ensure error is visible
             time.sleep(0.1) # Prevent tight loop on unexpected error


if __name__ == "__main__":
    # This process uses simple queues and stdin/stdout for IPC
    # In a real-world scenario, use multiprocessing.Queue or pipes
    # for more robust cross-process communication.
    # We'll simulate queues using global objects and thread safety assumption
    # within this single process, receiving tasks via stdin and sending results via stdout.

    if len(sys.argv) != 2:
        print("Usage: worker_script.py <worker_count>", file=sys.stderr)
        sys.exit(1)

    worker_count = int(sys.argv[1])

    # Use thread-safe queues for communication between main thread (reading stdin)
    # and worker threads within this process.
    input_queue = queue.Queue()
    output_queue = queue.Queue()

    workers = []
    for i in range(worker_count):
        # In this model, the worker threads process from input_queue and put to output_queue
        t = threading.Thread(target=worker, args=(input_queue, output_queue))
        t.daemon = True # Allow main process to exit even if threads are running
        t.start()
        workers.append(t)
        # print(f"Worker thread {i} started.") # Optional: log worker start

    # Main thread for IPC (reading stdin, writing stdout)
    def ipc_handler(input_q, output_q):
        # Thread to read from stdin
        def read_stdin(q):
            try:
                while True:
                    # Read raw bytes to handle potential encoding issues, then decode
                    line_bytes = sys.stdin.buffer.readline()
                    if not line_bytes:
                        # print("stdin closed, exiting read_stdin thread.") # Optional: log
                        q.put(None) # Signal end of input
                        break
                    try:
                        line = line_bytes.decode('utf-8').strip()
                        if line:
                             # Expecting JSON string representing the task
                             data = json.loads(line)
                             q.put(data)
                    except json.JSONDecodeError:
                         print(f"Worker IPC Error: Cannot decode JSON from stdin: {line_bytes.decode('utf-8').strip()}", file=sys.stderr)
                    except Exception as e:
                         print(f"Worker IPC Error: Exception in read_stdin: {e}", file=sys.stderr)
            except Exception as e:
                 print(f"Worker IPC Fatal Error in read_stdin thread: {e}", file=sys.stderr)


        # Thread to write to stdout
        def write_stdout(q):
             try:
                 while True:
                     # Use get with a timeout to check if the main read thread has signaled exit
                     data = q.get(timeout=0.1)
                     if data is None:
                         # print("output_queue received None, exiting write_stdout thread.") # Optional: log
                         break
                     try:
                         # Data should already be a JSON string from the worker threads
                         print(data) # Write the JSON string followed by a newline
                         sys.stdout.flush() # Important! Send data immediately
                     except Exception as e:
                         print(f"Worker IPC Error: Exception in write_stdout: {e}", file=sys.stderr)
             except Exception as e:
                  print(f"Worker IPC Fatal Error in write_stdout thread: {e}", file=sys.stderr)


        # Start the IPC threads
        stdin_thread = threading.Thread(target=read_stdin, args=(input_q,))
        stdout_thread = threading.Thread(target=write_stdout, args=(output_q,))

        stdin_thread.daemon = True
        stdout_thread.daemon = True

        stdin_thread.start()
        stdout_thread.start()

        # Keep the main IPC thread alive while the reader/writer threads are running
        # Or wait for a signal to stop (e.g., parent process termination)
        # A simple way is to wait for stdin_thread to finish (parent closed pipe)
        stdin_thread.join()
        # Once stdin is closed, put None into output queue to signal writer to exit
        output_q.put(None)
        stdout_thread.join()

        # print("IPC handler threads finished.") # Optional: log


    # Start the IPC handling in the main thread
    ipc_handler(input_queue, output_queue)

    # Send poison pills to the worker threads
    # This should happen after IPC handler detects parent termination
    # which puts None into input_queue
    # print("Sending poison pills to workers...") # Optional: log
    for _ in range(worker_count):
        input_queue.put(None)

    # Wait for all workers to finish processing poison pills
    # print("Waiting for workers to join...") # Optional: log
    for t in workers:
        t.join(timeout=5) # Wait up to 5 seconds for each worker

    # print("Worker script exiting.") # Optional: log
    sys.exit(0) # Exit cleanly
"""
        if not self.script_path.exists():
            try:
                with self.script_path.open("w") as f:
                    f.write(worker_script_content)
                print(f"Created worker script: {self.script_path}")
            except Exception as e:
                print(f"Error creating worker script {self.script_path}: {e}")
        # else:
        # print(f"Worker script already exists: {self.script_path}") # Optional: avoid spamming


class LogWindow(QtWidgets.QDialog):
    """
    Log window for worker pool output and errors.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Worker Pool Log")
        self.text_edit = QtWidgets.QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.ensureCursorVisible()  # Auto-scroll to bottom
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.text_edit)
        self.setLayout(layout)

    @pyqtSlot(str)  # Use PyQt5 decorator for slots
    def append_text(self, text):
        """Append text to the log window."""
        self.text_edit.append(text)
        # Auto-scroll down
        cursor = self.text_edit.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.text_edit.setTextCursor(cursor)


# Need QtGui for QTextCursor in PyQt5
try:
    from PyQt5 import QtGui  # <-- Import QtGui
except ImportError:
    print(
        "Warning: Could not import PyQt5.QtGui. Auto-scrolling in log might not work."
    )

    # Define a dummy if import fails to avoid crashing
    class DummyQtGui:
        class QTextCursor:
            End = 0  # Dummy value

            def movePosition(self, pos):
                pass

    QtGui = DummyQtGui


class WorkerPoolWidget(QtWidgets.QWidget):
    """
    Widget to manage the worker pool and display log.
    """

    # Signal to update log window from a different thread (like the process result handler)
    log_signal = pyqtSignal(str)  # <-- Use pyqtSignal

    def __init__(self, task_queue, result_queue):
        super().__init__()
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.worker_pool_process = None
        self.log_window = LogWindow()  # Log window instance

        self.init_ui()

        # Connect internal log signal to the log window slot
        self.log_signal.connect(self.log_window.append_text)

    def init_ui(self):
        self.setWindowTitle("Python Worker Pool")
        self.layout = QtWidgets.QVBoxLayout()

        self.start_button = QtWidgets.QPushButton("Start Worker Pool")
        self.start_button.clicked.connect(self.start_worker_pool)
        self.layout.addWidget(self.start_button)

        self.stop_button = QtWidgets.QPushButton("Stop Worker Pool")
        self.stop_button.clicked.connect(self.stop_worker_pool)
        self.stop_button.setEnabled(False)  # Initially disabled
        self.layout.addWidget(self.stop_button)

        self.status_label = QtWidgets.QLabel("Status: Stopped")
        self.layout.addWidget(self.status_label)

        # Removed separate log button, integrate log window directly or keep it always available
        # self.log_button = QtWidgets.QPushButton("Show Log")
        # self.log_button.clicked.connect(self.show_log)
        # self.layout.addWidget(self.log_button)

        self.setLayout(self.layout)

        # Show log window by default when the widget is shown
        self.log_window.show()

    @pyqtSlot()  # Use PyQt5 decorator
    def start_worker_pool(self):
        if (
            self.worker_pool_process is None
            or self.worker_pool_process.state() == QtCore.QProcess.NotRunning
        ):
            self.log_signal.emit("Attempting to start worker pool...")
            self.worker_pool_process = WorkerPoolProcess(
                self.task_queue, self.result_queue
            )
            # Connect process signals to log output
            self.worker_pool_process.readyReadStandardOutput.connect(
                self.worker_pool_process.read_output
            )  # Connect to internal reader
            self.worker_pool_process.readyReadStandardError.connect(
                self.worker_pool_process.read_error
            )  # Connect to internal reader
            self.worker_pool_process.process_finished_callback = (
                self.worker_process_finished
            )  # Set a callback
            self.worker_pool_process.log_callback = (
                self.log_signal.emit
            )  # Set a callback for logs

            self.worker_pool_process.start_pool(WORKER_COUNT)

            if self.worker_pool_process.waitForStarted(2000):  # Wait up to 2 seconds
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
                self.status_label.setText(f"Status: Running ({WORKER_COUNT} workers)")
                self.log_signal.emit("Worker pool process started successfully.")
            else:
                self.log_signal.emit(
                    f"Failed to start worker pool process: {self.worker_pool_process.errorString()}"
                )
                self.worker_pool_process = None  # Reset if failed to start
                self.status_label.setText("Status: Start Failed")

    @pyqtSlot()  # Use PyQt5 decorator
    def stop_worker_pool(self):
        if (
            self.worker_pool_process
            and self.worker_pool_process.state() != QtCore.QProcess.NotRunning
        ):
            self.log_signal.emit("Stopping worker pool...")
            # Send a signal to the worker script to tell its IPC handler to exit
            # A clean way is to close the stdin pipe of the worker process
            self.worker_pool_process.closeWriteChannel()

            # Give it a moment to shut down gracefully
            if not self.worker_pool_process.waitForFinished(
                5000
            ):  # Wait up to 5 seconds
                self.log_signal.emit(
                    "Worker pool did not finish gracefully, killing process."
                )
                self.worker_pool_process.kill()
                self.worker_pool_process.waitForFinished()  # Wait for kill to complete

            self.worker_pool_process = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Status: Stopped")
            self.log_signal.emit("Worker pool stopped.")
        else:
            self.log_signal.emit("Worker pool not running.")

    @pyqtSlot(int, QtCore.QProcess.ExitStatus)  # Use PyQt5 decorator
    def worker_process_finished(self, exit_code, exit_status):
        """Callback when the worker process finishes."""
        status_text = (
            "NormalExit" if exit_status == QtCore.QProcess.NormalExit else "CrashExit"
        )
        self.log_signal.emit(
            f"Worker pool process finished with code {exit_code} and status {status_text}"
        )
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText(f"Status: Finished ({status_text})")
        # Clear the process reference after it's truly done
        self.worker_pool_process = None

    def show_log(self):
        """Show the log window."""
        self.log_window.show()
        self.log_window.raise_()  # Bring to front
        self.log_window.activateWindow()


class IDAPythonWorkerPool(ida_idaapi.plugin_t):
    """
    IDA Pro plugin class.
    """

    flags = (
        ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    )  # Allow multiple instances (though maybe not useful here)
    comment = "Python Worker Pool for IDA Pro"
    help = "Launches a Python worker pool to offload tasks."
    wanted_name = "Python Worker Pool"
    wanted_hotkey = "Ctrl-Shift-P"

    def init(self):
        # These queues are accessed by both the main IDA thread and a result processing thread
        # queue.Queue is thread-safe.
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.widget = None  # Hold reference to the GUI widget
        self.timer = None  # Timer for processing results
        self.initialized = False

        print(f"[{self.wanted_name}] Initializing...")

        # Check if we can load PyQt5
        try:
            from PyQt5 import QtCore, QtGui, QtWidgets

            print(
                f"[{self.wanted_name}] Successfully imported PyQt5. Using PyQt5 for GUI."
            )
            self.initialized = True
        except ImportError as e:
            print(
                f"[{self.wanted_name}] Error importing PyQt5: {e}. Cannot initialize plugin GUI."
            )
            # We return PLUGIN_SKIP so IDA knows the plugin failed to load properly
            # This prevents IDA from trying to call run() later and crashing.
            return ida_idaapi.PLUGIN_SKIP
        except Exception as e:
            print(
                f"[{self.wanted_name}] Unexpected error during PyQt5 import: {e}. Cannot initialize plugin GUI."
            )
            return ida_idaapi.PLUGIN_SKIP

        # Set up a timer to periodically check the result queue
        # This needs to happen on the main IDA/Qt GUI thread.
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.process_results)
        # Start the timer. EVENT_LOOP_INTERVAL is in seconds, QTimer needs milliseconds.
        self.timer.start(int(EVENT_LOOP_INTERVAL * 1000))

        print(
            f"[{self.wanted_name}] Initialization successful. Hotkey: {self.wanted_hotkey}"
        )
        return ida_idaapi.PLUGIN_KEEP  # Keep the plugin loaded

    def run(self, arg):
        """Called when the plugin is invoked (e.g., by hotkey or menu)."""
        if not self.initialized:
            print(
                f"[{self.wanted_name}] Plugin failed to initialize properly. Check output log."
            )
            return

        if self.widget is None:
            # Create the GUI widget. It will use the imported PyQt5.
            try:
                self.widget = WorkerPoolWidget(self.task_queue, self.result_queue)
            except Exception as e:
                print(f"[{self.wanted_name}] Error creating WorkerPoolWidget: {e}")
                self.widget = None
                return  # Exit run if widget creation fails

        # Show the widget. This runs on the main IDA GUI thread.
        self.widget.show()
        # Optional: bring the main widget and log window to front
        self.widget.raise_()
        self.widget.activateWindow()
        if self.widget.log_window:
            self.widget.log_window.raise_()
            self.widget.log_window.activateWindow()

        print(f"[{self.wanted_name}] Worker Pool Widget shown.")

    def term(self):
        """Called when the plugin is unloaded."""
        print(f"[{self.wanted_name}] Terminating...")
        # Stop the timer
        if self.timer and self.timer.isActive():
            self.timer.stop()
            print(f"[{self.wanted_name}] Timer stopped.")

        # Stop the worker pool process if it's running
        if self.widget:
            self.widget.stop_worker_pool()
            # The stop_worker_pool method handles the process termination and None-ing out.
            # We might want to explicitly close the widget window though.
            # Closing the widget will also close the log window if it's its parent,
            # but our log window is a separate QDialog, so close it explicitly.
            if self.widget.log_window:
                self.widget.log_window.close()
                print(f"[{self.wanted_name}] Log window closed.")

            self.widget.close()
            print(f"[{self.wanted_name}] Main widget closed.")
            self.widget = None  # Release reference

        # Clean up queues? Not strictly necessary as they are garbage collected,
        # but could be done if needed.
        # while not self.task_queue.empty(): self.task_queue.get_nowait()
        # while not self.result_queue.empty(): self.result_queue.get_nowait()

        print(f"[{self.wanted_name}] Termination complete.")

    # Use PyQt5 decorator for slots if necessary, but this is called directly by QTimer
    def process_results(self):
        """
        Periodically called by QTimer to process results from the result queue.
        This runs on the main IDA GUI thread.
        """
        # print(f"[{self.wanted_name}] Checking result queue...") # Uncomment for debugging timer
        while not self.result_queue.empty():
            try:
                # Use get_nowait() to process available results without blocking
                result_item = self.result_queue.get_nowait()

                # Result item should be a JSON string from the worker process
                try:
                    result_data = json.loads(result_item)
                    task_id = result_data.get("task_id", "N/A")

                    if "result" in result_data:
                        result_value = result_data["result"]
                        log_message = f"Task {task_id} Result: {result_value}"
                        print(log_message)  # Print to IDA output window
                        if self.widget:
                            self.widget.log_signal.emit(
                                log_message
                            )  # Emit signal to update log GUI

                    elif "error" in result_data:
                        error_message = result_data["error"]
                        log_message = f"Task {task_id} Error: {error_message}"
                        print(log_message)  # Print to IDA output window
                        if self.widget:
                            self.widget.log_signal.emit(
                                f"<font color='red'>{log_message}</font>"
                            )  # Use HTML for color in Qt log

                    # Handle potential globals update if needed
                    # elif "globals" in result_data:
                    #      updated_globals = result_data["globals"]
                    # Logic to update globals in the main IDA script's context
                    # This is complex and potentially risky - handle with care!
                    # print(f"Task {task_id} updated globals: {updated_globals}")

                except json.JSONDecodeError:
                    # Should not happen if worker sends valid JSON, but handle corrupted data
                    log_message = (
                        f"Failed to decode result JSON from worker: {result_item}"
                    )
                    print(f"[{self.wanted_name}] {log_message}")
                    if self.widget:
                        self.widget.log_signal.emit(
                            f"<font color='orange'>Warning: {log_message}</font>"
                        )

                # If using JoinableQueue, call task_done() here. Not needed for simple Queue.
                # self.result_queue.task_done()

            except queue.Empty:
                # This is expected when the queue is empty
                break
            except Exception as e:
                # Catch unexpected errors during result processing on the main thread
                log_message = (
                    f"[{self.wanted_name}] Unexpected error processing result: {e}"
                )
                print(log_message)
                if self.widget:
                    self.widget.log_signal.emit(
                        f"<font color='red'>{log_message}</font>"
                    )


def submit_task(code, globals_to_send=None):
    """
    Submit a task (Python code snippet) to the worker pool.
    Can optionally send a dictionary of serializable global variables.
    This function is intended to be called from *other* IDA Python scripts
    once the worker pool plugin is loaded and running.
    """
    # Find the running plugin instance to get access to its queues
    # This assumes there's only one instance running, or you need a way to get the specific one.
    # A more robust way might be a global access point managed by the plugin itself.
    plugin_instance = None
    for plugin in ida_idaapi.get_plugins():
        # Check if the plugin name matches and it's a loaded instance
        if (
            hasattr(plugin, "wanted_name")
            and plugin.wanted_name == "Python Worker Pool"
            and hasattr(plugin, "task_queue")
        ):
            # Check if it's a loaded plugin instance (not just the PLUGIN_ENTRY)
            # This is tricky. A simple approach is to trust the first one found or use a global variable.
            # Let's assume for simplicity the first one found with the right attributes is the running one.
            plugin_instance = plugin
            break  # Found it!

    if plugin_instance is None:
        print("Error: Python Worker Pool plugin not loaded or initialized.")
        return None  # Indicate failure

    task_queue = plugin_instance.task_queue

    global task_id_counter
    if "task_id_counter" not in globals():
        globals()["task_id_counter"] = 0
    task_id_counter += 1
    task_id = task_id_counter

    # Serialize specified globals, or an empty dict if none provided
    globals_dict = {}
    if globals_to_send:
        # Only include serializable types
        globals_dict = {
            k: v
            for k, v in globals_to_send.items()
            if isinstance(v, (int, float, str, bool, list, dict, tuple, type(None)))
        }
        # Add a warning if non-serializable types were requested
        non_serializable_keys = [
            k
            for k, v in globals_to_send.items()
            if not isinstance(v, (int, float, str, bool, list, dict, tuple, type(None)))
        ]
        if non_serializable_keys:
            print(
                f"Warning: Non-serializable global variables skipped: {non_serializable_keys}"
            )

    try:
        globals_data = json.dumps(globals_dict)
    except Exception as e:
        print(f"Error serializing globals for task {task_id}: {e}")
        return None  # Cannot submit task if globals can't be serialized

    task_queue.put((task_id, code, globals_data))
    print(f"Task {task_id} submitted to worker pool.")
    return task_id


# Create worker_script.py if it doesn't exist
# This is handled by the WorkerPoolProcess class now, so it's created when the plugin starts the process.
# script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker_script.py")
# if not os.path.exists(script_path):
#     with open(script_path, "w") as f:
#         f.write(WORKER_SCRIPT)


# Instantiate and register the plugin
def PLUGIN_ENTRY():
    return IDAPythonWorkerPool()
