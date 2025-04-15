import multiprocessing
import os
import pathlib
import platform  # Keep for logging
import queue
import random
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

# --- Configuration ---

# Directly use the specified path construction
prefix_path = pathlib.Path(sys.exec_prefix)
specific_python_path = prefix_path / "bin" / "python"

PYTHON_EXECUTABLE = str(specific_python_path)

STDERR_LOG_PATH = pathlib.Path("./worker_stderr_specific_path.log")


# --- Simple target function (same as before) ---
def simple_worker_task():
    with STDERR_LOG_PATH.open("w+", encoding="utf-8") as f_err:
        print(
            f"WORKER (PID: {os.getpid()}): Hello from worker!", flush=True, file=f_err
        )
        print(f"WORKER (PID: {os.getpid()}): Exiting normally.", flush=True, file=f_err)


# --- Wrapper function for redirection (same as before) ---
def worker_wrapper(log_path):
    try:
        sys.stderr = open(log_path, "w", encoding="utf-8")
        simple_worker_task()
    except Exception as e:
        print(f"WORKER WRAPPER EXCEPTION: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        if sys.stderr and not sys.stderr.closed:
            sys.stderr.flush()


# --- Configuration Class ---
class ProcessingConfig:
    # Use max() to ensure at least 1 worker, not min()
    NUM_WORKERS: int = max(1, multiprocessing.cpu_count() // 2)
    CHECKPOINT_INTERVAL_S: float = 60.0
    SQLITE_DB_FILENAME: str = "processing_state.db"


# --- Data Structures ---
class TaskStatus(Enum):
    PENDING = auto()
    PROCESSING = auto()
    COMPLETED = auto()
    FAILED = auto()


@dataclass
class Task:
    task_id: str
    offset: int
    size: int


@dataclass
class Result:
    task_id: str
    status: TaskStatus
    payload: Any = None


# Manager Signals QObject
class ManagerSignals(QObject):
    progress_updated = Signal(int, int, int)
    log_message = Signal(int, str, str)  # level, process name, message
    error_occurred = Signal(str)
    processing_complete = Signal(int, int)
    processing_terminated = Signal()


from PySide6.QtCore import QCoreApplication, QObject, Qt, Signal, Slot
from PySide6.QtWidgets import QApplication


# Processing Manager Thread
class ProcessingManager(threading.Thread):
    def __init__(self, data: bytearray, config: ProcessingConfig):
        super().__init__(name="ProcessingManagerThread", daemon=True)
        self.data_size = len(data)
        self.initial_data = data
        self.config = config
        self.signals = ManagerSignals()
        self.task_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.log_queue = multiprocessing.Queue()
        self.shm_name = f"shm_{random.randint(0, 1000000)}"  # Generate unique name
        self.shm = None
        self.db_conn = None
        self.workers: List[multiprocessing.Process] = []
        self._stop_event = threading.Event()
        self.tasks: Dict[str, Tuple[Task, TaskStatus]] = {}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0

    def run(self):
        print("Manager thread started.")
        last_checkpoint_time = time.monotonic()
        shm_created_by_this_instance = False

        try:

            print(f"Starting {self.config.NUM_WORKERS} worker processes...")
            for i in range(self.config.NUM_WORKERS):
                # *** Target is the WRAPPER function ***
                p = multiprocessing.Process(
                    target=worker_wrapper,  # Use the wrapper
                    args=(STDERR_LOG_PATH,),
                    name=f"Worker-{i}",
                    daemon=True,
                )
                self.workers.append(p)
                p.start()
                print(f"Worker-{i} (PID: {p.pid}) started.")

            pending_tasks = [
                task
                for task, status in self.tasks.values()
                if status == TaskStatus.PENDING
            ]
            print(f"Distributing {len(pending_tasks)} pending tasks.")
            for task in pending_tasks:
                self.task_queue.put(task)

            while (self.completed_tasks + self.failed_tasks) < self.total_tasks:
                if self._stop_event.is_set():
                    print("Stop event received. Initiating shutdown.")
                    break
                try:
                    result: Result = self.result_queue.get(
                        timeout=0.5
                    )  # Adjusted timeout
                except queue.Empty:
                    alive_workers = sum(1 for w in self.workers if w.is_alive())
                    # Check for worker death *only if* tasks are expected to be running
                    if (
                        alive_workers < len(self.workers)
                        and (self.completed_tasks + self.failed_tasks)
                        < self.total_tasks
                    ):
                        # Check exit codes if workers died prematurely
                        for i, w in enumerate(self.workers):
                            if not w.is_alive() and w.exitcode != 0:
                                print(
                                    f"Worker {w.name} (PID: {w.pid}) terminated unexpectedly with exit code {w.exitcode}. Check crash logs."
                                )
                        # Avoid triggering error immediately, maybe other workers finish
                        # If all die, the next check handles it.

                    if (
                        alive_workers == 0
                        and (self.completed_tasks + self.failed_tasks)
                        < self.total_tasks
                    ):
                        msg = "All workers terminated prematurely."
                        print(msg)
                        self.signals.error_occurred.emit(msg)
                        break  # Exit manager loop
                    continue  # Continue loop if timeout occurred but workers potentially alive
                else:
                    # Process result
                    print(
                        f"Received result for task {result.task_id}: Status {result.status}"
                    )
                    self._update_task_status(
                        result.task_id, result.status, str(result.payload)
                    )
                    self.signals.progress_updated.emit(
                        self.completed_tasks, self.failed_tasks, self.total_tasks
                    )

                now = time.monotonic()
                if now - last_checkpoint_time > self.config.CHECKPOINT_INTERVAL_S:
                    print("Performing periodic checkpoint...")
                    if self.db_conn:
                        try:
                            self.db_conn.commit()
                        except Exception as db_e:
                            print(f"Checkpoint commit failed: {db_e}")
                    last_checkpoint_time = now

            if (
                not self._stop_event.is_set()
                and (self.completed_tasks + self.failed_tasks) >= self.total_tasks
            ):
                print("All tasks processed.")
                self.signals.processing_complete.emit(
                    self.completed_tasks, self.failed_tasks
                )

        except Exception as e:
            print(f"Exception in manager thread run loop: {e}")
            self.signals.error_occurred.emit(f"Manager thread error: {e}")
        finally:
            # --- Cleanup ---
            print("Manager thread cleaning up...")
            print("Signaling workers to terminate...")
            for _ in range(len(self.workers)):
                try:
                    self.task_queue.put(None, timeout=0.1)  # Short timeout
                except queue.Full:
                    pass  # Ignore if full during shutdown
                except Exception:
                    pass
            print("Joining worker processes...")
            # Allow slightly more time for workers to finish logging/cleanup
            join_timeout = 15.0
            start_join = time.monotonic()
            for worker in self.workers:
                try:
                    remaining_time = join_timeout - (time.monotonic() - start_join)
                    if remaining_time <= 0:
                        print(f"Timeout expired before joining {worker.name}")
                        if worker.is_alive():
                            worker.terminate()
                            worker.join(1)
                        continue
                    worker.join(timeout=remaining_time)
                    if worker.is_alive():
                        print(
                            f"Worker {worker.name} did not exit after join, terminating."
                        )
                        worker.terminate()
                        worker.join(1)  # Final wait after terminate
                    else:
                        print(
                            f"Worker {worker.name} joined cleanly (Exitcode: {worker.exitcode})."
                        )
                except Exception as e:
                    print(f"Error joining worker {worker.name}: {e}")
            print("Finished joining workers.")

            print("Closing queues...")
            for q in [self.task_queue, self.result_queue, self.log_queue]:
                try:
                    q.close()
                    q.join_thread()
                except Exception:
                    pass

            print("Manager thread finished cleanup.")
            self.signals.processing_terminated.emit()

    def request_stop(self):
        print("Stop requested for manager thread.")
        self._stop_event.set()

    # get_modified_data_view remains the same


from PySide6.QtCore import QCoreApplication, QObject, Qt, Signal, Slot
from PySide6.QtWidgets import QApplication


class ByteProcessorPlugin(QObject):
    def __init__(self):
        super().__init__()  # Still call object init if QObject is mocked
        self.manager_thread: Optional[ProcessingManager] = None

    def start_processing(self, data: bytearray):
        print("Starting background processing...")
        # Create manager instance
        self.manager_thread = ProcessingManager(data, ProcessingConfig())

        # Connect signals
        self.manager_thread.signals.progress_updated.connect(self._handle_progress)
        self.manager_thread.signals.log_message.connect(self._handle_log)
        self.manager_thread.signals.error_occurred.connect(self._handle_error)
        self.manager_thread.signals.processing_complete.connect(self._handle_completion)
        self.manager_thread.signals.processing_terminated.connect(
            self._handle_termination
        )

        self.manager_thread.start()
        print("Background processing manager started.")

    def stop_processing(self):
        if self.manager_thread and self.manager_thread.is_alive():
            print("Requesting background processing stop...")
            self.manager_thread.request_stop()
        else:
            print("Processing not running.")

    # --- Slot Methods (remain the same) ---
    @Slot(int, int, int)
    def _handle_progress(self, completed, failed, total):
        percent = (completed + failed) / total * 100 if total > 0 else 0
        print(
            f"Progress: {completed}/{total} completed ({failed} failed) [{percent:.1f}%]"
        )

    @Slot(int, str, str)
    def _handle_log(self, level, process_name, message):
        try:
            print(f"[{process_name}] {message}")
        except Exception as e:
            print(f"Error in _handle_log slot: {e}")

    @Slot(str)
    def _handle_error(self, error_msg):
        print(f"Processing error reported: {error_msg}")

    @Slot(int, int)
    def _handle_completion(self, completed, failed):
        print(
            f"Processing completed. Total tasks processed: {completed+failed}, Failed: {failed}"
        )

    @Slot()
    def _handle_termination(self):
        print("Processing manager has terminated and cleaned up.")
        self.manager_thread = None


# --- Main execution block (important for spawn) ---
if __name__ == "__main__":
    print(f"PARENT (PID: {os.getpid()}): Script started.")
    # Delete old log file
    if STDERR_LOG_PATH.exists():
        try:
            STDERR_LOG_PATH.unlink()
            print(f"PARENT: Removed old log file: {STDERR_LOG_PATH}")
        except OSError as e:
            print(f"PARENT: Warning - Could not remove old log file: {e}")

    try:
        # --- Setup multiprocessing ---
        multiprocessing.set_executable(PYTHON_EXECUTABLE)
        try:
            multiprocessing.set_start_method("spawn", force=True)
        except ValueError:  # Already set
            current_method = multiprocessing.get_start_method()
            print(f"PARENT: Start method already set to '{current_method}'.")
            if current_method != "spawn":
                print("PARENT: ERROR - Start method not 'spawn', script might fail.")
                sys.exit(1)

        # In IDA, get existing instance
        app = QApplication.instance()
        if app is None:
            print("Running in IDA context but QApplication not found!")
            # Attempt to create one? Might interfere with IDA.
            # app = QApplication(sys.argv) ?
            # _RUN_EVENT_LOOP = True ? # Risky
        else:
            print("Using existing IDA QApplication instance.")

        # --- Instantiate plugin, generate data, start processing ---
        plugin_instance = ByteProcessorPlugin()
        data_size = 0x100000  # 1MB for testing
        print(f"Generating {data_size / (1024*1024):.2f} MB of sample data...")
        original_data = bytearray([i % 256 for i in range(data_size)])

        plugin_instance.start_processing(original_data)
        # --- Create and start the process ---
        print("PARENT: Creating Process object...")
        # p = multiprocessing.Process(target=worker_wrapper, args=(STDERR_LOG_PATH,))

        # print("PARENT: Starting process...")
        # p.start()

        # --- Wait for the process to complete ---
        # print(f"PARENT: Waiting for process {p.pid if p.pid else '?'} to finish...")
        # p.join(timeout=10)  # Wait up to 10 seconds

        # --- Check the outcome ---
        # if p.is_alive():
        #    print(f"PARENT: Process {p.pid} is still alive, terminating.")
        #    p.terminate()
        #    p.join(timeout=2)  # Give terminate time
        # exit_code = (
        #    p.exitcode
        #    if hasattr(p, "exitcode") and p.exitcode is not None
        #    else "Unknown/Terminated"
        # )
        # print(f"PARENT: Process finished. Exit code: {exit_code}")

        # --- Check the stderr log file ---
        if STDERR_LOG_PATH.exists():
            print(f"PARENT: Reading worker stderr log: {STDERR_LOG_PATH}")
            try:
                with open(STDERR_LOG_PATH, "r", encoding="utf-8") as f_err:
                    stderr_content = f_err.read()
                if stderr_content:
                    print("------ Worker stderr START ------")
                    print(stderr_content)
                    print("------- Worker stderr END -------")
                else:
                    print("PARENT: Worker stderr log is empty.")
            except Exception as e:
                print(f"PARENT: Error reading stderr log: {e}")
        else:
            print(f"PARENT: Worker stderr log file not found ({STDERR_LOG_PATH}).")

    except Exception as e:
        print(f"PARENT: An error occurred in the main script: {e}")
        traceback.print_exc()

    print("PARENT: Script finished.")
