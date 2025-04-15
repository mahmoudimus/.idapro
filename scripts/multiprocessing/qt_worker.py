import logging
import logging.handlers
import math
import multiprocessing
import pathlib
import queue
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum, auto
from multiprocessing import Queue, shared_memory  # Explicitly import Queue
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if sys.platform == "win32":
    PYTHON_BIN = pathlib.Path(sys.exec_prefix) / "python.exe"
else:
    PYTHON_BIN = pathlib.Path(sys.exec_prefix) / "bin" / "python"

assert PYTHON_BIN.exists(), f"Python executable not found: {PYTHON_BIN}"

try:
    from PySide6.QtCore import QCoreApplication, QObject, Qt, QTimer, Signal, Slot

    _PYSIDE_AVAILABLE = True
except ImportError:
    # ... (Fallback definitions as before) ...
    logging.error(
        "PySide6 not found. Install it (`pip install PySide6`) for Qt integration."
    )
    _PYSIDE_AVAILABLE = False

    class QObject:
        pass

    def Signal(*args, **kwargs):
        return object()

    def Slot(*args, **kwargs):
        return lambda func: func

    class Qt:
        AutoConnection = 0
        QueuedConnection = 1


# --- Logging Setup (Main Process/Manager Config) ---
# This basicConfig will apply to the main process and the manager thread initially.
# The listener will handle records from the workers.
# log_format = '%(asctime)s - %(levelname)s - [%(threadName)s/%(processName)s] - %(message)s'
# Add processName to see logs from specific workers more easily if needed via StreamHandler
log_format = "%(asctime)s - %(levelname)s - [%(name)s:%(processName)s] - %(message)s"
logging.basicConfig(level=logging.INFO, format=log_format)


# --- Constants / Configuration (Unchanged) ---
class ProcessingConfig:
    NUM_WORKERS: int = min(1, multiprocessing.cpu_count() // 2)
    CHECKPOINT_INTERVAL_S: float = 60.0
    SQLITE_DB_FILENAME: str = "processing_state.db"
    SHM_NAME_PREFIX: str = f"ida_byte_proc_{multiprocessing.current_process().pid}_"
    # Log level for worker processes (sent via QueueHandler)
    WORKER_LOG_LEVEL: int = logging.DEBUG


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


# Modified Result: Removed log-specific fields
@dataclass
class Result:
    task_id: str
    status: TaskStatus
    payload: Any = None  # Result data or error message


# --- Worker Process Logic ---


def setup_worker_logging(log_queue: Queue, level: int):
    """Configures logging in a worker process to send records to the queue."""
    queue_handler = logging.handlers.QueueHandler(log_queue)
    # Get the root logger specific to this worker process
    root_logger = logging.getLogger()
    root_logger.handlers.clear()  # Remove any default/inherited handlers
    root_logger.addHandler(queue_handler)
    root_logger.setLevel(level)


def worker_process_main(
    task_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    log_queue: Queue,  # Added log queue argument
    shm_name: str,
    shm_size: int,
    worker_log_level: int,  # Pass the desired level
):
    """Main function executed by each worker process."""

    # --- Configure logging FIRST ---
    setup_worker_logging(log_queue, worker_log_level)

    worker_name = multiprocessing.current_process().name
    logging.info(
        f"Worker started. Attaching to SHM '{shm_name}'"
    )  # Now uses standard logging

    shm = None
    try:
        # --- SHM Attachment (same as before) ---
        shm = shared_memory.SharedMemory(name=shm_name)
        if shm.size != shm_size:
            raise ValueError(
                f"SHM size mismatch: expected {shm_size}, found {shm.size}"
            )
        buffer = shm.buf
        logging.info("Attached to SHM.")

        # --- Main Worker Loop ---
        while True:
            try:
                task: Optional[Task] = task_queue.get()
                if task is None:
                    logging.info("Received shutdown signal.")  # Standard logging
                    break

                # --- Use standard logging with task context ---
                logging.info(f"Task {task.task_id}: Starting processing.")

                try:
                    # --- Actual Data Processing (same as before) ---
                    chunk_view = memoryview(buffer)[
                        task.offset : task.offset + task.size
                    ]
                    processed_count = 0
                    for i in range(len(chunk_view)):
                        chunk_view[i] = 255 - chunk_view[i]
                        processed_count += 1
                    # logging.debug(f"Task {task.task_id}: Processed {processed_count} bytes.") # Example debug log

                    # --- Task Completed ---
                    result_payload = {"bytes_processed": processed_count}
                    # Only put actual results on the result_queue
                    result = Result(
                        task_id=task.task_id,
                        status=TaskStatus.COMPLETED,
                        payload=result_payload,
                    )
                    result_queue.put(result)
                    logging.info(f"Task {task.task_id}: Completed successfully.")

                except Exception as e:
                    # Use logging.exception to include traceback in the log record
                    logging.exception(f"Task {task.task_id}: Error during processing.")
                    result = Result(
                        task_id=task.task_id, status=TaskStatus.FAILED, payload=str(e)
                    )
                    result_queue.put(result)
                    # logging.error(f"Task {task.task_id}: Failed: {e}") # Redundant if using logging.exception

            except (EOFError, BrokenPipeError):
                logging.warning("Queue connection lost, exiting.")
                break
            except Exception as e:
                logging.exception(
                    "Unexpected error in worker main loop."
                )  # Standard logging
                break

    except FileNotFoundError:
        logging.error(f"Could not find SHM block: {shm_name}")  # Standard logging
    except Exception as e:
        logging.exception(
            "Worker failed during initialization or shutdown."
        )  # Standard logging
    finally:
        if shm:
            shm.close()
            logging.info("Closed SHM handle.")  # Standard logging
        logging.info("Worker exiting.")  # Standard logging


# Removed _log_via_queue helper function


# --- Manager Thread Logic ---


# 1. Custom Log Handler that emits Qt signals
class QtSignalHandler(logging.Handler):
    """A logging handler that emits Qt signals with log record info."""

    def __init__(self, signal_emitter_func):
        """
        Args:
            signal_emitter_func: A callable that returns the QObject containing
                                 the log_message signal to be emitted.
                                 (Passed as a func to avoid instance issues during init).
        """
        super().__init__()
        self.signal_emitter_func = signal_emitter_func
        # Basic formatter, customize as needed
        self.setFormatter(
            logging.Formatter("%(levelname)s:%(name)s:%(processName)s: %(message)s")
        )

    def emit(self, record: logging.LogRecord):
        """Formats the record and emits the log_message signal."""
        if not _PYSIDE_AVAILABLE:
            return  # Do nothing if Qt is not available

        try:
            # Get the signal emitter object (ManagerSignals instance)
            signal_emitter = self.signal_emitter_func()
            if signal_emitter:
                # Format the message using the handler's formatter
                msg = self.format(record)
                # Extract process name (useful for identifying worker)
                process_name = record.processName
                # Emit the signal: level number, process name, formatted message
                # Make sure the receiving slot signature matches!
                signal_emitter.log_message.emit(record.levelno, process_name, msg)
        except Exception:
            self.handleError(record)  # Default error handling (prints to stderr)


# 2. Define ManagerSignals (QObject with signals) - Signature of log_message updated
class ManagerSignals(QObject):
    if _PYSIDE_AVAILABLE:
        progress_updated = Signal(int, int, int)
        # Updated log_message signature: level (int), process name (str), message (str)
        log_message = Signal(int, str, str)
        error_occurred = Signal(str)
        processing_complete = Signal(int, int)
        processing_terminated = Signal()
    else:
        # ... (Dummy signals as before) ...
        progress_updated = object()
        log_message = object()
        error_occurred = object()
        processing_complete = object()
        processing_terminated = object()


# 3. Modify ProcessingManager
class ProcessingManager(threading.Thread):
    def __init__(self, data: bytearray, db_path: Path, config: ProcessingConfig):
        super().__init__(name="ProcessingManagerThread", daemon=True)
        self.data_size = len(data)
        self.initial_data = data
        self.db_path = db_path
        self.config = config

        self.signals = ManagerSignals()  # Signals object (same)

        # Queues: one for tasks, one for results, one dedicated for logs
        self.task_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.log_queue = multiprocessing.Queue()  # Dedicated log queue
        self.log_listener: Optional[logging.handlers.QueueListener] = (
            None  # Add listener instance var
        )

        self.shm_name = f"{self.config.SHM_NAME_PREFIX}{uuid.uuid4()}"
        self.shm = None
        self.db_conn = None
        self.workers: List[multiprocessing.Process] = []

        self._stop_event = threading.Event()
        self.tasks: Dict[str, Tuple[Task, TaskStatus]] = {}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0

    # _initialize_db, _load_or_create_tasks (remain the same internally)
    # ... (Code for _initialize_db, _load_or_create_tasks identical) ...
    def _initialize_db(self):
        # ... (Identical) ...
        self.db_conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.db_conn.cursor()
        # Simplified table creation for brevity
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS tasks (task_id TEXT PRIMARY KEY, offset INTEGER, size INTEGER, status TEXT, result_payload TEXT NULL)"
        )
        cursor.execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES (?, ?)",
            ("shm_name", self.shm_name),
        )
        cursor.execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES (?, ?)",
            ("data_size", str(self.data_size)),
        )
        self.db_conn.commit()
        logging.info(f"Initialized/Connected to database: {self.db_path}")

    def _load_or_create_tasks(self):
        # ... (Identical logic, ensures self.total_tasks is set) ...
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT task_id, offset, size, status FROM tasks")
        existing_tasks = cursor.fetchall()
        if existing_tasks:
            logging.info(
                f"Resuming from checkpoint. Loading {len(existing_tasks)} task states."
            )
            for task_id, offset, size, status_str in existing_tasks:
                status = TaskStatus[status_str]
                task = Task(task_id=task_id, offset=offset, size=size)
                self.tasks[task_id] = (task, status)
                if status == TaskStatus.COMPLETED:
                    self.completed_tasks += 1
                elif status == TaskStatus.FAILED:
                    self.failed_tasks += 1
            self.total_tasks = len(self.tasks)
        else:
            logging.info(
                "No existing checkpoint found or starting fresh. Creating tasks."
            )
            chunk_size = 1 * 1024 * 1024
            num_chunks = math.ceil(self.data_size / chunk_size)
            self.total_tasks = 0
            tasks_to_insert = []
            for i in range(num_chunks):
                offset = i * chunk_size
                size = min(chunk_size, self.data_size - offset)
                if size <= 0:
                    continue
                task_id = str(uuid.uuid4())
                task = Task(task_id=task_id, offset=offset, size=size)
                self.tasks[task.task_id] = (task, TaskStatus.PENDING)
                tasks_to_insert.append((task_id, offset, size, TaskStatus.PENDING.name))
                self.total_tasks += 1
            cursor.execute("DELETE FROM tasks")
            cursor.executemany(
                "INSERT INTO tasks (task_id, offset, size, status) VALUES (?, ?, ?, ?)",
                tasks_to_insert,
            )
            self.db_conn.commit()
            logging.info(f"Created and saved {self.total_tasks} new tasks.")

    # _update_task_status (no longer needs to emit log signals directly here)
    def _update_task_status(
        self, task_id: str, status: TaskStatus, payload: Optional[str] = None
    ):
        if task_id in self.tasks:
            task, old_status = self.tasks[task_id]
            # --- Update counts logic (make sure it's correct for resume/transitions) ---
            status_changed = old_status != status
            was_completed = old_status == TaskStatus.COMPLETED
            was_failed = old_status == TaskStatus.FAILED
            is_completed = status == TaskStatus.COMPLETED
            is_failed = status == TaskStatus.FAILED

            if status_changed:
                self.tasks[task_id] = (task, status)  # Update in-memory state

                # Adjust counts based on transitions away from/to terminal states
                if was_completed and not is_completed:
                    self.completed_tasks -= 1
                if was_failed and not is_failed:
                    self.failed_tasks -= 1
                if is_completed and not was_completed:
                    self.completed_tasks += 1
                if is_failed and not was_failed:
                    self.failed_tasks += 1

                # --- Update DB ---
                try:
                    cursor = self.db_conn.cursor()
                    cursor.execute(
                        "UPDATE tasks SET status = ?, result_payload = ? WHERE task_id = ?",
                        (status.name, payload, task_id),
                    )
                except Exception as e:
                    # Log DB errors using standard logging (will be caught by listener if needed)
                    logging.exception(f"DB update failed for task {task_id}")
            # else: status did not change, no action needed
        else:
            logging.warning(f"Attempted update for unknown task_id: {task_id}")

    def run(self):
        logging.info("Manager thread started.")
        last_checkpoint_time = time.monotonic()
        shm_created_by_this_instance = False

        try:
            # --- Setup Log Listener ---
            # Define handlers: one for Qt signals, maybe one for console output from manager itself
            handlers = []
            if _PYSIDE_AVAILABLE:
                qt_handler = QtSignalHandler(
                    lambda: self.signals
                )  # Pass lambda to get signal obj
                handlers.append(qt_handler)

            # Optional: Add a StreamHandler to see worker logs directly in the manager's console output
            # stream_handler = logging.StreamHandler()
            # stream_handler.setFormatter(logging.Formatter('%(levelname)s:%(processName)s: %(message)s'))
            # handlers.append(stream_handler)

            if not handlers:
                logging.warning("No log handlers configured for QueueListener.")

            self.log_listener = logging.handlers.QueueListener(
                self.log_queue, *handlers, respect_handler_level=True
            )
            self.log_listener.start()
            logging.info("Log listener started.")

            # --- DB and SHM Setup (same as before) ---
            self._initialize_db()
            # ... (SHM creation/attachment logic) ...
            try:
                self.shm = shared_memory.SharedMemory(
                    name=self.shm_name, create=True, size=self.data_size
                )
                shm_created_by_this_instance = True
                logging.info("SHM block created. Copying initial data...")
                self.shm.buf[:] = self.initial_data
                self.initial_data = None  # Allow GC
            except FileExistsError:
                logging.warning(
                    f"SHM block '{self.shm_name}' already exists. Attaching."
                )
                self.shm = shared_memory.SharedMemory(name=self.shm_name, create=False)
                if self.shm.size != self.data_size:
                    raise RuntimeError("SHM size mismatch.")

            self._load_or_create_tasks()

            # --- Start Workers (pass log_queue) ---
            logging.info(f"Starting {self.config.NUM_WORKERS} worker processes...")
            for i in range(self.config.NUM_WORKERS):
                p = multiprocessing.Process(
                    target=worker_process_main,
                    args=(
                        self.task_queue,
                        self.result_queue,
                        self.log_queue,  # Pass the log queue
                        self.shm_name,
                        self.data_size,
                        self.config.WORKER_LOG_LEVEL,  # Pass log level
                    ),
                    name=f"Worker-{i}",
                    daemon=True
                )
                self.workers.append(p)
                p.start()

            # --- Distribute Tasks (same) ---
            pending_tasks = [
                task
                for task, status in self.tasks.values()
                if status == TaskStatus.PENDING
            ]
            logging.info(f"Distributing {len(pending_tasks)} pending tasks.")
            for task in pending_tasks:
                self.task_queue.put(task)

            # --- Main Loop (Handle only results_queue) ---
            while (self.completed_tasks + self.failed_tasks) < self.total_tasks:
                if self._stop_event.is_set():
                    logging.info("Stop event received. Initiating shutdown.")
                    break

                try:
                    # Only need to get from result_queue now
                    result: Result = self.result_queue.get(timeout=0.1)

                    # Process task completion/failure (log messages handled by listener)
                    logging.debug(
                        f"Received result for task {result.task_id}: Status {result.status}"
                    )
                    self._update_task_status(
                        result.task_id, result.status, str(result.payload)
                    )

                    # Emit progress signal (same as before)
                    if _PYSIDE_AVAILABLE:
                        self.signals.progress_updated.emit(
                            self.completed_tasks, self.failed_tasks, self.total_tasks
                        )

                except queue.Empty:  # Built-in queue.Empty
                    # ... check if workers are alive (same) ...
                    alive_workers = sum(1 for w in self.workers if w.is_alive())
                    if (
                        alive_workers == 0
                        and (self.completed_tasks + self.failed_tasks)
                        < self.total_tasks
                    ):
                        msg = "All workers terminated prematurely."
                        logging.error(msg)
                        if _PYSIDE_AVAILABLE:
                            self.signals.error_occurred.emit(msg)
                        break
                    pass

                # --- Checkpointing (same) ---
                now = time.monotonic()
                if now - last_checkpoint_time > self.config.CHECKPOINT_INTERVAL_S:
                    logging.info("Performing periodic checkpoint...")
                    if self.db_conn:
                        self.db_conn.commit()
                    last_checkpoint_time = now

            # --- End of loop (emit completion signal - same) ---
            if (
                not self._stop_event.is_set()
                and (self.completed_tasks + self.failed_tasks) >= self.total_tasks
            ):
                logging.info("All tasks processed.")
                if _PYSIDE_AVAILABLE:
                    self.signals.processing_complete.emit(
                        self.completed_tasks, self.failed_tasks
                    )

        except Exception as e:
            logging.exception("Exception in manager thread run loop:")
            if _PYSIDE_AVAILABLE:
                self.signals.error_occurred.emit(f"Manager thread error: {e}")
        finally:
            # --- Cleanup ---
            logging.info("Manager thread cleaning up...")

            # --- Stop Log Listener FIRST ---
            if self.log_listener:
                logging.info("Stopping log listener...")
                self.log_listener.stop()
                self.log_listener = None

            # --- Signal/Join Workers (same) ---
            logging.info("Signaling workers to terminate...")
            # ... (put None on task_queue, join workers) ...
            for _ in range(len(self.workers)):
                try:
                    self.task_queue.put(None, timeout=1.0)
                except:
                    pass
            logging.info("Joining worker processes...")
            for worker in self.workers:
                try:
                    worker.join(timeout=5.0)
                    if worker.is_alive():
                        worker.terminate()
                        worker.join()
                except Exception as e:
                    logging.exception(f"Error joining worker {worker.name}: {e}")

            # --- Close Queues (add log_queue) ---
            logging.info("Closing queues...")
            for q in [self.task_queue, self.result_queue, self.log_queue]:
                try:
                    q.close()
                except Exception as e:
                    logging.debug(f"Error closing queue: {e}")
            # Attempt to join queue threads (may fail if processes died)
            for q in [self.task_queue, self.result_queue, self.log_queue]:
                try:
                    q.join_thread()
                except (OSError, ValueError):
                    pass

            # --- Final DB Commit/Close (same) ---
            if self.db_conn:
                # ... (commit, close) ...
                logging.info("Committing final state to database.")
                try:
                    self.db_conn.commit()
                    self.db_conn.close()
                except Exception as e:
                    logging.exception(f"DB final commit/close error: {e}")
                self.db_conn = None

            # --- SHM Cleanup (same) ---
            if self.shm:
                # ... (close, potentially unlink) ...
                shm_name_final = self.shm.name
                self.shm.close()
                logging.info(f"Closed SHM handle {shm_name_final}.")
                if shm_created_by_this_instance:
                    try:
                        temp_shm = shared_memory.SharedMemory(name=shm_name_final)
                        temp_shm.unlink()
                        logging.info(f"Unlinked SHM block {shm_name_final}.")
                    except FileNotFoundError:
                        logging.warning(f"SHM block {shm_name_final} already unlinked.")
                    except Exception as e:
                        logging.exception(
                            f"Error unlinking SHM block {shm_name_final}: {e}"
                        )
                self.shm = None

            logging.info("Manager thread finished cleanup.")
            # --- Emit termination signal (same) ---
            if _PYSIDE_AVAILABLE:
                self.signals.processing_terminated.emit()

    def request_stop(self):
        # ... (same) ...
        logging.info("Stop requested for manager thread.")
        self._stop_event.set()

    # get_modified_data_view (same)
    # ... (same) ...
    def get_modified_data_view(self) -> Optional[memoryview]:
        # ... (same logic) ...
        if self.shm:
            try:
                return self.shm.buf
            except Exception:
                pass
        if hasattr(self, "shm_name"):
            try:
                temp_shm = shared_memory.SharedMemory(name=self.shm_name)
                buf = temp_shm.buf
                temp_shm.close()
                return buf
            except Exception:
                pass
        return None


# --- IDA Plugin Integration Example ---


# 4. Modify Plugin Class Slot Signature
class ByteProcessorPlugin(QObject):
    def __init__(self):
        if _PYSIDE_AVAILABLE:
            super().__init__()
        self.manager_thread: Optional[ProcessingManager] = None
        self.db_path = Path("./") / ProcessingConfig.SQLITE_DB_FILENAME

    def start_processing(self, data: bytearray):
        if not _PYSIDE_AVAILABLE:
            logging.error("Cannot start processing: PySide6 is not available.")
            return
        if self.manager_thread and self.manager_thread.is_alive():
            logging.warning("Processing is already running.")
            return

        logging.info("Starting background processing...")
        self.manager_thread = ProcessingManager(data, self.db_path, ProcessingConfig())

        # --- Connect signals (same signals, slot signature for log changed) ---
        self.manager_thread.signals.progress_updated.connect(self._handle_progress)
        self.manager_thread.signals.log_message.connect(
            self._handle_log
        )  # Connect to updated slot
        self.manager_thread.signals.error_occurred.connect(self._handle_error)
        self.manager_thread.signals.processing_complete.connect(self._handle_completion)
        self.manager_thread.signals.processing_terminated.connect(
            self._handle_termination
        )

        self.manager_thread.start()
        logging.info("Background processing manager started.")

    def stop_processing(self):
        # ... (same) ...
        if self.manager_thread and self.manager_thread.is_alive():
            logging.info("Requesting background processing stop...")
            self.manager_thread.request_stop()
        else:
            logging.info("Processing not running.")

    # --- Slot Methods ---
    @Slot(int, int, int)
    def _handle_progress(self, completed, failed, total):
        # ... (same) ...
        percent = (completed + failed) / total * 100 if total > 0 else 0
        logging.info(
            f"Progress: {completed}/{total} completed ({failed} failed) [{percent:.1f}%]"
        )

    # Updated Slot Signature for log messages
    @Slot(int, str, str)
    def _handle_log(self, level, process_name, message):
        """Handles log messages forwarded via Qt signals."""
        try:
            # Use the level passed from the record, include process_name for context
            # Note: message is already formatted by the QtSignalHandler's formatter
            logging.log(level, f"[{process_name}] {message}")
            # Optional: Display in IDA output window etc.
        except Exception as e:
            logging.exception(f"Error in _handle_log slot: {e}")

    @Slot(str)
    def _handle_error(self, error_msg):
        # ... (same) ...
        logging.error(f"Processing error reported: {error_msg}")

    @Slot(int, int)
    def _handle_completion(self, completed, failed):
        # ... (same) ...
        logging.info(
            f"Processing completed. Total tasks processed: {completed+failed}, Failed: {failed}"
        )

    @Slot()
    def _handle_termination(self):
        # ... (same) ...
        logging.info("Processing manager has terminated and cleaned up.")
        self.manager_thread = None


# --- Example Usage (Simulated IDA environment with Qt event loop) ---
if __name__ == "__main__":
    # ... (Setup multiprocessing context, QCoreApplication, plugin instance - same as before) ...

    if not _PYSIDE_AVAILABLE:
        print("PySide6 is not available. Exiting!")
        sys.exit(1)
    multiprocessing.set_executable(str(PYTHON_BIN))
    multiprocessing.freeze_support()        
    try:
        multiprocessing.set_start_method("spawn")
    except RuntimeError:
        pass
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication(sys.argv)
        _RUN_EVENT_LOOP = True
    else:
        _RUN_EVENT_LOOP = False

    plugin_instance = ByteProcessorPlugin()

    # --- Sample Data & DB Cleanup (same) ---
    data_size = 0x100000  # Smaller size for quicker testing
    logging.info(f"Generating {data_size / (1024*1024):.2f} MB of sample data...")
    original_data = bytearray([i % 256 for i in range(data_size)])
    if plugin_instance.db_path.exists():
        try:
            plugin_instance.db_path.unlink()
        except OSError as e:
            logging.warning(f"Could not remove DB: {e}")

    # --- Start Processing (same) ---
    plugin_instance.start_processing(original_data)

    # --- Event Loop Simulation (same) ---
    if _RUN_EVENT_LOOP:
        print("Starting event loop simulation (Ctrl+C to stop)...")
        try:
            while (
                plugin_instance.manager_thread
                and plugin_instance.manager_thread.is_alive()
            ):
                app.processEvents()
                time.sleep(0.05)
            print("Manager thread finished. Processing final events...")
            time.sleep(0.2)  # Allow listener cleanup and final signals
            app.processEvents()
            print("Event loop finished.")
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received. Stopping processing...")
            plugin_instance.stop_processing()
            start_wait = time.time()
            while plugin_instance.manager_thread and time.time() - start_wait < 10.0:
                app.processEvents()
                time.sleep(0.1)
            print("Shutdown attempt complete.")
    else:
        print("Assuming external event loop (like IDA's). Script finished setup.")

    logging.info("Main script finished.")
