# qt_worker.py
import logging
import logging.handlers
import math
import multiprocessing
import os
import pathlib
import queue
import sqlite3
import sys
import threading
import time
import traceback
import typing
import uuid
import zlib
from dataclasses import dataclass
from enum import Enum, auto
from multiprocessing import Queue, shared_memory  # Explicitly import Queue
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# --- Helper Functions ---
def is_ida():
    exec_name = pathlib.Path(sys.executable).name.lower()
    """Crude check to see if running inside IDA."""
    return exec_name.startswith("ida")


# --- PySide6 Imports and Fallbacks ---
try:
    from PySide6.QtCore import QCoreApplication, QObject, Qt, Signal, Slot

    # We don't use QTimer directly anymore, but good to know if needed
    # from PySide6.QtCore import QTimer
    if is_ida():
        # In IDA, use QApplication from QtWidgets if available/needed for UI later
        from PySide6.QtWidgets import QApplication
    _PYSIDE_AVAILABLE = True
except ImportError:
    logging.error(
        "PySide6 not found. Install it (`pip install PySide6`) for Qt integration."
    )
    _PYSIDE_AVAILABLE = False

    class QObject:  # type: ignore
        pass

    def Signal(*args, **kwargs):  # type: ignore
        return object()

    def Slot(*args, **kwargs):  # type: ignore
        return lambda func: func

    class Qt:  # type: ignore
        AutoConnection = 0
        QueuedConnection = 1

    # Define dummy QApplication if needed for standalone tests without GUI
    class QApplication:  # type: ignore
        @staticmethod
        def instance():
            return None

        def __init__(self, *args):
            pass

        def processEvents(self):
            pass


# --- Configuration Class ---
class ProcessingConfig:
    # Use max() to ensure at least 1 worker, not min()
    NUM_WORKERS: int = max(1, multiprocessing.cpu_count() // 2)
    CHECKPOINT_INTERVAL_S: float = 60.0
    SQLITE_DB_FILENAME: str = "processing_state.db"
    # SHM prefix calculated dynamically later or passed in
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


@dataclass
class Result:
    task_id: str
    status: TaskStatus
    payload: Any = None


# --- Worker Setup and Logic ---


def setup_worker_logging(log_queue: Queue, level: int):
    """Configures logging in a worker process to send records to the queue."""
    queue_handler = logging.handlers.QueueHandler(log_queue)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(queue_handler)
    root_logger.setLevel(level)


def worker_process_main(
    task_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    log_queue: Queue,
    shm_name: str,
    shm_size: int,
    worker_log_level: int,
):
    """The core logic executed by each worker process."""
    # Logging setup happens *before* this in the wrapper
    worker_name = multiprocessing.current_process().name
    logging.info(f"Worker started. Attaching to SHM '{shm_name}'")
    shm = None

    try:
        shm = shared_memory.SharedMemory(name=shm_name)
        if shm.size != shm_size:
            raise ValueError(
                f"SHM size mismatch: expected {shm_size}, found {shm.size}"
            )
        logging.info("Attached to SHM.")

        while True:
            task: Optional[Task] = None
            buffer_for_task = None
            chunk_view = None
            try:
                task = task_queue.get()
                if task is None:
                    logging.info("Received shutdown signal.")
                    break
                logging.info(f"Task {task.task_id}: Starting processing.")
                try:
                    buffer_for_task = shm.buf
                    chunk_view = buffer_for_task[task.offset : task.offset + task.size]
                    processed_count = 0
                    for i in range(len(chunk_view)):
                        chunk_view[i] = 255 - chunk_view[i]  # Example task
                        processed_count += 1

                    result_payload = {"bytes_processed": processed_count}
                    result = Result(
                        task_id=task.task_id,
                        status=TaskStatus.COMPLETED,
                        payload=result_payload,
                    )
                    result_queue.put(result)
                    logging.info(f"Task {task.task_id}: Completed successfully.")

                except Exception as e:
                    task_id_str = task.task_id if task else "UNKNOWN"
                    logging.exception(f"Task {task_id_str}: Error during processing.")
                    result = Result(
                        task_id=task_id_str, status=TaskStatus.FAILED, payload=str(e)
                    )
                    result_queue.put(result)
            except (EOFError, BrokenPipeError):
                logging.warning("Queue connection lost, exiting.")
                break
            except Exception as e:
                logging.exception("Unexpected error in worker main loop.")
                break  # Exit loop on unexpected errors

    except FileNotFoundError:
        logging.error(f"Could not find SHM block: {shm_name}")
        raise  # Re-raise critical errors like missing SHM
    except Exception as e:
        logging.exception("Worker failed during initialization or shutdown.")
        raise  # Re-raise other critical errors
    finally:
        logging.info("Entering worker finally block.")
        if shm:
            logging.info("Attempting to close SHM handle.")
            try:
                shm.close()
                logging.info("SHM handle closed successfully.")
            except BufferError as be:
                logging.error(f"!!! BufferError persisting: {be}")
            except Exception as ce:
                logging.error(f"Error during explicit SHM close: {ce}")
            shm = None
        logging.info("Worker exiting.")


def wrapped_worker_process_main(
    task_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    log_queue: Queue,
    shm_name: str,
    shm_size: int,
    worker_log_level: int,
):
    """Wrapper to catch all exceptions in worker and log to crash file."""
    worker_pid = os.getpid()
    error_log_path = Path(f"./worker_{worker_pid}_CRASH.log")

    try:
        # Setup logging first - if this fails, crash log will catch it
        setup_worker_logging(log_queue, worker_log_level)
        # Call the main worker logic
        worker_process_main(
            task_queue, result_queue, log_queue, shm_name, shm_size, worker_log_level
        )
        # Exit normally if no exception
        sys.exit(0)
    except Exception as top_level_exception:
        # --- Log ANY exception to the crash file ---
        try:
            with error_log_path.open("w", encoding="utf-8") as f_err:
                f_err.write(f"WORKER CRASHED (PID: {worker_pid})\n")
                f_err.write(f"SHM Name: {shm_name}\n")
                f_err.write("=" * 20 + "\n")
                traceback.print_exc(file=f_err)
        except Exception as log_write_error:
            # Fallback if crash log fails
            fallback_log = Path("./worker_CRITICAL_ERROR.log")
            try:
                with fallback_log.open("a", encoding="utf-8") as f_crit:
                    f_crit.write(
                        f"[{time.time()}] WORKER PID {worker_pid} CRITICAL ERROR:\n"
                    )
                    f_crit.write(f"  Original Error: {top_level_exception}\n")
                    f_crit.write(
                        f"  Failed to write crash log {error_log_path}: {log_write_error}\n\n"
                    )
            except:
                pass  # Ignore errors writing fallback log
        # Ensure parent process sees a failure
        sys.exit(1)


# --- Manager Thread Logic ---


# Custom Log Handler for Qt Signals
class QtSignalHandler(logging.Handler):
    def __init__(self, signal_emitter_func):
        super().__init__()
        self.signal_emitter_func = signal_emitter_func
        self.setFormatter(
            logging.Formatter("%(levelname)s:%(name)s:%(processName)s: %(message)s")
        )

    def emit(self, record: logging.LogRecord):
        if not _PYSIDE_AVAILABLE:
            return
        try:
            signal_emitter = self.signal_emitter_func()
            if signal_emitter:
                msg = self.format(record)
                process_name = record.processName
                signal_emitter.log_message.emit(record.levelno, process_name, msg)
        except Exception:
            self.handleError(record)


# Manager Signals QObject
class ManagerSignals(QObject):
    if _PYSIDE_AVAILABLE:
        progress_updated = Signal(int, int, int)
        log_message = Signal(int, str, str)  # level, process name, message
        error_occurred = Signal(str)
        processing_complete = Signal(int, int)
        processing_terminated = Signal()
    else:
        # Dummy signals
        (
            progress_updated,
            log_message,
            error_occurred,
            processing_complete,
            processing_terminated,
        ) = (object(),) * 5


# Unique SHM Name Generation
def generate_shm_name():
    """Generate a short, unique SHM name using CRC32 of a UUID."""
    u = uuid.uuid4()
    # Use zlib.crc32 on the UUID bytes for a good hash
    crc = zlib.crc32(u.bytes)
    # Format as 8-character hex (always positive on Python 3)
    crc_hex = f"{crc:08x}"
    # POSIX requires a leading slash and no other slashes
    # Keep it short: prefix + pid + crc32 hash
    prefix = "/"  # Required for POSIX shm_open
    # Combine elements, ensuring total length is reasonable
    # Example: /ida_12345_deadbeef (approx 20 chars + pid length)
    name = f"{prefix}ida_{os.getpid()}_{crc_hex}"

    # Optional: Add a check for known OS limits if necessary, but this is usually short enough
    # MAX_NAME_LEN = 30 # Example limit
    # if len(name) > MAX_NAME_LEN:
    #     logging.warning(f"Generated SHM name '{name}' might be too long (>{MAX_NAME_LEN})")
    # Potentially shorten further if needed, e.g., shorter hash or prefix

    logging.debug(f"Generated SHM name: {name}")
    return name


# Processing Manager Thread
class ProcessingManager(threading.Thread):
    def __init__(self, data: bytearray, db_path: Path, config: ProcessingConfig):
        super().__init__(name="ProcessingManagerThread", daemon=True)
        self.data_size = len(data)
        self.initial_data = data
        self.db_path = db_path
        self.config = config
        self.signals = ManagerSignals()
        self.task_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.log_queue = multiprocessing.Queue()
        self.log_listener: Optional[logging.handlers.QueueListener] = None
        self.shm_name = generate_shm_name()  # Generate unique name
        self.shm = None
        self.db_conn = None
        self.workers: List[multiprocessing.Process] = []
        self._stop_event = threading.Event()
        self.tasks: Dict[str, Tuple[Task, TaskStatus]] = {}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0

    def _initialize_db(self):
        try:
            self.db_conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.db_conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS tasks (task_id TEXT PRIMARY KEY, offset INTEGER, size INTEGER, status TEXT, result_payload TEXT NULL)"
            )
            # Store the specific SHM name for this run
            cursor.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("shm_name", self.shm_name),
            )
            cursor.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("data_size", str(self.data_size)),
            )
            self.db_conn.commit()
            # Check for consistency if resuming from a *previous* run (requires loading old shm_name/size)
            # Basic size check on load:
            res = cursor.execute(
                "SELECT value FROM metadata WHERE key=?", ("data_size",)
            ).fetchone()
            if res and int(res[0]) != self.data_size:
                raise RuntimeError(
                    f"Data size mismatch: DB expects {res[0]}, current is {self.data_size}."
                )
            logging.info(f"Initialized/Connected to database: {self.db_path}")
        except Exception as e:
            logging.exception("Failed to initialize database.")
            raise  # Propagate DB errors

    def _load_or_create_tasks(self):
        # ...(Same logic as before for loading/creating tasks)...
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
            # Use try-except for DB operations
            try:
                cursor.execute("DELETE FROM tasks")
                cursor.executemany(
                    "INSERT INTO tasks (task_id, offset, size, status) VALUES (?, ?, ?, ?)",
                    tasks_to_insert,
                )
                self.db_conn.commit()
                logging.info(f"Created and saved {self.total_tasks} new tasks.")
            except Exception as e:
                logging.exception("Failed to save new tasks to database.")
                raise  # Propagate DB errors

    def _update_task_status(
        self, task_id: str, status: TaskStatus, payload: Optional[str] = None
    ):
        # ...(Same logic as before for updating status)...
        if task_id in self.tasks:
            task, old_status = self.tasks[task_id]
            status_changed = old_status != status
            was_completed = old_status == TaskStatus.COMPLETED
            was_failed = old_status == TaskStatus.FAILED
            is_completed = status == TaskStatus.COMPLETED
            is_failed = status == TaskStatus.FAILED

            if status_changed:
                self.tasks[task_id] = (task, status)
                if was_completed and not is_completed:
                    self.completed_tasks -= 1
                if was_failed and not is_failed:
                    self.failed_tasks -= 1
                if is_completed and not was_completed:
                    self.completed_tasks += 1
                if is_failed and not was_failed:
                    self.failed_tasks += 1
                try:
                    cursor = self.db_conn.cursor()
                    cursor.execute(
                        "UPDATE tasks SET status = ?, result_payload = ? WHERE task_id = ?",
                        (status.name, payload, task_id),
                    )
                except Exception as e:
                    logging.exception(f"DB update failed for task {task_id}")
        else:
            logging.warning(f"Attempted update for unknown task_id: {task_id}")

    def run(self):
        logging.info("Manager thread started.")
        last_checkpoint_time = time.monotonic()
        shm_created_by_this_instance = False

        try:
            handlers = []
            if _PYSIDE_AVAILABLE:
                qt_handler = QtSignalHandler(lambda: self.signals)
                handlers.append(qt_handler)
            if not handlers:
                logging.warning("No log handlers configured for QueueListener.")
            self.log_listener = logging.handlers.QueueListener(
                self.log_queue, *handlers, respect_handler_level=True
            )
            self.log_listener.start()
            logging.info("Log listener started.")

            self._initialize_db()

            try:
                self.shm = shared_memory.SharedMemory(
                    name=self.shm_name, create=True, size=self.data_size
                )
                shm_created_by_this_instance = True
                logging.info(
                    f"SHM block '{self.shm_name}' created. Copying initial data..."
                )
                self.shm.buf[:] = self.initial_data
                self.initial_data = None
                logging.info("Data copied to SHM.")
            except FileExistsError:
                # This case should be less likely with uuid in name, but handle anyway
                logging.warning(
                    f"SHM block '{self.shm_name}' already exists. Attaching."
                )
                self.shm = shared_memory.SharedMemory(name=self.shm_name, create=False)
                if self.shm.size != self.data_size:
                    raise RuntimeError(
                        f"Existing SHM size mismatch for '{self.shm_name}'. Expected {self.data_size}, got {self.shm.size}"
                    )
            except Exception as shm_e:
                logging.exception(
                    f"Failed to create/attach SHM block '{self.shm_name}'"
                )
                raise shm_e  # Propagate SHM errors

            self._load_or_create_tasks()

            logging.info(f"Starting {self.config.NUM_WORKERS} worker processes...")
            for i in range(self.config.NUM_WORKERS):
                # *** Target is the WRAPPER function ***
                p = multiprocessing.Process(
                    target=wrapped_worker_process_main,  # Use the wrapper
                    args=(
                        self.task_queue,
                        self.result_queue,
                        self.log_queue,
                        self.shm_name,
                        self.data_size,
                        self.config.WORKER_LOG_LEVEL,
                    ),
                    name=f"Worker-{i}",
                    daemon=True,
                )
                self.workers.append(p)
                p.start()
                logging.info(f"Worker-{i} (PID: {p.pid}) started.")

            pending_tasks = [
                task
                for task, status in self.tasks.values()
                if status == TaskStatus.PENDING
            ]
            logging.info(f"Distributing {len(pending_tasks)} pending tasks.")
            for task in pending_tasks:
                self.task_queue.put(task)

            while (self.completed_tasks + self.failed_tasks) < self.total_tasks:
                if self._stop_event.is_set():
                    logging.info("Stop event received. Initiating shutdown.")
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
                                logging.warning(
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
                        logging.error(msg)
                        if _PYSIDE_AVAILABLE:
                            self.signals.error_occurred.emit(msg)
                        break  # Exit manager loop
                    continue  # Continue loop if timeout occurred but workers potentially alive
                else:
                    # Process result
                    logging.debug(
                        f"Received result for task {result.task_id}: Status {result.status}"
                    )
                    self._update_task_status(
                        result.task_id, result.status, str(result.payload)
                    )
                    if _PYSIDE_AVAILABLE:
                        self.signals.progress_updated.emit(
                            self.completed_tasks, self.failed_tasks, self.total_tasks
                        )

                now = time.monotonic()
                if now - last_checkpoint_time > self.config.CHECKPOINT_INTERVAL_S:
                    logging.info("Performing periodic checkpoint...")
                    if self.db_conn:
                        try:
                            self.db_conn.commit()
                        except Exception as db_e:
                            logging.exception("Checkpoint commit failed")
                    last_checkpoint_time = now

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
            logging.info("Signaling workers to terminate...")
            for _ in range(len(self.workers)):
                try:
                    self.task_queue.put(None, timeout=0.1)  # Short timeout
                except queue.Full:
                    pass  # Ignore if full during shutdown
                except Exception:
                    pass
            logging.info("Joining worker processes...")
            # Allow slightly more time for workers to finish logging/cleanup
            join_timeout = 15.0
            start_join = time.monotonic()
            for worker in self.workers:
                try:
                    remaining_time = join_timeout - (time.monotonic() - start_join)
                    if remaining_time <= 0:
                        logging.warning(f"Timeout expired before joining {worker.name}")
                        if worker.is_alive():
                            worker.terminate()
                            worker.join(1)
                        continue
                    worker.join(timeout=remaining_time)
                    if worker.is_alive():
                        logging.warning(
                            f"Worker {worker.name} did not exit after join, terminating."
                        )
                        worker.terminate()
                        worker.join(1)  # Final wait after terminate
                    else:
                        logging.info(
                            f"Worker {worker.name} joined cleanly (Exitcode: {worker.exitcode})."
                        )
                except Exception as e:
                    logging.exception(f"Error joining worker {worker.name}: {e}")
            logging.info("Finished joining workers.")

            if self.log_listener:
                logging.info("Stopping log listener...")
                try:
                    self.log_listener.stop()
                except Exception as e:
                    logging.exception("Error stopping log listener")
                self.log_listener = None
                logging.info("Log listener stopped.")

            logging.info("Closing queues...")
            for q in [self.task_queue, self.result_queue, self.log_queue]:
                try:
                    q.close()
                    q.join_thread()
                except Exception:
                    pass

            if self.db_conn:
                logging.info("Committing final state to database.")
                try:
                    self.db_conn.commit()
                    self.db_conn.close()
                except Exception as e:
                    logging.exception(f"DB final commit/close error: {e}")
                self.db_conn = None

            if self.shm:
                shm_name_final = self.shm.name
                try:
                    self.shm.close()
                    logging.info(f"Closed SHM handle {shm_name_final}.")
                    if shm_created_by_this_instance:
                        # Attempt unlink after close
                        try:
                            shared_memory.SharedMemory(name=shm_name_final).unlink()
                            logging.info(f"Unlinked SHM block {shm_name_final}.")
                        except FileNotFoundError:
                            logging.warning(
                                f"SHM block {shm_name_final} already unlinked."
                            )
                        except Exception as unlink_e:
                            logging.exception(
                                f"Error unlinking SHM block {shm_name_final}: {unlink_e}"
                            )
                except Exception as close_e:
                    logging.exception(
                        f"Error closing SHM handle {shm_name_final}: {close_e}"
                    )
                self.shm = None

            logging.info("Manager thread finished cleanup.")
            if _PYSIDE_AVAILABLE:
                self.signals.processing_terminated.emit()

    def request_stop(self):
        logging.info("Stop requested for manager thread.")
        self._stop_event.set()

    # get_modified_data_view remains the same


# --- IDA Plugin Integration Class ---
# Global variable to track MP configuration status
_MP_CONFIGURED_SUCCESSFULLY = False


class ByteProcessorPlugin(QObject):
    def __init__(self):
        global _MP_CONFIGURED_SUCCESSFULLY
        if _PYSIDE_AVAILABLE:
            super().__init__()
        else:
            super().__init__()  # Still call object init if QObject is mocked
        self.manager_thread: Optional[ProcessingManager] = None
        self.db_path = Path("./") / ProcessingConfig.SQLITE_DB_FILENAME

        # --- Configure MP once during plugin lifetime (or first use) ---
        if not _MP_CONFIGURED_SUCCESSFULLY:
            if configure_multiprocessing_for_embedding():
                _MP_CONFIGURED_SUCCESSFULLY = True
            else:
                logging.error(
                    "Multiprocessing configuration failed. Background processing will be disabled."
                )
                # Optionally disable UI elements here

    def start_processing(self, data: bytearray):
        if not _MP_CONFIGURED_SUCCESSFULLY:
            logging.error("Multiprocessing not configured. Cannot start processing.")
            if is_ida():  # Show warning only in IDA
                pass  # Replace with ida_kernwin.warning(...) if desired
            return

        if not _PYSIDE_AVAILABLE:
            logging.error("Cannot start processing: PySide6 is not available.")
            return
        if self.manager_thread and self.manager_thread.is_alive():
            logging.warning("Processing is already running.")
            return

        logging.info("Starting background processing...")
        # Create manager instance
        self.manager_thread = ProcessingManager(data, self.db_path, ProcessingConfig())

        # Connect signals
        self.manager_thread.signals.progress_updated.connect(self._handle_progress)
        self.manager_thread.signals.log_message.connect(self._handle_log)
        self.manager_thread.signals.error_occurred.connect(self._handle_error)
        self.manager_thread.signals.processing_complete.connect(self._handle_completion)
        self.manager_thread.signals.processing_terminated.connect(
            self._handle_termination
        )

        self.manager_thread.start()
        logging.info("Background processing manager started.")

    def stop_processing(self):
        if self.manager_thread and self.manager_thread.is_alive():
            logging.info("Requesting background processing stop...")
            self.manager_thread.request_stop()
        else:
            logging.info("Processing not running.")

    # --- Slot Methods (remain the same) ---
    @Slot(int, int, int)
    def _handle_progress(self, completed, failed, total):
        percent = (completed + failed) / total * 100 if total > 0 else 0
        logging.info(
            f"Progress: {completed}/{total} completed ({failed} failed) [{percent:.1f}%]"
        )

    @Slot(int, str, str)
    def _handle_log(self, level, process_name, message):
        try:
            logging.log(level, f"[{process_name}] {message}")
        except Exception as e:
            logging.exception(f"Error in _handle_log slot: {e}")

    @Slot(str)
    def _handle_error(self, error_msg):
        logging.error(f"Processing error reported: {error_msg}")

    @Slot(int, int)
    def _handle_completion(self, completed, failed):
        logging.info(
            f"Processing completed. Total tasks processed: {completed+failed}, Failed: {failed}"
        )

    @Slot()
    def _handle_termination(self):
        logging.info("Processing manager has terminated and cleaned up.")
        self.manager_thread = None


# --- Multiprocessing Configuration Function ---
CONFIGURED_PYTHON_EXECUTABLE = None  # Module level cache


def configure_multiprocessing_for_embedding():
    """Finds python, sets executable and start method. Call ONCE in parent."""
    global CONFIGURED_PYTHON_EXECUTABLE
    if CONFIGURED_PYTHON_EXECUTABLE:
        logging.debug("Multiprocessing already configured.")
        return True

    # Determine candidate paths based on platform
    prefix_path = pathlib.Path(sys.exec_prefix)
    candidates = []
    if sys.platform == "win32":
        candidates = [prefix_path / "python.exe", prefix_path / "pythonw.exe"]
    else:  # macOS/Linux
        candidates = [prefix_path / "bin" / "python", prefix_path / "python"]
        # Add variations often seen with pyenv or virtualenvs within frameworks
        candidates.append(prefix_path / ".." / "bin" / "python")  # Common for venv
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        # Example path from user: /Users/mahmoud/.pyenv/versions/3.13.3/Library/Frameworks/Python.framework/Versions/3.13/bin/python
        if "Frameworks/Python.framework" in str(prefix_path):
            framework_ver_path = prefix_path / f"Versions/{py_version}/bin/python"
            candidates.insert(
                0, framework_ver_path
            )  # Prioritize this if looks like framework path
        candidates.append(prefix_path / f"python{py_version}")

    found_path = None
    logging.debug(f"Using sys.exec_prefix: {prefix_path}")
    for candidate in candidates:
        logging.debug(f"Checking for Python executable: {candidate}")
        try:
            # Resolve symlinks for robustness
            resolved_candidate = candidate.resolve(strict=False)
            if resolved_candidate.exists() and resolved_candidate.is_file():
                found_path = str(resolved_candidate)
                logging.info(
                    f"Found Python executable for multiprocessing: {found_path}"
                )
                break
            else:
                logging.debug(
                    f"Candidate not found or not a file: {resolved_candidate}"
                )
        except Exception as e:
            logging.debug(f"Error checking candidate {candidate}: {e}")

    if not found_path:
        logging.error(
            f"Could not find suitable Python executable near {sys.exec_prefix} or in common locations."
        )
        # Fallback attempt (less reliable in embedding)
        if pathlib.Path(sys.executable).name.lower().startswith("python"):
            logging.warning(
                f"Falling back to potentially unreliable sys.executable: {sys.executable}"
            )
            found_path = sys.executable
        else:
            logging.error("No suitable Python found. Multiprocessing will likely fail.")
            return False

    CONFIGURED_PYTHON_EXECUTABLE = found_path
    try:
        multiprocessing.set_executable(CONFIGURED_PYTHON_EXECUTABLE)
        logging.info(
            f"Multiprocessing executable set to: {CONFIGURED_PYTHON_EXECUTABLE}"
        )

        # Set start method to 'spawn'
        current_method = multiprocessing.get_start_method(allow_none=True)
        if current_method != "spawn":
            multiprocessing.set_start_method("spawn", force=True)
            logging.info("Multiprocessing start method set to 'spawn'.")
        else:
            logging.info("Multiprocessing start method already set to 'spawn'.")
        return True
    except Exception as e:
        logging.exception(
            "Failed to configure multiprocessing executable/start method."
        )
        CONFIGURED_PYTHON_EXECUTABLE = None
        return False


# --- Standalone Execution Entry Point ---
if __name__ == "__main__":
    # --- Configure Root Logger for Standalone Run ---
    log_format = (
        "%(asctime)s - %(levelname)s - [%(name)s:%(processName)s] - %(message)s"
    )
    # Add a stream handler for console output during standalone run
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    if not root_logger.hasHandlers():  # Avoid adding multiple handlers if run again
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(log_format))
        root_logger.addHandler(handler)

    # --- Configure MP ---
    if not configure_multiprocessing_for_embedding():
        logging.error("Standalone run failed: Could not configure multiprocessing.")
        sys.exit(1)

    # Freeze support might be needed for creating executables (e.g., with PyInstaller)
    multiprocessing.freeze_support()

    # --- Standalone App Setup ---
    _RUN_EVENT_LOOP = False
    if not is_ida():
        app = QApplication.instance()
        if app is None:
            logging.info("Creating new QApplication for standalone run.")
            app = QApplication(sys.argv)
            _RUN_EVENT_LOOP = True
        else:
            logging.info("Using existing QApplication instance.")
    else:
        # In IDA, get existing instance
        app = QApplication.instance()
        if app is None:
            logging.error("Running in IDA context but QApplication not found!")
            # Attempt to create one? Might interfere with IDA.
            # app = QApplication(sys.argv) ?
            # _RUN_EVENT_LOOP = True ? # Risky
        else:
            logging.info("Using existing IDA QApplication instance.")

    # --- Instantiate plugin, generate data, start processing ---
    plugin_instance = ByteProcessorPlugin()
    data_size = 0x100000  # 1MB for testing
    logging.info(f"Generating {data_size / (1024*1024):.2f} MB of sample data...")
    original_data = bytearray([i % 256 for i in range(data_size)])

    if plugin_instance.db_path.exists():
        logging.info(f"Removing existing database: {plugin_instance.db_path}")
        try:
            plugin_instance.db_path.unlink()
        except OSError as e:
            logging.warning(f"Could not remove DB: {e}")

    plugin_instance.start_processing(original_data)

    # --- Event Loop Simulation (only if we created the app) ---
    if _RUN_EVENT_LOOP:
        print(
            "Starting event loop simulation (Ctrl+C to stop)...",
            file=sys.stdout,
            flush=True,
        )
        try:
            while (
                plugin_instance.manager_thread
                and plugin_instance.manager_thread.is_alive()
            ):
                app.processEvents()
                time.sleep(0.05)
            logging.info("Manager thread finished. Processing final events...")
            # Allow time for final signals/cleanup logs to be processed
            start_final_wait = time.monotonic()
            while time.monotonic() - start_final_wait < 0.5:
                app.processEvents()
                time.sleep(0.05)
            logging.info("Event loop finished.")
        except KeyboardInterrupt:
            print(
                "\nKeyboard interrupt received. Stopping processing...",
                file=sys.stdout,
                flush=True,
            )
            plugin_instance.stop_processing()
            start_wait = time.time()
            while plugin_instance.manager_thread and time.time() - start_wait < 10.0:
                app.processEvents()
                time.sleep(0.1)
            logging.info("Shutdown attempt complete.")
    else:
        logging.info(
            "Assuming external event loop (like IDA's). Script finished setup."
        )
        # Keep main script alive briefly for IDA execution? Usually not needed.
        # time.sleep(1)

    logging.info("Main script finished.")
