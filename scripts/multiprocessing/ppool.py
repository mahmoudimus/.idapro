import concurrent.futures
import dataclasses
import logging
import logging.handlers
import math
import multiprocessing
import os
import pathlib
import sys
import typing
from enum import Enum, auto

prefix_path = pathlib.Path(sys.exec_prefix)
specific_python_path = prefix_path / "bin" / "python"
if specific_python_path.exists() and specific_python_path.is_file():
    PYTHON_EXECUTABLE = str(specific_python_path)
else:
    print(
        f"ERROR: Python executable not found at {specific_python_path}. Please check your IDA installation!",
        file=sys.stderr,
    )
    sys.exit(1)

# --- Setup multiprocessing ---

try:
    multiprocessing.set_start_method("spawn", force=True)
except ValueError:  # Already set
    current_method = multiprocessing.get_start_method()
    if current_method != "spawn":
        print(f"ERROR: Start method not 'spawn', script might fail.", file=sys.stderr)
        sys.exit(1)

multiprocessing.set_executable(PYTHON_EXECUTABLE)
PROCESSING_POOL_CONTEXT = multiprocessing.get_context("spawn")
PROCESSING_POOL_CONTEXT.set_executable(PYTHON_EXECUTABLE)


def is_ida():
    exec_name = pathlib.Path(sys.executable).name.lower()
    """Crude check to see if running inside IDA."""
    return exec_name.startswith("ida")


# from queue import Queue

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class QueueListener(logging.handlers.QueueListener):
    def is_alive(self):
        try:
            return self._thread.is_alive()
        except AttributeError:
            return False


def console_log(logger, level=logging.INFO, queue=None):
    """Create a console log handler. Return a scribe thread object."""
    if queue is None:
        queue = multiprocessing.Queue(-1)
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s: %(message)s (%(name)s, %(levelname)s)", datefmt="%I:%M:%S %p"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    scribe = Scribe(queue)
    return scribe


def file_log(logger, log_filename, level=logging.INFO, queue=None, **kwargs):
    """Create a file log handler. Return a scribe thread object."""
    if queue is None:
        queue = multiprocessing.Queue(-1)
    logger.setLevel(level)
    ch = logging.FileHandler(log_filename, **kwargs)
    ch.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    scribe = Scribe(queue)
    return scribe


class Scribe(QueueListener):
    """Scribe class which logs records as retrieved from a queue to support consistent
    multi-process logging.

    :param queue: The multiprocessing queue which the scriber will listen to.
    """

    def __init__(self, queue):
        super().__init__(queue)

    def handle(self, record):
        logging.getLogger(record.name).handle(record)


class TopicQueueHandler(logging.handlers.QueueHandler):
    def __init__(self, queue, topic="log"):
        super().__init__(queue)
        self.topic = topic

    def prepare(self, record):
        return self.topic, record


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


@dataclasses.dataclass
class Task:
    task_id: str
    offset: int
    size: int


@dataclasses.dataclass
class Result:
    task_id: str
    status: TaskStatus
    payload: typing.Any = None


log_format = "%(asctime)s - %(levelname)s - [%(name)s:%(processName)s] - %(message)s"
log_queue = None
# log_queue, log_listener = None, None


def setup_logging(
    logger=None,
    console=False,
    console_level="INFO",
    filename=None,
    file_level="DEBUG",
    queue=None,
    file_kwargs=None,
):
    """Setup logging for console and/or file logging. Returns a scribe thread object.
    Defaults to no logging."""
    global log_queue
    if queue is None:
        if log_queue is None:
            log_queue = multiprocessing.Queue(-1)
        queue = log_queue
    if logger is None:
        logger = logging.getLogger()
    if file_kwargs is None:
        file_kwargs = {}

    logger.handlers = []
    if console:
        console_log(logger, level=getattr(logging, console_level))
        logger.info("Set up console logging")
    if filename is not None:
        file_log(logger, filename, level=getattr(logging, file_level), **file_kwargs)
        logger.info("Set up file logging")

    scribe = Scribe(queue)
    return scribe


def setup_worker_logging(lq: multiprocessing.Queue, log_level: int):
    """Configures logging in a worker process to send records to the queue."""
    queue_handler = logging.handlers.QueueHandler(lq)
    queue_handler.setLevel(log_level)
    queue_handler.setFormatter(logging.Formatter(log_format))
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(queue_handler)
    root_logger.setLevel(log_level)


# def setup_threaded_logging():
#     global log_queue, log_listener
#     if log_queue is None:
#         log_queue = multiprocessing.Queue(-1)
#         handler = logging.StreamHandler()
#         handler.setFormatter(logging.Formatter(log_format))
#         log_listener = logging.handlers.QueueListener(
#             log_queue,
#             handler,
#         )
#         log_listener.start()
#     return log_queue, log_listener


def compute_sqrt(n, worker_log_level: int):
    """Compute the square root of the given number and print details."""
    setup_worker_logging(log_queue, worker_log_level)
    logger = logging.getLogger()
    result = math.sqrt(n) + 1
    logger.info(f"WORKER (PID: {os.getpid()}): sqrt({n}) = {result}")
    return result


if __name__ == "__main__":
    # --- Configure Root Logger for Standalone Run ---

    # # Add a stream handler for console output during standalone run
    # root_logger = logging.getLogger()
    # root_logger.setLevel(logging.INFO)
    # if not root_logger.hasHandlers():  # Avoid adding multiple handlers if run again
    #     handler = logging.StreamHandler(sys.stdout)
    #     handler.setFormatter(logging.Formatter(log_format))
    #     root_logger.addHandler(handler)
    # Numbers to compute the square root for
    numbers = [4, 16, 25, 36, 49, 64, 81, 100]
    scribe = setup_logging(logger)
    scribe.start()
    logger.info(f"PARENT (PID: {os.getpid()}): Script started.")
    # setup_threaded_logging()
    logger.info("Log listener started.")

    # Use ProcessPoolExecutor to manage worker processes
    with concurrent.futures.ProcessPoolExecutor(
        mp_context=PROCESSING_POOL_CONTEXT
    ) as executor:
        # Submit tasks to compute the square root of each number
        futures = {
            executor.submit(compute_sqrt, n, ProcessingConfig.WORKER_LOG_LEVEL): n
            for n in numbers
        }

        # Retrieve and display the results as each completes
        for future in concurrent.futures.as_completed(futures):
            n = futures[future]
            try:
                result = future.result()
                logger.info(f"PARENT: Result for {n} is {result}")
            except Exception as e:
                logger.exception(
                    f"PARENT: Computation for {n} raised an exception: {e}"
                )

    logger.info("Is scribe alive? %s", scribe.is_alive())
    if scribe:
        logger.info("Stopping log listener...")
        try:
            scribe.stop()
        except Exception as e:
            logger.exception("Error stopping log listener")
        scribe = None
        logger.info("Log listener stopped.")
    for q in [log_queue]:
        try:
            q.close()
            q.join_thread()
        except Exception:
            pass
    logger.info("PARENT: Script finished.")
