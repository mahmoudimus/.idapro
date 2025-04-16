import concurrent

# if __name__ == "__main__":
#     main()
import concurrent.futures
import json
import logging
import logging.config
import logging.handlers
import multiprocessing
import os
import pathlib
import random
import socket
import sys
import tempfile
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime

from PyQt5.QtCore import QObject, QThread, pyqtSignal

# #
# # Because you'll want to define the logging configurations for listener and workers, the
# # listener and worker process functions take a configurer parameter which is a callable
# # for configuring logging for that process. These functions are also passed the queue,
# # which they use for communication.
# #
# # In practice, you can configure the listener however you want, but note that in this
# # simple example, the listener does not apply level or filter logic to received records.
# # In practice, you would probably want to do this logic in the worker processes, to avoid
# # sending events which would be filtered out between processes.
# #
# # The size of the rotated files is made small so you can see the results easily.
# def listener_configurer():
#     root = logging.getLogger()
#     h = logging.handlers.RotatingFileHandler("mptest.log", "a", 300, 10)
#     f = logging.Formatter(
#         "%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s"
#     )
#     h.setFormatter(f)
#     root.addHandler(h)


# # This is the listener process top-level loop: wait for logging events
# # (LogRecords)on the queue and handle them, quit when you get a None for a
# # LogRecord.
# def listener_process(queue, configurer):
#     configurer()
#     while True:
#         try:
#             record = queue.get()
#             if (
#                 record is None
#             ):  # We send this as a sentinel to tell the listener to quit.
#                 break
#             logger = logging.getLogger(record.name)
#             logger.handle(record)  # No level or filter logic applied - just do it!
#         except Exception:
#             import sys
#             import traceback

#             print("Whoops! Problem:", file=sys.stderr)
#             traceback.print_exc(file=sys.stderr)


# # Arrays used for random selections in this demo

# LEVELS = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]

# LOGGERS = ["a.b.c", "d.e.f"]

# MESSAGES = [
#     "Random message #1",
#     "Random message #2",
#     "Random message #3",
# ]


# # The worker configuration is done at the start of the worker process run.
# # Note that on Windows you can't rely on fork semantics, so each process
# # will run the logging configuration code when it starts.
# def worker_configurer(queue):
#     h = logging.handlers.QueueHandler(queue)  # Just the one handler needed
#     root = logging.getLogger()
#     for handler in root.handlers:
#         if isinstance(handler, logging.StreamHandler):
#             root.removeHandler(handler)
#             break
#     root.addHandler(h)
#     # send all messages, for demo; no other level or filter logic applied.
#     root.setLevel(logging.DEBUG)


# # This is the worker process top-level loop, which just logs ten events with
# # random intervening delays before terminating.
# # The print messages are just so you know it's doing something!
# def worker_process(queue, configurer):
#     configurer(queue)
#     name = multiprocessing.current_process().name
#     print("Worker started: %s" % name)
#     for i in range(10):
#         time.sleep(random.random() * 2)
#         logger = logging.getLogger(random.choice(LOGGERS))
#         level = random.choice(LEVELS)
#         message = random.choice(MESSAGES)
#         logger.log(level, message)
#     print("Worker finished: %s" % name)


# def main():
#     multiprocessing.set_start_method("spawn", force=True)
#     # Construct path to custom Python binary
#     prefix_path = pathlib.Path(sys.exec_prefix)
#     specific_python_path = prefix_path / "bin" / "python"
#     # multiprocessing.set_executable(str(specific_python_path))
#     mpctx = multiprocessing.get_context("spawn")
#     mpctx.set_executable(str(specific_python_path))
#     logger = logging.getLogger(__name__)

#     logger.info(
#         "I am now starting!: %s, %s, %s", specific_python_path, mpctx, prefix_path
#     )
#     queue = mpctx.Manager().Queue(-1)
#     listener = multiprocessing.Process(
#         target=listener_process, args=(queue, listener_configurer)
#     )
#     listener.start()
#     workers = []
#     for i in range(10):
#         worker = multiprocessing.Process(
#             target=worker_process, args=(queue, worker_configurer)
#         )
#         workers.append(worker)
#         worker.start()
#     for w in workers:
#         w.join()
#     queue.put_nowait(None)
#     listener.join()


# Custom file-based logging handler
class FileLogHandler(logging.Handler):
    def __init__(self, log_dir, worker_id):
        super().__init__()
        self.log_file = os.path.join(log_dir, f"worker_{worker_id}.log")
        # Ensure the file exists but is empty at start
        with open(self.log_file, "w") as f:
            pass

    def emit(self, record):
        try:
            msg = self.format(record)
            with open(self.log_file, "a") as f:
                f.write(msg + "\n")
                f.flush()
        except Exception:
            self.handleError(record)


# Worker function that will run in separate processes
def worker_function(task_id, task, result_file, log_dir):
    # Set up logging for this worker process
    logger = logging.getLogger(f"worker-{task_id}")
    logger.setLevel(logging.INFO)

    # Create and add file handler
    handler = FileLogHandler(log_dir, task_id)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    try:
        # Log start message
        logger.info(f"Worker {task_id} started processing task: {task}")
        time.sleep(1)  # Simulate work

        # Write result to file
        result = f"Task {task_id} result: {task} processed"
        with open(result_file, "w") as f:
            f.write(result)

        # Log completion message
        logger.info(f"Worker {task_id} completed task: {task}")
        return 0  # Success
    except Exception as e:
        logger.error(f"Worker {task_id} encountered an error: {str(e)}")
        return 1  # Error


# QThread to monitor log files
class LogMonitorThread(QThread):
    log_received = pyqtSignal(str)

    def __init__(self, log_dir, worker_count):
        super().__init__()
        self.log_dir = log_dir
        self.worker_count = worker_count
        self._stop_requested = False
        self.last_positions = {}

    def run(self):
        # Initialize tracking of log file positions
        for i in range(self.worker_count):
            log_file = os.path.join(self.log_dir, f"worker_{i}.log")
            self.last_positions[log_file] = 0

        while not self._stop_requested:
            for log_file, last_pos in list(self.last_positions.items()):
                try:
                    if os.path.exists(log_file):
                        with open(log_file, "r") as f:
                            f.seek(last_pos)
                            new_content = f.read()
                            if new_content:
                                print(f"LOG RECEIVED: {new_content.strip()}")
                                self.log_received.emit(new_content.strip())
                                self.last_positions[log_file] = f.tell()
                except Exception as e:
                    print(f"Error reading log file {log_file}: {e}")

            # Sleep briefly before checking again
            time.sleep(0.1)

    def stop(self):
        self._stop_requested = True
        self.wait(5000)  # Wait up to 5 seconds for thread to finish


# QThread to monitor result files
class ResultMonitorThread(QThread):
    result_received = pyqtSignal(str)

    def __init__(self, result_files):
        super().__init__()
        self.result_files = list(result_files)  # Copy to avoid modification issues
        self.processed_files = set()
        self._stop_requested = False

    def run(self):
        while not self._stop_requested and self.result_files:
            for result_file in list(self.result_files):
                if result_file in self.processed_files:
                    continue

                try:
                    if os.path.exists(result_file):
                        # Check if file has content (completed)
                        if os.path.getsize(result_file) > 0:
                            with open(result_file, "r") as f:
                                result = f.read().strip()
                                if result:
                                    print(f"QUEUE RESULT: {result}")
                                    self.result_received.emit(result)
                                    self.processed_files.add(result_file)
                except Exception as e:
                    print(f"Error reading result file {result_file}: {e}")

            # If all files are processed, we're done
            if len(self.processed_files) == len(self.result_files):
                break

            # Sleep briefly before checking again
            time.sleep(0.1)

    def stop(self):
        self._stop_requested = True
        self.wait(5000)  # Wait up to 5 seconds for thread to finish


def main():
    # Required prologue for embedded environment
    multiprocessing.set_start_method("spawn", force=True)
    # Construct path to custom Python binary
    prefix_path = pathlib.Path(sys.exec_prefix)
    specific_python_path = prefix_path / "bin" / "python"
    multiprocessing.set_executable(str(specific_python_path))
    mpctx = multiprocessing.get_context("spawn")
    mpctx.set_executable(str(specific_python_path))

    # Create temp directories for logs and results
    temp_dir = tempfile.mkdtemp(prefix="mp_example_")
    log_dir = os.path.join(temp_dir, "logs")
    results_dir = os.path.join(temp_dir, "results")
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)

    print(f"Using temp directory: {temp_dir}")

    # Define tasks
    tasks = [f"Task-{i}" for i in range(5)]

    # Create result file paths
    result_files = [
        os.path.join(results_dir, f"result_{i}.txt") for i in range(len(tasks))
    ]

    # Start log monitor
    log_monitor = LogMonitorThread(log_dir, len(tasks))
    log_monitor.start()

    # Start result monitor
    result_monitor = ResultMonitorThread(result_files)
    result_monitor.start()

    # List to keep track of processes
    processes = []

    try:
        # Start worker processes
        for i, (task, result_file) in enumerate(zip(tasks, result_files)):
            p = mpctx.Process(
                target=worker_function, args=(i, task, result_file, log_dir)
            )
            p.start()
            processes.append(p)

        # Wait for all processes to finish
        for p in processes:
            p.join()
            if p.exitcode != 0:
                print(f"Process exited with code {p.exitcode}")

        # Wait a moment to ensure all logs are processed
        time.sleep(2)

    finally:
        # Clean up
        log_monitor.stop()
        result_monitor.stop()

        # Terminate any remaining processes
        for p in processes:
            if p.is_alive():
                p.terminate()
                p.join(timeout=1)

        # Optionally clean up temp files
        # import shutil
        # shutil.rmtree(temp_dir)
        print(f"Temporary files are in: {temp_dir}")


if __name__ == "__main__":
    main()
