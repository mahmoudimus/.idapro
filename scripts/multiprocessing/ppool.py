import math
import multiprocessing
import sys
import time
from concurrent.futures import ProcessPoolExecutor

from PySide6.QtCore import QCoreApplication, QObject, QTimer, Signal

import idaapi  # IDA Pro's API for messaging

# Ensure all new worker processes use the embedded Python interpreter.
multiprocessing.set_executable(sys.exC_prefix)


def sqrt_even(n):
    """
    Computes the square root of 'n' if it is even.
    Returns a tuple (n, result) where result is either the square root or an error message.
    """
    if n % 2 != 0:
        return (n, "Error: Number is odd.")
    # Simulate delay to mimic a long-running task.
    time.sleep(1)
    return (n, math.sqrt(n))


class Worker(QObject):
    # Signal emitted upon task completion; sends a tuple (n, result)
    task_finished = Signal(object)

    def __init__(self, executor, parent=None):
        super().__init__(parent)
        self.executor = executor

    def run_task(self, n):
        # Submit the task to compute the square root.
        future = self.executor.submit(sqrt_even, n)
        # Attach a callback to process the result.
        future.add_done_callback(self.handle_result)

    def handle_result(self, future):
        try:
            result = future.result()
        except Exception as e:
            result = ("", f"Exception: {str(e)}")
        # Ensure the signal is emitted in the main Qt thread.
        QTimer.singleShot(0, lambda: self.task_finished.emit(result))


def on_task_finished(result):
    """
    Callback that processes the result and uses idaapi.msg to display it.
    The result is a tuple (n, res), where if res is a string, an error occurred;
    otherwise, it's the computed square root.
    """
    n, res = result
    if isinstance(res, str):
        message = f"Input {n}: {res}\n"
    else:
        message = f"Square root of {n} is {res}\n"
    idaapi.msg(message)


# Retrieve the existing Qt application instance.
app = QCoreApplication.instance()
# If no instance exists (e.g., during standalone testing), create one.
if app is None:
    app = QCoreApplication([])

# Create a ProcessPoolExecutor with a desired number of worker processes.
with ProcessPoolExecutor(max_workers=4) as executor:
    worker = Worker(executor)
    worker.task_finished.connect(on_task_finished)

    # Submit several tasks (including one odd number to trigger the error handling).
    numbers = [2, 3, 4, 6, 8, 10]
    for n in numbers:
        worker.run_task(n)

    # If running standalone, start the event loop.
    # In IDA Pro, the event loop is already running.
    if QCoreApplication.instance() is None or not idaapi.exec_debugger():
        app.exec()
