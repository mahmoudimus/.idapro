import logging
import multiprocessing
import pathlib
import sys
from concurrent.futures import ProcessPoolExecutor

# Import Qt modules from PySide6 (this may be replaced with PyQt if needed)
from PySide6.QtCore import QCoreApplication, QTimer
from PySide6.QtNetwork import QLocalServer, QLocalSocket

# Optionally import IDA API if available. In IDA Pro the IDAPython environment will have it.
try:
    import idaapi
except ImportError:
    idaapi = None


# -----------------------------
# Custom logging handler that sends log messages over a QLocalSocket.
# -----------------------------
class QLocalSocketHandler(logging.Handler):
    def __init__(self, server_name):
        super().__init__()
        self.server_name = server_name

    def emit(self, record):
        try:
            # Format the log record.
            log_entry = self.format(record)
            # Create a local socket and connect to the logging server.
            socket = QLocalSocket()
            socket.connectToServer(self.server_name)
            if not socket.waitForConnected(1000):
                print("QLocalSocketHandler: Connection to server failed.")
                return
            # Send the log entry (encoded as UTF-8) with a newline terminator.
            data = log_entry.encode("utf-8") + b"\n"
            socket.write(data)
            socket.flush()
            socket.waitForBytesWritten(1000)
            socket.disconnectFromServer()
        except Exception:
            self.handleError(record)


# -----------------------------
# Worker function executed in a separate process.
# -----------------------------
def worker_task(server_name, worker_id):
    # Set up a logger for the worker.
    logger = logging.getLogger(f"worker_{worker_id}")
    logger.setLevel(logging.DEBUG)
    handler = QLocalSocketHandler(server_name)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Log some messages.
    logger.info(f"Worker {worker_id} starting task.")
    logger.debug(f"Worker {worker_id} processing data.")
    logger.info(f"Worker {worker_id} finished task.")
    return f"Worker {worker_id} done."


# -----------------------------
# Function to process new incoming connections from workers.
# -----------------------------
def handle_new_connection(server):
    # Accept the pending connection.
    socket = server.nextPendingConnection()

    # Slot to read data from the socket.
    def read_socket():
        while socket.bytesAvailable():
            data = socket.readAll().data().decode("utf-8").strip()
            if data:
                print("Log received:", data)

    socket.readyRead.connect(read_socket)


def is_ida():
    exec_name = pathlib.Path(sys.executable).name.lower()
    """Crude check to see if running inside IDA."""
    return exec_name.startswith("ida")


def _in_ida(app):
    if not is_ida():
        return

    # If running inside IDA, you might consider using IDA's queue to run periodic tasks.
    # For example, replace QTimer with idaapi.execute_sync() if needed.
    print("Running inside IDA Pro; using the existing Qt application instance.")
    # Required prologue for embedded environment
    multiprocessing.set_start_method("spawn", force=True)
    # Construct path to custom Python binary
    prefix_path = pathlib.Path(sys.exec_prefix)
    specific_python_path = prefix_path / "bin" / "python"
    multiprocessing.set_executable(str(specific_python_path))
    mpctx = multiprocessing.get_context("spawn")
    mpctx.set_executable(str(specific_python_path))

    # Define a server name unique to your logging server.
    server_name = "LoggingServer_IDA"
    local_server = QLocalServer()
    # Clean up any old server with the same name.
    QLocalServer.removeServer(server_name)
    if not local_server.listen(server_name):
        print("Error: Unable to start the logging server:", local_server.errorString())
        sys.exit(1)
    local_server.newConnection.connect(lambda: handle_new_connection(local_server))

    # Launch worker processes using ProcessPoolExecutor.
    futures = []

    # Define a function to check if workers are done.
    def check_workers():
        # if all(f.done() for f in futures):
        for f in futures:
            if f.done():
                print("Result:", f.result())
            else:
                print("Not done:", f)

    # Set up a QTimer to check on the worker results.
    timer = QTimer()
    timer.timeout.connect(check_workers)
    timer.start(500)  # Check every 500 ms

    with ProcessPoolExecutor(max_workers=2, mp_context=mpctx) as executor:
        for i in range(4):
            futures.append(executor.submit(worker_task, server_name, i))

    # When running inside IDA Pro, the event loop is already running.
    # So you can simply return control to IDA.
    print("Logging server is running within IDA Pro's event loop.")


# -----------------------------
# Main entry point for the logging server.
# -----------------------------
def main():
    # In IDA Pro, a Qt application is already created.
    # Use the existing instance if it exists.
    app = None
    if is_ida():
        app = QCoreApplication.instance()
        _in_ida(app)
    else:
        print("Not running inside IDA!")


if __name__ == "__main__":
    main()
