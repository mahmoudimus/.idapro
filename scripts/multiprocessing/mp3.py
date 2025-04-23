import logging
import multiprocessing
import pathlib
import sys
from concurrent.futures import ProcessPoolExecutor

# Import Qt modules from PySide6 (this may be replaced with PyQt if needed)
from PySide6.QtCore import QCoreApplication, QTextStream, QTimer
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
    # pull off the new QLocalSocket
    socket = server.nextPendingConnection()

    # wrap it in a QTextStream for line‑based UTF‑8 reads
    stream = QTextStream(socket)
    stream.setCodec("UTF-8")
    stream.setAutoDetectUnicode(True)

    def read_socket():
        # read as many lines as the socket has buffered
        while not stream.atEnd():
            line = stream.readLine()
            if line:
                # send it to IDA's console
                idaapi.msg(line + "\n")

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

    # 1) remove old socket; 2) start listening
    orig_name = "LoggingServer_IDA"
    QLocalServer.removeServer(orig_name)
    server = QLocalServer(app)
    if not server.listen(orig_name):
        idaapi.msg(f"Error: Unable to start logging server: {server.errorString()}\n")
        sys.exit(1)

    try:
        # Qt ≥5.10 / Qt6 provides this static helper
        full_socket_path = QLocalServer.fullServerName(orig_name)
    except (AttributeError, TypeError):
        # Fallback: build "/tmp/{appName}_{orig_name}" if appName is set,
        # otherwise "/tmp/{orig_name}"
        from PySide6.QtCore import QDir

        app_name = app.applicationName() if app else ""
        socket_file = f"{app_name}_{orig_name}" if app_name else orig_name
        full_socket_path = QDir.tempPath() + QDir.separator() + socket_file

    idaapi.msg(f"Logging server listening on: {full_socket_path}\n")
    server.newConnection.connect(lambda: handle_new_connection(server))

    # Launch workers exactly as before...
    futures = []

    # install a QTimer on the IDA app so it doesn't get GC'd
    timer = QTimer(app)

    def check_workers():
        all_done = True
        for f in futures:
            if f.done():
                idaapi.msg(f"Result: {f.result()}\n")
            else:
                all_done = False
                idaapi.msg("Not done yet…\n")
        # once all are done, you can shut down the executor
        if all_done and executor:
            executor.shutdown(wait=False)

    timer.timeout.connect(check_workers)
    timer.start(500)  # every half‑second
    idaapi.msg("Starting workers...\n")
    # IMPORTANT: keep a reference so we don't block the UI by shutting down immediately
    executor = ProcessPoolExecutor(max_workers=2, mp_context=mpctx)
    for i in range(4):
        futures.append(executor.submit(worker_task, full_socket_path, i))

    idaapi.msg("Waiting for workers to finish...\n")


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
