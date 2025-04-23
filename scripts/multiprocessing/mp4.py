import concurrent.futures
import math
import multiprocessing
import os
import pathlib
import sys
import uuid
import zlib
from multiprocessing.connection import Client, Listener, wait
from threading import Event, Thread

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, Signal, Slot
from PySide6.QtGui import QWindow
from PySide6.QtWidgets import QMdiSubWindow, QWidget

PREFIX_PATH = pathlib.Path(sys.exec_prefix)
PYTHON_INTERPRETER = PREFIX_PATH / "bin" / "python"
multiprocessing.set_start_method("spawn", force=True)
multiprocessing.set_executable(str(PYTHON_INTERPRETER))
MPCTX = multiprocessing.get_context("spawn")
MPCTX.set_executable(str(PYTHON_INTERPRETER))


def is_ida():
    exec_name = pathlib.Path(sys.executable).name.lower()
    """Crude check to see if running inside IDA."""
    return exec_name.startswith("ida")


if is_ida():
    import ida_idaapi
    import ida_kernwin


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

    # logging.debug(f"Generated SHM name: {name}")
    return name


# ————————————————————————————————————————————————————————————————————————————————
class ConnectionServer(QObject):
    new_connection = Signal(object)

    def __init__(self, address=None, parent=None):
        super().__init__(parent)
        self.listener = Listener(address or ("localhost", 0), authkey=b"secret")
        self.thread = Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    @property
    def address(self):
        return self.listener.address

    def _run(self):
        while True:
            try:
                conn = self.listener.accept()
            except OSError:
                break
            self.new_connection.emit(conn)

    def close(self):
        self.listener.close()


class TaskManagerClient(QProcess):
    winid_available = Signal(int)

    def __init__(self, python_exe, parent=None):
        super().__init__(parent)

        # strip out conflicting env vars
        env = QProcessEnvironment.systemEnvironment()
        for v in ("PYTHONHOME", "PYTHONPATH"):
            if env.contains(v):
                env.remove(v)
        self.setProcessEnvironment(env)

        # spin up our IPC server
        self._server = ConnectionServer()
        self._server.new_connection.connect(self._on_conn)
        self._server.start()

        host, port = self._server.address
        self.setProgram(python_exe)
        self.setArguments(
            [str(pathlib.Path(__file__)), "--host", host, "--port", str(port)]
        )
        self.setProcessChannelMode(QProcess.MergedChannels)
        self.readyRead.connect(self._echo)

    @Slot(object)
    def _on_conn(self, conn):
        # launch receiver loop
        Thread(target=self._recv, args=(conn,), daemon=True).start()

    def _recv(self, conn):
        try:
            verb, arg = conn.recv()
        except EOFError:
            return
        if verb == "WINID":
            self.winid_available.emit(arg)
        ida_kernwin.msg(f"[_rcv] {verb} {arg}")

    @Slot()
    def _echo(self):
        text = bytes(self.readAllStandardOutput()).decode(errors="ignore")
        ida_kernwin.msg(f"[offload] {text}")

    def cleanup(self):
        self._server.close()
        if self.state() != QProcess.NotRunning:
            self.terminate()
            self.waitForFinished(2000)


def compute_sqrt(n):
    """Compute the square root of the given number and print details."""
    result = math.sqrt(n) + 1
    print(f"WORKER (PID: {os.getpid()}): sqrt({n}) = {result}")
    return result


def task(conn):
    # Use ProcessPoolExecutor to manage worker processes
    numbers = [4, 16, 25, 36, 49, 64, 81, 100]
    with concurrent.futures.ProcessPoolExecutor(mp_context=MPCTX) as executor:
        # Submit tasks to compute the square root of each number
        futures = {executor.submit(compute_sqrt, n): n for n in numbers}

        # Retrieve and display the results as each completes
        for future in concurrent.futures.as_completed(futures):
            n = futures[future]
            try:
                result = future.result()
                conn.send(("LOG", f"PARENT: Result for {n} is {result}"))
            except Exception as e:
                conn.send(
                    ("LOG", f"PARENT: Computation for {n} raised an exception: {e}")
                )


if __name__ == "__main__":
    """
    if is_ida():
        mgr_client = TaskManagerClient()
        mgr_client.launch_server()
        mgr_client.connect_to_server()
        mgr_client.start_task()
        mgr_client.shutdown()
        mgr_client.cleanup()

    else:
        parser = parse_args()
        mgr_server = TaskManagerServer.from_args(parser.args)
        mgr_server.start()
    """

    if is_ida():
        mgr_client = TaskManagerClient()
        mgr_client.launch_server()
        mgr_client.connect_to_server()
        mgr_client.start_task()
        mgr_client.shutdown(after=10)  # 10 seconds
    else:
        import argparse

        p = argparse.ArgumentParser()
        p.add_argument("--host")
        p.add_argument("--port", type=int)
        args = p.parse_args()

        # connect back to IDA
        conn = Client((args.host, args.port), authkey=b"secret")
        conn.send(("LOG", "Hello from external process"))
        task(conn)
