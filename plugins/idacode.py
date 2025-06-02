import asyncio
import inspect
import json
import logging
import os
import pathlib
import signal
import socket
import stat
import subprocess
import sys

if sys.version_info < (3, 4):
    raise RuntimeError("Sorry, python 3.8+ required")

import concurrent.futures
import tempfile
import threading
import typing

import ida_kernwin
import idaapi

try:
    import debugpy.server.api
    import tornado.httpserver
    import tornado.ioloop
    import tornado.platform.asyncio
    import tornado.web
    import tornado.websocket
except ImportError:
    print(
        "[IDACode] Dependencies missing, run: python -m pip install --user debugpy tornado"
    )
    exit(-1)

import PyQt5.QtWidgets as QtWidgets

VERSION = "0.3.0"
initialized = False

_STOP_SERVER = threading.Event()


def get_python_interpreter() -> str:
    """
    Gets the path to a suitable Python interpreter.
    Ensures we find a standalone Python executable.

    >>> interp: str = MultiprocessingHelper.get_python_interpreter()
    ...
    >>>
    """
    base_executable = getattr(sys, "_base_executable", None)
    if base_executable and "python" in pathlib.Path(base_executable).name.lower():
        return str(pathlib.Path(base_executable))

    base_paths = [
        sys.prefix,
        sys.exec_prefix,
        sys.executable,
    ]
    exe_suffix = ".exe" if os.name == "nt" else ""
    python_name = f"python{exe_suffix}"

    def base_dirs():
        for dirname in map(pathlib.Path, base_paths):
            yield dirname
            yield dirname.parent
            yield dirname.parent.parent

    for dirname in base_dirs():
        for basename in ["", "bin", "python"]:
            interp_path = dirname / basename / python_name
            if not interp_path.exists():
                continue

            if not interp_path.is_file() or not interp_path.is_symlink():
                continue

            if not interp_path.stat().st_mode & (
                stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            ):
                continue

            print(f"[IDACode] Found Python interpreter at: {interp_path}")
            return str(interp_path)

    print(
        "[IDACode] Could not determine Python interpreter path, falling back to 'python' in PATH."
    )
    return str(pathlib.Path("python"))


class Settings:
    HOST = "127.0.0.1"
    PORT = 7065
    DEBUG_PORT = 7066
    PYTHON = get_python_interpreter()
    LOGGING = False
    ALLOW_UNSAFE_ORIGIN = False

    @classmethod
    def load(cls):
        return cls()


settings = Settings.load()


class Dbg:

    api = debugpy.server.api

    @classmethod
    def bp(cls, *args):
        condition = True
        message = ""
        for arg in args:
            if type(arg) is bool:
                condition = arg
                break
        for arg in args:
            if type(arg) is str:
                message = arg
                break
        if condition:
            if message:
                print("[IDACode] {message}".format(message=message))
            cls.api.breakpoint()


class Hooks:
    script_folder = ""
    getcwd_original = staticmethod(os.getcwd)

    @classmethod
    def getcwd_hook(cls):
        if cls.script_folder:
            return cls.script_folder
        return cls.getcwd_original()

    @classmethod
    def set_script_folder(cls, folder):
        cls.script_folder = folder

    @classmethod
    def install(cls):
        os.getcwd = cls.getcwd_hook

    @classmethod
    def uninstall(cls):
        os.getcwd = cls.getcwd_original


def create_env():
    return {"dbg": Dbg, "__idacode__": True, "__name__": "__main__"}


# Shouldn't apply to docker-compose dev mode (1 process, 1 thread), but may be needed when enabling debugging in other contexts
def is_debugger_listening(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s.connect_ex(("127.0.0.1", port)) == 0


def start_debug_server():
    if is_debugger_listening(settings.DEBUG_PORT):
        print(
            "[IDACode] IDACode debug server already listening on {address}:{port}".format(
                address=settings.HOST, port=settings.DEBUG_PORT
            )
        )
        return

    if settings.LOGGING:
        tmp_path = tempfile.gettempdir()
        debugpy.log_to(tmp_path)
        print("[IDACode] Logging to {} with pattern debugpy.*.log".format(tmp_path))
    debugpy.configure(
        {
            "python": settings.PYTHON,
            # https://github.com/microsoft/debugpy/issues/262
            # "subProcess": True,
        }
    )
    debugpy.listen((settings.HOST, settings.DEBUG_PORT))
    print(
        "[IDACode] IDACode debug server listening on {address}:{port}".format(
            address=settings.HOST, port=settings.DEBUG_PORT
        )
    )


class SocketHandler(tornado.websocket.WebSocketHandler):

    def check_origin(self, origin):
        # NOTE: This is called when connecting from a browser
        return settings.ALLOW_UNSAFE_ORIGIN

    def open(self):
        print("[IDACode] Client connected")

    def on_message(self, message):
        if isinstance(message, bytes):
            message = message.decode("utf8")
        message = json.loads(message)

        if message["event"] == "set_workspace":
            path = message["path"]
            Hooks.set_script_folder(path)
            print("[IDACode] Set workspace folder to {}".format(path))
        elif message["event"] == "attach_debugger":
            start_debug_server()
            self.write_message({"event": "debugger_ready"})
        elif message["event"] == "execute_script":
            script = message["path"]
            env = create_env()
            print("[IDACode] Executing {}".format(script))
            idaapi.execute_sync(
                lambda: idaapi.IDAPython_ExecScript(script, env), idaapi.MFF_WRITE
            )
        else:
            print("[IDACode] Invalid event {}".format(message["event"]))

    def on_close(self):
        print("[IDACode] Client disconnected")


def setup_patches():
    Hooks.install()
    # sys.executable = settings.PYTHON


def join_gui_thread(thread: threading.Thread, timeout=None):
    iterations = 0
    iteration_timeout = 0.1
    while True:
        if not thread.is_alive():
            return True
        thread.join(iteration_timeout)
        QtWidgets.QApplication.processEvents()
        if timeout is not None and iteration_timeout * iterations >= timeout:
            return False
        iterations += 1


class Server:
    def __init__(self):
        self.started = False
        self.server: tornado.httpserver.HTTPServer | None = None
        self.thread: threading.Thread = threading.Thread(target=self.server_thread)

    def start(self):
        self.stop()
        self.thread.start()
        self.started = True

    def stop(self):
        if not self.started:
            return

        if self.server is not None:
            self.io_loop.add_callback(self.server.stop)
            self.io_loop.add_callback(self.server.close_all_connections)
            self.io_loop.add_callback(self.io_loop.stop)

        if not join_gui_thread(self.thread, 1.0):
            print("[IDACode] Waiting for server to stop...")
            if not join_gui_thread(self.thread, 5.0):
                print(
                    "[IDACode] deadlock while stopping server, please report an issue!\n"
                )
        self.thread = threading.Thread(target=self.server_thread)
        self.server = None
        print("[IDACode] Server stopped")

    def server_thread(self):
        # Create a new event loop for the thread
        # https://github.com/tornadoweb/tornado/issues/2308#issuecomment-372582005
        loop = asyncio.new_event_loop()
        loop.set_debug(False)
        logging.getLogger("asyncio").setLevel(
            logging.CRITICAL
        )  # Remove some debug spam
        asyncio.set_event_loop(loop)

        # Before starting the event loop, instantiate a WebSocketClient and add a
        # callback to the event loop to start it. This way the first thing the
        # event loop does is to start the client.
        self.io_loop = tornado.ioloop.IOLoop.current()
        app = tornado.web.Application(
            [
                (r"/ws", SocketHandler),
            ]
        )
        server = tornado.httpserver.HTTPServer(app)
        print(
            "[IDACode] Listening on {address}:{port}".format(
                address=settings.HOST, port=settings.PORT
            )
        )
        server.listen(address=settings.HOST, port=settings.PORT)
        self.server = server

        # Start the event loop.
        self.io_loop.start()

        # Signal that the service is finished
        self.started = False


def get_python_versions():
    settings_version = subprocess.check_output(
        [settings.PYTHON, "-c", "import sys; print(sys.version + sys.platform)"]
    )
    settings_version = settings_version.decode("utf-8", "ignore").strip()
    ida_version = "{}{}".format(sys.version, sys.platform)
    return (settings_version, ida_version)


class IDACode(idaapi.plugin_t):
    def __init__(self):
        # self.flags = idaapi.PLUGIN_UNL
        # PLUGIN_HIDE: do not show this plugin in the Edit->Plugins menu
        # PLUGIN_FIX: keep plugin loaded until IDA stops. because have no way to stop debugpy
        self.flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
        self.comment = "IDACode"
        self.help = "IDACode"
        self.wanted_name = "IDACode"
        self.wanted_hotkey = ""
        self.server: Server

    @property
    def started(self):
        return self.server.started

    def init(self):
        global initialized
        if initialized:
            return idaapi.PLUGIN_OK

        initialized = True
        if os.path.isfile(settings.PYTHON):
            settings_version, ida_version = get_python_versions()
            if settings_version != ida_version:
                print("[IDACode] settings.PYTHON version mismatch, aborting load:")
                print("[IDACode] IDA interpreter: {}".format(ida_version))
                print("[IDACode] settings.PYTHON: {}".format(settings_version))
                return idaapi.PLUGIN_SKIP
        else:
            print(
                "[IDACode] settings.PYTHON ({}) does not exist, aborting load".format(
                    settings.PYTHON
                )
            )
            print(
                "[IDACode] To fix this issue, modify idacode_utils/settings.py to point to the python executable"
            )
            return idaapi.PLUGIN_SKIP
        print("[IDACode] Plugin version {}".format(VERSION))
        print(
            "[IDACode] Plugin loaded, use Edit -> Plugins -> IDACode to start the server"
        )
        StartMenuHandle.register(self)
        StopMenuHandle.register(self)
        OptionMenuHandle.register(self)
        self.server = Server()
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pass

    def start(self):
        self.server.start()

    def stop(self):
        self.server.stop()

    def term(self):
        self.stop()

    def option(self):
        dialog = OptionDialog(settings.HOST, settings.HOST)
        if dialog.Execute() == 1:
            settings.HOST = dialog.host
            settings.PORT = dialog.port
        dialog.Free()


# =====================================================================================
# UI
# =====================================================================================
class MenuHandle(ida_kernwin.action_handler_t):
    NAME = ""
    TEXT = ""
    TOOLTIP = ""
    HOTKEY = ""
    PATH = ""

    def __init__(self, plugin: IDACode) -> None:
        super(MenuHandle, self).__init__()
        self.plugin = plugin

    @classmethod
    def register(cls, plugin: IDACode) -> None:
        desc = ida_kernwin.action_desc_t(
            cls.NAME, cls.TEXT, cls(plugin), cls.HOTKEY, cls.TOOLTIP
        )
        if not ida_kernwin.register_action(desc):
            print(f"Failed to register action: {cls.NAME}")
        ida_kernwin.attach_action_to_menu(cls.PATH, cls.NAME, ida_kernwin.SETMENU_APP)


class StartMenuHandle(MenuHandle):

    NAME = "IDACode:start"
    TEXT = "Start"
    TOOLTIP = "Start debug server"
    PATH = "Edit/IDACode/Start"

    def activate(self, ctx):
        self.plugin.start()

    def update(self, ctx):
        if self.plugin.started:
            return ida_kernwin.AST_DISABLE
        else:
            return ida_kernwin.AST_ENABLE


class StopMenuHandle(MenuHandle):
    NAME = "IDACode:stop"
    TEXT = "Stop"
    TOOLTIP = "Stop debug server"
    PATH = "Edit/IDACode/Stop"

    def activate(self, ctx):
        self.plugin.stop()

    def update(self, ctx):
        if self.plugin.started:
            return ida_kernwin.AST_ENABLE
        else:
            return ida_kernwin.AST_DISABLE


class OptionMenuHandle(MenuHandle):
    NAME = "patching:option"
    TEXT = "Option..."
    TOOLTIP = "Option"
    PATH = "Edit/IDACode/Option..."

    def activate(self, ctx):
        self.plugin.option()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class OptionDialog(ida_kernwin.Form):

    def __init__(self, host, control_port):
        self.c_host: ida_kernwin.Form.StringInput
        self.c_port: ida_kernwin.Form.NumericInput

        super(OptionDialog, self).__init__(
            r"""STARTITEM 0
BUTTON YES* OK
IDACODE :: OPTION

<Hostname       :{c_host}>
<Port           :{c_port}>
            """,
            {
                "c_host": self.StringInput(value=host),
                "c_port": self.NumericInput(value=control_port, tp=self.FT_DEC),
            },
        )

        self.Compile()

    @property
    def host(self):
        return self.c_host.value

    @property
    def port(self):
        return self.c_port.value


class ErrorDialog(ida_kernwin.Form):

    def __init__(self, text):
        super(ErrorDialog, self).__init__(
            r"""STARTITEM 1
BUTTON YES* OK
IDACODE :: Error

{c_text}
            """,
            {
                "c_text": self.StringLabel(value=text),
            },
        )

        self.Compile()


def PLUGIN_ENTRY():
    return IDACode()
