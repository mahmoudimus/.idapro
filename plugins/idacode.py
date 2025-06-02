import asyncio
import inspect
import json
import os
import signal
import socket
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


VERSION = "0.3.0"
initialized = False

_STOP_SERVER = threading.Event()


class Settings:
    HOST = "127.0.0.1"
    PORT = 7065
    DEBUG_PORT = 7066
    PYTHON = r"C:\\dev\\python\\313-ida\\python.exe"
    LOGGING = False

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
    getcwd_original = os.getcwd

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


class BackgroundTornadoServer:
    server: typing.ClassVar
    WAIT = threading.Event()

    def __init__(self, daemon=False):
        self._thread = threading.Thread(target=self._run_server)
        self._thread.daemon = daemon
        self._started = concurrent.futures.Future()
        self._stop_lock = threading.Lock()
        self._stop_requested = False

    def reset(self, force=False):
        if not force:
            force = self._thread.ident
        if force:
            is_daemon = self._thread.daemon
            self._thread = threading.Thread(target=self._run_server)
            self._thread.daemon = is_daemon
            self._started = concurrent.futures.Future()
        self.WAIT.clear()

    def start(self):
        self.reset()
        self._thread.start()
        try:
            self._started.result()
        except:
            self._thread.join()
            raise

    def _run_server(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # https://github.com/dask/distributed/blob/f6796f77f4adfc42cd1608ca1b8a22cba4432685/distributed/utils.py#L1048-L1067
            if (
                sys.platform == "win32"
                and sys.version_info >= (3, 8)
                and tornado.version_info <= (6, 0)
            ):
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            tornado.platform.asyncio.AsyncIOMainLoop()
            self.loop = loop
            loop.call_soon(self._start_server)
            loop.run_forever()
            loop.close()
        except Exception as exc:
            self._started.set_exception(exc)

    def _start_server(self):
        try:
            self._attempt_to_start_server()
            self._started.set_result(None)
        except Exception as e:
            self.loop.stop()
            self._started.set_exception(e)

    def _attempt_to_start_server(self):
        raise NotImplementedError

    def request_stop(self):
        with self._stop_lock:
            if not self._stop_requested:
                self._stop_requested = True
                self.loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(self._stop())
                )

    def stop(self):
        self.request_stop()
        self.WAIT.wait(timeout=5.0)
        if self._thread is not threading.current_thread():
            self._thread.join()
        print(
            "loop is closed? ",
            self.loop.is_closed(),
            " loop is running?",
            self.loop.is_running(),
        )
        print("is thread alive?", self._thread.is_alive())
        # self._thread.join()

    async def _stop(self):
        self.server.stop()
        await tornado.platform.asyncio.to_asyncio_future(
            self.server.close_all_connections()
        )
        self.loop.stop()
        self.WAIT.set()


class Server(BackgroundTornadoServer):
    def __init__(self, config: Settings):
        super().__init__(daemon=True)
        self.config = config
        self.app = tornado.web.Application(
            [
                (r"/ws", SocketHandler),
            ]
        )
        self.server = tornado.httpserver.HTTPServer(self.app)
        # self.thread = threading.Thread(target=self._start)
        # self.thread.daemon = True
        self.stopcheck: tornado.ioloop.PeriodicCallback
        # self.ioloop: tornado.ioloop.IOLoop

        # install signals once
        for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGABRT, signal.SIGSEGV]:
            signal.signal(sig, self.on_signal)

        self._initialized = False

    @property
    def running(self):
        return self._thread.is_alive() and self._initialized

    def _attempt_to_start_server(self):
        """start server"""
        if self.running:
            return
        setup_patches()
        # if self._thread.ident is not None:
        #     # threads can only be started once
        #     self.thread = threading.Thread(target=self._start)
        #     self.thread.daemon = True

        # self.thread.start()
        self._start()
        self._initialized = True

    def _start(self):
        # asyncio.set_event_loop(asyncio.new_event_loop())

        print(
            "[IDACode] Listening on {address}:{port}".format(
                address=settings.HOST, port=settings.PORT
            )
        )
        # every second checks if server should stop
        # self.ioloop = tornado.ioloop.IOLoop.current()
        self.stopcheck = tornado.ioloop.PeriodicCallback(self.handle_stop_event, 1000)
        self.server.listen(address=self.config.HOST, port=self.config.PORT)
        self.stopcheck.start()
        # self.ioloop.start()

    def on_signal(self, sig, frame):
        print("[IDACode] Signal", signal.Signals(sig).name, "received.")
        self.stop()

    def handle_stop_event(self):
        if _STOP_SERVER.is_set():
            print("[IDACode] Stop server event detected.")
            _STOP_SERVER.clear()
            print("[IDACode] Stopping server.")
            self.stopcheck.stop()
            super().stop()
            print(
                "[IDACode] Server stopped. Control thread alive? ",
                self._thread.is_alive(),
            )
            self._initialized = False

    def stop(self):
        """stop server"""
        if not self.running:
            return
        print("[IDACode] Signaling to server to stop")
        _STOP_SERVER.set()

    # def _stop(self):
    #
    # self.server.stop()  # no more requests are accepted (only if no_keep_alive=True)
    # await self.server.close_all_connections()
    # self.ioloop.close()
    # self.ioloop.run_sync(self.server.close_all_connections)
    # self.thread.join()
    # self.stopcheck.stop()

    # self.thread = threading.Thread(target=self._start)
    # self.thread.daemon = True
    # print("[IDACode] Server stopped. Control thread alive? ", self.thread.is_alive())
    # def _close_server_socket(self):
    #     self.app.default_router.named_rules["ws"]
    # # self.ioloop.stop()
    # # self.ioloop = None
    # self.ioloop.add_callback(self.ioloop.stop)
    # # asyncio.new_event_loop().run_until_complete(self.server.close_all_connections())
    # self.server.stop()
    # self.thread.join()

    # self.thread = threading.Thread(target=self._start)
    # self.thread.daemon = True

    # if dbgsrv_running:
    #     raise DebugServerCannotStopError(
    #         "Debug server cannot be stopped currently.\ncheck here: https://github.com/microsoft/debugpy/issues/870"
    #     )


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
    def running(self):
        return self.server.running

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
        self.server = Server(settings)
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pass

    def start(self):
        _STOP_SERVER.clear()
        self.server.start()
        # thread = threading.Thread(target=self.ioloop.start)
        # thread.daemon = True
        # thread.start()

    def stop(self):
        # _STOP_SERVER.set()
        # self.ioloop.stop()
        self.server.stop()

        # dialog = ErrorDialog(
        #     "Control server stoped, but debug server is still running and cannot be stopped currently.\nCheck here for more: https://github.com/microsoft/debugpy/issues/870"
        # )
        # dialog.Execute()
        # dialog.Free()

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
    HOTKEY = None
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
        if self.plugin.running:
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
        if self.plugin.running:
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
