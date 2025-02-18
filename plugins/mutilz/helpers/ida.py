import inspect
import time
import types
from dataclasses import dataclass

import ida_kernwin
import ida_ua
import idaapi


def clear_window(window):
    form = ida_kernwin.find_widget(window)
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")


def clear_output():
    clear_window("Output window")


def decode_to_instr(address: int) -> ida_ua.insn_t:
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, address)  # corrected function name
    return insn


def format_addr(addr: int) -> str:
    """Return the address formatted as a string: 0x{address:02X}"""
    return f"0x{addr:02X}"


def refresh_idaview(force=False):
    if not force:
        ida_kernwin.refresh_navband(True)
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.request_refresh(ida_kernwin.IWID_FUNCS)
    else:
        ida_kernwin.refresh_idaview_anyway()
        idaapi.require_refresh()


class ProgressDialog:
    def __init__(self, message="Please wait...", hide_cancel=False):
        self._default_msg: str
        self.hide_cancel: bool
        self.__user_canceled = False
        self.configure(message, hide_cancel)

    def _message(self, message=None, hide_cancel=None):
        display_msg = self._default_msg if message is None else message
        hide_cancel = self.hide_cancel if hide_cancel is None else hide_cancel
        prefix = "HIDECANCEL\n" if hide_cancel else ""
        return prefix + display_msg

    def configure(self, message="Please wait...", hide_cancel=False):
        self._default_msg = message
        self.hide_cancel = hide_cancel
        return self

    __call__ = configure

    def __enter__(self):
        ida_kernwin.show_wait_box(self._message())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        ida_kernwin.hide_wait_box()
        if self.__user_canceled:
            ida_kernwin.warning("Canceled")

    def replace_message(self, new_message, hide_cancel=False):
        msg = self._message(message=new_message, hide_cancel=hide_cancel)
        ida_kernwin.replace_wait_box(msg)

    def user_canceled(self):
        self.__user_canceled = ida_kernwin.user_cancelled()
        return self.__user_canceled

    user_cancelled = user_canceled


class ida_tguidm:

    def __init__(self, iterable, total=None, initial=0):
        self.iterable = iterable

        if total is None and iterable is not None:
            if isinstance(iterable, types.GeneratorType) or inspect.isgeneratorfunction(
                iterable
            ):
                self.iterable = list(iterable)
                iterable = self.iterable
            try:
                total = len(iterable)
            except (TypeError, AttributeError):
                total = None

        if total == float("inf"):
            # Infinite iterations, behave same as unknown
            total = None
        self.total = total
        self.start_time = None  # Track start time
        self.n = initial

    def __iter__(self):
        # Inlining instance variables as locals (speed optimization)
        iterable = self.iterable
        total = self.total
        self.start_time = time.time()  # Start tracking time
        with ProgressDialog("Executing") as pd:
            for idx, item in enumerate(iterable, start=1):
                if pd.user_canceled():
                    break

                elapsed_time = time.time() - self.start_time
                avg_time_per_item = elapsed_time / idx if idx > 0 else 0
                remaining_time = (total - idx) * avg_time_per_item if total else None

                if remaining_time is not None:
                    eta_str = f" | ETA: {int(remaining_time)}s"
                else:
                    eta_str = ""

                pd.replace_message(f"Processing ({idx}/{total}){eta_str}")

                try:
                    yield item
                except Exception as e:
                    ida_kernwin.warning(f"Unexpected error {e}")
                    break


class WaitBox:
    buffertime = 0.0
    shown = False
    msg = ""

    @staticmethod
    def _show(msg):
        WaitBox.msg = msg
        if WaitBox.shown:
            ida_kernwin.replace_wait_box(msg)
        else:
            ida_kernwin.show_wait_box(msg)
            WaitBox.shown = True

    @staticmethod
    def show(msg, buffertime=0.1):
        if msg == WaitBox.msg:
            return

        if buffertime > 0.0:
            if time.time() - WaitBox.buffertime < buffertime:
                return
            WaitBox.buffertime = time.time()
        WaitBox._show(msg)

    @staticmethod
    def hide():
        if WaitBox.shown:
            ida_kernwin.hide_wait_box()
            WaitBox.shown = False


@dataclass
class BaseActionHandler(idaapi.action_handler_t):
    """An action handler for IDA Pro with automatic metadata extraction.
    Override the action_desc attributes to customize the action."""

    category: str = "mutilz"  # Default category, can be overridden
    action_name_prefix: str = f"{category}:"
    action_name: str = ""
    action_label: str = ""
    action_desc: str = ""
    icon: int = 156  # gear icon

    def __post_init__(self):
        if not self.action_name:
            self.action_name = self.get_action_name()
        if not self.action_label:
            self.action_label = self.get_action_label()
        if not self.action_desc:
            self.action_desc = self.get_action_desc()
        super().__init__()

    @classmethod
    def get_action_name(cls):
        return cls.action_name_prefix + cls.__name__.replace("Handler", "").lower()

    @classmethod
    def get_action_label(cls):
        return cls.__name__.replace("Handler", "").replace("_", " ")

    @classmethod
    def get_action_desc(cls):
        return cls.__doc__.strip() if cls.__doc__ else "No description available."

    @classmethod
    def get_icon(cls):
        return cls.icon

    @classmethod
    def get_category(cls):
        return cls.category  # Allows subclasses to override the category


class PopUpHook(idaapi.UI_Hooks):
    def __init__(self, action_handler_cls, predicate):
        super().__init__()
        action_handler = action_handler_cls()
        self.action = idaapi.action_desc_t(
            action_handler.action_name,
            action_handler.action_label,
            action_handler,
            None,  # No hotkey (context menu only)
            action_handler.action_desc,
            action_handler.icon,
        )
        assert idaapi.register_action(
            self.action
        ), f"Failed to register action {self.action.name}"

        self.predicate = predicate
        self.category = action_handler.category

    def term(self):
        idaapi.unregister_action(self.action.name)

    # Right-click menu popup
    def finish_populating_widget_popup(self, widget, popup, ctx):
        if self.predicate(widget, popup, ctx):
            idaapi.attach_action_to_popup(
                widget, popup, self.action.name, f"{self.category}/"
            )


class HookedActionMeta(type):
    """Metaclass to automatically manage UI hooks in action classes."""

    def __new__(cls, name, bases, dct):
        if "uihook_class" in dct:
            uihook_class = dct["uihook_class"]

            # Define __init__ method
            def __init__(self):
                self.uihook = uihook_class()
                self.uihook.hook()

            # Define term method
            def term(self):
                self.uihook.unhook()
                self.uihook.term()

            dct["__init__"] = __init__
            dct["term"] = term

        return super().__new__(cls, name, bases, dct)


def is_disassembly_widget(widget, popup, ctx):
    return idaapi.get_widget_type(widget) == idaapi.BWN_DISASM
