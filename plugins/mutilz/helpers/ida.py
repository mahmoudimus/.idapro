import inspect
import time
import types
import typing
from dataclasses import dataclass

import ida_bytes
import ida_ida
import ida_kernwin
import ida_nalt
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


def monitored_iter(iterable, timeout=60, diagnostic=None):
    """
    Wraps an iterable or generator to monitor its iteration time.
    If processing takes longer than `timeout` seconds, prompts the user
    with optional diagnostic information.

    Parameters:
        iterable: An iterable or generator to be wrapped.
        timeout: Number of seconds to wait before prompting the user (default is 60).
        diagnostic: Optional diagnostic information.
            - If a string, it will be appended to the prompt.
            - If a callable, it is called with (index, item) and should return a string.

    Yields:
        Each item from the original iterable.

    Raises:
        StopIteration: If the user chooses not to continue.

    Example:

    >>> def sample_diagnostic(idx, item):
    >>>     return f"Processing item {idx}: {item}"
    >>>
    >>> # An example generator that yields numbers 0 to 9 with a delay.
    >>> def slow_generator():
    >>>     for i in range(10):
    >>>         time.sleep(10)  # simulate long processing
    >>>         yield i
    >>>
    >>> try:
    >>>     for number in monitored_iter(slow_generator(), timeout=15, diagnostic=sample_diagnostic):
    >>>         print(f"Got number: {number}")
    >>> except StopIteration as e:
    >>>     print(e)
    """
    t = time.time()
    asked = False
    for index, item in enumerate(iterable):
        # Check if the elapsed time exceeds the timeout
        if time.time() - t > timeout and not asked:
            message = "The process is taking too long."
            if diagnostic:
                # Allow diagnostic to be a callable or a string
                if callable(diagnostic):
                    message += " " + diagnostic(index, item)
                else:
                    message += " " + str(diagnostic)
            message += " Do you want to continue?"
            response = idaapi.ask_yn(1, message)
            asked = True  # Only ask once per timeout event
            if response != 1:
                raise StopIteration("Iteration aborted by the user.")
            else:
                t = time.time()  # Reset timer after confirmation
                asked = False
        yield item


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
    def __init__(self, action_handler_cls, predicate, widget_populator=None):
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
        self.widget_populator = widget_populator

    def term(self):
        idaapi.unregister_action(self.action.name)

    def _widget_populator(self, widget, popup, ctx):
        if self.predicate(widget, popup, ctx):
            idaapi.attach_action_to_popup(
                widget, popup, self.action.name, f"{self.category}/"
            )

    # Right-click menu popup
    def finish_populating_widget_popup(self, widget, popup, ctx):
        if self.widget_populator:
            return self.widget_populator(self, widget, popup, ctx)
        return self._widget_populator(widget, popup, ctx)


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


def find_signature(ida_signature: str) -> list:
    binary_pattern = idaapi.compiled_binpat_vec_t()
    idaapi.parse_binpat_str(binary_pattern, ida_ida.inf_get_min_ea(), ida_signature, 16)
    results = []
    ea = ida_ida.inf_get_min_ea()
    while True:
        occurence, _ = ida_bytes.bin_search(
            ea,
            ida_ida.inf_get_max_ea(),
            binary_pattern,
            ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_FORWARD,
        )
        if occurence == idaapi.BADADDR:
            break
        results.append(occurence)
        ea = occurence + 1
    return results


# TODO (mr): use find_bytes
# https://github.com/mandiant/capa/issues/2339
def find_byte_sequence(
    start: int, end: int, seq: list[int] | bytes
) -> typing.Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        start: min virtual address
        end: max virtual address
        seq: bytes to search e.g. b"\x01\x03"
    """
    patterns = ida_bytes.compiled_binpat_vec_t()

    if isinstance(seq, list):
        seqstr = " ".join([f"{b:02x}" if b != -1 else "?" for b in seq])
    else:
        seqstr = seq.decode("utf-8")

    err = ida_bytes.parse_binpat_str(
        patterns,
        start,
        seqstr,
        16,
        ida_nalt.get_default_encoding_idx(  # use one byte-per-character encoding
            ida_nalt.BPU_1B
        ),
    )

    if err:
        return

    while True:
        ea = ida_bytes.bin_search(start, end, patterns, ida_bytes.BIN_SEARCH_FORWARD)
        # "drc_t" in IDA 9
        ea = ea[0]
        if ea == idaapi.BADADDR:
            break
        start = ea + 1
        yield ea


# def scan(pattern):
#     ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
#     print("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase()))


# def fullscan(pattern):
#     ea = 0
#     while True:
#         ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
#         if ea == idc.BADADDR:
#             break
#         print("Found match at %x +%x" % (ea, ea - idaapi.get_imagebase()))


def sig_bytes_to_ida_pattern(
    sig: str | list[int],
    sep: str = ", ",
    wildcards: set[int | str] = {"?", -1},
) -> str:
    """
    Cannot pass in bytes or bytearray because wildcards are difficult to
    differentiate between 0xFF and -1. Maybe we can do ord("?") which is
    63 or 0x3F? not sure.
    """
    if isinstance(sig, str):
        sig = [int(b, 16) for b in sig.split(sep)]
    return " ".join([f"{b:02x}" if b not in wildcards else b for b in sig])
