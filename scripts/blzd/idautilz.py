import time

import ida_kernwin


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
            try:
                total = len(iterable)
            except (TypeError, AttributeError):
                total = None

        if total == float("inf"):
            # Infinite iterations, behave same as unknown
            total = None
        self.total = total
        self.n = initial

    def __iter__(self):
        # Inlining instance variables as locals (speed optimization)
        iterable = self.iterable
        total = self.total
        with ProgressDialog("Executing") as pd:
            for idx, item in enumerate(iterable, start=1):
                if pd.user_canceled():
                    break
                pd.replace_message(f"Processing ({idx}/{total})")
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
