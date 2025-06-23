import typing

import ipyida.ida_qtconsole
from IPython.core.formatters import DisplayFormatter
from IPython.core.getipython import get_ipython

from idapythonrc import reload_package


def ipy_hexon():
    formatter = get_ipython()
    if formatter is None or not isinstance(
        formatter.display_formatter, DisplayFormatter
    ):
        return
    formatter = typing.cast(DisplayFormatter, formatter.display_formatter)
    formatter.formatters["text/plain"].for_type(
        int, lambda n, p, cycle: p.text("0x%x" % n)
    )


def ipy_hexoff():
    formatter = get_ipython()
    if formatter is None or not isinstance(
        formatter.display_formatter, DisplayFormatter
    ):
        return
    formatter = typing.cast(DisplayFormatter, formatter.display_formatter)
    formatter.formatters["text/plain"].for_type(
        int, lambda n, p, cycle: p.text("%d" % n)
    )


ipyida.ida_qtconsole.set_widget_options(
    dict(
        font_family="PragmataPro Mono Liga",
        font_size=12,
        buffer_size=10000,
        confirm_exit=False,
    )
)
