import logging
from time import strftime
from unittest.mock import MagicMock


class EveryNFilter(logging.Filter):
    def __init__(self, n):
        super().__init__()
        self.n = n
        self.count = 0

    def filter(self, record):
        self.count += 1
        # Only pass through every n-th log record.
        return self.count % self.n == 0


class LimitedLogger:
    mock = MagicMock()

    def __init__(self, logger, limit=None):
        self._logger = logger
        self._limit = limit
        self._count = 0

    def get(self):
        if self._limit is None or self._count < self._limit:
            self._count += 1
            return self._logger
        else:
            return self.mock

    def reset(self, limit=None):
        self._limit = self._limit if limit is None else limit
        self._count = 0


def configure_logging(
    log,
    level=logging.INFO,
    handler_filters=None,
    fmt_str="[%(levelname)s] @ %(asctime)s %(message)s",
):
    log.propagate = False
    log.setLevel(level)
    formatter = logging.Formatter(fmt_str)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)

    # Add the custom filter if every_n is specified.
    if handler_filters is not None:
        for _filter in handler_filters:
            handler.addFilter(_filter)

    for handler in log.handlers[:]:
        log.removeHandler(handler)
        handler.close()

    if not log.handlers:
        log.addHandler(handler)


def configure_debug_logging(log, **kwargs):
    kwargs["level"] = logging.DEBUG
    configure_logging(log, **kwargs)


def dprint(func, every_n=None):
    count = 0

    def wrapped_func(*args, **kwargs):
        nonlocal count
        count += 1
        if every_n is None or (every_n is not None and count % every_n == 0):
            return func(*args, **kwargs)

    return wrapped_func
