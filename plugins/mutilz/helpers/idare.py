import re
import typing
from dataclasses import dataclass
from enum import Enum

import idc


# Assuming PatternCategory is an Enum defined elsewhere
class PatternCategory(Enum):
    FUNCTION_PADDING = 1


@dataclass
class RegexPatternMetadata:
    category: PatternCategory
    pattern: bytes
    description: typing.Optional[str] = None
    compiled: typing.Optional[typing.Pattern] = None

    def compile(self, flags=0):
        if self.compiled is None:
            self.compiled = re.compile(self.pattern, flags)
        return self.compiled

    @property
    def group_names(self):
        return self.compile().groupindex


class MemHelper:
    def __init__(self, start: int, end: int):
        self.mem_results = b""
        self.mem_offsets = []
        self.start = start
        self.end = end
        if not self.mem_results:
            self._get_memory(start, end)

    def _get_memory(self, start: int, end: int):
        result = idc.get_bytes(start, end - start)
        self.mem_results = result
        self.mem_offsets.append((start, end - start))
