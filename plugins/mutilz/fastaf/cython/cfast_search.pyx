# coding: utf-8
# cython: language_level=3, boundscheck=False, wraparound=False

import cython
from cython import Py_ssize_t


@cython.locals(
    data_len=Py_ssize_t,
    pattern_len=Py_ssize_t,
    i=Py_ssize_t,
    j=Py_ssize_t,
    match=cython.bint,
)
@cython.returns(Py_ssize_t)
def search_pattern(data: bytes, pattern: bytes) -> int:
    """Searches for a byte pattern in a byte array (pure Python mode)."""
    data_len = len(data)
    pattern_len = len(pattern)

    if data_len < pattern_len:
        return -1

    for i in range(data_len - pattern_len + 1):
        match = True
        for j in range(pattern_len):
            if pattern[j] != -1 and pattern[j] != data[i + j]:
                match = False
                break
        if match:
            return i

    return -1


@cython.locals(
    data_len=Py_ssize_t,
    pattern_len=Py_ssize_t,
    i=Py_ssize_t,
    j=Py_ssize_t,
    match=cython.bint,
)
@cython.returns(Py_ssize_t)
def search_pattern_memoryview(data, pattern) -> int:
    """Searches for a byte pattern using memoryviews (pure Python mode)."""
    data_len = len(data)
    pattern_len = len(pattern)
    data_view: cython.uchar[:] = data  # Type annotation, not assignment
    pattern_view: cython.uchar[:] = pattern

    if data_len < pattern_len:
        return -1

    for i in range(data_len - pattern_len + 1):
        match = True
        for j in range(pattern_len):
            if pattern_view[j] != -1 and pattern_view[j] != data_view[i + j]:
                match = False
                break
        if match:
            return i

    return -1


@cython.locals(
    data_len=Py_ssize_t,
    pattern_len=Py_ssize_t,
    i=Py_ssize_t,
    j=Py_ssize_t,
    match=cython.bint,
)
@cython.returns(Py_ssize_t)
def search_pattern_memoryview_int(data, pattern) -> int:
    """Searches for an int pattern using memoryviews (pure Python mode)."""
    data_len = len(data)
    pattern_len = len(pattern)
    data_view: cython.uchar[:] = data
    pattern_view: cython.int[:] = pattern  # int[:] for integer pattern

    if data_len < pattern_len:
        return -1

    for i in range(data_len - pattern_len + 1):
        match = True
        for j in range(pattern_len):
            if pattern_view[j] != -1 and pattern_view[j] != data_view[i + j]:
                match = False
                break
        if match:
            return i

    return -1

@cython.locals(
    data_len=Py_ssize_t,
    pattern_len=Py_ssize_t,
    i=Py_ssize_t,
    j=Py_ssize_t,
    shift=Py_ssize_t,
    bad_char_table=dict,
)
def search_pattern_boyer_moore_horspool(data: bytes, pattern: bytes) -> Py_ssize_t:
    """Searches for a byte pattern using Boyer-Moore-Horspool."""
    data_len = len(data)
    pattern_len = len(pattern)

    if data_len < pattern_len:
        return -1
    if pattern_len == 0:
        return 0

    # Preprocess: Build the bad character shift table.
    bad_char_table = {}
    for i in range(pattern_len - 1):  # All but the last character
        bad_char_table[pattern[i]] = pattern_len - 1 - i

    # Search
    i = 0
    while i <= data_len - pattern_len:
        j = pattern_len - 1
        while j >= 0 and (pattern[j] == -1 or pattern[j] == data[i + j]):
            j -= 1
        if j < 0:
            return i  # Match found

        # Shift based on the bad character rule.
        shift = bad_char_table.get(data[i + pattern_len - 1], pattern_len)
        i += shift

    return -1
    
@cython.locals(
    data_len=Py_ssize_t,
    pattern_len=Py_ssize_t,
    i=Py_ssize_t,
    j=Py_ssize_t,
    period=Py_ssize_t,
    memory=Py_ssize_t,
)
def search_pattern_two_way(data: bytes, pattern: bytes) -> Py_ssize_t:
    """Searches for a byte pattern using the Two-Way algorithm."""
    data_len = len(data)
    pattern_len = len(pattern)

    if data_len < pattern_len:
        return -1
    if pattern_len == 0:
        return 0

    # Preprocessing: Find the period and memory.
    period, memory = _find_period_and_memory(pattern)

    # Search
    i = 0
    memory = -1  # Initialize memory
    while i <= data_len - pattern_len:
        if memory < i:
            j = max(0, memory - i + 1)  # Start comparison after memory
            while j < pattern_len and (pattern[j] == -1 or pattern[j] == data[i + j]):
                j += 1
            if j == pattern_len:
                return i  # Match found
            if j <= period:
                i += period
                memory = i + j - period -1 # Update memory
            else:
                i += j - period
        else: #memory >= i
            j = pattern_len -1
            while j >= period and (pattern[j] == -1 or pattern[j] == data[i+j]):
                j -= 1
            if j < period:
                return i
            else:
                i += j - period + 1
                memory = i -1

    return -1

@cython.locals(period=Py_ssize_t, memory=Py_ssize_t, i=Py_ssize_t, j=Py_ssize_t)
def _find_period_and_memory(pattern: bytes) -> tuple[int, int]:
    """Finds the period and memory for the Two-Way algorithm."""
    n = len(pattern)
    period = 1
    memory = -1

    for p in range(1, n + 1):
        is_period = True
        for i in range(p, n):
            if pattern[i] != -1 and pattern[i - p] != -1 and pattern[i] != pattern[i - p]:
                is_period = False
                break
        if is_period:
            period = p
            break

    for m in range(n -1, -1, -1):
        is_memory = True
        for i in range(m + 1, n):
            if pattern[i] != -1 and pattern[i - (m+1)] != -1 and pattern[i] != pattern[i-(m+1)]:
                is_memory = False
                break
        if is_memory:
            memory = m
            break

    return period, memory    