# coding: utf-8
# cython: language_level=3, boundscheck=False, wraparound=False
import cython
from cython import Py_ssize_t, uchar, ulonglong


@cython.locals(
    i=Py_ssize_t,
    n=Py_ssize_t,
    seed=ulonglong,
    prime=ulonglong,
    c=uchar,
    mask=ulonglong,
)
@cython.returns(ulonglong)
def fnv1a_hash(data: memoryview | bytes | bytearray) -> int:
    """Fowler-Noll-Vo hash function

    >>> fnv1a_hash(b'3ce6330f-ab86-45df-b2ff-b16cad4f24f1')
    872280216
    >>> fnv1a_hash(b'31eef3c2-42b8-4959-abd4-dc559aba7331')
    2859758067
    >>> fnv1a_hash(b'646f39fb-c3bb-440b-befc-9aa56559d131')
    3424154349
    >>> fnv1a_hash(b'3dc0be7a-30ca-452c-8cf0-19364f697a14')
    4099963837
    >>> fnv1a_hash(u'🦄🌈')
    1842577985
    >>> fnv1a_hash(u'🦄🌈'.encode('utf-8'))
    2868248295
    """
    seed = 0xCBF29CE484222325
    prime = 0x100000001B3
    mask = 0xFFFFFFFFFFFFFFFF
    for c in data:
        seed = (prime * (c ^ seed)) & mask
    return seed
