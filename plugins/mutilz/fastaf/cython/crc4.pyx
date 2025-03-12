# coding: utf-8
# cython: language_level=3, boundscheck=False, wraparound=False
import cython

from mutilz.fastaf.cython import cyfnv1a

@cython.locals(
    binary='unsigned char[::1]',   # 1D C-style array of unsigned chars
    key_state='unsigned char[::1]', 
    start_offset=cython.Py_ssize_t,   # Use Py_ssize_t for potentially large indices
    prev_key_state_offset=cython.int,
    i=cython.Py_ssize_t,              # Use Py_ssize_t here too
    curr_key_state_index=cython.int,
    binary_index=cython.Py_ssize_t,   # And here
    curr_key_state=cython.uchar,
    page_size=cython.int
)
@cython.boundscheck(False)   # Disable bounds checking for speed (be sure you're safe!)
@cython.wraparound(False)    # Disable negative index wrapping
def process(binary, start_offset,key_state, page_size: int = 0x1000):
    """
    Perform an RC4-like XOR operation on a single page in 'binary',
    starting at 'start_offset'. Uses 'key_state' as the RC4-like state array.

    :param binary:        Memoryview of the data buffer (e.g., a slice of a bytearray).
    :param start_offset:  The index in 'binary' where the page begins.
    :param key_state:     A 256-byte memoryview representing the RC4-like key state.
    """
    prev_key_state_offset = 0
    for i in range(page_size):
        curr_key_state_index = (i + 1) & 0xFF
        curr_key_state = key_state[curr_key_state_index]

        binary_index = start_offset + i
        # Bounds check in case the offset + page size goes beyond 'binary'
        if binary_index < binary.shape[0]:
            binary[binary_index] ^= curr_key_state

        prev_key_state_offset = (prev_key_state_offset + curr_key_state) & 0xFF

        # Swap in the key state
        key_state[curr_key_state_index], key_state[prev_key_state_offset] = (
            key_state[prev_key_state_offset],
            key_state[curr_key_state_index],
        )
         
@cython.locals(
    crypt_offset_base=cython.int,
    const1=cython.int,
    i=cython.int,
    j=cython.int,
    prev_key_state_offset=cython.int,
    curr=cython.int,
    key_material_index=cython.int
)
def initialize_key_state(crypt_key, const1: int, crypt_offset_base: int, page_hash: int):
    """
    Initialize and return the key state array as a 256-byte memoryview.
    
    :param crypt_key: A bytes-like object containing key data.
    :param const1:    A constant integer value.
    :param crypt_offset_base: An integer offset into crypt_key.
    :param page_hash: The current 64-bit page hash.
    :return: A memoryview of 256 unsigned chars representing the key state.
    """
    total_length = const1 + 0x100  # const1 + 256
    key_state_arr = bytearray(total_length)
    
    # Convert the page hash into 8 little-endian bytes.
    hash_bytes = page_hash.to_bytes(8, 'little')
    
    # Fill key_state[256:256+const1] with key material derived from crypt_key and the page hash.
    for i in range(const1):
        key_state_arr[0x100 + i] = crypt_key[crypt_offset_base + i] ^ hash_bytes[i & 7]
    
    # Initialize the first 256 bytes with values 0..255.
    for i in range(0x100):
        key_state_arr[i] = i

    prev_key_state_offset = 0
    for j in range(0x100):
        curr = key_state_arr[j]
        key_material_index = (j % const1) + 0x100
        prev_key_state_offset = (prev_key_state_offset + key_state_arr[key_material_index] + curr) & 0xFF
        # Swap the elements.
        key_state_arr[j], key_state_arr[prev_key_state_offset] = (
            key_state_arr[prev_key_state_offset],
            key_state_arr[j],
        )
    
    return key_state_arr

@cython.locals(
    binary='unsigned char[::1]',
    crypt_key='unsigned char[::1]',
    crypt_offset_base=cython.int,
    const1=cython.int,
    file_offset=cython.int,
    page_size=cython.int
)
def decrypt_page(binary, crypt_key, crypt_offset_base: int, start_offset: int,
                 const1: int, encrypt_mode: bool, page_hash: int, page_size: int) -> int:
    """
    Decrypt a page of data in-place.
    
    :param binary:      A memoryview (or bytearray) of the data buffer.
    :param crypt_key:   A memoryview (or bytes) containing key data.
    :param crypt_offset_base: Base offset into crypt_key.
    :param start_offset:  MemoryOffset.
    :param const1:      A constant integer value.
    :param encrypt_mode: Must be False for decryption; otherwise, an error is raised.
    :param page_hash:    The current 64-bit page hash.
    :return:            The updated page hash after processing.
    """
    if encrypt_mode:
        raise ValueError("Cannot decrypt when encryption mode is enabled.")

    key_state = bytearray(initialize_key_state(crypt_key, const1, crypt_offset_base, page_hash))
    process(binary, start_offset, key_state, page_size)
    # Update and return the page hash (assuming fnv1a returns a 64-bit integer).
    new_page_hash = cyfnv1a.fnv1a_hash(memoryview(binary[start_offset : start_offset + page_size]))
    return new_page_hash

@cython.locals(
    binary='unsigned char[::1]',
    crypt_key='unsigned char[::1]',
    file_offset=cython.int,
    memory_offset=cython.int,
    const1=cython.int,
    const2=cython.int,
    crypt_offset_base=cython.int,
    key_state='unsigned char[::1]',
    page_size=cython.int
)
def encrypt_page(binary, crypt_key, start_offset: int, const1: int, const2: int,
                 encrypt_mode: bool, page_hash: int, page_size: int) -> int:
    """
    Encrypt a page of data in-place.
    
    :param binary:      A memoryview (or bytearray) of the data buffer.
    :param crypt_key:   A memoryview (or bytes) containing key data.
    :param start_offset: MemoryOffset
    :param const1:      A constant integer value.
    :param const2:      A constant integer value.
    :param encrypt_mode: Must be True for encryption; otherwise, an error is raised.
    :param page_hash:    The current 64-bit page hash.
    :return:            The updated page hash after processing.
    """
    if not encrypt_mode:
        raise ValueError("Cannot encrypt when encryption mode is disabled.")

    memory_offset = start_offset
    crypt_offset_base = const1 * ((memory_offset // page_size) % const2)
    key_state = initialize_key_state(crypt_key, const1, crypt_offset_base, page_hash)
    new_page_hash =  cyfnv1a.fnv1a_hash(memoryview(binary[memory_offset : memory_offset + page_size]))
    process(binary, memory_offset, key_state, page_size)
    return new_page_hash
        