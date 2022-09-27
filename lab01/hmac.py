from typing import Iterable
from functools import reduce
from copy import deepcopy
from crypto import needed_padding, bitize_int, shiftLeft

# offset and shifts for each shift sum (2) for extend_words
EXTEND_OFFSET_SHIFTS = (
    (15, ( 7, 18,  3)),
    ( 2, (17, 19, 10))
)

# offset and shifts for each shift sum (2) for compress_work_arr
COMPRESS_OFFSET_SHIFTS = (
    ( 0, ( 2, 13, 22)),
    ( 4, ( 6, 11, 25))
)

# array of round constants
# with the first 32 fractional bits of the cube roots of the
# first 64 primes (SHA-2, 2022).
ROUND_CONSTS = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)

def sha256(msg_bits: Iterable[int]) -> list[int]:
    """
    Performs SHA256 hashing on the given bytes.
    """
    # initialize the hashes
    # with the first 32 fractional bits of the square roots of the
    # first 8 primes (SHA-2, 2022).
    hashes = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )
    preproc_msg = preprocess(msg_bits)
    # loop through 512-bit chunks
    for k in range(0, len(preproc_msg), 512):
        process_chunk512(hashes, preproc_msg[k:(k + 512)])
    # next k
    # append all hashes together to make the digest
# end def sha256(msg_bits: Iterable[int])

def preprocess(msg_bits: Iterable[int]) -> list[int]:
    """
    Preprocess for SHA256.
    """
    # length of the original message
    len_msg = len(msg_bits)
    # calculate padding n_pad so that ((len_msg + 1 + n_pad + 64) | 512).
    # The 64-bits will store the length of the original message
    n_pad = needed_padding(len_msg + 1 + 64, divisor=512)
    # create padding preceding with set bit
    padding = ([0]*(n_pad + 1))
    padding[0] = 1
    # pad the message
    padded_message = (msg_bits + padding)
    # also append n-bits as 64-bits to the message
    bitize_int(padded_message, len_msg, size=64)
    # return result
    return padded_message
# end def preprocess(msg_bits: Iterable[int])

def process_chunk512(hashes: list[int], chunk512: Iterable[int]):
    # create an array of 64 to fill with 32-bit word
    words = [None]*64
    # copy first 16 words from the chunk
    for k in range(16):
        words[k] = chunk512[(k << 5):((k + 1) << 5)]
    # next k
    # extend the word array
    extend_words(words)
    # copy the hash values into working array
    work_arr = deepcopy(hashes)
    # compress the words of the chunk into the working array
    compress_work_arr(work_arr, words)
    # add the compressed chunks into the hash
    hashes = (h + work for (h, work) in zip(hashes, work_arr))
    return hashes
# end def process_as_512(hashes: list[int], chunk512: Iterable[int])

def extend_words(words: list[list[int]]):
    """
    Extends a list of words using sums of rotation shifts.
    """
    for k in range(16, 64):
        # calculate the shift sums
        shift_sum = (
            reduce(xor, 
                (shiftLeft(32, words[k - off], -shift) for shift in shifts)
            ) for (off, shifts) in EXTEND_OFFSET_SHIFTS
        )
        # add them arithmetically with earlier words for new words
        words[k] = (words[k - 16] + words[i - 7] + sum(shift_sum))
    # next k
# end def extend_words(words: list[list[int]])

def compress_work_arr(work_arr, words):
    for (word, ROUND_CONST) in zip(words, ROUND_CONSTS):
        # working array elements to AND together for maj
        maj_andends = ((0, 1), (0, 2), (1, 2))
        # calculate Shift sum, ch, maj
        Shift_sum = (
            reduce(xor,
                (shift_int(work_arr[off], right=shift) for shift in shifts)
            ) for (off, shifts) in offset_shifts
        )
        ch = ((work_arr[4] & work_arr[5]) ^ ((~work_arr[4]) & work_arr[6]))
        maj = reduce((lambda P, Q: P^Q),
            ((work_arr[k] & work_arr[L]) for (k, L) in maj_andends)
        )
        # debitize the current word_int
        word_int = debitize_int(word)
        # calculate temp values
        tmp = (
            (work_arr[7] + Shift_sum[1] + ch + ROUND_CONST + word_int),
            (Shift_sum[0] + maj)
        )
        # update working array
        work_arr.insert(0, sum(tmp))
        work_arr[4] += tmp[0]
    # next (word, ROUND_CONST)
    # pop off extra work array elements
    del work_arr[8:]
# end def compress_work_arr(work_arr, words)

def shift_int(shiftend: int, size:int = 32,
              left: int=None, right: int=None
):
    # handle defaults
    # use 0 for both if both None
    # otherwise, use (left + right = size)
    if (left==None):
        if (right== None):
            return shift_int(shiftend, size, 0, 0)
        return shift_int(shiftend, size, (size - right), right)
    if (right==None):
        return shift_int(shiftend, size, left, (size - left))
    # calculate the shift
    return (((shiftend << left) & ((1 << size) - 1)) | (shiftend >> right))

#
# References:
#
# SHA-2 (2022). Wikipedia: The free encyclopedia. Wikimedia Foundation,
#       Inc. Retrieved from https://en.wikipedia.org/wiki/SHA-2
#
