
from copy import deepcopy
import random
from typing import Iterable

DEBUG_MODE = False

class KeyManager:
    @staticmethod
    def read_key(key_file: str) -> bytes:
        with open(key_file, 'rb') as f:
            return f.read()
    
    @staticmethod
    def save_key(key_file: str, key: bytes):
        with open(key_file, 'wb') as f:
            f.write(key)

    def __init__(self, seed=None):
        self.random = random.Random(seed)
    
    def generate_key(self, key_len=256) -> bytes:
        """"
        Generate a random key of length key_len (bit length).
        return: random bytes of length (key_len // 8)
        """
        # TODO: your code here
        rand_bytes = bytes() # just a placeholder

        return rand_bytes


def bitize(byts: bytes) -> 'list[int]':
    """
    bitize bytes
    """
    bits = []

    # TODO: your code here

    # for each byt
    for byt in byts:
        # loop through the bits
        for i in range(8,0,-1):
            # pop off less significant bits
            shift = (byt >> (i - 1))
            # store the new least significant bit
            bits.append(shift & 1)
        # end for i in range(8,0,-1)
    # end for byt in byts

    return bits

def debitize(bits: Iterable[int]) -> bytes:
    """
    debbitize a list of bits
    """
    # TODO: your code here
    quo, rem = divmod(len(bits), 8)
    if rem != 0:
        raise ValueError('bits length is not a multiple of 8')

    byts = [sum(b*2**(7-i) for (i, b) in enumerate(bits[8*k : 8*(k+1)])) for k in range(0, quo)]

    # make sure to return as bytes, rather than list[int]
    return bytes(byts)

def bit2hex(bits: Iterable[int]) -> str:
    """
    convert bits to hex string
    """
    return debitize(bits).hex()

def hex2bit(hex_str: str) -> list:
    """
    convert hex string to bits
    """
    return bitize(bytes.fromhex(hex_str))

def permute(raw_seq: Iterable, table: Iterable[int], n: int = None, m: int = None) -> list[int]:
    """
    permute bits with a table
    @param raw_seq: Iterable = block before permutation
    @param table: Iterable[int] =
        table of indices to use in permutation
    @param n: int = size of  input block (default len(raw_seq))
    @param m: int = size of output block (default len(table))
    """
    # TODO: your code here
    # set defaults
    if (n is None):
        n = len(raw_seq)
    if (m is None):
        m = len(table)

    # use indices in table as indices for raw_seq
    # e.g. permuteBlock = permute(n=64, m=56, raw_seq=key, table=KEY_DROP)
    sliced_seq = raw_seq[:n]
    if (DEBUG_MODE):
        print('expected length:', n)
        print('actual length:', len(sliced_seq))
    permutation = [sliced_seq[k] for k in table]
    return permutation[:m]
# end def permute(n: int, m: int, raw_seq: Iterable, table: Iterable[int])

def xor(bits1: Iterable[int], bits2: Iterable[int]) -> 'list[int]':
    """
    xor two bits
    """
    # TODO: your code here
    return [ (b1^b2) for b1, b2 in zip(bits1, bits2)]

def split(n: int, m: int, inBlockN: 'list[int]') -> 'tuple(list[int])':
    '''
    Splits block inBlockN of size n into leftmost and rightmost
    blocks of size m.
    @param n: int = size of original block
    @param m: int = size of split blocks
    @param inBlockN: list[list[int]] = block to split
    @return `tuple(list[list[int]])` representing split leftmost
    and rightmost blocks of size m
    '''
    return (
        inBlockN[:m],
        inBlockN[m:]
    )
# end def split(n: int, m: int, inBlockN: 'list[list[int]]')

def shiftLeft(n: int, blockN : 'list[int]', numOfShifts: int):
    '''
    Performs `numOfShifts` left shifts on each block of size n.
    @param n: int = size of block
    @param blockN: list[list[int]] = block to shift
    @param numOfShifts: int = number of left shifts to perform
    '''
    return (blockN[numOfShifts:n] + blockN[:numOfShifts])
# end def shiftLeft(n: int, blockN : 'list[list[int]]', numOfShifts: int)

def combine(n: int, m: int, leftBlockN: 'list[int]', rightBlockN: 'list[int]') -> 'list[int]':
    '''
    Combines leftBlockN and rightBlockN of size n into a block of size 
    blocks of size m.
    @param n: int = size of original blocks
    @param m: int = size of combined block
    @param leftBlockN: list[list[int]] = left half to combine
    @param rightBlockN: list[list[int]] = right half to combine
    @return `list[list[int]]` representing join of leftBlockN and rightBlockN
    '''
    return (leftBlockN[:n] + rightBlockN[:n])[:m]
# end def combine(n: int, m: int, leftKeyN: 'list[list[int]]', rightKeyN: 'list[list[int]]')

def needed_padding(i: int, divisor=8):
    '''
    Calculates the amount of padding needed to complete a multiple of
    the divisor.
    '''
    return ((-i) % divisor)
# end def needed_padding(i: int, divisor=8)

class DES:

    # initial permutation
    # reminder that Chapter 6 explanation is 1-indexed
    # whereas python is 0-indexed
    IP = [
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8, 0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]

    # final permutation
    FP = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    # parity-bit drop table for key schedule
    KEY_DROP = [
        56, 48, 40, 32, 24, 16, 8, 0,
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 60, 52, 44, 36,
        28, 20, 12, 4, 27, 19, 11, 3
    ]

    # this is the ShiftTable in the algorithm
    BIT_SHIFT = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

    # key compression permutation
    KEY_COMPRESSION = [
        13, 16, 10, 23, 0, 4, 2, 27,
        14, 5, 20, 9, 22, 18, 11, 3,
        25, 7, 15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54, 29, 39,
        50, 44, 32, 47, 43, 48, 38, 55,
        33, 52, 45, 41, 49, 35, 28, 31
    ]
    
    # D box, key expansion permutation
    D_EXPANSION = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16, 
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28, 
        27, 28, 29, 30, 31, 0
    ]
    
    # S boxes
    S1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]

    S2 = [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ]

    S3 = [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ]

    S4 = [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ]

    S5 = [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ]

    S6 = [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ]

    S7 = [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ]

    S8 = [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    
    # S-box substitution
    S = [S1, S2, S3, S4, S5, S6, S7, S8]
    
    # D box, straight permutation
    D_STRAIGHT = [
        15, 6, 19, 20, 28, 11, 27, 16,
        0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]

    @staticmethod
    def key_generation(key: 'list[int]', ShiftTable16=BIT_SHIFT) -> 'list[list[int]]':
        """
        raw_key: 64 bits
        return: 16 * (48bits key)
        """

        n = 64
        dropN = n*7//8
        # split from the parity DROPPED key
        splitN = dropN//2

        cipherKey = permute(n=n, m=dropN, raw_seq=key, table=DES.KEY_DROP)
        leftKey, rightKey = split(n=dropN, m=splitN, inBlockN=cipherKey)

        if (DEBUG_MODE):
            print('cipherKey: ', bit2hex(cipherKey))
            leftKeyPad = ([0] * needed_padding(len(leftKey)))
            rightKeyPad = ([0] * needed_padding(len(rightKey)))
            print(f'[{bit2hex(leftKeyPad + leftKey)}, {bit2hex(rightKeyPad + rightKey)}]')

        RoundKeys16x48 = [None] * 16

        for i_round in range(0, 16):
            # perform shifts
            leftKey = shiftLeft(n=splitN, blockN=leftKey, numOfShifts=ShiftTable16[i_round])
            rightKey = shiftLeft(n=splitN, blockN=rightKey, numOfShifts=ShiftTable16[i_round])
            # combine and permute
            preRoundKey = combine(n=splitN, m=dropN, leftBlockN=leftKey, rightBlockN=rightKey)
            RoundKeys16x48[i_round] = permute(n=dropN, m=48, raw_seq=preRoundKey, table=DES.KEY_COMPRESSION)

            # print the RoundKey generated if in debug mode
            if (DEBUG_MODE):
                leftKeyPad = ([0] * needed_padding(len(leftKey)))
                rightKeyPad = ([0] * needed_padding(len(rightKey)))
                print(f'round #{i_round}: ', end='')
                print(f'[{bit2hex(leftKeyPad + leftKey)}, {bit2hex(rightKeyPad + rightKey)}]')
                print(f'key_generation  preround #{i_round}: ', bit2hex(preRoundKey))
                print(f'key_generation postround #{i_round}: ', bit2hex(RoundKeys16x48[i_round]))
        return RoundKeys16x48

    # bits input into S-box
    S_IP_BITS = 6
    # rows in S-boxes are defined by bits R[[0,-1]]
    II_ROW_BITS = [0, (S_IP_BITS-1)]
    # padding for rows
    I_ROW_PAD = [0]*(8 - len(II_ROW_BITS))
    # columns in S-boxes are defined by bits R[1:-1]
    II_COL_BITS = range(1,II_ROW_BITS[1])
    # padding for columns
    I_COL_PAD = [0]*(8 - len(II_COL_BITS))

    @staticmethod
    def f(R: 'list[int]', key: 'list[int]') -> 'list[int]':
        """
        The heart of DES[,] the DES function (Mal-Sarkar & Yu, 2015).
        f function
        R: 32 bits = right block
        key: 48 bits
        return: 32 bits
        """
        # TODO: your code here

        N = 32
        N_EXPAND = 48

        # expand the right block with the expansion D-box
        expanded_R = permute(n=N, m=N_EXPAND, raw_seq=R, table=DES.D_EXPANSION)
        # whiten expanded_R by XORing with the key
        white_R = xor(expanded_R, key)

        if (DEBUG_MODE):
            print('whitened R: ', bit2hex(white_R))

        # use S-boxes to perform actual "mixing"
        # this creates confusion

        # allocate space for S-mixed R
        # the values in S-boxes are nibbles, not bits
        n_S = len(DES.S)
        S_R_nibbles = [0] * n_S

        # R is then divided into 8, 6-bit chunks
        for i_S, k in enumerate(range(0, N_EXPAND, DES.S_IP_BITS)):
            # get the next 6-bit chunk
            R_6bit = white_R[k:(k + DES.S_IP_BITS)]
            # extract row and column bits
            i_row_bits = [R_6bit[ii] for ii in DES.II_ROW_BITS]
            i_col_bits = [R_6bit[ii] for ii in DES.II_COL_BITS]
            # convert row and col from bits
            i_row = debitize(DES.I_ROW_PAD + i_row_bits)[0]
            i_col = debitize(DES.I_COL_PAD + i_col_bits)[0]
            # store the 4-bit value from next S-box from R_6bit
            # the S-box contains nibbles (or hexadecimal digits)
            S_R_nibbles[i_S] = DES.S[i_S][i_row][i_col]
            if (DEBUG_MODE):
                print(f'({i_row},{i_col})')
                print(f'S-mixed R [nibbles] #{i_S}:', S_R_nibbles[i_S])
        # next k

        # convert nibbles pairs to bytes
        S_R_bytes = [((S_R_nibbles[k]*16) + S_R_nibbles[k|1]) for k in range(0, n_S, 2)]
        # bitize S_R again
        S_R_bits = bitize(S_R_bytes)

        # perform the straight permutation
        # S-mixed R is now the original size
        R_out = permute(n=N, m=N, raw_seq=S_R_bits, table=DES.D_STRAIGHT)

        if (DEBUG_MODE):
            print('S-mixed R [bytes]:', S_R_bytes)
            print('S-mixed R [bits]: ', bit2hex(S_R_bits))
            print('R_out: ', bit2hex(R_out))

        return R_out

    @staticmethod  
    def mixer(L: 'list[int]', R: 'list[int]', sub_key: 'list[int]') -> 'tuple[list[int]]':
        """
        right_half: 32 bits
        sub_key: 48 bits
        return: 32 bits
        """
        # TODO: your code here
        # tips: finish f and xor first, then use them here

        return (L, R) # just a placeholder
    
    @staticmethod
    def swapper(L: 'list[int]', R: 'list[int]') -> 'tuple[list[int]]':
        """
        A free function for you, LMAO ^O^
        """
        return R, L

    def __init__(self, raw_key: bytes) -> None:
        # for encryption use
        self.keys = DES.key_generation(key=bitize(raw_key))
        
        # for decryption use
        self.reverse_keys = deepcopy(self.keys)
        self.reverse_keys.reverse()

    def enc_block(self, block: 'list[int]') -> 'list[int]':
        """
        Encrypt a block of 64 bits (8 bytes).
        block: 64 bits.
        return: 64 bits.
        """
        return self.cry_block(block, self.keys)

    def dec_block(self, block: 'list[int]') -> 'list[int]':
        """
        similar to enc_block
        block: 64 bits
        return: 64 bits
        """
        # TODO: your code here
        return self.cry_block(block, self.reverse_keys)

    def cry_block(self, block: 'list[int]', keys) -> 'list[int]':
        """
        Encrypt/decrypt a block of 64 bits (8 bytes).
        block: 64 bits.
        return: 64 bits.
        """
        N_ROUNDS = 16
        N = 64
        HALF_N = N//2

        # apply initial permutation
        block_IP = permute(n=N, m=N, raw_seq=block, table=DES.IP)
        # split the block into left and right blocks
        leftBlock, rightBlock = split(n=N, m=HALF_N, inBlockN=block_IP)

        # perform rounds
        for k in range(N_ROUNDS):
            # mixer mixes f(R, K) into L
            f_R_key = DES.f(rightBlock, keys[k])
            # swapper swaps L, R
            leftBlock, rightBlock = (rightBlock, xor(leftBlock, f_R_key))
        # next k

        # reverse the last swap
        leftBlock, rightBlock = rightBlock, leftBlock
        # recombine after rounds
        rounds_result = combine(n=HALF_N, m=N, leftBlockN=leftBlock, rightBlockN=rightBlock)

        block_FP = permute(n=N, m=N, raw_seq=rounds_result, table=DES.FP)

        if (DEBUG_MODE):
            print("Before IP:", ''.join(str(i) for i in block))
            print("After  IP:", ''.join(str(i) for i in block_IP))
            print("After  FP:", ''.join(str(i) for i in block_FP))
        # end if (DEBUG_MODE)

        return block_FP
    # end def cry_block(self, block: 'list[int]', keys)

    def encrypt(self, msg_str: str, encoding: str='utf-8') -> bytes:
        """
        Encrypt the whole message.
        Handle block division here.
        *Inputs are guaranteed to have a length divisible by 8.
        """
        # TODO: your code here
        # convert message to bytes
        msg_bytes = msg_str.encode(encoding)
        # encrypt these bytes, giving cypher
        cypher = self.encrypt_bytes(msg_bytes)
        return cypher
    
    def decrypt(self, cip_bytes: bytes, encoding: str='utf-8') -> str:
        """
        Decrypt the whole message.
        Similar to encrypt.
        """
        # decrypt bytes, giving plaintext bytes
        plaintext_bytes = self.decrypt_bytes(cip_bytes)
        # convert to string
        plaintext_string = plaintext_bytes.decode(encoding)
        return plaintext_string

    def encrypt_bytes(self, msg_bytes: bytes) -> bytes:
        """
        Encrypt the whole message bytes.
        """
        # encrypt these bytes, giving cypher
        cypher = self.crypt_bytes(msg_bytes, self.enc_block)
        return cypher
    
    def decrypt_bytes(self, cip_bytes: bytes) -> bytes:
        """
        Decrypt the whole message, keeping it as bytes.
        """
        # decrypt bytes, giving plaintext bytes
        plaintext_bytes = self.crypt_bytes(cip_bytes, self.dec_block)
        return plaintext_bytes

    def crypt_bytes(self, msg_bytes: bytes, callback: 'Callable[[DES, list[int]], list[int]]') -> bytes:
        """
        Transforms the bit blocks in msg_bytes, using callback, and
        convert back to bytes. 
        Handle block division here.
        *Inputs are guaranteed to have a length divisible by 8.
        """
        # pad if number of bytes if needed
        msg_bytes_pad = bytearray(needed_padding(len(msg_bytes)))
        padded_msg_bytes = msg_bytes + msg_bytes_pad
        if (DEBUG_MODE):
            print('original length:', len(msg_bytes))
            print('padding created:', len(msg_bytes_pad))
            print('new length:', len(padded_msg_bytes))
        # initialize the bits of the bytes to return
        cry_all_bits = []
        # loop through each 8-byte segment (64-bit block), encrypting it
        for k in range(0, len(padded_msg_bytes), 8):
            # get the segment
            msg_block = padded_msg_bytes[k:(k + 8)]
            # convert to bits
            msg_bits = bitize(msg_block)
            # encrypt the bits
            cry_bits = callback(msg_bits)
            # append to bits to return
            cry_all_bits.extend(cry_bits)
        # next k
        # convert back to bytes
        cry_all_bytes = bytes(debitize(cry_all_bits))
        return cry_all_bytes
    
