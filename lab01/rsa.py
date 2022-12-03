import random
from math import gcd
from collections import deque
from itertools import chain
import to_alpha

DEBUG_MODE = False
DEBUG_MODE_CODEC_GRAPH = False
SEED_RANDOM = False
if (SEED_RANDOM):
    random.seed(42)

# prime numbers in [137, 311]
PRIMES = [
    137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    211, 223, 227, 229, 233, 237, 239, 241, 251, 257, 263, 269, 271, 277,
    281, 283, 293, 307, 311
]

# expected remainder of key test
R_EXPC = 1

# to shift from upper case to lower case
ord_shift = 32

# ASCII range of alphabetic characters
ordA = ord('A')
ordZ = ord('Z')
rangeAZ = range(ordA, (ordZ + 1))
lenAZ = len(rangeAZ)

# size of input multigraphs w.r.t. encoding
INGRAPH_LEN = 3
# number of input multigraphs in each block
BLOCK_SIZE = 5
# size of output multigraphs w.r.t. encoding
OUTGRAPH_LEN = 4

# prepadding sequence, ZQKGZ, or character# 256
PAD_PREFIX = (90, 81, 75, 71, 90)
# the ending of the padding to complete block size
PAD_ENDING = tuple(range(ordA, (ordA + (BLOCK_SIZE*INGRAPH_LEN))))

# number of rounds used for encoding
N_CODEC_ROUNDS = 18

def main():
    # select the key
    n, e, d = selectKey()
    msg = ''
    # REPL loop until exit() given
    while True:
        msg = input('rsa> ')
        if ('exit()'==msg):
            break
        print({'original message': msg})
        # test encoding
        ciphertext = encode(n, e, msg)
        print({'ciphertext': ciphertext})
        # test decoding
        plaintext = decode(n, d, ciphertext)
        print({'plaintext': plaintext})

def encode(n: int, e: int, msg: str) -> str:
    if (DEBUG_MODE):
        print()
        print('encode:')
    # convert the mesage to ordinals
    msg_ords = str2ords(msg)
    # encode the message to alphabetic
    alpha_msg = tuple(to_alpha.ords2alpha(msg_ords))
    # pad the message as necessary
    pad_alpha_msg = pad_block_msg(alpha_msg)
    if (DEBUG_MODE):
        print({'padded message in alpha': ords2str(pad_alpha_msg), 'len': len(pad_alpha_msg)})
    # split message into blocks
    msg_blocks = splitModIndex(pad_alpha_msg, (BLOCK_SIZE*INGRAPH_LEN))

    # stores incoming output multigraphs
    outgraphs_acc = []
    for msg_block in msg_blocks:
        # encode the current block
        outgraphs = codec_block(n, e, msg_block, INGRAPH_LEN, OUTGRAPH_LEN)
        # convert to ASCII strings
        outgraph_chrs = ords2str(outgraphs)
        # accumulate the output
        outgraphs_acc.extend(outgraph_chrs)
    # join the output into a string and return it
    ciphertext = str.join('', outgraphs_acc)
    return ciphertext

def decode(n: int, d: int, msg: str) -> str:
    if (DEBUG_MODE):
        print()
        print('decode:')
    # convert to ordinals
    msg_ords = str2ords(msg)
    # perform the decoding on the blocks
    outgraphs = tuple(codec_block(n, d, msg_ords, OUTGRAPH_LEN, INGRAPH_LEN))
    if (DEBUG_MODE):
        print({'outgraphs from decode block': outgraphs})
    # if there is an ending sequence, look for it and terminate the message there
    try:
        i_terminate = tupleindex(outgraphs, PAD_PREFIX)
        outgraphs = outgraphs[:i_terminate]
        if (DEBUG_MODE):
            print({'outgraphs after terminate': outgraphs})
    except ValueError as e:
        pass
    # convert from alpha to ords
    plaintext_ords = (to_alpha.alpha2ords(outgraphs))
    # join the output into a string and return it
    plaintext_str = ords2str(plaintext_ords)
    return plaintext_str

def codec_block(n: int, k: int, block, ingraph_len, outgraph_len) -> str:
    # split block into letter codes
    letter_codes = tuple((c - ordA) for c in block)
    # convert to ingraphs
    ingraphs = splitModIndex(letter_codes, ingraph_len)
    # convert to ingraph codes
    ingraph_codes = (polysubs(ingraph, lenAZ) for ingraph in ingraphs)
    if (DEBUG_MODE):
        # make a tuple, so it can be reused
        ingraph_codes = tuple(ingraph_codes)
        print({'ingraphs': ingraph_codes})

    ciphertexts = (codec_multigraph(n, k, ingraph) for ingraph in ingraph_codes)
    if (DEBUG_MODE):
        # make a tuple, so it can be reused
        ciphertexts = tuple(ciphertexts)
        print({'ciphertexts': ciphertexts})

    outgraphs = (polyunsubs(ciph, lenAZ, outgraph_len) for ciph in ciphertexts)

    outgraph_ords = (((letter + ordA) for letter in outgraph) for outgraph in outgraphs)
    if (DEBUG_MODE):
        # make a tuple, so it can be reused
        outgraph_ords = tuple(tuple(o) for o in outgraph_ords)
        print({'outgraph_ords': outgraph_ords})

    # flaten the tuple
    outgraphs_flat = chain.from_iterable(outgraph_ords)

    return outgraphs_flat

def codec_multigraph(n: int, k: int, multigraph: int) -> int:
    if (DEBUG_MODE):
        print({'n': n, 'k': k})
    # initialize quotient, dividend, [multigraph^KEY mod Modulus]
    Q = k
    dividend = multigraph
    ciphertext = 1
    # table for multigraph^Q mod Modulus
    # index is current LSbit of public key
    pow_multi_Q = [1, None]
    # calculate multigraph^Q mod Modulus
    for L in range(N_CODEC_ROUNDS):
        # quotient mod 2, or bit #0 of Q
        Q0 = (Q & 1)
        # multigraph^Q mod Modulus
        _, pow_multi_Q[1] = divmod(dividend, n)
        # the ciphertext = (multigraph^KEY mod Modulus)
        _, ciphertext = divmod((ciphertext * pow_multi_Q[Q0]), n)
        # update quotient, dividend
        Q = (Q >> 1)
        dividend = (pow_multi_Q[1]*pow_multi_Q[1])
        if (DEBUG_MODE_CODEC_GRAPH):
            print({'Q': Q, 'pow_multi_Q': pow_multi_Q, 'ciphertext': ciphertext})
    return ciphertext

def selectKey():
    # retrieve 2 random primes
    p, q = random.sample(PRIMES, 2)
    if (DEBUG_MODE):
        print({'p': p})
        print({'q': q})

    # calculate modulus
    n = (p*q)
    # calculate Euler totient PHI(n)
    PHI_n = ((p - 1)*(q - 1))

    # candidates for e in [2..99]
    e_candidates = list(range(2, 99))
    # shuffle the candidates
    random.shuffle(e_candidates)

    # find the public key, the first number with GCD = 1
    # with PHI(n)
    e = next(gen_coprimes(e_candidates, PHI_n))
    # find the private key
    d = sum(gen_private_key_summand(PHI_n, e))
    if (DEBUG_MODE):
        print({'e': e, 'd': d})

    # key test
    _, r_calc = divmod((e*d), PHI_n)
    assert (r_calc == R_EXPC),\
        (
            f'Multiplying public key {e} by the private key {d}, and'
            f' dividing by the Euler totient {PHI_n} should leave a'
            f' remainder of {R_EXPC}, but is {r_calc}.'
        )

    return (n, e, d)

def pad_block_msg(block_msg):
    # to pad the message, we add the sequence ZQKGZ for
    # "character# 256" to mark the end of the string
    # Since Latin-1 extended ASCII has 256 characters, this frees
    # characters# [256..(25^2)[.
    # After ZQKGZ as many letters are added until 'O', letter# 15.

    # get the length of message, and its modulus
    msg_len = len(block_msg)
    _, r = divmod(msg_len, (BLOCK_SIZE*INGRAPH_LEN))
    # if already 0, then no need to pad
    if (0==r):
        return block_msg

    # add the sequence to mark the end of the string
    padded = (block_msg + PAD_PREFIX)

    # update the modulus
    msg_len = len(padded)
    _, r = divmod(msg_len, (BLOCK_SIZE*INGRAPH_LEN))
    # add the padding endding
    padded = (padded + PAD_ENDING[r:])

    return padded

def gen_coprimes(arr, ref: int) -> int:
    # yield each integer, k, in vector, arr, s.t. (1 == GCD(ref, k))
    for k in arr:
        if (1 == gcd(ref, k)):
            yield k

def gen_private_key_summand(PHI_n: int, e: int) -> int:
    # reference original PHI_n
    ref_PHI_n = PHI_n
    # no division by 0 yet
    div0 = False
    # create deque of last 2 T-values
    T_tuple = (1, 0)
    T = deque(T_tuple, len(T_tuple))
    # loop until division by 0
    while (not(div0)):
        # try dividing
        try:
            q, r = divmod(PHI_n, e)
        except ZeroDivisionError as ex:
            # flag division by 0 if unsuccessful
            div0 = True
            continue
        # slice T-values
        v = (T[k] for k in range(2))
        # T coefficients
        m = (-q, 1)
        # calculate and enqueue new T
        T.appendleft(vdot(v, m))
        # calculate and yield the summand
        summand = (divmod(T[0], ref_PHI_n)[1] if (1==r) else 0)
        yield summand
        if (DEBUG_MODE):
            print({'PHI_n': PHI_n, 'e': e, 'r': r, 'q': q, 'T': T, 'summand': summand})
        # update the totient and public key
        PHI_n, e = (e, r)

def str2ords(string):
    return (ord(c) for c in string)

def ords2str(ords):
    return str.join('', (chr(o) for o in ords))

def splitModIndex(v, n):
    return (v[k:(k + n)] for k in range(0, len(v), n))

def polysubs(v, s):
    '''
    Substitutes for variable, s, in the polynomial represented by v,
    s.t.
        P(s) = v.(s^L | k in N(L + k + 1 = n)).
    @param v = a vector of coefficients in descending order
    @param s = the value to substitute for s
    '''
    return vdot(v, ((s**k) for k in reversed(range(len(v))) ))

def vdot(v, u):
    '''
    Multiplies vectors, v, and u.
    '''
    return sum((z[0]*z[1]) for z in zip(v, u))

def polyunsubs(total, s, min_coefs=0):
    '''
    Finds the tuple of the coefficients representing the polynomial on
    s for which substituting for s, s.t.
        P(s) = v.(s^L | k in N(L + k + 1 = n))
    will give the given total.
    @param total = value of P(s)
    @param s = the value to substitute for s
    @param min_coefs = minimum number of coefficients
    '''
    unpadded = tuple(reversed(tuple(genpolyunsubs(total, s))))
    n_pad = (min_coefs - len(unpadded))
    return ((((0,)*n_pad) + unpadded)
        if (n_pad > 0)
        else unpadded)

def genpolyunsubs(total, s):
    '''
    Finds the coefficients giving the specified total for a polynomial
    on s when substituting for s, s.t.
        P(s) = v.(s^L | k in N(L + k + 1 = n))
    in ascending order.
    @param total = value of P(s)
    @param s = the value to substitute for s
    '''
    # initialize quotient and remainder
    q, r = (total, 0)
    # while non-ZERO quotient
    while (q):
        # repeated division
        q, r = divmod(q, s)
        yield r

def tupleindex(a_tuple, subtuple):
    '''
    Searches for the given subtuple in the tuple given by a_tuple.
    '''
    sublen = len(subtuple)
    for k in range(len(a_tuple) - sublen + 1):
        if (a_tuple[k:(k + sublen)]==subtuple):
            return k
    raise ValueError('subtuple not found')

# run the REPL test
if __name__ == '__main__':
    main()
# end if __name__ == '__main__'

