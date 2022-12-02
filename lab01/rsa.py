import random
from math import gcd
from collections import deque
from itertools import chain

DEBUG_MODE = True
DEBUG_MODE_CODEC_GRAPH = False
SEED_RANDOM = True
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

# number of rounds used for encoding
N_CODEC_ROUNDS = 18

def main():
    n, e, d = selectKey()
    ciphertext = encode(n, e, 'please help me now!')
    decode_block(n, d, ciphertext)

def encode(n: int, e: int, msg: str) -> str:
    quadragraphs = encode_block(n, e, msg)
    ciphertext = str.join('', chain.from_iterable(quadragraphs))
    if (DEBUG_MODE):
        print({'ciphertext': ciphertext})
    return ciphertext

def encode_block(n: int, e: int, block: str) -> str:
    # convert to upper case ASCII values
    upper_ords = ((ord(c) & ~ord_shift) for c in block)
    # filter out all non-letter characters, convert to letter code
    letter_codes = ((c - ordA) for c in upper_ords if c in rangeAZ)
    # convert to trigraphs
    trigraphs = splitModIndex(tuple(letter_codes), 3)
    # convert to trigraph codes
    trigraph_codes = (polysubs(tri, lenAZ) for tri in trigraphs)
    if (DEBUG_MODE):
        # make a tuple, so it can be reused
        trigraph_codes = tuple(trigraph_codes)
        print({'trigraphs': trigraph_codes})

    ciphertexts = (codec_multigraph(n, e, trigraph) for trigraph in trigraph_codes)
    if (DEBUG_MODE):
        # make a tuple, so it can be reused
        ciphertexts = tuple(ciphertexts)
        print({'ciphertexts': ciphertexts})

    quadragraphs = (polyunsubs(ciph, lenAZ, 4) for ciph in ciphertexts)
    quadragraph_chrs = ((chr(letter + ordA) for letter in quadragraph) for quadragraph in quadragraphs)

    return quadragraph_chrs

def decode_block(n: int, d: int, block: str):
    # split block into letter codes
    letter_codes = ((ord(c) - ordA) for c in block)
    # group into quads
    quadragraphs = splitModIndex(tuple(letter_codes), 4)
    # convert to quadgraph codes
    quadragraph_codes = (polysubs(quad, lenAZ) for quad in quadragraphs)
    plaintexts = (codec_multigraph(n, d, quadragraph) for quadragraph in quadragraph_codes)
    if (DEBUG_MODE):
        # make a tuple, so it can be reused
        plaintexts = tuple(plaintexts)
        print({'plaintexts': tuple(plaintexts)})

def codec_multigraph(n, e, multigraph):
    if (DEBUG_MODE):
        print({'n': n, 'e': e})
    # initialize quotient, dividend, [multigraph^KEY mod Modulus]
    Q = e
    dividend = multigraph
    ciphertext = 1
    # table for multigraph^Q mod Modulus
    # index is current LSbit of public key
    pow_multi_Q = [1, None]
    # calculate multigraph^Q mod Modulus
    for k in range(N_CODEC_ROUNDS):
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

def gen_coprimes(arr, ref):
    # yield each integer, k, in vector, arr, s.t. (1 == GCD(ref, k))
    for k in arr:
        if (1 == gcd(ref, k)):
            yield k

def gen_private_key_summand(PHI_n, e):
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

def splitModIndex(v, n):
    return zip(*(v[k::n] for k in range(n)))

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
        if (len(unpadded) > 0)
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

main()
