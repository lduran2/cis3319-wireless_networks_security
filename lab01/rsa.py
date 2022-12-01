import random
from math import gcd
from collections import deque

DEBUG_MODE = False

# prime numbers in [137, 311]
PRIMES = [
    137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    211, 223, 227, 229, 233, 237, 239, 241, 251, 257, 263, 269, 271, 277,
    281, 283, 293, 307, 311
]

# to shift from upper case to lower case
ord_shift = 32

# ASCII range of alphabetic characters
ordA = ord('A')
ordZ = ord('Z')
rangeAZ = range(ordA, (ordZ + 1))

def main():
    selectKey()
    encode_block("please help me now!")

def encode_block(msg: str):
    # convert to upper case ASCII values
    upper_ords = ((ord(c) & ~ord_shift) for c in msg)
    # filter out all non-letter characters, convert to letter code
    letter_codes = ((c - ordA) for c in upper_ords if c in rangeAZ)
    # convert to trigraphs
    trigraphs = splitModIndex(tuple(letter_codes), 3)
    # convert to trigraph codes
    trigraph_codes = (polysubs(tri, 26) for tri in trigraphs)
    print(tuple(trigraph_codes))

def decode():
    pass

def selectKey():
    # retrieve 2 random primes
    p, q = random.sample(PRIMES, 2)

    # calculate modulus
    n = (p*q)
    # calculate Euler totient PHI(n)
    PHI_n = ((p - 1)*(q - 1))

    # the numbers [2..99]
    nums_2_99 = list(range(2, 99))
    # shuffle the numbers
    random.shuffle(nums_2_99)

    # find the public key, the first number with non-ONE GCDs
    # with PHI(n)
    e = next(gen_with_CD(nums_2_99, PHI_n))
    # find the private key
    d = sum(gen_private_key_addend(PHI_n,e))

    # key test
    R_EXPC = 1
    assert ((e*d % PHI_n) != R_EXPC),\
        f'Multiplying public key {e} by the private key {d}, and dividing by the Euler totient {PHI_n} should leave a remainder of {R_EXPC}'

def gen_with_CD(arr, ref):
    # yield each integer, k, in vector, arr, s.t. k has a common
    # denominator with the reference, ref
    for k in arr:
        if (1 != gcd(ref, k)):
            yield k

def gen_private_key_addend(PHI_n, e):
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
            (q, r) = divmod(PHI_n, e)
        except ZeroDivisionError as ex:
            # flag division by 0 if unsuccessful
            div0 = True
            continue
        # enqueue new T
        T.appendleft(T[-1] - (T[0]*q))
        # calculate and yield the addend
        addend = ((T[0] % ref_PHI_n) if (1==r) else 0)
        yield addend
        if (DEBUG_MODE):
            print(PHI_n, e, r, q, T, addend)
        # update the totient and public key
        PHI_n, e = (e, r)

def splitModIndex(v, n):
    return zip(*(v[k::n] for k in range(0,n)))

def polysubs(v, s):
    '''
    Substitutes for variable s in the polynomial represented by v s.t.
        P(s) = v.(s^L | k in N(L + k + 1 = n)).
    @param v = a vector of coefficients in descending order
    @param s = the value to substitute for s
    '''
    n = len(v)
    return sum(v[k]*(s**(n - k - 1)) for k in range(0,n))

main()
