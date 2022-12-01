import random
from math import gcd
from collections import deque

def main():
    # prime numbers in [137, 311]
    PRIMES = [
        137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
        211, 223, 227, 229, 233, 237, 239, 241, 251, 257, 263, 269, 271, 277,
        281, 283, 293, 307, 311
    ]

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
        print(PHI_n, e, r, q, T, addend)
        # update the totient and public key
        PHI_n, e = (e, r)

main()
