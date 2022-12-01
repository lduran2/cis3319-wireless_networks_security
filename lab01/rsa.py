import random
from math import gcd

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
    # print PHI(n), e, their gcd
    print(PHI_n, e, gcd(PHI_n, e))

def gen_with_CD(arr, ref):
    # yield each integer, k, in vector, arr, s.t. k has a common
    # denominator with the reference, ref
    for k in arr:
        if (1 != gcd(ref, k)):
            yield k

main()
