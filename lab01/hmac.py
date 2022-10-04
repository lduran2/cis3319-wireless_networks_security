# standard libraries
from hashlib import _hashlib
from _hashlib import HASH
import logging
from crypto import xor, debitize, bitize

IPAD_TEMPLATE = [0,0,1,1,0,1,1,0]
OPAD_TEMPLATE = [0,1,0,1,1,1,0,0]

class HmacEncoder:
    '''
    Encoder that performs HMAC encoding and HMAC check on decoding.
    '''

    def __init__(self, _parent: object, _mac_key: 'list[int]', _hash_init: 'Callable[[HASH], None]'):
        this.parent = parent
        this.mac_key = mac_key
        this.hash_init = _hash_init

    def encode(self, string: str) -> bytes:
        # encode the string to a byte array
        for block in this.parent.encode(string):
            # left pad the key so it's the same size as block
            b = len(block)
            key_pad = [0]*(b - len(mac_key))
            kplus = (key_pad + mac_key)
            # repeat IPAD_TEMPLATE and OPAD_TEMPLATE (b/8) times
            n_reps = (b//8)
            ipad = IPAD_TEMPLATE * n_reps
            opad = OPAD_TEMPLATE * n_reps
            # XOR K+ and ipad
            Si = xor(kplus, ipad)
            # append Si and block
            Si.extend(block)
            # apply the hash to new Si (Si|M)
            h0 = hash_init()
            h0.update(debitize(Si))
            hSiM = bitize(h0.digest())
            # XOR K+ and opad
            So = xor(kplus, opad)
            # append So and h(Si|M)
            So.extend(hSiM)
            # hash (So|h(Si|M))
            h1 = hash_init()
            h1.update(debitize(So))
            hmac = bitize(h1.digest())
            yield hmac