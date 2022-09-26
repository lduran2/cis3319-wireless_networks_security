from crypto import needed_padding, bitize_int

def sha256(msg_bits: Iterable[int]) -> List[int]:
    """
    Performs SHA256 hashing on the given bytes.
    """
    # initial hash values used in sha256
    pass

def preprocess(msg_bits: Iterable[int]) -> List[int]:
    """
    Preprocess for SHA256.
    """
    # length of the original message
    L = len(msg_bits)
    # calculate padding n_pad so that (L + 1 + n_pad + 64) | 512
    # the 64-bits will store the length of the original message
    n_pad = needed_padding(L + 1 + 64, divisor=512)
    # create padding preceding with set bit
    padding = [0]*(n_pad + 1)
    padding[0] = 1
    # pad the message
    padded_message = (msg_bits + padding)
    # also append n-bits as 64-bits to the message
    bitize_int(padded_message, L, nbits=64)
    # return result
    return padded_message
# end def preprocess(msg_bits: Iterable[int])
