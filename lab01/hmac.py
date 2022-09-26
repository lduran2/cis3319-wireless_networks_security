from crypto import needed_padding, bitize_int

def sha256(msg_bits: Iterable[int]) -> List[int]:
    """
    Performs SHA256 hashing on the given bytes.
    """
    preproc_msg = preprocess(msg_bits)
    
    for k in range(0, len(padded_msg_bytes), 8):
    

def preprocess(msg_bits: Iterable[int]) -> List[int]:
    """
    Preprocess for SHA256.
    """
    # length of the original message
    len_msg = len(msg_bits)
    # calculate padding n_pad so that (len_msg + 1 + n_pad + 64) | 512
    # the 64-bits will store the length of the original message
    n_pad = needed_padding(len_msg + 1 + 64, divisor=512)
    # create padding preceding with set bit
    padding = [0]*(n_pad + 1)
    padding[0] = 1
    # pad the message
    padded_message = (msg_bits + padding)
    # also append n-bits as 64-bits to the message
    bitize_int(padded_message, len_msg, size=64)
    # return result
    return padded_message
# end def preprocess(msg_bits: Iterable[int])

def process_as_512(chunk512: Iterable[int]):
    # loop through 512-bit chunks
    for k in range(0, range(0, msg_bits, 512)):
        # create an array of 64 to fill with 32-bit word
        words = [None]*64
        # copy first 16 words from the chunk
        for k in range(16):
            words[k] = chunk512[(k << 5):((k + 1) << 5)]
    # next k