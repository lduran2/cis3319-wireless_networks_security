from hashlib import sha256

class SimpleHmacEncoder:
    '''
    Encoder that performs HMAC encoding and HMAC check on decoding.
    '''

    def __init__(self, _parent: object, _mac_key: bytes)
        '''
        Initializes an encoder.
        @param _encoding: str = the character set used to encode and
            decode
        '''
        self.parent = _parent
        self.mac_key = _mac_key

    def encode(self, string: str) -> bytes:
        '''
        Encodes the given string into bytes using self's character
        encoding.
        @param string: str = to encode
        @return byte encoding of the string
        '''
        msg_byts = self._parent.encode(self.encoding)
        return hmac(msg_byts)

    def decode(self, byts: bytes) -> str:
        '''
        Decodes the given byte arrays into a string using self's
        character encoding.
        @param byts: bytes = to decode
        @return string decoded from the byte array
        '''
        
        return byts.decode(self.encoding)

    def hmac(self, byts: bytes) -> bytes:
        # append mac to msg_byts
        msg_mac = (msg_byts + self.mac_key)
        # hash msg_mac
        h0 = hash_init()
        h0.update(debitize(msg_mac))
        h_msg_mac = bitize(h0.digest())
        # return the result
    
# end class SimpleHmacEncoder
