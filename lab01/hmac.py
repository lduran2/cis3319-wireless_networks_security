from hashlib import sha256

class SimpleHmacEncoder:
    '''
    Encoder that performs HMAC encoding and HMAC check on decoding.
    
    This is a simple implementation of HMAC appended to the end of the
    entire message.
    '''

    def __init__(self, _parent: object, _mac_key: bytes):
        '''
        Initializes an encoder.
        @param _parent: object = backing encoder with encode and decode
            methods
        @param _mac_key: bytes = the mac key as bytes
        '''
        self.parent = _parent
        self.mac_key = _mac_key

    def encode(self, string: str) -> bytes:
        '''
        Encodes the given string using the backing encoder, then
        appends its HMAC.
        @param string: str = to encode
        @return HMAC encoding of the string
        '''
        # delegate to parent encoder
        msg_byts = self._parent.encode(string)
        # HMAC the result
        msg_mac = hmac(msg_byts)
        # append to msg_byts
        complete_msg = (msg_bytes + msg_mac)
        # return the result
        return complete_msg

    def decode(self, byts: bytes) -> str:
        '''
        Separates the message from its HMAC, and decodes it using the
        backing encoder.
        @param byts: bytes = to decode
        @return message string decoded from the byte array
        '''
        # split byte array into message, theoretical MAC
        # sha256 is always 256 bytes = 32 bytes
        msg_byts, theo_mac = (byts[:-32], byts[-32:])
        # calculate the mac from the message
        calc_mac = hmac(msg_byts)
        # compare MACs
        if (theo_mac != calc_mac):
            # if different, throw an exception
            # but do NOT include the calculated MAC
            raise UnexpectedMac(f'Unexpected MAC: expected {theo_mac}')
        # otherwise
        # delegate msg_byts to parent encoder
        return self._parent.decode(msg_byts)
    # end def decode(self, byts: bytes)

    def hmac(self, msg_byts: bytes) -> bytes:
        '''
        Finds the hashed MAC of the given message in bytes.
        '''
        # append mac to msg_byts
        msg_mac = (msg_byts + self.mac_key)
        # hash msg_mac
        h0 = hash_init()
        h0.update(msg_mac)
        # return the result
        return h0.digest()
    
# end class SimpleHmacEncoder

class UnexpectedMac(Exception):
    '''
    Thrown when a calculated MAC does not match the expected
    theoretical MAC.
    '''
