
# standard library socket
import socket
# local library crypto
from crypto import KeyManager, DES


class Client:
    '''
    A simple socket client.
    '''

    def __init__(self, addr: str, port: int, buffer_size=1024):
        '''
        Allocates space for the socket client and initializes it.
        @param addr: str = address whereto to connect (without port)
        @param port: int = port of address whereto to connect
        @param buffer_size: int = default buffer size for receiving
                messages
        '''
        # store address, port and buffer size
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        # create the stream socket to serve
        # using IPv4 or string hostnames
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # connect the socket to the given address and port
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        '''
        Sends the message given by `msg_bytes` through the socket.
        @param msg_bytes: bytes = message to send
        '''
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        '''
        Receives a message from the socket.
        @param buffer_size: int? = size of the receiving buffer
        @return the message received
        '''
        # if no buffer_size given, use the default
        if buffer_size is None:
            buffer_size = self.buffer_size
        # delegate to the socket
        msg_bytes = self.s.recv(self.buffer_size)
        # return the message
        return msg_bytes

    def close(self):
        '''
        Closes the backing socket.
        '''
        self.s.close()
# end class Client


# import connection address and port
from server import LISTEN_ADDR as CONNECT_ADDR, LISTEN_PORT as CONNECT_PORT
# name of file containing the key
KEY_FILE = 'key.txt'
# prompt for input
PROMPT = '> '
# ends the input stream
SENTINEL = 'exit'


# run the client until SENTINEL is given
if __name__ == '__main__':
    # create a client
    client = Client(CONNECT_ADDR, CONNECT_PORT)
    # read in the key word
    key = KeyManager().read_key(KEY_FILE)
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(key)

    while True:
        # accept user input until SENTINEL given
        msg = input(PROMPT)
        if msg == SENTINEL:
            break

        # TODO: your code here
    # end while True

    # close the server
    client.close()
# end if __name__ == '__main__'
