
# standard libraries
import socket
import logging
from sys import stderr
from _thread import start_new_thread
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


# import connection address, port, and character encoding
from server import SERVER_ADDR, SERVER_PORT, SERVER_CHARSET
# name of file containing the key
KEY_FILE = 'key.txt'
# prompt for input
PROMPT = 'client> '
# ends the input stream
SENTINEL = 'exit'


def receiveThread(client):
    while True:
        try:
            # read in from the client
            msg_bytes = client.recv()
            # if empty message, skip
            if (len(msg_bytes) <= 0):
                continue
            # convert to a string
            msg_string = msg_bytes.decode(SERVER_CHARSET)
            # print the message
            print(file=stderr)
            print('Received: ', end='', file=stderr, flush=True)
            print(msg_string)
            # print new prompt
            print(file=stderr, end=PROMPT, flush=True)
        except:
            continue
    # end while True
# end def receiveThread(client)


# run the client until SENTINEL is given
if __name__ == '__main__':
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create a client
    logging.info(f'connecting to {SERVER_ADDR}:{SERVER_PORT} . . .')
    client = Client(SERVER_ADDR, SERVER_PORT)
    # read in the key word
    key = KeyManager().read_key(KEY_FILE)
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(key)
    print([sum([des.keys[0][i]==L for (i,L) in enumerate(k)]) for k in des.keys])

    # start the receiving thread
    start_new_thread(receiveThread, (client,))

    while True:
        # accept user input until SENTINEL given
        msg_string = input(PROMPT)
        if msg_string == SENTINEL:
            break

        # TODO: your code here
        # convert new input message to bytes
        msg_bytes = msg_string.encode(SERVER_CHARSET)
        # send the message
        client.send(msg_bytes)
    # end while True

    # close the server
    client.close()
# end if __name__ == '__main__'
