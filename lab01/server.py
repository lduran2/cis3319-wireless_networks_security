
# standard libraries
import socket
import logging
from sys import stderr
from _thread import start_new_thread

# local library crypto
from crypto import KeyManager, DES

class Server:
    '''
    A simple socket server.
    '''

    # the maximum number of connections
    MAX_N_CONNS = 1

    def __init__(self, addr: str, port: int, buffer_size=1024):
        '''
        Allocates space for the socket server and initializes it.
        @param addr: str = address whereat to listen (without port)
        @param port: int = port of address whereat to listen
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
        # bind it to the address whereat to listen
        self.s.bind((self.addr, self.port))
        # start listening
        self.s.listen(Server.MAX_N_CONNS)
        # store the connected socket and update the address
        self.conn, self.addr = self.s.accept()

    def send(self, msg_bytes: bytes):
        '''
        Sends the message given by `msg_bytes` through the socket.
        @param msg_bytes: bytes = message to send
        '''
        # delegate to the socket
        self.conn.send(msg_bytes)

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
        msg_bytes = self.conn.recv(buffer_size)
        # return the message
        return msg_bytes

    def close(self):
        '''
        Closes the backing socket.
        '''
        self.conn.close()
# end class Server


# address whereat to listen
SERVER_ADDR = 'localhost'
SERVER_PORT = 9999
SERVER_CHARSET = 'utf-8'
# name of file containing the key
KEY_FILE = 'key.txt'
# prompt for input
PROMPT = 'server> '
# ends the input stream
SENTINEL = 'exit'


def receiveThread(server):
    while True:
        try:
            # read in from the server
            msg_bytes = server.recv()
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
# end def receiveThread(server)


# run the server until SENTINEL is given
if __name__ == '__main__':
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create a server
    logging.info(f'listening to {SERVER_ADDR}:{SERVER_PORT} . . .')
    server = Server(SERVER_ADDR, SERVER_PORT)
    # read in the key word
    key = KeyManager.read_key(KEY_FILE)
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(key)

    # start the receiving thread
    start_new_thread(receiveThread, (server,))

    while True:
        # TODO: your code here

        # accept user input until SENTINEL given
        msg_string = input(PROMPT)
        if msg_string == SENTINEL:
            break
        
        # TODO: your code here
        # convert new input message to bytes
        msg_bytes = msg_string.encode(SERVER_CHARSET)
        # send the message
        server.send(msg_bytes)
    # end while True

    # close the server
    server.close()
# end if __name__ == '__main__'
