
# standard libraries
import socket
import logging
import traceback
from sys import stderr
from _thread import start_new_thread

# local library crypto
from crypto import KeyManager, DES, bit2hex

class Node:
    '''
    A simple socket node.
    '''

    def __init__(self, addr: str, port: int, connect_func: "Callable[[Node], NoneType]", buffer_size=1024):
        '''
        Allocates space for the socket node and initializes it.
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
        # apply network function
        connect_func(self)

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
# end class Node


# name of file containing the key
KEY_FILE = 'key.txt'
# ends the input stream
SENTINEL = 'exit'


def receiveThread(node, des, encoding, prompt):
    old_tb = None
    while True:
        try:
            # read in from the node
            msg_bytes = node.recv()
            # if empty message, skip
            if (len(msg_bytes) <= 0):
                continue
            # ignore any illegal bytes
            msg_bytes = bytes(b for b in msg_bytes if b in range(256))
            # decrypt the message
            dec_string = des.decrypt(msg_bytes, encoding=encoding)
            # log the message received
            print(file=stderr)
            print(file=stderr)
            logging.info(f'Received: {msg_bytes}')
            # print the decrypted message
            print('Decrypted: ', end='', file=stderr, flush=True)
            print(dec_string)
            # print new prompt
            print(file=stderr)
            print(file=stderr, end=prompt, flush=True)
        except Exception as e:
            tb = traceback.format_exc()
            # don't repeat the trackback
            if (tb != old_tb):
                print(file=stderr)
                logging.error(tb)
            old_tb = tb
            continue
    # end while True
# end def receiveThread(node, des, encoding)

# run the node until SENTINEL is given
def main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, encoding: str, prompt: str):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create a node
    logging.info(f'{connecting_status} to {addr}:{port} . . .')
    node = node_init(addr, port)
    # read in the key word for encryption
    enc_key = KeyManager.read_key(KEY_FILE)
    # read in the key word for HMAC
    mac_key = KeyManager().read_key('mac_key.txt')
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(enc_key)

    # start the receiving thread
    start_new_thread(receiveThread, (node, des, encoding, prompt))

    while True:
        # TODO: your code here

        # accept user input until SENTINEL given
        msg_string = input(prompt)
        if msg_string == SENTINEL:
            break
        
        # TODO: your code here
        # encryption
        cyp_bytes = des.encrypt(msg_string, encoding=encoding)
        # send the message
        logging.info(f'Sending cypher: {cyp_bytes}')
        node.send(cyp_bytes)
    # end while True

    # close the node
    node.close()
# end main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, encoding: str, prompt: str)
