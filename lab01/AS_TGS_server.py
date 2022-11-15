
# standard libraries
import logging
import time
from sys import stderr

# reference libraries
from random_utf8 import get_random_unicode as utf8random

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config
from crypto import KeyManager, DES
from node import Node
from V_server import Server


class AG_TGS_Server:
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
        # create and store the node
        self.node = Node(addr, port, Server.bindListenAccept, buffer_size)

    @staticmethod
    def bindListenAccept(node: Node):
        # bind it to the address whereat to listen
        node.s.bind((node.addr, node.port))
        # start listening
        node.s.listen(Server.MAX_N_CONNS)
        # store the connected socket and update the address
        node.conn, node.addr = node.s.accept()

    def send(self, msg_bytes: bytes):
        '''
        Sends the message given by `msg_bytes` through the socket.
        @param msg_bytes: bytes = message to send
        '''
        # delegate to the node
        self.node.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        '''
        Receives a message from the socket.
        @param buffer_size: int? = size of the receiving buffer
        @return the message received
        '''
        # delegate to the node
        msg_bytes = self.node.recv(buffer_size)
        # return the message
        return msg_bytes

    def close(self):
        '''
        Closes the backing socket.
        '''
        self.node.close()
# end class Server


# ID for this node
ID = "CIS3319TGSID"

# corresponding section in configuration file
SECTION = 'AS_TGS_server'
# load server data
SERVER = servers_config_data[SECTION]
# load node data
NODE = nodes_config_data[SECTION]

# size for DES keys
DES_KEY_SIZE = 8

# the lifetimes of tickets
Lifetimes = { 2: 60, 4: 86400 } # [s]


def requestKerberos(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Kerberos server
    AD_c = '{server_data.addr}:{server_data.port}'
    logging.info(f'{node_data.connecting_status} {AD_c} . . .')
    server = Server(server_data.addr, server_data.port)

    # read each key
    Kc, K_tgs, Kv = (KeyManager.read_key(file)
        for file in config['kerberos_keys'].values())
    
    # create DES for Ktgs and Kc
    DES_tgs, DES_c = (DES(key) for key in (K_tgs, Kc))

    try:
        # loop indefinitely
        while True:
            # (1Rx) C -> AS:  ID_c || ID_tgs || TS1
            # initialize empty to start the loop
            msg_bytes = bytes()
            # read in from node until bytes are read
            while (not(msg_bytes)):
                msg_bytes = server.recv()

            # decode the message
            msg_chars = msg_bytes.decode(server_data.charset)
            # log the message received
            logging.info(f'(1Rx) Received: {msg_bytes}')
            # print the decoded message
            print(file=stderr, flush=True)
            print('Decoded: ', end='', file=stderr, flush=True)
            print(msg_chars)
            # split the message
            ID_c, ID_tgs, TS1 = msg_chars.split('||')

            # (2Tx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])
            # create a random key for C/TGS
            K_c_tgs = utf8random(DES_KEY_SIZE)
            # get a time stamp
            TS2 = time.time()

            # concatenate the ticket
            plain_Ticket_tgs = f'{K_c_tgs}||{ID_c}||{AD_c}||{ID_tgs}||{TS2}||{Lifetimes[2]}'
            # encrypt the ticket
            logging.info(f'(2) Encrypting plain: {plain_Ticket_tgs}')
            cipher_Ticket_tgs = DES_tgs.encrypt(plain_Ticket_tgs)
            
            # concatenate the message
            plain_shared_key_ticket = f'{K_c_tgs}||{ID_tgs}||{TS2}||{Lifetimes[2]}||{cipher_Ticket_tgs}'
            # encrypt the message
            logging.info(f'(2) Sending plain: {plain_shared_key_ticket}')
            cipher_shared_key_ticket = DES_c.encrypt(plain_shared_key_ticket)
            # send it
            server.send(cipher_shared_key_ticket)
        # end while True
    finally:
        # close the node
        server.close()
# end 


# run the server until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(NODE, SERVER)
# end if __name__ == '__main__'

