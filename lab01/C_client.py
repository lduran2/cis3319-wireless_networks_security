
# standard libraries
import json
import logging
import socket

# local library crypto
import run_node
from run_node import config
from node import Node


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
        # create and store the node
        self.node = Node(addr, port, Client.connect, buffer_size)

    @staticmethod
    def connect(node: Node):
        # connect the socket to the given address and port
        node.s.connect((node.addr, node.port))
        # set connection to socket
        node.conn = node.s

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
# end class Client


# corresponding section in configuration file
SECTION = 'C_client'
# load connection address, port whereat the server listens
# load character encoding
V_SERVER_ADDR, V_SERVER_PORT, V_SERVER_CHARSET = (
    config['V_server'][key] for key in ('addr', 'port', 'charset'))
# load prompt for input, connection status
PROMPT, CONNECTING_STATUS = (
    config[SECTION][key] for key in ('prompt', 'connecting_status'))


# run the client until SENTINEL is given
if __name__ == '__main__':
    # configure the logger
    logging.basicConfig(level=logging.INFO)
    # create a node
    logging.info(f'{CONNECTING_STATUS} {V_SERVER_ADDR}:{V_SERVER_PORT} . . .')
    vClient = Client(V_SERVER_ADDR, V_SERVER_PORT)
    # encode and send user input, decode messages received
    run_node.encodeDecode(vClient, V_SERVER_CHARSET, PROMPT)
    # close the node
    vClient.close()
# end if __name__ == '__main__'
