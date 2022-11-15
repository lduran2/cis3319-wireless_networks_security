
# standard libraries
import logging
import traceback
from sys import stderr
from _thread import start_new_thread

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data
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


def requestKerberos(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Kerberos server
    logging.info(f'{node_data.connecting_status} {server_data.addr}:{server_data.port} . . .')
    server = Server(server_data.addr, server_data.port)

    try:
        # loop indefinitely
        while True:
            # initialize empty to start the loop
            msg_bytes = bytes()
            # read in from node until bytes are read
            while (not(msg_bytes)):
                msg_bytes = server.recv()
            # decode the message
            msg_chars = msg_bytes.decode(server_data.charset)
            # log the message received
            logging.info(f'Received: {msg_bytes}')
            # print the decoded message
            print('Decoded: ', end='', file=stderr, flush=True)
            print(msg_chars)
        # end while True
    finally:
        # close the node
        server.close()
# end 


# run the server until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(NODE, SERVER)
# end if __name__ == '__main__'

