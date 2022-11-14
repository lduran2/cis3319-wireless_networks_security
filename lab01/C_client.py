
# standard libraries
import logging
import time

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data
from node import Node
from AS_TGS_server import ID as ID_tgs


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


# ID for this node
ID = 'CIS3319USERID'

# corresponding section in configuration file
SECTION = 'C_client'
# split data for both V_server and AS_TGS_server
V_SERVER, AS_TGS_SERVER = (
    servers_config_data[server] for server in ('V_server', 'AS_TGS_server'))
# load client data
CLIENT = nodes_config_data[SECTION]


def requestKerberos(client_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Kerberos client
    logging.info(f'{client_data.connecting_status} {server_data.addr}:{server_data.port} . . .')
    client = Client(server_data.addr, server_data.port)

    # get a time stamp
    TS = time.time()
    # create the client authentication
    client_auth = f'{ID}||{ID_tgs}||{TS}'
    # send the client authentication message
    logging.info(f'Sending cypher: {client_auth}')
    client_auth_bytes = client_auth.encode(server_data.charset)
    client.send(client_auth_bytes)
# end def requestKerberos()


# run the client until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(CLIENT, AS_TGS_SERVER)
    # run_node.main_ns(CLIENT, V_SERVER, Client)
# end if __name__ == '__main__'