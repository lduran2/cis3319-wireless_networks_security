
# standard libraries
import json
import socket

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data
from node import Node


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
ID = "CIS3319SERVERID"

# corresponding section in configuration file
SECTION = 'V_server'
# load server data
SERVER = servers_config_data[SECTION]
# load node data
NODE = nodes_config_data[SECTION]

# run the server until SENTINEL is given
if __name__ == '__main__':
    run_node.main_ns(NODE, SERVER, Server)
# end if __name__ == '__main__'