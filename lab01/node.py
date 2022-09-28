
# standard libraries
import socket

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
