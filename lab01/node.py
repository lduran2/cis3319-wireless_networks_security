
# standard libraries
import socket

class Node:
    '''
    A simple socket node.
    '''

    def __init__(self, addr: str, port: int, connect_func: "Callable[[Node], NoneType]", buffer_size=1024,
            encoding: str='utf-8',
            encoder: 'Callable[[str, str], bytes]'=(
                lambda s, encoding: s.encode(encoding)
            ),
            decoder: 'Callable[[bytes, str], str]'=(
                lambda byts, encoding: byts.decode(encoding)
            )
        ):
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

        # store encoding, encoder and decoder functions
        self.encoding = encoding
        self.encoder = encoder
        self.decoder = decoder

    def send(self, msg_string: str):
        '''
        Sends the message given by `msg_string` through the socket.
        @param msg_string: str = message to send
        '''
        # encode the string, converting to bytes
        msg_bytes = encoder(msg_string, encoding)
        # delegate to the socket
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> str:
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
        # decode the bytes, converting to string
        msg_string = decoder(msg_string, encoding)
        # return the message
        return msg_string

    def close(self):
        '''
        Closes the backing socket.
        '''
        self.conn.close()
# end class Node
