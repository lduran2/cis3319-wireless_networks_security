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

    def acceptNextConnection(self):
        # allow for more connections
        Server.acceptNextConnectionOnNode(self.node)

    @staticmethod
    def bindListenAccept(node: Node):
        # bind it to the address whereat to listen
        node.s.bind((node.addr, node.port))
        # start listening
        node.s.listen(Server.MAX_N_CONNS)
        # accept first connection
        Server.acceptNextConnectionOnNode(node)

    @staticmethod
    def acceptNextConnectionOnNode(node: Node):
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


