
# standard libraries
import logging
import time
from sys import stderr

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config
from crypto import KeyManager, DES
from node import Node
from AS_TGS_server import ID as ID_tgs, KEY_CHARSET
from V_server import ID as ID_v


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
    AD_c = f'{server_data.addr}:{server_data.port}'
    logging.info(f'{client_data.connecting_status} {AD_c} . . .')
    client = Client(server_data.addr, server_data.port)

    # read the key for C/AS
    Kc = KeyManager.read_key(config['kerberos_keys']['Kc_file'])
    
    # create DES for Kc
    DES_c = DES(Kc)

    # (1Tx) C -> AS:  ID_c || ID_tgs || TS1
    # get a time stamp
    TS1 = time.time()
    # create the client authentication
    client_auth = f'{ID}||{ID_tgs}||{TS1}'
    # send the client authentication message
    logging.info(f'(1) Sending plain: {client_auth}')
    client_auth_bytes = client_auth.encode(server_data.charset)
    client.send(client_auth_bytes)

    # (2Rx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])
    # initialize empty to start the loop
    msg_bytes = bytes()
    # read in from node until bytes are read
    while (not(msg_bytes)):
        msg_bytes = client.recv()

    # decrypt the message
    msg_chars = DES_c.decrypt(msg_bytes)
    # log the message received
    logging.info(f'(2Rx) Received: {msg_bytes}')
    # print the decoded message
    print(file=stderr, flush=True)
    print('Decrypted: ', end='', file=stderr, flush=True)
    print(msg_chars)
    print(file=stderr, flush=True)
    # split the message
    K_c_tgs, ID_tgs2, TS2, Lifetime2, Ticket_tgs = msg_chars.split('||')
    # print the ticket
    print('Ticket_tgs: ', end='', file=stderr, flush=True)
    print(Ticket_tgs)
    print(file=stderr, flush=True)
    # create DES for K_c_tgs
    DES_c_tgs = DES(K_c_tgs.encode(KEY_CHARSET))
    
    # (3Tx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c
    # get a time stamp
    TS3 = time.time()

    # create the authenticator
    plain_Authenticator_c = f'{ID}||{AD_c}||{TS3}'
    # encrypt the authenticator
    logging.info(f'(3) Encrypting plain: {plain_Authenticator_c}')
    cipher_Authenticator_c = DES_c_tgs.encrypt(plain_Authenticator_c)

    # concatenate the message
    server_ID_client_auth = f'{ID_v}||{Ticket_tgs}||{cipher_Authenticator_c}'
    # send the client authentication message
    logging.info(f'(3) Sending plain: {server_ID_client_auth}')
    server_ID_client_auth_bytes = client_auth.encode(server_data.charset)
    client.send(server_ID_client_auth_bytes)
# end def requestKerberos()


# run the client until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(CLIENT, AS_TGS_SERVER)
    # run_node.main_ns(CLIENT, V_SERVER, Client)
# end if __name__ == '__main__'