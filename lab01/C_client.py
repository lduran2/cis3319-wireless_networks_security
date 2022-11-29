
# standard libraries
import logging
import time
from sys import stderr

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config
from crypto import KeyManager, DES
from node import Node
from ticket import TicketValidity, TICKET_EXPIRED
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


def requestKerberos(client_data, atgs_data, v_server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Kerberos client
    AD_c = f'{atgs_data.addr}:{atgs_data.port}'
    logging.info(f'{client_data.connecting_status} {AD_c} . . .')
    atgsClient = Client(atgs_data.addr, atgs_data.port)

    # read the key and create DES for C/AS
    DES_c = DES(KeyManager.read_key(config['kerberos_keys']['Kc_file']))

    # (1Tx) C -> AS:  ID_c || ID_tgs || TS1
    # get a time stamp
    TS1 = time.time()
    # create the client authentication
    client_auth = f'{ID}||{ID_tgs}||{TS1}'
    # send the client authentication message
    logging.info(f'(1) Sending plain: [{client_auth}]')
    client_auth_bytes = client_auth.encode(atgs_data.charset)
    atgsClient.send(client_auth_bytes)

    # (2Rx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])
    # initialize empty to start the loop
    msg_bytes = bytes()
    # read in from node until bytes are read
    while (not(msg_bytes)):
        msg_bytes = atgsClient.recv()

    # decrypt the message
    msg_chars = DES_c.decrypt(msg_bytes)
    # log the message received
    logging.info(f'(2Rx) Received: {msg_bytes}')
    # print the decoded message
    print(file=stderr, flush=True)
    print('Decrypted: [', end='', file=stderr, flush=True)
    print(msg_chars)
    print(']', file=stderr, flush=True)
    # split the message
    K_c_tgs, ID_tgs_1o, TS2, Lifetime2, Ticket_tgs = msg_chars.split('||')
    # print the ticket
    print('Ticket_tgs: "', end='', file=stderr, flush=True)
    print(Ticket_tgs)
    print('"', file=stderr, flush=True)
    # create DES for K_c_tgs
    DES_c_tgs = DES(K_c_tgs.encode(KEY_CHARSET))
    
    # (3Tx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c
    # get a time stamp
    TS3 = time.time()

    # create the authenticator
    plain_Authenticator_c1 = f'{ID}||{AD_c}||{TS3}'
    # encrypt the authenticator
    logging.info(f'(3) Encrypting plain: {plain_Authenticator_c1}')
    cipher_Authenticator_c1 = DES_c_tgs.encrypt(plain_Authenticator_c1)

    # concatenate the message
    Ticket_tgs_server_ID_client_auth = f'{ID_v}||{Ticket_tgs}||{cipher_Authenticator_c1}'
    # send the client authentication message
    logging.info(f'(3) Sending plain: {Ticket_tgs_server_ID_client_auth}')
    Ticket_tgs_server_ID_client_auth_bytes = Ticket_tgs_server_ID_client_auth.encode(atgs_data.charset)
    atgsClient.send(Ticket_tgs_server_ID_client_auth_bytes)

    # (3'Rx)
    # initialize empty to start the loop
    msg_bytes = bytes()
    # read in from node until bytes are read
    while (not(msg_bytes)):
        msg_bytes = atgsClient.recv()

    # check if expired
    # decrypt the message
    msg_chars = DES_c_tgs.decrypt(msg_bytes)
    # log the message received
    logging.info(f'(4Rx) Received: {msg_bytes}')
    if (TICKET_EXPIRED==msg_chars):
        print(f'For TGS_server, {msg_chars}')
        return

    # (4Rx) TGS -> C:   E(K_c_tgs, [K_c_v || ID_v || TS4 || Ticket_v])
    # print the decoded message
    print(file=stderr, flush=True)
    print('Decrypted: [', end='', file=stderr, flush=True)
    print(msg_chars)
    print(']', file=stderr, flush=True)
    # split the message
    K_c_v, ID_v_1o, TS4, Lifetime4, Ticket_v = msg_chars.split('||')
    # print the ticket
    print('Ticket_v: "', end='', file=stderr, flush=True)
    print(Ticket_v)
    print('"', file=stderr, flush=True)
    # create DES for K_c_v
    DES_c_v = DES(K_c_v.encode(KEY_CHARSET))

    # (5Tx) C -> V: Ticket_v || Authenticator_c
    # get a time stamp
    TS5 = time.time()

    # create the authenticator
    plain_Authenticator_c2 = f'{ID}||{AD_c}||{TS5}'
    # encrypt the authenticator
    logging.info(f'(5) Encrypting plain: {plain_Authenticator_c2}')
    cipher_Authenticator_c2 = DES_c_tgs.encrypt(plain_Authenticator_c2)

    # end connection with AS/TGS
    atgsClient.close()

    # create the chat client
    logging.info(f'{client_data.connecting_status} {v_server_data.addr}:{v_server_data.port} . . .')
    vClient = Client(v_server_data.addr, v_server_data.port)

    # concatenate the message
    Ticket_v_client_auth = f'{Ticket_v}||{cipher_Authenticator_c2}'
    # send the client authentication message
    logging.info(f'(5) Sending plain: {Ticket_v_client_auth}')
    Ticket_tgs_server_ID_client_auth_bytes = Ticket_v_client_auth.encode(v_server_data.charset)
    vClient.send(Ticket_tgs_server_ID_client_auth_bytes)

    # (5'Rx)
    # initialize empty to start the loop
    msg_bytes = bytes()
    # read in from node until bytes are read
    while (not(msg_bytes)):
        msg_bytes = vClient.recv()

    # check if expired
    # decrypt the message
    logging.info(f'(5\'Rx) Received cipher: {msg_bytes}')
    msg_chars = DES_c_v.decrypt(msg_bytes)
    # log the message received
    logging.info(f'(5\'Rx) Received plain: {msg_bytes}')
    print(file=stderr)
    if (TICKET_EXPIRED==msg_chars):
        print(f'For V_server, {msg_chars}')
        return
    print(file=stderr)
    print(msg_chars)

    # encode and send user input, decode messages received
    run_node.run_node(vClient, v_server_data.charset, client_data.prompt)
    # close the node
    vClient.close()
# end def requestKerberos()


# run the client until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(CLIENT, AS_TGS_SERVER, V_SERVER)
# end if __name__ == '__main__'
