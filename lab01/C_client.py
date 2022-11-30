
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

    # (a) authentication service exchange to obtain ticket granting-ticket
    request_ticket_granting_ticket(atgsClient, atgs_data.charset)
    DES_c_tgs, Ticket_tgs = receive_ticket_granting_ticket(atgsClient)

    # (b) ticket-granting service exchange to obtain service-granting ticket
    request_service_granting_ticket(atgsClient, atgs_data.charset, Ticket_tgs, DES_c_tgs, AD_c)
    # check if the ticket-granting ticket was valid
    sgt = receive_from_ticket(atgsClient, DES_c_tgs, ID_tgs)
    if (not(sgt)):
        return
    DES_c_v, Ticket_v = parse_service_granting_ticket(sgt)

    # end connection with AS/TGS
    atgsClient.close()

    # create the chat client
    print(file=stderr)
    logging.info(f'{client_data.connecting_status} {v_server_data.addr}:{v_server_data.port} . . .')
    vClient = Client(v_server_data.addr, v_server_data.port)

    # (c) client/server authentication exchange to obtain service
    request_service(vClient, v_server_data.charset, Ticket_v, DES_c_v, AD_c)
    # check if the service-granting ticket was valid
    service = receive_from_ticket(vClient, DES_c_v, ID_v)
    if (not(service)):
        return

    print(file=stderr)

    # encode and send user input, decode messages received
    run_node.run_node(vClient, v_server_data.charset, client_data.prompt)
    # close the chat client
    vClient.close()
# end def requestKerberos()


def request_ticket_granting_ticket(client, atgs_charset):
    # (1Tx) C -> AS:  ID_c || ID_tgs || TS1
    # get a time stamp
    TS1 = time.time()
    # create the client authentication
    client_auth = f'{ID}||{ID_tgs}||{TS1}'
    # send the client authentication message
    client_auth_bytes = client_auth.encode(atgs_charset)
    client.send(client_auth_bytes)
# end def request_ticket_granting_ticket(client, atgs_charset)


def receive_ticket_granting_ticket(client):
    # read the key and create DES for C/AS
    DES_c = DES(KeyManager.read_key(config['kerberos_keys']['Kc_file']))

    # (2Rx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])

    # receive the message
    msg_bytes = run_node.recv_blocking(client)
    # decrypt the message
    msg_chars = DES_c.decrypt(msg_bytes)
    # split the message
    K_c_tgs, ID_tgs, TS2, Lifetime2, Ticket_tgs = msg_chars.split('||')
    # create DES for K_c_tgs
    DES_c_tgs = DES(K_c_tgs.encode(KEY_CHARSET))
    return (DES_c_tgs, Ticket_tgs)
# end def receive_ticket_granting_ticket(client)


def request_service_granting_ticket(client, atgs_charset, Ticket_tgs, DES_c_tgs, AD_c):
    # (3Tx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c
    # get a time stamp
    TS3 = time.time()

    # create the authenticator
    plain_Authenticator_c = f'{ID}||{AD_c}||{TS3}'
    # encrypt the authenticator
    cipher_Authenticator_c = DES_c_tgs.encrypt(plain_Authenticator_c)

    # concatenate the message
    Ticket_tgs_server_ID_client_auth = f'{ID_v}||{Ticket_tgs}||{cipher_Authenticator_c}'
    # send the client authentication message
    Ticket_tgs_server_ID_client_auth_bytes = Ticket_tgs_server_ID_client_auth.encode(atgs_charset)
    client.send(Ticket_tgs_server_ID_client_auth_bytes)
# end def request_service_granting_ticket(client, atgs_charset, Ticket_tgs, DES_c_tgs, AD_c)


def receive_from_ticket(client, des, prompt):
    # (3'Rx)

    # receive the message
    msg_bytes = run_node.recv_blocking(client)
    # check if expired
    # decrypt the message
    msg_chars = des.decrypt(msg_bytes)
    if (TICKET_EXPIRED==msg_chars):
        print(f'from {prompt} {msg_chars}')
        print(file=stderr)
        return False

    # return the message if ticket is valid
    return msg_chars
# end def receive_from_ticket(client, des)


def parse_service_granting_ticket(sgt):
    # (4Rx) TGS -> C:   E(K_c_tgs, [K_c_v || ID_v || TS4 || Ticket_v])
    # split the message
    K_c_v, ID_v, TS4, Ticket_v = sgt.split('||')
    # create DES for K_c_v
    DES_c_v = DES(K_c_v.encode(KEY_CHARSET))
    return (DES_c_v, Ticket_v)
# end def parse_service_granting_ticket(sgt)


def request_service(client, v_charset, Ticket_v, DES_c_v, AD_c):
    # (5Tx) C -> V: Ticket_v || Authenticator_c
    # get a time stamp
    TS5 = time.time()

    # create the authenticator
    plain_Authenticator_c = f'{ID}||{AD_c}||{TS5}'
    logging.info(plain_Authenticator_c)
    # encrypt the authenticator
    cipher_Authenticator_c_byts = DES_c_v.encrypt(plain_Authenticator_c)
    # convert to string
    cipher_Authenticator_c_str = cipher_Authenticator_c_byts.decode(KEY_CHARSET)

    # concatenate the message
    Ticket_v_client_auth = f'{Ticket_v}||{cipher_Authenticator_c_str}'
    # send the client authentication message
    Ticket_tgs_server_ID_client_auth_bytes = Ticket_v_client_auth.encode(v_charset)
    client.send(Ticket_tgs_server_ID_client_auth_bytes)
# end def request_service(client, v_charset, Ticket_v, DES_c_v, AD_c)


# run the client until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(CLIENT, AS_TGS_SERVER, V_SERVER)
# end if __name__ == '__main__'
