
# standard libraries
import logging
import time
from sys import stderr
from os import urandom

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET
from crypto import KeyManager, DES
from node import Node
from server import Server
from ticket import receive_ticket


# debug modes
FAIL_TS2 = False
FAIL_TS4 = False


# ID for this node
ID = "CIS3319TGSID"

# corresponding section in configuration file
SECTION = 'AS_TGS_server'
# load server data
SERVER = servers_config_data[SECTION]
# load node data
NODE = nodes_config_data[SECTION]

# size for DES keys
DES_KEY_SIZE = 8

# the lifetimes of tickets
Lifetimes = { 2: 60, 4: 86400 } # [s]

def respondKerberos(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Kerberos server
    AD_c = f'{server_data.addr}:{server_data.port}'
    logging.info(f'{node_data.connecting_status} {AD_c} . . .')
    server = Server(server_data.addr, server_data.port)

    # read each key
    # and create DES for Ktgs and Kc
    DES_tgs, DES_c, DES_v = (DES(KeyManager.read_key(file))
        for file in config['kerberos_keys'].values())

    try:
        # loop indefinitely
        while True:
            serve_authentication(server, server_data.charset, DES_c, DES_tgs, AD_c)
            serve_ticket_granting(server, server_data.charset, DES_tgs, DES_v, AD_c)
        # end while True
    finally:
        # close the node
        server.close()
# end def respondKerberos(node_data, server_data)


def serve_authentication(server, charset, DES_c, DES_tgs, AD_c):
    # (a) authentication service exchange to obtain ticket granting-ticket
    ID_c = receive_ticket_granting_ticket_request(server, charset)
    send_ticket_granting_ticket(server, DES_c, DES_tgs, ID_c, AD_c)
# end def serve_authentication(server, charset, DES_c, DES_tgs, AD_c)


def serve_ticket_granting(server, charset, DES_tgs, DES_v, AD_c):
    # (b) ticket-granting service exchange to obtain service-granting ticket
    # check for service-granting ticket request with valid ticket
    sgt_request = receive_ticket(server, charset, DES_tgs)
    if (not(sgt_request)):
        return
    # split the service-granting ticket request
    # Authenticator_c is not needed
    ID_v, _, DES_c_tgs, ID_c = sgt_request
    # send the service-granting ticket
    send_service_granting_ticket(server, DES_c_tgs, DES_v, ID_c, AD_c, ID_v)
# end def serve_ticket_granting(server, charset, DES_tgs, DES_v, AD_c)


def receive_ticket_granting_ticket_request(server, charset):
    # (1Rx) C -> AS:  ID_c || ID_tgs || TS1
    # receive the message
    msg_bytes = run_node.recv_blocking(server)
    # decode the message
    msg_chars = msg_bytes.decode(charset)
    # split the message
    ID_c, ID_tgs, TS1 = msg_chars.split('||')
    return ID_c
# end def receive_ticket_granting_ticket_request(server, charset)


def send_ticket_granting_ticket(server, DES_c, DES_tgs, ID_c, AD_c):
    # (2Tx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])
    K_c_tgs_chars, TS2, Ticket_tgs = create_ticket(server, DES_tgs, ID_c, AD_c, ID, FAIL_TS2, Lifetimes[2])
    # concatenate the message
    plain_shared_key_ticket = f'{K_c_tgs_chars}||{ID}||{TS2}||{Lifetimes[2]}||{Ticket_tgs}'
    # encrypt the message
    cipher_shared_key_ticket = DES_c.encrypt(plain_shared_key_ticket)
    # send it
    server.send(cipher_shared_key_ticket)
# end def send_ticket_granting_ticket(server, ID_c, AD_c)


def receive_service_granting_ticket_request(server, charset, DES_tgs):
    # (3Rx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c

    # receive the message
    msg_bytes = run_node.recv_blocking(server)
    # decode the message
    msg_chars = msg_bytes.decode(charset)
    # split the message
    ID_v, cipher_Ticket_tgs_chars, Authenticator_c = msg_chars.split('||')
    
    # decrypt the Ticket_tgs'
    # 1st encode the ticket to the key charset
    # this includes 0 bytes
    cipher_Ticket_tgs_byts_untrim = cipher_Ticket_tgs_chars.encode(KEY_CHARSET)
    # trim last 0 bytes
    cipher_Ticket_tgs_byts = bytes.rstrip(cipher_Ticket_tgs_byts_untrim, b'\x00')
    # decrypt the ticket
    plain_Ticket_tgs = DES_tgs.decrypt(cipher_Ticket_tgs_byts)
    # split the ticket
    K_c_tgs, ID_c, AD_c, ID_tgs, TS2_str, Lifetime2_str = plain_Ticket_tgs.split('||')
    # create DES for K_c_tgs
    DES_c_tgs = DES(K_c_tgs.encode(KEY_CHARSET))

    # parse timestamps
    TS2, Lifetime2 = (float(ts.rstrip('\0')) for ts in (TS2_str, Lifetime2_str))
    # validate Ticket_tgs' by its TS2
    Ticket_tgs_validity = TicketValidity.validate(TS2, Lifetime2)
    # filter out any expired ticket
    if (not(Ticket_tgs_validity)):
        # encrypt an expiration message
        cipher_expire = DES_c_tgs.encrypt(TICKET_EXPIRED)
        # send expiration message
        server.send(cipher_expire)
        # listen for a new message
        return False
    # end if (now - TS2 >= Lifetime2)

    return (ID_v, DES_c_tgs, ID_c)
# end def receive_service_granting_ticket_request(server, charset, DES_tgs)


def send_service_granting_ticket(server, DES_c_tgs, DES_v, ID_c, AD_c, ID_v):
    # (4Tx) TGS -> C:   E(K_c_tgs, [K_c_v || ID_v || TS4 || Ticket_v])
    K_c_v_chars, TS4, Ticket_v = create_ticket(server, DES_v, ID_c, AD_c, ID_v, FAIL_TS4, Lifetimes[4])
    # concatenate the message
    plain_shared_key_ticket = f'{K_c_v_chars}||{ID_v}||{TS4}||{Ticket_v}'
    # encrypt the message
    cipher_shared_key_ticket = DES_c_tgs.encrypt(plain_shared_key_ticket)
    # send it
    server.send(cipher_shared_key_ticket)
# end def send_service_granting_ticket(server, DES_c_tgs, DES_v, ID_c, AD_c, ID_v)


def create_ticket(server, des_next_server, ID_c, AD_c, server_ID, fail_timestamp, Lifetime):
    # Ticket = E(K_next_dest
    # create a random key
    K_c_next_server_byts = urandom(DES_KEY_SIZE)
    K_c_next_server_chars = K_c_next_server_byts.decode(KEY_CHARSET)
    # get a time stamp
    TS = time.time()
    # clear if need to fail
    if (fail_timestamp):
        TS = 0
    # end if (fail_timestamp)

    # concatenate the ticket
    plain_Ticket = f'{K_c_next_server_chars}||{ID_c}||{AD_c}||{server_ID}||{TS}||{Lifetime}'
    # encrypt the ticket
    cipher_Ticket_byts = des_next_server.encrypt(plain_Ticket)
    cipher_Ticket_chars = cipher_Ticket_byts.decode(KEY_CHARSET)

    return (K_c_next_server_chars, TS, cipher_Ticket_chars)
# end def create_ticket(server, des_next_server, ID_c, AD_c, server_ID, fail_timestamp, Lifetime)


# run the server until SENTINEL is given
if __name__ == '__main__':
    respondKerberos(NODE, SERVER)
# end if __name__ == '__main__'

