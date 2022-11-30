
# standard libraries
import logging
import time
from sys import stderr
from os import urandom

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config
from crypto import KeyManager, DES
from node import Node
from server import Server
from ticket import TicketValidity, TICKET_EXPIRED


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
# Python uses Latin-1 for Pickles, so it's good enough to encode keys
KEY_CHARSET = 'Latin-1'

# the lifetimes of tickets
Lifetimes = { 2: 60, 4: 86400 } # [s]

def requestKerberos(node_data, server_data):
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
            # (a) authentication service exchange to obtain ticket granting-ticket
            ID_c = receive_ticket_granting_ticket_request(server, server_data.charset)
            DES_c_tgs = send_ticket_granting_ticket(server, DES_c, DES_tgs, ID_c, AD_c)

            # (b) ticket-granting service exchange to obtain service-granting ticket
            # check for service-granting ticket request with valid ticket
            sgt_request = receive_service_granting_ticket_request(server, server_data.charset, DES_tgs, DES_c_tgs)
            if (not(sgt_request)):
                continue
            # split the service-granting ticket request
            ID_v, DES_c_tgs, ID_c = sgt_request
            # send the service-granting ticket
            send_service_granting_ticket(server, DES_c_tgs, DES_v, ID_c, AD_c, ID_v)
        # end while True
    finally:
        # close the node
        server.close()
# end def requestKerberos(node_data, server_data)


def receive_ticket_granting_ticket_request(server, charset):
    # (1Rx) C -> AS:  ID_c || ID_tgs || TS1
    # receive the message
    msg_bytes = run_node.recv_blocking(server)
    # decode the message
    msg_chars = msg_bytes.decode(charset)
    # log the message received
    logging.info(f'(1Rx) Received: {msg_bytes}')
    # print the decoded message
    print(file=stderr, flush=True)
    print('(1Rx) Decoded: ', end='', file=stderr, flush=True)
    print(msg_chars)
    # split the message
    ID_c, ID_tgs, TS1 = msg_chars.split('||')
    return ID_c
# end def receive_ticket_granting_ticket_request(server, charset)


def send_ticket_granting_ticket(server, DES_c, DES_tgs, ID_c, AD_c):
    # (2Tx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])
    # create a random key for C/TGS
    K_c_tgs_byts = urandom(DES_KEY_SIZE)
    K_c_tgs_chars = K_c_tgs_byts.decode(KEY_CHARSET)
    DES_c_tgs = DES(K_c_tgs_byts)
    # get a time stamp
    TS2 = time.time()
    # clear if need to fail
    if (FAIL_TS2):
        TS2 = 0
    # end if (FAIL_TS2)

    # concatenate the ticket
    plain_Ticket_tgs = f'{K_c_tgs_chars}||{ID_c}||{AD_c}||{ID}||{TS2}||{Lifetimes[2]}'
    # encrypt the ticket
    logging.info(f'(2) Encrypting plain: {plain_Ticket_tgs}')
    cipher_Ticket_tgs_byts = DES_tgs.encrypt(plain_Ticket_tgs)
    cipher_Ticket_tgs_chars = cipher_Ticket_tgs_byts.decode(KEY_CHARSET)
    
    # concatenate the message
    plain_shared_key_ticket = f'{K_c_tgs_chars}||{ID}||{TS2}||{Lifetimes[2]}||{cipher_Ticket_tgs_chars}'
    # encrypt the message
    logging.info(f'(2) Sending plain: {plain_shared_key_ticket}')
    cipher_shared_key_ticket = DES_c.encrypt(plain_shared_key_ticket)
    # send it
    server.send(cipher_shared_key_ticket)

    return DES_c_tgs
# end def send_ticket_granting_ticket(server, ID_c, AD_c)


def receive_service_granting_ticket_request(server, charset, DES_tgs, DES_c_tgs):
    # (3Rx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c

    # receive the message
    msg_bytes = run_node.recv_blocking(server)
    # decode the message
    msg_chars = msg_bytes.decode(charset)
    # log the message received
    logging.info(f'(3Rx) Received: {msg_bytes}')
    # print the decoded message
    print(file=stderr, flush=True)
    print('(3Rx) Decoded: ', end='', file=stderr, flush=True)
    print(msg_chars)
    # split the message
    ID_v, cipher_Ticket_tgs_chars, Authenticator_c = msg_chars.split('||')
    logging.info(f'cipher_Ticket_tgs_chars   : "{cipher_Ticket_tgs_chars}"')
    
    # decrypt the Ticket_tgs'
    # 1st encode the ticket to the key charset
    # this includes 0 bytes
    cipher_Ticket_tgs_byts_untrim = cipher_Ticket_tgs_chars.encode(KEY_CHARSET)
    # trim last 0 bytes
    cipher_Ticket_tgs_byts = bytes.rstrip(cipher_Ticket_tgs_byts_untrim, b'\x00')
    logging.info(f'cipher_Ticket_tgs_byts_untrim: "{cipher_Ticket_tgs_byts_untrim}"')
    logging.info(f'cipher_Ticket_tgs_byts       : "{cipher_Ticket_tgs_byts}"')
    print(file=stderr, flush=True)
    # decrypt the ticket
    plain_Ticket_tgs = DES_tgs.decrypt(cipher_Ticket_tgs_byts)
    logging.info(f'decrypted: "{plain_Ticket_tgs}"')
    print()
    # split the ticket
    K_c_tgs_chars, ID_c, AD_c, ID_tgs, TS2_str, Lifetime2_str = plain_Ticket_tgs.split('||')

    # parse timestamps
    TS2, Lifetime2 = (float(ts.rstrip('\0')) for ts in (TS2_str, Lifetime2_str))
    # validate Ticket_tgs' by its TS2
    Ticket_tgs_validity = TicketValidity.validate(TS2, Lifetime2)
    print(f'This ticket is {Ticket_tgs_validity.name}.')
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
# end def receive_service_granting_ticket_request(server, charset, DES_tgs, DES_c_tgs)


def send_service_granting_ticket(server, DES_c_tgs, DES_v, ID_c, AD_c, ID_v):
    # (4Tx) TGS -> C:   E(K_c_tgs, [K_c_v || ID_v || TS4 || Ticket_v])
    # create a random key for C/V
    K_c_v_chars = urandom(DES_KEY_SIZE).decode(KEY_CHARSET)
    # get a time stamp
    TS4 = time.time()
    # clear if need to fail
    if (FAIL_TS4):
        TS4 = 0
    # end if (FAIL_TS4)

    # concatenate the ticket
    plain_Ticket_v = f'{K_c_v_chars}||{ID_c}||{AD_c}||{ID_v}||{TS4}||{Lifetimes[4]}'
    # encrypt the ticket
    logging.info(f'(4) Encrypting plain: {plain_Ticket_v}')
    cipher_Ticket_v_byts = DES_v.encrypt(plain_Ticket_v)
    cipher_Ticket_v_chars = cipher_Ticket_v_byts.decode(KEY_CHARSET)
    
    # concatenate the message
    plain_shared_key_ticket = f'{K_c_v_chars}||{ID_v}||{TS4}||{Lifetimes[4]}||{cipher_Ticket_v_chars}'
    # encrypt the message
    logging.info(f'(4) Sending plain: {plain_shared_key_ticket}')
    cipher_shared_key_ticket = DES_c_tgs.encrypt(plain_shared_key_ticket)
    logging.info(f'(4) Sending cipher: {cipher_shared_key_ticket}')
    # send it
    server.send(cipher_shared_key_ticket)

    print(file=stderr)
    logging.info(f'finished authenticating: {ID_c}')
# end def send_service_granting_ticket(server, DES_c_tgs, DES_v, ID_c, AD_c, ID_v)


# run the server until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(NODE, SERVER)
# end if __name__ == '__main__'

