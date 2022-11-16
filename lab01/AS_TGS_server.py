
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
FAIL_TS4 = True


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
            # (1Rx) C -> AS:  ID_c || ID_tgs || TS1
            # initialize empty to start the loop
            msg_bytes = bytes()
            # read in from node until bytes are read
            while (not(msg_bytes)):
                msg_bytes = server.recv()

            # decode the message
            msg_chars = msg_bytes.decode(server_data.charset)
            # log the message received
            logging.info(f'(1Rx) Received: {msg_bytes}')
            # print the decoded message
            print(file=stderr, flush=True)
            print('(1Rx) Decoded: ', end='', file=stderr, flush=True)
            print(msg_chars)
            # split the message
            ID_c, ID_tgs, TS1 = msg_chars.split('||')

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
            plain_Ticket_tgs = f'{K_c_tgs_chars}||{ID_c}||{AD_c}||{ID_tgs}||{TS2}||{Lifetimes[2]}'
            # encrypt the ticket
            logging.info(f'(2) Encrypting plain: {plain_Ticket_tgs}')
            cipher_Ticket_tgs_byts = DES_tgs.encrypt(plain_Ticket_tgs)
            cipher_Ticket_tgs_chars = cipher_Ticket_tgs_byts.decode(KEY_CHARSET)
            
            # concatenate the message
            plain_shared_key_ticket = f'{K_c_tgs_chars}||{ID_tgs}||{TS2}||{Lifetimes[2]}||{cipher_Ticket_tgs_chars}'
            # encrypt the message
            logging.info(f'(2) Sending plain: {plain_shared_key_ticket}')
            cipher_shared_key_ticket = DES_c.encrypt(plain_shared_key_ticket)
            # send it
            server.send(cipher_shared_key_ticket)

            # (3Rx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c
            # initialize empty to start the loop
            msg_bytes = bytes()
            # read in from node until bytes are read
            while (not(msg_bytes)):
                msg_bytes = server.recv()
            
            # decode the message
            msg_chars = msg_bytes.decode(server_data.charset)
            # log the message received
            logging.info(f'(3Rx) Received: {msg_bytes}')
            # print the decoded message
            print(file=stderr, flush=True)
            print('(3Rx) Decoded: ', end='', file=stderr, flush=True)
            print(msg_chars)
            # split the message
            ID_v, cipher_Ticket_tgs_1o_chars, Authenticator_c = msg_chars.split('||')
            logging.info(f'cipher_Ticket_tgs_1o_chars: "{cipher_Ticket_tgs_1o_chars}"')
            logging.info(f'cipher_Ticket_tgs_chars   : "{cipher_Ticket_tgs_chars}"')
            
            # decrypt the Ticket_tgs'
            # 1st encode the ticket to the key charset
            # this includes 0 bytes
            cipher_Ticket_tgs_1o_byts_untrim = cipher_Ticket_tgs_1o_chars.encode(KEY_CHARSET)
            # trim last 0 bytes
            cipher_Ticket_tgs_1o_byts = bytes.rstrip(cipher_Ticket_tgs_1o_byts_untrim, b'\x00')
            logging.info(f'cipher_Ticket_tgs_1o_byts_untrim: "{cipher_Ticket_tgs_1o_byts_untrim}"')
            logging.info(f'cipher_Ticket_tgs_1o_byts       : "{cipher_Ticket_tgs_1o_byts}"')
            logging.info(f'cipher_Ticket_tgs_byts          : "{cipher_Ticket_tgs_byts}"')
            print(file=stderr, flush=True)
            # decrypt the ticket
            plain_Ticket_tgs_1o = DES_tgs.decrypt(cipher_Ticket_tgs_1o_byts)
            logging.info(f'decrypted: "{plain_Ticket_tgs_1o}"')
            print()
            # split the ticket
            K_c_tgs_chars_1o, ID_c_1o, AD_c_1o, ID_tgs_1o, TS2_1o_str, Lifetime2_1o_str = plain_Ticket_tgs_1o.split('||')

            # parse timestamps
            TS2_1o, Lifetime2_1o = (float(ts.rstrip('\0')) for ts in (TS2_1o_str, Lifetime2_1o_str))
            # validate Ticket_tgs' by its TS2
            Ticket_tgs_1o_validity = TicketValidity.validate(TS2_1o, Lifetime2_1o)
            print(f'This ticket is {Ticket_tgs_1o_validity.name}.')
            # filter out any expired ticket
            if (not(Ticket_tgs_1o_validity)):
                # encrypt an expiration message
                cipher_expire = DES_c_tgs.encrypt(TICKET_EXPIRED)
                # send expiration message
                server.send(cipher_expire)
                # listen for a new message
                continue
            # end if (now - TS2_1o >= Lifetime2_1o)
            
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
            # send it
            server.send(cipher_shared_key_ticket)

        # end while True
    finally:
        # close the node
        server.close()
# end def requestKerberos(node_data, server_data)

# run the server until SENTINEL is given
if __name__ == '__main__':
    requestKerberos(NODE, SERVER)
# end if __name__ == '__main__'

