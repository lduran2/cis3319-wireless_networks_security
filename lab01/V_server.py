
# standard libraries
import logging
from sys import stderr
from os import urandom

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config
from crypto import KeyManager, DES
from server import Server
from ticket import TicketValidity, TICKET_EXPIRED
from AS_TGS_server import KEY_CHARSET, DES_KEY_SIZE

# ID for this node
ID = "CIS3319SERVERID"

# corresponding section in configuration file
SECTION = 'V_server'
# load server data
SERVER = servers_config_data[SECTION]
# load node data
NODE = nodes_config_data[SECTION]


def main(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)
    # create a node
    logging.info(f'{node_data.connecting_status} {server_data.addr}:{server_data.port} . . .')
    server = Server(server_data.addr, server_data.port)

    # read the key and create DES for TGS/V
    DES_v = DES(KeyManager.read_key(config['kerberos_keys']['Kv_file']))

    # (5Rx) C -> V: Ticket_v || Authenticator_c
    # initialize empty to start the loop
    msg_bytes = bytes()
    # read in from node until bytes are read
    while (not(msg_bytes)):
        msg_bytes = server.recv()

    # decode the message
    msg_chars = msg_bytes.decode(server_data.charset)
    # log the message received
    logging.info(f'(5Rx) Received: {msg_bytes}')
    # print the decoded message
    print(file=stderr, flush=True)
    print('(5Rx) Decoded: ', end='', file=stderr, flush=True)
    print(msg_chars)
    # split the message
    cipher_Ticket_v_chars, Authenticator_c2 = msg_chars.split('||')

    # decrypt the Ticket_v
    # 1st encode the ticket to the key charset
    # this includes 0 bytes
    cipher_Ticket_v_byts_untrim = cipher_Ticket_v_chars.encode(KEY_CHARSET)
    # trim last 0 bytes
    cipher_Ticket_v_byts = bytes.rstrip(cipher_Ticket_v_byts_untrim, b'\x00')
    # decrypt the ticket
    plain_Ticket_v = DES_v.decrypt(cipher_Ticket_v_byts)
    print()
    # split the ticket
    K_c_v, ID_c, AD_c, ID_v, TS4_str, Lifetime4_str = plain_Ticket_v.split('||')
    # create DES for K_c_v
    DES_c_v = DES(K_c_v.encode(KEY_CHARSET))

    # create a random key for C/TGS
    # (may be used to encrypt the result of validation)
    K_c_v_byts = urandom(DES_KEY_SIZE)
    K_c_v_chars = K_c_v_byts.decode(KEY_CHARSET)
    DES_c_v = DES(K_c_v_byts)

    # parse timestamps
    TS4, Lifetime4 = (float(ts.rstrip('\0')) for ts in (TS4_str, Lifetime4_str))
    # validate Ticket_v by its TS4
    Ticket_v_validity = TicketValidity.validate(TS4, Lifetime4)
    print(f'This ticket is {Ticket_v_validity.name}.')
    # filter out any expired ticket
    if (not(Ticket_v_validity)):
        # encrypt an expiration message
        cipher_expire = DES_c_v.encrypt(TICKET_EXPIRED)
        # send expiration message
        server.send(cipher_expire)
        # listen for a new message
        return
    # end if (now - TS2_1o >= Lifetime2_1o)
    


    # encode and send user input, decode messages received
    run_node.run_node(server, server_data.charset, node_data.prompt)
    # close the node
    server.close()
# end def main(node_data, server_data)


# run the server until SENTINEL is given
if __name__ == '__main__':
    main(NODE, SERVER)
# end if __name__ == '__main__'
