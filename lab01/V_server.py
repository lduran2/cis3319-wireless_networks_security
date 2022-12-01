
# standard libraries
import logging
from sys import stderr
from os import urandom

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET
from crypto import KeyManager, DES
from server import Server
from ticket import receive_ticket
from AS_TGS_server import DES_KEY_SIZE

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

    # (c) client/server authentication exchange to obtain service
    # check for service-granting ticket request with valid ticket
    print('(c5) V acting . . .')
    service_request = receive_ticket(server, server_data.charset, DES_v)
    if (not(service_request)):
        return
    # split the service request
    # there is no next server.  no need for ID_c
    _, Authenticator_c, DES_c_v, _ = service_request
    # get the timestamp and send it to client for authentication
    TS5 = parse_authenticator(DES_c_v, Authenticator_c)
    send_service(server, DES_c_v, TS5)

    # encrypt and send user input, decrypt messages received
    # use DES_c_v as the DES encrypter, not enc_key
    run_node.run_node(server, DES_c_v, server_data.charset, node_data.prompt)
    # close the node
    server.close()
# end def main(node_data, server_data)


def receive_service_request(server, charset, DES_v):
    # (5Rx) C -> V: Ticket_v || Authenticator_c

    # receive the message
    msg_bytes = run_node.recv_blocking(server)
    # decode the message
    msg_chars = msg_bytes.decode(charset)
    # split the message
    cipher_Ticket_v_chars, Authenticator_c = msg_chars.split('||')

    # decrypt the Ticket_v
    # 1st encode the ticket to the key charset
    # this includes 0 bytes
    cipher_Ticket_v_byts_untrim = cipher_Ticket_v_chars.encode(KEY_CHARSET)
    # trim last 0 bytes
    cipher_Ticket_v_byts = bytes.rstrip(cipher_Ticket_v_byts_untrim, b'\x00')
    # decrypt the ticket
    plain_Ticket_v = DES_v.decrypt(cipher_Ticket_v_byts)
    # split the ticket
    K_c_v, ID_c, AD_c, ID_v, TS4_str, Lifetime4_str = plain_Ticket_v.split('||')
    # create DES for K_c_v
    # (may be used to encrypt the result of validation)
    DES_c_v = DES(K_c_v.encode(KEY_CHARSET))

    # parse timestamps
    TS4, Lifetime4 = (float(ts.rstrip('\0')) for ts in (TS4_str, Lifetime4_str))
    # validate Ticket_v by its TS4
    Ticket_v_validity = TicketValidity.validate(TS4, Lifetime4)
    # filter out any expired ticket
    if (not(Ticket_v_validity)):
        # encrypt an expiration message
        cipher_expire = DES_c_v.encrypt(TICKET_EXPIRED)
        # send expiration message
        server.send(cipher_expire)
        # listen for a new message
        return False
    # end if (now - TS2_1o >= Lifetime2_1o)

    return (Authenticator_c, DES_c_v)
# end def receive_service_request(server, charset, DES_v)


def parse_authenticator(DES_c_v, Authenticator_c):
    # decrypt Authenticator_c
    # 1st encode Authenticator_c to the key charset
    # this includes 0 bytes
    cipher_Authenticator_c_byts_untrim = Authenticator_c.encode(KEY_CHARSET)
    # trim last 0 bytes
    cipher_Authenticator_c_byts = bytes.rstrip(cipher_Authenticator_c_byts_untrim, b'\x00')
    # decrypt Authenticator_c
    plain_Authenticator_c = DES_c_v.decrypt(cipher_Authenticator_c_byts)
    # split Authenticator_c
    ID_c, AD_c, TS5_str = plain_Authenticator_c.split('||')
    # parse the timestamp TS5
    TS5 = float(TS5_str.rstrip('\0'))
    return TS5
# end def parse_authenticator(DES_c_v, Authenticator_c)


def send_service(server, DES_c_v, TS5):
    # send a message for successful authentication
    plain_success = f'{TS5 + 1}'
    cipher_success = DES_c_v.encrypt(plain_success)
    server.send(cipher_success)
# end def send_service(server, DES_c_v, TS5)


# run the server until SENTINEL is given
if __name__ == '__main__':
    main(NODE, SERVER)
# end if __name__ == '__main__'
