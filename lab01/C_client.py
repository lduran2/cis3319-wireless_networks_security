
# standard libraries
import logging
import time
from sys import stderr

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET
from crypto import KeyManager, DES
from client import Client
from ticket import TICKET_EXPIRED
from AS_TGS_server import ID as ID_tgs
from V_server import ID as ID_v


# ID for this node
ID = 'CIS3319USERID'

# corresponding section in configuration file
SECTION = 'C_client'
# split data for both V_server and AS_TGS_server
V_SERVER, AS_TGS_SERVER, CERTIFICATE_AUTHORITY = (
    servers_config_data[server] for server in 'V_server, AS_TGS_server, CertificateAuthority'.split(', '))
# load client data
CLIENT = nodes_config_data[SECTION]


def requestServers(client_data, cauth_data, atgs_data, v_server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # request the Kerberos authetication
    is_kerberos_authenticated = requestKerberos(client_data, atgs_data, v_server_data)
    # stop if not authenticated
    if (not(kerberos_authentication)):
        return
    # otherwise, this fetch the client and its DES key
    vClient, DES_c_v = kerberos_authentication

    # encrypt and send user input, decrypt messages received
    # use DES_c_v as the DES encrypter, not enc_key
    run_node.run_node(vClient, DES_c_v, v_server_data.charset, client_data.prompt)
    # close the chat client
    vClient.close()
# end def requestServers()


def requestKerberos(client_data, atgs_data, v_server_data):
    # create the Kerberos client
    AD_c_tsg = f'{atgs_data.addr}:{atgs_data.port}'
    logging.info(f'{client_data.connecting_status} {AD_c_tsg} . . .')
    atgsClient = Client(atgs_data.addr, atgs_data.port)

    # (a) authentication service exchange to obtain ticket granting-ticket
    request_ticket_granting_ticket(atgsClient, atgs_data.charset)
    DES_c_tgs, Ticket_tgs = receive_ticket_granting_ticket(atgsClient)

    # (b) ticket-granting service exchange to obtain service-granting ticket
    request_with_authenticator(atgsClient, atgs_data.charset, ID_v, Ticket_tgs, DES_c_tgs, AD_c_tsg)
    # check if the ticket-granting ticket was valid
    print('(b4)')
    sgt = receive_from_ticket(atgsClient, DES_c_tgs, ID_tgs)
    print()
    if (not(sgt)):
        return False
    DES_c_v, Ticket_v = parse_service_granting_ticket(sgt)

    # end connection with AS/TGS
    atgsClient.close()

    # create the chat client
    print(file=stderr)
    logging.info(f'{client_data.connecting_status} {v_server_data.addr}:{v_server_data.port} . . .')
    vClient = Client(v_server_data.addr, v_server_data.port)

    # (c) client/server authentication exchange to obtain service
    request_with_authenticator(vClient, v_server_data.charset, '', Ticket_v, DES_c_v, AD_c_tsg)
    # check if the service-granting ticket was valid
    print('(c6)')
    service = receive_from_ticket(vClient, DES_c_v, ID_v)
    # print label for the message
    print('= (TS5 + 1)')
    print()
    if (not(service)):
        return False

    return (vClient, DES_c_v)
# end def requestKerberos(client_data, atgs_data, v_server_data)


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
    # log the message received
    logging.info(f'(a2) C Received: {msg_bytes}')
    # print the decrypted message
    print(f'(a2) C Decrypted: {msg_chars}')
    print()
    # split the message
    K_c_tgs, ID_tgs, TS2, Lifetime2, Ticket_tgs = msg_chars.split('||')
    # create DES for K_c_tgs
    DES_c_tgs = DES(K_c_tgs.encode(KEY_CHARSET))
    return (DES_c_tgs, Ticket_tgs)
# end def receive_ticket_granting_ticket(client)


def request_with_authenticator(client, charset, next_server_ID, Ticket, des_shared_c, AD_c_tsg):
    # (3Tx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c
    # (5Tx) C -> V: Ticket_v || Authenticator_c
    # get a time stamp
    TS = time.time()

    # create the authenticator
    plain_Authenticator_c = f'{ID}||{AD_c_tsg}||{TS}'
    # encrypt the authenticator
    cipher_Authenticator_c_byts = des_shared_c.encrypt(plain_Authenticator_c)
    # convert to string
    cipher_Authenticator_c_str = cipher_Authenticator_c_byts.decode(KEY_CHARSET)

    # add separator on next destination, if there is one
    next_dest_sep = f'{next_server_ID}||' if (next_server_ID) else ''
    # concatenate the message
    Ticket_client_auth = f'{next_dest_sep}{Ticket}||{cipher_Authenticator_c_str}'
    # send the client authentication message
    Ticket_client_auth_bytes = Ticket_client_auth.encode(charset)
    client.send(Ticket_client_auth_bytes)
# end request_with_authenticator(client, charset, next_server_ID, Ticket, des_shared_c, AD_c_tsg)


def receive_from_ticket(client, des_shared_c, prompt):
    # (3'Rx)
    # (5'Rx)

    # receive the message
    msg_bytes = run_node.recv_blocking(client)
    # check if expired
    # decrypt the message
    msg_chars = des_shared_c.decrypt(msg_bytes)
    # log the message received
    logging.info(f'C Received: {msg_bytes}')
    # print the decrypted message
    print(f'C Decrypted: {msg_chars}')
    if (TICKET_EXPIRED==msg_chars):
        return False

    # return the message if ticket is valid
    return msg_chars
# end def receive_from_ticket(client, des_shared_c)


def parse_service_granting_ticket(sgt):
    # (4Rx) TGS -> C:   E(K_c_tgs, [K_c_v || ID_v || TS4 || Ticket_v])
    # split the message
    K_c_v, ID_v, TS4, Ticket_v = sgt.split('||')
    # create DES for K_c_v
    DES_c_v = DES(K_c_v.encode(KEY_CHARSET))
    return (DES_c_v, Ticket_v)
# end def parse_service_granting_ticket(sgt)


# run the client until SENTINEL is given
if __name__ == '__main__':
    requestServers(CLIENT, CERTIFICATE_AUTHORITY, AS_TGS_SERVER, V_SERVER)
# end if __name__ == '__main__'
