
# standard libraries
import logging
import time
from sys import stderr

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET
from run_node import PKca
from crypto import KeyManager, DES
import rsa
from client import Client
from ticket import TICKET_EXPIRED
from AS_TGS_server import ID_ker as ID_tgs, ID_pki as ID_s
from V_server import ID as ID_v


# ID for this node in Kerberos
ID_ker = 'CIS3319USERID'
# ID for this node in PKI
ID_pki = 'ID-Client'


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

    # create the Kerberos client
    AD_c_tsg = f'{atgs_data.addr}:{atgs_data.port}'
    logging.info(f'{client_data.connecting_status} {AD_c_tsg} . . .')
    atgsClient = Client(atgs_data.addr, atgs_data.port)

    requestClientRegistrationService(atgsClient)

    return

    # request the Kerberos authetication
    is_kerberos_authenticated = requestKerberos(atgsClient, client_data.connecting_status, atgs_data, v_server_data)
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


#######################################################################
# PKI-based authentication
#######################################################################

def requestClientRegistrationService(client):
    # (b) client registration: to obtain session key for further
    # communication
    request_server_public_key_certificate(client)
    PKs, Cert_s = send_public_key_certificate(client)
    DES_tmp2 = send_registration_information(client, Cert_s, PKs)
    DES_sess = receive_session_key(client, DES_tmp2)


def request_server_public_key_certificate(client):
    # (3Tx) C -> S:     ID_s||TS3
    # get a time stamp
    TS3 = time.time()
    # create the registration
    plain_client_registration = f'{ID_s}||{TS3}'
    print(f'(b3) C sending: {plain_client_registration}')
    print()
    # encode and send the message
    client.send(plain_client_registration.encode(KEY_CHARSET))


def send_public_key_certificate(client):
    # (4Rx): S -> C:    PKs||Cert_s||TS4
    msg = run_node.recv_blocking(client).decode(KEY_CHARSET)
    print(f'(b4) C Received: {msg}')
    print()
    # split the messge
    PKs_str, Cert_s, TS4 = msg.split('||')
    # parse keys
    PKs = rsa.str2key(PKs_str)
    return (PKs, Cert_s)


def send_registration_information(client, Cert_s, PKs):
    # (5Tx): C -> S:    RSA[PKs][K_tmp2||ID_c||IP_c||Port_c||TS5]
    validate_certificate(Cert_s, PKs)
    # create temporary key
    K_tmp2_byts = KeyManager().generate_key()
    K_tmp2_str = K_tmp2_byts.decode(KEY_CHARSET)
    # create its DES object
    DES_tmp2 = DES(K_tmp2_byts)
    # get a time stamp
    TS5 = time.time()
    # create the registration information
    plain_registration_info = f'{K_tmp2_str}||{ID_pki}||{client.node.addr}||{client.node.port}||{TS5}'
    # encode the registration inormation using PKs
    cipher_registration_info = rsa.encode(*PKs, plain_registration_info)
    print(f'(b5) C sending: {plain_registration_info}')
    print(f'(b5) C encoded: {cipher_registration_info}')
    print(f'(b5) C generated: {K_tmp2_byts}')
    print()
    # encode and send the message
    client.send(cipher_registration_info.encode(KEY_CHARSET))
    return DES_tmp2


def validate_certificate(Cert_s, PKs):
    # note: Cert_s = Sign[SKca][ID_s||ID_ca||PKs]
    # verify the PKs and Cert_s
    # first decode Cert_s
    plain_Cert_s = rsa.decode(*PKca, Cert_s)
    # split the certificate
    ID_s_rx, ID_ca, PKs_rx_str = plain_Cert_s.split('||')
    # compare the 2 ID_s values
    if (ID_s_rx != ID_s):
        raise IncorrectServerIdentity(f'expected: {ID_s};  certificate gave: {ID_s_rx}')
    # compare the two public keys
    PKs_rx = rsa.str2key(PKs_rx_str)
    if (PKs_rx != PKs):
        raise IncorrectPublicKey(f'expected: {PKs};  server {ID_s} gave: {PKs_rx}')


def receive_session_key(client, DES_tmp2):
    # (6Tx) S -> C:     DES[K_tmp2][K_sess||Lifetime_sess||ID_c||TS6]
    # receive the message
    cipher_msg = run_node.recv_blocking(client)
    print(f'(b6) C Received: {cipher_msg}')
    # decrypt the registration
    plain_msg = DES_tmp2.decrypt(cipher_msg)
    # split it into its fields
    K_sess_str, Lifetime_sess, IP_c, TS6 = plain_msg.split('||')
    # encode the key, and create its DES object
    K_sess_byts = K_sess_str.encode(KEY_CHARSET)
    DES_sess = DES(K_sess_byts)
    print(f'(b6) S found key: {K_sess_byts}')
    print()
    return DES_sess


class IncorrectServerIdentity(Exception):
    '''
    Thrown when a certificate has the incorrect server ID.
    '''


class IncorrectPublicKey(Exception):
    '''
    Thrown when a received the incorrect server ID.
    '''


#######################################################################
# Kerberos
#######################################################################

def requestKerberos(atgsClient, connecting_status, atgs_data, v_server_data):
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
    logging.info(f'{connecting_status} {v_server_data.addr}:{v_server_data.port} . . .')
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
# end def requestKerberos(connecting_status, atgs_data, v_server_data)


def request_ticket_granting_ticket(client, atgs_charset):
    # (1Tx) C -> AS:  ID_c || ID_tgs || TS1
    # get a time stamp
    TS1 = time.time()
    # create the client authentication
    client_auth = f'{ID_ker}||{ID_tgs}||{TS1}'
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
    plain_Authenticator_c = f'{ID_ker}||{AD_c_tsg}||{TS}'
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
