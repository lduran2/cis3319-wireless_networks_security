
# standard libraries
import logging
import time
from _thread import start_new_thread
import traceback
from sys import stderr
from os import urandom

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET, SENTINEL
from run_node import PKca
from crypto import KeyManager, DES
import rsa
from node import Node
from client import Client
from server import Server
from ticket import receive_ticket


# debug modes
FAIL_TS2 = False
FAIL_TS4 = False


# ID for this node in Kerberos
ID_ker = 'CIS3319TGSID'
# ID for this node in PKI
ID_pki = 'ID-Server'

# services provided
MEMO_REQ = 'memo'

# the service data requested
MEMO_DATA = 'take cis3319 class this morning'

# corresponding section in configuration file
SECTION = 'AS_TGS_server'
# load this server's data
ASTGS = servers_config_data[SECTION]
# load the certification authority's data
CAUTH = servers_config_data['CertificateAuthority']
# load node data
NODE = nodes_config_data[SECTION]

# size for DES keys
DES_KEY_SIZE = 8

# named keys for Lifetimes
SESS = 'SESS'
# the lifetimes of tickets
Lifetimes = {
    2: 60.0, 4: 86400.0,
    SESS: 86400.0
} # [in seconds]

EXIT_INSTRUCTION = f'Type "{SENTINEL}" to exit: '


def serveApplication(client_data, cauth_data, atgs_data):
    requestCertificate(client_data, cauth_data, atgs_data)
    return
    respondKerberos(client_data, atgs_data)


def clientRegistrationThread(atgsServer, callback, callback_args):
    old_tb = None
    print(end=EXIT_INSTRUCTION, flush=True)
    # loop indefinitely
    while True:
        try:
            print()
            print()
            callback(*callback_args)

            # repeat the exit instruction
            print(end=EXIT_INSTRUCTION, flush=True)
            # accept next connection
            atgsServer.acceptNextConnection()
        except Exception as e:
            tb = traceback.format_exc()
            # don't repeat the trackback
            if (tb != old_tb):
                print(file=stderr)
                logging.error(tb)
            old_tb = tb
            print(end=EXIT_INSTRUCTION, flush=True)
    # end while True


#######################################################################
# PKI-based authentication
#######################################################################

def requestCertificate(client_data, cauth_data, atgs_data):
    # create the Certificate Authority client
    AD_s_ca = f'{cauth_data.addr}:{cauth_data.port}'
    logging.info(f'connecting to {AD_s_ca} . . .')
    caClient = Client(cauth_data.addr, cauth_data.port)

    try:
        # (a) application server registration to obtain its public/private
        # key pair and certificate
        DES_tmpl = register_with_certificate_authority(caClient)
        PKs, SKs, Cert_s = receive_certificate(caClient, DES_tmpl)
    finally:
        # close the node
        caClient.close()

    AD_c = f'{atgs_data.addr}:{atgs_data.port}'
    logging.info(f'{client_data.connecting_status} {AD_c} . . .')
    atgsServer = Server(atgs_data.addr, atgs_data.port)

    # listen for new client registrations
    start_new_thread(clientRegistrationThread,
        (atgsServer, clientRegistrationCallback,
            (atgsServer, PKs, SKs, Cert_s, atgs_data.charset, AD_c)))

    while True:
        # TODO: your code here

        # accept user input until SENTINEL given
        msg_string = input()
        if msg_string == SENTINEL:
            break

    # close the node
    atgsServer.close()


def clientRegistrationCallback(atgsServer, PKs, SKs, Cert_s, charset, AD_c):
    print('###############################################################')
    print('# PKI-based authentication')
    print('###############################################################')

    # (b) client registration: to obtain session key for further
    # communication
    receive_public_key_certificate_request(atgsServer)
    send_public_key_certificate(atgsServer, PKs, Cert_s)
    DES_tmp2, ID_c = receive_registration_information(atgsServer, SKs)
    DES_sess = send_session_key(atgsServer, DES_tmp2, ID_c)

    # (c) service request: to obtain application data
    req = receive_service_data_request(atgsServer, DES_sess)
    # if the request is incorrect, stop 
    if (MEMO_REQ != req):
        raise
    send_service_data(atgsServer, DES_sess)

    # DES_sess is the key DES_c for the Kerberos
    # get the other keys too
    DES_tgs, DES_v = kerberos_keys()

    # repeat exit message while waiting for kerberos
    print(end=EXIT_INSTRUCTION)
    print()
    print()
    kerberosCallback(atgsServer, charset, DES_sess, DES_tgs, DES_v, AD_c)


def register_with_certificate_authority(client):
    # (1Tx) S -> CA:    RSA[PKca][K_tmpl||ID_s||TS1]
    # create temporary key
    K_tmpl_byts = KeyManager().generate_key()
    K_tmpl_str = K_tmpl_byts.decode(KEY_CHARSET)
    # create its DES object
    DES_tmpl = DES(K_tmpl_byts)
    # get a time stamp
    TS1 = time.time()
    # create the registration
    plain_cert_registration = f'{K_tmpl_str}||{ID_pki}||{TS1}'
    # encode the registration
    cipher_cert_registration = rsa.encode(*PKca, plain_cert_registration)
    print(f'(a1) S encoded: {cipher_cert_registration}')
    print(f'(a1) S generated: {K_tmpl_byts}')
    print()
    # encode and send the message
    client.send(cipher_cert_registration.encode(KEY_CHARSET))
    return DES_tmpl


def receive_certificate(client, DES_tmpl):
    # (2Rx) CA -> S:    DES[K_tmpl][PKs||SKs||Cert_s||ID_s||TS2] s.t.
    #       Cert_s = Sign[SKca][ID_s||ID_ca||PKs]
    # receive the DES message
    msg_cipher = run_node.recv_blocking(client)
    print(f'(a2) S Received encrypted: {msg_cipher}')
    # decrypt the message
    msg_chars = DES_tmpl.decrypt(msg_cipher)
    # split the messge
    PKs_str, SKs_str, Cert_s_cipher, ID_s, TS2 = msg_chars.split('||')
    # parse keys
    PKs = rsa.str2key(PKs_str)
    SKs = rsa.str2key(SKs_str)
    print(''.join((f'(a2) S found keys: ', str({'PKs': PKs, 'SKs': SKs}))))
    print(f'(a2) S found certificate: {Cert_s_cipher}')
    print()
    return (PKs, SKs, Cert_s_cipher)


def receive_public_key_certificate_request(server):
    # (3Rx): C -> S:     ID_s||TS3
    msg = run_node.recv_blocking(server).decode(KEY_CHARSET)
    print(f'(b3) S Received: {msg}')
    print()

def send_public_key_certificate(server, PKs, Cert_s):
    # (4Tx): S -> C:    PKs||Cert_s||TS4
    # get a time stamp
    TS4 = time.time()
    # convert the key to string
    PKs_str = rsa.key2str(PKs)
    # create the message
    plain_key_cert = f'{PKs_str}||{Cert_s}||{TS4}'
    print(f'(b4) S sending: {plain_key_cert}')
    print()
    # encode and send the message
    server.send(plain_key_cert.encode(KEY_CHARSET))


def receive_registration_information(server, SKs):
    # (5Rx): C -> S:    RSA[PKs][K_tmp2||ID_c||IP_c||Port_c||TS5]
    # receive the message
    cipher_msg = run_node.recv_blocking(server).decode(KEY_CHARSET)
    print(f'(b5) S Received: {cipher_msg}')
    # decode the registration
    plain_msg = rsa.decode(*SKs, cipher_msg)
    # split it into its fields
    K_tmp2_str, ID_c, IP_c, Port_c, TS5 = plain_msg.split('||')
    # encode the key, and create its DES object
    K_tmp2_byts = K_tmp2_str.encode(KEY_CHARSET)
    DES_tmp2 = DES(K_tmp2_byts)
    print(f'(b5) S found key: {K_tmp2_byts}')
    print()
    return (DES_tmp2, ID_c)


def send_session_key(server, DES_tmp2, ID_c):
    # (6Tx) S -> C:     DES[K_tmp2][K_sess||Lifetime_sess||ID_c||TS6]
    # create session key
    K_sess_byts = KeyManager().generate_key()
    K_sess_str = K_sess_byts.decode(KEY_CHARSET)
    # create its DES object
    DES_sess = DES(K_sess_byts)
    # get a time stamp
    TS6 = time.time()
    # assemble the session key message
    plain_session_key_msg = f'{K_sess_str}||{Lifetimes[SESS]}||{ID_c}||{TS6}'
    cipher_session_key_msg = DES_tmp2.encrypt(plain_session_key_msg)
    print(f'(b6) S encrypted: {cipher_session_key_msg}')
    print(f'(b6) S generated: {K_sess_byts}')
    print()
    server.send(cipher_session_key_msg)
    return DES_sess


def receive_service_data_request(server, DES_sess):
    # (7Rx) C -> S:     DES[K_sess][req||TS7]
    # receive the message
    cipher_msg = run_node.recv_blocking(server)
    print(f'(c7) S Received: {cipher_msg}')
    # decrypt the registration
    plain_msg = DES_sess.decrypt(cipher_msg)
    # split it into its fields
    req, TS7 = plain_msg.split('||')
    print(f'(c7) S decrypted: {req}')
    print()
    return req


def send_service_data(server, DES_sess):
    # (8Tx) S -> C:     DES[K_sess][data||TS8]
    # get a time stamp
    TS8 = time.time()
    # assemble the session request
    plain_request = f'{MEMO_DATA}||{TS8}'
    cipher_request = DES_sess.encrypt(plain_request)
    print(f'(c8) S encrypted: {cipher_request}')
    print()
    server.send(cipher_request)


class BadRequest(Exception):
    '''
    Thrown when a client makes an invalid request.
    '''


#######################################################################
# Kerberos
#######################################################################

def respondKerberos(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Kerberos server
    AD_c = f'{server_data.addr}:{server_data.port}'
    logging.info(f'{node_data.connecting_status} {AD_c} . . .')
    server = Server(server_data.addr, server_data.port)

    # read the default client key
    DES_c = DES(KeyManager.read_key(config['kerberos_keys']['Kc_file']))
    # get the other keys too
    DES_tgs, DES_v = kerberos_keys()

    # listen for new client registrations
    start_new_thread(clientRegistrationThread, (server, server_data.charset, DES_c, DES_tgs, DES_v, AD_c))

    while True:
        # TODO: your code here

        # accept user input until SENTINEL given
        msg_string = input()
        if msg_string == SENTINEL:
            break

    # close the node
    server.close()
# end def respondKerberos(node_data, server_data)


def kerberosCallback(server, charset, DES_c, DES_tgs, DES_v, AD_c):
    print('###############################################################')
    print('# Kerberos')
    print('###############################################################')

    serve_authentication(server, charset, DES_c, DES_tgs, AD_c)
    serve_ticket_granting(server, charset, DES_tgs, DES_v, AD_c)
# end def respondKerberos(node_data, server_data)


def kerberos_keys():
    # read each key
    # and create DES for Ktgs and Kv
    DES_tgs, DES_v = (DES(KeyManager.read_key(config['kerberos_keys'][file]))
        for file in 'K_tgs_file, Kv_file'.split(', '))
    return (DES_tgs, DES_v)

def serve_authentication(server, charset, DES_c, DES_tgs, AD_c):
    # (a) authentication service exchange to obtain ticket granting-ticket
    ID_c = receive_ticket_granting_ticket_request(server, charset)
    send_ticket_granting_ticket(server, DES_c, DES_tgs, ID_c, AD_c)
# end def serve_authentication(server, charset, DES_c, DES_tgs, AD_c)


def serve_ticket_granting(server, charset, DES_tgs, DES_v, AD_c):
    # (b) ticket-granting service exchange to obtain service-granting ticket
    # check for service-granting ticket request with valid ticket
    print('(b3) TGS acting . . .')
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
    # log the message received
    logging.info(f'(a1) AS Received: {msg_bytes}')
    # print the decoded message
    print(f'(a1) AS Decoded: {msg_chars}')
    print()
    # split the message
    ID_c, ID_tgs, TS1 = msg_chars.split('||')
    return ID_c
# end def receive_ticket_granting_ticket_request(server, charset)


def send_ticket_granting_ticket(server, DES_c, DES_tgs, ID_c, AD_c):
    # (2Tx) AS -> C:    E(Kc, [K_c_tgs || ID_tgs || TS2 || Lifetime2 || Ticket_tgs])
    K_c_tgs_chars, TS2, Ticket_tgs = create_ticket(server, DES_tgs, ID_c, AD_c, ID_ker, FAIL_TS2, Lifetimes[2])
    # concatenate the message
    plain_shared_key_ticket = f'{K_c_tgs_chars}||{ID_ker}||{TS2}||{Lifetimes[2]}||{Ticket_tgs}'
    # encrypt the message
    cipher_shared_key_ticket = DES_c.encrypt(plain_shared_key_ticket)
    # send it
    server.send(cipher_shared_key_ticket)
# end def send_ticket_granting_ticket(server, ID_c, AD_c)


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
    serveApplication(NODE, CAUTH, ASTGS)
# end if __name__ == '__main__'

