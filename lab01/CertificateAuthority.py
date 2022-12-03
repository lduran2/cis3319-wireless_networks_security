
# standard libraries
import logging
import time

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET
from run_node import SKca, split_rsa_key_pair
from crypto import KeyManager, DES
import rsa
from node import Node
from server import Server

# ID for this node
ID = "CIS3319CAID"

# corresponding section in configuration file
SECTION = 'CertificateAuthority'
# load server data
SERVER = servers_config_data[SECTION]
# load node data
NODE = nodes_config_data[SECTION]

# RSA(.) denotes RSA encryption with the specified public key
# DES(.) means DES encryption with the specified DES key
# Sign(.) is RSA signature generation with the specified private key


def respondCertification(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Certificate Authority server
    AD_c = f'{server_data.addr}:{server_data.port}'
    logging.info(f'{node_data.connecting_status} {AD_c} . . .')
    server = Server(server_data.addr, server_data.port)

    # (a) application server registration to obtain its public/private
    DES_tmpl, ID_s = receive_certificate_registration(server)
    send_certificate(server, DES_tmpl, ID_s)


def receive_certificate_registration(server):
    # (1Rx) S -> CA:    RSA[PKca][K_tmpl||ID_s||TS1]
    # receive the message
    cipher_msg = run_node.recv_blocking(server).decode(KEY_CHARSET)
    print(f'(a1) CA Received: {cipher_msg}')
    # decode the registration
    plain_msg = rsa.decode(*SKca, cipher_msg)
    # split it into its fields
    K_tmpl_str, ID_s, TS1 = plain_msg.split('||')
    # encode the key, and create its DES object
    K_tmpl_byts = K_tmpl_str.encode(KEY_CHARSET)
    DES_tmpl = DES(K_tmpl_byts)
    print(f'(a1) CA found key: {K_tmpl_byts}')
    print()
    return (DES_tmpl, ID_s)


def send_certificate(server, DES_tmpl, ID_s):
    # (2Tx) CA -> S:    DES[K_tmpl][PKs||SKs||Cert_s||ID_s||TS2] s.t.
    #       Cert_s = Sign[SKca][ID_s||ID_ca||PKs]
    # select a key for Application server AS
    key_s = rsa.selectKey()
    PKs, SKs = split_rsa_key_pair(key_s)
    # convert to strings
    PKs_str, SKs_str = (rsaKey2str(k) for k in (PKs, SKs))
    # create the certificate Cert_s
    Cert_s_plain = f'{ID_s}||{ID}||{PKs_str}'
    Cert_s_cipher = rsa.encode(*SKca, Cert_s_plain)
    # get a time stamp
    TS2 = time.time()
    # concatenate the message
    certificate_msg_plain = f'{PKs_str}||{SKs_str}||{Cert_s_cipher}||{ID_s}||{TS2}'
    certificate_msg_cipher = DES_tmpl.encrypt(certificate_msg_plain)
    print(f'(a2) CA encrypted: {certificate_msg_cipher}')
    print(''.join((f'(a2) CA generated: ', str({'PKs': PKs, 'SKs': SKs}))))
    print(f'(a2) CA signed: {Cert_s_cipher}')
    print()
    # send the message (already in bytes)
    server.send(certificate_msg_cipher)


def rsaKey2str(rsaKey):
    return (','.join(str(f) for f in rsaKey))


# run the server until SENTINEL is given
if __name__ == '__main__':
    respondCertification(NODE, SERVER)
# end if __name__ == '__main__'

