
# standard libraries
import logging
import time

# local library crypto
import run_node
from run_node import servers_config_data, nodes_config_data, config, KEY_CHARSET
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

def respondCertification(node_data, server_data):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create the Certificate Authority server
    AD_c = f'{server_data.addr}:{server_data.port}'
    logging.info(f'{node_data.connecting_status} {AD_c} . . .')
    server = Server(server_data.addr, server_data.port)


# run the server until SENTINEL is given
if __name__ == '__main__':
    respondCertification(NODE, SERVER)
# end if __name__ == '__main__'

