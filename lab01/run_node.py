
# standard libraries
import json
import logging
import traceback
from sys import stderr
from _thread import start_new_thread
from collections import namedtuple


# local library crypto
from crypto import KeyManager, DES, CharacterEncoder, bit2hex
from node import Node
from hmac import SimpleHmacEncoder, UnexpectedMac

# load configuration
config = json.load(open('config.json', 'r'))

# the keys for server configurations
SERVERS_CONFIG_DATA_KEYS = 'V_server, AS_TGS_server'.split(', ')
SERVER_DATA_KEYS = 'addr,port,charset'.split(',')
# named tuple to store server configuration
ServerData = namedtuple('ServerData', SERVER_DATA_KEYS)
# set up the configuration data for exporting
servers_config_data = {
    server: ServerData(*(config[server][key] for key in SERVER_DATA_KEYS))
        for server in SERVERS_CONFIG_DATA_KEYS }

# the keys for ode configurations
NODE_CONFIG_DATA_KEYS = 'V_server, AS_TGS_server, C_client'.split(', ')
NODE_DATA_KEYS = 'prompt, connecting_status'.split(', ')
# named tuple to store node configuration
NodeData = namedtuple('NodeData', NODE_DATA_KEYS)
# set up the configuration data for exporting
nodes_config_data = {
    node: NodeData(*(config[node][key] for key in NODE_DATA_KEYS))
        for node in NODE_CONFIG_DATA_KEYS }

# load name of files containing the keys
ENC_FILE, MAC_FILE = (
    config['node'][key] for key in ('enc_key_file', 'mac_key_file'))
# load string that ends the input stream
SENTINEL = config['node']['sentinel']

def receiveThread(node, des, decode, prompt):
    old_tb = None
    while True:
        try:
            # read in from the node
            msg_bytes = node.recv()
            # if empty message, skip
            if (len(msg_bytes) <= 0):
                continue
            # ignore any illegal bytes
            msg_bytes = bytes(b for b in msg_bytes if b in range(256))
            # decrypt the message
            try:
                dec_string = des.decrypt(msg_bytes, decode=decode)
                # log success
                print(file=stderr)
                print(file=stderr)
                logging.info("MAC authentication successful!")
                # log the message received
                logging.info(f'Received: {msg_bytes}')
                # print the decrypted message
                print('Decrypted: ', end='', file=stderr, flush=True)
                print(dec_string)
            except UnexpectedMac as e:
                # warn if unexpected MAC
                print(file=stderr)
                print(file=stderr)
                logging.warning(e)
                # log the message received
                logging.info(f'Received: {msg_bytes}')
            # try des.decrypt(...)
            # print new prompt
            print(file=stderr)
            print(file=stderr, end=prompt, flush=True)
        except Exception as e:
            tb = traceback.format_exc()
            # don't repeat the trackback
            if (tb != old_tb):
                print(file=stderr)
                logging.error(tb)
            old_tb = tb
            continue
    # end while True
# end def receiveThread(node, des, charset)

def main_ns(node_data, server_data, node_init: 'Callable[[addr, port], Node]'):
    '''
    Run the node until SENTINEL is input using the given configuration
    tuples.  Convenience function.
    This implementation handles the entire life cycle.
    '''
    return main(node_data.connecting_status, node_init,
        server_data.addr, server_data.port, server_data.charset,
        node_data.prompt)

def main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, charset: str, prompt: str):
    '''
    Run the node until SENTINEL is input using the given parameters.
    This implementation handles the entire life cycle.
    '''
    # configure the logger
    logging.basicConfig(level=logging.INFO)
    # create a node
    logging.info(f'{connecting_status} {addr}:{port} . . .')
    node = node_init(addr, port)
    # encode and send user input, decode messages received
    run_node(node, charset, prompt)
    # close the node
    node.close()
# end main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, charset: str, prompt: str)

# run the node until SENTINEL is given
def run_node(node: Node, charset: str, prompt: str):
    '''
    Runs an existing node.
    '''
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # read in the key word for encryption
    enc_key = KeyManager.read_key(ENC_FILE)
    # read in the key word for HMAC
    mac_key = KeyManager.read_key(MAC_FILE)
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(enc_key)

    # create the encoder
    # use the given charset
    charEncoder = CharacterEncoder(charset)
    # and use HMAC charset
    serverEncoder = SimpleHmacEncoder(charEncoder, mac_key)
    # fetch decode
    decode = serverEncoder.decode

    # start the receiving thread
    start_new_thread(receiveThread, (node, des, decode, prompt))

    while True:
        # TODO: your code here

        # accept user input until SENTINEL given
        msg_string = input(prompt)
        if msg_string == SENTINEL:
            break
        
        # TODO: your code here
        # encryption
        cyp_bytes = des.encrypt(msg_string, encode=serverEncoder.encode)
        # send the message
        logging.info(f'Sending cypher: {cyp_bytes}')
        node.send(cyp_bytes)
    # end while True
# end run_node(node: Node, charset: str, prompt: str)


def recv_blocking(node: Node) -> bytes:
    # initialize empty to start the loop
    msg_bytes = bytes()
    # read in from node until bytes are read
    while (not(msg_bytes)):
        msg_bytes = node.recv()
    return msg_bytes
# end def recv_blocking(node: Node) -> bytes