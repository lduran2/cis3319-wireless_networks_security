
# standard libraries
import logging
import traceback
from sys import stderr
from _thread import start_new_thread


# local library crypto
from crypto import KeyManager, DES, bit2hex
from node import Node

# name of file containing the key
KEY_FILE = 'key.txt'
# ends the input stream
SENTINEL = 'exit'

def receiveThread(node, des, charset, prompt):
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
            dec_string = des.decrypt(msg_bytes, encoding=charset)
            # log the message received
            print(file=stderr)
            print(file=stderr)
            logging.info(f'Received: {msg_bytes}')
            # print the decrypted message
            print('Decrypted: ', end='', file=stderr, flush=True)
            print(dec_string)
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

# run the node until SENTINEL is given
def main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, charset: str, prompt: str):
    '''
    Run the node until SENTINEL is input using the given parameters.
    This implementation handles the node's entire life cycle from
    allocation to closing.
    '''
    # configure the logger
    logging.basicConfig(level=logging.INFO)
    # create a node
    logging.info(f'{connecting_status} to {addr}:{port} . . .')
    node = node_init(addr, port)
    # encode and send user input, decode messages received
    run_node(node, charset, prompt)
    # close the node
    node.close()
# end main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, charset: str, prompt: str)

def run_node(node: Node, charset: str, prompt: str):
    '''
    Runs an existing node until SENTINEL is read from standard input.
    '''
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # read in the key word
    key = KeyManager.read_key(KEY_FILE)
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(key)

    # start the receiving thread
    start_new_thread(receiveThread, (node, des, charset, prompt))

    while True:
        # TODO: your code here

        # accept user input until SENTINEL given
        msg_string = input(prompt)
        if msg_string == SENTINEL:
            break
        
        # TODO: your code here
        # encryption
        cyp_bytes = des.encrypt(msg_string, encoding=charset)
        # send the message
        logging.info(f'Sending cypher: {cyp_bytes}')
        node.send(cyp_bytes)
    # end while True

# end run_node(node: Node, charset: str, prompt: str)
