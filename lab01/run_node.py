
# standard libraries
import json
import logging
import traceback
from sys import stderr
from _thread import start_new_thread


# local library crypto
from crypto import KeyManager, DES, CharacterEncoder, bit2hex
from hmac import SimpleHmacEncoder

# load configuration
config = json.load(open('config.json', 'r'))

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
                logging.info("Authentication successful!")
                # log the message received
                logging.info(f'Received: {msg_bytes}')
                # print the decrypted message
                print('Decrypted: ', end='', file=stderr, flush=True)
                print(dec_string)
            except UnexpectedMac as e:
                # warn if unexpected MAC
                logging.warning(e)
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
# end def receiveThread(node, des, encoding)

# run the node until SENTINEL is given
def main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, encoding: str, prompt: str):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # create a node
    logging.info(f'{connecting_status} {addr}:{port} . . .')
    node = node_init(addr, port)
    # read in the key word for encryption
    enc_key = KeyManager.read_key(ENC_FILE)
    # read in the key word for HMAC
    mac_key = KeyManager().read_key(MAC_FILE)
    # generate the DES key for encryption
    # and reverse key for decryption
    des = DES(enc_key)

    # create the encoder
    # use the given encoding
    charEncoder = CharacterEncoder(encoding)
    # and use HMAC encoding
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

    # close the node
    node.close()
# end main(connecting_status: str, node_init: 'Callable[[addr, port], Node]', addr: str, port: int, encoding: str, prompt: str)
