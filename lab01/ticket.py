import time
from enum import Enum
import logging

# local library run_node
import run_node
from run_node import KEY_CHARSET
from crypto import DES

# expired ticket message
TICKET_EXPIRED = "This ticket has expired."


class TicketValidity(Enum):
    VALID = True
    NOT_VALID = False
    
    def __bool__(self):
        return self.value
    
    @staticmethod
    def valueOf(_is):
        return (TicketValidity.VALID if _is else TicketValidity.NOT_VALID)

    @staticmethod
    def validate(timestamp, lifetime):
        # get the current time
        now = time.time()
        # filter out any expired ticket
        return TicketValidity.valueOf(now - timestamp < lifetime)

def receive_ticket(server, charset, des_server):
    # configure the logger
    logging.basicConfig(level=logging.INFO)

    # (3Rx) C -> TGS: ID_v || Ticket_tgs || Authenticator_c
    # (5Rx) C -> V: Ticket_v || Authenticator_c

    # receive the message
    msg_bytes = run_node.recv_blocking(server)
    # decode the message
    msg_chars = msg_bytes.decode(charset)
    # log the message received
    logging.info(f'Received: {msg_bytes}')
    # print the decrypted message
    print(f'Decrypted: {msg_chars}')
    print()

    # split the message
    message_split = msg_chars.split('||')
    # [-2:-1] are [Ticket, Authenticator_c]
    cipher_Ticket_chars, Authenticator_c = (message_split[k] for k in range(-2,0))
    # if > 3 fields, then [0] is next server
    next_server_ID = (message_split[0] if (len(message_split) >= 3) else '')

    # decrypt the Ticket
    # 1st encode the ticket to the key charset
    # this includes 0 bytes
    cipher_Ticket_byts_untrim = cipher_Ticket_chars.encode(KEY_CHARSET)
    # trim last 0 bytes
    cipher_Ticket_byts = bytes.rstrip(cipher_Ticket_byts_untrim, b'\x00')
    # decrypt the ticket
    plain_Ticket = des_server.decrypt(cipher_Ticket_byts)
    # split the ticket
    K_shared_c, ID_c, AD_c, server_ID, TS_str, Lifetime_str = plain_Ticket.split('||')
    # create DES for key shared between C, this server
    DES_shared_c = DES(K_shared_c.encode(KEY_CHARSET))

    # parse timestamps
    TS, Lifetime = (float(ts.rstrip('\0')) for ts in (TS_str, Lifetime_str))
    # validate Ticket by its TS
    Ticket_validity = TicketValidity.validate(TS, Lifetime)
    # print the validity
    print(f'The ticket is {Ticket_validity}')
    print()

    # filter out any expired ticket
    if (not(Ticket_validity)):
        # encrypt an expiration message
        cipher_expire = DES_shared_c.encrypt(TICKET_EXPIRED)
        # send expiration message
        server.send(cipher_expire)
        # listen for a new message
        return False
    # end if (now - TS2 >= Lifetime2)

    return (next_server_ID, Authenticator_c, DES_shared_c, ID_c)
# end def receive_ticket(server, charset, des_server)
