import time
from enum import Enum

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

