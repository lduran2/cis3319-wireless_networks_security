'''
This library is used to convert between ASCII to alphabetic encoding. 

The purpose of alphabetic encoding is to have all values encoded as a
sequence of uppercase letters.

Alphabetic characters in the source are left as is in alphabetic mode.

Z is the least common letter in the English alphabet, followed by Q. 
Thus the sequence ZQ is used to mark the beginning of an alphabetic
escape mode.

Within alphabetic escape mode, ASCII values are converted to base 25
(A-Y), allowing for 625 possible character encodings.

At the first instance of Z, the string enters alphabetic mode.

An intentional sequence of ZQ in the source will be marked up as
ZQDPDGZ.
'''

DEBUG_MODE = False

# ASCII range of alphabetic characters
ordA = ord('A')
ordZ = ord('Z')
rangeAZ = range(ordA, (ordZ + 1))
lenAZ = len(rangeAZ)

# ZQ marks beginning of alphabetic escape mode
ordQ = ord('Q')
# used to escape literal ZQ
ordD = ord('D')
ordG = ord('G')
ordP = ord('P')

def ords2alpha(ords):
    # flags that previous character was Z
    prevZ = False
    # flags that currently in escape mode (c.f. alphabetic mode)
    escape_mode = False

    for o in ords:
        # if in range A-Z, send the value as is
        if (o in rangeAZ):
            # if exiting escape mode, send Z to mark end
            if (escape_mode):
                yield ordZ
                # no longer escape mode
                escape_mode = False
            # if the previous, current character are 'ZQ',
            # then send the escape sequence, ZQDPDGZ
            if (DEBUG_MODE):
                print({'prevZ before': prevZ})
            if ((ordQ==o) and prevZ):
                yield ordQ
                yield ordD
                yield ordP
                yield ordD
                yield ordG
                yield ordZ
                prevZ = False
                continue
            # end if ((ordQ==o) and prevZ)
            # for any other letter return the value as is
            yield o
            prevZ = (ordZ==o)
            if (DEBUG_MODE):
                print({'prevZ after': prevZ})
        # end if (o in rangeAZ)
        else:
            # check not previously in escape mode, send 'ZQ'
            if (not(escape_mode)):
                yield ordZ
                yield ordQ
                escape_mode = True
            # compute the sequence for this character
            seq = divmod(o, (lenAZ - 1))
            if (DEBUG_MODE):
                print({'seq': prevZ})
            for L in seq:
                # send that each letter in sequence, framed in A-Z
                yield (L + ordA)
    # end for o in ords
    # exit escape mode if necessary
    if (escape_mode):
        yield ordZ
# end def ords2alpha(ords)

def alpha2ords(alpha):
    # flags that previous character was Z
    prevZ = False
    # flags that currently in escape mode (c.f. alphabetic mode)
    escape_mode = False
    # index within codes in escape mode
    i_code = 0
    # the accumulated ordinal code so far
    code_acc = 0
    for a in alpha:
        if (escape_mode):
            # if current character is Z, then exit escape mode
            if (ordZ==a):
                escape_mode = False
                continue
            # 0-index the alpha so 'A'=0
            a -= ordA
            if (1==i_code):
                # shift the previous code
                code_acc *= (lenAZ - 1)
                # add the current code
                code_acc += a
                yield code_acc
                # next character is odd
                i_code = 0
                continue
            # set accumulator to current character
            code_acc = a
            # next character is even
            i_code += 1
        # end if (escape_mode)
        else:
        # if in alphabetic mode
            # if previous character was Z
            if (prevZ):
                # if current character is Q
                if (ordQ==a):
                    prevZ = False
                    # go into escape mode
                    escape_mode = True
                    continue
                # otherwise, send both
                else:
                    yield ordZ
            # unless previous Z, hold if the current character is Z
            elif (ordZ==a):
                prevZ = True
                continue
            # send as is
            yield a
            prevZ = False
    # if there is a Z to send, send it
    # for a in alpha
    if (prevZ):
        yield ordZ
# end def alpha2ords(alpha)
