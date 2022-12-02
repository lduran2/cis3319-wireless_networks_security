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
    prev_alpha = True
    prevZ = False
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
            if (('Q'==o) and prevZ):
                yield ordQ
                yield ordD
                yield ordP
                yield ordD
                yield ordG
                yield ordZ
                prevZ = False
                continue
            # end if (('Q'==o) and prevZ)
            # for any other letter return the value as is
            yield o
            prevZ = ('Z'==o)
        # end if (o in rangeAZ)
        else:
            # check not previously in escape mode, send 'ZQ'
            if (not(escape_mode)):
                yield ordZ
                yield ordQ
                escape_mode = True
            # compute the sequence for this character
            seq = divmod(o, (lenAZ - 1))
            print(seq)
            for L in seq:
                # send that each letter in sequence, framed in A-Z
                yield (L + ordA)
    # end for o in ords
    # exit escape mode if necessary
    if (escape_mode):
        yield ordZ
# end def ords2alpha(ords)
