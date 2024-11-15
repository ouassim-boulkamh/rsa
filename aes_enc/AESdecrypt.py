from .AESdecryptfunc import *
import math


def decrypt_file(cipherhex_filename, plaintext_filename, pass_phrase_file):
    file = open(pass_phrase_file, "r")
    pass_phrase = (file.read())
    file.close()

    if len(pass_phrase) < 16:
        while len(pass_phrase) != 16:
            pass_phrase = pass_phrase + "\00"
    if len(pass_phrase) > 16:
        pass_phrase = pass_phrase[0:16]

    file = open(cipherhex_filename, "r")
    message = file.read()
    file.close()

    start = 0
    end = 32
    length = len(message)
    loopmsg = math.ceil(length / 32) + 1

    pass_phrase = BitVector(textstring=pass_phrase)
    roundkey1 = findroundkey(pass_phrase.get_bitvector_in_hex(), 1)
    roundkey2 = findroundkey(roundkey1, 2)
    roundkey3 = findroundkey(roundkey2, 3)
    roundkey4 = findroundkey(roundkey3, 4)
    roundkey5 = findroundkey(roundkey4, 5)
    roundkey6 = findroundkey(roundkey5, 6)
    roundkey7 = findroundkey(roundkey6, 7)
    roundkey8 = findroundkey(roundkey7, 8)
    roundkey9 = findroundkey(roundkey8, 9)
    roundkey10 = findroundkey(roundkey9, 10)
    roundkeys = [roundkey1, roundkey2, roundkey3, roundkey4, roundkey5, roundkey6, roundkey7, roundkey8, roundkey9,
                 roundkey10]

    fileout = open(plaintext_filename, 'w', encoding='utf-8')

    for y in range(1, loopmsg):
        plaintextseg = message[start:end]

        bv1 = BitVector(hexstring=plaintextseg)
        bv2 = BitVector(hexstring=roundkeys[9])
        resultbv = bv1 ^ bv2
        myhexstring = resultbv.get_bitvector_in_hex()
        myhexstring = invshiftrow(myhexstring)
        myhexstring = invsubbyte(myhexstring)

        for x in range(8, -1, -1):
            bv1 = BitVector(hexstring=myhexstring)
            bv2 = BitVector(hexstring=roundkeys[x])
            resultbv = bv1 ^ bv2
            myhexstring = resultbv.get_bitvector_in_hex()
            bv3 = BitVector(hexstring=myhexstring)
            myhexstring = invmixcolumn(bv3)
            myhexstring = invshiftrow(myhexstring)
            myhexstring = invsubbyte(myhexstring)

        bv1 = BitVector(hexstring=myhexstring)
        bv2 = pass_phrase
        resultbv = bv1 ^ bv2
        myhexstring = resultbv.get_bitvector_in_hex()

        start = start + 32
        end = end + 32

        replacementptr = 0
        while replacementptr < len(myhexstring):
            if myhexstring[replacementptr:replacementptr + 2] == '0d':
                myhexstring = myhexstring[0:replacementptr] + myhexstring[replacementptr + 2:len(myhexstring)]
            else:
                replacementptr = replacementptr + 2

        outputhex = BitVector(hexstring=myhexstring)
        asciioutput = outputhex.get_bitvector_in_ascii()
        asciioutput = asciioutput.replace('\x00', '')
        fileout.write(asciioutput)
    fileout.close()
