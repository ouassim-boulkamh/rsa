from .AESencryptfunc import *
import math


def encrypt_file(plaintext_filename, cipherhex_filename, pass_phrase_file):
    file = open(pass_phrase_file, "r")
    pass_phrase = (file.read())
    file.close()

    if len(pass_phrase) < 16:
        while len(pass_phrase) != 16:
            pass_phrase = pass_phrase + "\00"
    if len(pass_phrase) > 16:
        pass_phrase = pass_phrase[0:16]

    file = open(plaintext_filename, "r")
    message = file.read()
    file.close()

    message = BitVector(textstring=message)
    message = message.get_bitvector_in_hex()
    replacementptr = 0
    while replacementptr < len(message):
        if message[replacementptr:replacementptr + 2] == '0a':
            message = message[0:replacementptr] + '0d' + message[replacementptr:len(message)]
            replacementptr = replacementptr + 4
        else:
            replacementptr = replacementptr + 2

    message = BitVector(hexstring=message)
    message = message.get_bitvector_in_ascii()
    start = 0
    end = 0
    length = len(message)
    loopmsg = math.ceil(length / 16) + 1

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

    fileout = open(cipherhex_filename, 'w')

    for y in range(1, loopmsg):
        if end + 16 < length:
            plaintextseg = message[start:end + 16]
        else:
            plaintextseg = message[start:length]
            for z in range(0, ((end + 16) - length), 1):
                plaintextseg = plaintextseg + "\00"

        bv1 = BitVector(textstring=plaintextseg)
        bv2 = pass_phrase
        resultbv = bv1 ^ bv2

        for x in range(1, 10):
            myhexstring = resultbv.get_bitvector_in_hex()
            temp1 = subbyte(myhexstring)
            temp2 = shiftrow(temp1)
            bv3 = BitVector(hexstring=temp2)
            newbvashex = mixcolumn(bv3)
            newbv = BitVector(hexstring=newbvashex)

            bv1 = BitVector(bitlist=newbv)
            bv2 = BitVector(hexstring=roundkeys[x - 1])
            resultbv = bv1 ^ bv2

        myhexstring = resultbv.get_bitvector_in_hex()
        temp1 = subbyte(myhexstring)
        temp2 = shiftrow(temp1)
        newbv = BitVector(hexstring=temp2)
        bv1 = BitVector(bitlist=newbv)
        bv2 = BitVector(hexstring=roundkeys[9])
        resultbv = bv1 ^ bv2

        outputhextemp = resultbv.get_hex_string_from_bitvector()
        fileout.write(outputhextemp)
        start = start + 16
        end = end + 16

    fileout.close()
