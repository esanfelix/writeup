# from pwntools import *
import struct

u32 = lambda x: struct.unpack("<I", x)[0]

def parse_l1(value):
    typ = value & 3

    desc = ""
    if typ == 0:
        return "FAULT"
    elif typ == 1:
        desc += "TBL"
    elif typ == 2:
        desc +="NO_PXN "
    elif typ == 3:
        desc += "PXN"


    if ((value >> 18) & 1):
        desc += " SUPER "
    else:
        desc += " SECT "

    desc += " PA 0x%.8x " % ((value >> 20) << 20)

    ap = (((value >> 15) & 1) << 2) | ((value >> 10) & 3)

    if ap == 0:
        desc += "NO_ACCESS "
    elif ap == 1:
        desc += "RW_PL1 "
    elif ap == 2:
        desc += "RW_PL1 RO_PL0 "
    elif ap == 3:
        desc += "RW "
    elif ap==4:
        desc += "INVALID_AP "
    elif ap==5:
        desc += "RO_PL1 "
    else:
        desc += "RO "

    xn = (value >> 4) & 1
    if xn:
        desc += " XN"

    return desc

data = open("mmu.bin", "rb").read()


for i in xrange(0, len(data), 4):
    print "VA 0x%.8x --> " % (i<<18), 
    print parse_l1(u32(data[i:i+4]))
    # print "="*35
    if i == 0x80*4:
        break
