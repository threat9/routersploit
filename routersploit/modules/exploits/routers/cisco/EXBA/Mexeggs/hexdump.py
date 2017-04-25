#!/usr/bin/env python
import sys

def hexdump(x,lead="[+] ",out=sys.stdout):
    '''




    '''
    
    x=str(x)
    l = len(x)
    i = 0
    while i < l:
        print >>out, "%s%04x  " % (lead,i),
        for j in range(16):
            if i+j < l:
                print >>out, "%02X" % ord(x[i+j]),
            else:
                print >>out, "  ",
            if j%16 == 7:
                print >>out, "",
        print >>out, " ",
        print >>out, sane(x[i:i+16])
        i += 16

def sane(x):
    '''

    '''
    
    
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return r
