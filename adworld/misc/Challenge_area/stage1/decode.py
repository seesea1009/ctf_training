#!/usr/bin/env python3

with open ("qr.pyc", "wb") as fout:
    with open ("qr.txt", "rb") as fin:
        buf = fin.read()
        buf = buf.strip()
        bytelist = [ int(buf[i:i+2], 16) for i in range(0, len(buf), 2) ]
        fout.write(bytearray(bytelist))