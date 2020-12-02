#!/usr/bin/env python3
# -*- coding: utf-8 -*-

key = bytearray(b'GoodLuckToYou')
flag = bytearray()
with open('./badd3e0621ff43de8cf802545bbd3ed0', 'rb') as f:
    con = f.read()
    for i in range(len(con)):
        flag.append(con[i] ^ key[i%13])
f = open('flag.txt', 'wb')
f.write(flag)
f.close()