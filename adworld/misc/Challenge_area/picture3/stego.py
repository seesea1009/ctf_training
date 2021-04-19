#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

base64str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
bin_str = ''
with open("stego.txt", "r") as fin:
    lines = fin.readlines()
for line in lines:
    line = line.strip()
    pad_len = line.count("=")
    line = line.replace("=", "")
    if pad_len > 0:
        b64idx = base64str.index(line[-1])
        bin_str += '{0:06b}'.format(b64idx)[-pad_len*2:]

#bin2int = lambda x:[int(bin_str[i:i+8],2) for i in range(0, len(bin_str), 8)]

print(''.join([chr(int(bin_str[i:i+8],2)) for i in range(0,len(bin_str),8)]))

