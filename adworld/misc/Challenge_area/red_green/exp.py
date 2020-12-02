#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PIL import Image
import bitstring

im = Image.open("2ec5da20345342909d2336aa7418afed.png")

#width, height = im.size
width  = im.size[0]
height = im.size[1]
pim = im.load()

bin_result = ''

for h in range(height):
    for w in range(width):
        if pim[w, h][0] == 255:  # 判断是否是红色（R,G,B）[0]表示第一通道
            bin_result += '1'
        else:
            bin_result += '0'
with open("stego.png", "wb") as f:
    f.write(bitstring.BitArray(bin=bin_result).bytes)