#!/usr/bin/env python3

import numpy as np
from PIL import Image
from PIL import ImageFilter
from PIL import ImageSequence
import base64
from Crypto.Cipher import DES

im = Image.open("out.gif")

bits = []
for frame in ImageSequence.Iterator(im):
    # magenta = (255, 0, 255), green = (0, 255. 0)
    # palette of magenta color block is (255, 0, 255)
    # palette of green color block is (0, 255. 0)
    if np.array(frame.getpalette())[0] == 0:
        bits.append("0")
    else:
        bits.append("1")

print(np.array(bits).reshape(72,8))

b64_char = []
for i in range(0, 576, 8):
    b64_char.append(chr(int("".join(bits[i: i + 8]), 2)))
b64_str = "".join(b64_char)

print(b64_str)
print(base64.b64decode(b64_str[:-16]))

key="ctfer2333"

#cipher = DES.new(key, DES.MODE_ECB)
#print(cipher.decrypt(b64_str))

#http://tool.chacuo.net/cryptdes
#flag{2ce3b416457d4380dc9a6149858f71db}