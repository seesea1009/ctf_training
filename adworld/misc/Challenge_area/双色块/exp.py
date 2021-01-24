#!/usr/bin/env python3

import numpy as np
from PIL import Image
from PIL import ImageSequence

im = Image.open("out.gif")

im.save("gif-000.png")
qr_im = Image.new("RGB", im.size)

idx = 0
for frame in ImageSequence.Iterator(im):
    x = (idx % 24) * 10
    y = (idx // 24) * 10
    im_crop = frame.crop((x, y, x + 10, y + 10))
    qr_im.paste(im_crop, (x, y))

    idx += 1

qr_im.show()
qr_im.save("qr.png")
