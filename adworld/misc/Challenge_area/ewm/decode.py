#!/usr/bin/env python3
#-*- coding: utf8 -*-

from PIL import Image
import os

small_list_pipe = os.popen("ls -t | grep _small")
small_list = small_list_pipe.read().split()
small_tmp = Image.open(small_list[0])
w, h = small_tmp.size
small_img = Image.new("RGB", (w * 7, h * 7))
small_tmp.close()

for i in range(7):
    for j in range(7):
        small_tmp = Image.open(small_list[i * 7 + j])
        small_img.paste(small_tmp, (w * (6 - j), h * (6 - i)))
        small_tmp.close()
small_img.show()
small_img.save("small.png")

big_list_pipe = os.popen("ls -t | grep _big")
big_list = big_list_pipe.read().split()
big_tmp = Image.open(big_list[0])

w, h = big_tmp.size
big_img = Image.new("RGB", (w * 6, h * 6))
big_tmp.close()

for i in range(6):
    for j in range(6):
        big_tmp = Image.open(big_list[i * 6 + j])
        big_img.paste(big_tmp, (w * (6 - j), h * (6 - i)))
        big_tmp.close()
big_img.show()
big_img.save("big.png")