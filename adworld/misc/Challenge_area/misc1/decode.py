#!/usr/bin/env python3
# -*- coding: utf-8 -*-

text = 'd4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9e1e6b3e3b9e4b3b7b7e2b6b1e4b2b6b9e2b1b1b3b3b7e6b3b3b0e3b9b3b5e6fd'

new_text = [ chr(int(text[i:i+2],16)&0x7f) for i in range(0,len(text),2)]
print(''.join(new_text))