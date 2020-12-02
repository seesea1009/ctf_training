# coding:utf-8

__author__ = 'YFP'

from Crypto import Random
from Crypto.Cipher import AES

import sys
import base64

IV = 'QWERTYUIOPASDFGH'

def decrypt(encrypted):
    aes = AES.new(IV, AES.MODE_CBC, IV)
    return aes.decrypt(encrypted)

def encrypt(message):
    length = 16
    count = len(message)
    padding = length - (count % length)
    message = message + '\0' * padding
    aes = AES.new(IV, AES.MODE_CBC, IV)
    return aes.encrypt(message)
str = 'this is a test'

example = encrypt(str)

print(decrypt(example))
data='19aaFYsQQKr+hVX6hl2smAUQ5a767TsULEUebWSajEo='

print(decrypt(base64.b64decode(data)))