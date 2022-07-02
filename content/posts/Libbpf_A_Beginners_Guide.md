---
title: "【译】 Libbpf：初学者指南"
date: 2022-07-02T12:14:27+08:00
categories: ["eBPF"]
#draft: true
---

（原文链接：https://www.containiq.com/post/libbpf）

本文讨论了 libbpf 及其在开发 BPF 工具和应用程序时相对于 BCC 的优势。包括代码示例和入门指南。

BPF 应用程序让工程师可以直接了解操作系统的底层。这些应用程序可以通过内核子系统中的挂钩（hooks）来监控性能和访问资源。

不过，在内核应用程序上工作是一种微妙的平衡。你需要确保在一系列系统上的兼容性，并避免任何过时或弃用的东西。BCC 可以简化该过程，但 libbpf 的优势使其在许多情况下成为更好的解决方案。

在本文中，你将了解 libbpf 与 BCC 的不同之处、如何使用它，以及在你决定进行切换时它提供了什么。我们来看看：

- BCC及其问题
- 什么是 libbpf？
- Libbpf 和 BPF CO-RE
- Libbpf 相对于 BCC 的优势
- libbpf 是如何工作的？
- 你为什么要使用它？
- 开始使用 libbpf

### 什么是 BPF？

Berkeley Packet Filter 或[BPF](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)最初是一个虚拟机，它允许程序员更安全、更轻松地访问低级内核功能。根据[Netflix 工程师 Brendan Gregg](https://www.brendangregg.com/blog/2019-12-02/bpf-a-new-type-of-software.html)的说法，它后来演变成“通用内核执行引擎” 。**它确保程序不会崩溃或无限期地运行**，这是程序员与操作系统交互方式的重大变化。

BPF 的效率意味着它被用来驱动一些最大的站点。Facebook在每台服务器上运行[着 40 多个 BPF 程序](https://www.brendangregg.com/Slides/UM2019_BPF_a_new_type_of_software.pdf)，有时多达一百个。

BCC 是使用 BPF 的老牌玩家，而 libbpf 是新来的。

#### BCC及其问题

BCC 或[BPF Compiler Collection](https://www.containiq.com/post/bcc-tools)使用扩展的 BPF 来更轻松地创建低级程序。C 是一种常见的语言选择，但 Lua、Python、C++ 和 Rust 都是可行的替代方案。

它提供了大量示例和工具以及有用的错误消息，[有助于确保你的 BPF 程序是正确的](https://lwn.net/Articles/742082/)。

但是，BCC 也有缺点。它嵌入编译器组件，例如 Clang，并在运行时编译程序。这需要额外的 CPU 和内存，并且可能会暴露仅在编译程序时出现的问题。

BCC 需要内核头包，这意味着它们必须安装在目标主机上。如果你使用多台机器，会很困难。这也意味着需要在源代码中使用未导出内核内容的类型定义，这会很混乱。

### 什么是Libbpf？

Libbpf 是一组用于构建 BPF 应用程序的替代工具。对于网络、安全和分析应用程序，它提供了优于 BCC 的几个潜在优势。

#### Libbpf 和 BPF CO-RE

Libbpf 通常与 BPF CO-RE 一起使用（编译一次，到处运行）。BPF CO-RE 旨在[解决 BPF 的可移植性问题](https://nakryiko.com/posts/bpf-portability-and-co-re/)，允许你创建在不同内核版本上运行的二进制文件。

它包括[BPF 类型格式 (BTF)](https://www.containiq.com/post/btf-bpf-type-format)信息。这意味着你[需要使用](https://github.com/iovisor/bcc/issues/2855)在编译时设置了`CONFIG_DEBUG_INFO_BTF=y`的内核构建。如果你使用的是标准的消费者 Linux 版本，则需要进行自定义编译以启用此功能；否则，你会遇到错误。

#### Libbpf 相对于 BCC 的优势

Libbpf 通过消除各种令人头疼的问题，使开发人员可以专注于手头的任务。

它生成简单的二进制文件，编译一次就可以在任何地方运行。它消除了许多依赖关系并尽可能接近[一对一地](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html)执行你的代码。

为了运行用BCC编译的程序，需要安装的LLVM、内核和头文件的依赖性可能会超过100MB。并且消除包括LLVM和Clang库在内的开销会导致更小的二进制文件。

例如，一个包含它们的工具使用 BCC 编译为 645 KB。使用 libbpf 工具重新编译的工具生成了一个[只有 151 KB 的可移植二进制文件](https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html)。这大幅度减少了程序的体积。

Libbpf 还创建使用更少内存的二进制文件，例如，与使用 Python 的 BCC 占用 80 MB 相比，libbpf [内存占用为 9 MB 。](https://github.com/iovisor/bcc/pull/2778#issuecomment-594202408)

### Libbpf 是如何工作的？

Libbpf作为一个BPF程序加载器。[它加载、检查和重新定位BPF程序，整理出地图和钩子](https://pingcap.com/blog/why-we-switched-from-bcc-to-libbpf-for-linux-bpf-performance-analysis)。这使开发者可以自由地实现他们的程序而不必做所有的内务（housekeeping）工作。

偏移量和类型被自动匹配和更新，这意味着一个程序可以在目标主机上运行，而不需要昂贵的附加软件，如Clang。你实际上是在编写一个普通的C语言用户模式程序，做你期望的事情，没有任何意外。

libbpf 实现此目的的一种方法是使用 vmheader 文件，该文件包含多种内核类型，因此你不依赖于系统范围的内核头文件。这意味着[要从 BCC 切换到 libbpf](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/)，你需要包含 vmlinux.h。

一个 BPF 应用程序会经历[几个阶段](https://www.youtube.com/watch?v=i6rbzbu-_qM)：

- ‍ **打开阶段**  —— BPF 程序在发现映射、变量和全局变量时暂停。
- ‍ **加载阶段**  —— 创建映射。BPF 程序被加载到内核中并被验证。
- ‍ **附加阶段**  —— BPF 程序附加到钩子上，准备工作。
- ‍ **拆除（Tear Down）阶段**  —— 当 BPF 程序从内核中分离和卸载时，资源被释放。

如果你查看下面的 minimum.c，你将看到与每个阶段相对应的函数（销毁用于拆除阶段）。

如果你不需要进行运行时调整，[可以组合打开和加载阶段。](https://pingcap.com/blog/tips-and-tricks-for-writing-linux-bpf-applications-with-libbpf)使用这个功能：

```
<name>_open_and_load()
```

如果需要，你还可以修改附加阶段以选择性地附加资源。

### 为什么要使用Libbpf？

Libpf 提供了几个好处。它不需要依赖关系，使其在多台机器上使用起来更快、更容易。使用你的程序的人越多，这种优势就越大。

它在资源使用、输出更小的二进制文件和使用更少的内存方面更好，这使其非常适合系统关键任务。它对性能的有限影响也使其成为监控、安全和分析的理想选择。

### 开始使用 Libbpf

要开始使用，请尝试 GitHub 上的[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)演示应用程序。下载 repo 后，你可以使用 Make 和 Sudo 构建各种示例。下面是为 Minimal 演示构建和测试一些输出的示例：

```
cd examples/c
make minimal
sudo ./minimal
sudo cat/sys/kernel/debug/tracing/trace_pipe
```

此代码和下面的代码来自 libbpf-bootstrap 存储库并使用[BSD 3-Clause 许可证](https://github.com/libbpf/libbpf-bootstrap/blob/master/LICENSE)。

这是一个 libbpf `hello world`的示例：

**minimal.bpf.c**:

```c

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write"
int handle_tp(void *ctx)
{
 int pid = bpf_get_current_pid_tgid() >> 32;

 if (pid != my_pid)
 return 0;

 bpf_printk("BPF triggered from PID %d.\n", pid);

 return 0;
}
```

及其配套文件`minimum.c`：

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
 return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
 struct rlimit rlim_new = {
  .rlim_cur  = RLIM_INFINITY,
  .rlim_max  = RLIM_INFINITY,
 };

 if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
  fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
  exit(1);
 }
}
int main(int argc, char **argv)
{
 struct minimal_bpf *skel;
 int err;

 /* Set up libbpf errors and debug info callback */
 libbpf_set_print(libbpf_print_fn);

 /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
 bump_memlock_rlimit();

 /* Open BPF application */
 skel = minimal_bpf_open();
 if (!skel) {
  fprintf(stderr, "Failed to open BPF skeleton\n");
  return 1;
 }

 /* ensure BPF program only handles write() syscalls from our process */
 skel->bss->my_pid = getpid();

 /* Load & verify BPF programs */
 err = minimal_bpf_load(skel);
 if (err) {
  fprintf(stderr, "Failed to load and verify BPF skeleton\n");
  goto cleanup;
 }

 /* Attach tracepoint handler */
 err = minimal_bpf_attach(skel);
 if (err) {
  fprintf(stderr, "Failed to attach BPF skeleton\n");
  goto cleanup;
 }

 printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe`"
 "to see output of the BPF programs.\n");

 for (;;) {
  /* trigger our BPF program */
  fprintf(stderr, ".");
  sleep(1);
 }

cleanup:
 minimal_bpf_destroy(skel);
 return -err;
}
```

### 更多提示

除了 Minimal，libbpf-bootstrap GitHub[示例文件夹](https://github.com/libbpf/libbpf-bootstrap/tree/master/examples)中还有其他几个有用的示例：

**Bootstrap** – 它跟踪流程并为你提供有关它们的统计信息，向你展示如何执行一些基本任务。如果你想编写监控或性能跟踪应用程序，请先看这里。

**Tracecon** – Rust 爱好者可以查看 tracecon，这是一个 Rust & Co. 应用程序，可让你跟踪机器上的所有 TCPv4 连接。

**Uprobe** – 这向你展示了如何使用用户空间探针，让你跟踪参数和输出。

**Fentry** – 这些是基于 fentry 和 fexit 的跟踪程序。它们的性能优于 kprobes，但需要至少 5.5 的内核版本。

**Kprobe** - 此功能是另一个与内核空间入口和出口探测器一起使用的日志记录示例。

**XDP** – 这是一个记录数据包大小的 Rust 示例。

如果你在使用 libbpf 时遇到任何问题，请查看其日志输出。它不使用 BCC 删除内存限制的方法来确保程序可以成功加载到内核中。

为确保你有足够的内存，你可以在程序开始时[调用 setrlimit](https://man7.org/linux/man-pages/man2/setrlimit.2.html)。你可以在上面的 `minimum.c` 中看到一个示例。

正如这些示例所示，切换到 libbpf 并不太痛苦，如果你遇到上述任何问题，那么切换是非常值得的。

### 结论

BPF 为你提供了可观察性的超能力，但[它的可移植性和资源使用存在问题](https://www.containiq.com/post/using-ebpf-to-enhance-kubernetes-monitoring)。Libbpf 可以帮助你缓解这些问题，如果你正在创建底层 Linux 软件，就会给你带来很大的帮助。

Libbpf 生成的文件较小，比 BCC 生成的文件使用的内存少。它还删除了依赖关系，使你的代码更简单，不再需要内核导入。这意味着你可以写出更干净的代码，在文件的开头有更少的包含，而且你的输出更容易让客户安装。 

在两者的直接比较中，libbpf是一个明显的赢家。从 BCC 转换是很容易做到的。Libbpf 更低的资源使用量和更大的可移植性简化了你的工作，使你的最终产品对你的客户更有吸引力，所以你从这个改变中可以获得很多好处。

### More about me

欢迎关注 「barryX的技术笔记」 微信公众号

<img src="/images/wx.png" style="zoom:33%;" />
