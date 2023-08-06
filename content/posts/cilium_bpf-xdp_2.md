---
title: "BPF架构（二）"
date: 2023-08-06T16:15:35+08:00
categories: ["eBPF","Linux Kernel"]
---

BPF架构（一）指令集：https://barryx.cn/cilium_bpf-xdp_1/

## 辅助函数（Helper Functions）

辅助函数是一个概念，它使得BPF程序能够查询内核定义的一组核心函数调用，以从内核检索/推送（retrieve / push）数据。可用的辅助函数可能因BPF程序类型而有所不同，例如，附加到套接字的BPF程序仅允许调用一部分辅助函数，与附加到tc层的BPF程序相比。轻量级隧道的封装和解封装辅助函数构成了仅对较低的tc层可用的函数示例，而用于将通知推送到用户空间的事件输出辅助函数则可用于tc和XDP程序。

每个辅助函数的实现具有类似系统调用的共享函数签名。该签名定义如下：

```
u64 fn(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
```

前文所述的调用约定适用于所有BPF辅助函数。

内核将辅助函数抽象为宏`BPF_CALL_0()`到`BPF_CALL_5()`，类似于系统调用。下面的示例是一个从辅助函数中提取的部分，该辅助函数通过调用相应的映射实现回调函数来更新映射元素：

```c
BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
           void *, value, u64, flags)
{
    WARN_ON_ONCE(!rcu_read_lock_held());
    return map->ops->map_update_elem(map, key, value, flags);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
    .func           = bpf_map_update_elem,
    .gpl_only       = false,
    .ret_type       = RET_INTEGER,
    .arg1_type      = ARG_CONST_MAP_PTR,
    .arg2_type      = ARG_PTR_TO_MAP_KEY,
    .arg3_type      = ARG_PTR_TO_MAP_VALUE,
    .arg4_type      = ARG_ANYTHING,
};
```

这种方法有多种优点：虽然 cBPF 重载了其加载指令，以便在不可能的数据包偏移处获取数据以调用辅助辅助函数，但每个 cBPF JIT 都需要实现对此类 cBPF 扩展的支持。对于 eBPF，每个新添加的辅助函数都将以透明且高效的方式进行 JIT 编译，这意味着 JIT 编译器只需要发出一条调用指令，因为寄存器映射的方式使得 BPF 寄存器分配已经与底层架构的调用约定。这使得可以轻松地通过新的辅助功能扩展核心内核。所有BPF辅助函数都是核心内核的一部分，无法通过内核模块进行扩展或添加。

上述函数签名还允许验证者执行类型检查。上面的`struct bpf_func_proto`用于将关于辅助函数需要知道的所有必要信息传递给验证器，以便验证器能够确保辅助函数的期望类型与BPF程序分析的寄存器的当前内容匹配。

参数类型可以从传递任何类型的值到限制内容（例如指针/大小对于BPF堆栈缓冲区）的传递。在后一种情况下，验证器还可以执行额外的检查，例如，检查缓冲区是否先前已初始化。

可用的BPF辅助函数列表相当长并且不断增长，例如，截至本文撰写时，tc BPF程序可以从38个不同的BPF辅助函数中进行选择。内核的`struct bpf_verifier_ops`包含一个`get_func_proto`回调函数，可以为给定的BPF程序类型提供特定的枚举`bpf_func_id`到可用的辅助函数的映射。

## 映射（Maps）

![/images/bpf_map.png](./cilium_bpf-xdp_2.assets/bpf_map.png)

映射（Maps）是高效的内核空间键值存储。BPF程序可以访问映射以在多个BPF程序调用之间保持状态。它们还可以通过文件描述符从用户空间访问，并可以与其他BPF程序或用户空间应用程序共享。

共享映射的BPF程序不需要是相同的程序类型，例如，跟踪程序可以与网络程序共享映射。一个单独的BPF程序目前可以直接访问多达64个不同的映射。

映射的实现由核心内核提供。有通用的映射，per-CPU 和non-per-CPU类型都可以读/写任意数据，但还有一些与辅助函数一起使用的非通用映射。

目前可用的通用映射有 `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_PERCPU_HASH`, `BPF_MAP_TYPE_PERCPU_ARRAY`, `BPF_MAP_TYPE_LRU_HASH`, `BPF_MAP_TYPE_LRU_PERCPU_HASH` and `BPF_MAP_TYPE_LPM_TRIE`. 。它们都使用相同的一组BPF辅助函数来执行查找、更新或删除操作，同时实现具有不同语义和性能特征的不同后端。

内核中当前的非通用映射有 `BPF_MAP_TYPE_PROG_ARRAY`, `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, `BPF_MAP_TYPE_CGROUP_ARRAY`, `BPF_MAP_TYPE_STACK_TRACE`, `BPF_MAP_TYPE_ARRAY_OF_MAPS`, `BPF_MAP_TYPE_HASH_OF_MAPS`。例如，`BPF_MAP_TYPE_PROG_ARRAY`是一个包含其他BPF程序的数组映射，`BPF_MAP_TYPE_ARRAY_OF_MAPS`和`BPF_MAP_TYPE_HASH_OF_MAPS`都包含指向其他映射的指针，以便可以在运行时原子地替换整个BPF映射。这些类型的映射解决了一个特定问题，通过BPF辅助函数无法独立实现，因为需要在多个BPF程序调用之间保存额外（non-data）状态。

## 对象固定（Object Pinning）

![/images/bpf_fs.png](./cilium_bpf-xdp_2.assets/bpf_fs.png)

BPF映射和程序充当内核资源，只能通过文件描述符进行访问，这些文件描述符由内核中的匿名inode支持。虽然它们有一些优点，但也伴随着一些缺点：

用户空间应用程序可以利用大多数与文件描述符相关的API，Unix域套接字的文件描述符传递也可以正常工作，但与此同时，文件描述符限于进程的生命周期，这使得像映射共享这样的选项变得相对繁琐。

因此，它给某些用例带来了许多复杂性，例如 iproute2，其中 tc 或 XDP 设置程序并将其加载到内核中且最终自行终止。接着，从用户空间侧也无法访问映射，尽管在某些情况下它可能很有用，例如当映射在数据路径的入口和出口位置之间共享时。此外，第三方应用程序可能希望在 BPF 程序运行时监视或更新映射内容。

为了克服这个限制，一个最小内核空间的BPF文件系统被实现了，可以将BPF映射和程序固定到其中，这个过程称为对象固定（object pinning）。因此，BPF系统调用已被扩展为两个新命令，可以使用`BPF_OBJ_PIN`命令来固定（pin）或使用`BPF_OBJ_GET`命令来检索（retrieve）之前固定的对象。

例如，诸如tc的工具使用这个基础设施在入口和出口上共享映射。BPF相关的文件系统不是单实例（singleton）的，它支持多个挂载实例、硬链接和软链接等功能。

## 尾调用（Tail Calls）

![/images/bpf_tailcall.png](./cilium_bpf-xdp_2.assets/bpf_tailcall.png)

BPF还可以使用的另一个概念称为尾调用（tail call）。尾调用可以被看作是一种机制，允许一个BPF程序调用另一个BPF程序，而不返回到旧程序。这样的调用开销很小，因为与函数调用不同，它用长跳转实现（long jump），重用相同的堆栈帧。

这些程序是相互独立验证的，因此为了传输状态，可以使用per-CPU映射作为临时缓冲区，或者在tc程序的情况下，可以使用`skb`字段，如`cb[]`区域。

只有相同类型的程序可以进行尾调用，并且它们还需要在JIT编译方面匹配，因此只能调用JIT编译或仅解释的程序，而不能混合使用。

进行尾调用涉及到两个组件：第一部分需要设置一个特殊的映射，称为程序数组（`BPF_MAP_TYPE_PROG_ARRAY`），用户空间可以使用键值对来填充此映射，其中值是尾调用的BPF程序的文件描述符。第二部分是一个`bpf_tail_call()`辅助函数，该函数传递上下文、程序数组的引用和查找键。然后内核将此辅助函数调用直接内联到专用的BPF指令中。当前，这样的程序数组只能从用户空间写入。

内核根据传递的文件描述符查找相关的BPF程序，并原子性地替换给定映射槽位上的程序指针。当在提供的键处找不到映射条目时，内核将会“穿透（fall through）”并继续执行位于`bpf_tail_call()`之后的指令。尾调用是一种强大的工具，例如，可以通过尾调用来结构化解析网络头。在运行时，可以以原子方式添加或替换功能，从而改变BPF程序的执行行为。

## BPF到BPF调用（BPF to BPF Calls）

![/images/bpf_call.png](./cilium_bpf-xdp_2.assets/bpf_call-20230806150815778.png)

除了BPF辅助函数调用和BPF尾调用之外，最近在BPF核心基础设施中添加的另一个新特性是BPF到BPF调用。在该特性引入内核之前，典型的BPF C程序必须将可重用的代码（例如，位于头文件中的代码）声明为`always_inline`，以便当LLVM编译并生成BPF目标文件时，所有这些函数都被内联化，并在生成的目标文件中被多次复制，从而人为地增加了其代码大小：

```c
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

static __inline int foo(void)
{
    return XDP_DROP;
}

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return foo();
}

char __license[] __section("license") = "GPL";
```

这样做的主要原因是由于BPF程序加载器以及验证器、解释器和JIT的函数调用支持不足。从Linux内核4.16和LLVM 6.0开始，这个限制被解除，BPF程序不再需要在每个地方都使用`always_inline`。因此，之前展示的BPF示例代码可以更自然地改写为：

```c
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

static int foo(void)
{
    return XDP_DROP;
}

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return foo();
}

char __license[] __section("license") = "GPL";
```

主流的BPF JIT编译器（如`x86_64`和`arm64`）现在已经支持BPF到BPF的调用，其他架构也将在不久的将来跟进。BPF到BPF的调用是一种重要的性能优化，它极大地减小了生成的BPF代码大小，从而更加友好地适应CPU的指令缓存。

从BPF Helper函数中所了解的调用约定同样适用于BPF到BPF的调用，意味着`r1`到`r5`用于向被调用方传递参数，结果会在`r0`中返回。`r1`到`r5`是临时寄存器，而`r6`到`r9`则按照通常的方式在调用之间保留。最大的嵌套调用次数和允许的调用帧是`8`。调用方可以传递指针（例如，传递给调用方的栈帧）给被调用方，但不能反过来。

BPF JIT编译器为每个函数体生成单独的映像，并在最终的JIT传递中修复映像中的函数调用地址。经过验证这对JIT的改动非常小，它们可以将BPF到BPF调用视为常规的BPF Helper调用。

在内核5.9之前，BPF尾调用和BPF子程序是互斥的。利用尾调用的BPF程序不能享受减小程序映像大小和更快的加载时间的好处。Linux内核5.10最终允许用户将这两个功能结合起来，添加了将BPF子程序与尾调用结合使用的能力。

然而，这种改进也有一些限制。混合使用这两个功能可能会导致内核堆栈溢出。为了了解可能发生的情况，请参见下面的图片，它说明了bpf2bpf调用和尾调用的混合使用：

![/images/bpf_tailcall_subprograms.png](./cilium_bpf-xdp_2.assets/bpf_tailcall_subprograms.png)

在实际跳转到目标程序之前，尾调用将仅展开其当前的堆栈帧。如上面的示例所示，如果在子函数中发生了尾调用，当程序执行到func2时，函数（func1）的堆栈帧将存在于堆栈上。一旦最终的函数（func3）终止，所有先前的堆栈帧将被展开，控制将返回给BPF程序调用者的调用者。

内核引入了额外的逻辑来检测这个功能组合。在整个调用链中，从子程序（注意，如果验证器检测到bpf2bpf调用，那么主函数也被视为子函数）到每个子程序的堆栈大小有一个限制，为256字节。总体而言，受此限制，BPF程序的调用链最多可以消耗8KB的堆栈空间。这个限制是由每个堆栈帧的256字节乘以尾调用计数限制（33）得出的。如果没有这个限制，BPF程序将在512字节的堆栈大小上运行，在某些架构上，尾调用的最大数量将导致堆栈溢出，总共占用16KB的空间。

值得一提的是，这个功能组合目前只在x86-64架构上受支持。

## JIT

64位 `x86_64`, `arm64`, `ppc64`, `s390x`, `mips64`, `sparc64` 和32位`arm`、`x86_32`架构都默认配备了一个内核内置的eBPF JIT编译器，而且它们功能相同，可以通过以下方式启用：

```bash
# echo 1 > /proc/sys/net/core/bpf_jit_enable
```

32位mips、ppc和sparc架构目前拥有一个cBPF JIT编译器。提到的架构仍然保留了cBPF JIT，以及所有其他由Linux内核支持但没有BPF JIT编译器的剩余架构需要通过内置的解释器运行eBPF程序。

在内核源代码树中，可以通过grep命令轻松确定`HAVE_EBPF_JIT`（eBPF JIT支持情况）：

```bash
# git grep HAVE_EBPF_JIT arch/
arch/arm/Kconfig:       select HAVE_EBPF_JIT   if !CPU_ENDIAN_BE32
arch/arm64/Kconfig:     select HAVE_EBPF_JIT
arch/powerpc/Kconfig:   select HAVE_EBPF_JIT   if PPC64
arch/mips/Kconfig:      select HAVE_EBPF_JIT   if (64BIT && !CPU_MICROMIPS)
arch/s390/Kconfig:      select HAVE_EBPF_JIT   if PACK_STACK && HAVE_MARCH_Z196_FEATURES
arch/sparc/Kconfig:     select HAVE_EBPF_JIT   if SPARC64
arch/x86/Kconfig:       select HAVE_EBPF_JIT   if X86_64
```

JIT编译器显著加快了BPF程序的执行速度，因为它们降低了与解释器相比每条指令的成本。通常，指令可以与底层架构的本地指令进行1:1映射。这也减小了生成的可执行映像的大小，因此对CPU的指令缓存更友好。特别是对于CISC指令集（如`x86`），JIT被优化为针对给定指令发出最短的操作码，以缩小程序转换所需的总大小。

## 加固（Hardening）

为了防止代码可能发生的破坏，BPF在程序的整个生命周期中将整个BPF解释器映像（`struct bpf_prog`）以及JIT编译映像（`struct bpf_binary_header`）在内核中设置为只读。在此阶段发生的任何破坏，例如由于一些内核错误导致的，将导致通用保护错误（general protection fault），从而导致内核崩溃，而不是允许悄无声息地发生破坏。

支持将映像内存设置为只读的架构可以通过以下方式确定：

```bash
$ git grep ARCH_HAS_SET_MEMORY | grep select
arch/arm/Kconfig:    select ARCH_HAS_SET_MEMORY
arch/arm64/Kconfig:  select ARCH_HAS_SET_MEMORY
arch/s390/Kconfig:   select ARCH_HAS_SET_MEMORY
arch/x86/Kconfig:    select ARCH_HAS_SET_MEMORY
```

选项`CONFIG_ARCH_HAS_SET_MEMORY`不可配置，因此该保护始终内置。其他架构可能在未来会采用相同的方式。

对于`x86_64` JIT编译器，通过设置`CONFIG_RETPOLINE`（在大多数现代Linux发行版中默认设置）实现了对尾调用间接跳转的JIT编译，其使用了[retpoline](https://lkml.org/lkml/2018/1/3/780)。

如果`/proc/sys/net/core/bpf_jit_harden`设置为`1`，则针对无特权用户的JIT编译将生效，并采取额外的强化措施。这在一定程度上稍微降低了它们的性能，但可以减少在不受信任的用户操作系统上进行攻击的可能性。与完全切换到解释器相比，程序执行的减少仍然会带来更好的性能。

目前，启用加固措施将在JIT编译时使所有用户提供的32位和64位常量对BPF程序变为不可见，以防止JIT喷洒攻击（JIT spraying attacks），这些攻击会将本机操作码注入为立即数。由于这些立即数位于可执行内核内存中，因此可能从某些内核错误触发的跳转将跳转到立即数的起始位置，然后执行这些作为本机指令。

通过对实际指令进行随机化操作，JIT常量保护防止了这种情况，这意味着该操作从基于立即值的源操作数转换为基于寄存器的操作数，通过将加载该值的实际过程分为两个步骤来重写指令：1）将经过混淆的立即值`rnd ^ imm`加载到寄存器中，2）通过将寄存器与rnd异或，使得原始的imm立即数存在于寄存器中，可以用于实际操作。这个示例提供了一个加载操作，但实际上所有的通用操作都会被混淆。

示例中展示了禁用固化措施的JIT编译程序：

```bash
# echo 0 > /proc/sys/net/core/bpf_jit_harden

  ffffffffa034f5e9 + <x>:
  [...]
  39:   mov    $0xa8909090,%eax
  3e:   mov    $0xa8909090,%eax
  43:   mov    $0xa8ff3148,%eax
  48:   mov    $0xa89081b4,%eax
  4d:   mov    $0xa8900bb0,%eax
  52:   mov    $0xa810e0c1,%eax
  57:   mov    $0xa8908eb4,%eax
  5c:   mov    $0xa89020b0,%eax
  [...]
```

同样的程序在启用加固的情况下，通过非特权用户加载BPF程序时会出现常数盲化（blinded）：

```bash
# echo 1 > /proc/sys/net/core/bpf_jit_harden

  ffffffffa034f1e5 + <x>:
  [...]
  39:   mov    $0xe1192563,%r10d
  3f:   xor    $0x4989b5f3,%r10d
  46:   mov    %r10d,%eax
  49:   mov    $0xb8296d93,%r10d
  4f:   xor    $0x10b9fd03,%r10d
  56:   mov    %r10d,%eax
  59:   mov    $0x8c381146,%r10d
  5f:   xor    $0x24c7200e,%r10d
  66:   mov    %r10d,%eax
  69:   mov    $0xeb2a830e,%r10d
  6f:   xor    $0x43ba02ba,%r10d
  76:   mov    %r10d,%eax
  79:   mov    $0xd9730af,%r10d
  7f:   xor    $0xa5073b1f,%r10d
  86:   mov    %r10d,%eax
  89:   mov    $0x9a45662b,%r10d
  8f:   xor    $0x325586ea,%r10d
  96:   mov    %r10d,%eax
  [...]

```

这两个程序在语义上是相同的，只是第二个程序的反汇编中不再可见原始的立即数。

同时，加固也禁用了特权用户的任何JIT kallsyms暴露，防止JIT映像地址再次暴露到`/proc/kallsyms`中。

此外，Linux内核提供了`CONFIG_BPF_JIT_ALWAYS_ON`选项，该选项从内核中移除了整个BPF解释器，并永久启用了JIT编译器。这是作为Spectre v2上下文中的一种缓解措施开发的，以便在基于虚拟机的环境中，客户机内核不再重用主机内核的BPF解释器来进行攻击。对于基于容器的环境，`CONFIG_BPF_JIT_ALWAYS_ON`配置选项是可选的，但是如果无论如何启用了JITs，也可以编译掉解释器以减少内核的复杂性。因此，对于像`x86_64`和`arm64`等主流架构来说，一般建议广泛使用JITs。

最后，内核还提供了一个选项，通过`/proc/sys/kernel/unprivileged_bpf_disabled` sysctl开关禁用非特权用户使用`bpf(2)`系统调用。这是一个一次性的紧急开关，意味着一旦设置为`1`，就没有办法将其重置为`0`，除非重新启动内核。在设置为`1`后，只有`CAP_SYS_ADMIN`特权的进程才能从初始命名空间开始使用`bpf(2)`系统调用。Cilium启动时也将此开关设置为`1`。

```bash
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled
```

## 卸载（Offloads）

![/images/bpf_offload.png](./cilium_bpf-xdp_2.assets/bpf_offload.png)

在BPF中的网络程序，特别是用于tc和XDP的程序，确实可以通过内核中的硬件进行卸载，以便直接在网络适配器上执行BPF代码。

目前，Netronome的`nfp`驱动程序支持通过JIT编译器对BPF进行卸载，该编译器将BPF指令翻译为针对网络适配器实现的指令集。这还包括将BPF映射卸载到网络适配器上，因此卸载后的BPF程序可以执行映射的查找、更新和删除操作。

## BPF sysctls

Linux内核提供了一些与BPF相关的sysctls，本节介绍了这些sysctls。

- `/proc/sys/net/core/bpf_jit_enable`：启用或禁用BPF JIT编译器。

| 值   | 描述                                    |
| ---- | --------------------------------------- |
| 0    | 禁用JIT，仅使用解释器（内核的默认值）   |
| 1    | 启用JIT编译器                           |
| 2    | 启用JIT并将调试 traces 输出到内核日志中 |

正如在后续章节中描述的那样，当JIT编译器设置为调试模式（选项`2`）时，可以使用`bpf_jit_disasm`工具来处理调试 traces。

- `/proc/sys/net/core/bpf_jit_harden`：启用或禁用BPF JIT加固。需要注意的是启用加固会影响性能，但可以通过盲化BPF程序的立即值来减轻JIT spraying攻击。对于通过解释器处理的程序，不需要或不执行立即值的盲化。

| 值   | 描述                        |
| ---- | --------------------------- |
| 0    | 禁用JIT加固（内核的默认值） |
| 1    | 仅为非特权用户启用JIT加固   |
| 2    | 为所有用户启用JIT加固       |

- `/proc/sys/net/core/bpf_jit_kallsyms`：启用或禁用将JIT程序作为内核符号导出到`/proc/kallsyms`，以便与`perf`工具一起使用，并使内核对这些地址感知，以进行堆栈展开，例如，用于输出堆栈跟踪。符号名包含BPF程序的标签（`bpf_prog_<tag>`）。如果启用了`bpf_jit_harden`，则禁用此功能。

| 值   | 描述                                 |
| ---- | ------------------------------------ |
| 0    | 禁用JIT kallsyms导出（内核的默认值） |
| 1    | 仅为特权用户启用JIT kallsyms导出     |

- `/proc/sys/kernel/unprivileged_bpf_disabled`：启用或禁用非特权用户对`bpf(2)`系统调用的使用。Linux内核默认启用对`bpf(2)`的非特权使用。

一旦将值设置为1，非特权使用将被永久禁用，直到下一次重新启动，无论是应用程序还是管理者都无法再次重置该值。

该值也可以设置为2，这意味着它可以在运行时更改为0或1，而现在禁用非特权使用。此值在Linux 5.13中添加。如果在内核配置中启用了`BPF_UNPRIV_DEFAULT_OFF`，则此开关默认为2，而不是0。

该开关不会影响任何不使用`bpf(2)`系统调用将程序加载到内核中的cBPF程序，如seccomp或传统的套接字过滤器。

| 值   | 描述                                                         |
| ---- | ------------------------------------------------------------ |
| 0    | 启用bpf syscall的非特权使用（内核的默认值）                  |
| 1    | 禁用bpf syscall的非特权使用（重新启动前）                    |
| 2    | 禁用bpf syscall的非特权使用（如果在内核配置中启用了BPF_UNPRIV_DEFAULT_OFF，则为默认值） |

### More about me

欢迎关注 「barryX的技术笔记」 微信公众号

<img src="/images/wx.png" style="zoom:33%;" />
