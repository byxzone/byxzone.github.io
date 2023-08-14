---
title: "BPF开发工具（二）"
date: 2023-08-14T20:20:35+08:00
categories: ["eBPF","Linux Kernel"]
---

3. **不允许使用全局变量。**

由于前面提到的原因，BPF不能像常规C程序中常用的那样使用全局变量。

然而，有一种解决方法，即程序可以使用`BPF_MAP_TYPE_PERCPU_ARRAY`类型的BPF映射，其中只有一个任意值大小的插槽。这是可行的，因为在执行期间，BPF程序保证不会被内核抢占，因此可以将单个映射条目用作临时数据的暂存缓冲区，例如，用于扩展超出栈的限制。这在尾部调用中也是有效的，因为它具有与抢占相关的相同保证。

否则，在多个BPF程序运行之间保持状态的话，可以使用普通的BPF映射。

4. **不允许使用const字符串或数组。**

在BPF C程序中定义`const`字符串或其他数组不起作用，原因与第1和第3部分指出的原因相同，即会在ELF文件中生成重定位项，由于这些重定位项不是向加载器的ABI的一部分，因此会被加载器（loaders）拒绝（加载器也无法修复这些条目，因为这将需要对已编译的BPF序列进行大规模重写）。

将来，LLVM可能会检测到这些情况并提前向用户报错。

诸如`trace_printk()`之类的辅助函数可以通过以下方式解决：

```c
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif
```

程序可以像这样自然地使用宏，例如 `printk("skb len:%u\n", skb->len);`。然后，输出将被写入跟踪管道。可以使用 `tc exec bpf dbg` 从那里检索消息。

然而，使用 `trace_printk()` 辅助函数有一些缺点，因此不建议在生产环境中使用。像 `"skb len:%u\n"` 这样的常量字符串需要在每次调用辅助函数时加载到BPF栈中，而且BPF辅助函数最多只能有5个参数。这只留下了3个额外的变量可以用于转储。

因此，尽管对于快速调试很有帮助，但建议（对于网络程序）分别使用 `skb_event_output()` 或 `xdp_event_output()` 辅助函数。它们允许将自定义结构从BPF程序传递到perf事件环形缓冲区，以及可选的数据包样本。例如，Cilium 的监视器使用这些辅助函数来实现调试框架、网络策略违规通知等。这些辅助函数通过无锁内存映射的per-CPU `perf` 环形缓冲区传递数据，因此比 `trace_printk()` 要快得多。

5. **使用 LLVM 内置函数 memset()/memcpy()/memmove()/memcmp()**

因为BPF程序除了对BPF辅助函数的调用外，不能执行任何函数调用，所以常用的库代码需要实现为内联函数。此外，LLVM还提供了一些内建函数，程序可以用于常数大小（这里是 `n` ），这些函数将始终被内联：

```c
#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif
```

`memcmp()` 内建函数存在一些特殊情况，由于后端中的一个LLVM问题，内联未发生，因此在问题修复之前不建议使用。

6. **暂时还不支持循环。**

内核中的BPF验证器通过对所有可能的程序路径进行深度优先搜索，以及其他控制流图验证，来检查BPF程序是否包含循环。目的是确保程序始终能够保证终止。

对于常数上界的循环，可以使用 `#pragma unroll` 指令。以下是编译为BPF的示例代码：

```c
#pragma unroll
    for (i = 0; i < IPV6_MAX_HEADERS; i++) {
        switch (nh) {
        case NEXTHDR_NONE:
            return DROP_INVALID_EXTHDR;
        case NEXTHDR_FRAGMENT:
            return DROP_FRAG_NOSUPPORT;
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_AUTH:
        case NEXTHDR_DEST:
            if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
                return DROP_INVALID;

            nh = opthdr.nexthdr;
            if (nh == NEXTHDR_AUTH)
                len += ipv6_authlen(&opthdr);
            else
                len += ipv6_optlen(&opthdr);
            break;
        default:
            *nexthdr = nh;
            return len;
        }
    }
```

 另一种可能性是使用尾调用（tail calls），通过再次调用相同的程序，并使用一个 `BPF_MAP_TYPE_PERCPU_ARRAY` 映射来实现局部临时空间。尽管是动态的，但这种循环形式最多可以进行34次迭代（初始程序加上来自尾调用的33次迭代）。

在未来，BPF可能会有一些native的、但有限的循环实现方式。

7. **用尾调用分割程序**

尾调用提供了在运行时原子地更改程序行为的灵活性，通过从一个BPF程序跳转到另一个程序。为了选择下一个程序，尾调用使用程序数组映射（`BPF_MAP_TYPE_PROG_ARRAY`），并传递映射以及要跳转到的下一个程序的索引。在执行跳转后，不会返回到旧程序，而且如果给定映射索引处没有程序，那么执行将继续在原始程序上。

例如，这可以用于实现解析器的各个阶段，其中这些阶段在运行时可以使用新的解析功能进行更新。

另一个用例是事件通知，例如，Cilium可以在运行时选择包丢弃通知，其中 `skb_event_output() `调用位于尾调用的程序中。因此，在正常操作期间，始终会执行默认路径，除非将程序添加到相关的映射索引，然后程序准备元数据并触发事件通知到用户空间守护程序。

程序数组映射非常灵活，还可以实现位于每个映射索引中的各个动作。例如，附加到XDP或tc的根程序可以对程序数组映射的索引0执行初始尾调用，执行流量采样，然后跳转到程序数组映射的索引1，在那里应用防火墙策略并且该数据包要么被丢弃，要么在程序数组映射的索引2中进一步处理，被修改并再次发送到接口。程序数组映射中的跳转当然可以是任意的。当达到最大尾调用限制时，内核最终会执行默认路径。

以下是使用尾调用的最小示例摘录：

```c
[...]

#ifndef __stringify
# define __stringify(X)   #X
#endif

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)          \
   __section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#define BPF_JMP_MAP_ID   1

static void BPF_FUNC(tail_call, struct __sk_buff *skb, void *map,
                     uint32_t index);

struct bpf_elf_map jmp_map __section("maps") = {
    .type           = BPF_MAP_TYPE_PROG_ARRAY,
    .id             = BPF_JMP_MAP_ID,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint32_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 1,
};

__section_tail(BPF_JMP_MAP_ID, 0)
int looper(struct __sk_buff *skb)
{
    printk("skb cb: %u\n", skb->cb[0]++);
    tail_call(skb, &jmp_map, 0);
    return TC_ACT_OK;
}

__section("prog")
int entry(struct __sk_buff *skb)
{
    skb->cb[0] = 0;
    tail_call(skb, &jmp_map, 0);
    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
```

当加载此示例程序时，tc将创建程序数组并将其固定到BPF文件系统中的全局命名空间下的`jmp_map`。此外，iproute2中的BPF ELF加载程序也会识别标记为`__section_tail()`的部分。在`struct bpf_elf_map`中提供的`id`将与`__section_tail()`中的id标记（即`JMP_MAP_ID`）进行匹配，因此在用户指定的程序数组映射索引处加载程序，本示例中为`0`。结果是，iproute2加载程序将所有提供的尾调用部分填充到相应的映射中。此机制不仅适用于tc，还可以应用于iproute2支持的任何其他BPF程序类型（例如XDP、lwt）。

生成的 ELF 包含描述映射 ID 和映射中的条目的section headers ：

```bash
$ llvm-objdump -S --no-show-raw-insn prog_array.o | less
prog_array.o:   file format ELF64-BPF

Disassembly of section 1/0:
looper:
       0:       r6 = r1
       1:       r2 = *(u32 *)(r6 + 48)
       2:       r1 = r2
       3:       r1 += 1
       4:       *(u32 *)(r6 + 48) = r1
       5:       r1 = 0 ll
       7:       call -1
       8:       r1 = r6
       9:       r2 = 0 ll
      11:       r3 = 0
      12:       call 12
      13:       r0 = 0
      14:       exit
Disassembly of section prog:
entry:
       0:       r2 = 0
       1:       *(u32 *)(r1 + 48) = r2
       2:       r2 = 0 ll
       4:       r3 = 0
       5:       call 12
       6:       r0 = 0
       7:       exi
```

在这种情况下，`section 1/0` 表示 `looper()` 函数位于映射 ID `1` 中的位置 `0`。

固定的映射可以由用户空间应用程序（例如 Cilium 守护进程）检索，但也可以由 tc 本身进行检索，以便更新映射中的新程序。更新是原子的，首先从各个子系统触发的初始条目程序也是原子更新的。

以下是 tc 执行尾调用映射更新的示例：

```bash
# tc exec bpf graft m:globals/jmp_map key 0 obj new.o sec foo
```

如果 iproute2 要更新固定的程序数组，可以使用 `graft` 命令。通过将其指向 `globals/jmp_map`，tc 将会使用位于对象文件 `new.o` 中的 `foo` 部分的新程序来更新索引/键为 `0` 的映射。

8. **最大 512 字节的有限堆栈空间。**

BPF 程序的堆栈空间仅限于 512 字节，因此在实现 C 语言的 BPF 程序时需要特别注意。然而，正如前面在第3点中提到的，可以使用具有单个条目的 `BPF_MAP_TYPE_PERCPU_ARRAY` 映射来扩展临时缓冲区空间。

9. **可以使用 BPF 内联汇编。**

从 LLVM 6.0 版本开始，可以在 BPF 中使用内联汇编，用于极少数可能需要的情况。下面是一个（毫无意义的）玩具示例，展示了一个64位的原子加法。由于缺乏文档，LLVM 源代码中的 `lib/Target/BPF/BPFInstrInfo.td` 以及 `test/CodeGen/BPF/` 可能会对提供一些其他示例有所帮助。测试代码：

```c
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("prog")
int xdp_test(struct xdp_md *ctx)
{
    __u64 a = 2, b = 3, *c = &a;
    /* just a toy xadd example to show the syntax */
    asm volatile("lock *(u64 *)(%0+0) += %1" : "=r"(c) : "r"(b), "0"(c));
    return a;
}

char __license[] __section("license") = "GPL";
```

上述程序被编译成以下BPF指令序列：

```assembly
Verifier analysis:

0: (b7) r1 = 2
1: (7b) *(u64 *)(r10 -8) = r1
2: (b7) r1 = 3
3: (bf) r2 = r10
4: (07) r2 += -8
5: (db) lock *(u64 *)(r2 +0) += r1
6: (79) r0 = *(u64 *)(r10 -8)
7: (95) exit
processed 8 insns (limit 131072), stack depth 8
```

10. **使用 #pragma pack 删除结构填充并对齐成员。**

在现代编译器中，数据结构默认按照对内存的高效访问进行对齐。结构体成员被紧密地打包到内存地址中，并添加填充以便与处理器字大小进行适当对齐（例如，64位处理器为8字节，32位处理器为4字节）。因此，结构体的大小往往会比预期更大。

```c
struct called_info {
    u64 start;  // 8-byte
    u64 end;    // 8-byte
    u32 sector; // 4-byte
}; // size of 20-byte ?

printf("size of %d-byte\n", sizeof(struct called_info)); // size of 24-byte

// Actual compiled composition of struct called_info
// 0x0(0)                   0x8(8)
//  ↓________________________↓
//  |        start (8)       |
//  |________________________|
//  |         end  (8)       |
//  |________________________|
//  |  sector(4) |  PADDING  | <= address aligned to 8
//  |____________|___________|     with 4-byte PADDING.
```

内核中的BPF验证器会检查BPF程序的堆栈边界，以确保其不会在边界之外或未初始化的堆栈区域进行访问。如果将填充的结构体用作映射值，将会在`bpf_prog_load()`上导致“invalid indirect read from stack”错误。

示例代码：

```c
struct called_info {
    u64 start;
    u64 end;
    u32 sector;
};

struct bpf_map_def SEC("maps") called_info_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(long),
    .value_size = sizeof(struct called_info),
    .max_entries = 4096,
};

SEC("kprobe/submit_bio")
int submit_bio_entry(struct pt_regs *ctx)
{
    char fmt[] = "submit_bio(bio=0x%lx) called: %llu\n";
    u64 start_time = bpf_ktime_get_ns();
    long bio_ptr = PT_REGS_PARM1(ctx);
    struct called_info called_info = {
            .start = start_time,
            .end = 0,
            .sector = 0
    };

    bpf_map_update_elem(&called_info_map, &bio_ptr, &called_info, BPF_ANY);
    bpf_trace_printk(fmt, sizeof(fmt), bio_ptr, start_time);
    return 0;
}
```

对应在`bpf_load_program()`上的输出：

```
bpf_load_program() err=13
0: (bf) r6 = r1
...
19: (b7) r1 = 0
20: (7b) *(u64 *)(r10 -72) = r1
21: (7b) *(u64 *)(r10 -80) = r7
22: (63) *(u32 *)(r10 -64) = r1
...
30: (85) call bpf_map_update_elem#2
invalid indirect read from stack off -80+20 size 24
```

在`bpf_prog_load()`中，会调用eBPF验证器`bpf_check()`，该验证器会通过调用`check_func_arg() -> check_stack_boundary()`来检查堆栈边界。从上述错误信息中可以看出，`struct called_info` 编译后的大小为24字节，错误信息指出从+20处读取数据是无效的间接读取。正如我们之前讨论的，地址0x14（20）是PADDING所在的位置。

```c
// Actual compiled composition of struct called_info
// 0x10(16)    0x14(20)    0x18(24)
//  ↓____________↓___________↓
//  |  sector(4) |  PADDING  | <= address aligned to 8
//  |____________|___________|     with 4-byte PADDING.
```

`check_stack_boundary()`在内部通过循环遍历从起始指针开始的每个`access_size`（24）字节，以确保其在堆栈边界内，并且堆栈的所有元素都被初始化。由于填充不应该被使用，所以会导致“invalid indirect read from stack”错误。为了避免这种类型的错误，需要通过使用`#pragma pack(n)`指令来去除结构体中的填充。

使用`#pragma pack(n)`指令去除填充：

```c
#pragma pack(4)
struct called_info {
    u64 start;  // 8-byte
    u64 end;    // 8-byte
    u32 sector; // 4-byte
}; // size of 20-byte ?

printf("size of %d-byte\n", sizeof(struct called_info)); // size of 20-byte

// Actual compiled composition of packed struct called_info
// 0x0(0)                   0x8(8)
//  ↓________________________↓
//  |        start (8)       |
//  |________________________|
//  |         end  (8)       |
//  |________________________|
//  |  sector(4) |             <= address aligned to 4
//  |____________|                 with no PADDING.
```

通过将`#pragma pack(4)`放置在`struct called_info`之前，编译器会将结构体成员对齐到4字节或其自然对齐较小者。正如您所看到的，`struct called_info`的大小已经缩小到20字节，不再存在填充。

但是，去除填充也有缺点。例如，编译器将生成较少优化的代码。由于我们去除了填充，处理器将对结构体进行不对齐的访问，可能会导致性能下降。而且，在某些架构上，不对齐的访问可能会被验证器拒绝。

然而，有一种方法可以避免紧凑结构的缺点。只需在结构的末尾添加显式填充`u32 pad`成员，就可以解决相同的问题，而无需压缩结构。

```c
struct called_info {
    u64 start;  // 8-byte
    u64 end;    // 8-byte
    u32 sector; // 4-byte
    u32 pad;    // 4-byte
}; // size of 24-byte ?

printf("size of %d-byte\n", sizeof(struct called_info)); // size of 24-byte

// Actual compiled composition of struct called_info with explicit padding
// 0x0(0)                   0x8(8)
//  ↓________________________↓
//  |        start (8)       |
//  |________________________|
//  |         end  (8)       |
//  |________________________|
//  |  sector(4) |  pad (4)  | <= address aligned to 8
//  |____________|___________|     with explicit PADDING.
```

11. **通过无效引用访问数据包数据**

一些网络BPF辅助函数，例如`bpf_skb_store_bytes`，可能会改变数据包数据的大小。由于验证器无法跟踪此类更改，对数据的任何先前引用都将被验证器使无效。因此，在访问数据之前需要更新引用，以避免验证器拒绝程序。

为了说明这一点，考虑以下代码片段：

```c
struct iphdr *ip4 = (struct iphdr *) skb->data + ETH_HLEN;

skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &new_saddr, 4, 0);

if (ip4->protocol == IPPROTO_TCP) {
    // do something
}
```

由于对无效的`ip4->protocol`进行解引用，验证器将拒绝此代码片段：

```
R1=pkt_end(id=0,off=0,imm=0) R2=pkt(id=0,off=34,r=34,imm=0) R3=inv0
R6=ctx(id=0,off=0,imm=0) R7=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff))
R8=inv4294967162 R9=pkt(id=0,off=0,r=34,imm=0) R10=fp0,call_-1
...
18: (85) call bpf_skb_store_bytes#9
19: (7b) *(u64 *)(r10 -56) = r7
R0=inv(id=0) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0,umax_value=2,var_off=(0x0; 0x3))
R8=inv4294967162 R9=inv(id=0) R10=fp0,call_-1 fp-48=mmmm???? fp-56=mmmmmmmm
21: (61) r1 = *(u32 *)(r9 +23)
R9 invalid mem access 'inv'
```

要解决此问题，必须更新对`ip4`的引用：

```c
struct iphdr *ip4 = (struct iphdr *) skb->data + ETH_HLEN;

skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &new_saddr, 4, 0);

ip4 = (struct iphdr *) skb->data + ETH_HLEN;

if (ip4->protocol == IPPROTO_TCP) {
    // do something
}
```

## iproute2

有各种前端用于将BPF程序加载到内核中，例如bcc、perf、iproute2等。Linux内核源代码树还提供了一个位于`tools/lib/bpf/`目录下的用户空间库，主要由perf用于将BPF跟踪程序加载到内核中。然而，该库本身是通用的，不仅限于perf。bcc是一个工具包，提供许多有用的BPF程序，主要用于跟踪，通过嵌入BPF C代码的Python接口进行临时加载。总的来说，不同前端实现BPF程序的语法和语义略有不同。此外，内核源代码树中还有BPF示例（`samples/bpf/`），它们解析生成的目标文件，并通过系统调用接口直接加载代码。

本节和前面的几节主要关注于iproute2套件的BPF前端，用于加载XDP、tc或lwt类型的网络程序，因为Cilium的程序是针对这个BPF加载器实现的。未来，Cilium将配备一个原生的BPF加载器，但程序仍然兼容通过iproute2套件加载，以便于开发和调试。

iproute2支持的所有BPF程序类型共享相同的BPF加载器逻辑，因为它们都有一个通用的加载器后端实现，作为一个库（iproute2源代码树中的`lib/bpf.c`）。

前面关于LLVM的部分还涵盖了与编写BPF C程序有关的一些iproute2部分，本文档后面的部分与编写程序时的tc和XDP特定方面有关。因此，本节将更多地关注使用iproute2加载目标文件的用法示例，以及加载器的一些通用机制。它不会试图提供对所有细节的完全覆盖，但足够帮助入门。

1. **加载XDP BPF目标文件。**

假设已经为XDP编译了一个BPF目标文件`prog.o`，可以使用以下命令将其加载到名为`em1`的支持XDP的网络设备中：

```bash
# ip link set dev em1 xdp obj prog.o
```

上述命令假设程序代码位于默认的段中，在XDP情况下被称为`prog`。如果不是这种情况，而段的名称不同，例如`foobar`，那么需要按如下方式加载程序：

```bash
# ip link set dev em1 xdp obj prog.o sec foobar
```

请注意，还可以将程序加载到`.text`段之外。通过从`xdp_drop`入口点中删除`__section()`注释，将最小化的独立XDP丢弃程序进行更改，将如下所示：

```c
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

int xdp_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char __license[] __section("license") = "GPL";
```

并且可以如下加载：

```bash
# ip link set dev em1 xdp obj prog.o sec .text
```

默认情况下，如果一个XDP程序已经附加到网络接口上，`ip`命令会抛出错误，以防止意外覆盖。为了用新程序替换当前正在运行的XDP程序，必须使用`-force`选项：

```bash
# ip -force link set dev em1 xdp obj prog.o
```

大多数现代的XDP驱动程序支持无中断地将现有程序替换为新程序。由于性能原因，XDP驱动程序始终只附加一个程序，因此不支持程序链。然而，如前一节所述，可以通过尾调用进行程序分割，以在必要时实现类似的用例。

如果接口附加了XDP程序，`ip link`命令将显示一个`xdp`标志。因此，可以使用`ip link | grep xdp`来查找所有正在运行XDP的接口。通过详细视图（`ip -d link`）可以提供进一步的内省功能（introspection facilities），而`bpftool`可以用于基于在`ip link`输出中显示的BPF程序ID来检索有关附加程序的信息。

要从接口中移除现有的XDP程序，必须使用以下命令：

```bash
# ip link set dev em1 xdp off
```

在将驱动程序的操作模式从non-XDP切换到Native XDP或反之亦然时，通常需要重新配置接收（和发送）环，以确保接收的数据包在单个页面内线性设置，以便BPF进行读写。然而，一旦完成，大多数驱动程序只需要在请求交换BPF程序时执行程序本身的原子替换。

总共有三种XDP操作模式，iproute2也实现了这三种：`xdpdrv`、`xdpoffload`和`xdpgeneric`。

- `xdpdrv` 代表native XDP，意味着BPF程序直接在驱动程序的接收路径上在最早可能的软件点运行。这是普通/传统的XDP模式，要求驱动程序实现XDP支持，上游Linux内核中的所有主要的10G/40G/+网络驱动程序都已提供。
- `xdpgeneric` 代表通用XDP（generic XDP），旨在作为尚不支持native XDP的驱动程序的实验性测试平台。由于通用XDP挂钩在数据包已经作为`skb`进入栈的主接收路径的较晚时间点，性能比在`xdpdrv`模式下处理要低得多。因此，`xdpgeneric`在很大程度上只适用于实验，而不适用于生产环境。
- 最后，`xdpoffload`模式由智能网卡（如Netronome的nfp驱动程序支持的智能网卡）实现，允许将整个BPF/XDP程序offloaded 到硬件中，因此程序直接在每个数据包接收时在网卡上运行。这提供了比在native XDP中运行更高的性能，尽管与native XDP相比，并非所有BPF映射类型或BPF辅助函数都可供使用。在这种情况下，BPF验证器将拒绝程序并向用户报告不受支持的内容。除了停留在受支持的 BPF 功能和辅助函数范围内之外，在编写 BPF C 程序时无需采取特殊的预防措施。

当使用类似`ip link set dev em1 xdp obj [...]`的命令时，内核将首先尝试将程序加载为native XDP，如果驱动程序不支持native XDP，则会自动回退到通用XDP。因此，例如，显式使用`xdpdrv`而不是`xdp`，内核将仅尝试将程序作为native XDP加载，如果驱动程序不支持，则会失败，这可以保证完全避免通用XDP。

下面是一个强制加载BPF/XDP程序以native XDP模式运行、转储链接详细信息并再次offloaded 程序的示例：

```bash
# ip -force link set dev em1 xdpdrv obj prog.o
# ip link show
[...]
6: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc mq state UP mode DORMANT group default qlen 1000
    link/ether be:08:4d:b6:85:65 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 1 tag 57cd311f2e27366b
[...]
# ip link set dev em1 xdpdrv off
```

现在使用相同的示例强制通用 XDP模式，即使驱动程序支持native XDP，并另外通过 bpftool 转储附加虚拟程序的 BPF 指令：

```bash
# ip -force link set dev em1 xdpgeneric obj prog.o
# ip link show
[...]
6: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc mq state UP mode DORMANT group default qlen 1000
    link/ether be:08:4d:b6:85:65 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 4 tag 57cd311f2e27366b                <-- BPF program ID 4
[...]
# bpftool prog dump xlated id 4                       <-- Dump of instructions running on em1
0: (b7) r0 = 1
1: (95) exit
# ip link set dev em1 xdpgeneric off
```

最后但同样重要的是offloaded XDP，我们还通过 bpftool 转储程序信息以检索一般元数据：

```bash
# ip -force link set dev em1 xdpoffload obj prog.o
# ip link show
[...]
6: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpoffload qdisc mq state UP mode DORMANT group default qlen 1000
    link/ether be:08:4d:b6:85:65 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 8 tag 57cd311f2e27366b
[...]
# bpftool prog show id 8
8: xdp  tag 57cd311f2e27366b dev em1                  <-- Also indicates a BPF program offloaded to em1
    loaded_at Apr 11/20:38  uid 0
    xlated 16B  not jited  memlock 4096B
# ip link set dev em1 xdpoffload off
```

请注意，不能同时使用`xdpdrv`、`xdpgeneric`或其他模式，意味着必须选择其中一种XDP操作模式。

从通用模式切换到native模式不能以原子方式完成，反之亦然。只有在特定操作模式下切换程序才是原子的：

```bash
# ip -force link set dev em1 xdpgeneric obj prog.o
# ip -force link set dev em1 xdpoffload obj prog.o
RTNETLINK answers: File exists
# ip -force link set dev em1 xdpdrv obj prog.o
RTNETLINK answers: File exists
# ip -force link set dev em1 xdpgeneric obj prog.o    <-- Succeeds due to xdpgeneric
```

在切换模式之前，需要首先离开当前的操作模式，然后进入新的模式：

```bash
# ip -force link set dev em1 xdpgeneric obj prog.o
# ip -force link set dev em1 xdpgeneric off
# ip -force link set dev em1 xdpoffload obj prog.o
# ip l
[...]
6: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpoffload qdisc mq state UP mode DORMANT group default qlen 1000
    link/ether be:08:4d:b6:85:65 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 17 tag 57cd311f2e27366b
[...]
# ip -force link set dev em1 xdpoffload off
```

2. **加载tc BPF目标文件。**

假设已经为tc编译了一个BPF目标文件`prog.o`，可以通过tc命令将其加载到一个网络设备上。与XDP不同，支持将BPF程序附加到设备的操作不依赖于驱动程序。在这里，网络设备称为`em1`，通过以下命令，可以将程序附加到`em1`的网络“ingress”路径上：

```bash
# tc qdisc add dev em1 clsact
# tc filter add dev em1 ingress bpf da obj prog.o
```

第一步是设置一个`clsact`队列规则（Linux排队规则）。`clsact`是类似于`ingress`队列规则的虚拟队列规则，它只能包含分类器和操作，但不执行实际的排队。这是为了附加`bpf`分类器所需的。`clsact`队列规则提供了两个特殊的钩子，称为`ingress`和`egress`，可以在这两个钩子上附加分类器。`ingress`和`egress`钩子位于网络数据路径中的中央接收和传输位置，设备上的每个数据包都会通过这里。`ingress`钩子在内核中从`__netif_receive_skb_core() -> sch_handle_ingress()`调用，而`egress`钩子从`__dev_queue_xmit() -> sch_handle_egress()`调用。

将程序附加到`egress`钩子的等效方式如下所示：

```bash
# tc filter add dev em1 egress bpf da obj prog.o
```

`clsact`队列规则从`ingress`和`egress`方向进行无锁处理，也可以附加到虚拟的无队列设备，比如连接容器的`veth`设备。

除了钩子之外，`tc filter`命令还选择在`da`（直接操作）模式下使用`bpf`。推荐使用`da`模式，并且应该始终指定。基本上，这意味着`bpf`分类器不需要调用外部tc操作模块，这对于`bpf`来说是不必要的，因为所有的数据包操作、转发或其他类型的操作都可以在要附加的单个BPF程序内执行，因此速度会更快。

此时，程序已经被附加，并且在数据包穿越设备时执行。与XDP类似，如果不使用默认的段名，可以在加载时指定，例如，对于段名`foobar`的情况：

```bash
# tc filter add dev em1 egress bpf da obj prog.o sec foobar
```

iproute2的BPF加载器允许在不同的程序类型之间使用相同的命令行语法，因此`obj prog.o sec foobar`与前面提到的XDP的语法是相同的。

可以通过以下命令列出附加的程序：

```bash
# tc filter show dev em1 ingress
filter protocol all pref 49152 bpf
filter protocol all pref 49152 bpf handle 0x1 prog.o:[ingress] direct-action id 1 tag c5f7825e5dac396f

# tc filter show dev em1 egress
filter protocol all pref 49152 bpf
filter protocol all pref 49152 bpf handle 0x1 prog.o:[egress] direct-action id 2 tag b2fd5adc0f262714
```

`prog.o:[ingress]`的输出说明了从文件`prog.o`加载了程序段`ingress`，而且`bpf`以`direct-action`模式运行。对于每种情况，都附加了程序的`id`和`tag`，其中后者表示对指令流进行哈希处理，可以与对象文件或者带有栈跟踪等信息的`perf`报告相关联。最后但同样重要的是，`id`表示了系统范围内唯一的BPF程序标识符，可以与`bpftool`一起使用，以进一步检查或转储已附加的BPF程序。

tc可以附加不止一个BPF程序，它还提供了各种其他的分类器，可以将它们链接在一起。然而，附加单个BPF程序已经足够，因为所有的数据包操作都可以包含在程序自身中，这得益于`da`（`direct-action`）模式，这意味着BPF程序本身将返回tc操作的判决，例如`TC_ACT_OK`、`TC_ACT_SHOT`等。为了获得最佳性能和灵活性，这是推荐的用法。

在上述`show`命令中，tc还在与BPF相关的输出旁边显示了`pref 49152`和`handle 0x1`。如果这些参数在命令行中没有明确提供，它们将会被自动生成。`pref`表示优先级号，这意味着如果附加了多个分类器，它们将根据升序优先级执行，而`handle`表示在同一个`pref`下加载了多个相同分类器实例的标识符。由于在BPF的情况下，单个程序已经足够，通常可以忽略`pref`和`handle`。

只有在计划原子地替换已附加的BPF程序的情况下，才建议在初始加载时明确指定`pref`和`handle`，以便在以后的时间点不必为`replace`操作查询它们。因此，创建操作变为：

```bash
# tc filter add dev em1 ingress pref 1 handle 1 bpf da obj prog.o sec foobar

# tc filter show dev em1 ingress
filter protocol all pref 1 bpf
filter protocol all pref 1 bpf handle 0x1 prog.o:[foobar] direct-action id 1 tag c5f7825e5dac396f
```

而对于原子替换，可以使用以下命令来更新现有的程序，将入口钩子中的新BPF程序从文件`prog.o`的`foobar`段加载进去：

```bash
# tc filter replace dev em1 ingress pref 1 handle 1 bpf da obj prog.o sec foobar
```

最后但同样重要的一点是，为了从入口和出口钩子中删除所有附加的程序，可以使用以下命令：

```bash
# tc filter del dev em1 ingress
# tc filter del dev em1 egress
```

要从网络设备中删除整个`clsact`队列规则，这也会隐式地将所有附加的程序从`ingress`和`egress`钩子中删除，可以使用以下命令：

```bash
# tc qdisc del dev em1 clsact
```

与XDP BPF程序类似，如果网卡和驱动程序支持，tc BPF程序也可以进行offloaded 。Netronome的nfp支持的网卡提供了这两种类型的BPF offloaded功能。

```bash
# tc qdisc add dev em1 clsact
# tc filter replace dev em1 ingress pref 1 handle 1 bpf skip_sw da obj prog.o
Error: TC offload is disabled on net device.
We have an error talking to the kernel
```

如果显示了上述错误，则首先需要通过ethtool的`hw-tc-offload`设置为设备启用tc硬件卸载功能：

```bash
# ethtool -K em1 hw-tc-offload on
# tc qdisc add dev em1 clsact
# tc filter replace dev em1 ingress pref 1 handle 1 bpf skip_sw da obj prog.o
# tc filter show dev em1 ingress
filter protocol all pref 1 bpf
filter protocol all pref 1 bpf handle 0x1 prog.o:[classifier] direct-action skip_sw in_hw id 19 tag 57cd311f2e27366b
```

`in_hw`标志确认程序已经卸载到了网卡上。

请注意，无论是tc还是XDP的BPF卸载选项，不能同时加载。必须选择其中一个。

3. **通过netdevsim驱动程序测试BPF卸载接口。**

Linux内核的netdevsim驱动程序提供了一个虚拟驱动程序，它实现了XDP BPF和tc BPF程序的卸载接口，并且可以用于测试内核更改或实现直接针对内核UAPI的控制平面的低级用户空间程序。

可以按照以下方式创建一个netdevsim设备：

```bash
# modprobe netdevsim
// [ID] [PORT_COUNT]
# echo "1 1" > /sys/bus/netdevsim/new_device
# devlink dev
netdevsim/netdevsim1
# devlink port
netdevsim/netdevsim1/0: type eth netdev eth0 flavour physical
# ip l
[...]
4: eth0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 2a:d5:cd:08:d1:3f brd ff:ff:ff:ff:ff:ff
```

在完成上述步骤后，可以像之前的各个示例中所示，进行XDP BPF或tc BPF程序的测试加载：

```bash
# ip -force link set dev eth0 xdpoffload obj prog.o
# ip l
[...]
4: eth0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 xdpoffload qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 2a:d5:cd:08:d1:3f brd ff:ff:ff:ff:ff:ff
    prog/xdp id 16 tag a04f5eef06a7f555
```

这两个工作流程是使用iproute2加载XDP BPF和tc BPF程序的基本操作。

对于BPF加载器，还有其他各种高级选项，适用于XDP和tc，其中一些列在这里。出于简单起见，示例中只展示了XDP。

1. **即使成功也显示详细日志输出。**
   可以附加选项`verb`来加载程序，以便在没有发生错误的情况下转储验证器日志：

```bash
# ip link set dev em1 xdp obj xdp-example.o verb

Prog section 'prog' loaded (5)!
 - Type:         6
 - Instructions: 2 (0 over limit)
 - License:      GPL

Verifier analysis:

0: (b7) r0 = 1
1: (95) exit
processed 2 insns
```

2. **加载已经固定在BPF文件系统中的程序：**

除了从目标文件加载程序，iproute2还可以从BPF文件系统中获取程序，以便在某些外部实体将其固定在那里并将其附加到设备上：

```bash
# ip link set dev em1 xdp pinned /sys/fs/bpf/prog
```

iproute2还可以使用相对于检测到的BPF文件系统的挂载点的短形式：

```bash
# ip link set dev em1 xdp pinned m:prog
```

在加载BPF程序时，iproute2将自动检测已挂载的文件系统实例以执行节点固定。如果没有找到已挂载的BPF文件系统实例，则tc将自动将其挂载到默认位置`/sys/fs/bpf/`下。

如果已经找到一个实例，则将使用该实例，不会执行额外的挂载：

```bash
# mkdir /var/run/bpf
# mount --bind /var/run/bpf /var/run/bpf
# mount -t bpf bpf /var/run/bpf
# tc filter add dev em1 ingress bpf da obj tc-example.o sec prog
# tree /var/run/bpf
/var/run/bpf
+-- ip -> /run/bpf/tc/
+-- tc
|   +-- globals
|       +-- jmp_map
+-- xdp -> /run/bpf/tc/

4 directories, 1 file
```

默认情况下，tc将创建一个初始的目录结构，如上所示，在`globals`命名空间中，所有子系统用户将通过符号链接指向相同的位置，以便在iproute2中各种BPF程序类型之间可以重复使用固定的BPF映射。如果文件系统实例已经被挂载，并且已经存在现有的结构，则tc将不会覆盖它。这可以用于将`lwt`、`tc`和`xdp`映射分开，以便不在所有映射之间共享`globals`。	

正如前面LLVM部分简要介绍的那样，在安装过程中，iproute2将安装一个头文件，BPF程序可以通过标准的包含路径包含该头文件：

```c
#include <iproute2/bpf_elf.h>
```

这个头文件的目的是为程序提供映射和默认段名的API。它是iproute2和BPF程序之间的稳定合约。

iproute2的映射定义为`struct bpf_elf_map`。它的成员在本文档的前面的LLVM部分已经介绍过了。

在解析BPF目标文件时，iproute2加载器会遍历所有的ELF段。它首先获取辅助段，如`maps`和`license`。对于`maps`，将检查`struct bpf_elf_map`数组的有效性，并在需要时执行兼容性的处理。然后，使用用户提供的信息创建所有的映射，无论是作为固定对象检索的，还是新创建的，然后固定到BPF文件系统中。接下来，加载器将处理所有包含用于映射的ELF重定位条目的程序段，这意味着将BPF指令加载映射文件描述符到寄存器中的部分将被重写，以便将相应的映射文件描述符编码到指令的立即值中，以便内核能够稍后将它们转换为映射内核指针。之后，所有的程序本身将通过BPF系统调用创建，并且如果存在的话，尾调用的映射将使用程序的文件描述符进行更新。