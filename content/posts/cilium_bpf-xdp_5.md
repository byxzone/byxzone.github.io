---
title: "BPF开发工具（一）"
date: 2023-08-10T21:40:35+08:00
categories: ["eBPF","Linux Kernel"]

---

原文链接：https://docs.cilium.io/en/latest/bpf/toolchain/

本节讨论了关于BPF的用户空间工具、自检设施（introspection facilities）和内核控制选项。

> Note
>
> 围绕BPF的工具和基础设施仍在快速发展中，因此可能无法完整呈现所有可用工具的全貌。

## 开发环境

以下是在Fedora和Ubuntu上设置BPF开发环境的逐步指南。本指南将引导您完成构建、安装和测试开发内核，以及构建和安装iproute2。

通常情况下，手动构建iproute2和Linux内核通常是不必要的，因为主要发行版默认已经安装了足够新的内核，但对于测试最新版本或向iproute2和Linux内核贡献BPF补丁，这是必需的。同样地，为了调试和自检的目的，构建bpftool是可选的，但推荐这样做。

- **Fedora**

The following applies to Fedora 25 or later:

```bash
$ sudo dnf install -y git gcc ncurses-devel elfutils-libelf-devel bc \
  openssl-devel libcap-devel clang llvm graphviz bison flex glibc-static
```

> Note
>
> 如果您正在运行其他 Fedora 衍生产品并且缺少 `dnf`，请尝试使用 `yum` 代替。

- **Ubuntu**

The following applies to Ubuntu 17.04 or later:

```bash
$ sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev \
  clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev bison flex \
  graphviz
```

- **openSUSE Tumbleweed**

The following applies to openSUSE Tumbleweed and openSUSE Leap 15.0 or later:

```bash
$ sudo zypper install -y git gcc ncurses-devel libelf-devel bc libopenssl-devel \
libcap-devel clang llvm graphviz bison flex glibc-devel-static
```

### 编译内核

Linux内核的新BPF功能开发发生在`net-next` git树中，最新的BPF修复在`net`树中。以下命令将通过git获取`net-next`树的内核源代码：

```bash
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git
```

如果不关心git提交历史记录，那么使用`--depth 1`选项将只保留最近的提交记录，从而更快地克隆树。

如果您对`net`树感兴趣，可以从以下URL进行克隆：

```bash
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git
```

互联网上有许多关于如何构建Linux内核的教程，一个很好的资源是Kernel Newbies网站（https://kernelnewbies.org/KernelBuild），可以根据上面提到的两个git树之一进行操作。

确保生成的`.config`文件包含以下用于运行BPF的`CONFIG_*`条目。这些条目对于Cilium也是必需的。

```
CONFIG_CGROUP_BPF=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_ACT=y
CONFIG_BPF_JIT=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_TEST_BPF=m
```

其中一些条目无法通过`make menuconfig`进行调整。例如，如果特定架构配备了eBPF JIT，则会自动选择`CONFIG_HAVE_EBPF_JIT`。在这种特定情况下，`CONFIG_HAVE_EBPF_JIT`是可选的，但强烈推荐使用。如果某个架构没有eBPF JIT编译器，将需要回退到内核内解释器，这会导致执行BPF指令的效率降低。

### 验证设置

在您启动到新编译的内核后，前往BPF自测试套件以测试BPF功能（当前工作目录指向克隆的git树的根目录）：

```bash
$ cd tools/testing/selftests/bpf/
$ make
$ sudo ./test_verifier
```

验证器测试会打印出当前正在执行的所有检查。在运行所有测试结束时，总结会显示测试的成功和失败信息：

```
Summary: 847 PASSED, 0 SKIPPED, 0 FAILED
```

> Note
>
> 对于内核版本4.16+，BPF自测试依赖于LLVM 6.0+，这是由于不再需要内联的BPF函数调用。有关更多信息，请参阅[ BPF to BPF Calls](https://docs.cilium.io/en/latest/bpf/architecture/#bpf-to-bpf-calls)章节或内核补丁的封面信（https://lwn.net/Articles/741773/）。并非每个BPF程序都依赖于LLVM 6.0+，如果不使用此新特性，则没有这个依赖。如果您的发行版没有提供LLVM 6.0+，您可以按照[LLVM](https://docs.cilium.io/en/latest/bpf/toolchain/#tooling-llvm)章节中的说明进行编译。

为了运行所有的BPF自测试，需要使用以下命令：

```bash
$ sudo make run_tests
```

如果您看到任何失败，请使用完整的测试输出在[Cilium Slack](https://cilium.herokuapp.com/)上与我们联系。

### 编译iproute2

类似于`net`（仅修复）和`net-next`（新特性）内核树，iproute2的git树也有两个分支，分别是`master`和`net-next`。`master`分支基于`net`树，`net-next`分支基于`net-next`内核树。这是必要的，以便可以在iproute2树中同步头文件的更改。

为了克隆iproute2的`master`分支，可以使用以下命令：

```bash
$ git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
```

同样地，要克隆到iproute2的上述`net-next`分支，运行以下命令：

```bash
$ git clone -b net-next https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
```

之后，继续构建和安装：

```bash
$ cd iproute2/
$ ./configure --prefix=/usr
TC schedulers
 ATM    no

libc has setns: yes
SELinux support: yes
ELF support: yes
libmnl support: no
Berkeley DB: no

docs: latex: no
 WARNING: no docs can be built from LaTeX files
 sgml2html: no
 WARNING: no HTML docs can be built from SGML
$ make
[...]
$ sudo make install
```

确保`configure`脚本显示`ELF support: yes`，以便iproute2可以处理来自LLVM的BPF后端的ELF文件。在之前的Fedora和Ubuntu的依赖项安装说明中列出了libelf。

### 编译bpftool

`bpftool`是围绕BPF程序和映射的调试和自检的重要工具。它是内核树的一部分，位于`tools/bpf/bpftool/`目录下。

请确保已按照前面的说明克隆了`net`或`net-next`内核树。为了构建和安装bpftool，需要执行以下步骤：

```bash
$ cd <kernel-tree>/tools/bpf/bpftool/
$ make
Auto-detecting system features:
...                        libbfd: [ on  ]
...        disassembler-four-args: [ OFF ]

  CC       xlated_dumper.o
  CC       prog.o
  CC       common.o
  CC       cgroup.o
  CC       main.o
  CC       json_writer.o
  CC       cfg.o
  CC       map.o
  CC       jit_disasm.o
  CC       disasm.o
make[1]: Entering directory '/home/foo/trees/net/tools/lib/bpf'

Auto-detecting system features:
...                        libelf: [ on  ]
...                           bpf: [ on  ]

  CC       libbpf.o
  CC       bpf.o
  CC       nlattr.o
  LD       libbpf-in.o
  LINK     libbpf.a
make[1]: Leaving directory '/home/foo/trees/bpf/tools/lib/bpf'
  LINK     bpftool
$ sudo make install
```

## LLVM

目前，LLVM是唯一提供BPF后端的编译器套件。gcc在这一点上不支持BPF。

BPF后端已合并到LLVM的3.7版本中。主要的发行版在打包LLVM时默认启用了BPF后端，因此在大多数最新的发行版上，只需要安装clang和llvm即可开始将C编译成BPF对象文件。

典型的工作流程是，BPF程序以C语言编写，由LLVM编译成object/ELF文件，这些文件由用户空间的BPF ELF加载器（例如iproute2或其他工具）解析，通过BPF系统调用推送到内核中。内核会验证BPF指令并对其进行即时编译（JIT），返回一个新的程序文件描述符，然后可以将该描述符附加到子系统（例如网络）。如果支持，子系统还可以将BPF程序进一步卸载到硬件（例如网卡）。

要检查LLVM是否支持BPF目标，请参考以下示例：

```bash
$ llc --version
LLVM (http://llvm.org/):
LLVM version 3.8.1
Optimized build.
Default target: x86_64-unknown-linux-gnu
Host CPU: skylake

Registered Targets:
  [...]
  bpf        - BPF (host endian)
  bpfeb      - BPF (big endian)
  bpfel      - BPF (little endian)
  [...]
```

默认情况下，`bpf`目标使用编译所在CPU的字节顺序，这意味着如果CPU的字节顺序是小端，程序也将以小端格式表示，如果CPU的字节顺序是大端，程序则以大端格式表示。这也与BPF的运行时行为相匹配，BPF是通用的，并使用它运行在的CPU的字节顺序，以不会在任何格式中对架构造成不利影响。

对于交叉编译，引入了`bpfeb`和`bpfel`这两个目标，因此可以在以一种字节顺序（例如x86上的小端）运行的节点上编译BPF程序，然后在以另一种字节顺序格式（例如arm上的大端）运行的节点上运行。需要注意的是，前端（clang）也需要以目标字节顺序运行。

在没有字节顺序混合的情况下，使用`bpf`作为目标是首选方式。例如，对于`x86_64`上的编译，在`bpf`和`bpfel`目标上的输出是相同的，因为都是小端字节顺序，因此触发编译的脚本也不必考虑字节顺序。

一个简单的、独立的XDP丢弃程序示例可能如下所示（`xdp-example.c`）：

```c
#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char __license[] __section("license") = "GPL";
```

然后可以将其编译并加载到内核中，如下所示：

```bash
$ clang -O2 -Wall --target=bpf -c xdp-example.c -o xdp-example.o
$ ip link set dev em1 xdp obj xdp-example.o
```

> Note
>
> 如上所述将 XDP BPF 程序附加到网络设备需要 Linux 4.11 以及支持 XDP 的设备，或者 Linux 4.12 或更高版本。

对于生成的目标文件，LLVM（>= 3.9）使用官方的BPF机器值，即`EM_BPF`（十进制：`247` / 十六进制：`0xf7`）。在此示例中，程序已使用`bpf`目标在`x86_64`上编译，因此关于字节顺序显示为`LSB`（与`MSB`相反）：

```bash
$ file xdp-example.o
xdp-example.o: ELF 64-bit LSB relocatable, *unknown arch 0xf7* version 1 (SYSV), not stripped
```

`readelf -a xdp-example.o`将进一步展示有关ELF文件的信息，有时候对于自检生成的节头、重定位条目和符号表会很有用。

在极少数情况下，如果需要从头编译clang和LLVM，可以使用以下命令：

```bash
$ git clone https://github.com/llvm/llvm-project.git
$ cd llvm-project
$ mkdir build
$ cd build
$ cmake -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD="BPF;X86" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_RUNTIME=OFF  -G "Unix Makefiles" ../llvm
$ make -j $(getconf _NPROCESSORS_ONLN)
$ ./bin/llc --version
LLVM (http://llvm.org/):
LLVM version x.y.zsvn
Optimized build.
Default target: x86_64-unknown-linux-gnu
Host CPU: skylake

Registered Targets:
  bpf    - BPF (host endian)
  bpfeb  - BPF (big endian)
  bpfel  - BPF (little endian)
  x86    - 32-bit X86: Pentium-Pro and above
  x86-64 - 64-bit X86: EM64T and AMD64

$ export PATH=$PWD/bin:$PATH   # add to ~/.bashrc
```

确保`--version`中提到了`Optimized build.`，否则在使用LLVM进行调试时，程序的编译时间将显著增加（例如增加10倍或更多）。

对于调试，可以使用以下方法生成clang的汇编输出：

```bash
$ clang -O2 -S -Wall --target=bpf -c xdp-example.c -o xdp-example.S
$ cat xdp-example.S
    .text
    .section    prog,"ax",@progbits
    .globl      xdp_drop
    .p2align    3
xdp_drop:                             # @xdp_drop
# BB#0:
    r0 = 1
    exit

    .section    license,"aw",@progbits
    .globl    __license               # @__license
__license:
    .asciz    "GPL"
```

从LLVM的6.0版本开始，还引入了汇编器解析器支持。您可以直接使用BPF汇编语言进行编程，然后使用llvm-mc将其汇编成目标文件。例如，您可以使用以下命令将上面列出的xdp-example.S文件汇编回目标文件：

```bash
$ llvm-mc -triple bpf -filetype=obj -o xdp-example.o xdp-example.S
```

此外，更新的LLVM版本（>= 4.0）还可以将调试信息以dwarf格式存储在目标文件中。可以通过在编译时添加`-g`来完成这个常规的工作流程。

```bash
$ clang -O2 -g -Wall --target=bpf -c xdp-example.c -o xdp-example.o
$ llvm-objdump -S --no-show-raw-insn xdp-example.o

xdp-example.o:        file format ELF64-BPF

Disassembly of section prog:
xdp_drop:
; {
    0:        r0 = 1
; return XDP_DROP;
    1:        exit
```

然后，`llvm-objdump`工具可以使用编译时使用的原始C代码对汇编输出进行注释。在这种情况下，这个简单的示例并不包含太多C代码，然而，显示为`0:`和`1:`的行号直接对应于内核的验证器（verifier）日志。

这意味着，如果BPF程序被验证器拒绝，`llvm-objdump`可以帮助将指令与原始的C代码进行关联，这对于分析非常有用。

```bash
$ ip link set dev em1 xdp obj xdp-example.o verb

Prog section 'prog' loaded (5)!
 - Type:         6
 - Instructions: 2 (0 over limit)
 - License:      GPL

Verifier analysis:

0: (b7) r0 = 1
1: (95) exit
processed 2 insns
```

正如在验证器分析中所看到的，`llvm-objdump`输出会转储与内核相同的BPF汇编代码。

如果省略`--no-show-raw-insn`选项，还会在汇编代码前以十六进制形式转储原始的`struct bpf_insn`：

```bash
$ llvm-objdump -S xdp-example.o

xdp-example.o:        file format ELF64-BPF

Disassembly of section prog:
xdp_drop:
; {
   0:       b7 00 00 00 01 00 00 00     r0 = 1
; return foo();
   1:       95 00 00 00 00 00 00 00     exit
```

对于LLVM IR调试，BPF的编译过程可以分为两个步骤，生成一个二进制LLVM IR中间文件`xdp-example.bc`，稍后可以将其传递给llc：

```bash
$ clang -O2 -Wall --target=bpf -emit-llvm -c xdp-example.c -o xdp-example.bc
$ llc xdp-example.bc -march=bpf -filetype=obj -o xdp-example.o
```

生成的LLVM IR也可以通过以下命令以人类可读的格式进行转储：

```bash
$ clang -O2 -Wall -emit-llvm -S -c xdp-example.c -o -
```

LLVM能够将调试信息附加到生成的BPF目标文件中，例如程序中使用的数据类型的描述。默认情况下，这是以DWARF格式存储的。

BPF使用的一个大大简化的版本称为BTF（BPF Type Format）。生成的DWARF可以转换为BTF，并通过BPF目标加载器加载到内核中。内核然后会验证BTF数据的正确性，并跟踪BTF数据所包含的数据类型。

然后，BPF映射可以通过BTF数据进行键和值类型的注释，以便以后对映射的转储会导出与相关类型信息一起的映射数据。这可以更好地进行自检、调试和值的美观地打印。请注意，BTF数据是通用的调试数据格式，因此任何DWARF到BTF转换的数据都可以加载（例如内核的vmlinux DWARF数据可以转换为BTF并加载）。后者尤其适用于未来的BPF跟踪。

为了从DWARF调试信息生成BTF，需要elfutils（>= 0.173）。如果没有这个库，那么在编译期间需要在`llc`命令中添加`-mattr=dwarfris`选项：

```bash
$ llc -march=bpf -mattr=help |& grep dwarfris
  dwarfris - Disable MCAsmInfo DwarfUsesRelocationsAcrossSections.
  [...]
```

使用`-mattr=dwarfris`标志的原因是，标志dwarfris（段中的dwarf重定位）禁用了DWARF与ELF符号表之间的DWARF跨段重定位，因为libdw没有适当的BPF重定位支持，因此诸如pahole等工具无法正确地从对象中转储结构。

elfutils（>= 0.173）实现了适当的BPF重定位支持，因此在没有`-mattr=dwarfris`选项的情况下也可以实现相同的功能。从对象文件中转储结构可以使用DWARF或BTF信息进行。目前，pahole使用LLVM生成的DWARF信息，然而，将来的pahole版本可能会使用可用的BTF。

要将DWARF转换为BTF，需要一个较新的pahole版本（>= 1.12）。如果在发行版软件包中没有找到，也可以从官方的git存储库获取较新的pahole版本：

```bash
$ git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
```

`pahole`提供了`-J`选项，用于从目标文件中将DWARF转换为BTF。可以按照以下方式检测`pahole`的BTF支持（请注意，`pahole`也需要`llvm-objcopy`工具，因此还要检查它的存在）：

```bash
$ pahole --help | grep BTF
-J, --btf_encode           Encode as BTF
```

生成调试信息还需要前端通过在`clang`命令行中传递`-g`来生成源级别的调试信息。请注意，不管是否使用了`llc`的`dwarfris`选项，都需要`-g`。下面是生成目标文件的完整示例：

```bash
$ clang -O2 -g -Wall --target=bpf -emit-llvm -c xdp-example.c -o xdp-example.bc
$ llc xdp-example.bc -march=bpf -mattr=dwarfris -filetype=obj -o xdp-example.o
```

另一种方法是仅使用clang构建带有调试信息的BPF程序（当具有适当的elfutils版本时，可以省略dwarfris标志）：

```bash
$ clang --target=bpf -O2 -g -c -Xclang -target-feature -Xclang +dwarfris -c xdp-example.c -o xdp-example.o
```

在成功编译后，可以使用`pahole`根据DWARF信息正确地转储BPF程序的结构：

```bash
$ pahole xdp-example.o
struct xdp_md {
        __u32                      data;                 /*     0     4 */
        __u32                      data_end;             /*     4     4 */
        __u32                      data_meta;            /*     8     4 */

        /* size: 12, cachelines: 1, members: 3 */
        /* last cacheline: 12 bytes */
};
```

通过`-J`选项，`pahole`最终可以从DWARF生成BTF。在目标文件中，除了新添加的BTF数据外，仍会保留DWARF数据。下面是结合了完整的`clang`和`pahole`示例：

```bash
$ clang --target=bpf -O2 -Wall -g -c -Xclang -target-feature -Xclang +dwarfris -c xdp-example.c -o xdp-example.o
$ pahole -J xdp-example.o
```

可以通过`readelf`工具查看`.BTF`节的存在：

```bash
$ readelf -a xdp-example.o
[...]
  [18] .BTF              PROGBITS         0000000000000000  00000671
[...]
```

BPF加载器（例如iproute2）将检测并加载BTF节，以便BPF映射可以注释为带有类型信息。

LLVM默认使用BPF基础指令集来生成代码，以确保生成的目标文件也可以加载到较旧的内核中，如长期稳定内核（例如4.9+）。

然而，LLVM在BPF后端中有一个`-mcpu`选择器，用于选择不同版本的BPF指令集，即在BPF基础指令集之上的指令集扩展，以便生成更高效和更小的代码。

可以通过以下方式查询可用的`-mcpu`选项：

```bash
$ llc -march bpf -mcpu=help
Available CPUs for this target:

  generic - Select the generic processor.
  probe   - Select the probe processor.
  v1      - Select the v1 processor.
  v2      - Select the v2 processor.
[...]
```

`generic`处理器是默认处理器，也是BPF的基本指令集`v1`。`v1`和`v2`选项通常在BPF程序被交叉编译的环境中非常有用，而程序加载的目标主机与编译的主机不同（因此可用的BPF内核功能也可能不同）。

推荐的`-mcpu`选项，也是Cilium内部使用的选项，是`-mcpu=probe`！在这里，LLVM的BPF后端会查询内核，以检查BPF指令集扩展是否可用，如果发现可用，LLVM将在适当的时候使用它们来编译BPF程序。

以下是带有llc的`-mcpu=probe`的完整命令行示例：

```bash
$ clang -O2 -Wall --target=bpf -emit-llvm -c xdp-example.c -o xdp-example.bc
$ llc xdp-example.bc -march=bpf -mcpu=probe -filetype=obj -o xdp-example.o
```

通常情况下，LLVM IR生成是与架构无关的。然而，使用`clang --target=bpf`与不使用`--target=bpf`（使用clang的默认目标）之间有一些区别，具体取决于底层架构，可能是`x86_64`、`arm64`或其他架构。

引用自内核的`Documentation/bpf/bpf_devel_QA.txt`：

- BPF程序可能递归地包含具有文件作用域的内联汇编代码的头文件。默认target可以很好地处理这一点，而如果BPF后端汇编器不理解这些汇编代码（在大多数情况下是这样），则bpf target 可能会失败。
- 在没有`-g`选项的情况下，使用默认target编译时，可能会在object文件中存在额外的elf节，例如`.eh_frame`和`.rela.eh_frame`，但在bpf目标中不会有这些节。
- 默认target可能会将C中的`switch`语句转换为`switch`表查找和跳转操作。由于`switch`表位于全局只读节中，BPF程序将无法加载。bpf目标不支持`switch`表优化。可以使用clang选项`-fno-jump-tables`禁用`switch`表生成。
- 对于`clang --target=bpf`，可以保证指针或`long`/`unsigned long`类型的宽度始终为64位，无论底层clang二进制文件还是默认target（或内核）是32位还是64位。然而，当使用native clang target时，这些类型会根据底层架构的约定进行编译，这意味着在32位架构的情况下，例如在BPF上下文结构中，指针或`long`/`unsigned long`类型的宽度将为32位，而BPF LLVM后端仍然在64位上运行。

native target在跟踪中主要用于遍历映射CPU寄存器的内核`struct pt_regs`字段，或者其他CPU寄存器宽度很重要的内核结构。在所有其他情况下，例如网络，使用`clang --target=bpf`是首选选择。

此外，自LLVM的7.0版本起，LLVM开始支持32位子寄存器和BPF ALU32指令。新增了一个名为`alu32`的代码生成属性。当启用它时，LLVM会尽可能使用32位子寄存器，通常在对32位类型进行操作时。具有32位子寄存器的相关ALU指令将变为ALU32指令。例如，对于以下示例代码：

```bash
$ cat 32-bit-example.c
    void cal(unsigned int *a, unsigned int *b, unsigned int *c)
    {
      unsigned int sum = *a + *b;
      *c = sum;
    }
```

在默认代码生成时，汇编器将如下所示：

```bash
$ clang --target=bpf -emit-llvm -S 32-bit-example.c
$ llc -march=bpf 32-bit-example.ll
$ cat 32-bit-example.s
    cal:
      r1 = *(u32 *)(r1 + 0)
      r2 = *(u32 *)(r2 + 0)
      r2 += r1
      *(u32 *)(r3 + 0) = r2
      exit
```

64位寄存器被使用，因此加法操作表示64位加法。现在，如果通过指定`-mattr=+alu32`启用新的32位子寄存器支持，那么汇编代码将如下所示：

```bash
$ llc -march=bpf -mattr=+alu32 32-bit-example.ll
$ cat 32-bit-example.s
    cal:
      w1 = *(u32 *)(r1 + 0)
      w2 = *(u32 *)(r2 + 0)
      w2 += w1
      *(u32 *)(r3 + 0) = w2
      exit
```

将使用`w`寄存器，表示32位子寄存器，而不是64位的`r`寄存器。

启用32位子寄存器可以帮助减少类型扩展指令序列。它还可以帮助32位架构的内核eBPF JIT编译器，对于这些架构，使用寄存器对来模拟64位eBPF寄存器，并且需要额外的指令来操作高32位。尽管从32位子寄存器中读取的值保证只读取低32位，但写入仍然需要清除高32位，如果JIT编译器已经知道一个寄存器的定义只有子寄存器读取，那么可以消除设置目标高32位的指令。

在为BPF编写C程序时，与使用C进行常规应用程序开发相比，有一些需要注意的陷阱。以下内容描述了BPF模型的一些差异：

1. **一切都需要内联，没有函数调用（在较旧的LLVM版本中）或共享库调用可用。**

   不能在BPF中使用共享库等。然而，BPF程序中使用的常见库代码可以放在头文件中，并在主程序中包含。例如，Cilium就大量使用了它（见`bpf/lib/`）。然而，这仍然允许包括头文件，例如从内核或其他库中，并重用其静态内联函数或宏/定义。

   除非使用了支持BPF到BPF函数调用的较新内核（4.16+）和LLVM（6.0+），否则LLVM需要将整个代码编译并内联到给定程序段的平坦BPF指令序列（flat sequence of BPF instructions）中。在这种情况下，最佳做法是为每个库函数使用像下面所示的`__inline`注释。推荐使用`always_inline`，因为编译器仍然可以决定不将只有`inline`注释的大函数内联。

   如果发生后一种情况，LLVM将在ELF文件中生成重定位条目，而BPF ELF加载器（如iproute2）无法解析这些条目，因此会产生错误，因为只有 BPF 映射才是加载程序可以处理的有效重定位条目。

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

2. **在一个单独的C文件中可以包含多个不同段的程序。**

为BPF编写的C程序大量使用段注释。一个C文件通常被划分为3个或更多个段。BPF ELF加载器使用这些名称来提取和准备相关信息，以便通过bpf系统调用加载程序和映射。例如，iproute2使用`maps`和`license`作为默认段名称，以分别找到创建映射所需的元数据和BPF程序的许可证。在程序创建时，后者也被推送到内核中，同时在程序还持有GPL兼容许可证的情况下，启用一些辅助函数，例如`bpf_ktime_get_ns()`、`bpf_probe_read()`等，这些辅助函数只在程序也持有GPL兼容许可证的情况下才能使用。

其余的段名称是特定于BPF程序代码的，例如，下面的代码已被修改为包含两个程序段，`ingress`和`egress`。这个玩具（toy）示例代码演示了两者可以共享一个映射和常见的静态内联助手函数，例如`account_data()`函数。

`xdp-example.c`示例已被修改为一个`tc-example.c`示例，可以通过tc加载并附加到网络设备的入口和出口挂钩上。它将传输的字节计入名为`acc_map`的映射中，该映射有两个映射槽，一个用于入口挂钩上的流量计数，一个用于出口挂钩上的流量计数。

```c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
   ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map acc_map __section("maps") = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint32_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 2,
};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir)
{
    uint32_t *bytes;

    bytes = map_lookup_elem(&acc_map, &dir);
    if (bytes)
            lock_xadd(bytes, skb->len);

    return TC_ACT_OK;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return account_data(skb, 0);
}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{
    return account_data(skb, 1);
}

char __license[] __section("license") = "GPL";
```

该示例还演示了在开发程序时需要了解的一些其他事项。代码包括内核头文件、标准C头文件和一个特定于iproute2的头文件，其中包含了`struct bpf_elf_map`的定义。iproute2具有通用的BPF ELF加载器，因此`struct bpf_elf_map`的定义对于XDP和tc类型的程序是完全相同的。

`struct bpf_elf_map`条目定义了程序中的一个映射，并包含生成映射所需的所有相关信息（例如键/值大小等），这些信息用于两个BPF程序中。该结构必须放置在`maps`段中，以便加载器可以找到它。可以有多个具有不同变量名的此类型的映射声明，但是所有映射声明都必须带有`__section("maps")`注释。

`struct bpf_elf_map`特定于iproute2。不同的BPF ELF加载器可能具有不同的格式，例如，内核源代码中的libbpf主要由`perf`使用，其规范不同。iproute2保证了对`struct bpf_elf_map`的向后兼容性。Cilium遵循iproute2的模型。

该示例还演示了如何将BPF辅助函数映射到C代码并进行使用。在这里，`map_lookup_elem()`被定义为将该函数映射到`BPF_FUNC_map_lookup_elem`枚举值中，该枚举值作为一个辅助函数在`uapi/linux/bpf.h`中公开。当程序稍后加载到内核时，验证器会检查传递的参数是否为预期类型，并将辅助函数调用重新指向真正的函数调用。此外，`map_lookup_elem()`还演示了如何将映射传递给BPF辅助函数。在这里，`maps`段中的`&acc_map`作为第一个参数传递给`map_lookup_elem()`。

由于定义的数组映射是全局的，因此计算需要使用原子操作，其定义为`lock_xadd()`。LLVM将`__sync_fetch_and_add()`映射为BPF原子加法指令的内置函数，即对于字大小，为`BPF_STX | BPF_XADD | BPF_W`。

最后但同样重要的是，`struct bpf_elf_map`表明该映射将被固定为`PIN_GLOBAL_NS`。这意味着tc将该映射固定到BPF伪文件系统中作为一个节点。默认情况下，它将被固定到`/sys/fs/bpf/tc/globals/acc_map`，对于给定示例来说是这样。由于`PIN_GLOBAL_NS`，该映射将放置在`/sys/fs/bpf/tc/globals/`下。`globals`充当跨对象文件的全局命名空间。如果示例使用了`PIN_OBJECT_NS`，则tc将创建一个相对于对象文件的本地目录。例如，具有BPF代码的不同C文件可以具有与上述相同的`acc_map`定义，带有`PIN_GLOBAL_NS`固定。在这种情况下，将共享在不同对象文件中产生的BPF程序之间的映射。`PIN_NONE`表示该映射不会被放置到BPF文件系统中作为节点，结果是在tc退出后将无法从用户空间访问。这也意味着tc为每个程序创建了两个单独的映射实例，因为它无法检索以该名称固定的映射。所提到的路径中的`acc_map`部分是在源代码中指定的映射名称。

因此，在加载`ingress`程序时，tc将发现在BPF文件系统中不存在这样的映射，并创建一个新的映射。成功后，该映射也将被固定，以便在通过tc加载`egress`程序时，它将发现在BPF文件系统中已经存在这样的映射，并将其用于`egress`程序。加载器还确保在存在具有相同名称的映射的情况下，它们的属性（键/值大小等）也相匹配。

就像tc可以检索相同的映射一样，第三方应用程序也可以使用bpf系统调用中的`BPF_OBJ_GET`命令创建一个指向相同映射实例的新文件描述符，然后可以使用该文件描述符来查找/更新/删除映射元素。

以下是通过iproute2编译和加载代码的方法：

```bash
$ clang -O2 -Wall --target=bpf -c tc-example.c -o tc-example.o

# tc qdisc add dev em1 clsact
# tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
# tc filter add dev em1 egress bpf da obj tc-example.o sec egress

# tc filter show dev em1 ingress
filter protocol all pref 49152 bpf
filter protocol all pref 49152 bpf handle 0x1 tc-example.o:[ingress] direct-action id 1 tag c5f7825e5dac396f

# tc filter show dev em1 egress
filter protocol all pref 49152 bpf
filter protocol all pref 49152 bpf handle 0x1 tc-example.o:[egress] direct-action id 2 tag b2fd5adc0f262714

# mount | grep bpf
sysfs on /sys/fs/bpf type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
bpf on /sys/fs/bpf type bpf (rw,relatime,mode=0700)

# tree /sys/fs/bpf/
/sys/fs/bpf/
+-- ip -> /sys/fs/bpf/tc/
+-- tc
|   +-- globals
|       +-- acc_map
+-- xdp -> /sys/fs/bpf/tc/

4 directories, 1 file
```

一旦数据包通过`em1`设备，BPF映射中的计数器将会增加。

> 未完待续...