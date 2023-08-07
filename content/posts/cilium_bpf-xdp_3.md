---
title: "BPF程序类型（XDP）"
date: 2023-08-07T14:37:35+08:00
categories: ["eBPF","XDP","Linux Kernel"]
---

原文链接：https://docs.cilium.io/en/latest/bpf/progtypes/#xdp

在撰写本文时，共有18种不同的BPF程序类型可用，其中网络方面的两种主要类型XDP BPF程序和tc BPF程序将在下面的小节中进一步解释。对于这两种程序类型更多的使用示例，可以在[工具链部分](https://docs.cilium.io/en/latest/bpf/toolchain/)找到，这里不再涵盖。本节将侧重于它们的架构、概念和使用案例。

## XDP

XDP代表eXpress Data Path（快速数据路径），为BPF提供了一个框架，能够在Linux内核中实现高性能的可编程数据包处理。它在软件中的最早可能点运行BPF程序，即在网络驱动程序接收数据包的瞬间。

在这一快速路径中，驱动程序刚刚从接收环中获取了数据包，而没有进行任何高开销的操作，比如为将数据包推送到网络堆栈上层而分配`skb`，也没有将数据包推送到GRO引擎中等。因此，XDP BPF程序在可供CPU处理的最早时刻执行。

XDP与Linux内核及其基础设施协同工作，意味着内核并未像一些仅在用户空间操作的各种网络框架中那样被绕过。将数据包保留在内核空间具有几个重要优势：

- XDP能够重用所有上游开发的内核网络驱动程序、用户空间工具，甚至是BPF辅助调用中的其他可用内核基础设施，比如路由表、套接字等。

- 作为内核空间的一部分，XDP在访问硬件时具有与内核其他部分相同的安全模型。

- 由于处理的数据包已经位于内核空间，因此无需跨越内核/用户空间边界，可以将数据包灵活地转发到内核中的其他实体，如容器使用的命名空间或内核的网络堆栈本身。这在Meltdown和Spectre时期尤为重要。

- 将数据包从XDP传递到内核强大、广泛使用且高效的TCP/IP堆栈非常简单，可以完全重用，无需像用户空间框架那样维护单独的TCP/IP堆栈。

- 使用BPF可以实现完全的可编程性，保持与内核系统调用ABI相同的“永不破坏用户空间”的保证，与模块相比，还通过BPF验证器提供了对内核操作稳定性的安全措施。

- XDP可以在运行时轻松地原子性地交换程序，而无需中断任何网络流量，甚至无需内核/系统重启。

- XDP允许将工作负载灵活地集成到内核中。例如，它可以在“繁忙轮询（busy polling）”或“中断驱动”模式下运行。不需要专门将CPU分配给XDP。无需特殊的硬件要求，也不依赖于大页面。

- XDP不需要任何第三方内核模块或许可证。它是一个长期的架构解决方案，是Linux内核的核心部分，由内核社区开发。

- XDP已经在所有主要发行版中启用并随附，在运行等效于4.8或更高版本内核的主要分发版中运行，并支持大多数主要的10G或更高速率的网络驱动程序。

作为在驱动程序中运行BPF的框架，XDP还确保数据包在单个可由BPF程序读写的DMA页面上线性布局。XDP还确保BPF程序可通过`bpf_xdp_adjust_head()` BPF助手调整自定义封装标头的附加前空间，并通过`bpf_xdp_adjust_meta()`在数据包前添加自定义元数据。

该框架包含在下面的小节中进一步描述的XDP操作代码，BPF程序可以返回这些操作代码，以指示驱动程序如何处理数据包，并且它使得可以在XDP层运行的BPF程序之间原子性地替换。XDP是专为高性能而设计的。BPF允许通过“直接数据包访问”来访问数据包数据，这意味着程序直接在寄存器中持有数据指针，将内容加载到寄存器中，或从寄存器中写入数据包。

传递给BPF程序作为BPF上下文的XDP中的数据包表示如下：

```c
struct xdp_buff {
    void *data;
    void *data_end;
    void *data_meta;
    void *data_hard_start;
    struct xdp_rxq_info *rxq;
};
```

`data` 指向页面中数据包数据的起始位置，正如其名称所示，`data_end` 指向数据包数据的末尾。由于XDP允许有一些头部空间，`data_hard_start` 指向页面中最大可能的头部空间起始位置，这意味着当数据包需要封装时，通过 `bpf_xdp_adjust_head()` 将 `data` 移动到更靠近 `data_hard_start`。同样的BPF辅助函数也允许进行去封装，此时 `data` 会从 `data_hard_start` 进一步移开。

`data_meta` 最初指向与 `data` 相同的位置，但 `bpf_xdp_adjust_meta()` 也可以将指针移动到 `data_hard_start`，以提供用于自定义元数据的空间，这些元数据对于正常的内核网络堆栈是不可见的，但可以被 tc BPF 程序读取，因为它是从 XDP 传递到 `skb` 中的。反之，通过将 `data_meta` 从 `data_hard_start` 移开，相同的BPF辅助函数也可以移除或减小自定义元数据的大小。`data_meta` 也可以仅用于在尾调用之间传递状态，类似于 tc BPF 程序中可以访问的 `skb->cb[]` 控制块情况。

这为 `struct xdp_buff` 数据包指针提供了以下关系或不变式：`data_hard_start` <= `data_meta` <= `data` < `data_end`。

`rxq` 字段指向一些额外的每个接收队列元数据，这些元数据在环设置时（而不是在XDP运行时）填充：

```c
struct xdp_rxq_info {
    struct net_device *dev;
    u32 queue_index;
    u32 reg_state;
} ____cacheline_aligned;
```

### BPF程序返回码

在运行XDP-BPF程序之后，程序会返回一个判决（verdict），以便告诉驱动程序接下来如何处理数据包。在`linux/bpf.h`系统头文件中，列举了所有可用的返回判决：

```c
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};
```

`XDP_DROP` 顾名思义会直接在驱动程序级别丢弃数据包，而不会浪费任何进一步的资源。这对于实现DDoS缓解机制或一般性防火墙的BPF程序尤为有用。`XDP_PASS` 返回代码意味着允许数据包传递到内核的网络堆栈。这意味着正在处理该数据包的当前CPU现在会分配一个 `skb`，填充它，并将其传递到GRO引擎中。这相当于没有使用XDP的默认数据包处理行为。使用 `XDP_TX`，BPF程序可以有效地选择将网络数据包重新从刚刚到达的同一NIC传输出去。这在一些节点实现防火墙并在集群中进行后续负载平衡时非常有用，因此在重写XDP BPF中的数据包后，它们作为Hairpinned负载平衡器将传入的数据包推回交换机。`XDP_REDIRECT` 与 `XDP_TX` 类似，它能够传输XDP数据包，但通过另一个NIC。对于 `XDP_REDIRECT` 的另一个选项是将其重定向到BPF cpumap中，这意味着为NIC接收队列上的XDP提供服务的CPU可以继续这样做，并将数据包推送到远程CPU以处理上层内核堆栈。这与 `XDP_PASS` 类似，但其能力在于，XDP BPF程序可以继续处理传入的高负载，而不是暂时在当前数据包上花费工作来推入上层。最后，`XDP_ABORTED` 用于指示程序的异常状态，并且其行为与 `XDP_DROP` 相同，唯一的区别在于 `XDP_ABORTED` 会传递 `trace_xdp_exception` 跟踪点，可以额外用于监控以检测异常行为。

### XDP的使用案例

以下是XDP的一些主要使用案例。这个列表不是详尽无遗的，由于XDP和BPF的可编程性和效率，它可以轻松地适应解决非常特定的使用案例。

- **DDoS缓解、防火墙**

  XDP BPF的基本特性之一是通过 `XDP_DROP` 来指示驱动程序在此早期阶段丢弃数据包，从而允许以极低的每数据包成本进行高效的网络策略执行。这在需要应对各种DDoS攻击的情况下非常理想，同时也允许实现几乎没有开销的BPF防火墙策略，例如作为独立的设备（例如通过 `XDP_TX` 将“干净”的流量推送出去）或者广泛部署在保护终端主机的节点上（通过 `XDP_PASS` 或cpumap的 `XDP_REDIRECT` 处理良好的流量）。通过offload的XDP将这一点推向了更进一步，将已经很小的每数据包成本完全转移到了NIC，实现了以线速（line-rate）进行处理。

- **数据包转发和负载平衡**

  XDP的另一个主要用例是通过 `XDP_TX` 或 `XDP_REDIRECT` 操作进行数据包转发和负载平衡。数据包可以由在XDP层中运行的BPF程序任意修改，甚至可以使用BPF辅助函数来增加或减少数据包的头部空间，以在再次发送之前任意封装或去封装数据包。通过 `XDP_TX`，可以实现将数据包从原始接收网络设备推出，或者通过 `XDP_REDIRECT` 操作将其转发到另一个NIC进行传输。后一种返回代码还可以与BPF的cpumap结合使用，将数据包负载均衡传递给本地堆栈，但在远程的非XDP处理CPU上处理。

- **堆栈前过滤/处理**

  除了策略执行，XDP还可以使用 `XDP_DROP` 案例来强化内核的网络堆栈，意味着它可以在网络堆栈在查看数据包之前的最早可能时刻丢弃不相关的数据包，例如，如果我们知道一个节点只提供TCP流量，那么任何UDP、SCTP或其他L4流量都可以立即丢弃。这具有优势，即数据包不需要在进入之前遍历各种实体，如GRO引擎、内核的流解析器等，即可确定是否要丢弃它们，从而减少内核的攻击面。由于XDP的早期处理阶段，这实际上“假装”内核的网络堆栈从未看到过这些数据包。此外，如果堆栈的接收路径中出现潜在的错误，并导致类似“ping of dead”的情况，可以利用XDP立即丢弃此类数据包，而无需重新启动内核或重新启动任何服务。由于能够原子地交换此类程序以强制丢弃错误数据包，主机上甚至没有中断任何网络流量。

  堆栈前处理的另一个用例是，由于内核尚未为数据包分配 `skb`，所以BPF程序可以自由地修改数据包，并且再次“假装”将其传递给了网络设备。这允许诸如具有自定义数据包重整和封装协议之类的情况，其中数据包可以在进入 GRO 聚合之前被解封装，否则 GRO 由于不知道自定义协议而无法执行任何类型的聚合。XDP还允许将元数据（非数据包数据）推送到数据包之前。这对于正常的内核堆栈是“不可见的”，可以在GRO中进行聚合（以匹配元数据），并且稍后可以与tc入口BPF程序协调处理，在此情况下，它具有用于设置各种skb字段的 `skb` 上下文。

- **流量采样、监控**

  XDP还可以用于数据包监控、采样或任何其他网络分析用例，例如作为路径中的中间节点或在终端主机上，还可以与前面提到的用例结合使用。对于复杂的数据包分析，XDP提供了一种方法，可以将网络数据包（截断或带有完整负载）和自定义元数据有效地推送到从Linux perf基础设施提供的快速无锁per-CPU内存映射环形缓冲区中的用户空间应用程序。这还允许在仅分析流的初始数据时的情况，一旦确定为良好的流量，则监视可以被绕过。由于BPF带来的灵活性，这可以实现任何类型的自定义监控或采样。

XDP BPF的一个生产用例是Facebook的SHIV和Droplet基础架构，它们实现了L4负载平衡和DDoS对策。将生产基础架构从netfilter的IPVS（IP虚拟服务器）迁移到XDP BPF上，与以前的IPVS设置相比，速度提高了10倍。这首次在netdev 2.1大会上进行了介绍：

- Slide：https://netdevconf.info/2.1/slides/apr6/zhou-netdev-xdp
- Video: https://youtu.be/YEU2ClcGqts

另一个例子是将XDP集成到Cloudflare的DDoS缓解流程中，最初使用cBPF而不是eBPF来通过iptables的`xt_bpf`模块进行攻击签名匹配。由于使用iptables导致在受到攻击时出现严重的性能问题，需要一个用户空间绕过解决方案，但也带来了一些缺点，例如需要忙等待NIC和数据包重新注入到内核的堆栈中的高开销。迁移到eBPF和XDP结合使用，将两者的优势结合在一起，实现了高性能的可编程数据包处理，直接在内核中进行：

- Slides: https://netdevconf.info/2.1/slides/apr6/bertin_Netdev-XDP.pdf
- Video: https://youtu.be/7OuOukmuivg

### XDP的工作模式

XDP有三种操作模式，其中Native XDP是默认模式。提到XDP时，通常暗示的就是这种模式。

- **Native XDP**

这是默认模式，其中XDP BPF程序直接从网络驱动程序的早期接收路径运行。大多数用于10G及更高速率的广泛使用的NIC已经支持本机XDP。

- **Offloaded XDP**

在卸载的XDP模式中，XDP BPF程序直接卸载到NIC中，而不是在主机CPU上执行。因此，已经极低的每数据包成本完全从主机CPU上移开，并在NIC上执行，提供了比在本机XDP中运行更高的性能。此卸载通常由包含多线程、多核流处理器的SmartNIC实现，其中内核中的JIT编译器将BPF翻译成后者的本机指令。支持卸载XDP的驱动程序通常也支持Native XDP，以用于一些BPF辅助函数在Native模式下可能尚不可用或只在Native模式下可用的情况。

- **Generic XDP**

对于尚未实现本机或卸载XDP的驱动程序，内核提供了通用XDP的选项，该选项不需要进行任何驱动程序更改，因为在网络堆栈的较后阶段运行。此设置主要针对希望针对内核的XDP API编写和测试程序的开发人员，不会以本机或卸载模式的性能速率运行。在生产环境中使用XDP时，Native模式或Offload模式更适合，并且是运行XDP的推荐方式。

#### 驱动程序支持

**支持Native XDP的驱动程序**

支持native XDP的驱动程序列表可以在下表中找到。接口的相应网络驱动程序名称可以通过以下方式确定：

```bash
# ethtool -i eth0
driver: nfp
[...]
```

| Vendor            | Driver     | XDP Support |
| ----------------- | ---------- | ----------- |
| Amazon            | ena        | >= 5.6      |
| Broadcom          | bnxt_en    | >= 4.11     |
| Cavium            | thunderx   | >= 4.12     |
| Freescale         | dpaa2      | >= 5.0      |
| Intel             | ixgbe      | >= 4.12     |
| ixgbevf           | >= 4.17    |             |
| i40e              | >= 4.13    |             |
| ice               | >= 5.5     |             |
| Marvell           | mvneta     | >= 5.5      |
| Mellanox          | mlx4       | >= 4.8      |
| mlx5              | >= 4.9     |             |
| Microsoft         | hv_netvsc  | >= 5.6      |
| Netronome         | nfp        | >= 4.10     |
| Others            | virtio_net | >= 4.10     |
| tun/tap           | >= 4.14    |             |
| bond              | >= 5.15    |             |
| Qlogic            | qede       | >= 4.10     |
| Socionext         | netsec     | >= 5.3      |
| Solarflare        | sfc        | >= 5.5      |
| Texas Instruments | cpsw       | >= 5.3      |

**支持offloaded XDP模式的驱动**

- **Netronome**
  - nfp

### More about me

欢迎关注 「barryX的技术笔记」 微信公众号

<img src="/images/wx.png" style="zoom:33%;" />