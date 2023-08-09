---
title: "BPF程序类型（tc 流量控制）"
date: 2023-08-09T22:00:35+08:00
categories: ["eBPF","Linux Kernel"]
---

原文链接：https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control

除了其他类型的程序（如XDP），BPF 还可以在网络数据路径的内核 tc（流量控制）层之外使用。从高层次来看，比较 XDP BPF 程序和 tc BPF 程序有三个主要差异：

- BPF 输入的上下文是 `sk_buff` 而不是 `xdp_buff`。当内核的网络堆栈接收到数据包后，经过 XDP 层后，它会分配一个缓冲区并解析数据包以存储有关数据包的元数据。这个表示被称为 `sk_buff`。然后，在 BPF 输入上下文中公开此结构，以便来自 tc 入口层的 BPF 程序可以使用堆栈从数据包中提取的元数据。这可能很有用，但与之相关的成本是堆栈执行此分配和元数据提取，并处理数据包直到它触发 tc 钩子（tc hook）。根据定义，`xdp_buff` 不能访问此元数据，因为在执行此工作之前会调用 XDP 钩子。这是导致 XDP 和 tc 钩子之间性能差异的重要因素之一。

  因此，连接到 tc BPF 钩子的 BPF 程序可以读取或写入 `sk_buff` 的 `mark`、`pkt_type`、`protocol`、`priority`、`queue_mapping`、`napi_id`、`cb[]` 数组、`hash`、`tc_classid` 或 `tc_index`、VLAN 元数据、XDP 传递的自定义元数据以及其他各种信息。tc BPF 中使用的 `struct __sk_buff` BPF 上下文的所有成员都在 `linux/bpf.h` 系统头文件中定义。

  通常情况下，`sk_buff` 与 `xdp_buff` 的性质完全不同，二者都有优缺点。例如，`sk_buff` 情况下的优点是它非常容易修改关联的元数据，但它还包含许多协议特定信息（例如 GSO 相关状态），这使得仅通过重新编写数据包数据来切换协议变得困难。这是因为堆栈基于元数据处理数据包，而不是每次访问数据包内容时都要产生开销。因此，还需要从 BPF 辅助函数进行额外的转换，以确保 `sk_buff` 的内部也被正确转换。然而，`xdp_buff` 情况则不会面临这些问题，因为它处于内核甚至还没有分配 `sk_buff` 的早期阶段，因此可以轻松地实现任何类型的数据包重写。然而，`xdp_buff` 情况的缺点是在此阶段无法对 `sk_buff` 的元数据进行修改。不过，通过将自定义元数据从 XDP BPF 传递给 tc BPF，可以解决后者在数据操纵方面的限制。根据使用情况来操作这两种类型的互补程序，可以解决每种程序类型的限制。

- 与 XDP 相比，tc BPF 程序可以在网络数据路径中的入口点和出口点触发，而不仅限于 XDP 中的入口。

  内核中的两个挂钩点 `sch_handle_ingress()` 和 `sch_handle_egress()` 是由 `__netif_receive_skb_core()` 和 `__dev_queue_xmit()` 触发的。后两者是数据路径中的主要接收和发送函数，除了 XDP 以外，它们都为每个进出节点的网络数据包触发，从而允许 tc BPF 程序在这些挂钩点上完全可见。

- tc BPF 程序不需要进行任何驱动程序更改，因为它们在网络堆栈的通用层次的挂钩点上运行。因此，它们可以附加（attach）到任何类

- 型的网络设备上。

  尽管这提供了灵活性，但与在Native XDP 层运行相比，性能方面存在一些权衡。然而，tc BPF 程序仍然是在通用内核网络数据路径中最早的一点，此时 GRO 已经运行，但在任何协议处理、传统的 iptables 防火墙处理（如 iptables PREROUTING 或 nftables 入口挂钩）或其他数据包处理之前。同样，在出口方面，tc BPF 程序在将数据包交给驱动程序本身进行传输之前的最后一点执行，即在传统的 iptables 防火墙挂钩（如 iptables POSTROUTING）之后，但仍在将数据包交给内核的 GSO 引擎之前。然而，有一个需要驱动程序更改的例外，那就是offloaded的 tc BPF 程序，通常由 SmartNIC 提供，与offloaded  XDP 类似，只是由于 BPF 输入上下文、辅助函数和决策代码的差异，具有不同的功能集。

在 tc 层中运行的 BPF 程序是从 `cls_bpf` 分类器运行的。尽管 tc 术语将 BPF 附加点描述为“分类器”，但这有点误导，因为它未充分呈现出 `cls_bpf` 的功能。也就是说，`cls_bpf` 是一个完全可编程的数据包处理器，不仅能够读取 `skb` 的元数据和数据包数据，还可以任意地修改两者，并以操作决策结束 tc 处理。因此，`cls_bpf` 可以被视为一个自包含的实体，用于管理和执行 tc BPF 程序。

`cls_bpf` 可以持有一个或多个 tc BPF 程序。在 Cilium 部署 `cls_bpf` 程序的情况下，它只会在 `direct-action` 模式下为给定的钩子附加一个程序。通常，在传统的 tc 方案中，分类器和操作模块之间存在划分，分类器附加一个或多个操作，一旦分类器匹配就会触发这些操作。在软件数据路径中使用 tc 的现代世界中，对于复杂的数据包处理，这种模型不太适用。由于附加到 `cls_bpf` 的 tc BPF 程序是完全自包含的，它们将解析和操作过程有效地合并为单个单元。由于 `cls_bpf` 的 `direct-action` 模式，它将立即返回 tc 操作决策并终止处理流水线。这可以通过避免操作的线性迭代来实现网络数据路径中可扩展的可编程数据包处理。`cls_bpf` 是 tc 层中唯一支持此类快速路径的“分类器”模块。

与 XDP BPF 程序一样，tc BPF 程序可以通过 `cls_bpf` 在运行时进行原子更新，而无需中断任何网络流量或重新启动服务。

`cls_bpf` 可以附加到 tc 的入口和出口挂钩，由一个名为 `sch_clsact` 的伪 qdisc 进行管理。这是入口 qdisc 的一个直接替代品和适当的超集，因为它能够同时管理入口和出口 tc 钩子。对于 `__dev_queue_xmit()` 中的 tc 出口挂钩，重要的是强调它不是在内核的 qdisc 根锁下执行的。因此，tc 的入口和出口挂钩都是在快速路径中无锁执行的。在任何情况下，抢占被禁用，执行在 RCU 读侧下进行。

通常情况下，在出口方面，netdevice 上会附加一些 qdisc，例如 `sch_mq`、`sch_fq`、`sch_fq_codel` 或 `sch_htb`，其中一些是包含子类的类 qdisc，因此需要数据包分类机制来确定决策在哪里解复用数据包。这通过调用 `tcf_classify()` 来处理，后者会调用 tc 分类器（如果存在）。`cls_bpf` 也可以附加并在这些情况下使用。这种操作通常发生在 qdisc 根锁下，并可能受到锁争用的影响。然而，`sch_clsact` qdisc 的出口挂钩在这方面处于更早的位置，不受此类影响，完全独立于传统的出口 qdisc。因此，对于 `sch_htb` 等情况，`sch_clsact` qdisc 可以通过 tc BPF 在不受根锁限制的情况下执行重要的数据包分类工作，从而在根锁下减少争用，只需进行扁平映射。

offloaded的 tc BPF 程序支持 `sch_clsact` 与 `cls_bpf` 的组合，其中先前加载的 BPF 程序是从 SmartNIC 驱动程序中即时编译（JIT）并在 NIC 上本地运行的。只支持在 `direct-action` 模式下运行的 `cls_bpf` 程序进行offloaded。`cls_bpf` 仅支持offloaded一个程序，无法offloaded多个程序。此外，只有入口挂钩支持offloaded BPF 程序。

一个 `cls_bpf` 实例可以在内部持有多个 tc BPF 程序。如果是这种情况，那么`TC_ACT_UNSPEC` 程序返回代码将继续执行该列表中的下一个 tc BPF 程序。然而，这具有一个缺点，即需要多个程序一遍又一遍地解析数据包，导致性能下降。

### BPF程序返回码

tc 入口和出口钩子共享 tc BPF 程序可以使用的相同操作返回判决。它们在`linux/pkt_cls.h`系统头文件中定义：

```c
#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7
```

系统头文件中还有一些额外的`TC_ACT_*`动作判决在系统中可用，这些判决也在这两个钩子中使用。然而，它们与上述判决具有相同的语义。从tc BPF的角度来看，`TC_ACT_OK`和`TC_ACT_RECLASSIFY`具有相同的语义，以及三个`TC_ACT_STOLEN`、`TC_ACT_QUEUED`和`TC_ACT_TRAP`操作码。因此，在这些情况下，我们只描述`TC_ACT_OK`和这两个群组的`TC_ACT_STOLEN`操作码。

首先是`TC_ACT_UNSPEC`。它的含义是“未指定的操作”，在三种情况下使用，

i) 当连接了一个offloaded tc BPF程序并运行tc入口钩子时，offloaded 程序的`cls_bpf`表示将返回`TC_ACT_UNSPEC`，

ii) 为了继续多程序情况下的`cls_bpf`中的下一个tc BPF程序。后者也与点i中的来自 offloaded tc BPF程序结合使用，在那里的`TC_ACT_UNSPEC`从那里继续，仅在非offloaded情况下运行下一个仅在非offloaded情况下的tc BPF程序。

最后但同样重要的是，iii) `TC_ACT_UNSPEC`也用于单程序情况，仅仅告诉内核在没有额外副作用（additional side-effects）的情况下继续处理`skb`。`TC_ACT_UNSPEC`与`TC_ACT_OK`操作代码非常相似，因为两者都分别将`skb`传递到入口上层堆栈的更高层或传递到出口的网络设备驱动程序以进行传输。唯一的区别是`TC_ACT_OK`基于tc BPF程序设置的classid来设置`skb->tc_index`。后者是通过BPF上下文中的`skb->tc_classid`从tc BPF程序本身设置的。

`TC_ACT_SHOT`指示内核丢弃数据包，这意味着网络堆栈的上层将永远不会在入口处看到`skb`，类似地，数据包也永远不会在出口处提交传输。`TC_ACT_SHOT`和`TC_ACT_STOLEN`在性质上都相似，但有一些区别：`TC_ACT_SHOT`将向内核指示`skb`是通过`kfree_skb()`释放的，并向调用者返回`NET_XMIT_DROP`以供即时反馈，而`TC_ACT_STOLEN`将通过`consume_skb()`释放`skb`，并假装对上层来说传输是成功的，通过`NET_XMIT_SUCCESS`。因此，性能的丢弃监视器记录`kfree_skb()`的跟踪也不会从`TC_ACT_STOLEN`中看到任何丢弃指示，因为其语义是`skb`已被“消耗”或排队，但肯定不是“丢弃”。

最后但同样重要的是`TC_ACT_REDIRECT`操作，这也适用于tc BPF程序。连同`bpf_redirect()`辅助函数，这允许将`skb`重定向到相同或另一个设备的入口或出口路径。能够将数据包注入另一个设备的入口或出口方向允许使用BPF进行完全灵活的数据包转发。目标网络设备除了本身是网络设备外，没有其他要求，无需在目标设备上运行另一个`cls_bpf`实例或其他限制。

**tc BPF FAQ**

本节包含一些与tc BPF程序相关的常见问题和答案。

- **Q：** `act_bpf`作为tc操作模块，是否仍然相关？
  - **A：** 实际上不是。虽然`cls_bpf`和`act_bpf`对于tc BPF程序具有相同的功能，但`cls_bpf`更加灵活，因为它是`act_bpf`的一个适当超集。tc的工作方式是，tc操作需要附加到tc分类器上。为了实现与`cls_bpf`相同的灵活性，`act_bpf`需要附加到`cls_matchall`分类器上。正如名称所示，这将匹配每个数据包，以便将其传递给附加的tc操作处理。对于`act_bpf`来说，这将导致比直接在`direct-action`模式下使用`cls_bpf`的数据包处理效率更低。如果在与`cls_bpf`或`cls_matchall`以外的其他分类器一起使用`act_bpf`，则由于tc分类器的操作方式，性能甚至会更差。意思是，如果分类器A不匹配，则将数据包传递给分类器B，重新解析数据包，等等，因此在典型情况下，数据包需要在最坏的情况下穿越N个分类器，以查找匹配并在其上执行`act_bpf`。因此，`act_bpf`从未是非常相关的。此外，与`cls_bpf`相比，`act_bpf`也不提供tc卸载接口。

- **Q：** 是否推荐在`direct-action`模式下使用`cls_bpf`？
- **A：** 不推荐。答案与上面的类似，这在其他情况下无法进行更复杂的处理。tc BPF已经可以以高效的方式完成自己所需的一切，因此除了`direct-action`模式外，不需要任何其他模式。
- **Q：**  offloaded 的`cls_bpf`和 offloaded 的XDP之间是否有性能差异？
- **A：** 没有。两者都通过内核中的相同编译器进行JIT编译，该编译器处理了SmartNIC的卸载以及两者的加载机制非常相似。因此，BPF程序被翻译成相同的目标指令集，以便能够在NIC上本地运行。例如两种tc BPF和XDP BPF程序类型具有不同的特性集，因此根据用例，可以由于卸载情况下某些助手函数的可用性选择其中之一。

**tc BPF 的用例**

本小节介绍了一些主要的tc BPF程序用例。同样，这个列表是非详尽的，考虑到tc BPF的可编程性和高效性，它可以很容易地定制并集成到编排系统中，以解决非常特定的用例。虽然一些XDP的用例可能重叠，但tc BPF和XDP BPF在很大程度上是相辅相成的，两者也可以同时使用，或者根据解决给定问题的情况选择使用其中之一。

- **容器的策略执行**

  tc BPF程序适用于实现容器或pod的策略执行、自定义防火墙或类似的安全措施。在传统情况下，容器隔离是通过网络命名空间实现的，其中veth网络设备将主机的初始命名空间与专用容器的命名空间连接起来。由于veth对的一端已移动到容器的命名空间，而另一端仍位于主机的初始命名空间，所有来自容器的网络流量都必须通过面向主机的veth设备，从而允许在veth的tc入口和出口钩子上附加tc BPF程序。进入容器的网络流量将通过面向主机的veth的tc出口钩子传递，而从容器发出的网络流量将通过面向主机的veth的tc入口钩子传递。

  对于像veth设备这样的虚拟设备，XDP在这种情况下不适用，因为内核仅在此处操作`skb`，generic XDP在操作克隆的`skb`时有一些限制。后者在TCP/IP堆栈中广泛使用，以保持用于重传的数据段，在generic XDP钩子中，它将简单地被绕过。此外，generic XDP需要线性化整个`skb`，导致性能严重下降。另一方面，tc BPF更灵活，因为它专注于`skb`输入上下文情况，因此不需要处理通用XDP的限制。

- **转发和负载均衡**

  转发和负载均衡用例与XDP类似，尽管略微更加针对东西向容器工作负载，而不是南北流量（尽管两种技术都可以在任何情况下使用）。由于XDP仅在入口侧可用，tc BPF程序允许进一步的用例，尤其在出口侧适用，例如，容器基础的流量可以通过初始命名空间的BPF在出口侧进行NAT和负载均衡，使其对容器本身透明。由于基于`sk_buff`结构的出口流量由于内核的网络堆栈的性质，所以可以在tc BPF之外对数据包进行重写和重定向。通过利用`bpf_redirect()`助手函数，BPF可以接管转发逻辑，将数据包推入另一个网络设备的入口或出口路径。因此，通过使用tc BPF作为转发结构，可以避免使用任何类似桥设备的设备。

- **流量采样、监控**

  与XDP类似，流量采样和监控可以通过高性能的无锁per-CPU内存映射的perf环形缓冲区来实现，在这里BPF程序能够将自定义数据、完整或截断的数据包内容或两者都推送到用户空间应用程序。从tc BPF程序中，这通过具有与`bpf_xdp_event_output()`相同的函数签名和语义的`bpf_skb_event_output()` BPF辅助函数实现。由于tc BPF程序可以附加到入口和出口，而不仅仅是入口，与XDP BPF情况只能附加到入口相反，以及两个tc钩子位于（通用）网络堆栈的最低层，这允许双向监视来自特定节点的所有网络流量。这可能与tcpdump和Wireshark使用的cBPF情况有些相关，尽管无需克隆`skb`，并且在可编程性方面要灵活得多，例如，BPF已经可以在内核中执行聚合，而不是将所有内容推送到用户空间以及推送到环形缓冲区的数据包的自定义注释。后者在Cilium中也得到了大量使用，其中可以进一步注释以关联容器标签和必须将给定数据包丢弃的原因（例如由于策略违规），以提供更丰富的上下文信息。

- **数据包调度预处理**

    `sch_clsact`的出口钩子，称为`sch_handle_egress()`，在获取内核的qdisc根锁之前运行，因此可以利用tc BPF程序在数据包传入真正的完整的qdisc（例如`sch_htb`）之前执行所有繁重的数据包分类和篡改工作。`sch_clsact`与稍后在传输阶段的实际qdisc（如`sch_htb`）之间的这种交互允许减少传输上的锁争用，因为`sch_clsact`的出口钩子在不锁定的情况下执行。

  一个具体的tc BPF但也是XDP BPF程序的用户是Cilium。Cilium是一款用于透明地保护使用Linux容器管理平台（如Docker和Kubernetes）部署的应用服务之间的网络连接的开源软件，它在第3/4层和第7层操作。Cilium的核心操作是BPF，以实施策略执行以及负载均衡和监控。

  - 幻灯片：https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp
  - 视频：https://youtu.be/ilKlmTDdFgk
  - Github：https://github.com/cilium/cilium

**驱动程序支持**

由于tc BPF程序是从内核的网络堆栈触发的，而不是直接从驱动程序中触发的，因此它们不需要任何额外的驱动程序修改，因此可以在任何网络设备上运行。唯一的例外是将tc BPF程序卸载到NIC。

**支持 offloaded tc BPF 的驱动程序**

- **Netronome**
  - nfp

### More about me

欢迎关注 「barryX的技术笔记」 微信公众号

<img src="/images/wx.png" style="zoom:33%;" />