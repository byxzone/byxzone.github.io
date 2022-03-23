---
title: "Cilium eBPF 搭建与使用"
date: 2022-03-15T23:33:27+08:00
categories: ["eBPF","Golang"]
---

目前使用 Go 开发 eBPF 程序可以使用的框架有 **IO Visor-gobpf**、**Dropbox-goebpf **和 **Cilium-ebpf **等，考虑到 Cilium 的社区活跃度和未来的发展，使用 Cilium 的 ebpf 是一个比较不错的选择。

### 一、环境搭建：

#### 0.基础环境

官方文档：https://github.com/cilium/ebpf

> ####  Requirements
>
> - A version of Go that is [supported by upstream](https://gitee.com/link?target=https%3A%2F%2Fgolang.org%2Fdoc%2Fdevel%2Frelease.html%23policy)
> - Linux >= 4.4. CI is run against LTS releases.

建议使用较新的 Go 和内核版本，笔者使用的环境：

- Ubuntu 20.04（**5.17**.0-051700rc7-generic）

- go version go**1.18** linux/amd64

#### 1.安装依赖

```
apt install clang llvm
```

#### 2.配置环境变量

```
export BPF_CLANG=clang
```

#### 3.将Cilium eBPF克隆到本地：

```
git clone https://github.com/cilium/ebpf.git
```

#### 4.测试

进入`kprobe`目录：

```
cd kprobe
```

删除之前生成的文件：

```
rm *.o
rm bpf_*.go
```

此时剩下的文件应为：

```
.
├── kprobe.c
└── main.go
```

在该目录下执行：

```
go generate
```

此时该目录下的文件：

```
$ tree
.
├── bpf_bpfeb.go
├── bpf_bpfeb.o
├── bpf_bpfel.go
├── bpf_bpfel.o
├── kprobe.c
└── main.go
```

可以看出，此操作分别生成了两对 **.go** 和 **.o** 文件。

继续执行：

```
go build
```

生成了二进制文件`kprobe`

执行该二进制文件：

```
$ sudo ./kprobe
2022/03/23 14:51:54 Waiting for events..
2022/03/23 14:51:55 sys_execve called 6 times
2022/03/23 14:51:56 sys_execve called 25 times
2022/03/23 14:51:57 sys_execve called 35 times
2022/03/23 14:51:58 sys_execve called 37 times
```

打印的结果为执行`sys_execve`的次数，若正确输出则说明环境搭建成功。

### 二、创建自己的 Cilium eBPF 项目

建立并进入项目文件夹：

```
mkdir YOUR_PATH && cd YOUR_PATH
```

将 Cilium eBPF examples 中的相关文件复制过来作为基础进行修改：

```
cd CILIUM_EBPF_PATH/examples   #替换为自己的Cilium eBPF路径
cp -r headers/ YOUR_PATH       #头文件目录
cp kprobe/main.go YOUR_PATH    #Go主程序
cp kprobe/kprobe.c YOUR_PATH   #eBPF C程序 
```

编辑 main.go：

```
vim main.go
```

将第19行

```
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -c    flags $BPF_CFLAGS bpf kprobe.c -- -I../headers
```

改为（修改了最后headers的相对路径）

```
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -c    flags $BPF_CFLAGS bpf kprobe.c -- -I./headers
```

关于 go generate 的原理：

> go generate命令是go 1.4版本里面新添加的一个命令，当运行go generate时，它将扫描与当前包相关的源代码文件，找出所有包含"//go:generate"的特殊注释，提取并执行该特殊注释后面的命令，命令为可执行程序，形同shell下面执行。

在自己的项目目录下执行：

```
go mod init YOUR_NAME
```

此时生成了**go.mod**文件，再继续执行：

```
go mod tidy
```

将依赖添加到了go.mod 中

```
$ cat go.mod
module YOUR_NAME

go 1.18

require github.com/cilium/ebpf v0.8.1

require golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34 // indirect
```

执行 go generate && go build 测试，若无报错并成功生成了 bpf_xxx.go、bpf_xxx.o文件和可执行文件则说明配置成功。

### 三、基于 kprobe 例程打造自己的 eBPF 程序

首先，我们先来分析一下 kprobe 例程中的代码。

main.go 中 main 函数前半部分：

```go
func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()
```

`fn`中定义了kprobe附着的函数为`sys_execve`，并锁定当前进程 eBPF 资源的内存。

之后是调用`loadBpfObjects`将预先编译的 eBPF 程序和 maps 加载到内核，其定义在生成的**.go**文件中，最后是调用`link.Kprobe`进行真正的attach。

关于这个`objs`，其类型是`bpfObjects`，定义在生成的**.go**文件：

```go
// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}
```

`bpfProgramSpecs`、`bpfMapSpecs`的定义分别为：

```go
// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	KprobeExecve *ebpf.ProgramSpec `ebpf:"kprobe_execve"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	KprobeMap *ebpf.MapSpec `ebpf:"kprobe_map"`
}
```

`kprobe_execve`、`kprobe_map`分别对应 kprobe.c 文件中定义的：

```c
struct bpf_map_def SEC("maps") kprobe_map = {
    ...
};

SEC("kprobe/sys_execve")
int kprobe_execve() {
    ...
}
```

所以，Go 中的这两个名字 `KprobeExecve`、`KprobeMap` 就是根据 C 程序中的这两个名字生成过来的，规则是：**首字母大写，去除下划线`_`并大写后一个字母**。

#### 监听open系统调用，获取filename

现在，我们准备利用刚刚创建的 Cilium eBPF 项目，编写一个可以监听 **open** 系统调用，获取 `filename` 的程序。首先先看一下open系统调用：

```
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
	|--do_sys_open(AT_FDCWD, filename, flags, mode);
			|--do_sys_openat2(dfd, filename, &how);
```

```c
static long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how) { ...
```

我们的目标是获取`do_sys_openat2`的第二个参数`filename`。打开kprobe.c开始改造：

将宏SEC的名字和函数名改为：

```c
SEC("kprobe/do_sys_openat2")
int kprobe_openat2(struct pt_regs *ctx) { ...
```

我们想知道当前是哪个进程进行了open系统调用，所以可以通过BPF辅助函数`bpf_get_current_pid_tgid`获得当前pid_tgid：

```c
u32 pid = bpf_get_current_pid_tgid() >> 32;
```

> 关于BPF辅助函数，可以参考文档：https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html

那么怎么获取到 **filename** 呢？

filename 在`kprobe_openat2`的第二个参数，可以通过`PT_REGS_PARM2`宏获取，其定义在`bpf_tracing.h`：

```c
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rsp)
```

（所以需要在 kprobe.c 中 `#include "bpf_tracing.h"`）

`__user`代表该数据在用户空间，所以需要`bpf_probe_read_user_str`读取:

```c
char filename[20];
const char *fp = (char *)PT_REGS_PARM2(ctx);
long err = bpf_probe_read_user_str(filename, sizeof(filename), fp);
```

之后可以通过`bpf_printk`将这些数据输出到`/sys/kernel/debug/tracing/trace`中：

```
bpf_printk("pid:%d,filename:%s,err:%ld",pid,filename,err);
```

kprobe.c 改造结束了，但是使用`PT_REGS_PARM2`需要指定target，在main.go中，继续修改第19行为：

```
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf kprobe.c -- -I./headers
```

我所使用的机器平台为amd64，所以我加上了`--target=amd64`

删除之前生成的文件，否则可能会在之后报错：

```
rm *.o
rm bpf_*.go
```

执行 `go generate` 调用bpf2go生成，此次由于指定了target为amd64，所以生成的文件为：

```
bpf_bpfel_x86.go
bpf_bpfel_x86.o
```

打开 bpf_bpfel_x86.go

由于我们修改了 kprobe.c 中的函数名，所以此处也对应的发生了改变：

```go
type bpfProgramSpecs struct {
	KprobeOpenat2 *ebpf.ProgramSpec `ebpf:"kprobe_openat2"`
}
```

我们需要将 main.go 一并更改（第44行）：

```go
kp, err := link.Kprobe(fn, objs.KprobeOpenat2)
```

然后更改`fn`为我们要 attach 的函数 `do_sys_openat2`（第26行）：

```go
fn := "do_sys_openat2"
```

最后，生成二进制文件并运行：

```
$ go build && sudo ./YOUR_NAME
2022/03/23 17:01:03 Waiting for events..
2022/03/23 17:01:04 do_sys_openat2 called 760 times
2022/03/23 17:01:05 do_sys_openat2 called 958 times
```

查看输出

```
$ sudo cat /sys/kernel/debug/tracing/trace
cat-188135  [000] d..31 22778.701532: bpf_trace_printk: pid:188135,filename:/lib/x86_64-linux-g,err:20
cat-188135  [000] d..31 22778.701626: bpf_trace_printk: pid:188135,filename:/usr/lib/locale/loc,err:20
cat-188135  [000] d..31 22778.701647: bpf_trace_printk: pid:188135,filename:/proc/188110/stat,err:18
sleep-188141  [000] d..31 22779.153330: bpf_trace_printk: pid:188141,filename:/lib/x86_64-linux-g,err:20
sleep-188141  [000] d..31 22779.153332: bpf_trace_printk: pid:188141,filename:/lib/x86_64-linux-g,err:20
node-2180    [001] d..31 22779.321307: bpf_trace_printk: pid:2180,filename:/proc/188110/cmdlin,err:20
node-2976    [000] d..31 22779.323348: bpf_trace_printk: pid:2976,filename:/proc/3137/cmdline,err:19
node-2976    [000] d..31 22779.323374: bpf_trace_printk: pid:2976,filename:/proc/47269/cmdline,err:20
```

### 参考文献：

https://zhuanlan.zhihu.com/p/466893888

https://blog.csdn.net/qq_31362439/article/details/122727406

https://www.jianshu.com/p/a866147021da

https://blog.csdn.net/jasonactions/article/details/116125922

https://szp2016.github.io/uncategorized/ebpf%E5%85%A5%E9%97%A8/