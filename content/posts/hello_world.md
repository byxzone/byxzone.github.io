---
title: "Hello World!"
date: 2022-03-15T23:33:27+08:00
categories: ["misc"]
#draft: true
---

这篇文章是把博客从阿里云迁到腾讯云上之后的第一篇博客。

之前是在阿里云上使用WordPress搭建的，但是感觉比较臃肿，而且之前也就写过几篇博客，干脆就重新搭建一个。因为我现在一般都用Markdown格式写东西，所以就打算找一个利用Markdown生成静态网站的工具。

我目前有两台电脑，一台Windows笔记本、一台MacMini。

搭建了以下环境：

- **Typora**（编辑Markdown文档）

- **坚果云**（作为Typora的工作目录，每次保存可以同步，也便于我在两台电脑之间切换）

- **Gitee图床**  (存放静态图片）

- **PicGo** （配置Typora，将图片自动上传到Gitee图床）

服务器端：

- **Hugo** （生成静态页面）

- **Docker** （容器化）

- **Nginx** （作为静态页面的web服务器）

并且我在Gitee上单独开了一个仓库，存放Hugo生成的站点，并且开通了Gitee Pages。

我的想法是这样的：

- 使用Typora编写内容。

- 将编写好的内容，放到Hugo中，并生成静态页面。（因为Nginx的网页目录就是public，所以此时已经可以通过域名访问到）

- 将站点通过git push到Gitee中，并在Gitee Pages中部署。

以上在环境方面的准备，接下来是内容方面的准备。

目前研一在读，研究方向大体为**Linux Kernel**、**eBPF**、**内核网络**、**Golang**这些，所以博客的内容主要以学习这些的笔记为主。

初学者难免会犯一些错误，如果有问题的话，欢迎大家向我指出！感谢！

可以发邮件：i@barryx.cn

或者在Gitee中提交issue：https://gitee.com/barryx/barryx_blog/
