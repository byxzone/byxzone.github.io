# 本地搭建 Bootlin elixir 查阅内核代码


平时经常使用elixir.bootlin.com查看内核源码，很方便。但是苦于该站点服务器在国外，国内用起来很卡很慢，所以想着自己在本地搭一个。

### 使用环境

>Host：Ubuntu 20.04 （Kernel 5.15）
>
>Docker：ubuntu:latest

### 准备工作

#### 安装依赖

```
apt-get -y install python3 python3-pip python3-jinja2 python3-bsddb3 python3-pytest perl git libjansson4 libyaml-0-2 wget
pip3 install falcon
```

#### 下载两个特殊依赖并安装

```
wget https://bootlin.com/pub/elixir/universal-ctags_0+git20200526-0ubuntu1_amd64.deb
wget https://bootlin.com/pub/elixir/Pygments-2.6.1.elixir-py3-none-any.whl
dpkg -i universal-ctags_0+git20200526-0ubuntu1_amd64.deb
pip3 install Pygments-2.6.1.elixir-py3-none-any.whl
```

#### 配置环境变量

- 修改`/etc/profile`，在末尾增加（具体路径可改为其它）

```
export LXR_REPO_DIR=/srv/elixir-data/linux/repo
export LXR_DATA_DIR=/srv/elixir-data/linux/data
```

- 使环境变量生效

```
source /etc/profile
```

#### 下载配置kernel源码

- 下载kernel源码（建议使用清华大学开源镜像站：https://mirrors.tuna.tsinghua.edu.cn/kernel/）

（以5.15内核为例，可以根据需要自行调整）

```
wget https://mirrors.tuna.tsinghua.edu.cn/kernel/v5.x/linux-5.15.33.tar.gz
```

- 建立相应目录

```
mkdir -p $LXR_REPO_DIR
mkdir -p $LXR_DATA_DIR
```

- 解压至`$LXR_REPO_DIR`

```
tar -zvxf linux-5.15.33.tar.gz  --strip-components 1 -C $LXR_REPO_DIR
```

### 配置apache服务器

#### 安装依赖

```
apt install -y apache2 libapache2-mod-wsgi-py3 
```

- 修改`/etc/apache2/sites-available/000-default.conf`

（默认监听80端口，可以按照自己需要调整）

````
<Directory /usr/local/elixir/http/>
    Options +ExecCGI
    AllowOverride None
    Require all granted
    SetEnv PYTHONIOENCODING utf-8
    SetEnv LXR_PROJ_DIR /srv/elixir-data
</Directory>
<Directory /usr/local/elixir/api/>
    SetHandler wsgi-script
    Require all granted
    SetEnv PYTHONIOENCODING utf-8
    SetEnv LXR_PROJ_DIR /srv/elixir-data
</Directory>
AddHandler cgi-script .py
<VirtualHost *:80>
    ServerName MY_LOCAL_IP
    DocumentRoot /usr/local/elixir/http
    WSGIScriptAlias /api /usr/local/elixir/api/api.py
    AllowEncodedSlashes On
    RewriteEngine on
    RewriteRule "^/$" "/linux/latest/source" [R]
    RewriteRule "^/(?!api|acp).*/(source|ident|search)" "/web.py" [PT]
    RewriteRule "^/acp" "/autocomplete.py" [PT]
</VirtualHost>
````

- 配置apache.conf

```
echo -e "\nHttpProtocolOptions Unsafe" >> /etc/apache2/apache.conf
```

- 开启依赖模块

```
a2enmod cgi rewrite
```

- 启动apache

```
/usr/sbin/apache2ctl -D FOREGROUND
```

### 安装配置bootlin/exilir

- 进入`$LXR_REPO_DIR`目录，更改REPO目录以及www-data的用户目录所有者为www-data

```
cd $LXR_REPO_DIR
cd ..
chown -R www-data ./repo 
cd /var
chown -R www-data ./www
```

- 切换账号到www-data操作（避免一些权限问题引起的错误）

修改`/etc/passwd`，使其可以登录。找到www-data一行，将其改为

```
www-data:x:33:33:www-data:/var/www:/bin/bash
```

修改www-data用户密码（自己设置一个）

```
passwd www-data
```

切换至www-data（可能提示输入密码，输入上面设置的就行）

```
su www-data
```

- 回到`$LXR_REPO_DIR`，进行git初始化（带有v5.15版本号的可以根据自己需要调整）

```
cd $LXR_REPO_DIR
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
git init
git add .
git commit -m 'v5.15'
git tag v5.15
```

- 切换回管理员用户，如`su ubuntu`，将bootlin/elixir项目clone下载

```
git clone https://github.com/bootlin/elixir.git /usr/local/elixir/
```

（最好不要修改`/usr/local/elixir/`）

- 生成索引

```
git config --global --add safe.directory $LXR_REPO_DIR
cd /usr/local/elixir/
python3 update.py
```

（大约需等待一小时左右）

- 大功告成，在浏览器输入对应地址即可查看~

<img src= "/images/bootlin.jpg" />

>官方给出了dockerfile：https://github.com/bootlin/elixir/tree/master/docker，但笔者使用这个安装后打开浏览器是空白页面，推测是权限问题，所以选择了手动配置。

### Ref

bootlin/elixir：https://github.com/bootlin/elixir

### More about me

欢迎关注 「barryX的技术笔记」 微信公众号

<img src="https://gitee.com/barryx/kernel_study/raw/master/img/202203231934741.png" style="zoom:33%;" />
