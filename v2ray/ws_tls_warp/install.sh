#!/usr/bin/env bash
# VPS一键安装V2ray脚本（含warp）
#0. 前言：必须先在dns服务商将域名指向新开的服务器，再在服务器上执行本脚本
#1. 编译安装Nginx + openssl
#2. 申请证书：acme.sh 并自动更新
#3. 安装V2ray 并使用ws+tls1.3模式
#4. 安装cloudfare warp 并自动配置 openai.com 的分流规则
#5. 安装完成后，将生成的客户端配置下载到本地导入GUI工具即可

#------------------------------------------------------------------
#自定义区域：可手动选择404页面的模板序号，默认为2
FRONTPAGE_INDEX=1
#------------------------------------------------------------------
V2RAY_VERSION="v4.45.2"
NGINX_VERSION="1.19.1"
OPENSSL_VERSION="1.1.1s"
REPO_ADDR="https://raw.githubusercontent.com/ummmme/impatriot"
V2RAY_INSTALL_SCRIPT="https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh"
GEO_FILES_DOWNLOAD="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/"

#说明
showUsage() {
cat 1>&2 <<EOF
*-----------------------------------------------------------------------
v2ray 一键安装脚本，自动安装v2ray, nginx, 自动申请证书，自动更新证书，自动生成websocket+nginx+tls1.3模式的服务端和客户端配置
注意： 使用本脚本前必须先将域名指向这台服务器
*-----------------------------------------------------------------------
EOF
}

showFinishInfo() {
cat 1>&2 <<EOF
*-----------------------------------------------------------------------
INFO：v2ray 已经安装并配置完毕，请将生成的配置文件：/tmp/$1.json 下载至本地导入到客户端使用
INFO：服务端v2ray版本为：$2，请注意客户端版本是否匹配
*-----------------------------------------------------------------------
EOF
}

printr() {
    echo -e "\033[32m====================================================================================\033[0m";
    echo -e "\033[32m$1\033[0m"
    echo -e "\033[32m====================================================================================\033[0m";
}

# 生成随机数字
rand(){
    min=$1
    max=$(($2-$min+1))
    num=$(cat /proc/sys/kernel/random/uuid | cksum | awk -F ' ' '{print $1}')
    echo $(($num%$max+$min))
}

#生成随机长度的字符串,默认为5到8位
randStr() {
    len=$(rand 5 8);
    echo $(date +%s%N | md5sum | head -c "${len}");
}

#等待输入域名，开始安装
clear
showUsage;
# shellcheck disable=SC2116
read -p "请输入您的域名，确保已经指向当前服务器：" PROXY_DOMAIN;

#判断域名有效性(兼容GCP等使用弹性IP的云服务器，只需要获取公网出口的IP地址即可，忽略代理层)
PUBLIC_IP=$(curl whatismyip.akamai.com);
DOMAIN_IP=$(ping -c 1 ${PROXY_DOMAIN} | sed -n "1p" | awk -F '(' '{print $2}'| awk -F ')' '{print $1}');

if [[ "${PUBLIC_IP}" != "${DOMAIN_IP}" ]]; then
    printr "[ERROR]:  域名:${PROXY_DOMAIN} 没有指向当前服务器，请检查后重试";
    exit 1;
fi

#准备Nginx与Openssl的安装文件(暂不做签名比对)
wget -c https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -O /usr/local/nginx-${NGINX_VERSION}.tar.gz
if [ ! -f "/usr/local/nginx-${NGINX_VERSION}.tar.gz" ]; then
    printr "下载nginx失败，请重试"
fi

wget -c https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz  -O /usr/local/openssl-${OPENSSL_VERSION}.tar.gz
if [ ! -f "/usr/local/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    printr "下载openssl失败，请重试"
fi

#-----------------------------------------------------------------------------------------------------------------------
# 请勿修改以下配置
#-----------------------------------------------------------------------------------------------------------------------
#1. 更新系统
printr "1. UPDATING SYSTEM"
curl https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
sudo apt update -qq && sudo apt upgrade -yqq

#2. 安装必要的组件
printr "2. INSTALLING REQUIREMENTS"
sudo apt install -yqq build-essential libpcre3 libpcre3-dev zlib1g-dev unzip git dnsutils vim net-tools tcl tk expect

#配置三级域名来转发v2ray流量，不要用二级域名
PROXY_DOMAIN_CERT_FILE="/usr/local/nginx/ssl/${PROXY_DOMAIN}.fullchain.cer"
PROXY_DOMAIN_KEY_FILE="/usr/local/nginx/ssl/${PROXY_DOMAIN}.key"

#UUID
UUID=`cat /proc/sys/kernel/random/uuid`;

#使用随机字符串作为v2ray流量入口
V2RAY_PATH=`randStr`;

#0. 验证：
#0.1 系统
#if [[ 'ubuntu' != "$(cat /etc/os-release | grep -w ID | awk -F '=' '{print $2}')" ]]; then
#    echo "System Not UBuntu, exit";
#    exit 1;
#fi

#1.0  机器名，时区
#echo ${HOST_NAME} > /etc/hostname && hostname ${HOST_NAME}
timedatectl set-timezone Asia/Shanghai

## 1.1 配置命令alias:
cat >> ~/.bashrc << EOF
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
EOF
source ~/.bashrc

#1.2 配置vim(Debian):
# 备份
cp /usr/share/vim/vim80/defaults.vim /usr/share/vim/vim80/defaults.vim.bak
#1.2.1 取消可视化模式(删除带有set mouse=a)
lines=`grep -n 'set mouse=a' /usr/share/vim/vim80/defaults.vim | tail -1 | awk -F ":" '{print $1}'`;
if [[ ${lines} -gt 0 ]]; then
    startM=`expr ${lines} - 1`;
    endN=`expr ${lines} + 1`;
    sed -i ${startM},${endN}d /usr/share/vim/vim80/defaults.vim
fi

#1.3 开启bbr(Debian9 4.9内核以上已经集成bbr，打开配置即可)
printr "3. OPENING BBR"
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
sysctl net.ipv4.tcp_available_congestion_control

#4. 编译安装Nginx，开启tls1.3支持
cd /usr/local || exit 1;

#4.1.1 安装依赖
groupadd www # 添加组
useradd -s /sbin/nologin -g www www #添加用户

#4.1.2 安装openssl
tar zxvf openssl-${OPENSSL_VERSION}.tar.gz && rm openssl-${OPENSSL_VERSION}.tar.gz

#4.1.3 下载nginx
tar zxvf nginx-${NGINX_VERSION}.tar.gz && rm nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION} || exit 1;

#编译
printr "4. CONFIGURING NGINX"
./configure --user=www \
--group=www \
--prefix=/usr/local/nginx \
--pid-path=/run/nginx.pid \
--with-openssl=/usr/local/openssl-${OPENSSL_VERSION} \
--with-openssl-opt='enable-tls1_3' \
--with-http_v2_module \
--with-http_ssl_module \
--with-http_gzip_static_module \
--with-http_stub_status_module \
--with-http_sub_module \
--with-stream \
--with-stream_ssl_module \
> /tmp/nginx_conf.log

#安装
printr "5. INSTALLING NGINX"
make > /tmp/nginx_make.log && make install > /tmp/nginx_make_install.log

#快捷方式
ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx

#Nginx注册服务(注意：Ubuntu的systemd路径与centos不一致，此处为Ubuntu)
cat > /etc/systemd/system/nginx.service << \EOF
[Unit]
Description=Nginx - high performance web server
Documentation=http://nginx.org/en/docs/
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf
ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
ExecReload=/bin/kill -s HUP $(cat /run/nginx.pid)
ExecStop=/bin/kill -s QUIT $(cat /run/nginx.pid)
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# 启动nginx
printr "6. STARTING NGINX"
systemctl start nginx

if ! pgrep -x "nginx"; then
    printr "ERROR: NGINX SERVICE NOT START";
    journalctl -u nginx;
    exit 1;
fi

#4.2 配置nginx.ws_nginx_tls, 默认主页为404页面
printr "7. CONFIGURING NGINX WEB PAGE"
mkdir -p /export/www/${PROXY_DOMAIN}
curl -f -L -sS ${REPO_ADDR}/master/404/${FRONTPAGE_INDEX}.html > /export/www/${PROXY_DOMAIN}/index.html
sed -i "s/domainName/${PROXY_DOMAIN}/g" /export/www/${PROXY_DOMAIN}/index.html
chmod -R 777 /export/www/${PROXY_DOMAIN}

mv /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.conf.bak
cat >  /usr/local/nginx/conf/nginx.conf << EOF
user  www;
worker_processes  auto;

error_log  /usr/local/nginx/logs/error.log warn;
pid        /run/nginx.pid;

worker_rlimit_nofile 65535;

events {
    use epoll;
    worker_connections  8192;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    access_log  off;
    charset utf-8;
    client_header_buffer_size 32k; #上传文件大小限制
    large_client_header_buffers 4 64k; #设定请求缓
    client_max_body_size 8m; #设定请求缓存大小

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    keepalive_timeout  60;

    #站点配置
    server {
        listen  80;
        server_name ${PROXY_DOMAIN};
        root    /export/www/${PROXY_DOMAIN};
        index   index.html index.htm index.php;
    }
}
EOF

#5. 重启
printr "8. RESTARTING NGINX"
systemctl enable nginx
systemctl restart nginx

#6. 安装acme.sh 自动更新tls证书
printr "9. INSTALLING ACME.SH"
curl  https://get.acme.sh | sh
source ~/.bashrc

#6.1 创建证书存放文件夹
mkdir -p /usr/local/nginx/ssl

#6.2 申请证书
printr "10. APPLYING ACME CERT"
/root/.acme.sh/acme.sh --server letsencrypt --issue -d ${PROXY_DOMAIN} --webroot /export/www/${PROXY_DOMAIN}

#6.3 安装证书
printr "11. INSTALLING ACME CERT"
/root/.acme.sh/acme.sh --installcert -d ${PROXY_DOMAIN} \
--key-file ${PROXY_DOMAIN_KEY_FILE} \
--fullchain-file ${PROXY_DOMAIN_CERT_FILE} \
--reloadcmd "systemctl restart nginx"

#6.4 自动更新证书
printr "12. CONFIGURING ACME AUTO UPGRADE"
/root/.acme.sh/acme.sh  --upgrade  --auto-upgrade

# 7. 安装Cloudfare warp---------------------------------------------------------------
printr "13. INSTALL CF WARP"
apt install -yqq cloudflare-warp

if ! pgrep -x warp-svc ; then
  printr "ERROR: WARP SERVICE NOT RUNNING";
fi

warp-cli register
warp-cli set-mode proxy
warp-cli connect
warp-cli enable-always-on

#更新v2ray 安装方式---------------------------------------------------------------
#7.1 安装V2ray（新）
printr "14. INSTALLING V2RAY"
bash <(curl -L ${V2RAY_INSTALL_SCRIPT}) --version ${V2RAY_VERSION};

#7.2 生成服务端配置（单配置文件模式）
mkdir -p /etc/v2ray
cat > /usr/local/etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {},
  "stats": {},
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/${V2RAY_PATH}"
        },
        "security": "none"
      },
      "tag": "in-0",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0
          }
        ]
      },
      "protocol": "vmess",
      "port": 44222,
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "settings": {},
      "protocol": "freedom"
    },
    {
      "tag": "blocked",
      "settings": {},
      "protocol": "blackhole"
    },
    {
      "tag":"warp",
      "protocol":"socks",
      "settings": {
        "servers": [
          {
            "address":"127.0.0.1",
            "port":40000,
            "users":[]
          }
        ]
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "warp",
        "domain": [
          "openai.com",
          "geosite:openai"
        ]
      }
    ],
    "domainStrategy": "AsIs"
  },
  "policy": {},
  "reverse": {},
  "transport": {}
}
EOF

#7.3 更新Nginx的websocket + tls1.3 配置
printr "15. CONFIGURING NGINX WEBSOCKET SETTINGS"
cat >  /usr/local/nginx/conf/nginx.conf << EOF
user  www;
worker_processes  auto;

error_log  /usr/local/nginx/logs/error.log warn;
pid        /run/nginx.pid;

worker_rlimit_nofile 65535;

events {
    use epoll;
    worker_connections  8192;
    multi_accept on;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    charset utf-8;
    access_log  off;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    keepalive_timeout  60;

    server {
        listen 80;
        server_name ${PROXY_DOMAIN};
        rewrite ^(.*)$ https://\${server_name}\$1 permanent;
    }

    #站点配置
    server {
        listen 443 ssl default_server;

        ssl_certificate       ${PROXY_DOMAIN_CERT_FILE};
        ssl_certificate_key   ${PROXY_DOMAIN_KEY_FILE};
        ssl_protocols         TLSv1.3;
        ssl_ciphers 'CHACHA20:EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;';
        ssl_prefer_server_ciphers on; #优化SSL加密
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 60m;

        root /export/www/${PROXY_DOMAIN};
        index index.htm index.html;
        server_name ${PROXY_DOMAIN};
        location / {
            try_files \$uri \$uri/ =404;
        }

        location /${V2RAY_PATH} {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:44222;

            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
            proxy_read_timeout 300s;
        }
    }
}
EOF

#7.4 更新服务端的geosite文件
printr "16. UPDATING V2RAY GEOSITE"
# 下载 geoip.dat 和 geosite.dat 文件
wget -c ${GEO_FILES_DOWNLOAD}/geosite.dat -O /tmp/geosite.dat
wget -c ${GEO_FILES_DOWNLOAD}/geoip.dat -O /tmp/geoip.dat

# 备份
cp /usr/local/share/v2ray/geosite.dat /usr/local/share/v2ray/geosite.dat.bak
cp /usr/local/share/v2ray/geoip.dat /usr/local/share/v2ray/geoip.dat.bak

# 更新
mv /tmp/geoip.dat /usr/local/share/v2ray/geoip.dat
mv /tmp/geosite.dat /usr/local/share/v2ray/geosite.dat

#7.5 重启nginx
printr "17. RESTARTING NGINX"
systemctl restart nginx

#7.7 自定义v2ray-daemon（截至4.34版本）
printr "18. STARTING V2RAY"
#备用启动命令： nohup /usr/local/bin/v2ray --config=/usr/local/etc/v2ray/config.json 2>&1 & >> /dev/null
if [[ -f "/etc/systemd/system/v2ray.service" ]]; then
    mv /etc/systemd/system/v2ray.service /etc/systemd/system/v2ray.service.bak
fi

cat > /etc/systemd/system/v2ray.service << EOF
[Unit]
Description=V2Ray Service
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

#7.6 启动v2ray（指定单配置文件模式）
systemctl enable v2ray
systemctl daemon-reload
systemctl start v2ray

#7.7 首次启动检测
printr "19. FIRST TIME START CHECKING"
if [ ! $(ps aux| grep v2ray|grep -v 'grep'|awk '{print $11}') = "/usr/local/bin/v2ray" ]; then
    printr "v2ray启动失败，参考日志：";
    journalctl -u v2ray;
    exit 1;
else
    printr "v2ray启动成功";
fi

#8. 优化
printr "20. SYSTEM PARAM OPTIMIZATION"
cat > /etc/sysctl.d/default.conf << EOF
# 最大打开文件
fs.file-max = 65535
# 最大读取缓冲区
net.core.rmem_max = 67108864
# 最大写入缓冲区
net.core.wmem_max = 67108864
# 默认读取缓冲区
net.core.rmem_default = 65536
# 默认写入缓冲区
net.core.wmem_default = 65536
# 最大处理器输入队列
net.core.netdev_max_backlog = 4096
# 最大积压量
net.core.somaxconn = 4096

# 抵御 SYN 洪水攻击
net.ipv4.tcp_syncookies = 1
# 安全时重用 timewait 套接字
net.ipv4.tcp_tw_reuse = 1
# 关闭快速 timewait 套接字回收
net.ipv4.tcp_tw_recycle = 0
# FIN 超时时间
net.ipv4.tcp_fin_timeout = 30
# keepalive 间隔时间
net.ipv4.tcp_keepalive_time = 1200
# 出站端口范围
net.ipv4.ip_local_port_range = 10000 65000
# 最大 SYN 积压
net.ipv4.tcp_max_syn_backlog = 4096
# 由系统同时持有的最大 timewait 套接字
net.ipv4.tcp_max_tw_buckets = 5000
# 开启 TCP Fast Open
net.ipv4.tcp_fastopen = 3
# TCP 接收缓冲区
net.ipv4.tcp_rmem = 4096 87380 67108864
# TCP 写入缓冲区
net.ipv4.tcp_wmem = 4096 65536 67108864
# 开启 MTU 探测
net.ipv4.tcp_mtu_probing = 1

# 开启忽略 ICMP 请求
#net.ipv4.icmp_echo_ignore_all = 1

# 适用于高延迟网络
#net.ipv4.tcp_congestion_control = hybla

# 对于低延迟网络，用 cubic 代替
#net.ipv4.tcp_congestion_control = cubic

# BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl --system

#7.2 增加文件描述符限制, <所有用户> <软限制和硬限制> <文件描述符> <整型数值>
printr "21. FINISHING INSTALL, ENJOY!"
mkdir -p /etc/security/limits.d
echo "* - nofile 65535" > /etc/security/limits.d/default.conf;
ulimit -n 65535

V_VERSION=`/usr/local/bin/v2ray -version  | grep V2Ray  |   awk '{print  $2}'`;
showFinishInfo ${PROXY_DOMAIN} ${V_VERSION};
