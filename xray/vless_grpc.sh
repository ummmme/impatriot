#!/usr/bin/env bash
# 一键安装xray: 不支持低于Ubuntu22.04以下版本，不支持低于Debian 12以下版本;
#0. 前言：必须先在dns服务商将域名指向新开的服务器，再在服务器上执行本脚本
#1. 编译安装Nginx + openssl(LTS 版本)
#2. 申请证书：acme.sh 并自动更新
#3. 安装xray 并使用 grpc + tls1.3 模式
#4. 安装完成后，将生成的客户端配置下载到本地导入GUI工具即可

#------------------------------------------------------------------
#自定义区域：可手动选择404页面的模板序号
FRONTPAGE_INDEX=0
#------------------------------------------------------------------
XRAY_VERSION="25.8.3"
NGINX_VERSION="1.26.3"
OPENSSL_VERSION="3.0.17"
REPO_ADDR="https://raw.githubusercontent.com/ummmme/impatriot"
GEO_FILES_DOWNLOAD="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/"
PROXY_DOMAIN_CERT_FILE="/usr/local/nginx/ssl/${PROXY_DOMAIN}.fullchain.cer"
PROXY_DOMAIN_KEY_FILE="/usr/local/nginx/ssl/${PROXY_DOMAIN}.key"

#说明
showUsage() {
cat 1>&2 <<EOF
*-----------------------------------------------------------------------
xray 一键安装脚本，自动安装XRAY, nginx, 自动申请证书，自动更新证书，自动生成vless+nginx+grpc+tls1.3模式的服务端和客户端配置
注意： 使用本脚本前必须先将域名指向这台服务器
*-----------------------------------------------------------------------
EOF
}

showFinishInfo() {
cat 1>&2 <<EOF
*-----------------------------------------------------------------------
INFO：XRAY 已经安装并配置完毕，请将生成的配置文件：/tmp/$1.json 下载至本地导入到客户端使用
INFO：服务端XRAY版本为：$2，请注意客户端版本是否匹配
INFO：请打开浏览器访问 https://$1 ，若可以正常访问表示安装正常
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

#下载Nginx与Openssl的安装文件(暂不做签名比对)
wget -c https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -O /usr/local/nginx-${NGINX_VERSION}.tar.gz
if [ ! -f "/usr/local/nginx-${NGINX_VERSION}.tar.gz" ]; then
    printr "下载nginx失败，请重试"
    exit 1;
fi

wget -c https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz  -O /usr/local/openssl-${OPENSSL_VERSION}.tar.gz
if [ ! -f "/usr/local/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    printr "下载openssl失败，请重试"
    exit 1;
fi

#-----------------------------------------------------------------------------------------------------------------------
# 请勿修改以下配置
#-----------------------------------------------------------------------------------------------------------------------
#1. 更新系统
printr "0. UPDATING SYSTEM"
apt update -qq && apt upgrade -yqq
apt install -yqq build-essential libpcre3 libpcre3-dev zlib1g-dev unzip git dnsutils vim net-tools tcl tk perl expect bc htop

#2. 验证：
#2.1 系统版本 Debian12+， Ubuntu22.04+
printr "1. CHECKING SYSTEM VERSION";
curSysName=$(cat /etc/os-release | grep -w NAME | awk -F '=' '{print $2}' | tr -d '"');
curSysVer=$(cat /etc/os-release | grep -w VERSION_ID | awk -F '=' '{print $2}' | tr -d '"');
if [[ $curSysName == 'Debian GNU/Linux' ]] && [ $(echo "$curSysVer >= 12" |bc) -eq 1 ] ; then
  printr "OK, System Debian 12+ Matched";
elif  [[ $curSysName == 'Ubuntu' ]] && [ $(echo "$curSysVer >= 22"|bc) -eq 1 ] ; then
  printr "OK, System Ubuntu 22.04+ Matched";
else
  printr "[ERROR] System Version is too old to install. Require Version： Debian 12+ or Ubuntu 22.04+"
fi

#UUID
UUID=`cat /proc/sys/kernel/random/uuid`;

#使用随机字符串作为XRAY流量入口
XRAY_PATH=`randStr`;

printr "2. SYSTEM CONFIG";
timedatectl set-timezone Asia/Shanghai

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

touch ~/.vimrc
echo 'syntax on' >> ~/.vimrc
echo 'set nu' >> ~/.vimrc
echo 'set mouse=""' >> ~/.vimrc

#4. 编译安装Nginx，开启tls1.3支持
cd /usr/local || exit 1;
mkdir -p /var/log/nginx

#4.1.1 安装依赖
# 检查 www-data 用户和组是否存在，不存在则创建
if ! getent group www-data > /dev/null; then
    /usr/sbin/groupadd www-data
fi
if ! getent passwd www-data > /dev/null; then
    /usr/sbin/useradd -s /sbin/nologin -g www-data www-data
fi

#4.1.2 安装openssl
tar zxf openssl-${OPENSSL_VERSION}.tar.gz && rm openssl-${OPENSSL_VERSION}.tar.gz

#4.1.3 下载nginx
tar zxf nginx-${NGINX_VERSION}.tar.gz && rm nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION} || exit 1;

#编译
printr "4. CONFIGURING NGINX"
./configure --user=www-data \
--group=www-data \
--prefix=/usr/local/nginx \
--pid-path=/run/nginx.pid \
--with-openssl=/usr/local/openssl-${OPENSSL_VERSION} \
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
if [ ! -f "/usr/sbin/nginx" ]; then
  ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx
else
  rm -f /usr/sbin/nginx && ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx
fi  

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

#4.2 配置nginx默认主页
printr "7. CONFIGURING NGINX WEB PAGE"
mkdir -p /export/www/${PROXY_DOMAIN}
curl -f -L -sS ${REPO_ADDR}/master/404/${FRONTPAGE_INDEX}.html > /export/www/${PROXY_DOMAIN}/index.html
sed -i "s/domainName/${PROXY_DOMAIN}/g" /export/www/${PROXY_DOMAIN}/index.html
chmod -R 777 /export/www/${PROXY_DOMAIN}

mv /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.conf.bak
cat >  /usr/local/nginx/conf/nginx.conf << EOF
user  www-data;
worker_processes  auto;
error_log  /var/log/nginx/error.log warn; # 使用标准日志路径
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

#5. 清理安装日志
printr "8. RESTARTING NGINX & CLEANING NGINX INSTALL LOGS"
systemctl enable nginx
systemctl restart nginx
rm -f /tmp/nginx_make*.log 

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

#7. XRAY 安装---------------------------------------------------------------
#7.1 安装XRAY
printr "14. INSTALLING XRAY"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" install --version v${XRAY_VERSION};

#7.2 生成服务端配置（单配置文件模式）
mkdir -p /etc/xray
cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "dnsLog": false
  },
  "dns": {},
  "stats": {},
  "inbounds": [
    {
      "tag": "in-0",
      "listen": "127.0.0.1",
      "port": 44222,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}"
          }
        ],
      "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${XRAY_PATH}"
        },
        "security": "none"
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
      }
    ],
    "domainStrategy": "AsIs"
  },
  "policy": {},
  "reverse": {},
  "transport": {}
}
EOF

#7.3 更新Nginx的grpc + tls1.3 配置
printr "15. CONFIGURING NGINX GRPC SETTINGS"
cp /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.conf.bak_before_xray
cat > /usr/local/nginx/conf/nginx.conf << EOF
user  www-data;
worker_processes  auto;
error_log  /var/log/nginx/error.log warn; # 使用标准日志路径
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

    # HTTP 到 HTTPS 跳转 (优化后)
    server {
        listen 80;
        listen [::]:80;
        server_name ${PROXY_DOMAIN};
        return 301 https://\$host\$request_uri;
    }

    #站点配置
    server {
        listen 443 ssl default_server;
        listen [::]:443 ssl ;
        http2 on; #注意此处为1.26版本以上的nginx语法

        server_name ${PROXY_DOMAIN};
        root /export/www/${PROXY_DOMAIN};
        index index.htm index.html;
      
        ssl_certificate       ${PROXY_DOMAIN_CERT_FILE};
        ssl_certificate_key   ${PROXY_DOMAIN_KEY_FILE};

        # 协议版本：明确指定只使用 TLSv1.3，使用指定的密码套件
        ssl_protocols TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256';
        ssl_prefer_server_ciphers on;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;

        resolver 8.8.8.8 8.8.4.4 valid=300s;
        resolver_timeout 5s;

        # 4. HSTS (HTTP Strict Transport Security)  强烈推荐，强制浏览器只使用 HTTPS。 警告：请确保全站已准备好纯 HTTPS。
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

        location / {
            try_files \$uri \$uri/ =404;
        }

        location /${XRAY_PATH} {
            # 检查请求类型，增加安全性
            if (\$content_type !~ "application/grpc") {
              return 404;
            }
            client_max_body_size 0;

            grpc_pass grpc://127.0.0.1:44222;
        }
      }
}
EOF

#7.4 更新服务端的geosite文件
printr "16. UPDATING XRAY GEOSITE"
# 下载 geoip.dat 和 geosite.dat 文件
wget -c ${GEO_FILES_DOWNLOAD}/geosite.dat -O /tmp/geosite.dat
wget -c ${GEO_FILES_DOWNLOAD}/geoip.dat -O /tmp/geoip.dat

# 备份
cp /usr/local/share/xray/geosite.dat /usr/local/share/xray/geosite.dat.bak
cp /usr/local/share/xray/geoip.dat /usr/local/share/xray/geoip.dat.bak

# 更新
mv /tmp/geoip.dat /usr/local/share/xray/geoip.dat
mv /tmp/geosite.dat /usr/local/share/xray/geosite.dat

#7.5 重启nginx
printr "17. RESTARTING NGINX"
systemctl restart nginx

#7.6 客户端配置
printr "18. GENERATING CLIENT CONFIGURATION"
cat > /tmp/${PROXY_DOMAIN}.json << EOF
{
  "inbounds": [
    {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${PROXY_DOMAIN}",
            "port": 443,
            "users": [
              {
                "id": "${UUID}",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${PROXY_DOMAIN}",
          "fingerprint": "chrome"
        },
        "grpcSettings": {
          "serviceName": "${XRAY_PATH}"
        }
      }
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "direct"
      }
    ]
  }
}
EOF

#7.7 自定义xray-daemon
printr "19. STARTING XRAY"
#备用启动命令： nohup /usr/local/bin/xray --config=/usr/local/etc/xray/config.json 2>&1 & >> /dev/null
if [[ -f "/etc/systemd/system/xray.service" ]]; then
    mv /etc/systemd/system/xray.service /etc/systemd/system/xray.service.bak
fi

cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

#7.8 启动xray（指定单配置文件模式）
systemctl enable xray
systemctl daemon-reload
systemctl start xray

#7.9 首次启动检测
printr "20. FIRST TIME START CHECKING"
sleep 3  # 等待几秒钟让xray服务启动
if systemctl is-active --quiet xray; then
    printr "xray启动成功 (Xray service started successfully)";
else
    printr "xray启动失败，请检查日志 (Xray service failed to start, check logs):";
    journalctl -u xray --no-pager -n 50 # 显示最近50行日志
    exit 1;
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
/usr/sbin/sysctl --system

#8.2 增加文件描述符限制, <所有用户> <软限制和硬限制> <文件描述符> <整型数值>
printr "21. FINISHING INSTALL, ENJOY!"
mkdir -p /etc/security/limits.d
echo "* - nofile 65535" > /etc/security/limits.d/default.conf;
ulimit -n 65535

#9. ALL DONE
V_VERSION=$(/usr/local/bin/xray version  | grep V2Ray  |   awk '{print  $2}');
showFinishInfo ${PROXY_DOMAIN} ${V_VERSION};
