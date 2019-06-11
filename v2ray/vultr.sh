#!/usr/bin/env bash
# VPS一键安装V2ray脚本(websocket + nginx + tls)(Ubuntu18.04)
#0. 前言：必须先在dns服务商将 二级域名指向新开的服务器，再在服务器上执行本脚本
#1. 更新系统
#2. 安装Nginx
#3. 申请证书：acme.sh
#4. 安装V2ray, 配置生成：https://www.veekxt.com/utils/v2ray_gen
#5. 安装完成后，将服务器上的/etc/v2ray/config.json.client 文件复制到本地，并重命名为/etc/v2ray/config.json后，重启本地v2ray即可
#Date: 2019-06-10

#配置主机名
HOST_NAME="Toronto"

#配置二级域名来转发v2ray流量，不要用一级域名
PROXY_DOMAIN="toronto.abc.com"

#请勿修改以下配置-------------------------------------------
PROXY_DOMAIN_CERT_FILE="/etc/nginx/ssl/${PROXY_DOMAIN}.fullchain.cer"
PROXY_DOMAIN_KEY_FILE="/etc/nginx/ssl/${PROXY_DOMAIN}.key"

#UUID
UUID=`cat /proc/sys/kernel/random/uuid`;

#0. 验证：
#0.1 系统
if [[ 'ubuntu' != "$(cat /etc/os-release | grep -w ID | awk -F '=' '{print $2}')" ]]; then
    echo "System Not UBuntu, exit";
    exit 1;
fi

#1. 基础配置 ：
apt update
apt -y upgrade

#1.0  机器名，时区
echo ${HOST_NAME} > /etc/hostname && hostname ${HOST_NAME}
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
if [ ${lines} -gt 0 ]; then
    startM=`expr ${lines} - 1`;
    endN=`expr ${lines} + 1`;
    sed -i ${startM},${endN}d /usr/share/vim/vim80/defaults.vim
fi

#1.3 开启bbr(Debian9 4.9内核以上已经集成bbr，打开配置即可)
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
sysctl net.ipv4.tcp_available_congestion_control

#4. 安装Nginx
#4.1 安装
apt install -y nginx

#4.2 配置nginx.conf
mkdir -p /export/www/${PROXY_DOMAIN}
echo "hello" > /export/www/${PROXY_DOMAIN}/index.html

mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
cat >  /etc/nginx/nginx.conf << EOF
user  www-data;
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

worker_rlimit_nofile 65535;

events {
    use epoll;
    worker_connections  8192;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    charset utf-8;
    client_header_buffer_size 32k; #上传文件大小限制
    large_client_header_buffers 4 64k; #设定请求缓
    client_max_body_size 8m; #设定请求缓存大小

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    keepalive_timeout  60;

    #gzip模块设置
    gzip               on;
    gzip_vary          on;
    gzip_comp_level    6;
    gzip_buffers       16 8k;
    gzip_min_length    1000;
    gzip_proxied       any;
    gzip_disable       "msie6";
    gzip_http_version  1.0;
    gzip_types         text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript;

    include /etc/nginx/conf.d/*.conf;

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
service nginx restart

#6. 安装acme.sh 自动更新tls证书
curl  https://get.acme.sh | sh
source ~/.bashrc

#6.1 创建证书存放文件夹
mkdir -p /etc/nginx/ssl

#6.2 申请证书
/root/.acme.sh/acme.sh  --issue -d ${PROXY_DOMAIN} --webroot /export/www/${PROXY_DOMAIN}

#6.3 安装证书
/root/.acme.sh/acme.sh --installcert -d ${PROXY_DOMAIN} \
--key-file ${PROXY_DOMAIN_KEY_FILE} \
--fullchain-file ${PROXY_DOMAIN_CERT_FILE} \
--reloadcmd "service nginx force-reload"

#6.4 自动更新证书
/root/.acme.sh/acme.sh  --upgrade  --auto-upgrade

#7. 安装V2ray veekxt.com
curl -L -s https://install.direct/go.sh | bash;
mv /etc/v2ray/config.json /etc/v2ray/config.json.bak
cat > /etc/v2ray/config.json << EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
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
          "path": "/ws"
        },
        "security": "none"
      },
      "tag": "in-0",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 32
          }
        ]
      },
      "protocol": "vmess",
      "port": 44222
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


#6.2 更新Nginx的tls配置
cat >  /etc/nginx/nginx.conf << EOF
user  www-data;
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

worker_rlimit_nofile 65535;

events {
    use epoll;
    worker_connections  8192;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    charset utf-8;
    client_header_buffer_size 32k; #上传文件大小限制
    large_client_header_buffers 4 64k; #设定请求缓
    client_max_body_size 8m; #设定请求缓存大小

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    keepalive_timeout  60;

    #gzip模块设置
    gzip               on;
    gzip_vary          on;
    gzip_comp_level    6;
    gzip_buffers       16 8k;
    gzip_min_length    1000;
    gzip_proxied       any;
    gzip_disable       "msie6";
    gzip_http_version  1.0;
    gzip_types         text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript;

    include /etc/nginx/conf.d/*.conf;

    #站点配置
    server {
        listen  80;
        server_name ${PROXY_DOMAIN};
        root    /export/www/${PROXY_DOMAIN};
        index   index.html index.htm index.php;
    }
    server {
        listen 443 ssl;

        ssl on;
        ssl_certificate       ${PROXY_DOMAIN_CERT_FILE};
        ssl_certificate_key   ${PROXY_DOMAIN_KEY_FILE};
        ssl_protocols         TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers           HIGH:!aNULL:!MD5;

        root /export/www/${PROXY_DOMAIN};
        index index.html index.htm index.nginx-debian.html;
        server_name _;
        location / {
            try_files \$uri \$uri/ =404;
        }

        location /ws {
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


#6.3 客户端配置(复制到本地)
cat > /etc/v2ray/config.json.client << EOF
{
  "log":{},
  "dns":{},
  "stats":{},
  "inbounds":[
    {
      "tag":"in-0",
      "settings":{
        "udp":true,
        "auth":"noauth"
      },
      "port":"1080",
      "protocol":"socks"
    },
    {
      "tag":"in-1",
      "settings":{},
      "port":"1081",
      "protocol":"http"
    }
  ],
  "outbounds":[
    {
      "tag":"out-0",
      "settings":{
        "vnext":[
          {
            "users":[
              {
                "id":"${UUID}",
                "alterId":32
              }
            ],
            "address":"${PROXY_DOMAIN}",
            "port":443
          }
        ]
      },
      "streamSettings":{
        "network":"ws",
        "wsSettings":{
          "path":"/ws"
        },
        "tlsSettings":{
          "serverName":"${PROXY_DOMAIN}"
        },
        "security":"tls"
      },
      "protocol":"vmess",
      "mux": {"enabled": true}
    },
    {
      "tag":"direct",
      "settings":{},
      "protocol":"freedom"
    },
    {
      "tag":"blocked",
      "settings":{},
      "protocol":"blackhole"
    }
  ],
  "routing":{
    "rules":[
      {
        "type":"field",
        "ip":[
          "geoip:private"
        ],
        "outboundTag":"direct"
      }
    ],
    "domainStrategy":"IPOnDemand"
  },
  "policy":{},
  "reverse":{},
  "transport":{}
}
EOF

#6.4 重启nginx and v2ray
service nginx restart
systemctl restart v2ray

echo "install finished";