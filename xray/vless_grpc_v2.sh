#!/usr/bin/env bash
#=============================================================================
# 脚本名称：xray-secure-deploy.sh
# 功能描述：自动化部署 Xray + Nginx + TLS (vless+grpc) 后端服务
# 版本要求：Ubuntu 22.04+ 或 Debian 12+
# 安全标准：遵循最小权限原则，禁用不安全协议，启用自动安全更新
#=============================================================================

# 1. 严格模式：遇到错误立即退出，使用未定义变量报错，管道失败报错
set -euo pipefail

# 2. 全局变量配置
readonly SCRIPT_VERSION="2.0.0"
readonly NGINX_CONF_DIR="/etc/nginx"
readonly XRAY_CONF_DIR="/etc/xray"
readonly WEB_ROOT="/var/www/html"
readonly SSL_DIR="/etc/nginx/ssl"
readonly LOG_FILE="/var/log/xray_deploy.log"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly PLAIN='\033[0m'

# 3. 日志与工具函数
log_info() {
    echo -e "${GREEN}[INFO]${PLAIN} $(date '+%F %T') - $1"
    echo "[INFO] $(date '+%F %T') - $1" >> "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${PLAIN} $(date '+%F %T') - $1" >&2
    echo "[ERROR] $(date '+%F %T') - $1" >> "${LOG_FILE}"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${PLAIN} $(date '+%F %T') - $1"
    echo "[WARN] $(date '+%F %T') - $1" >> "${LOG_FILE}"
}

# 异常退出处理
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "脚本执行失败，退出码：${exit_code}。请检查 ${LOG_FILE}"
        # 此处可添加清理逻辑，如停止未完全启动的服务
    fi
    exit $exit_code
}
trap cleanup EXIT

# 确保 Root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 身份运行 (sudo -i)"
        exit 1
    fi
}

# 系统版本检查
check_system() {
    local sys_name
    local sys_ver
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        sys_name="${ID}"
        sys_ver="${VERSION_ID}"
    else
        log_error "无法识别操作系统版本"
        exit 1
    fi

    # 版本比较逻辑 (简化版，仅检查主要版本)
    if [[ "${sys_name}" == "ubuntu" ]]; then
        if (( $(echo "${sys_ver} < 22.04" | bc -l) )); then
            log_error "Ubuntu 版本过低，要求 22.04 及以上 (当前：${sys_ver})"
            exit 1
        fi
    elif [[ "${sys_name}" == "debian" ]]; then
        if (( $(echo "${sys_ver} < 12" | bc -l) )); then
            log_error "Debian 版本过低，要求 12 及以上 (当前：${sys_ver})"
            exit 1
        fi
    else
        log_warn "未官方测试的系统：${sys_name} ${sys_ver}，可能遇到兼容性问题"
    fi
    log_info "系统检查通过：${sys_name} ${sys_ver}"
}

# 4. 核心安装逻辑

# 安装基础依赖
install_dependencies() {
    log_info "更新系统包并安装依赖..."
    apt update -qq
    # 使用 -yqq 减少输出干扰，安装必要工具
    apt install -yqq curl wget sudo git socat cron qrencode bc openssl nginx unzip
    log_info "依赖安装完成"
}

# 检查 DNS 解析 (带重试)
check_dns_propagation() {
    local domain=$1
    local max_retries=5
    local retry_count=0
    local server_ip
    
    # 获取本机公网 IP (多接口备份)
    server_ip=$(curl -s4m5 https://api.ip.sb/ip || curl -s4m5 https://ifconfig.me/ip || echo "")
    
    if [[ -z "${server_ip}" ]]; then
        log_error "无法获取本机公网 IP"
        exit 1
    fi
    log_info "本机公网 IP: ${server_ip}"

    log_info "正在验证域名 ${domain} 解析..."
    while [[ $retry_count -lt $max_retries ]]; do
        local domain_ip
        domain_ip=$(dig +short "${domain}" A | head -n1)
        
        if [[ "${domain_ip}" == "${server_ip}" ]]; then
            log_info "域名解析验证成功"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        log_warn "域名解析不匹配 (期望：${server_ip}, 实际：${domain_ip})，重试 ${retry_count}/${max_retries}..."
        sleep 5
    done
    
    log_error "域名解析验证失败，请检查 DNS 设置"
    exit 1
}

# 安装 Xray Core
install_xray() {
    log_info "安装 Xray Core..."
    # 使用官方安装脚本，自动检测最新稳定版
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    if ! systemctl is-active --quiet xray; then
        log_error "Xray 服务安装后未运行"
        exit 1
    fi
    log_info "Xray Core 安装完成"
}

# 配置 Xray
config_xray() {
    local uuid=$1
    local path=$2
    
    log_info "配置 Xray..."
    # 备份原有配置
    [[ -f "${XRAY_CONF_DIR}/config.json" ]] && cp "${XRAY_CONF_DIR}/config.json" "${XRAY_CONF_DIR}/config.json.bak.$(date +%s)"
    
    cat > "${XRAY_CONF_DIR}/config.json" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 44222,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "level": 0,
            "email": "user@example.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${path}"
        }
      }
    }
  ],
  "outbounds": [
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
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
    
    # 修复权限
    chown -R nobody:nogroup "${XRAY_CONF_DIR}"
    chmod 644 "${XRAY_CONF_DIR}/config.json"
    
    # 更新 Geo 文件 (可选，确保路由正常)
    log_info "更新 Geo 数据库..."
    curl -sL -o /tmp/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    curl -sL -o /tmp/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    mv /tmp/geosite.dat /usr/local/share/xray/geosite.dat
    mv /tmp/geoip.dat /usr/local/share/xray/geoip.dat
    
    systemctl daemon-reload
    systemctl restart xray
    log_info "Xray 配置完成"
}

# 安装 SSL 证书 (acme.sh)
install_ssl() {
    local domain=$1
    local email=$2
    
    log_info "安装 acme.sh 并申请证书..."
    curl https://get.acme.sh | sh
    source ~/.bashrc
    
    mkdir -p "${SSL_DIR}"
    
    #  issue 证书
    ~/.acme.sh/acme.sh --issue -d "${domain}" --webroot "${WEB_ROOT}" --accountemail "${email}"
    
    # 安装证书
    ~/.acme.sh/acme.sh --installcert -d "${domain}" \
        --key-file "${SSL_DIR}/${domain}.key" \
        --fullchain-file "${SSL_DIR}/${domain}.fullchain.cer" \
        --reloadcmd "systemctl reload nginx"
    
    # 严格权限保护私钥
    chmod 600 "${SSL_DIR}/${domain}.key"
    chmod 644 "${SSL_DIR}/${domain}.fullchain.cer"
    
    log_info "SSL 证书安装完成"
}

# 配置 Nginx
config_nginx() {
    local domain=$1
    local path=$2
    local ssl_key="${SSL_DIR}/${domain}.key"
    local ssl_cert="${SSL_DIR}/${domain}.fullchain.cer"
    
    log_info "配置 Nginx..."
    
    # 备份默认配置
    [[ -f "${NGINX_CONF_DIR}/nginx.conf" ]] && cp "${NGINX_CONF_DIR}/nginx.conf" "${NGINX_CONF_DIR}/nginx.conf.bak"
    
    cat > "${NGINX_CONF_DIR}/conf.d/${domain}.conf" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    
    # ACME 挑战目录
    location /.well-known/acme-challenge/ {
        root ${WEB_ROOT};
    }
    
    # 强制跳转 HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${domain};
    
    # SSL 配置
    ssl_certificate ${ssl_cert};
    ssl_certificate_key ${ssl_key};
    ssl_protocols TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    
    # 安全头
    add_header Strict-Transport-Security "max-age=63072000" always;
    server_tokens off;
    
    root ${WEB_ROOT};
    index index.html;
    
    # 默认页面
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # gRPC 代理
    location /${path} {
        client_max_body_size 0;
        grpc_pass grpc://127.0.0.1:44222;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$host;
    }
}
EOF

    # 测试配置并重启
    if ! nginx -t; then
        log_error "Nginx 配置测试失败"
        exit 1
    fi
    
    systemctl enable nginx
    systemctl restart nginx
    log_info "Nginx 配置完成"
}

# 系统内核优化
optimize_system() {
    log_info "优化系统网络参数..."
    cat > /etc/sysctl.d/99-xray-optimize.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 5000
EOF
    sysctl --system
    log_info "系统优化完成 (BBR 已启用)"
}

# 生成客户端配置
generate_client_config() {
    local domain=$1
    local uuid=$2
    local path=$3
    
    log_info "生成客户端配置..."
    
    local vless_link="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=grpc&serviceName=${path}&sni=${domain}"
    
    echo -e "\n${GREEN}====================================================================${PLAIN}"
    echo -e "${GREEN} 部署成功！配置信息如下：${PLAIN}"
    echo -e "${GREEN}====================================================================${PLAIN}\n"
    echo -e "域名 (Domain): ${domain}"
    echo -e "路径 (Path): ${path}"
    echo -e "用户 ID (UUID): ${uuid}"
    echo -e "端口 (Port): 443"
    echo -e "协议 (Protocol): VLESS + gRPC + TLS 1.3"
    echo -e "\n订阅链接 (VLESS Link):"
    echo -e "${YELLOW}${vless_link}${PLAIN}\n"
    echo -e "二维码:"
    qrencode -t UTF8 -m 2 "${vless_link}"
    echo -e "\n${GREEN}====================================================================${PLAIN}"
    echo -e "${YELLOW}提示：请确保本地客户端时间与服务器时间同步 (误差<90 秒)${PLAIN}"
    echo -e "${GREEN}====================================================================${PLAIN}\n"
}

# 5. 主执行流程
main() {
    check_root
    check_system
    
    log_info "开始部署 Xray 安全后端服务 (v${SCRIPT_VERSION})"
    
    # 用户输入
    echo -n "请输入已解析到本机的域名 (例如：example.com): "
    read -r PROXY_DOMAIN
    echo -n "请输入用于申请证书的邮箱 (例如：admin@example.com): "
    read -r CERT_EMAIL
    
    if [[ -z "${PROXY_DOMAIN}" || -z "${CERT_EMAIL}" ]]; then
        log_error "域名或邮箱不能为空"
        exit 1
    fi
    
    # 生成随机配置
    readonly UUID=$(cat /proc/sys/kernel/random/uuid)
    readonly XRAY_PATH=$(openssl rand -hex 4)
    
    # 执行步骤
    install_dependencies
    check_dns_propagation "${PROXY_DOMAIN}"
    
    # 先启动 Nginx 以便申请证书
    systemctl enable nginx
    systemctl start nginx
    
    install_ssl "${PROXY_DOMAIN}" "${CERT_EMAIL}"
    install_xray
    config_xray "${UUID}" "${XRAY_PATH}"
    config_nginx "${PROXY_DOMAIN}" "${XRAY_PATH}"
    optimize_system
    
    # 最终验证
    sleep 2
    if systemctl is-active --quiet xray && systemctl is-active --quiet nginx; then
        generate_client_config "${PROXY_DOMAIN}" "${UUID}" "${XRAY_PATH}"
        log_info "所有服务运行正常"
    else
        log_error "服务启动检查失败，请检查 systemctl status xray/nginx"
        exit 1
    fi
}

# 启动
main "$@"
