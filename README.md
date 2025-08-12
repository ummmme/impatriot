# impatriot
科学上网，从我做起

## Catalog
### 404
静态HTML，共3个模板

### v2ray
V2Ray一键安装脚本

### xray
xray一键安装脚本

### speedtest
部分VPS测速脚本

## Preparations & Requirements
```bash
apt update -qq && apt -yqq upgrade && apt install -yqq sudo curl
```

## Quick Start（Recommended）
Nginx + Vless + gRPC + TLS1.3， 系统要求：Debian12、Ubuntu22.04及以上
```bash
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/xray/vless_grpc.sh)
```

## Quick Start（Legency）
```bash
# Nginx + Vmess + WebSocket + TLS1.3，仅支持Debian10、Ubuntu20.04以下
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls/install.sh)

# Nginx + Vmess + WebSocket + TLS1.3，系统要求：Debian12、Ubuntu22.04及以上
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls/new.sh)
```

## Note
- 仅支持Debian类系统，含Ubuntu及其衍生版
- 鉴于 Vmess + Websocket + tls 方案的 TLS In TLS 特征明显，默认建议使用 vless + grpc 方案。

## License
MIT License
