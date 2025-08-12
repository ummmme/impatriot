# impatriot
科学上网，理性爱国

## Catalog
### 404
首页HTML

### v2ray
V2Ray一键安装脚本

#### WS+TLS+WARP模式
增加 Warp 组件，默认配置openAI 相关域名进行分流， 若有其他类似被封禁IP 需要解开的需求也可使用
![warp](https://github.com/ummmme/impatriot/blob/master/assets/img/warp.png)

### speedtest
部分VPS测速脚本

## Preparations & Requirements
```bash
apt update && apt -y upgrade && apt install -y sudo curl
```

## Quick Start（Recommended）
```bash
# Nginx + Vless + Grpc + TLS1.3， 系统要求：Debian12、Ubuntu22.04及以上
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
- 鉴于 Vmess + Websocket + tls 方案的 Tls In Tls 特征明显，默认建议使用 vless + grpc 方案。

## License
MIT License
