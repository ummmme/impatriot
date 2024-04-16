# impatriot
科学上网，理性爱国

## Catalog
### 404
首页HTML

### v2ray
V2Ray一键安装脚本

#### WS+TLS+WARP模式
增加 Warp 进行 chatGPT 流量分流解决1020错误(需要手动同意cloudfare隐私协议)
![warp](https://github.com/ummmme/impatriot/blob/master/assets/img/warp.png)

### speedtest
部分VPS测速脚本

## Preparations & Requirements
```bash
apt update && apt -y upgrade 
apt install -y sudo curl
```

## Quick Start（Recommended）
```bash
# 默认模式
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls/install.sh)

# openai 兼容 
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls_warp/install.sh)
```

## Note
- 仅支持Debian类系统，含Ubuntu及其衍生版
- 切勿在安装了$$的服务器上使用此脚本，切记切记

## License
MIT License
