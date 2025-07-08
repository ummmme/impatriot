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
# 默认模式（全自动模式，仅支持Debian10、Ubuntu20.04以下）
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls/install.sh)

# openai 兼容 ，仅支持Debian10、Ubuntu20.04以下
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls_warp/install.sh)

# openai 兼容 ，仅支持Debian12+、Ubuntu22.04+
bash <(curl -f -L -sS https://raw.githubusercontent.com/ummmme/impatriot/master/v2ray/ws_tls_warp/install.sh)
```

## Note
- 仅支持Debian类系统，含Ubuntu及其衍生版
- Debian 12+，Ubuntu22.04+ 系统请使用 `install_new.sh`

## License
MIT License
