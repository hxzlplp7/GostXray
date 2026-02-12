# Multi-EasyGost v3 使用指南

## 感谢

1. 感谢 [@go-gost](https://github.com/go-gost) 开发的 [GOST v3](https://github.com/go-gost/gost) 隧道程序
2. 官方文档: [https://gost.run](https://gost.run)
3. 感谢 [@KANIKIG](https://github.com/KANIKIG/Multi-EasyGost) 提供的原版脚本

## 简介

基于 GOST v3 重写的一键中转管理脚本，使用 **YAML 配置格式**。

### v2 vs v3 主要区别

| 特性 | v2 | v3 |
|------|----|----|
| 配置格式 | JSON | YAML |
| 下载源 | `ginuerzh/gost` | `go-gost/gost` |
| 文档 | docs.ginuerzh.xyz | **gost.run** |

## 快速开始

### Linux VPS (Root 环境)

```bash
# 下载脚本
wget -O gost.sh https://raw.githubusercontent.com/hxzlplp7/easygostv3/main/gost.sh

# 运行
chmod +x gost.sh && ./gost.sh
```

### 国内 VPS (无法访问 GitHub)

```bash
# 通过代理下载脚本（任选一个可用的代理）
wget -O gost.sh https://gh-proxy.com/https://raw.githubusercontent.com/hxzlplp7/easygostv3/main/gost.sh
# 备选代理1:
# wget -O gost.sh https://ghfast.top/https://raw.githubusercontent.com/hxzlplp7/easygostv3/main/gost.sh
# 备选代理2:
# wget -O gost.sh https://ghproxy.net/https://raw.githubusercontent.com/hxzlplp7/easygostv3/main/gost.sh

# 运行（安装 GOST 时选择"代理加速"下载源）
chmod +x gost.sh && ./gost.sh
```

### Serv00 / HostUno (FreeBSD 非 Root)

```bash
# 下载脚本
curl -sL https://raw.githubusercontent.com/hxzlplp7/easygostv3/main/gost-serv00.sh -o gost.sh

# 运行
chmod +x gost.sh && ./gost.sh
```

> ⚠️ **Serv00 版本特点:**
>
> - 安装到用户目录 `~/.gost3/`
> - 使用进程管理替代 systemd
> - **Devil 端口管理**: 自动添加端口

## 功能

### 基础功能

- systemd 服务管理
- 多条转发规则同时生效
- 机器重启后转发不失效

### 传输类型

- TCP + UDP 不加密转发
- TLS 隧道加密/解密
- WS 隧道加密/解密
- WSS 隧道加密/解密

### 代理服务

- Shadowsocks 代理
- SOCKS5 代理
- HTTP 代理

### 高级功能

- 多落地均衡负载 (round/random/fifo)
- CDN 自选节点转发
- 自定义 TLS 证书 (ACME 一键申请)
- 定时重启任务

## 菜单

```
==========================================
 1. 安装 GOST v3       2. 卸载 GOST v3
==========================================
 3. 启动 GOST          4. 停止 GOST
 5. 重启 GOST
==========================================
 6. 新增转发配置       7. 查看现有配置
 8. 删除一则配置
==========================================
 9. 定时重启配置      10. TLS 证书配置
==========================================
 0. 退出脚本
==========================================
```

## 配置示例

### TCP+UDP 不加密转发 (YAML)

```yaml
services:
  - name: relay-tcp-0
    addr: ":8080"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "192.168.1.1:80"
  - name: relay-udp-0
    addr: ":8080"
    handler:
      type: udp
    listener:
      type: udp
    forwarder:
      nodes:
        - name: target
          addr: "192.168.1.1:80"
chains: []
```

### TLS 隧道加密 (中转机)

```yaml
services:
  - name: relay-0
    addr: ":8080"
    handler:
      type: tcp
      chain: chain-0
    listener:
      type: tcp
chains:
  - name: chain-0
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: "落地机IP:8443"
            connector:
              type: relay
            dialer:
              type: tls
```

### TLS 解密 (落地机)

```yaml
services:
  - name: relay-0
    addr: ":8443"
    handler:
      type: relay
    listener:
      type: tls
      metadata:
        certFile: /root/gost_cert/cert.pem
        keyFile: /root/gost_cert/key.pem
    forwarder:
      nodes:
        - name: target
          addr: "127.0.0.1:代理端口"
chains: []
```

### 均衡负载

```yaml
services:
  - name: peer-0
    addr: ":8080"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target-0
          addr: "192.168.1.1:80"
        - name: target-1
          addr: "192.168.1.2:80"
      selector:
        strategy: round  # round/random/fifo
```

## 文件路径

| 文件 | 路径 |
|------|------|
| GOST 二进制 | `/usr/bin/gost` |
| 配置文件 | `/etc/gost3/config.yaml` |
| 原始配置 | `/etc/gost3/rawconf` |
| 服务文件 | `/usr/lib/systemd/system/gost.service` |
| 证书目录 | `~/gost_cert/` |

## 常用命令

```bash
# 查看服务状态
systemctl status gost

# 查看日志
journalctl -u gost -f

# 手动重启
systemctl restart gost

# 查看配置
cat /etc/gost3/config.yaml
```

## License

MIT License
