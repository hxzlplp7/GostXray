# GOST v3 + Xray 任意门 中转管理脚本

[English](README_EN.md)

## 🚀 快速开始

### Linux VPS (Root 环境)

```bash
# 下载脚本
wget -O gost.sh https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost.sh

# 添加执行权限并运行
chmod +x gost.sh && ./gost.sh
```

安装完成后，可以在任意位置输入 `gostxray` 进入管理菜单！

### Serv00 / HostUno (FreeBSD 非 Root 环境)

```bash
# 下载 Serv00 专用版本
curl -sL https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost-serv00.sh -o gost.sh

# 运行
chmod +x gost.sh && ./gost.sh
```

> ⚠️ **Serv00/HostUno 版本特点:**
> - 专为 FreeBSD 非 root 环境设计
> - 安装到用户目录 `~/.gost/`
> - 使用进程管理替代 systemd
> - **Devil 端口管理**: 自动使用 `devil` 命令添加和管理端口
> - **端口连通性检查**: 添加规则前自动检测目标端口是否可达
> - **协议类型识别**: 自动识别 TCP/UDP 协议类型并添加相应端口

### Serv00 / HostUno + MrChrootBSD (伪 Root 环境) 🆕

通过 MrChrootBSD 获取伪 root 权限后，可以在 chroot 环境中以 root 身份运行 GostXray：

```bash
# 方式一：使用一键安装脚本（推荐）
curl -sL https://raw.githubusercontent.com/hxzlplp7/MrChrootBSD/main/setup-mrchroot.sh -o setup.sh
chmod +x setup.sh && ./setup.sh

# 安装完成后使用快捷命令
source ~/.profile
gostxray-root  # 在 chroot root 环境中运行 GostXray
```

```bash
# 方式二：手动安装
# 1. 先安装 MrChrootBSD 并配置 chroot 环境
# 2. 下载 Root 版本脚本到 chroot 环境
curl -sL https://raw.githubusercontent.com/hxzlplp7/GostXray/main/gost-root.sh -o ~/chroot/root/gost-root.sh

# 3. 进入 chroot 并运行
./mrchroot ~/chroot /root/gost-root.sh
```

> 🔥 **MrChrootBSD Root 版本特点:**
> - 在 chroot 环境中以 **root 权限**运行
> - **无需 devil 端口管理**，可直接绑定任意端口
> - 支持安装到系统目录 `/usr/local/bin/`
> - 可使用 pkg 安装额外依赖
> - **适合需要更多权限的高级用法**

## ✨ 功能特性

| 功能 | 说明 |
|------|------|
| **GOST v3** | 适配最新 GOST v3，支持 TCP+UDP 双协议转发 |
| **Xray 任意门** | 集成 dokodemo-door，实现透明代理中转 |
| **快捷命令** | 安装后输入 `gostxray` 即可进入管理菜单 |
| **协议解析** | 自动识别并解析 9 种主流代理协议链接 |
| **中转链接生成** | 自动生成中转后的节点链接 |
| **批量添加** | 支持批量导入多个节点链接 |
| **端口管理** | 随机分配 / 范围分配 / 手动指定 |

## 📋 支持的协议

| 协议 | 链接格式 | 解析 | 生成链接 |
|------|----------|------|----------|
| VLESS | `vless://...` | ✅ | ✅ |
| VMess | `vmess://...` | ✅ | ✅ |
| Trojan | `trojan://...` | ✅ | ✅ |
| Shadowsocks | `ss://...` | ✅ | ✅ |
| Hysteria2 | `hysteria2://...` / `hy2://...` | ✅ | ✅ |
| TUIC | `tuic://...` | ✅ | ✅ |
| SOCKS5 | `socks://...` / `socks5://...` | ✅ | ✅ |
| HTTP | `http://...` | ✅ | ✅ |

## 🎛️ 菜单功能

```
========================================================
      GOST v3 + Xray 任意门 中转管理脚本 [v3.1.0]
========================================================
 支持: VLESS VMess Trojan SS Hy2 TUIC SOCKS HTTP
--------------------------------------------------------
 1.  安装 GOST v3          2.  安装 Xray
 3.  卸载 GOST v3          4.  卸载 Xray
--------------------------------------------------------
 5.  启动 GOST v3          6.  停止 GOST v3
 7.  重启 GOST v3          8.  查看日志
--------------------------------------------------------
 9.  启动 Xray             10. 停止 Xray
 11. 重启 Xray             12. 查看日志
--------------------------------------------------------
 13. 添加中转配置          14. 批量添加中转
 15. 查看当前配置          16. 删除配置
--------------------------------------------------------
 17. 解析节点链接 (测试)   18. 安装快捷命令
--------------------------------------------------------
 0.  退出脚本
========================================================
```

## 📝 使用示例

### 单个节点中转

1. 运行脚本: `gost` 或 `./gost3-xray.sh`
2. 选择 `13` 添加中转配置
3. 选择中转方式 (GOST 或 Xray)
4. 粘贴节点链接
5. 选择端口分配方式
6. 复制生成的中转链接使用

### 批量添加节点

1. 选择 `14` 批量添加中转
2. 每行粘贴一个节点链接，空行结束
3. 选择中转方式和端口分配
4. 脚本自动添加并生成所有中转链接

### 端口分配选项

```
[1] 随机选择端口 (10000-65535)
[2] 指定端口范围自动分配
[3] 手动指定端口
```

## 🔧 配置文件

| 文件 | 路径 | 说明 |
|------|------|------|
| GOST 配置 | `/etc/gost3/config.yaml` | GOST v3 YAML 配置 |
| Xray 配置 | `/etc/xray/config.json` | Xray JSON 配置 |
| 原始记录 | `/etc/gost3/rawconf` | 中转配置记录 |
| 端口记录 | `/etc/gost3/ports.conf` | 已使用端口 |
| 快捷命令 | `/usr/local/bin/gost` | 快捷启动脚本 |

## 🌐 使用场景

### 线路优化中转
```
用户 → 国内中转机 (GOST/Xray) → 国外节点
```

### 多层中转
```
用户 → 入口机 → 中转机 → 落地机
```

### 负载均衡
配置多条中转规则指向同一目标的不同端口

## ⚙️ 系统要求

- Linux (Debian/Ubuntu/CentOS)
- Root 权限
- 开放相应防火墙端口

## 📊 服务状态

脚本启动时自动显示:
- GOST v3 运行状态
- Xray 运行状态
- 中转配置数量
- 本机公网 IP

## 🔄 更新日志

### v3.2.0
- ✅ Serv00/HostUno 版本增强
- ✅ 添加 Devil 端口管理 (自动添加/检查系统端口)
- ✅ 添加端口连通性检查 (tcping 检测目标端口)
- ✅ 添加协议类型自动识别 (TCP/UDP)
- ✅ 从 x-ui 项目移植的任意门功能整合

### v3.1.0
- ✅ 添加快捷命令 `gost` 支持
- ✅ 添加批量导入功能
- ✅ 添加服务状态显示
- ✅ 添加日志查看功能
- ✅ 优化协议解析 (支持更多参数)
- ✅ 优化用户交互体验
- ✅ 添加安装确认和错误处理

### v3.0.0
- 全面适配 GOST v3
- 集成 Xray 任意门
- 支持 8 种协议解析
- 自动生成中转链接

## 🙏 致谢

- [GOST](https://github.com/go-gost/gost) - GO Simple Tunnel
- [Xray-core](https://github.com/XTLS/Xray-core) - Xray
- [Multi-EasyGost](https://github.com/KANIKIG/Multi-EasyGost) - 原版脚本

## 📄 License

MIT License
