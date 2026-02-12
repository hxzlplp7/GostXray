#!/bin/bash
# Multi-EasyGost v3 - GOST v3 一键安装配置脚本
# 基于 KANIKIG/Multi-EasyGost 重写，适配 GOST v3 (YAML 配置)
# 项目地址: https://github.com/go-gost/gost
# 文档: https://gost.run

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Yellow_font_prefix="\033[33m"
Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Warning="${Yellow_font_prefix}[警告]${Font_color_suffix}"

shell_version="3.0.0"
gost_version="3.0.0"

# 目录配置
GOST_DIR="/etc/gost3"
GOST_BIN="/usr/bin/gost"
GOST_CONF="$GOST_DIR/config.yaml"
RAW_CONF="$GOST_DIR/rawconf"
CERT_DIR="$HOME/gost_cert"
SERVICE_FILE="/usr/lib/systemd/system/gost.service"

# ==================== 系统检测 ====================
check_root() {
    [[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号，请使用 ${Green_background_prefix}sudo su${Font_color_suffix} 获取ROOT权限" && exit 1
}

check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    fi
    
    bit=$(uname -m)
    case "$bit" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        armv7*) ARCH="armv7" ;;
        armv6*) ARCH="armv6" ;;
        armv5*) ARCH="armv5" ;;
        *) 
            echo -e "${Warning} 未识别的架构: $bit"
            read -p "请输入架构 (amd64/arm64/386/armv7/armv6/armv5): " ARCH
            ;;
    esac
}

install_deps() {
    if [[ ${release} == "centos" ]]; then
        yum install -y wget curl tar gzip 2>/dev/null
    else
        apt-get update 2>/dev/null
        apt-get install -y wget curl tar gzip 2>/dev/null
    fi
}

# ==================== 安装 GOST ====================
install_gost() {
    check_root
    check_sys
    install_deps
    
    echo -e "${Info} 开始安装 GOST v3..."
    
    # 清理旧版本
    systemctl stop gost 2>/dev/null
    rm -rf "$GOST_BIN" "$GOST_DIR" "$SERVICE_FILE"
    
    # 创建目录
    mkdir -p "$GOST_DIR"
    
    # 下载 GOST v3
    local github_url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_linux_${ARCH}.tar.gz"
    
    echo -e ""
    echo -e "请选择下载源:"
    echo -e "[1] GitHub 直连 (默认)"
    echo -e "[2] gh-proxy.com 代理加速"
    echo -e "[3] ghfast.top 代理加速"
    echo -e "[4] ghproxy.net 代理加速"
    read -p "请选择 [1-4]: " dl_source
    
    local url
    case "$dl_source" in
        2) url="https://gh-proxy.com/${github_url}" ;;
        3) url="https://ghfast.top/${github_url}" ;;
        4) url="https://ghproxy.net/${github_url}" ;;
        *) url="${github_url}" ;;
    esac
    echo -e "${Info} 下载地址: $url"
    
    cd /tmp
    if command -v wget &>/dev/null; then
        wget -q --show-progress "$url" -O gost.tar.gz
    elif command -v curl &>/dev/null; then
        curl -L "$url" -o gost.tar.gz
    else
        echo -e "${Error} 请安装 wget 或 curl"
        return 1
    fi
    
    if [[ ! -f gost.tar.gz ]]; then
        echo -e "${Error} 下载失败"
        return 1
    fi
    
    tar -xzf gost.tar.gz
    mv gost "$GOST_BIN"
    chmod +x "$GOST_BIN"
    rm -f gost.tar.gz
    
    # 初始化配置
    cat > "$GOST_CONF" << 'EOF'
services: []
chains: []
EOF
    
    touch "$RAW_CONF"
    
    # 创建 systemd 服务
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=GOST v3 Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=$GOST_BIN -C $GOST_CONF
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable gost >/dev/null 2>&1
    
    echo -e "${Info} GOST v3 安装完成!"
    echo -e "${Info} 二进制: $GOST_BIN"
    echo -e "${Info} 配置文件: $GOST_CONF"
    echo -e "${Info} 服务状态: systemctl status gost"
}

# ==================== 卸载 GOST ====================
uninstall_gost() {
    check_root
    echo -e "${Warning} 确定要卸载 GOST? [y/N]"
    read -r confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    systemctl stop gost 2>/dev/null
    systemctl disable gost 2>/dev/null
    rm -f "$GOST_BIN" "$SERVICE_FILE"
    rm -rf "$GOST_DIR"
    systemctl daemon-reload
    
    echo -e "${Info} GOST 已卸载"
}

# ==================== 服务管理 ====================
start_gost() {
    systemctl start gost
    sleep 1
    if systemctl is-active gost >/dev/null 2>&1; then
        echo -e "${Info} GOST 启动成功"
    else
        echo -e "${Error} GOST 启动失败"
        journalctl -u gost --no-pager -n 20
    fi
}

stop_gost() {
    systemctl stop gost
    echo -e "${Info} GOST 已停止"
}

restart_gost() {
    rebuild_config
    systemctl restart gost
    sleep 1
    if systemctl is-active gost >/dev/null 2>&1; then
        echo -e "${Info} GOST 重启成功"
    else
        echo -e "${Error} GOST 重启失败"
        journalctl -u gost --no-pager -n 20
    fi
}

# ==================== 配置管理 ====================

# 读取转发类型
read_protocol() {
    echo -e ""
    echo -e "请问您要设置哪种功能: "
    echo -e "-----------------------------------"
    echo -e "[1] TCP+UDP 流量转发 (不加密)"
    echo -e "说明: 一般设置在国内中转机上"
    echo -e "-----------------------------------"
    echo -e "[2] 加密隧道流量转发"
    echo -e "说明: 用于转发原本加密等级较低的流量，一般设置在国内中转机上"
    echo -e "     选择此协议意味着你还有一台机器用于接收加密流量"
    echo -e "-----------------------------------"
    echo -e "[3] 解密由 GOST 传输的流量并转发"
    echo -e "说明: 对于经由 GOST 加密中转的流量，通过此选项进行解密并转发"
    echo -e "      一般设置在用于接收中转流量的国外机器上"
    echo -e "-----------------------------------"
    echo -e "[4] 一键安装 SS/SOCKS5/HTTP 代理"
    echo -e "说明: 使用 GOST 内置的代理协议，轻量且易于管理"
    echo -e "-----------------------------------"
    echo -e "[5] 进阶：多落地均衡负载"
    echo -e "说明: 支持各种加密方式的简单均衡负载"
    echo -e "-----------------------------------"
    echo -e "[6] 进阶：转发 CDN 自选节点"
    echo -e "说明: 只需在中转机设置"
    echo -e "-----------------------------------"
    read -p "请选择: " num_protocol

    case "$num_protocol" in
        1) flag_a="nonencrypt" ;;
        2) encrypt_menu ;;
        3) decrypt_menu ;;
        4) proxy_menu ;;
        5) peer_menu ;;
        6) cdn_menu ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 加密隧道菜单
encrypt_menu() {
    echo -e ""
    echo -e "请问您要设置的加密传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] TLS 隧道"
    echo -e "[2] WS 隧道"
    echo -e "[3] WSS 隧道"
    echo -e "注意: 同一则转发，中转与落地传输类型必须对应！"
    echo -e "-----------------------------------"
    read -p "请选择: " num_encrypt

    case "$num_encrypt" in
        1) 
            flag_a="encrypttls"
            echo -e "${Warning} 落地机是否开启了自定义 TLS 证书？[y/n]"
            read -r is_cert
            ;;
        2) flag_a="encryptws" ;;
        3) 
            flag_a="encryptwss"
            echo -e "${Warning} 落地机是否开启了自定义 TLS 证书？[y/n]"
            read -r is_cert
            ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 解密菜单
decrypt_menu() {
    echo -e ""
    echo -e "请问您要设置的解密传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] TLS"
    echo -e "[2] WS"
    echo -e "[3] WSS"
    echo -e "-----------------------------------"
    read -p "请选择: " num_decrypt

    case "$num_decrypt" in
        1) flag_a="decrypttls" ;;
        2) flag_a="decryptws" ;;
        3) flag_a="decryptwss" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 代理菜单
proxy_menu() {
    echo -e ""
    echo -e "请问您要设置的代理类型: "
    echo -e "-----------------------------------"
    echo -e "[1] Shadowsocks"
    echo -e "[2] SOCKS5"
    echo -e "[3] HTTP"
    echo -e "-----------------------------------"
    read -p "请选择: " num_proxy

    case "$num_proxy" in
        1) flag_a="ss" ;;
        2) flag_a="socks" ;;
        3) flag_a="http" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 均衡负载菜单
peer_menu() {
    echo -e ""
    echo -e "请问您要设置的均衡负载传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] 不加密转发"
    echo -e "[2] TLS 隧道"
    echo -e "[3] WS 隧道"
    echo -e "[4] WSS 隧道"
    echo -e "-----------------------------------"
    read -p "请选择: " num_peer

    case "$num_peer" in
        1) flag_a="peerno" ;;
        2) flag_a="peertls" ;;
        3) flag_a="peerws" ;;
        4) flag_a="peerwss" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# CDN 菜单
cdn_menu() {
    echo -e ""
    echo -e "请问您要设置的 CDN 传输类型: "
    echo -e "-----------------------------------"
    echo -e "[1] 不加密转发"
    echo -e "[2] WS 隧道"
    echo -e "[3] WSS 隧道"
    echo -e "-----------------------------------"
    read -p "请选择: " num_cdn

    case "$num_cdn" in
        1) flag_a="cdnno" ;;
        2) flag_a="cdnws" ;;
        3) flag_a="cdnwss" ;;
        *) echo -e "${Error} 无效选择"; exit 1 ;;
    esac
}

# 读取本地端口
read_s_port() {
    if [[ "$flag_a" == "ss" ]]; then
        read -p "请输入 SS 密码: " flag_b
    elif [[ "$flag_a" == "socks" ]]; then
        read -p "请输入 SOCKS5 密码: " flag_b
    elif [[ "$flag_a" == "http" ]]; then
        read -p "请输入 HTTP 密码: " flag_b
    else
        echo -e ""
        read -p "请输入本地监听端口: " flag_b
    fi
}

# 读取目标地址
read_d_ip() {
    if [[ "$flag_a" == "ss" ]]; then
        echo -e ""
        echo -e "请选择 SS 加密方式: "
        echo -e "-----------------------------------"
        echo -e "[1] aes-256-gcm"
        echo -e "[2] aes-128-gcm"
        echo -e "[3] chacha20-ietf-poly1305"
        echo -e "[4] xchacha20-ietf-poly1305"
        echo -e "-----------------------------------"
        read -p "请选择: " ss_encrypt
        case "$ss_encrypt" in
            1) flag_c="aes-256-gcm" ;;
            2) flag_c="aes-128-gcm" ;;
            3) flag_c="chacha20-ietf-poly1305" ;;
            4) flag_c="xchacha20-ietf-poly1305" ;;
            *) flag_c="aes-256-gcm" ;;
        esac
    elif [[ "$flag_a" == "socks" ]]; then
        read -p "请输入 SOCKS5 用户名: " flag_c
    elif [[ "$flag_a" == "http" ]]; then
        read -p "请输入 HTTP 用户名: " flag_c
    elif [[ "$flag_a" == "peer"* ]]; then
        echo -e ""
        read -p "请输入落地列表文件名 (不含后缀): " flag_c
        touch "$GOST_DIR/${flag_c}.txt"
        echo -e "${Info} 请依次输入落地 IP 和端口"
        while true; do
            read -p "落地 IP: " peer_ip
            read -p "落地端口: " peer_port
            echo "$peer_ip:$peer_port" >> "$GOST_DIR/${flag_c}.txt"
            read -p "是否继续添加? [Y/n]: " add_more
            [[ ${add_more} =~ ^[Nn]$ ]] && break
        done
        echo -e "${Info} 落地列表已保存到 $GOST_DIR/${flag_c}.txt"
    elif [[ "$flag_a" == "cdn"* ]]; then
        read -p "请输入自选 CDN IP: " flag_c
        echo -e "[1] 80  [2] 443  [3] 自定义"
        read -p "请选择端口: " cdn_port_choice
        case "$cdn_port_choice" in
            1) flag_c="$flag_c:80" ;;
            2) flag_c="$flag_c:443" ;;
            3) read -p "自定义端口: " custom_port; flag_c="$flag_c:$custom_port" ;;
        esac
    else
        echo -e ""
        if [[ ${is_cert} =~ ^[Yy]$ ]]; then
            echo -e "${Warning} 落地机开启自定义 TLS 证书，请填写域名"
        fi
        read -p "请输入目标 IP/域名: " flag_c
    fi
}

# 读取目标端口
read_d_port() {
    if [[ "$flag_a" == "ss" ]]; then
        read -p "请输入 SS 服务端口: " flag_d
    elif [[ "$flag_a" == "socks" ]]; then
        read -p "请输入 SOCKS5 服务端口: " flag_d
    elif [[ "$flag_a" == "http" ]]; then
        read -p "请输入 HTTP 服务端口: " flag_d
    elif [[ "$flag_a" == "peer"* ]]; then
        echo -e ""
        echo -e "请选择均衡负载策略: "
        echo -e "[1] round - 轮询"
        echo -e "[2] random - 随机"
        echo -e "[3] fifo - 优先级"
        read -p "请选择: " num_strategy
        case "$num_strategy" in
            1) flag_d="round" ;;
            2) flag_d="random" ;;
            3) flag_d="fifo" ;;
            *) flag_d="round" ;;
        esac
    elif [[ "$flag_a" == "cdn"* ]]; then
        read -p "请输入 Host 头: " flag_d
    else
        read -p "请输入目标端口: " flag_d
        if [[ ${is_cert} =~ ^[Yy]$ ]]; then
            flag_d="$flag_d?secure=true"
        fi
    fi
}

# 保存原始配置
write_rawconf() {
    echo "$flag_a/$flag_b#$flag_c#$flag_d" >> "$RAW_CONF"
}

# 解析原始配置
parse_rawconf() {
    local line="$1"
    is_encrypt="${line%%/*}"
    local rest="${line#*/}"
    s_port="${rest%%#*}"
    rest="${rest#*#}"
    d_ip="${rest%%#*}"
    d_port="${rest#*#}"
}

# 重建配置文件
rebuild_config() {
    # 开始 YAML
    echo "services:" > "$GOST_CONF"
    local chains_content=""
    local service_idx=0
    
    [[ ! -f "$RAW_CONF" ]] && echo "chains: []" >> "$GOST_CONF" && return
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        parse_rawconf "$line"
        
        case "$is_encrypt" in
            nonencrypt)
                # TCP+UDP 不加密转发
                cat >> "$GOST_CONF" << EOF
  - name: relay-tcp-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${d_ip}:${d_port}"
  - name: relay-udp-${service_idx}
    addr: ":${s_port}"
    handler:
      type: udp
    listener:
      type: udp
    forwarder:
      nodes:
        - name: target
          addr: "${d_ip}:${d_port}"
EOF
                ;;
            encrypttls|encryptws|encryptwss)
                # 加密隧道
                local dialer_type="${is_encrypt#encrypt}"
                local secure_opt=""
                [[ "$d_port" == *"secure=true"* ]] && secure_opt="
        metadata:
          serverName: ${d_ip}"
                d_port="${d_port%%\?*}"
                
                cat >> "$GOST_CONF" << EOF
  - name: relay-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
      chain: chain-${service_idx}
    listener:
      type: tcp
  - name: relay-udp-${service_idx}
    addr: ":${s_port}"
    handler:
      type: udp
      chain: chain-${service_idx}
    listener:
      type: udp
EOF
                chains_content+="
  - name: chain-${service_idx}
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: \"${d_ip}:${d_port}\"
            connector:
              type: relay
            dialer:
              type: ${dialer_type}${secure_opt}"
                ;;
            decrypttls|decryptws|decryptwss)
                # 解密转发
                local listener_type="${is_encrypt#decrypt}"
                local cert_opts=""
                if [[ -d "$CERT_DIR" ]]; then
                    cert_opts="
      metadata:
        certFile: ${CERT_DIR}/cert.pem
        keyFile: ${CERT_DIR}/key.pem"
                fi
                
                cat >> "$GOST_CONF" << EOF
  - name: relay-${service_idx}
    addr: ":${s_port}"
    handler:
      type: relay
    listener:
      type: ${listener_type}${cert_opts}
    forwarder:
      nodes:
        - name: target
          addr: "${d_ip}:${d_port}"
EOF
                ;;
            ss)
                # Shadowsocks 代理
                cat >> "$GOST_CONF" << EOF
  - name: ss-${service_idx}
    addr: ":${d_port}"
    handler:
      type: ss
      auth:
        username: "${d_ip}"
        password: "${s_port}"
    listener:
      type: tcp
EOF
                ;;
            socks)
                # SOCKS5 代理
                cat >> "$GOST_CONF" << EOF
  - name: socks-${service_idx}
    addr: ":${d_port}"
    handler:
      type: socks5
      auth:
        username: "${d_ip}"
        password: "${s_port}"
    listener:
      type: tcp
EOF
                ;;
            http)
                # HTTP 代理
                cat >> "$GOST_CONF" << EOF
  - name: http-${service_idx}
    addr: ":${d_port}"
    handler:
      type: http
      auth:
        username: "${d_ip}"
        password: "${s_port}"
    listener:
      type: tcp
EOF
                ;;
            peerno|peertls|peerws|peerwss)
                # 均衡负载
                local peer_file="$GOST_DIR/${d_ip}.txt"
                local nodes=""
                local node_idx=0
                if [[ -f "$peer_file" ]]; then
                    while IFS= read -r peer_line; do
                        nodes+="
        - name: target-${node_idx}
          addr: \"${peer_line}\""
                        ((node_idx++))
                    done < "$peer_file"
                fi
                
                if [[ "$is_encrypt" == "peerno" ]]; then
                    cat >> "$GOST_CONF" << EOF
  - name: peer-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:${nodes}
      selector:
        strategy: ${d_port}
EOF
                else
                    local dialer_type="${is_encrypt#peer}"
                    cat >> "$GOST_CONF" << EOF
  - name: peer-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
      chain: chain-peer-${service_idx}
    listener:
      type: tcp
EOF
                    chains_content+="
  - name: chain-peer-${service_idx}
    hops:
      - name: hop-0
        nodes:${nodes}
        selector:
          strategy: ${d_port}"
                fi
                ;;
            cdnno|cdnws|cdnwss)
                # CDN 转发
                local cdn_addr="${d_ip}"
                local host_header="${d_port}"
                
                if [[ "$is_encrypt" == "cdnno" ]]; then
                    cat >> "$GOST_CONF" << EOF
  - name: cdn-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${cdn_addr}"
          http:
            host: "${host_header}"
EOF
                else
                    local dialer_type="${is_encrypt#cdn}"
                    cat >> "$GOST_CONF" << EOF
  - name: cdn-${service_idx}
    addr: ":${s_port}"
    handler:
      type: tcp
      chain: chain-cdn-${service_idx}
    listener:
      type: tcp
EOF
                    chains_content+="
  - name: chain-cdn-${service_idx}
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: \"${cdn_addr}\"
            connector:
              type: relay
            dialer:
              type: ${dialer_type}
              metadata:
                host: \"${host_header}\""
                fi
                ;;
        esac
        
        ((service_idx++))
    done < "$RAW_CONF"
    
    # 添加 chains
    if [[ -n "$chains_content" ]]; then
        echo "chains:$chains_content" >> "$GOST_CONF"
    else
        echo "chains: []" >> "$GOST_CONF"
    fi
}

# 添加配置
add_config() {
    read_protocol
    read_s_port
    read_d_ip
    read_d_port
    write_rawconf
    rebuild_config
    systemctl restart gost
    echo -e "${Info} 配置已添加并生效"
    show_all_config
}

# 显示所有配置
show_all_config() {
    echo -e ""
    echo -e "                      GOST 配置                        "
    echo -e "--------------------------------------------------------"
    printf "%-4s | %-16s | %-8s | %s\n" "序号" "方法" "本地端口" "目标地址"
    echo -e "--------------------------------------------------------"
    
    [[ ! -f "$RAW_CONF" ]] && echo -e "${Warning} 暂无配置" && return
    
    local i=1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        parse_rawconf "$line"
        
        local method_str=""
        case "$is_encrypt" in
            nonencrypt) method_str="不加密中转" ;;
            encrypttls) method_str="TLS 隧道加密" ;;
            encryptws) method_str="WS 隧道加密" ;;
            encryptwss) method_str="WSS 隧道加密" ;;
            decrypttls) method_str="TLS 解密" ;;
            decryptws) method_str="WS 解密" ;;
            decryptwss) method_str="WSS 解密" ;;
            ss) method_str="SS 代理" ;;
            socks) method_str="SOCKS5 代理" ;;
            http) method_str="HTTP 代理" ;;
            peerno) method_str="不加密均衡" ;;
            peertls) method_str="TLS 均衡" ;;
            peerws) method_str="WS 均衡" ;;
            peerwss) method_str="WSS 均衡" ;;
            cdnno) method_str="CDN 不加密" ;;
            cdnws) method_str="CDN WS" ;;
            cdnwss) method_str="CDN WSS" ;;
            *) method_str="未知" ;;
        esac
        
        printf "%-4s | %-16s | %-8s | %s\n" "$i" "$method_str" "$s_port" "$d_ip:$d_port"
        echo -e "--------------------------------------------------------"
        ((i++))
    done < "$RAW_CONF"
}

# 删除配置
delete_config() {
    show_all_config
    [[ ! -s "$RAW_CONF" ]] && return
    
    read -p "请输入要删除的配置编号 (0 取消): " num_delete
    [[ "$num_delete" == "0" ]] && return
    
    if [[ "$num_delete" =~ ^[0-9]+$ ]]; then
        sed -i "${num_delete}d" "$RAW_CONF"
        rebuild_config
        systemctl restart gost
        echo -e "${Info} 配置已删除，服务已重启"
    else
        echo -e "${Error} 请输入正确数字"
    fi
}

# ==================== 证书管理 ====================
cert_menu() {
    echo -e ""
    echo -e "证书配置: "
    echo -e "-----------------------------------"
    echo -e "[1] ACME 一键申请证书"
    echo -e "[2] 手动上传证书"
    echo -e "-----------------------------------"
    read -p "请选择: " num_cert

    if [[ "$num_cert" == "1" ]]; then
        check_sys
        if [[ ${release} == "centos" ]]; then
            yum install -y socat
        else
            apt-get install -y socat
        fi
        
        read -p "请输入邮箱: " cert_email
        read -p "请输入域名: " cert_domain
        
        curl https://get.acme.sh | sh
        "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        "$HOME"/.acme.sh/acme.sh --register-account -m "${cert_email}"
        
        echo -e "[1] HTTP 申请 (需要 80 端口空闲)"
        echo -e "[2] DNS 申请 (Cloudflare)"
        read -p "请选择: " cert_method
        
        mkdir -p "$CERT_DIR"
        
        if [[ "$cert_method" == "1" ]]; then
            "$HOME"/.acme.sh/acme.sh --issue -d "${cert_domain}" --standalone -k ec-256 --force
        else
            read -p "请输入 Cloudflare 邮箱: " cf_email
            read -p "请输入 Cloudflare API Key: " cf_key
            export CF_Key="${cf_key}"
            export CF_Email="${cf_email}"
            "$HOME"/.acme.sh/acme.sh --issue --dns dns_cf -d "${cert_domain}" -k ec-256 --force
        fi
        
        "$HOME"/.acme.sh/acme.sh --installcert -d "${cert_domain}" \
            --fullchainpath "$CERT_DIR/cert.pem" \
            --keypath "$CERT_DIR/key.pem" --ecc --force
            
        echo -e "${Info} 证书已安装到 $CERT_DIR"
        
    elif [[ "$num_cert" == "2" ]]; then
        mkdir -p "$CERT_DIR"
        echo -e "${Info} 请将证书文件上传到 $CERT_DIR 目录:"
        echo -e "  - cert.pem (证书)"
        echo -e "  - key.pem (私钥)"
    fi
}

# ==================== 定时任务 ====================
cron_menu() {
    echo -e ""
    echo -e "定时重启配置: "
    echo -e "-----------------------------------"
    echo -e "[1] 配置定时重启"
    echo -e "[2] 删除定时重启"
    echo -e "-----------------------------------"
    read -p "请选择: " num_cron

    if [[ "$num_cron" == "1" ]]; then
        echo -e "[1] 每 N 小时重启"
        echo -e "[2] 每天 N 点重启"
        read -p "请选择: " cron_type
        
        if [[ "$cron_type" == "1" ]]; then
            read -p "每几小时重启: " cron_hour
            echo "0 */${cron_hour} * * * systemctl restart gost" >> /etc/crontab
        else
            read -p "每天几点重启: " cron_hour
            echo "0 ${cron_hour} * * * systemctl restart gost" >> /etc/crontab
        fi
        echo -e "${Info} 定时重启已配置"
        
    elif [[ "$num_cron" == "2" ]]; then
        sed -i "/gost/d" /etc/crontab
        echo -e "${Info} 定时重启已删除"
    fi
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    echo -e ""
    echo -e "        Multi-EasyGost v3 一键脚本 ${Red_font_prefix}[${shell_version}]${Font_color_suffix}"
    echo -e "        基于 GOST v3 (YAML 配置)"
    echo -e "        文档: https://gost.run"
    echo -e ""
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}1.${Font_color_suffix} 安装 GOST v3"
    echo -e " ${Green_font_prefix}2.${Font_color_suffix} 卸载 GOST v3"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}3.${Font_color_suffix} 启动 GOST"
    echo -e " ${Green_font_prefix}4.${Font_color_suffix} 停止 GOST"
    echo -e " ${Green_font_prefix}5.${Font_color_suffix} 重启 GOST"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}6.${Font_color_suffix} 新增转发配置"
    echo -e " ${Green_font_prefix}7.${Font_color_suffix} 查看现有配置"
    echo -e " ${Green_font_prefix}8.${Font_color_suffix} 删除一则配置"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}9.${Font_color_suffix} 定时重启配置"
    echo -e " ${Green_font_prefix}10.${Font_color_suffix} TLS 证书配置"
    echo -e "=========================================="
    echo -e " ${Green_font_prefix}0.${Font_color_suffix} 退出脚本"
    echo -e "=========================================="
    echo -e ""
    
    # 显示服务状态
    if systemctl is-active gost >/dev/null 2>&1; then
        echo -e " GOST 状态: ${Green_font_prefix}运行中${Font_color_suffix}"
    else
        echo -e " GOST 状态: ${Red_font_prefix}已停止${Font_color_suffix}"
    fi
    
    local count=0
    [[ -f "$RAW_CONF" ]] && count=$(wc -l < "$RAW_CONF" | tr -d ' ')
    echo -e " 配置数量: ${count}"
    echo -e ""
    
    read -p " 请输入数字 [0-10]: " num
    
    case "$num" in
        0) exit 0 ;;
        1) install_gost ;;
        2) uninstall_gost ;;
        3) start_gost ;;
        4) stop_gost ;;
        5) restart_gost ;;
        6) add_config ;;
        7) show_all_config ;;
        8) delete_config ;;
        9) cron_menu ;;
        10) cert_menu ;;
        *) echo -e "${Error} 请输入正确数字 [0-10]" ;;
    esac
    
    echo -e ""
    read -p "按回车继续..."
}

# ==================== 主程序 ====================
main() {
    check_root
    
    while true; do
        show_menu
    done
}

main
