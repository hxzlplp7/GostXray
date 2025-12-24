#!/bin/bash
# GOST v3 + Xray 任意门 中转脚本
# 支持协议: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS, HTTP
# 快捷命令: gostxray

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Yellow_font_prefix="\033[33m"
Blue_font_prefix="\033[34m" && Purple_font_prefix="\033[35m" && Cyan_font_prefix="\033[36m"
Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Warning="${Yellow_font_prefix}[警告]${Font_color_suffix}"
Tip="${Cyan_font_prefix}[提示]${Font_color_suffix}"

shell_version="3.1.0"
gost_version="3.0.0"
gost_conf_path="/etc/gost3/config.yaml"
xray_conf_path="/etc/xray/config.json"
raw_conf_path="/etc/gost3/rawconf"
port_conf_path="/etc/gost3/ports.conf"
script_path="/usr/local/bin/gostxray"

# ==================== 工具函数 ====================
check_root() {
    [[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号，请使用 sudo su 获取权限" && exit 1
}

check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue 2>/dev/null | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue 2>/dev/null | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    fi
    
    arch=$(uname -m)
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
        armv6l) arch="armv6" ;;
        i686|i386) arch="386" ;;
        *) echo -e "${Error} 不支持的架构: $arch"; exit 1 ;;
    esac
}

install_deps() {
    echo -e "${Info} 安装依赖..."
    if [[ ${release} == "centos" ]]; then
        yum install -y wget curl jq tar gzip net-tools >/dev/null 2>&1
    else
        apt-get update >/dev/null 2>&1
        apt-get install -y wget curl jq tar gzip net-tools >/dev/null 2>&1
    fi
}

get_ip() {
    local ip=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 ifconfig.me 2>/dev/null || curl -s4m5 ipinfo.io/ip 2>/dev/null)
    echo "$ip"
}

# ==================== 快捷命令安装 ====================
install_shortcut() {
    echo -e "${Info} 安装快捷命令..."
    
    # 获取当前脚本的实际路径
    local current_script=$(readlink -f "$0")
    
    # 复制脚本到 /usr/local/bin
    cp "$current_script" "$script_path"
    chmod +x "$script_path"
    
    echo -e "${Info} 快捷命令安装完成！"
    echo -e "${Tip} 现在可以在任意位置输入 ${Green_font_prefix}gostxray${Font_color_suffix} 进入管理菜单"
}

uninstall_shortcut() {
    if [[ -f "$script_path" ]]; then
        rm -f "$script_path"
        echo -e "${Info} 快捷命令已删除"
    else
        echo -e "${Warning} 快捷命令不存在"
    fi
}

check_shortcut() {
    if [[ -f "$script_path" ]]; then
        echo -e "${Info} 快捷命令 ${Green_font_prefix}gost${Font_color_suffix} 已安装"
        return 0
    else
        return 1
    fi
}

# ==================== 端口管理 ====================
get_random_port() {
    local min=$1
    local max=$2
    shuf -i ${min}-${max} -n 1
}

get_next_port() {
    local min=$1
    local max=$2
    local used_ports=$(cat $port_conf_path 2>/dev/null | tr '\n' ' ')
    
    for ((port=min; port<=max; port++)); do
        if ! echo "$used_ports" | grep -qw "$port"; then
            if ! ss -tuln 2>/dev/null | grep -q ":$port "; then
                echo $port
                return
            fi
        fi
    done
    echo "0"
}

check_port_available() {
    local port=$1
    if ss -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    return 0
}

read_port_config() {
    echo -e ""
    echo -e "${Info} 端口配置选项:"
    echo -e "-----------------------------------"
    echo -e "[1] 随机选择端口 (10000-65535)"
    echo -e "[2] 指定端口范围自动分配"
    echo -e "[3] 手动指定端口"
    echo -e "-----------------------------------"
    read -p "请选择 [默认1]: " port_mode
    port_mode=${port_mode:-1}
    
    case $port_mode in
        1)
            local_port=$(get_random_port 10000 65535)
            local retry=0
            while ! check_port_available $local_port && [ $retry -lt 10 ]; do
                local_port=$(get_random_port 10000 65535)
                ((retry++))
            done
            echo -e "${Info} 随机分配端口: ${Green_font_prefix}$local_port${Font_color_suffix}"
            ;;
        2)
            read -p "请输入端口范围起始值 [默认10000]: " port_min
            read -p "请输入端口范围结束值 [默认65535]: " port_max
            port_min=${port_min:-10000}
            port_max=${port_max:-65535}
            local_port=$(get_next_port $port_min $port_max)
            if [ "$local_port" == "0" ]; then
                echo -e "${Error} 指定范围内没有可用端口"
                return 1
            fi
            echo -e "${Info} 自动分配端口: ${Green_font_prefix}$local_port${Font_color_suffix}"
            ;;
        3)
            read -p "请输入本地监听端口: " local_port
            if ! check_port_available $local_port; then
                echo -e "${Warning} 端口 $local_port 已被占用"
                read -p "是否继续使用? [y/N]: " confirm
                [[ ! $confirm =~ ^[Yy]$ ]] && return 1
            fi
            ;;
        *)
            echo -e "${Error} 无效选择"
            return 1
            ;;
    esac
    
    # 记录使用的端口
    mkdir -p /etc/gost3
    echo "$local_port" >> $port_conf_path
    return 0
}

# ==================== Base64 解码 ====================
base64_decode() {
    local input="$1"
    # 处理 URL 安全的 base64
    input="${input//-/+}"
    input="${input//_/\/}"
    # 修复 base64 填充
    local mod=$((${#input} % 4))
    if [ $mod -eq 2 ]; then
        input="${input}=="
    elif [ $mod -eq 3 ]; then
        input="${input}="
    fi
    echo "$input" | base64 -d 2>/dev/null
}

url_decode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

# ==================== 协议解析函数 ====================
parse_vless() {
    local link="$1"
    link="${link#vless://}"
    
    local user_host="${link%%\?*}"
    local params="${link#*\?}"
    
    local uuid="${user_host%%@*}"
    local host_port="${user_host#*@}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    # 解析参数
    local type="" security="" sni="" path="" flow="" host_param="" fp="" pbk="" sid=""
    while IFS='=' read -r key value; do
        value=$(url_decode "$value")
        case $key in
            type) type="$value" ;;
            security) security="$value" ;;
            sni) sni="$value" ;;
            path) path="$value" ;;
            flow) flow="$value" ;;
            host) host_param="$value" ;;
            fp) fp="$value" ;;
            pbk) pbk="$value" ;;
            sid) sid="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "vless|$uuid|$host|$port|$type|$security|$sni|$path|$flow|$host_param|$fp|$pbk|$sid"
}

parse_vmess() {
    local link="$1"
    link="${link#vmess://}"
    local decoded=$(base64_decode "$link")
    
    if [ -z "$decoded" ]; then
        echo "vmess|||||||||||"
        return
    fi
    
    local host=$(echo "$decoded" | jq -r '.add // .host // ""' 2>/dev/null)
    local port=$(echo "$decoded" | jq -r '.port // ""' 2>/dev/null)
    local uuid=$(echo "$decoded" | jq -r '.id // ""' 2>/dev/null)
    local aid=$(echo "$decoded" | jq -r '.aid // "0"' 2>/dev/null)
    local net=$(echo "$decoded" | jq -r '.net // "tcp"' 2>/dev/null)
    local type=$(echo "$decoded" | jq -r '.type // "none"' 2>/dev/null)
    local tls=$(echo "$decoded" | jq -r '.tls // ""' 2>/dev/null)
    local sni=$(echo "$decoded" | jq -r '.sni // ""' 2>/dev/null)
    local path=$(echo "$decoded" | jq -r '.path // ""' 2>/dev/null)
    local ps=$(echo "$decoded" | jq -r '.ps // ""' 2>/dev/null)
    
    echo "vmess|$uuid|$host|$port|$net|$tls|$sni|$path|$aid|$ps"
}

parse_trojan() {
    local link="$1"
    link="${link#trojan://}"
    
    local pass_host="${link%%\?*}"
    local params="${link#*\?}"
    
    local password="${pass_host%%@*}"
    local host_port="${pass_host#*@}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local sni="" type="" host_param="" path=""
    while IFS='=' read -r key value; do
        value=$(url_decode "$value")
        case $key in
            sni) sni="$value" ;;
            type) type="$value" ;;
            host) host_param="$value" ;;
            path) path="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "trojan|$password|$host|$port|$type|$sni|$host_param|$path"
}

parse_ss() {
    local link="$1"
    link="${link#ss://}"
    
    local method="" password="" host="" port=""
    
    if [[ "$link" == *"@"* ]]; then
        local encoded_part="${link%%@*}"
        local host_part="${link#*@}"
        local decoded=$(base64_decode "$encoded_part")
        method="${decoded%%:*}"
        password="${decoded#*:}"
        host="${host_part%%:*}"
        port="${host_part##*:}"
        port="${port%%#*}"
        port="${port%%\?*}"
    else
        local decoded=$(base64_decode "${link%%#*}")
        method="${decoded%%:*}"
        local rest="${decoded#*:}"
        password="${rest%%@*}"
        local host_port="${rest#*@}"
        host="${host_port%%:*}"
        port="${host_port##*:}"
    fi
    
    echo "ss|$method|$password|$host|$port"
}

parse_hysteria2() {
    local link="$1"
    link="${link#hysteria2://}"
    link="${link#hy2://}"
    
    local auth_host="${link%%\?*}"
    local params="${link#*\?}"
    
    local password="${auth_host%%@*}"
    local host_port="${auth_host#*@}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local sni="" insecure="" obfs="" obfs_password=""
    while IFS='=' read -r key value; do
        value=$(url_decode "$value")
        case $key in
            sni) sni="$value" ;;
            insecure) insecure="$value" ;;
            obfs) obfs="$value" ;;
            obfs-password) obfs_password="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "hysteria2|$password|$host|$port|$sni|$insecure|$obfs|$obfs_password"
}

parse_tuic() {
    local link="$1"
    link="${link#tuic://}"
    
    local auth="${link%%@*}"
    local uuid="${auth%%:*}"
    local password="${auth#*:}"
    
    local rest="${link#*@}"
    local host_port="${rest%%\?*}"
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    
    local params="${rest#*\?}"
    local sni="" alpn="" congestion_control=""
    while IFS='=' read -r key value; do
        value=$(url_decode "$value")
        case $key in
            sni) sni="$value" ;;
            alpn) alpn="$value" ;;
            congestion_control) congestion_control="$value" ;;
        esac
    done <<< "$(echo "$params" | tr '&' '\n' | cut -d'#' -f1)"
    
    echo "tuic|$uuid|$password|$host|$port|$sni|$alpn|$congestion_control"
}

parse_socks() {
    local link="$1"
    link="${link#socks://}"
    link="${link#socks5://}"
    
    if [[ "$link" == *"@"* ]]; then
        local auth="${link%%@*}"
        local decoded=$(base64_decode "$auth" 2>/dev/null || echo "$auth")
        local user="${decoded%%:*}"
        local pass="${decoded#*:}"
        local host_port="${link#*@}"
    else
        local user="" pass=""
        local host_port="${link%%#*}"
    fi
    
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    port="${port%%\?*}"
    
    echo "socks|$user|$pass|$host|$port"
}

parse_http() {
    local link="$1"
    link="${link#http://}"
    link="${link#https://}"
    
    if [[ "$link" == *"@"* ]]; then
        local auth="${link%%@*}"
        local user="${auth%%:*}"
        local pass="${auth#*:}"
        local host_port="${link#*@}"
    else
        local user="" pass=""
        local host_port="${link%%/*}"
        host_port="${host_port%%#*}"
    fi
    
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    port="${port%%#*}"
    port="${port%%\?*}"
    
    echo "http|$user|$pass|$host|$port"
}

# ==================== 自动识别协议 ====================
detect_protocol() {
    local link="$1"
    
    case "$link" in
        vless://*) echo "vless" ;;
        vmess://*) echo "vmess" ;;
        trojan://*) echo "trojan" ;;
        ss://*) echo "ss" ;;
        hysteria2://*|hy2://*) echo "hysteria2" ;;
        tuic://*) echo "tuic" ;;
        socks://*|socks5://*) echo "socks" ;;
        http://*|https://*) echo "http" ;;
        *) echo "unknown" ;;
    esac
}

parse_node_link() {
    local link="$1"
    local protocol=$(detect_protocol "$link")
    
    case $protocol in
        vless) parse_vless "$link" ;;
        vmess) parse_vmess "$link" ;;
        trojan) parse_trojan "$link" ;;
        ss) parse_ss "$link" ;;
        hysteria2) parse_hysteria2 "$link" ;;
        tuic) parse_tuic "$link" ;;
        socks) parse_socks "$link" ;;
        http) parse_http "$link" ;;
        *) echo "unknown" ;;
    esac
}

get_target_from_parsed() {
    local protocol="$1"
    local parsed="$2"
    
    IFS='|' read -ra parts <<< "$parsed"
    
    case $protocol in
        vless|vmess|trojan)
            echo "${parts[2]}|${parts[3]}"
            ;;
        ss)
            echo "${parts[3]}|${parts[4]}"
            ;;
        hysteria2)
            echo "${parts[2]}|${parts[3]}"
            ;;
        tuic)
            echo "${parts[3]}|${parts[4]}"
            ;;
        socks|http)
            echo "${parts[3]}|${parts[4]}"
            ;;
    esac
}

# ==================== GOST v3 安装 ====================
install_gost3() {
    check_root
    check_sys
    install_deps
    
    echo -e "${Info} 正在下载 GOST v3..."
    
    local download_url="https://github.com/go-gost/gost/releases/download/v${gost_version}/gost_${gost_version}_linux_${arch}.tar.gz"
    
    mkdir -p /etc/gost3
    cd /tmp
    rm -rf gost*
    
    # 尝试使用镜像
    echo -e "${Info} 尝试从 GitHub 下载..."
    if ! wget --no-check-certificate -t 3 -T 30 "$download_url" -O gost.tar.gz 2>/dev/null; then
        echo -e "${Warning} GitHub 下载失败，尝试使用镜像..."
        download_url="https://ghproxy.com/$download_url"
        if ! wget --no-check-certificate -t 3 -T 30 "$download_url" -O gost.tar.gz 2>/dev/null; then
            echo -e "${Error} GOST v3 下载失败"
            return 1
        fi
    fi
    
    tar -xzf gost.tar.gz
    mv gost /usr/bin/gost3
    chmod +x /usr/bin/gost3
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/gost3.service << 'EOF'
[Unit]
Description=GOST v3 Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/gost3 -C /etc/gost3/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # 初始化配置文件
    cat > $gost_conf_path << 'EOF'
services: []
EOF

    touch $raw_conf_path
    touch $port_conf_path
    
    systemctl daemon-reload
    systemctl enable gost3 >/dev/null 2>&1
    
    echo -e "${Info} GOST v3 安装完成"
    echo -e "${Info} GOST 版本: $(/usr/bin/gost3 -V 2>&1 | head -1)"
    rm -rf /tmp/gost*
    
    # 安装快捷命令
    install_shortcut
}

# ==================== Xray 安装 ====================
install_xray() {
    check_root
    check_sys
    install_deps
    
    echo -e "${Info} 正在安装 Xray..."
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    if [ $? -eq 0 ]; then
        echo -e "${Info} Xray 安装完成"
        
        mkdir -p /etc/gost3
        
        # 初始化配置
        cat > $xray_conf_path << 'EOF'
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ],
    "routing": {
        "rules": []
    }
}
EOF
        systemctl restart xray
        
        # 如果没有安装快捷命令，也安装一下
        if ! check_shortcut; then
            install_shortcut
        fi
    else
        echo -e "${Error} Xray 安装失败"
    fi
}

# ==================== 生成中转链接 ====================
generate_relay_link() {
    local protocol="$1"
    local parsed="$2"
    local relay_ip="$3"
    local relay_port="$4"
    
    IFS='|' read -ra parts <<< "$parsed"
    
    case $protocol in
        vless)
            local uuid="${parts[1]}"
            local orig_host="${parts[2]}"
            local type="${parts[4]}"
            local security="${parts[5]}"
            local sni="${parts[6]}"
            local path="${parts[7]}"
            local flow="${parts[8]}"
            local host_param="${parts[9]}"
            local fp="${parts[10]}"
            local pbk="${parts[11]}"
            local sid="${parts[12]}"
            
            local new_link="vless://${uuid}@${relay_ip}:${relay_port}?"
            [ -n "$type" ] && new_link+="type=${type}&"
            [ -n "$security" ] && new_link+="security=${security}&"
            [ -n "$sni" ] && new_link+="sni=${sni}&"
            [ -n "$path" ] && new_link+="path=${path}&"
            [ -n "$flow" ] && new_link+="flow=${flow}&"
            [ -n "$host_param" ] && new_link+="host=${host_param}&"
            [ -n "$fp" ] && new_link+="fp=${fp}&"
            [ -n "$pbk" ] && new_link+="pbk=${pbk}&"
            [ -n "$sid" ] && new_link+="sid=${sid}&"
            new_link="${new_link%&}#Relay-${orig_host}"
            echo "$new_link"
            ;;
        vmess)
            local uuid="${parts[1]}"
            local orig_host="${parts[2]}"
            local orig_port="${parts[3]}"
            local net="${parts[4]}"
            local tls="${parts[5]}"
            local sni="${parts[6]}"
            local path="${parts[7]}"
            local aid="${parts[8]}"
            local ps="${parts[9]}"
            
            local json="{\"v\":\"2\",\"ps\":\"Relay-${ps:-$orig_host}\",\"add\":\"${relay_ip}\",\"port\":\"${relay_port}\",\"id\":\"${uuid}\",\"aid\":\"${aid:-0}\",\"net\":\"${net:-tcp}\",\"type\":\"none\",\"host\":\"${sni}\",\"path\":\"${path}\",\"tls\":\"${tls}\"}"
            echo "vmess://$(echo -n "$json" | base64 -w0)"
            ;;
        trojan)
            local password="${parts[1]}"
            local orig_host="${parts[2]}"
            local type="${parts[4]}"
            local sni="${parts[5]}"
            local host_param="${parts[6]}"
            local path="${parts[7]}"
            
            local new_link="trojan://${password}@${relay_ip}:${relay_port}?"
            [ -n "$type" ] && new_link+="type=${type}&"
            [ -n "$sni" ] && new_link+="sni=${sni}&"
            [ -n "$host_param" ] && new_link+="host=${host_param}&"
            [ -n "$path" ] && new_link+="path=${path}&"
            new_link="${new_link%&}#Relay-${orig_host}"
            echo "$new_link"
            ;;
        ss)
            local method="${parts[1]}"
            local password="${parts[2]}"
            local orig_host="${parts[3]}"
            
            local auth=$(echo -n "${method}:${password}" | base64 -w0)
            echo "ss://${auth}@${relay_ip}:${relay_port}#Relay-${orig_host}"
            ;;
        hysteria2)
            local password="${parts[1]}"
            local orig_host="${parts[2]}"
            local sni="${parts[4]}"
            local insecure="${parts[5]}"
            local obfs="${parts[6]}"
            local obfs_password="${parts[7]}"
            
            local new_link="hysteria2://${password}@${relay_ip}:${relay_port}?"
            [ -n "$sni" ] && new_link+="sni=${sni}&"
            [ -n "$insecure" ] && new_link+="insecure=${insecure}&"
            [ -n "$obfs" ] && new_link+="obfs=${obfs}&"
            [ -n "$obfs_password" ] && new_link+="obfs-password=${obfs_password}&"
            new_link="${new_link%&}#Relay-${orig_host}"
            echo "$new_link"
            ;;
        tuic)
            local uuid="${parts[1]}"
            local password="${parts[2]}"
            local orig_host="${parts[3]}"
            local sni="${parts[5]}"
            local alpn="${parts[6]}"
            local cc="${parts[7]}"
            
            local new_link="tuic://${uuid}:${password}@${relay_ip}:${relay_port}?"
            [ -n "$sni" ] && new_link+="sni=${sni}&"
            [ -n "$alpn" ] && new_link+="alpn=${alpn}&"
            [ -n "$cc" ] && new_link+="congestion_control=${cc}&"
            new_link="${new_link%&}#Relay-${orig_host}"
            echo "$new_link"
            ;;
        socks)
            local user="${parts[1]}"
            local pass="${parts[2]}"
            local orig_host="${parts[3]}"
            
            if [ -n "$user" ]; then
                local auth=$(echo -n "${user}:${pass}" | base64 -w0)
                echo "socks://${auth}@${relay_ip}:${relay_port}#Relay-${orig_host}"
            else
                echo "socks://${relay_ip}:${relay_port}#Relay-${orig_host}"
            fi
            ;;
        http)
            local user="${parts[1]}"
            local pass="${parts[2]}"
            local orig_host="${parts[3]}"
            
            if [ -n "$user" ]; then
                echo "http://${user}:${pass}@${relay_ip}:${relay_port}#Relay-${orig_host}"
            else
                echo "http://${relay_ip}:${relay_port}#Relay-${orig_host}"
            fi
            ;;
    esac
}

# ==================== GOST v3 配置生成 ====================
generate_gost3_tcp_udp() {
    local listen_port="$1"
    local target_host="$2"
    local target_port="$3"
    
    cat << EOF
  - name: relay-${listen_port}-tcp
    addr: ":${listen_port}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target
          addr: "${target_host}:${target_port}"
  - name: relay-${listen_port}-udp
    addr: ":${listen_port}"
    handler:
      type: udp
    listener:
      type: udp
      metadata:
        keepAlive: true
        ttl: 10s
        readBufferSize: 4096
    forwarder:
      nodes:
        - name: target
          addr: "${target_host}:${target_port}"
EOF
}

add_gost3_relay() {
    local listen_port="$1"
    local target_host="$2"
    local target_port="$3"
    
    mkdir -p /etc/gost3
    
    local new_config=$(generate_gost3_tcp_udp "$listen_port" "$target_host" "$target_port")
    
    # 检查配置文件是否只有 services: []
    if grep -q "^services: \[\]$" $gost_conf_path 2>/dev/null; then
        cat > $gost_conf_path << EOF
services:
${new_config}
EOF
    else
        # 如果文件不存在或为空
        if [ ! -s "$gost_conf_path" ]; then
            cat > $gost_conf_path << EOF
services:
${new_config}
EOF
        else
            echo "$new_config" >> $gost_conf_path
        fi
    fi
    
    echo "gost3|tcp+udp|${listen_port}|${target_host}|${target_port}" >> $raw_conf_path
}

# ==================== Xray 任意门配置 ====================
add_xray_dokodemo() {
    local listen_port="$1"
    local target_host="$2"
    local target_port="$3"
    local network="${4:-tcp,udp}"
    
    mkdir -p /etc/gost3
    
    local tag="dokodemo-${listen_port}"
    
    # 如果配置文件不存在，创建初始配置
    if [ ! -f "$xray_conf_path" ]; then
        cat > $xray_conf_path << 'EOF'
{
    "log": {"loglevel": "warning"},
    "inbounds": [],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": []}
}
EOF
    fi
    
    # 使用 jq 添加新的 inbound
    local temp_file=$(mktemp)
    jq ".inbounds += [{\"tag\": \"${tag}\", \"port\": ${listen_port}, \"protocol\": \"dokodemo-door\", \"settings\": {\"address\": \"${target_host}\", \"port\": ${target_port}, \"network\": \"${network}\"}}]" $xray_conf_path > "$temp_file"
    mv "$temp_file" $xray_conf_path
    
    echo "xray|dokodemo|${listen_port}|${target_host}|${target_port}|${network}" >> $raw_conf_path
}

# ==================== 添加中转配置 ====================
add_relay_config() {
    echo -e ""
    echo -e "${Info} 请选择中转方式:"
    echo -e "-----------------------------------"
    echo -e "[1] GOST v3 TCP+UDP 中转"
    echo -e "[2] Xray 任意门 (dokodemo-door)"
    echo -e "-----------------------------------"
    read -p "请选择 [默认1]: " relay_type
    relay_type=${relay_type:-1}
    
    echo -e ""
    echo -e "${Info} 请选择配置方式:"
    echo -e "-----------------------------------"
    echo -e "[1] 粘贴节点链接 (自动解析)"
    echo -e "[2] 手动输入目标地址和端口"
    echo -e "-----------------------------------"
    read -p "请选择 [默认1]: " input_type
    input_type=${input_type:-1}
    
    local protocol="" parsed=""
    
    if [ "$input_type" == "1" ]; then
        echo -e ""
        read -p "请粘贴节点链接: " node_link
        
        if [ -z "$node_link" ]; then
            echo -e "${Error} 节点链接不能为空"
            return 1
        fi
        
        protocol=$(detect_protocol "$node_link")
        if [ "$protocol" == "unknown" ]; then
            echo -e "${Error} 无法识别的协议类型"
            return 1
        fi
        
        echo -e "${Info} 检测到协议: ${Green_font_prefix}${protocol^^}${Font_color_suffix}"
        
        parsed=$(parse_node_link "$node_link")
        local target_info=$(get_target_from_parsed "$protocol" "$parsed")
        IFS='|' read -r target_host target_port <<< "$target_info"
        
        if [ -z "$target_host" ] || [ -z "$target_port" ]; then
            echo -e "${Error} 解析节点链接失败"
            return 1
        fi
        
        echo -e "${Info} 目标地址: ${Green_font_prefix}${target_host}:${target_port}${Font_color_suffix}"
    else
        read -p "请输入目标地址 (IP或域名): " target_host
        read -p "请输入目标端口: " target_port
        
        if [ -z "$target_host" ] || [ -z "$target_port" ]; then
            echo -e "${Error} 目标地址和端口不能为空"
            return 1
        fi
    fi
    
    # 配置本地端口
    if ! read_port_config; then
        return 1
    fi
    
    # 获取本机IP
    local local_ip=$(get_ip)
    if [ -z "$local_ip" ]; then
        echo -e "${Warning} 无法获取本机公网IP，请稍后手动替换链接中的IP"
        local_ip="YOUR_IP"
    fi
    
    if [ "$relay_type" == "1" ]; then
        if [ ! -f "/usr/bin/gost3" ]; then
            echo -e "${Warning} GOST v3 未安装，是否立即安装? [Y/n]"
            read -p "" install_confirm
            if [[ ! $install_confirm =~ ^[Nn]$ ]]; then
                install_gost3
            else
                return 1
            fi
        fi
        add_gost3_relay "$local_port" "$target_host" "$target_port"
        systemctl restart gost3
        echo -e "${Info} GOST v3 中转配置已添加"
    else
        if ! command -v xray &> /dev/null; then
            echo -e "${Warning} Xray 未安装，是否立即安装? [Y/n]"
            read -p "" install_confirm
            if [[ ! $install_confirm =~ ^[Nn]$ ]]; then
                install_xray
            else
                return 1
            fi
        fi
        add_xray_dokodemo "$local_port" "$target_host" "$target_port"
        systemctl restart xray
        echo -e "${Info} Xray 任意门配置已添加"
    fi
    
    echo -e ""
    echo -e "${Green_font_prefix}===========================================${Font_color_suffix}"
    echo -e "${Info} 中转配置完成!"
    echo -e "${Green_font_prefix}===========================================${Font_color_suffix}"
    echo -e " 本机IP:      ${Cyan_font_prefix}${local_ip}${Font_color_suffix}"
    echo -e " 本地端口:    ${Cyan_font_prefix}${local_port}${Font_color_suffix}"
    echo -e " 目标地址:    ${target_host}:${target_port}"
    echo -e "${Green_font_prefix}===========================================${Font_color_suffix}"
    
    # 如果是通过节点链接添加，生成中转后的链接
    if [ "$input_type" == "1" ] && [ -n "$parsed" ]; then
        local relay_link=$(generate_relay_link "$protocol" "$parsed" "$local_ip" "$local_port")
        echo -e ""
        echo -e "${Info} 中转后的节点链接:"
        echo -e "${Green_font_prefix}-------------------------------------------${Font_color_suffix}"
        echo -e "${Cyan_font_prefix}${relay_link}${Font_color_suffix}"
        echo -e "${Green_font_prefix}-------------------------------------------${Font_color_suffix}"
    fi
    
    echo -e ""
    read -p "按回车键继续..."
}

# ==================== 批量添加中转 ====================
batch_add_relay() {
    echo -e ""
    echo -e "${Info} 批量添加中转配置"
    echo -e "${Tip} 请输入节点链接，每行一个，输入空行结束"
    echo -e "-----------------------------------"
    
    local links=()
    while true; do
        read -p "> " line
        if [ -z "$line" ]; then
            break
        fi
        links+=("$line")
    done
    
    if [ ${#links[@]} -eq 0 ]; then
        echo -e "${Error} 没有输入任何链接"
        return 1
    fi
    
    echo -e ""
    echo -e "${Info} 请选择中转方式:"
    echo -e "[1] GOST v3  [2] Xray 任意门"
    read -p "请选择 [默认1]: " relay_type
    relay_type=${relay_type:-1}
    
    echo -e ""
    echo -e "${Info} 端口分配方式:"
    echo -e "[1] 从指定端口开始递增  [2] 随机分配"
    read -p "请选择 [默认1]: " port_mode
    port_mode=${port_mode:-1}
    
    local start_port=10000
    if [ "$port_mode" == "1" ]; then
        read -p "请输入起始端口 [默认10000]: " start_port
        start_port=${start_port:-10000}
    fi
    
    local local_ip=$(get_ip)
    local current_port=$start_port
    
    echo -e ""
    echo -e "${Info} 开始批量添加..."
    echo -e ""
    
    for link in "${links[@]}"; do
        local protocol=$(detect_protocol "$link")
        if [ "$protocol" == "unknown" ]; then
            echo -e "${Warning} 跳过无法识别的链接: ${link:0:50}..."
            continue
        fi
        
        local parsed=$(parse_node_link "$link")
        local target_info=$(get_target_from_parsed "$protocol" "$parsed")
        IFS='|' read -r target_host target_port <<< "$target_info"
        
        if [ -z "$target_host" ] || [ -z "$target_port" ]; then
            echo -e "${Warning} 跳过解析失败的链接"
            continue
        fi
        
        # 获取可用端口
        if [ "$port_mode" == "1" ]; then
            while ! check_port_available $current_port; do
                ((current_port++))
            done
            local_port=$current_port
            ((current_port++))
        else
            local_port=$(get_random_port 10000 65535)
            while ! check_port_available $local_port; do
                local_port=$(get_random_port 10000 65535)
            done
        fi
        
        echo "$local_port" >> $port_conf_path
        
        if [ "$relay_type" == "1" ]; then
            add_gost3_relay "$local_port" "$target_host" "$target_port"
        else
            add_xray_dokodemo "$local_port" "$target_host" "$target_port"
        fi
        
        local relay_link=$(generate_relay_link "$protocol" "$parsed" "$local_ip" "$local_port")
        echo -e "${Info} [$protocol] ${target_host}:${target_port} -> :${local_port}"
        echo -e "    ${Cyan_font_prefix}${relay_link}${Font_color_suffix}"
        echo -e ""
    done
    
    if [ "$relay_type" == "1" ]; then
        systemctl restart gost3
    else
        systemctl restart xray
    fi
    
    echo -e "${Info} 批量添加完成!"
    read -p "按回车键继续..."
}

# ==================== 查看配置 ====================
show_all_config() {
    echo -e ""
    echo -e "${Green_font_prefix}==================== 当前中转配置 ====================${Font_color_suffix}"
    
    if [ ! -f "$raw_conf_path" ] || [ ! -s "$raw_conf_path" ]; then
        echo -e "${Warning} 暂无配置"
        echo -e "${Green_font_prefix}=======================================================${Font_color_suffix}"
        return
    fi
    
    printf "%-4s | %-12s | %-8s | %s\n" "序号" "类型" "本地端口" "目标地址"
    echo -e "-------------------------------------------------------"
    
    local i=1
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            IFS='|' read -ra parts <<< "$line"
            local type="${parts[0]}-${parts[1]}"
            local port="${parts[2]}"
            local host="${parts[3]}"
            local dport="${parts[4]}"
            printf "%-4s | %-12s | %-8s | %s\n" "$i" "$type" "$port" "$host:$dport"
            ((i++))
        fi
    done < $raw_conf_path
    
    echo -e "${Green_font_prefix}=======================================================${Font_color_suffix}"
}

# ==================== 删除配置 ====================
delete_config() {
    show_all_config
    
    if [ ! -f "$raw_conf_path" ] || [ ! -s "$raw_conf_path" ]; then
        return
    fi
    
    echo -e ""
    read -p "请输入要删除的配置序号 (输入 0 取消): " del_num
    
    if [ "$del_num" == "0" ]; then
        return
    fi
    
    if ! [[ "$del_num" =~ ^[0-9]+$ ]]; then
        echo -e "${Error} 请输入有效数字"
        return
    fi
    
    local line=$(sed -n "${del_num}p" $raw_conf_path)
    if [ -z "$line" ]; then
        echo -e "${Error} 配置不存在"
        return
    fi
    
    IFS='|' read -ra parts <<< "$line"
    local service_type="${parts[0]}"
    local local_port="${parts[2]}"
    
    # 从原始配置文件删除
    sed -i "${del_num}d" $raw_conf_path
    
    # 从端口配置删除
    sed -i "/^${local_port}$/d" $port_conf_path 2>/dev/null
    
    # 重新生成配置
    if [ "$service_type" == "gost3" ]; then
        cat > $gost_conf_path << 'EOF'
services: []
EOF
        while IFS= read -r conf_line; do
            if [[ "$conf_line" == gost3* ]]; then
                IFS='|' read -ra p <<< "$conf_line"
                local new_config=$(generate_gost3_tcp_udp "${p[2]}" "${p[3]}" "${p[4]}")
                if grep -q "^services: \[\]$" $gost_conf_path; then
                    cat > $gost_conf_path << EOF
services:
${new_config}
EOF
                else
                    echo "$new_config" >> $gost_conf_path
                fi
            fi
        done < $raw_conf_path
        systemctl restart gost3
    else
        cat > $xray_conf_path << 'EOF'
{
    "log": {"loglevel": "warning"},
    "inbounds": [],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "routing": {"rules": []}
}
EOF
        while IFS= read -r conf_line; do
            if [[ "$conf_line" == xray* ]]; then
                IFS='|' read -ra p <<< "$conf_line"
                add_xray_dokodemo "${p[2]}" "${p[3]}" "${p[4]}" "${p[5]}"
            fi
        done < $raw_conf_path
        systemctl restart xray
    fi
    
    echo -e "${Info} 配置已删除"
}

# ==================== 服务状态 ====================
show_status() {
    echo -e ""
    echo -e "${Green_font_prefix}==================== 服务状态 ====================${Font_color_suffix}"
    
    # GOST 状态
    if [ -f "/usr/bin/gost3" ]; then
        local gost_status=$(systemctl is-active gost3 2>/dev/null)
        if [ "$gost_status" == "active" ]; then
            echo -e " GOST v3:  ${Green_font_prefix}运行中${Font_color_suffix}"
        else
            echo -e " GOST v3:  ${Red_font_prefix}已停止${Font_color_suffix}"
        fi
    else
        echo -e " GOST v3:  ${Yellow_font_prefix}未安装${Font_color_suffix}"
    fi
    
    # Xray 状态
    if command -v xray &> /dev/null; then
        local xray_status=$(systemctl is-active xray 2>/dev/null)
        if [ "$xray_status" == "active" ]; then
            echo -e " Xray:     ${Green_font_prefix}运行中${Font_color_suffix}"
        else
            echo -e " Xray:     ${Red_font_prefix}已停止${Font_color_suffix}"
        fi
    else
        echo -e " Xray:     ${Yellow_font_prefix}未安装${Font_color_suffix}"
    fi
    
    # 配置数量
    local config_count=0
    if [ -f "$raw_conf_path" ]; then
        config_count=$(wc -l < $raw_conf_path 2>/dev/null || echo 0)
    fi
    echo -e " 中转数量: ${Cyan_font_prefix}${config_count}${Font_color_suffix}"
    
    # 本机IP
    local ip=$(get_ip)
    echo -e " 本机IP:   ${Cyan_font_prefix}${ip:-获取中...}${Font_color_suffix}"
    
    echo -e "${Green_font_prefix}==================================================${Font_color_suffix}"
}

# ==================== 解析测试 ====================
test_parse() {
    echo -e ""
    read -p "请粘贴节点链接: " test_link
    
    if [ -z "$test_link" ]; then
        echo -e "${Error} 链接不能为空"
        return
    fi
    
    local protocol=$(detect_protocol "$test_link")
    echo -e ""
    echo -e "${Info} 协议类型: ${Green_font_prefix}${protocol^^}${Font_color_suffix}"
    
    if [ "$protocol" == "unknown" ]; then
        echo -e "${Error} 无法识别的协议"
        return
    fi
    
    local parsed=$(parse_node_link "$test_link")
    echo -e "${Info} 解析结果:"
    echo -e "${Cyan_font_prefix}${parsed}${Font_color_suffix}"
    
    local target_info=$(get_target_from_parsed "$protocol" "$parsed")
    IFS='|' read -r target_host target_port <<< "$target_info"
    echo -e ""
    echo -e "${Info} 目标地址: ${Green_font_prefix}${target_host}:${target_port}${Font_color_suffix}"
    
    echo -e ""
    read -p "按回车键继续..."
}

# ==================== 卸载 ====================
uninstall_gost3() {
    echo -e "${Warning} 确定要卸载 GOST v3 吗? [y/N]"
    read -p "" confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        return
    fi
    
    systemctl stop gost3 2>/dev/null
    systemctl disable gost3 2>/dev/null
    rm -rf /usr/bin/gost3 /etc/gost3 /etc/systemd/system/gost3.service
    systemctl daemon-reload
    echo -e "${Info} GOST v3 已卸载"
}

uninstall_xray() {
    echo -e "${Warning} 确定要卸载 Xray 吗? [y/N]"
    read -p "" confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        return
    fi
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
    echo -e "${Info} Xray 已卸载"
}

# ==================== 主菜单 ====================
show_menu() {
    clear
    show_status
    
    echo -e "
${Green_font_prefix}========================================================${Font_color_suffix}
      GOST v3 + Xray 任意门 中转管理脚本 ${Red_font_prefix}[v${shell_version}]${Font_color_suffix}
${Green_font_prefix}========================================================${Font_color_suffix}
 ${Cyan_font_prefix}支持: VLESS VMess Trojan SS Hy2 TUIC SOCKS HTTP${Font_color_suffix}
${Green_font_prefix}--------------------------------------------------------${Font_color_suffix}
 ${Green_font_prefix}1.${Font_color_suffix}  安装 GOST v3          ${Green_font_prefix}2.${Font_color_suffix}  安装 Xray
 ${Green_font_prefix}3.${Font_color_suffix}  卸载 GOST v3          ${Green_font_prefix}4.${Font_color_suffix}  卸载 Xray
${Green_font_prefix}--------------------------------------------------------${Font_color_suffix}
 ${Green_font_prefix}5.${Font_color_suffix}  启动 GOST v3          ${Green_font_prefix}6.${Font_color_suffix}  停止 GOST v3
 ${Green_font_prefix}7.${Font_color_suffix}  重启 GOST v3          ${Green_font_prefix}8.${Font_color_suffix}  查看日志
${Green_font_prefix}--------------------------------------------------------${Font_color_suffix}
 ${Green_font_prefix}9.${Font_color_suffix}  启动 Xray             ${Green_font_prefix}10.${Font_color_suffix} 停止 Xray
 ${Green_font_prefix}11.${Font_color_suffix} 重启 Xray             ${Green_font_prefix}12.${Font_color_suffix} 查看日志
${Green_font_prefix}--------------------------------------------------------${Font_color_suffix}
 ${Green_font_prefix}13.${Font_color_suffix} 添加中转配置          ${Green_font_prefix}14.${Font_color_suffix} 批量添加中转
 ${Green_font_prefix}15.${Font_color_suffix} 查看当前配置          ${Green_font_prefix}16.${Font_color_suffix} 删除配置
${Green_font_prefix}--------------------------------------------------------${Font_color_suffix}
 ${Green_font_prefix}17.${Font_color_suffix} 解析节点链接 (测试)   ${Green_font_prefix}18.${Font_color_suffix} 安装快捷命令
${Green_font_prefix}--------------------------------------------------------${Font_color_suffix}
 ${Green_font_prefix}0.${Font_color_suffix}  退出脚本
${Green_font_prefix}========================================================${Font_color_suffix}
"
    read -p " 请输入数字 [0-18]: " num
    
    case "$num" in
        1) install_gost3 ;;
        2) install_xray ;;
        3) uninstall_gost3 ;;
        4) uninstall_xray ;;
        5) systemctl start gost3 && echo -e "${Info} GOST v3 已启动" ;;
        6) systemctl stop gost3 && echo -e "${Info} GOST v3 已停止" ;;
        7) systemctl restart gost3 && echo -e "${Info} GOST v3 已重启" ;;
        8) journalctl -u gost3 -n 50 --no-pager ;;
        9) systemctl start xray && echo -e "${Info} Xray 已启动" ;;
        10) systemctl stop xray && echo -e "${Info} Xray 已停止" ;;
        11) systemctl restart xray && echo -e "${Info} Xray 已重启" ;;
        12) journalctl -u xray -n 50 --no-pager ;;
        13) add_relay_config ;;
        14) batch_add_relay ;;
        15) show_all_config; read -p "按回车键继续..." ;;
        16) delete_config ;;
        17) test_parse ;;
        18) install_shortcut ;;
        0) exit 0 ;;
        *) echo -e "${Error} 请输入正确数字 [0-18]" ;;
    esac
}

# ==================== 启动脚本 ====================
main() {
    check_root
    check_sys
    
    while true; do
        show_menu
        echo -e ""
    done
}

main
